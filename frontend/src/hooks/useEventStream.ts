import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';
import { TopologyStore } from '../lib/topology';
import type { Stats, Verdict, WsMessage } from '../lib/types';

export interface StreamVerdict extends Verdict {
  key: number; // React key — 클라이언트에서 부여
}

export const MAX_ROWS = 500;
const FLUSH_MS = 250;

export interface EventStream {
  connected: boolean;
  verdicts: StreamVerdict[];
  stats: Stats | null;
  paused: boolean;
  pause: () => void;
  resume: () => void;
  unseenAlerts: number;
  ackAlerts: () => void;
  topology: TopologyStore;
  topologyVersion: number;
  // WS 메시지 원본 구독(토스트 · 건 갱신). 반환값으로 해제
  subscribe: (fn: (m: WsMessage) => void) => () => void;
}

// 백엔드 /ws/events 구독. 메시지는 FLUSH_MS마다 묶어서 렌더링한다(초당 수십 건 대비).
export function useEventStream(url = defaultUrl()): EventStream {
  const [connected, setConnected] = useState(false);
  const [verdicts, setVerdicts] = useState<StreamVerdict[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [paused, setPaused] = useState(false);
  const [unseenAlerts, setUnseen] = useState(0);
  const [topologyVersion, setTopologyVersion] = useState(0);

  const pausedRef = useRef(false);
  const queue = useRef<StreamVerdict[]>([]);
  const seq = useRef(0);
  const [topology] = useState(() => new TopologyStore());
  const listeners = useRef(new Set<(m: WsMessage) => void>());
  const subscribe = useCallback((fn: (m: WsMessage) => void) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  const accept = useCallback((v: Verdict) => {
    topology.ingest(v); // 토폴로지는 일시정지와 무관하게 누적
    if (v.matched) setUnseen((n) => n + 1);
    if (pausedRef.current) return;
    queue.current.push({ ...v, key: ++seq.current });
  }, [topology]);

  // 최근 판정으로 초기 화면 채우기 (새로고침 직후 빈 화면 방지)
  useEffect(() => {
    let cancelled = false;
    api
      .recent(MAX_ROWS)
      .then((vs) => {
        if (cancelled) return;
        const seeded = vs.map((v) => ({ ...v, key: ++seq.current }));
        [...vs].reverse().forEach((v) => topology.ingest(v));
        setVerdicts((prev) => [...prev, ...seeded].slice(0, MAX_ROWS));
        setTopologyVersion((n) => n + 1);
      })
      .catch(() => {
        /* 백엔드 미기동 — WebSocket 재연결이 처리 */
      });
    api
      .stats()
      .then((s) => !cancelled && setStats((cur) => cur ?? s))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [topology]);

  useEffect(() => {
    let ws: WebSocket | undefined;
    let retry: number | undefined;
    let attempt = 0;
    let closed = false;

    const connect = () => {
      ws = new WebSocket(url);
      ws.onopen = () => {
        attempt = 0;
        setConnected(true);
      };
      ws.onclose = () => {
        // 이미 정리된 연결(StrictMode 재마운트 · 화면 이탈)의 늦은 close 가 새 연결 상태를 덮지 않게
        if (closed) return;
        setConnected(false);
        const delay = Math.min(1000 * 2 ** attempt, 10_000); // 1s → 10s 백오프
        attempt++;
        retry = window.setTimeout(connect, delay);
      };
      ws.onmessage = (e) => {
        let msg: WsMessage;
        try {
          msg = JSON.parse(e.data as string) as WsMessage;
        } catch {
          return;
        }
        if (msg.type === 'verdict') accept(msg.data);
        else if (msg.type === 'stats') setStats(msg.data);
        listeners.current.forEach((fn) => fn(msg));
      };
    };
    connect();

    const flush = window.setInterval(() => {
      if (queue.current.length === 0) return;
      const batch = queue.current.reverse();
      queue.current = [];
      setVerdicts((prev) => [...batch, ...prev].slice(0, MAX_ROWS));
      setTopologyVersion((n) => n + 1);
    }, FLUSH_MS);

    return () => {
      closed = true;
      window.clearTimeout(retry);
      window.clearInterval(flush);
      ws?.close();
    };
  }, [url, accept]);

  return {
    connected,
    verdicts,
    stats,
    paused,
    pause: () => {
      pausedRef.current = true;
      setPaused(true);
    },
    resume: () => {
      pausedRef.current = false;
      setPaused(false);
    },
    unseenAlerts,
    ackAlerts: () => setUnseen(0),
    topology,
    topologyVersion,
    subscribe,
  };
}

function defaultUrl() {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}/ws/events`;
}
