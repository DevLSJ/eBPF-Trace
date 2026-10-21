import { useCallback, useEffect, useRef, useState } from 'react';
import { api, recheckSession } from '../lib/api';
import { gapOf, mergeByTime } from '../lib/shell';
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
  // W19(10/20 D): 실시간 연결이 끊김(한 번 붙은 뒤, 또는 처음부터 5초 넘게 못 붙음) — 셸 상단 붉은 배너 · 알림 센터
  down: boolean;
  // 다시 붙은 뒤 /api/events/recent 로 끊긴 구간을 채운 결과(채운 수 · 시각). 셸이 토스트로 알린다
  backfill: { n: number; at: number } | null;
  // 최초 recent · stats 로드 실패 — 삼키지 않고 셸이 오류 배너로 보인다(백엔드가 꺼져 있는데 「위반 없음」으로 보이지 않게)
  loadError: unknown;
  retryLoad: () => void;
  // W20: 첫 recent 가 아직 끝나지 않음(이벤트 화면 스켈레톤) · recent 만의 오류(이벤트 목록 오류 칸). 다시 시도는 조용히(스켈레톤 없이)
  recentLoading: boolean;
  recentError: unknown;
}

const GRACE_MS = 5000;

// 백엔드 /ws/events 구독. 메시지는 FLUSH_MS마다 묶어서 렌더링한다(초당 수십 건 대비).
export function useEventStream(url = defaultUrl()): EventStream {
  const [connected, setConnected] = useState(false);
  const [verdicts, setVerdicts] = useState<StreamVerdict[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [paused, setPaused] = useState(false);
  const [unseenAlerts, setUnseen] = useState(0);
  const [topologyVersion, setTopologyVersion] = useState(0);
  const [everConnected, setEver] = useState(false);
  const [graceOver, setGraceOver] = useState(false);
  const [backfill, setBackfill] = useState<{ n: number; at: number } | null>(null);
  const [recentError, setRecentError] = useState<unknown>(null);
  const [recentLoading, setRecentLoading] = useState(true);
  const [statsError, setStatsError] = useState<unknown>(null);
  const [loadNonce, setLoadNonce] = useState(0);
  const verdictsRef = useRef<StreamVerdict[]>([]);
  useEffect(() => {
    verdictsRef.current = verdicts;
  }, [verdicts]);
  useEffect(() => {
    const t = window.setTimeout(() => setGraceOver(true), GRACE_MS);
    return () => window.clearTimeout(t);
  }, []);

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

  // 받은 것 + 아직 그리지 않은 것(큐)과 겹치지 않는 recent 만 더한다 — 다시 시도 · 끊긴 구간 채우기
  const fillFrom = useCallback(
    (vs: Verdict[]) => {
      const gap = gapOf(vs, [...verdictsRef.current, ...queue.current]);
      [...gap].reverse().forEach((v) => topology.ingest(v));
      if (gap.length && !pausedRef.current) {
        const rows = gap.map((v) => ({ ...v, key: ++seq.current }));
        setVerdicts((prev) => mergeByTime(prev, rows, MAX_ROWS));
      }
      setTopologyVersion((n) => n + 1);
      return gap.length;
    },
    [topology],
  );

  // 최근 판정으로 초기 화면 채우기 (새로고침 직후 빈 화면 방지). 실패는 loadError 로 드러낸다(W19) — 「다시 시도」가 loadNonce 를 올린다
  useEffect(() => {
    let cancelled = false;
    const first = loadNonce === 0;
    api
      .recent(MAX_ROWS)
      .then((vs) => {
        if (cancelled) return;
        setRecentError(null);
        setRecentLoading(false);
        if (!first) {
          fillFrom(vs);
          return;
        }
        const seeded = vs.map((v) => ({ ...v, key: ++seq.current }));
        [...vs].reverse().forEach((v) => topology.ingest(v));
        setVerdicts((prev) => [...prev, ...seeded].slice(0, MAX_ROWS));
        setTopologyVersion((n) => n + 1);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setRecentError(e);
        setRecentLoading(false);
      });
    api
      .stats()
      .then((s) => {
        if (cancelled) return;
        setStatsError(null);
        setStats((cur) => cur ?? s);
      })
      .catch((e: unknown) => {
        if (!cancelled) setStatsError(e);
      });
    return () => {
      cancelled = true;
    };
  }, [topology, loadNonce, fillFrom]);

  useEffect(() => {
    let ws: WebSocket | undefined;
    let retry: number | undefined;
    let attempt = 0;
    let closed = false;
    let wasUp = false; // 한 번 열린 뒤 끊겼으면 다시 열릴 때 끊긴 구간을 채운다

    const connect = () => {
      ws = new WebSocket(url);
      let opened = false;
      ws.onopen = () => {
        opened = true;
        attempt = 0;
        setConnected(true);
        setEver(true);
        if (wasUp) {
          wasUp = false;
          api.recent(MAX_ROWS).then(
            (vs) => {
              if (closed) return;
              setRecentError(null);
              setBackfill({ n: fillFrom(vs), at: Date.now() });
            },
            () => {
              /* 다음 재연결에서 다시 */
              if (!closed) wasUp = true;
            },
          );
        }
      };
      ws.onclose = () => {
        // 이미 정리된 연결(StrictMode 재마운트 · 화면 이탈)의 늦은 close 가 새 연결 상태를 덮지 않게
        if (closed) return;
        // 열리기 전에 닫힘 = 업그레이드 거절(로그아웃 · 세션 만료일 수 있음) → 로그인 여부를 다시 확인(W16)
        if (!opened) void recheckSession();
        else wasUp = true;
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
        else if (msg.type === 'stats') {
          setStats(msg.data);
          setStatsError(null);
        }
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
  }, [url, accept, fillFrom]);

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
    down: !connected && (everConnected || graceOver),
    backfill,
    loadError: recentError ?? statsError,
    retryLoad: () => setLoadNonce((n) => n + 1),
    recentLoading,
    recentError,
  };
}

function defaultUrl() {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}/ws/events`;
}
