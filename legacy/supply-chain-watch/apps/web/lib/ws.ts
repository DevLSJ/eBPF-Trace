'use client';
import { useEffect, useRef, useState } from 'react';
import type { WsEnvelope } from '@scw/shared-types';
import { WS_URL } from './utils';

export type WsState = 'connecting' | 'open' | 'closed';

// 재연결 백오프 1s→30s. 서버→클라이언트 이벤트 수신 (docs/06 §6).
export function useWebSocket(onEvent?: (e: WsEnvelope) => void) {
  const [state, setState] = useState<WsState>('connecting');
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let delay = 1000;
    let closed = false;

    const connect = () => {
      setState('connecting');
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        delay = 1000;
        setState('open');
      };
      ws.onmessage = (ev) => {
        try {
          onEventRef.current?.(JSON.parse(ev.data) as WsEnvelope);
        } catch {
          /* ignore malformed */
        }
      };
      ws.onclose = () => {
        setState('closed');
        if (!closed) {
          timer = setTimeout(connect, delay);
          delay = Math.min(delay * 2, 30000);
        }
      };
      ws.onerror = () => ws?.close();
    };
    connect();

    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return state;
}
