import { useCallback, useEffect, useState } from 'react';
import { isUnsupported } from '../lib/api';

interface LoadState<T> {
  fn: unknown;
  nonce: number;
  data?: T;
  error?: unknown;
}

// fn 은 useCallback 으로 고정해서 넘긴다. fn 이 바뀌면 다시 부르고, reload() 는 같은 fn 을 다시 부른다(이전 값은 유지).
export function useLoad<T>(fn: (() => Promise<T>) | null) {
  const [nonce, setNonce] = useState(0);
  const [st, setSt] = useState<LoadState<T>>({ fn: null, nonce: -1 });
  useEffect(() => {
    if (!fn) return;
    let live = true;
    fn().then(
      (data) => live && setSt({ fn, nonce, data }),
      (error: unknown) => live && setSt((cur) => ({ fn, nonce, error, data: cur.fn === fn ? cur.data : undefined })),
    );
    return () => {
      live = false;
    };
  }, [fn, nonce]);
  const current = st.fn === fn;
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const error = current ? st.error : undefined;
  return {
    data: current ? st.data : undefined,
    error,
    unsupported: isUnsupported(error),
    loading: !!fn && (!current || st.nonce !== nonce),
    reload,
  };
}

// 화면이 열려 있는 동안 주기적으로 다시 부른다
export function useInterval(fn: () => void, ms: number) {
  useEffect(() => {
    const t = window.setInterval(fn, ms);
    return () => window.clearInterval(t);
  }, [fn, ms]);
}

// 현재 시각 — 렌더 중 Date.now() 를 직접 부르지 않도록 상태로 둔다
export function useNow(ms = 30_000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(t);
  }, [ms]);
  return now;
}
