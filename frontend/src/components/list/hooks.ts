import { useEffect, useRef, type KeyboardEvent } from 'react';

// 오류 동안 30초마다 조용히 한 번 다시 부른다(스켈레톤 없이) — 오류가 풀리면 멈춘다
export function useAutoRetry(failing: boolean, retry: () => void, ms = 30_000) {
  const fn = useRef(retry);
  useEffect(() => {
    fn.current = retry;
  });
  useEffect(() => {
    if (!failing) return;
    const t = window.setInterval(() => fn.current(), ms);
    return () => window.clearInterval(t);
  }, [failing, ms]);
}

// 행 키보드 열기 — Tab 으로 닿고 Enter · Space 로 연다(행 안의 버튼 · 링크에서 누른 것은 그대로)
export function rowKeys(open: () => void) {
  return {
    tabIndex: 0,
    onKeyDown: (e: KeyboardEvent<HTMLElement>) => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
        e.preventDefault();
        open();
      }
    },
  };
}
