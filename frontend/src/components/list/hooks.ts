import { useEffect, useRef, type KeyboardEvent } from 'react';
import { isUnsupported } from '../../lib/api';

// 오류 동안 30초마다 조용히 한 번 다시 부른다(스켈레톤 없이) — 오류가 풀리면 멈춘다.
// 「백엔드 미지원」(라우트 없음)은 다시 불러도 같으니 돌지 않는다 — ListError 도 그때는 다시 시도 · 30초 문구를 숨긴다
export function useAutoRetry(failing: boolean, error: unknown, retry: () => void, ms = 30_000) {
  const fn = useRef(retry);
  useEffect(() => {
    fn.current = retry;
  });
  const on = failing && !isUnsupported(error);
  useEffect(() => {
    if (!on) return;
    const t = window.setInterval(() => fn.current(), ms);
    return () => window.clearInterval(t);
  }, [on, ms]);
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
