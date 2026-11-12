import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
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

// 재조회 진행 띠(R4 11/04 — 목업 kit.busy): 데이터가 있는 채로 다시 부를 때만, 짧은 재조회(5초 폴링 등)는 깜빡이지 않게 ms 뒤부터 켠다
export function useBusy(reloading: boolean, ms = 300) {
  const [on, setOn] = useState(false);
  useEffect(() => {
    const t = window.setTimeout(() => setOn(reloading), reloading ? ms : 0);
    return () => window.clearTimeout(t);
  }, [reloading, ms]);
  return reloading && on;
}

// 행 왼쪽 3px 막대(R4 11/04 — 목업 needs-action bar-*): 판정 대기(경고색) · 격리 · 정적 악성(빨강) 행만.
// 첫 칸에 둔다(목업 tr.needs-action td:first-child 와 같은 자리)
export type RowBar = 'danger' | 'warn' | null | undefined | false;
export const barStyle = (bar: RowBar) => (bar ? { boxShadow: `inset 3px 0 0 var(--${bar})` } : undefined);

// 행 상태(11/09 SPEC-1109 §3 — 참고 제품 C3): 고른 줄(checked) · 열린 줄(open) = 같은 연한 강조 바탕, 열린 줄만 첫 칸 왼쪽 3px 주 색.
// hover = 표 hover 회색 · 전환 시간 없음 · 행을 흐리게 하지 않음(꺼짐은 배지 글자로). 모양은 components/table-kit.css
//   <tr {...rowState({ open: id === cur, checked: picked.has(id) })} {...rowKeys(open)}>
export const rowState = ({ open, checked }: { open?: boolean; checked?: boolean }) => ({
  'data-kit-row': '',
  'data-open': open ? '' : undefined,
  'data-checked': checked ? '' : undefined,
  'aria-selected': open || checked ? true : undefined,
});
