import type { ReactNode } from 'react';

// 스크롤 없는 페이지 틀(11/04e, R1 11/04) — 셸(사이드바 · 머리 56)은 고정, 화면 이름 · 주 버튼은 셸 머리(PageActions)에.
// Page 는 남은 높이를 채우는 몸통: 자식이 flex 1 · min-height 0 으로 늘어나고, 스크롤은 화면 안의 채움 칸([data-fill])에서만 한다.
//   채움 칸 = 표 몸통 · 목록 · 피드 · 토폴로지 · 정책 칸 · 평가 몸통 · 보고서처럼 남은 높이를 채우고 넘치면 스크롤하는 칸.
//   화면은 그 칸에 data-fill 을 붙인다(<Fill> 또는 data-fill="" 속성 — 스크롤 · 얇은 스크롤바는 index.css [data-fill]).
// 768 이상: 문서 · main 스크롤 0. 768 미만: 지금 React 그대로(서랍 사이드바 · 1열, 화면 안 칸이 스크롤 — 문서 스크롤도 허용)
export function Page({ children }: { children: ReactNode }) {
  return (
    <div data-page="" className="sg-page">
      {children}
    </div>
  );
}

// 채움 칸 — 남은 높이를 채우고 넘치면 이 칸만 스크롤
export function Fill({ children, className = '', ...rest }: { children: ReactNode; className?: string } & Record<`data-${string}`, string | undefined>) {
  return (
    <div data-fill="" className={`min-h-0 flex-1 overflow-auto ${className}`} {...rest}>
      {children}
    </div>
  );
}
