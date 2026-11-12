import { useContext, useLayoutEffect, useRef } from 'react';
import { screenCopy } from '../lib/screenCopy';
import { ActionSlotSetContext } from './header-slot';

// 화면 설명 줄(11/09 밤 결정 ③) — 본문 맨 위 한 줄 = 왼쪽 화면 설명(lib/screenCopy) + 오른쪽 끝 주 버튼 칸.
//   버튼은 화면이 <PageActions> 로 꽂는다. 버튼이 많으면 줄을 바꾸지 않고 설명이 말줄임(전체는 툴팁).
//   768 미만은 버튼이 설명 아래 줄로(버튼끼리 줄바꿈 — 가로 넘침 0). 버튼이 없으면 칸은 숨고 줄은 설명 한 줄 높이(예전 설명 줄 그대로 — 시연 1920×1080 한 화면 등 높이 여유를 줄이지 않음).
//   인쇄에서는 버튼 칸만 숨긴다(예전 머리 줄처럼 — 건 보고서 인쇄)
//   screen = lib/screenCopy 키(화면 경로에서 앞 「/」를 뺀 것, 예 'policies/blocklist')
export function ScreenHead({ screen, className = '' }: { screen: string; className?: string }) {
  const setSlot = useContext(ActionSlotSetContext);
  const slot = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = slot.current;
    if (!el) return;
    setSlot(el);
    return () => setSlot((cur) => (cur === el ? null : cur));
  }, [setSlot]);
  const text = screenCopy(screen);
  return (
    <div data-part="screen-head" className={`flex min-w-0 shrink-0 items-center gap-3 max-md:flex-col max-md:items-stretch max-md:gap-2 ${className}`}>
      <p data-part="screen-copy" data-screen={screen} title={text} className="m-0 min-w-0 flex-1 truncate text-[length:var(--fs-sm)] text-text-3 max-md:flex-none">
        {text}
      </p>
      <div ref={slot} data-part="page-actions" data-testid="page-actions" className="flex shrink-0 items-center gap-2 empty:hidden max-md:flex-wrap print:hidden" />
    </div>
  );
}
