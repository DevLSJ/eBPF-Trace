import { useContext, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { ActionSlotContext, ActionSlotSetContext } from './header-slot';

// 화면 주 버튼(11/09 밤 결정 ③) — 본문 맨 위 화면 설명 줄의 오른쪽 끝(ScreenHead 의 버튼 칸). 머리 줄에는 제목 + 상태 표시만.
// 화면은 <PageActions> 로 버튼을 꽂는다 — 놓는 자리는 어디든(ScreenHead 앞 · 뒤). 버튼 칸이 아직 없거나 없는 화면이면 그리지 않는다
export function PageActions({ children }: { children: ReactNode }) {
  const slot = useContext(ActionSlotContext);
  return slot ? createPortal(children, slot) : null;
}

// 셸 본문을 감싸 버튼 칸 자리를 나눈다. 칸이 바뀌어도 감싼 화면은 다시 그리지 않고 PageActions 만 다시 그린다
export function ActionSlotProvider({ children }: { children: ReactNode }) {
  const [slot, setSlot] = useState<HTMLElement | null>(null);
  return (
    <ActionSlotSetContext.Provider value={setSlot}>
      <ActionSlotContext.Provider value={slot}>{children}</ActionSlotContext.Provider>
    </ActionSlotSetContext.Provider>
  );
}
