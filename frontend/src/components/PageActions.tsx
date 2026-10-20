import { useContext, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { HeaderSlotContext } from './header-slot';

// 상단 머리 = 화면 이름 + 그 화면의 주 버튼 · 입력. 화면은 <PageActions> 로 머리 칸에 버튼을 꽂는다.

export function PageActions({ children }: { children: ReactNode }) {
  const slot = useContext(HeaderSlotContext);
  return slot ? createPortal(children, slot) : null;
}
