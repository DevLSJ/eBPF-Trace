import { createContext } from 'react';

// 상단 머리 칸(화면 이름 옆) — AppShell 이 DOM 요소를 넣고 PageActions 가 그 안에 그린다
export const HeaderSlotContext = createContext<HTMLElement | null>(null);

// 상세 패널 자리(11/05) — AppShell 의 main 안 빈 칸. Sheet 가 포털로 그 안에 겹쳐 뜬다(머리줄 아래 · 사이드바 오른쪽 본문 전체)
export const SheetHostContext = createContext<HTMLElement | null>(null);
