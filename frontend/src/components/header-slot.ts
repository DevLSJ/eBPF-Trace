import { createContext } from 'react';

// 상단 머리 칸(화면 이름 옆) — AppShell 이 DOM 요소를 넣고 PageActions 가 그 안에 그린다
export const HeaderSlotContext = createContext<HTMLElement | null>(null);
