import { createContext, type Dispatch, type SetStateAction } from 'react';

// 화면 주 버튼 칸(11/09 밤 결정 ③) — 본문 맨 위 화면 설명 줄(ScreenHead)의 오른쪽 끝.
//   ScreenHead 가 자기 버튼 칸 DOM 을 알리고(ActionSlotSetContext) PageActions 가 그 안에 그린다(ActionSlotContext). 칸이 없으면 null
export const ActionSlotContext = createContext<HTMLElement | null>(null);
export const ActionSlotSetContext = createContext<Dispatch<SetStateAction<HTMLElement | null>>>(() => {});

// 상세 패널 자리(11/05) — AppShell 의 main 안 빈 칸. Sheet 가 포털로 그 안에 겹쳐 뜬다(머리줄 아래 · 사이드바 오른쪽 본문 전체)
export const SheetHostContext = createContext<HTMLElement | null>(null);
