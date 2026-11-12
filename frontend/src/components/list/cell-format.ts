import { EMPTY_TEXT } from '../../hooks/useTableKit';

// 표 칸 글자 도우미(11/09 SPEC-1109 §4 — 참고 제품 답변 G5 · G10): 부품은 cells.tsx(Dash · TwoLine · TimeText)
//   빈 값 = 빈 칸(null · undefined · '' · false, 11/09 「—」 없앰)
//   시각 3형식 — fmtLog 기록류 YYYY-MM-DD HH:mm:ss · fmtStatus 현황 MM-DD HH:mm · fmtDay 등록일 YYYY-MM-DD. 상대 시각(「n분 전」)은 쓰지 않는다. 시간대는 브라우저 로컬
export const DASH = EMPTY_TEXT;
export const isEmptyValue = (v: unknown) => v === null || v === undefined || v === '' || v === false;

export type TimeKind = 'log' | 'status' | 'day';
const pad = (n: number) => String(n).padStart(2, '0');
export const toDate = (v: string | number | Date) => (v instanceof Date ? v : new Date(v));
export const fmtLog = (v: string | number | Date) => {
  const d = toDate(v);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
export const fmtStatus = (v: string | number | Date) => {
  const d = toDate(v);
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
export const fmtDay = (v: string | number | Date) => {
  const d = toDate(v);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
};
export const fmtTimeKind = (v: string | number | Date, kind: TimeKind) => (kind === 'log' ? fmtLog(v) : kind === 'status' ? fmtStatus(v) : fmtDay(v));
