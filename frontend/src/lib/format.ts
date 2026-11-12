import { fmtLog } from '../components/list/cell-format';

const timeFmt = new Intl.DateTimeFormat('ko-KR', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});
const numFmt = new Intl.NumberFormat('ko-KR');

export const fmtTime = (iso: string) => timeFmt.format(new Date(iso));
// 시각 한 줄(시트 · 보고서 · 도우미 · 계정, 11/09 G41): YYYY-MM-DD HH:mm:ss — 표 칸 TimeText 'log' 와 같은 모양(cell-format fmtLog 한 곳)
export const fmtDateTime = (iso: string) => fmtLog(iso);
export const fmtNum = (n: number) => numFmt.format(n);
export const shortId = (id: string) => id.slice(0, 12);

// 오늘(로컬 날짜) 안의 시각인지
export const isToday = (iso: string | null | undefined, now: number) => {
  if (!iso) return false;
  const d = new Date(iso);
  const n = new Date(now);
  return d.getFullYear() === n.getFullYear() && d.getMonth() === n.getMonth() && d.getDate() === n.getDate();
};
