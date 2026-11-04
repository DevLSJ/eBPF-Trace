import { fmtNum } from './format';

// KPI 카드(components/KpiCard.tsx) 의 띠 · 증감 줄 — 위반 · 격리 증가만 danger(빨강), 격리 지연 증가 · 수집 감소는 warn, 나머지 neutral
export type Stripe = 'accent' | 'info' | 'danger' | 'warn' | 'ok';
export type DeltaTone = 'danger' | 'warn' | 'ok' | 'neutral';
export interface KpiDelta {
  dir: 'up' | 'down' | 'flat' | 'none';
  text?: string;
  tone?: DeltaTone;
  note?: string;
}
// 증감: cur − prev. up/down = 그 방향의 색(위반 증가 같은 위험만 danger, 그 밖은 neutral · warn)
export function kpiDelta(cur: number | null | undefined, prev: number | null | undefined, o: { up?: DeltaTone; down?: DeltaTone; unit?: string; note?: string } = {}): KpiDelta {
  if (cur == null || prev == null || !Number.isFinite(cur) || !Number.isFinite(prev)) return { dir: 'none', note: '이전 기간 정보 없음' };
  const d = cur - prev;
  if (!d) return { dir: 'flat', text: '변화 없음', tone: 'neutral', note: o.note };
  return { dir: d > 0 ? 'up' : 'down', text: `${fmtNum(Math.abs(d))}${o.unit ?? ''}`, tone: (d > 0 ? o.up : o.down) ?? 'neutral', note: o.note };
}

