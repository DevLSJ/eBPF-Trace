import { fmtNum } from './format';
import type { Timeline } from './types';

// 격리 타임라인 계산(10/30 계약 §3) — 화면은 components/TimelineBar.tsx. 구간 4개 · 합계 · ms 표기

export type SegKey = 'detect' | 'evidence' | 'kill' | 'notify';
export interface Segment {
  key: SegKey;
  label: string;
  ms: number | null;
}

const ms = (a?: string, b?: string) => (a && b ? Math.max(0, Date.parse(b) - Date.parse(a)) : null);

// 탐지→판정 = matchedAt − detectedAt · 증거 = 훅 시작→끝 · 격리 = (증거 끝 또는 판정)→kill 응답 · 알림 = kill→큐 투입
export function segmentsOf(t: Timeline | null | undefined): Segment[] {
  if (!t) return [
    { key: 'detect', label: '수집→탐지', ms: null },
    { key: 'evidence', label: '증거', ms: null },
    { key: 'kill', label: '격리', ms: null },
    { key: 'notify', label: '알림', ms: null },
  ];
  return [
    { key: 'detect', label: '수집→탐지', ms: ms(t.detectedAt, t.matchedAt) },
    { key: 'evidence', label: '증거', ms: ms(t.evidenceStartedAt, t.evidenceDoneAt) },
    { key: 'kill', label: '격리', ms: t.killedAt ? ms(t.evidenceDoneAt ?? t.matchedAt, t.killedAt) : null },
    { key: 'notify', label: '알림', ms: ms(t.killedAt, t.notifiedAt) },
  ];
}
// 격리까지 = killedAt − detectedAt(없으면 null)
export const isolationMs = (t: Timeline | null | undefined) => (t?.killedAt ? Math.max(0, Date.parse(t.killedAt) - Date.parse(t.detectedAt)) : null);
export const fmtSec = (v: number) => `${(v / 1000).toFixed(2)}초`;
export const fmtMs = (v: number | null) => (v === null ? '' : `${fmtNum(v)} ms`);
