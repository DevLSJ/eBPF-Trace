import type { PillTone } from '../../components/DataTable';
import { SANDBOX_SCOPE, summarize, toDraft, type Scope } from '../../lib/policyEasy';
import { seqSummary } from '../../lib/sequence';
import { isSingleRule, SYSTEM_RULES, type Rule } from '../../lib/types';

// 정책 목록 · 시트가 같이 쓰는 표기(11/09): 상태 · 판정 · 적용 컨테이너 · 조건 요약 · 출처
export type RuleStatus = 'on' | 'dry' | 'off';
export const STATUS: Record<RuleStatus, { label: string; tone: PillTone; order: number }> = {
  on: { label: '사용 중', tone: 'ok', order: 0 },
  dry: { label: '시험 운영', tone: 'warn', order: 1 },
  off: { label: '사용 안 함', tone: 'neutral', order: 2 },
};
export const statusOf = (r: Rule): RuleStatus => (r.disabled ? 'off' : r.action === 'kill' && r.dryRun ? 'dry' : 'on');

export const ACTION_LABEL: Record<Rule['action'], string> = { kill: '격리', alert: '경고' };
// 판정 거르기(사용 안 함 포함): 격리 = kill(시험 아님) · 경고 = alert · 시험 운영 = kill + dryRun · 사용 안 함 = disabled
export const ACT_OPTIONS = [
  { value: 'kill', label: '격리' },
  { value: 'alert', label: '경고' },
  { value: 'dry', label: '시험 운영' },
  { value: 'off', label: '사용 안 함' },
];
export function actMatches(r: Rule, act: string) {
  if (!act) return true;
  if (act === 'off') return !!r.disabled;
  if (r.disabled) return false;
  if (act === 'dry') return r.action === 'kill' && !!r.dryRun;
  if (act === 'kill') return r.action === 'kill' && !r.dryRun;
  return r.action === act;
}
export const SCOPE_OPTIONS = [
  { value: 'all', label: '모든 컨테이너' },
  { value: 'sandbox', label: '설치 검사' },
  { value: 'some', label: '지정' },
];

// 적용 컨테이너 칸 — 비면 「모든 컨테이너」, sg-install-* 만이면 「설치 검사」, 그 밖은 패턴 칩 2개 + 「+n」
export function containersText(r: Rule) {
  const xs = r.containers ?? [];
  const s = scopeFromList(xs);
  return s === 'all' ? '모든 컨테이너' : s === 'sandbox' ? '설치 검사' : xs.join(' · ');
}
// 조건 요약(숨김 칸) — 쉬운 설정의 한 줄 요약에서 「~컨테이너에서」 앞부분을 뺀 것
export function condSummary(r: Rule): string {
  if (!isSingleRule(r)) return seqSummary(r);
  const d = toDraft(r);
  return summarize({ ...d, lists: { ...d.lists, containers: '' }, disabled: false }).replace(/^모든 컨테이너에서 /, '');
}
// 출처(숨김 칸): 시스템 규칙 · 기본 정책(변경 기록 없음 — 처음 넣은 기본 정책) · 사용자 변경
export const originOf = (r: Rule & { updatedAt?: string }) => (SYSTEM_RULES.has(r.id) ? '시스템 규칙' : r.updatedAt ? '사용자 변경' : '기본 정책');

// 적용 범위 — 비면 모든 컨테이너 · sg-install-* 만이면 설치 검사 · 그 밖은 지정
export function scopeFromList(xs: string[]): Scope {
  return !xs.length ? 'all' : xs.every((c) => c === SANDBOX_SCOPE) ? 'sandbox' : 'some';
}
