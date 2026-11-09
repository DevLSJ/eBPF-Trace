import { actionTone } from '../../lib/actionTone';
import type { PillTone } from '../../components/DataTable';
import type { Change, Rule } from '../../lib/types';

// 변경 이력 보기(11/09 SPEC-1109 §7) — 동작 태그 이름은 「[대상] [동작]」 꼴, 색은 끝말(lib/actionTone 한 곳)
//   정책 저장(policy_edit)은 전후 값으로 나눈다: 변경 전 없음 = 정책 생성 · 변경 뒤 없음 = 정책 삭제 · 둘 다 = 정책 수정(옛 기록은 요약 글로)
const KIND_NAME: Record<string, string> = {
  proposal_applied: '제안 적용',
  proposal_discarded: '제안 버림',
  policy_replace: '정책 일괄 적용',
  blocklist_remove: '차단 해제',
  policy_revert: '정책 되돌림',
  demo_run: '시연 실행',
  integration_test: '연결 테스트',
};

export function changeName(c: Change, ruleId?: string): string {
  if (c.kind !== 'policy_edit') return KIND_NAME[c.kind] ?? c.kind;
  const id = ruleId ?? c.ruleIds?.[0];
  const had = !!(id && c.before?.[id]);
  const has = !!(id && c.after?.[id]);
  if (had && has) return '정책 수정';
  if (has) return '정책 생성';
  if (had) return '정책 삭제';
  return /삭제$/.test(c.summary) ? '정책 삭제' : '정책 수정';
}
export const changeTone = (c: Change, ruleId?: string): PillTone => actionTone(changeName(c, ruleId));

// 변경 이력 화면의 종류 거르기 — 값은 서버 종류 그대로
export const CHANGE_KIND_OPTIONS = [
  { value: 'policy_edit', label: '정책 생성 · 수정 · 삭제' },
  { value: 'policy_revert', label: '정책 되돌림' },
  { value: 'policy_replace', label: '정책 일괄 적용' },
  { value: 'proposal_applied', label: '제안 적용' },
  { value: 'proposal_discarded', label: '제안 버림' },
  { value: 'blocklist_remove', label: '차단 해제' },
  { value: 'demo_run', label: '시연 실행' },
  { value: 'integration_test', label: '연결 테스트' },
];

// 정책 칸 이름(화면 말) — 내부 칸 이름은 보이지 않는다
export const FIELD_LABEL: Record<string, string> = {
  description: '설명',
  kind: '종류',
  action: '판정',
  dryRun: '시험 운영',
  disabled: '사용',
  containers: '적용 컨테이너',
  denyComms: '막을 프로그램',
  denyArgs: '막을 명령',
  denyPaths: '막을 경로',
  allowPaths: '예외 경로',
  allowPorts: '허용 포트',
  allowCidrs: '허용 대역',
  allowHosts: '허용 도메인',
  denyPorts: '금지 포트',
  denyCidrs: '금지 대역',
  denyHosts: '금지 도메인',
  directIp: 'IP 직접 연결',
  denyQtypes: '금지 질의 유형',
  maxLabelLength: '라벨 길이 상한',
  maxNameLength: '이름 길이 상한',
  windowSeconds: '연쇄 시간 창',
  steps: '연쇄 단계',
};
const FIELDS = Object.keys(FIELD_LABEL);
const ACT: Record<string, string> = { kill: '격리', alert: '경고', allow: '허용' };
const KIND: Record<string, string> = { exec: '실행', open: '파일', connect: '통신', dns: '조회', sequence: '연쇄' };

export function fieldText(field: string, v: unknown): string {
  if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) return field === 'containers' ? '모든 컨테이너' : '—';
  if (field === 'disabled') return v ? '사용 안 함' : '사용';
  if (typeof v === 'boolean') return v ? '켬' : '끔';
  if (field === 'action' || field === 'directIp') return ACT[String(v)] ?? String(v);
  if (field === 'kind') return KIND[String(v)] ?? String(v);
  if (field === 'windowSeconds') return `${v}초`;
  if (field === 'steps' && Array.isArray(v)) return `${v.length}단계`;
  if (Array.isArray(v)) return v.map(String).join(' · ');
  return String(v);
}

export interface FieldDiff {
  field: string;
  label: string;
  before: string;
  after: string;
}
const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
// 두 정책 값의 차이(칸 순서 고정). disabled · dryRun 은 없음 = false 로 본다
export function ruleDiff(before: Rule | undefined, after: Rule | undefined): FieldDiff[] {
  const out: FieldDiff[] = [];
  const val = (r: Rule | undefined, f: string) => {
    const v = r ? (r as unknown as Record<string, unknown>)[f] : undefined;
    return (f === 'disabled' || f === 'dryRun') && r ? !!v : v;
  };
  for (const f of FIELDS) {
    const a = val(before, f);
    const b = val(after, f);
    if (same(a, b) || (!before && (b === false || b === undefined))) continue;
    out.push({ field: f, label: FIELD_LABEL[f], before: before ? fieldText(f, a) : '—', after: after ? fieldText(f, b) : '—' });
  }
  return out;
}

// 펼쳐 볼 바뀐 값이 있나(전후 값이 남은 기록) — ruleId 를 주면 그 정책만
export function changeHasDiff(c: Change, ruleId?: string) {
  const ids = ruleId ? [ruleId] : (c.ruleIds ?? []);
  return ids.some((id) => !!(c.before?.[id] || c.after?.[id]));
}
