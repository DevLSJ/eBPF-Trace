import type { Rule, Verdict } from './types';

// 연쇄 규칙(kind: sequence, 11/04) 화면 문구 — 목업 mock/shared/screens.js(seqSummary · seqRow) 확정 문구 그대로.
// 편집은 「고급 · YAML」만, 저장 전 확인은 요약 + 미리보기 불가 안내(+ dryRun 없는 kill 경고), 미리보기 API 를 부르지 않는다.

export const SEQ_NO_PREVIEW =
  '연쇄 규칙은 미리보기를 할 수 없습니다 — 감사 로그에는 위반만 저장돼 연쇄의 앞 단계(정상 실행 · 연결)가 남아 있지 않습니다. 시험 운영(dryRun)으로 저장해 실제 판정을 지켜본 뒤 격리로 바꾸세요';
export const SEQ_KILL_WARN = '시험 운영(dryRun) 없이 격리(kill)로 저장합니다 — 오탐이면 정상 컨테이너가 바로 종료됩니다. 먼저 dryRun: true 로 지켜보기를 권합니다';
export const SEQ_YAML_ONLY = '연쇄 규칙(sequence)은 「고급 · YAML」로만 편집합니다 — 쉬운 설정 · 폼에는 단계가 없습니다';

// 「연쇄 3단계 · 10초 안 · 시험(격리 대상)」 — 꺼진 규칙은 앞에 「[꺼짐] 」
export function seqSummary(r: Rule): string {
  const act = r.action === 'kill' ? (r.dryRun ? '시험(격리 대상)' : '격리') : '알림';
  return `${r.disabled ? '[꺼짐] ' : ''}연쇄 ${(r.steps ?? []).length}단계 · ${r.windowSeconds ?? 0}초 안 · ${act}`;
}

// 감사 · 이벤트 상세 「연쇄」 행 — 「규칙 X — exec wget(0.0초) → connect …(+2.1초) → open …(+2.4초)」.
// exec 는 프로세스 이름, 나머지는 상세(백엔드 사유와 같다). 단일 규칙이 이겨 연쇄가 주석이면 끝에 「 · 판정은 <규칙>」
export function seqLine(v: Pick<Verdict, 'ruleId' | 'sequence'>): string | null {
  const sq = v.sequence;
  if (!sq?.steps?.length) return null;
  const t0 = Date.parse(sq.steps[0].timestamp);
  const parts = sq.steps.map((x, i) => `${x.kind} ${x.kind === 'exec' && x.comm ? x.comm : x.detail}(${i ? '+' : ''}${((Date.parse(x.timestamp) - t0) / 1000).toFixed(1)}초)`);
  return `규칙 ${sq.ruleId} — ${parts.join(' → ')}${v.ruleId && v.ruleId !== sq.ruleId ? ` · 판정은 ${v.ruleId}` : ''}`;
}
