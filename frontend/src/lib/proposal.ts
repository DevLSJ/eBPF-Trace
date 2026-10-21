import type { BlockList, Preview, Proposal, ProposalChange } from './types';

export const LIST_LABEL = { packages: '패키지', images: '이미지', hosts: '도메인' } as const;
const FIELD_LABEL: Record<string, string> = { allowPaths: '예외 경로', allowHosts: '허용 도메인', allowCidrs: '허용 대역' };

export function changeText(c: ProposalChange): string {
  if (c.op === 'block') return `${LIST_LABEL[c.list] ?? c.list} 차단 ${c.value}`;
  if (c.op === 'except') return `${c.ruleId} ${FIELD_LABEL[c.field] ?? c.field} += ${c.value}`;
  return JSON.stringify(c);
}

// 제안 적용 확인 대화상자의 「함께 일어나는 일」(10/20 B) — 제안의 변경 + 이미 계산한 미리보기 결과만 쓴다(새 계산 없음)
export function applyEffects(p: Proposal, pv: Preview | null): string[] {
  const out: string[] = [];
  const blocks = p.changes.filter((x): x is Extract<ProposalChange, { op: 'block' }> => x.op === 'block');
  const ex = p.changes.filter((x): x is Extract<ProposalChange, { op: 'except' }> => x.op === 'except');
  if (blocks.length) {
    const by = (l: BlockList) => blocks.filter((x) => x.list === l).length;
    const parts = (['packages', 'images', 'hosts'] as const).filter((l) => by(l)).map((l) => `${LIST_LABEL[l]} ${by(l)}`);
    out.push(`차단 목록 +${blocks.length} (${parts.join(' · ')})`);
  }
  for (const b of blocks.filter((x) => x.list === 'packages')) out.push(`다음 sg-install 부터 ${b.value} 는 설치 전 거부(컨테이너를 띄우지 않음)`);
  for (const b of blocks.filter((x) => x.list === 'images')) out.push(`이미지 ${b.value} — 이 이미지로 시작하는 컨테이너는 다음 시작 때 격리(지금 실행은 그대로)`);
  if (blocks.some((x) => x.list === 'hosts')) out.push('도메인 차단은 시스템 규칙 blocklist-hosts 로 바로 집행(런타임 · 설치 모두)');
  if (ex.length) out.push(`규칙 예외 +${ex.length} (${[...new Set(ex.map((x) => x.ruleId))].join(', ')}) — 엔진에 바로 반영`);
  if (pv) out.push(`과거 위반 ${pv.changed.length}건의 탐지 결과가 바뀜 (통과로 ${pv.counts.toNormal} · 차단으로 ${pv.counts.toBlocked})`);
  out.push(`건 ${p.caseId} 종결 · 변경 이력에 남음`);
  return out;
}
