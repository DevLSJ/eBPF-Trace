import type { ProposalChange } from './types';

export const LIST_LABEL = { packages: '패키지', images: '이미지', hosts: '도메인' } as const;
const FIELD_LABEL: Record<string, string> = { allowPaths: '예외 경로', allowHosts: '허용 도메인', allowCidrs: '허용 대역' };

export function changeText(c: ProposalChange): string {
  if (c.op === 'block') return `${LIST_LABEL[c.list] ?? c.list} 차단 ${c.value}`;
  if (c.op === 'except') return `${c.ruleId} ${FIELD_LABEL[c.field] ?? c.field} += ${c.value}`;
  return JSON.stringify(c);
}

