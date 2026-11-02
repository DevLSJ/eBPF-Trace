import { severity } from './topology';
import { detailOf, levelOf, type InstallViolation, type Kind, type Level } from './types';

// 공격 체인 한 단계(설치 검사 위반 · 토폴로지 노드 공통)
export interface ChainStepView {
  id: string;
  kind: Kind;
  label: string;
  rule?: string;
  level: Level;
  count?: number;
}

// dns 는 통신 단계(3)에서 connect 보다 앞(10/30 계약 §1)
const KIND_ORDER: Record<Kind, number> = { exec: 1, open: 2, dns: 3, connect: 4 };

export const sortSteps = (steps: ChainStepView[]) =>
  [...steps].sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || severity[b.level] - severity[a.level]);

export function stepsFromViolations(vs: InstallViolation[]): ChainStepView[] {
  return sortSteps(
    vs.map((v, i) => ({
      id: `v${i}`,
      kind: v.event.kind,
      label: v.event.kind === 'exec' ? v.event.args || v.event.comm : detailOf(v.event),
      rule: v.ruleId,
      level: levelOf(v),
      count: v.count,
    })),
  );
}

