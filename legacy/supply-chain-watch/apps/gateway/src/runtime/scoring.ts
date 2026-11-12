// 런타임 룰 점수화 + 인시던트 그룹화 (docs/13 §6.2).
// 에이전트는 룰 ID와 원시 사실만 보내고, 등급은 gateway가 매긴다.
import type { RiskLevel, RuntimeRuleId } from '@scw/shared-types';

const RULE_RISK: Record<RuntimeRuleId, RiskLevel> = {
  PROC_CHAIN_SUSPECT: 'HIGH',
  NET_UNALLOWED_CONNECT: 'HIGH',
  TOOL_EXEC_IN_CONTAINER: 'MEDIUM',
  TMP_EXEC: 'MEDIUM',
};

const RISK_SCORE: Record<RiskLevel, number> = { HIGH: 92, MEDIUM: 55, LOW: 10 };

export function riskForRule(rule: string): RiskLevel {
  return RULE_RISK[rule as RuntimeRuleId] ?? 'LOW';
}

export function scoreForRisk(risk: RiskLevel): number {
  return RISK_SCORE[risk];
}

// 인시던트 그룹화: 같은 컨테이너에서 창(window) 안에 연이어 온 이벤트는 한 프로세스 트리로 본다.
const WINDOW_MS = 5000;

interface OpenIncident {
  key: string;
  lastAt: number;
}

const open = new Map<string, OpenIncident>(); // container → 진행 중 인시던트
let seq = 0;

export function incidentKeyFor(container: string, at: number = Date.now()): string {
  const cur = open.get(container);
  if (cur && at - cur.lastAt <= WINDOW_MS) {
    cur.lastAt = at;
    return cur.key;
  }
  const key = `${container}:${++seq}:${at}`;
  open.set(container, { key, lastAt: at });
  return key;
}
