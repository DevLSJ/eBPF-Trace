// backend/internal/model · stats · rules 와 1:1 스키마

export type Kind = 'exec' | 'open' | 'connect';
export type Action = 'alert' | 'kill';

export interface Event {
  kind: Kind;
  timestamp: string;
  containerId: string;
  containerName: string;
  imageName: string;
  comm: string;
  pid: number;
  args?: string; // exec
  path?: string; // open
  dstIp?: string; // connect
  dstPort?: number; // connect
  dstHost?: string; // connect — 같은 컨테이너의 DNS 응답으로 알아낸 목적지 도메인
}

export interface Verdict {
  event: Event;
  matched: boolean;
  ruleId?: string;
  action?: Action;
  reason?: string;
  dryRun?: boolean; // kill 대상이지만 dry-run이라 종료 안 함
  enforced?: boolean; // 실제 격리됨
  enforceError?: string;
}

export interface AuditEntry extends Verdict {
  id: number;
}

export interface Rule {
  id: string;
  description?: string;
  kind: Kind;
  action: Action;
  dryRun?: boolean;
  disabled?: boolean;
  containers?: string[];
  denyComms?: string[];
  denyArgs?: string[];
  denyPaths?: string[];
  allowPaths?: string[];
  allowPorts?: number[];
  allowCidrs?: string[];
  denyPorts?: number[];
  denyCidrs?: string[];
  allowHosts?: string[];
  denyHosts?: string[];
}

export interface TrendPoint {
  t: string;
  exec: number;
  open: number;
  connect: number;
  violations: number;
}

export interface Stats {
  timestamp: string;
  totalEvents: number;
  eventsLastMinute: number;
  eventsPerSec: number;
  totalViolations: number;
  riskScore: number;
  killed: { id: string; name: string; at: string }[];
  killedCount: number;
  topContainers: { name: string; violations: number }[];
  trend: TrendPoint[];
  wsClients: number;
  dropped: number;
  enforceKill: boolean;
  source: string;
}

export interface Info {
  source: 'gadget' | 'mock';
  gadgets: Kind[];
  enforceKill: boolean;
  authRequired: boolean;
  gadgetVersion: string;
}

export type WsMessage = { type: 'verdict'; data: Verdict } | { type: 'stats'; data: Stats };

export const KINDS: Kind[] = ['exec', 'open', 'connect'];

// 판정 표시 단계: 정상 · 경고 · 격리 대상(dry-run/실패) · 격리됨
export type Level = 'normal' | 'alert' | 'held' | 'killed';

export const LEVEL_LABEL: Record<Level, string> = {
  normal: '정상',
  alert: '경고',
  held: '격리 대상',
  killed: '격리됨',
};

export function levelOf(v: Verdict): Level {
  if (!v.matched) return 'normal';
  if (v.action !== 'kill') return 'alert';
  return v.enforced ? 'killed' : 'held';
}

export function detailOf(e: Event): string {
  switch (e.kind) {
    case 'exec':
      return e.args || e.comm;
    case 'open':
      return e.path ?? '';
    case 'connect':
      return e.dstHost ? `${e.dstIp}:${e.dstPort} (${e.dstHost})` : `${e.dstIp}:${e.dstPort}`;
  }
}
