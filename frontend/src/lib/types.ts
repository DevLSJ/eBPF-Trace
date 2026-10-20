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
  caseId?: string | null; // 이 위반이 속한 건 (API 계약 10/15)
  install?: { id: string; label: string } | null; // 설치 검사 위반이면 세션 · 패키지 이름
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
  // 서버 설정 보기(10/16): 감시 범위 · 제외. 옛 백엔드는 없음
  watchContainers?: string[];
  ignoreContainers?: string[];
}

export type WsMessage = { type: 'verdict'; data: Verdict } | { type: 'stats'; data: Stats } | { type: 'case'; data: Case };

export const KINDS: Kind[] = ['exec', 'open', 'connect'];

// 탐지 결과(엔진이 내리는 것): 정상 · 경고 · 격리 대상(dry-run/실패) · 격리됨. 사람의 결론은 「판정」(Decision)
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

// ── 설치 검사 · 판정 흐름 (Claude Docs 「API 계약」 탭, 2026-10-15) ──

export type InstallStatus = 'running' | 'passed' | 'isolated' | 'warned' | 'failed' | 'unknown' | 'refused';
export type Manager = 'pip' | 'npm' | 'cargo';

export const INSTALL_STATUS_LABEL: Record<InstallStatus, string> = {
  running: '진행 중',
  passed: '통과',
  isolated: '격리',
  warned: '경고',
  failed: '설치 실패',
  unknown: '결과 미확인',
  refused: '설치 전 거부',
};
export const INSTALL_STATUSES = Object.keys(INSTALL_STATUS_LABEL) as InstallStatus[];
export const MANAGERS: Manager[] = ['pip', 'npm', 'cargo'];

export interface InstallViolation extends Verdict {
  count: number;
}

export interface InstallActivity {
  kinds: Partial<Record<Kind, number>>;
  hosts: { host: string; ip: string; port: number; count: number; level: Level }[];
  programs: { comm: string; args: string; count: number; level: Level }[];
}

export interface InstallSession {
  id: string;
  manager: Manager;
  packages: string[];
  container: string;
  containerId?: string;
  image: string;
  startedAt: string;
  finishedAt?: string | null;
  exitCode?: number | null;
  containerExitedAt?: string | null;
  status: InstallStatus;
  refusedBy?: { list: BlockList; value: string } | null;
  caseId?: string | null;
  // 목록 응답에는 없을 수 있다 — 상세(GET /api/installs/{id})에만
  violations?: InstallViolation[];
  violationCount?: number;
  hostCount?: number;
  activity?: InstallActivity;
}

export type Decision = 'pending' | 'malicious' | 'false_positive';
export type CaseState = 'open' | 'decided' | 'closed';

export const DECISION_LABEL: Record<Decision, string> = {
  pending: '판정 대기',
  malicious: '악성',
  false_positive: '오탐',
};

export interface Case {
  id: string;
  source: 'install' | 'runtime';
  installId?: string | null;
  container: string;
  // 화면 표기: 설치 건 = 입력 그대로(「pip ./reqeusts」), 런타임 건 = 컨테이너 이름. 정규화 키는 package
  label?: string;
  image: string;
  package?: string | null;
  openedAt: string;
  level: Level;
  violations: number;
  ruleIds: string[];
  state: CaseState;
  decision: Decision;
  decidedAt?: string | null;
  decidedBy?: string | null;
  note?: string;
  proposalId?: string | null;
  closedAt?: string | null;
}

export type BlockList = 'packages' | 'images' | 'hosts';

export type ProposalChange =
  | { op: 'block'; list: BlockList; value: string }
  | { op: 'except'; ruleId: string; field: string; value: string };

export interface Proposal {
  id: string;
  caseId: string;
  decision: Exclude<Decision, 'pending'>;
  state: 'draft' | 'applied' | 'discarded';
  createdAt: string;
  createdBy: string;
  appliedAt?: string | null;
  appliedBy?: string | null;
  changes: ProposalChange[];
  // 자동으로 만들지 못한 변경 안내(예: 실행 규칙은 정책 탭에서 직접 수정)
  notes?: string[];
}

export interface Preview {
  evaluated: number;
  changed: { auditId: number; before: Level | Action | string; after: Level | string; container: string; ruleId: string }[];
  counts: { toNormal: number; toBlocked: number };
  // 과거 이벤트를 바꾸지 않는 변경(패키지 · 이미지 차단) — 「다음 설치 · 기동부터 적용」
  nextOnly?: { list: BlockList; value: string }[];
}

export interface BlockEntry {
  value: string;
  caseId?: string | null;
  at: string;
  by: string;
}
export type Blocklist = Record<BlockList, BlockEntry[]>;

export interface Change {
  id: string;
  at: string;
  by: string;
  kind: 'proposal_applied' | 'policy_edit' | 'policy_replace' | 'blocklist_remove' | string;
  caseId?: string | null;
  proposalId?: string | null;
  summary: string;
}

export interface OsvResult {
  ecosystem: string;
  name: string;
  vulns: number;
  ids: string[];
  queriedAt: string;
  source: string;
  error: string | null;
}

// 시스템 규칙 — 차단 목록(도메인)에서만 관리하고 정책 화면에서 직접 고치지 않는다
export const SYSTEM_RULES = new Set(['blocklist-hosts']);

// 건 표기: label(입력 그대로) → 없으면(옛 백엔드) 정규화 패키지 · 컨테이너
export const caseLabel = (c: Case) => c.label || (c.source === 'install' ? (c.package ?? c.container) : c.container);

// eBPF 수집 종합(10/16) — GET /api/summary?range=1h|24h|7d (백엔드 internal/summary)
export type SummaryRange = '1h' | '24h' | '7d';
export interface SummaryTop {
  ruleId?: string;
  container?: string;
  count: number;
  level: Level;
}
export interface Summary {
  range: SummaryRange | string;
  from: string;
  to: string;
  bucketSec: number;
  collected: { total: number; byKind: Record<'exec' | 'open' | 'connect', number> };
  violations: { total: number; killed: number; alert: number; held: number };
  isolatedContainers: number;
  series: { t: string; exec: number; open: number; connect: number; killed: number; alert: number }[];
  topRules: SummaryTop[];
  topContainers: SummaryTop[];
  installs: { total: number; passed: number; isolated: number; warned: number; refused: number; failed: number; running: number };
  decisions: { malicious: number; falsePositive: number; pending: number };
  blocklist: { packages: number; images: number; hosts: number };
}

// 공급망 검사(10/16) — GuardDog(악성 코드 패턴) · OSV-Scanner(알려진 취약점). 백엔드 internal/scan
export interface ScanFinding {
  rule: string;
  category: 'threat' | 'capability';
  message: string;
  file: string;
  line: number;
  match: string;
}
export interface ScanVuln {
  package: string;
  version: string;
  ecosystem: string;
  direct: boolean;
  count: number;
  maxSeverity: string;
  ids: string[];
}
export interface Scan {
  id: string;
  target: { kind: 'package' | 'repo' | 'file'; manager?: string; name?: string; version?: string; url?: string; fileName?: string; size?: number; label: string };
  status: 'running' | 'done' | 'failed';
  startedAt: string;
  finishedAt: string | null;
  error?: string;
  verdict?: 'malicious' | 'vulnerable' | 'clean';
  risk: { score: number; label: string } | null;
  engines: { name: string; version: string }[] | null;
  findings?: ScanFinding[] | null;
  vulns?: ScanVuln[] | null;
  files?: Record<string, string> | null;
  caseId: string | null;
  threats: number;
  capabilities: number;
  vulnCount: number;
  vulnMax: number | null;
}
