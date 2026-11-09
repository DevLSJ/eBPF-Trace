// backend/internal/model · stats · rules 와 1:1 스키마

export type Kind = 'exec' | 'open' | 'connect' | 'dns';
export type Action = 'alert' | 'kill';
// 규칙 kind(11/04) — 이벤트 kind 4개 + 연쇄 규칙 sequence. 이벤트에는 sequence 가 없다(backend model.KindSequence 는 Kinds 밖)
export type RuleKind = Kind | 'sequence';

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
  // connect — 이벤트가 올 때 trace_dns 가 돌고 있었는지(10/20). true 인데 dstHost 가 없고 공인 IP 면 「도메인 조회 없는 IP 직접 연결」.
  // connect 에는 false 도 명시해 온다(W20, false = trace_dns 꺼짐 → 판단 불가). 없음 = 필드가 생기기 전 옛 기록. 다른 종류에는 없다
  dnsTraced?: boolean;
  // dns(10/30) — 질의 유형(IG 열거 그대로 대문자: A AAAA TXT …). 질의 이름은 dstHost(소문자 · 끝 점 없음)
  qtype?: string;
}

// 격리 타임라인(10/30 계약 §3) — RFC3339Nano UTC. 해당 없으면 키 생략
export interface Timeline {
  detectedAt: string;
  matchedAt: string;
  evidenceStartedAt?: string;
  evidenceDoneAt?: string;
  killedAt?: string;
  notifiedAt?: string;
}
export interface IsolationRef {
  auditId: number;
  timeline: Timeline;
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
  // 11/06 라벨 연동: kill 정책인데 격리 범위 밖이라 보류 — "label" = 격리 라벨(supplyguard.enforce) 없음
  enforceSkip?: 'label';
  // 격리 타임라인(10/30) — matched 판정만, 옛 백엔드는 없음
  timeline?: Timeline;
  // 이 이벤트로 완성된 연쇄(11/04, backend model.SequenceHit). ruleId 와 같으면 연쇄가 판정, 다르면 단일 규칙이 이기고 연쇄는 주석
  sequence?: SequenceHit;
}

// 연쇄 1건(11/04) — 단계마다 그 단계를 채운 이벤트 요약(detail = Event.Detail())
export interface SequenceHit {
  ruleId: string;
  action: Action;
  dryRun?: boolean;
  steps: SequenceStep[];
}
export interface SequenceStep {
  kind: Kind;
  timestamp: string;
  comm: string;
  pid: number;
  detail: string;
}

export interface AuditEntry extends Verdict {
  id: number;
  caseId?: string | null; // 이 위반이 속한 건 (API 계약 10/15)
  install?: { id: string; label: string } | null; // 설치 검사 위반이면 세션 · 패키지 이름
}

// GET /api/audit?offset=&limit= 응답(11/04, backend api.AuditPage) — total 은 필터 뒤 전체 건수
export interface AuditPage {
  items: AuditEntry[];
  total: number;
  offset: number;
  limit: number;
}

export interface Rule {
  id: string;
  description?: string;
  kind: RuleKind;
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
  // 도메인 조회 없는 IP 직접 연결(10/20, connect 만) — 규칙의 action 대신 이 값. 비면 옛 동작(백엔드 rules/engine.go)
  directIp?: DirectIp;
  // dns(10/30, kind: dns 만) — 금지 질의 유형(대문자) · 이름 길이 상한(1..253) · 라벨 길이 상한(1..63). allowHosts · denyHosts 는 재사용
  denyQtypes?: string[];
  maxNameLength?: number;
  maxLabelLength?: number;
  // sequence(11/04, kind: sequence 만) — 창(1~60초) 안에 단계(2~5개)가 순서대로. 단계는 kind + 그 kind 의 조건만
  windowSeconds?: number;
  steps?: RuleStep[];
}
// 단일 규칙(이벤트 kind) — 쉬운 설정 · 고급 폼이 다루는 규칙
export type SingleRule = Rule & { kind: Kind };
export const isSingleRule = (r: Rule): r is SingleRule => r.kind !== 'sequence';
// 연쇄 규칙의 한 단계 — 헤더 필드(id · action · dryRun …) 없이 kind 와 조건만(backend V7)
export type RuleStep = Omit<Rule, 'id' | 'description' | 'kind' | 'action' | 'dryRun' | 'disabled' | 'containers' | 'windowSeconds' | 'steps'> & { kind: Kind };

export type DirectIp = 'allow' | 'alert' | 'kill';

// 정책 API 가 내보내는 정책(11/09, backend api.policyView) — Rule + 마지막 수정(그 정책을 다룬 마지막 변경 기록의 시각 · 처리자).
// 기록이 없으면(시드 정책) 두 키 없음. 저장(POST /api/policies)은 모르는 칸을 거절하므로 보낼 때는 stripView 로 뺀다
export interface PolicyView extends Rule {
  updatedAt?: string;
  updatedBy?: string;
}
export function stripView<R extends Rule>(r: R): Rule {
  const { updatedAt: _a, updatedBy: _b, ...rule } = r as R & PolicyView;
  void _a;
  void _b;
  return rule;
}

export interface TrendPoint {
  t: string;
  exec: number;
  open: number;
  connect: number;
  dns?: number; // 10/30 — 옛 백엔드는 없음
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
  // W16: 로그인(쿠키 세션)이 붙은 뒤로는 화면이 이 값으로 갈라지지 않는다 — 역할은 /api/auth/me
  authRequired?: boolean;
  gadgetVersion: string;
  // 서버 설정 보기(10/16): 감시 범위 · 제외. 옛 백엔드는 없음
  watchContainers?: string[];
  ignoreContainers?: string[];
  // 10/20: trace_dns 가 돌고 있는지 — off 면 도메인 미확인 연결은 fail-open(셸 상단 배너). 옛 백엔드는 없음
  dnsResolve?: 'ok' | 'off';
  // 10/20: 외부 알림 채널 상태(호스트만). 알림 서비스가 없는 백엔드는 생략
  notify?: NotifyStatus;
  // 10/20: AI 도우미(POST /api/chat) 사용 가능(ANTHROPIC_API_KEY 또는 OLLAMA_URL) — false 면 탭 안에서 켜는 법을 안내. 옛 백엔드는 없음
  chat?: boolean;
  // 11/09: 쓰는 모델 — claude 면 질문 · 조회한 사실이 Anthropic API 로 나간다(설정 화면 「AI 도우미」 절). 챗봇이 꺼져 있거나 옛 백엔드면 없음
  chatEngine?: ChatEngine;
  // 10/20: 실제로 쓰이는 컨테이너 발견 방식 fanotify | docker-events(mock · 가젯 시작 전은 빈 값) · docker-events 일 때 놓칠 수 있는 구간 안내
  discovery?: string;
  discoveryNote?: string;
  // 10/30: 시연 실행 API(DEMO_ENABLED) — true 일 때만 대시보드 「시연」 카드(관리자). 옛 백엔드는 없음
  demo?: boolean;
}

// ── 시연 실행(10/30 계약 §2) ──
export type DemoScenario = 'all' | 'shell' | 'revshell' | 'direct-ip' | 'domain' | 'dns-exfil' | 'benign' | 'chain';
export const DEMO_SCENARIOS: DemoScenario[] = ['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil', 'benign', 'chain'];
export type DemoStatus = 'running' | 'finished' | 'timeout' | 'failed' | 'refused';
export interface DemoRun {
  id: string;
  scenario: DemoScenario;
  container: string;
  installId: string;
  startedAt: string;
  finishedAt: string | null;
  status: DemoStatus;
  exitCode: number | null;
  simulated: boolean;
  // 11/04 「왜」 보충(backend demo/explain.go) — GET /api/demo 의 running · last 에만(POST 응답 · 거부 · 옛 백엔드는 없음)
  explain?: DemoExplain | null;
}
// 결과를 정한 판정(세션 위반 중 가장 강한 것, 같으면 이른 것) + 지금 정책의 규칙 설명 · 조건 요약(규칙이 지워졌으면 "")
export interface DemoDecider {
  ruleId: string;
  description: string;
  condition: string;
  action: Action;
  dryRun: boolean;
  enforced: boolean;
  reason: string;
  // 판정을 만든 이벤트 원문(빈 필드는 "" · 0 으로 올 수 있다)
  event: Pick<Event, 'kind' | 'timestamp' | 'comm' | 'pid'> & Partial<Pick<Event, 'args' | 'path' | 'dstIp' | 'dstPort' | 'dstHost' | 'qtype'>>;
  sequence?: string; // 이 판정에 연쇄가 붙었으면 그 규칙 id
}
export interface DemoSequenceStep {
  kind: Kind;
  condition: string;
  matched: boolean;
  event: SequenceStep | null;
  gapMs: number | null; // 앞 단계 이벤트에서 걸린 ms(첫 단계 · 미충족은 null)
}
// chain 시나리오의 연쇄 규칙 진행 — 완성(판정에 sequence 기록)이 아니면 위반 이벤트로 단계를 차례로 맞춘 결과
export interface DemoSequence {
  ruleId: string;
  description: string;
  action: Action;
  dryRun: boolean;
  disabled: boolean;
  windowSeconds: number;
  completed: boolean;
  steps: DemoSequenceStep[];
}
export interface DemoExplain {
  decidedBy: DemoDecider | null; // null = 위반 없음(실행 중이면 아직 판정 없음)
  sequence: DemoSequence | null;
}
export interface DemoState {
  enabled: boolean;
  scenarios: DemoScenario[];
  running: DemoRun | null;
  last: DemoRun | null;
}

// ── AI 도우미(10/20, 백엔드 internal/chat/types.go) ──
export interface ChatTurn {
  role: 'user' | 'assistant';
  text: string;
}
export interface ChatRequest {
  question: string;
  page: string; // 지금 보는 화면 경로(+쿼리)
  history: ChatTurn[]; // 최근 6턴
}
export interface ChatLink {
  label: string;
  href: string; // React 경로
}
// facts 이벤트 — 서버가 확정한 값. status 는 모델 문장보다 우선, sentences 는 모델이 꺼져 있을 때 답 대신 보인다
export interface ChatFacts {
  intent: string;
  tool?: string;
  status?: string;
  sentences?: string[] | null;
  cases?: unknown[];
  scan?: unknown;
}

export interface NotifyChannel {
  name: string; // webhook | slack
  host: string;
  sent: number;
  failed: number; // 재시도까지 모두 실패해 포기한 수
  dropped?: number;
  queued?: number;
  lastError?: string;
  lastAt?: string; // 마지막으로 성공한 시각
}
export interface NotifyStatus {
  enabled: boolean;
  channels: NotifyChannel[];
  sent: number;
  failed: number;
  dropped?: number;
  suppressed?: number;
  lastError?: string;
}

export type WsMessage = { type: 'verdict'; data: Verdict } | { type: 'stats'; data: Stats } | { type: 'case'; data: Case };

export const KINDS: Kind[] = ['exec', 'open', 'connect', 'dns'];
// 종류 긴 이름(10/30 계약 §1 라벨) — 배지 툴팁 · 필터
export const KIND_LONG: Record<Kind, string> = { exec: '프로그램 실행', open: '파일 열기', connect: '외부 통신', dns: '도메인 조회' };

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
    case 'dns':
      // 계약 §1: "<name> (<qtype>)" — Go Detail() · 목업 · sg-install 과 같은 문구
      return `${e.dstHost ?? ''} (${e.qtype ?? ''})`;
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
  // 격리 세션의 첫 kill 판정 타임라인(10/30) — 옛 백엔드는 없음
  isolation?: IsolationRef | null;
  // 11/04 종합 판정: 세션 시작 때 서버가 시작한 같은 패키지(첫 패키지)의 정적 검사. 저장 필드(scanId · scanSkip)는 옛 세션 · 옛 백엔드에 없다
  scanId?: string | null;
  scanSkip?: InstallScanSkip | '';
  // 읽을 때 계산한 정적 검사 요약 — 없으면(옛 세션 · 옛 백엔드) 목록 「—」 + 상세는 OSV 이름 조회 칸(하위 호환)
  scan?: InstallScan;
}

// 공급망 검사 판정(11/03 3단계) — 공급망 검사 화면 · 설치 목록 「정적 검사」 열이 같은 배지(components/Badges ScanVerdictBadge)를 쓴다
export type ScanVerdict = 'malicious' | 'vulnerable' | 'caution' | 'clean';
export const SCAN_VERDICT_LABEL: Record<ScanVerdict, string> = {
  malicious: '악성 의심',
  vulnerable: '취약점 있음',
  caution: '주의', // 점수 ≥ 5 인데 설치 시점 규칙 없음(런타임 휴리스틱만)
  clean: '위협 없음',
};

// 11/04 종합 판정 — 자동 정적 검사를 건너뛴 이유: 로컬 패키지 · cargo · 대기열 가득 · 검사기 없음 · 이름 해석 실패
export type InstallScanSkip = 'local' | 'unsupported' | 'busy' | 'off' | 'invalid';
export interface InstallScan {
  id: string; // 건너뜀이면 ''
  status: 'running' | 'done' | 'failed' | 'skipped';
  verdict?: ScanVerdict; // done 만
  label: string; // 「pip requests」 — 공급망 검사 대상 라벨
  version: string; // 받은 버전(Target.Version) — 범위 · 미지정은 최신
  riskScore: number | null;
  installThreats: number;
  threats: number;
  vulnCount: number;
  error?: string;
  skip?: InstallScanSkip | '';
  reused?: boolean; // 그 검사를 시작한 세션이 이 세션이 아님(실행 중 합류 · 24시간 재사용)
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
  source: 'install' | 'runtime' | 'scan'; // scan: 공급망 검사에서 「차단 목록에 올리기」(10/16)
  installId?: string | null;
  scanId?: string | null;
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
  // 런타임 격리 건의 타임라인(10/30) — 옛 백엔드는 없음
  isolation?: IsolationRef | null;
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
  kind: 'proposal_applied' | 'proposal_discarded' | 'policy_edit' | 'policy_replace' | 'blocklist_remove' | 'policy_revert' | 'demo_run' | 'integration_test' | string;
  caseId?: string | null;
  proposalId?: string | null;
  summary: string;
  // 확인 대화상자의 사유(W15 · W18) — 적용 · 버림 · 차단 해제 · 되돌리기(필수). 옛 백엔드는 없음
  reason?: string;
  // 11/09(backend model.Change): 이 변경이 다룬 정책 id · 정책 id → 변경 전 · 후 정책 전체(키가 없으면 그때 그 정책이 없었음 — 만듦 · 지움) ·
  // 되돌리기가 되돌린 변경 id. 옛 백엔드 · 정책과 무관한 변경은 없음
  ruleIds?: string[];
  before?: Record<string, Rule>;
  after?: Record<string, Rule>;
  revertOf?: string;
}
// GET /api/changes?offset=… 응답(11/09, backend api.ChangesPage) — total 은 거른 뒤 전체 수. rule 로 거르면 before · after 도 그 정책 값만
export interface ChangesPage {
  items: Change[];
  total: number;
  offset: number;
  limit: number;
}

// 변경 이력 종류 이름 — 정책 화면 · 감사 화면이 같이 쓴다
export const CHANGE_KIND_LABEL: Record<string, string> = {
  proposal_applied: '제안 적용',
  proposal_discarded: '제안 버림',
  policy_edit: '정책 편집',
  policy_replace: 'YAML 교체',
  blocklist_remove: '차단 해제',
  policy_revert: '정책 되돌림',
  demo_run: '시연 실행',
  integration_test: '연결 테스트',
};

// 판정 미리보기(W15) — POST /api/cases/{id}/preview → 확인 대화상자의 「함께 일어나는 일」(서버 계산 그대로)
export interface DecisionEffect {
  kind: 'blocklist' | 'already_blocked' | 'package' | 'image' | 'host' | 'exception' | 'none' | 'note' | 'next' | string;
  text: string;
  count?: number;
}
export interface DecisionPreview {
  caseId: string;
  decision: Exclude<Decision, 'pending'>;
  changes: ProposalChange[];
  notes: string[];
  effects: DecisionEffect[];
}

// 새 기본 규칙(10/20) — GET /api/policies/defaults
export interface PolicyDefaults {
  missing: Rule[];
  differs: { id: string; default: Rule; current: Rule }[];
}

// kill 직전 증거(10/20) — GET /api/evidence?container= (최근 것부터)
export interface Evidence {
  id: string;
  containerId: string;
  containerName: string;
  image: string;
  collectedAt: string;
  logs: string;
  changes: { kind: 'A' | 'C' | 'D' | string; path: string }[] | null;
  processes: { pid: number; user: string; cmd: string }[] | null;
  partial: boolean;
  durationMs: number;
  error?: string;
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
  // byKind.dns · series[].dns 는 옛 백엔드 호환으로 선택(10/30)
  collected: { total: number; byKind: Record<'exec' | 'open' | 'connect', number> & { dns?: number } };
  violations: { total: number; killed: number; alert: number; held: number };
  isolatedContainers: number;
  series: { t: string; exec: number; open: number; connect: number; dns?: number; killed: number; alert: number }[];
  topRules: SummaryTop[];
  topContainers: SummaryTop[];
  installs: { total: number; passed: number; isolated: number; warned: number; refused: number; failed: number; running: number };
  decisions: { malicious: number; falsePositive: number; pending: number };
  blocklist: { packages: number; images: number; hosts: number };
  // 격리 지연(10/30): 범위 안 killedAt 있는 행, ms = killedAt − detectedAt. 없으면 count 0 · 나머지 null. 옛 백엔드는 없음
  isolation?: { count: number; medianMs: number | null; p95Ms: number | null; maxMs: number | null };
  // 직전 기간(R2 11/04): 바로 앞 같은 길이 기간의 같은 숫자 — KPI 증감 줄. 그 기간에 기록이 없으면 null, 옛 백엔드는 키 없음
  previous?: SummaryPrevious | null;
}
export interface SummaryPrevious {
  collected: number; // collected.total
  violations: number; // violations.total
  isolatedContainers: number;
  installs: number; // installs.total
  decided: number; // decisions.malicious + falsePositive
  isolationMedianMs: number | null; // isolation.medianMs — 그 기간에 격리가 없으면 null
}

// 공급망 검사(10/16) — GuardDog(악성 코드 패턴) · OSV-Scanner(알려진 취약점). 백엔드 internal/scan
export interface ScanFinding {
  rule: string;
  category: 'threat' | 'capability';
  message: string;
  file: string;
  line: number;
  match: string;
  /** 테스트 코드(tests/ · test_*.py 등)의 탐지 — 위험 점수 · 판정 · 위협 수에 넣지 않는다(11/02) */
  test?: boolean;
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
// 결과에 나온 패키지(OSV-Scanner 가 읽은 잠금 · 의존성 파일의 항목) — 저장소 · 파일 검사에서 「차단 목록에 올리기」 후보(W4). manager 가 비면 차단 목록이 다루지 않는 생태계
export interface ScanPackage {
  manager: string; // pip | npm | cargo | ''
  name: string;
  version: string;
  ecosystem?: string;
  source?: string; // 잠금 파일 경로
  direct: boolean;
  vulns: number;
}
export interface Scan {
  id: string;
  // repo: ref(브랜치 · 태그 · 커밋) · subpath(하위 폴더)는 없으면 기본 브랜치 · 전체. label 은 github.com/o/r@ref/subpath (W4)
  target: { kind: 'package' | 'repo' | 'file'; manager?: string; name?: string; version?: string; url?: string; ref?: string; subpath?: string; fileName?: string; size?: number; label: string };
  status: 'running' | 'done' | 'failed';
  startedAt: string;
  finishedAt: string | null;
  error?: string;
  verdict?: 'malicious' | 'vulnerable' | 'caution' | 'clean'; // caution(11/03): 점수 ≥ 5 인데 런타임 휴리스틱 규칙만
  installThreats?: number; // 설치 시점 규칙(setup-* · exfil · preinstall …)에 걸린 위협 수 — 악성 판정의 근거
  risk: { score: number; label: string } | null;
  engines: { name: string; version: string }[] | null;
  findings?: ScanFinding[] | null;
  vulns?: ScanVuln[] | null;
  packages?: ScanPackage[] | null; // 상세에만(목록은 null)
  files?: Record<string, string> | null;
  caseId: string | null;
  threats: number;
  capabilities: number;
  /** 테스트 코드 탐지 수(점수 제외, 11/02 — 옛 백엔드는 없음) */
  testFindings?: number;
  vulnCount: number;
  vulnMax: number | null;
}

// ── 인증(W16, 10/20) — backend/internal/api/auth.go · model/user.go ──
export type Role = 'admin' | 'viewer';
export type SessionState = 'need_password' | 'need_license' | 'need_otp_enroll' | 'need_otp' | 'active';
export interface UserBrief {
  id: string;
  username: string;
  displayName: string;
  role: Role;
}
export interface License {
  keyMasked: string;
  kind: string; // trial
  issuedAt: string;
  expiresAt: string;
  registeredBy: string;
  expired: boolean;
}
export interface Me {
  state: SessionState;
  user: UserBrief;
  mustChangePassword: boolean;
  license: License | null;
  otpRequired: boolean;
}
export interface UserView extends UserBrief {
  disabled: boolean;
  otpEnabled: boolean;
  mustChangePassword: boolean;
  locked: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}
export interface AuthAuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  ip: string;
  ok: boolean;
  detail: string;
}

// ── 11/04 평가(GET /api/evaluation) — bench/reports 의 static.json · runtime.json · model.json 그대로(없는 쪽 null, 결과 없음 404) ──
export interface EvalStat {
  p50: number;
  p95: number;
  max?: number;
  n?: number;
}
export type EvalVerdict = 'malicious' | 'suspicious' | 'vulnerable' | 'clean' | 'error';
export interface EvalMetrics {
  detectionRate?: number | null;
  detectionRateWithSuspicious?: number | null;
  falsePositiveRate?: number | null;
  falsePositiveRateWithSuspicious?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1?: number | null;
}
export interface EvalConfusion {
  tp: number;
  fn: number;
  fp: number;
  tn: number;
}
export interface EvalStatic {
  schema: number;
  generatedAt: string;
  scanner?: { guarddog?: string; osv?: string; backendCommit?: string };
  datasets?: { id: string; label: string; kind: string; source?: string; sourceCommit?: string | null; files?: number; listSha256?: string }[];
  sets?: {
    id: string;
    kind: string;
    ecosystem?: string;
    primary?: boolean;
    total: number;
    scanned: number;
    skipped?: Record<string, number>;
    verdicts: Partial<Record<EvalVerdict, number>>;
    rates?: Record<string, number>;
  }[];
  metrics?: EvalMetrics;
  confusion?: EvalConfusion;
  metricsByEcosystem?: Record<string, { metrics: EvalMetrics; confusion?: EvalConfusion }>;
  rules?: { rule: string; maliciousHits: number; benignHits: number; installTime?: boolean }[];
  durationsSec?: { p50: number; p95: number };
  limits?: string[];
}
export interface EvalScenario {
  id: string;
  label: string;
  kind: string; // attack | control
  runs: number;
  detected: number;
  killed: number;
  rule?: string | null;
  latencyMs?: EvalStat | null;
  matchLatencyMs?: EvalStat | null;
  evidenceMs?: EvalStat | null;
  killApiMs?: EvalStat | null;
  dryRun?: boolean | null;
}
export interface EvalRuntime {
  schema: number;
  generatedAt: string;
  host?: { name: string; kernel: string; discovery: string; igVersion?: string; backendCommit?: string };
  benign?: {
    installs: number;
    byEcosystem?: Record<string, number>;
    violations: number;
    falsePositiveRate: number;
    items?: { ecosystem: string; name: string; result: string; rule?: string | null; seconds?: number }[];
  };
  scenarios?: EvalScenario[];
  killLatencyMs?: (EvalStat & { scenarios?: string[] }) | null;
  killStagesMs?: { match?: EvalStat | null; evidence?: EvalStat | null; killApi?: EvalStat | null } | null;
  limits?: string[];
}
export interface EvalCandidate {
  id: string;
  label: string;
  threshold?: number | null;
  calibration: { f1: number; fpr?: number; precision?: number; recall?: number };
  test: { f1: number; precision: number; recall: number; fpr: number };
  confusion?: EvalConfusion;
}
export interface EvalModel {
  schema: number;
  generatedAt?: string;
  protocol?: { seed?: number; split?: string; selection?: string; scope?: string; partitions?: Record<string, { malicious: number; benign: number }> };
  features?: string[];
  candidates?: EvalCandidate[];
  preferredId?: string;
  deploymentApproved?: boolean;
  npmReference?: { note?: string; rows?: number; recall?: Record<string, number> };
  topFeatures?: { feature: string; weight: number }[];
  limits?: string[];
  // model-all.json(PyPI + npm) — 시험 구간을 생태계별로 나눈 지표
  byEcosystem?: Record<string, { test?: { malicious: number; benign: number }; candidates?: Record<string, { test: EvalCandidate['test'] }> }>;
}
export interface Evaluation {
  static: EvalStatic | null;
  runtime: EvalRuntime | null;
  model: EvalModel | null;
  modelAll?: EvalModel | null;
}

// ── 연동(11/06): GET /api/integration · POST /api/integration/test ──
export interface IntegrationEnv {
  source: 'gadget' | 'mock';
  os: string;
  kernel: string;
  enforceKill: boolean;
  enforceNames: string[];
  labelWatch: string;
  labelEnforce: string;
  probeImage: string;
  testable: boolean;
}
export interface IntegrationContainer {
  id: string;
  name: string;
  image: string;
  ignored: boolean;
  watched: boolean;
  watchBy?: 'all' | 'name' | 'label';
  enforce: boolean;
  enforceBy?: 'all' | 'name' | 'label' | 'sandbox' | 'demo';
}
// 11/10 감시 중 컨테이너 상세(GET /api/integration/containers/{id}) — 읽기 전용 Docker inspect 일부. 환경 변수는 서버가 보내지 않는다
export interface ContainerPort {
  port: string; // "8080/tcp"
  hostIp?: string;
  hostPort?: string;
}
export interface IntegrationContainerDetail extends IntegrationContainer {
  imageId?: string;
  state: string; // running · created · exited · paused · restarting · removing · dead
  startedAt?: string;
  restartCount: number;
  ports: ContainerPort[];
  labels: Record<string, string>;
  // Docker 에서 못 읽어 목록 값만 왔을 때 서버 문장
  detailError?: string;
}
export interface IntegrationTest {
  id: string;
  container: string;
  state: 'running' | 'passed' | 'failed';
  startedAt: string;
  endedAt?: string;
  events: Partial<Record<Kind, number>>;
  error?: string;
}
export interface IntegrationStatus {
  env: IntegrationEnv;
  containers: IntegrationContainer[];
  listError?: string;
  test: IntegrationTest | null;
}

// 11/09: AI 도우미가 쓰는 모델(키는 담지 않음). backup = 기본 모델이 닿지 않거나 거절할 때 쓰는 예비
export interface ChatEngine {
  provider: 'claude' | 'ollama';
  model: string;
  backup?: 'ollama';
}

// 11/09 설치 검사 「사용 방법」(GET /api/sginstall/setup). token 은 관리자에게만 — 조회자는 tokenRequired 만
export interface SGInstallSetup {
  download?: string; // 서버에 스크립트가 있을 때 내려받기 경로(/api/tools/sg-install)
  api: string; // 서버 안에서 실행할 때 SUPPLYGUARD_API
  tokenRequired: boolean;
  token?: string;
  reporting: boolean; // false 면 백엔드가 설치 보고를 받지 않음(SANDBOX_TOKEN 없음)
}
