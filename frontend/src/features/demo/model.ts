import type { DemoDecider, DemoExplain, DemoRun, DemoScenario, DemoSequence, Event, InstallSession, Level, Timeline, Verdict } from '../../lib/types';

// 시연 페이지(R3 11/04 — 목업 shared/demo-page.js 11/04e B) 계산만 모은 곳. 화면은 DemoPage.tsx, 데이터는 useDemo.ts.

export type Expect = 'isolated' | 'passed';
// 한눈에 3줄(11/09) — 무엇을 · 잡는 규칙 · 예상 결과(개조식 명사형 종결). 규칙 이름(kebab-case)은 화면에서 코드 글꼴
export interface Brief {
  what: string;
  rule: string;
  result: string;
}
// 흐름 그림 대기 중 예상 경로(11/09) — 커널 이벤트 · 규칙 판정 노드의 부제
export interface FlowHint {
  event: string;
  rule: string;
}
// [이름, 한 줄 설명, 예상 결과] — 순서는 백엔드 GET /api/demo scenarios(DEMO_SCENARIOS)와 같다
export const SCENARIO: Record<DemoScenario, { name: string; line: string; expect: Expect; long: string; brief: Brief; flow: FlowHint }> = {
  all: {
    name: '전부 순서대로',
    line: '아래 다섯 공격을 차례로, 첫 격리에서 멈춤',
    expect: 'isolated',
    long: '설치 샌드박스에서 다섯 가지 공격 행동을 차례로 흘립니다. 실제와 같게 첫 격리(kill)에서 멈춥니다.',
    brief: {
      what: '공격 5종(셸 · 리버스 셸 · IP 직접 · 도메인 · DNS 유출) 차례로 실행함',
      rule: '첫 위반 규칙이 격리(보통 pipe-to-shell)',
      result: '첫 격리에서 멈춤 · 남은 공격 실행 안 됨',
    },
    flow: { event: '실행 · 통신 · DNS 공격 5종', rule: '첫 위반 규칙' },
  },
  shell: {
    name: '외부 스크립트 실행 + 비밀 파일 접근',
    line: 'sh -c "wget … | sh" → /etc/shadow',
    expect: 'isolated',
    long: 'post-install 단계에서 셸로 외부 스크립트를 받아 실행하고(| sh) 계정 파일을 엽니다(무해한 시뮬, TEST-NET 주소).',
    brief: {
      what: '셸로 외부 스크립트를 받아 바로 실행 · /etc/shadow 열기 시도함',
      rule: 'pipe-to-shell(인자 「| sh」) · sensitive-files(계정 파일)',
      result: '설치 끝나기 전 kill · 증거 보존됨',
    },
    flow: { event: 'exec sh -c "wget … | sh"', rule: 'pipe-to-shell' },
  },
  revshell: {
    name: '리버스 셸 포트 4444',
    line: 'connect 203.0.113.7:4444',
    expect: 'isolated',
    long: '리버스 셸에 흔한 포트 4444 로 나가는 연결을 엽니다(TEST-NET, 연결되지 않음).',
    brief: {
      what: '리버스 셸에 흔한 포트 4444 로 TEST-NET 주소에 연결 시도함',
      rule: 'reverse-shell-ports(금지 포트 4444 · 1337 · 31337)',
      result: '연결 시도 즉시 kill · 증거 보존됨',
    },
    flow: { event: 'connect 203.0.113.7:4444', rule: 'reverse-shell-ports' },
  },
  'direct-ip': {
    name: 'DNS 없이 공인 IP 접속',
    line: 'connect 203.0.113.7:443 · 도메인 조회 없음',
    expect: 'isolated',
    long: '도메인 조회 없이 공인 IP 로 바로 붙습니다. trace_dns 가 켜져 있으면 directIp 규칙으로 탐지합니다.',
    brief: {
      what: '도메인 조회 없이 공인 IP 203.0.113.7:443 으로 바로 연결함',
      rule: 'sandbox-egress(directIp: kill, trace_dns 켜짐 기준)',
      result: '연결 시도 즉시 kill · 증거 보존됨',
    },
    flow: { event: 'connect IP:443 · 조회 없음', rule: 'sandbox-egress' },
  },
  domain: {
    name: '예약 도메인 example.com 접속',
    line: 'dns example.com → connect :443',
    expect: 'isolated',
    long: '허용 목록 밖 예약 도메인(example.com)을 질의하고 연결합니다.',
    brief: {
      what: '허용 목록 밖 예약 도메인 example.com 질의 후 연결함',
      rule: 'sandbox-dns(질의) · sandbox-egress(연결)',
      result: '첫 위반(질의 · 연결)에서 kill · 증거 보존됨',
    },
    flow: { event: 'dns example.com → connect', rule: 'sandbox-dns · sandbox-egress' },
  },
  'dns-exfil': {
    name: 'DNS 질의로 데이터 실어 보내기',
    line: '48자 라벨 A 질의 + TXT 질의',
    expect: 'isolated',
    long: '긴 hex 라벨 · TXT 질의로 데이터를 실어 보내는 패턴(예약 TLD .example)입니다.',
    brief: {
      what: '48자 hex 라벨 · TXT 질의로 데이터 실어 보내기 시도함',
      rule: 'sandbox-dns(라벨 40자 초과) · runtime-dns-exfil(경고)',
      result: '질의 단계에서 kill · 연결 전 유출 차단됨',
    },
    flow: { event: 'dns 48자 라벨 · TXT 질의', rule: 'sandbox-dns' },
  },
  benign: {
    name: '정상 설치 대조군',
    line: 'pip sg-demo-benign · 위반 없이 통과',
    expect: 'passed',
    long: '정상 패키지를 설치합니다. 정책에 걸리는 행동이 없어 격리 없이 「통과」로 끝나는 모습을 보여 줍니다.',
    brief: {
      what: '정상 패키지 sg-demo-benign 설치함',
      rule: '걸리는 규칙 없음(모든 정책 통과)',
      result: '위반 없이 설치 완료 · 격리 · 증거 수집 없음',
    },
    flow: { event: 'pip 설치 정상 동작', rule: '위반 없음' },
  },
  chain: {
    name: '연쇄 규칙(다운로드 → 연결 → 비밀 파일)',
    line: 'wget 실행 → 외부 연결 → /root/.netrc',
    expect: 'isolated',
    long: '연쇄 규칙 chain-download-secrets(dryRun, 시연용 시험 운영)의 진행을 보여 줍니다. 기본 정책 no-shell-download 가 1단계(wget 실행)에서 먼저 격리하므로 연쇄는 1/3 에서 멈춥니다(연쇄 완성 장면은 따로 녹화).',
    brief: {
      what: 'wget 실행 → 외부 연결 → /root/.netrc 읽기 차례로 시도함',
      rule: 'no-shell-download 가 1단계(wget)에서 먼저 격리 · 연쇄 chain-download-secrets 는 dryRun',
      result: '1단계 격리 · 연쇄 진행 1/3 에서 멈춤(완성 장면은 별도 녹화)',
    },
    flow: { event: 'exec wget(연쇄 1단계)', rule: 'no-shell-download' },
  },
};
export const EXPECT_LABEL: Record<Expect, string> = { isolated: '격리 예상', passed: '통과 예상' };
export const STEPS = [
  ['start', '설치 시작'],
  ['events', '커널 이벤트'],
  ['match', '정책 탐지'],
  ['evidence', '증거 수집'],
  ['outcome', '결과'],
] as const;
export type StepKey = (typeof STEPS)[number][0];
export type StepState = 'done' | 'active' | 'todo' | 'skip';
export type Outcome = 'running' | 'isolated' | 'passed' | 'detected' | 'warned' | 'refused' | 'timeout' | 'failed';

// 초.밀리초(13:46:48.264)
export function ms3(iso: string) {
  const d = new Date(iso);
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}
const validAt = (iso?: string | null) => (iso && !Number.isNaN(Date.parse(iso)) ? iso : null);
export const msBetween = (a?: string | null, b?: string | null) => (a && b ? Math.max(0, Date.parse(b) - Date.parse(a)) : null);

// 이벤트 원문(목업 rawOf) — 실행 = 인자, 파일 = 경로, 조회 = "이름 (유형)", 연결 = "ip:port (도메인)"
export function rawOf(e: Partial<Event> | null | undefined): string {
  if (!e) return '';
  if (e.kind === 'exec') return e.args || e.comm || '';
  if (e.kind === 'open') return e.path || '';
  if (e.kind === 'dns') return `${e.dstHost || ''} (${e.qtype || ''})`;
  return e.dstHost ? `${e.dstIp}:${e.dstPort} (${e.dstHost})` : `${e.dstIp}:${e.dstPort}`;
}

// 판정 사유에서 걸린 부분을 찾아 원문에서 강조 — 원문에 실제로 있는 가장 긴 조각.
// 후보: 사유 앞머리(「금지 인자 패턴: 」 · 「규칙: 」)를 뗀 나머지 전체 · 그 안의 「 — 」 / 「 (」 앞 조각 · 따옴표 안 · 3자 이상 낱말.
// 백엔드 사유(rules/engine.go)는 「금지 인자 패턴: | sh」처럼 값이 콜론 뒤에 그대로 온다 — 목업의 낱말 후보만으로는 「| sh」를 못 찾아 나머지 전체를 더했다
export function markParts(text: string, reason?: string | null): [string, string, string] | null {
  const r = String(reason || '');
  const strip = (x: string) => x.replace(/^[^:]+:\s*/, '');
  const whys = [strip(r), strip(strip(r))];
  const cands = new Set<string>();
  for (const why of whys) {
    if (!why) continue;
    cands.add(why.trim());
    for (const seg of why.split(/\s+—\s+|\s+\(/)) cands.add(seg.trim());
    for (const m of why.matchAll(/"([^"]+)"/g)) cands.add(m[1]);
    for (const t of why.split(/\s+/)) {
      const w = t.replace(/^[(「"]+|[)」",.]+$/g, '');
      if (w.length >= 3) cands.add(w);
    }
  }
  const hit = [...cands].filter((c) => c.length >= 2 && text.includes(c)).sort((a, b) => b.length - a.length)[0];
  if (!hit) return null;
  const i = text.indexOf(hit);
  return [text.slice(0, i), hit, text.slice(i + hit.length)];
}

export type Level3 = Exclude<Level, 'normal'>;
export const levelOfDecider = (d: Pick<DemoDecider, 'action' | 'enforced'>): Level3 => (d.action !== 'kill' ? 'alert' : d.enforced ? 'killed' : 'held');
export const VERDICT_KO: Record<Level3, string> = { killed: '격리', held: '격리 대상(시험 운영 · 경고만)', alert: '경고' };

export interface DemoModel {
  // undefined = 아직 모름(판정 기다리는 중 · 정보 없음), null = 위반 없음(통과)
  d: DemoDecider | null | undefined;
  lv: Level3 | null;
  tl: Timeline | null;
  running: boolean;
  evs: Verdict[];
  count: number;
  outcome: Outcome | null;
  seq: DemoSequence | null;
}

// explain 이 있으면 그것(실행 중의 null 은 「아직 판정 없음」), 없으면(옛 백엔드 · 폴링 사이) 세션 위반 중 격리된 것 → 첫 위반
export function buildModel(run: DemoRun | null, session: InstallSession | null, streamEvs: Verdict[]): DemoModel {
  const x: DemoExplain | null | undefined = run?.explain;
  const running = run?.status === 'running';
  const dec0 = x ? x.decidedBy : undefined;
  const dec = dec0 === null && running ? undefined : dec0;
  const vs = session?.violations ?? [];
  const fb = vs.length ? (vs.find((v) => v.enforced) ?? vs[0]) : null;
  const d: DemoDecider | null | undefined =
    dec !== undefined
      ? dec
      : fb
        ? {
            ruleId: fb.ruleId ?? '',
            description: '',
            condition: '',
            action: fb.action ?? 'alert',
            dryRun: !!fb.dryRun,
            enforced: !!fb.enforced,
            reason: fb.reason ?? '',
            event: fb.event,
          }
        : run && !running && session
          ? null
          : undefined;
  const tl = session?.isolation?.timeline ?? null;
  // 그 컨테이너의 실시간 이벤트(시간 순). 스트림에 없으면 세션의 위반 이벤트로
  const evs = streamEvs.length ? streamEvs : vs.slice().sort((a, b) => a.event.timestamp.localeCompare(b.event.timestamp));
  const kinds = Object.values(session?.activity?.kinds ?? {}).reduce((n, k) => n + (k ?? 0), 0);
  const count = Math.max(kinds, evs.length);
  const lv = d ? levelOfDecider(d) : null;
  const outcome: Outcome | null = !run
    ? null
    : running
      ? 'running'
      : run.status === 'refused'
        ? 'refused'
        : run.status === 'timeout'
          ? 'timeout'
          : run.status === 'failed'
            ? 'failed'
            : lv === 'killed' || session?.status === 'isolated'
              ? 'isolated'
              : lv === 'held'
                ? 'detected'
                : lv === 'alert'
                  ? 'warned'
                  : 'passed';
  return { d, lv, tl, running, evs, count, outcome, seq: x?.sequence ?? null };
}

export interface Step {
  key: StepKey;
  at: string | null;
  state: StepState;
  delta: number | null;
}
// 단계마다 도착 시각 · 상태. 직전 도착 시각 대비 +N ms(도착 시각이 있는 단계끼리)
export function stepsOf(run: DemoRun | null, m: DemoModel): Step[] {
  const fin = !!run && !m.running;
  const out: Omit<Step, 'delta'>[] = [];
  out.push({ key: 'start', at: run ? validAt(run.startedAt) : null, state: run ? 'done' : 'todo' });
  out.push({ key: 'events', at: validAt(m.evs[0]?.event.timestamp), state: m.count ? 'done' : m.running ? 'active' : fin ? 'done' : 'todo' });
  if (m.d) out.push({ key: 'match', at: validAt(m.tl?.matchedAt ?? m.d.event?.timestamp), state: 'done' });
  else if (m.d === null && fin) out.push({ key: 'match', at: validAt(m.evs[m.evs.length - 1]?.event.timestamp ?? run?.finishedAt), state: 'done' });
  else out.push({ key: 'match', at: null, state: m.running && m.count ? 'active' : fin ? 'done' : 'todo' });
  if (m.tl?.evidenceDoneAt) out.push({ key: 'evidence', at: validAt(m.tl.evidenceDoneAt), state: 'done' });
  else if (fin && m.outcome !== 'isolated') out.push({ key: 'evidence', at: null, state: 'skip' });
  else out.push({ key: 'evidence', at: null, state: fin ? 'done' : m.lv === 'killed' ? 'active' : 'todo' });
  const ocAt = m.outcome === 'isolated' ? validAt(m.tl?.killedAt ?? run?.finishedAt) : fin ? validAt(run?.finishedAt) : null;
  out.push({ key: 'outcome', at: ocAt, state: fin ? 'done' : m.lv === 'killed' ? 'active' : 'todo' });
  let prev: number | null = null;
  return out.map((s) => {
    let delta: number | null = null;
    if (s.at) {
      const t = Date.parse(s.at);
      delta = prev !== null ? Math.max(0, t - prev) : null;
      prev = t;
    }
    return { ...s, delta };
  });
}

export const elapsedSec = (run: DemoRun, now: number) =>
  Math.max(0, Math.round(((run.status === 'running' || !run.finishedAt ? now : Date.parse(run.finishedAt)) - Date.parse(run.startedAt)) / 1000));
