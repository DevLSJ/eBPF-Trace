import type { Page } from '@playwright/test';
import type { Evidence } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';
import { demoRun } from './mock-backend';

// 10/30 F2 시연 패널(계약 §4) · F3 격리 타임라인(§3) · F4 상태 신호등(§5) · F5 건 보고서 1장(§5)

// R3 11/04: 시연은 대시보드 카드 → 독립 페이지 /demo(11/04e B). 카드 선택자 대신 페이지 선택자 · 단계 레일 6단계 → 흐름 5단계(번호 대신 키)
const DEMO = '[data-part="demo-page"]';
const PILLS = '[data-testid="signal-pills"]';
const step = (page: Page, k: string) => page.locator(`${DEMO} [data-part="demo-steps"] [data-step="${k}"]`);
const result = (page: Page) => page.locator(`${DEMO} [data-part="demo-outcome"]`);

test.describe('시연 패널', () => {
  test('관리자 + /api/info.demo 일 때만 「시연」 — 조회자 · demo false 면 없음', async ({ page, backend }) => {
    // R3 11/04: 대시보드 맨 위 카드 → 사이드바 「시연」(대시보드 바로 아래) · 페이지 /demo. 조건이 안 맞으면 메뉴가 없고 주소로 오면 안내
    const link = page.locator('aside[data-part="sidebar"] nav a[href="/demo"]');
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await expect(link).toHaveCount(0);
    backend.enableDemo();
    await page.reload();
    await expect(link).toBeVisible();
    await link.click();
    await expect(page.locator(DEMO)).toBeVisible();
    backend.auth.asViewer();
    await page.reload();
    await expect(page.locator('[data-part="demo-denied"]')).toBeVisible();
    await expect(page.locator(DEMO)).toHaveCount(0);
    await expect(link).toHaveCount(0);
  });

  test('시나리오 8개(기본 all · 11/04 benign · chain 추가) · 한 줄 설명 · 시작 → POST {scenario}', async ({ page, backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 5000; // 진행 전 상태를 본다
    await page.goto('/demo');
    // R3 11/04: 고르기 목록(select) → 시나리오 단추 8개 + 예상 결과, 기본 선택은 목업 시연 페이지처럼 shell
    const items = page.locator(`${DEMO} [data-scenario]`);
    await expect(items.first()).toBeVisible();
    expect(await items.evaluateAll((os) => os.map((o) => (o as HTMLElement).dataset.scenario))).toEqual(['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil', 'benign', 'chain']); // 11/04: 정상 대조군 · 연쇄 시연 추가
    await expect(page.locator(`${DEMO} [data-scenario="shell"]`)).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator(DEMO)).toContainText('전부 순서대로');
    await page.locator(`${DEMO} [data-scenario="dns-exfil"]`).click();
    await expect(page.locator(DEMO)).toContainText('DNS 질의로 데이터 실어 보내기');
    await page.locator(DEMO).getByRole('button', { name: '시연 시작' }).click();
    const w = backend.writes().find((r) => r.path === '/demo/run')!;
    expect(JSON.parse(w.body!)).toEqual({ scenario: 'dns-exfil' });
    expect(w.auth).toBeNull();
    await expect(step(page, 'start')).toHaveAttribute('data-state', 'done');
    await expect(step(page, 'events')).toHaveAttribute('data-state', /active|done/); // R3 11/04: 세션 생김 = 설치 시작(1단계)
    await expect(result(page)).toContainText(/실행 중 · \d+초 경과/);
    // R3 11/04: 「설치 검사에서 보기」 링크 → 「왜」 카드의 「건 보고서 열기」(세션 · 건)
    await expect(page.locator(`${DEMO} [data-action="open-report"]`)).toHaveAttribute('href', `/report?install=${backend.demo.running!.installId}`);
    await page.screenshot({ path: `${SHOTS}/1030-demo.png` });
  });

  test('시작 → 단계 진행 → 첫 위반에도 자리 유지 → 결과 한 줄 · 증거 · 탐지→kill ms · 다시 시작', async ({ page, backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 700;
    await page.goto('/demo');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await page.locator(DEMO).getByRole('button', { name: '시연 시작' }).click();
    await expect(step(page, 'events')).toHaveAttribute('data-state', 'done'); // 커널 이벤트 1건
    // R3 11/04: 첫 위반에 설치 시트로 자동 이동하지 않는다(녹화 중 페이지 고정 — 11/04e B)
    await expect(step(page, 'match')).toHaveAttribute('data-state', 'done');
    await expect(page).toHaveURL(/\/demo$/);
    await expect(page.locator('[data-sheet="install"]')).toHaveCount(0);
    for (const k of ['start', 'events', 'match', 'evidence', 'outcome']) await expect(step(page, k)).toHaveAttribute('data-state', 'done');
    // R3 11/04: 결과 한 줄 「격리됨 — 규칙 · 탐지→kill N ms」, 타임라인 막대 대신 「왜」 카드의 증거 수집 ms · 탐지→kill ms
    await expect(result(page)).toContainText('[격리] pipe-to-shell 위반 · 탐지→kill 420 ms');
    await expect(page.locator(`${DEMO} [data-part="kill-ms"]`)).toContainText('420 ms');
    await expect(page.locator(`${DEMO} [data-part="evidence-ms"]`)).toContainText('295 ms');
    await expect(page.locator(DEMO).getByRole('button', { name: '시연 시작' })).toBeEnabled();
    expect(backend.demo.last?.status).toBe('finished');
    // 설치 시트의 결과 칸에는 타임라인 막대(그대로)
    await page.goto(`/installs?id=${backend.demo.last!.installId}`);
    const bar = page.locator('[data-sheet="install"] [data-testid="timeline-bar"]');
    await expect(bar).toBeVisible();
    await expect(bar.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    await page.screenshot({ path: `${SHOTS}/1030-timeline.png` });
  });

  test('409 「이미 실행 중」 안내(실행 중인 Run 을 보인다) · 503 은 오류 띠 · 거부됨(차단 목록)', async ({ page, backend, allowConsole }) => {
    allowConsole(/Failed to load resource: the server responded with a status of (409|503)/);
    backend.enableDemo();
    await page.goto('/demo');
    const startBtn = page.locator(DEMO).getByRole('button', { name: '시연 시작' });
    await expect(startBtn).toBeVisible();
    // 다른 사람이 먼저 시작했다(세션은 진행 중인 ins-0012) — 화면은 아직 모른다
    const other = demoRun('shell', 'ins-0012');
    backend.demo.running = other;
    await startBtn.click();
    const err = page.locator(`${DEMO} [data-part="demo-error"]`);
    await expect(err).toContainText('이미 실행 중');
    await expect(page.locator(`${DEMO} [data-why="what"]`)).toContainText(other.container); // 409 본문의 running 을 보인다
    await expect(page.locator(DEMO)).toContainText('외부 스크립트 실행 + 비밀 파일 접근');
    await expect(page.locator(DEMO).getByRole('button', { name: '실행 중…' })).toBeDisabled();
    // 503
    backend.demo.running = null;
    backend.demoDown = true;
    await page.reload();
    await page.locator(DEMO).getByRole('button', { name: '시연 시작' }).click();
    await expect(err).toContainText('Docker 에 연결할 수 없습니다');
    backend.demoDown = false;
    backend.demoRefused = true;
    // R3 11/04: 띠의 「다시 시도」 → 시작 단추(잠기지 않음)를 다시 누른다
    await page.locator(DEMO).getByRole('button', { name: '시연 시작' }).click();
    await expect(err).toHaveCount(0);
    await expect(result(page)).toContainText('[거부] 차단 목록에 있어 설치 전 거부됨');
    await expect(result(page)).toContainText('차단 해제 후 다시');
  });
});

test.describe('격리 타임라인 · 종합 격리 지연', () => {
  test('설치 시트 · 토폴로지 판정 카드의 가로 막대 — 구간 4개 · ms 라벨 · 합계 · 없는 구간 「—」', async ({ page, backend }) => {
    backend.enableIsolation();
    await page.goto('/installs?id=ins-0012');
    const bar = page.locator('[data-sheet="install"] [data-testid="timeline-bar"]');
    await expect(bar.locator('[data-seg]')).toHaveCount(4);
    expect(await bar.locator('[data-seg]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.seg))).toEqual(['detect', 'evidence', 'kill', 'notify']);
    await expect(bar.locator('[data-seg="detect"]')).toContainText('12 ms');
    await expect(bar.locator('[data-seg="evidence"]')).toContainText('295 ms');
    await expect(bar.locator('[data-seg="kill"]')).toContainText('110 ms');
    await expect(bar.locator('[data-seg="notify"]')).not.toContainText('ms'); // 설치 쪽은 알림 시각 없음(값 칸은 빈 값)
    await expect(bar.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    await page.goto('/topology?node=c%3Apkg-reqeusts');
    const tb = page.getByTestId('topology-decision').locator('[data-testid="timeline-bar"]');
    await expect(tb.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.38초');
    await expect(tb.locator('[data-seg="notify"]')).toContainText('10 ms');
  });

  test('대시보드 종합 「격리 지연 중앙값 N ms」 — count 0 이면 빈 칸(11/09 「—」 없앰)', async ({ page, backend }) => {
    await page.goto('/');
    const v = page.locator('[data-section="overview"] [data-kpi="isolation"] [data-value]');
    await expect(v).toHaveText('');
    await expect(page.locator('[data-section="overview"] [data-kpi="isolation"]')).toContainText('격리 지연 중앙값');
    backend.enableIsolation();
    await page.reload();
    // R2 11/04: KPI 카드는 단위를 분리(값 28/700 · 단위 13/500)
    await expect(v.locator('.kpi-val')).toHaveText('380');
    await expect(v.locator('.kpi-unit')).toHaveText('ms');
    expect(backend.summary('24h').isolation).toEqual({ count: 2, medianMs: 380, p95Ms: 420, maxMs: 420 });
  });
});

test.describe('상태 신호등', () => {
  test('알약 5개 · 색 규칙(초록 · 노랑 · 빨강 · 회색) · 누르면 설정 해당 탭 · 키보드', async ({ page, backend }) => {
    await page.goto('/');
    const pills = page.locator(`${PILLS} [data-pill]`);
    expect(await pills.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.pill))).toEqual(['gadget', 'dns', 'kill', 'notify', 'license']);
    const tone = (k: string) => page.locator(`${PILLS} [data-pill="${k}"]`);
    await expect(tone('gadget')).toHaveAttribute('data-tone', 'warn'); // mock → 모의 이벤트
    await expect(tone('gadget')).toContainText('모의 이벤트');
    await expect(tone('dns')).toHaveAttribute('data-tone', 'ok');
    await expect(tone('kill')).toHaveAttribute('data-tone', 'ok');
    await expect(tone('notify')).toHaveAttribute('data-tone', 'ok');
    await expect(tone('license')).toHaveAttribute('data-tone', 'ok');
    await expect(tone('license')).toContainText('200일');
    await page.screenshot({ path: `${SHOTS}/1030-signal.png` });

    backend.info.source = 'gadget';
    backend.info.dnsResolve = 'off';
    backend.info.enforceKill = false;
    backend.stats.enforceKill = false;
    backend.info.notify = { enabled: true, channels: [{ name: 'slack', host: 'hooks.slack.com', sent: 1, failed: 2, lastError: '502 Bad Gateway' }], sent: 1, failed: 2, lastError: '502 Bad Gateway' };
    backend.auth.setLicenseDays(30);
    await page.reload();
    await expect(tone('gadget')).toHaveAttribute('data-tone', 'ok');
    await expect(tone('gadget')).toContainText('커널 감시 중');
    await expect(tone('dns')).toHaveAttribute('data-tone', 'warn');
    await expect(tone('dns')).toContainText('통과 처리');
    await expect(tone('kill')).toHaveAttribute('data-tone', 'warn');
    await expect(tone('kill')).toContainText('경고만');
    await expect(tone('notify')).toHaveAttribute('data-tone', 'danger');
    await expect(tone('license')).toHaveAttribute('data-tone', 'warn');

    backend.info.notify = { enabled: false, channels: [], sent: 0, failed: 0 };
    backend.auth.setLicenseDays(-1);
    await page.reload();
    await expect(tone('notify')).toHaveAttribute('data-tone', 'warn');
    await expect(tone('notify')).toContainText('미설정');
    await expect(tone('license')).toHaveAttribute('data-tone', 'danger');
    delete backend.info.dnsResolve;
    delete backend.info.notify;
    await page.reload();
    await expect(tone('dns')).toHaveAttribute('data-tone', 'muted');
    await expect(tone('notify')).toHaveAttribute('data-tone', 'muted');

    // 누르면 설정(해당 탭) · 키보드 접근
    await tone('license').click();
    await expect(page).toHaveURL(/\/settings\?tab=license$/);
    await page.goto('/');
    await tone('kill').focus();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/settings$/);
    await expect(page.locator('[data-view="server"]')).toBeVisible();
  });
});

const INSTALL_CTR = 'sg-install-pip-1792043525-24739';
const evidence = (): Evidence => ({
  id: 'ev-1', containerId: 'ins-0012abcdef0123456789', containerName: INSTALL_CTR, image: 'python:3.12-slim', collectedAt: new Date().toISOString(),
  logs: 'Collecting ./reqeusts\nRunning setup.py install\n[demo] shell start', changes: [{ kind: 'A', path: '/tmp/p.sh' }, { kind: 'C', path: '/etc/shadow' }], processes: null, partial: true, durationMs: 412, error: 'docker top 시간 초과',
});

test.describe('건 보고서 1장', () => {
  test('/report?install= — 내용 순서 고정 · 타임라인 · 위반 표 · 증거 요약(partial) · 판정 · 작성자', async ({ page, backend }) => {
    backend.enableIsolation();
    backend.evidence.push(evidence());
    await page.goto('/report?install=ins-0012');
    await expect(page.getByTestId('page-title')).toHaveText('건 보고서');
    const rep = page.getByTestId('report');
    await expect(rep.locator('[data-section="meta"]')).toBeVisible();
    expect(await rep.locator('[data-section]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.section))).toEqual([
      'title', 'summary', 'timeline', 'violations', 'evidence', 'decision', 'changes', 'meta',
    ]);
    const title = rep.locator('[data-section="title"]');
    await expect(title).toContainText('pip ./reqeusts');
    await expect(title).toContainText('설치 검사');
    await expect(title.locator('[data-status="isolated"]')).toHaveText('격리');
    const sum = rep.locator('[data-section="summary"] li');
    await expect(sum).toHaveCount(3);
    await expect(sum.nth(0)).toContainText('무엇이');
    await expect(sum.nth(1)).toContainText('언제');
    await expect(sum.nth(2)).toContainText('pipe-to-shell');
    await expect(rep.locator('[data-section="timeline"] [data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    const rows = rep.locator('[data-section="violations"] tbody tr');
    await expect(rows).toHaveCount(6);
    expect(await rep.locator('[data-section="violations"] thead th').allTextContents()).toEqual(['시각', '종류', '정책', '상세', '탐지 결과']); // 11/09 G44: 「규칙」 칸 → 「정책」
    await expect(rows.first().locator('[data-kind-badge]')).toBeVisible();
    const ev = rep.locator('[data-section="evidence"]');
    await expect(ev).toContainText('로그 3줄');
    await expect(ev).toContainText('파일 변경 2');
    await expect(ev).toContainText('프로세스 0');
    await expect(ev).toContainText('일부만 모음');
    await expect(ev).toContainText('docker top 시간 초과');
    await expect(rep.locator('[data-section="decision"]')).toContainText('판정 대기');
    await expect(rep.locator('[data-section="changes"]')).toContainText('없음');
    await expect(rep.locator('[data-section="meta"]')).toContainText('보안 담당자');
    await page.screenshot({ path: `${SHOTS}/1030-report.png`, fullPage: true });
  });

  test('/report?case= (런타임 건) · 조회자도 열람 · 적용된 제안은 정책 변경 · 차단 목록', async ({ page, backend }) => {
    backend.enableIsolation();
    backend.auth.asViewer();
    await page.goto('/report?case=case-0005');
    const rep = page.getByTestId('report');
    await expect(rep.locator('[data-section="title"]')).toContainText('pkg-reqeusts');
    await expect(rep.locator('[data-section="title"]')).toContainText('런타임');
    await expect(rep.locator('[data-section="violations"] tbody tr')).toHaveCount(5);
    await expect(rep.locator('[data-section="timeline"] [data-part="timeline-total"]')).toHaveText('격리까지 0.38초');
    await page.goto('/report?case=case-0002');
    await expect(rep.locator('[data-section="decision"]')).toContainText('악성');
    await expect(rep.locator('[data-section="decision"]')).toContainText('타이포스쿼팅');
    await expect(rep.locator('[data-section="changes"]')).toContainText('pip:colourama');
    await expect(rep.locator('[data-section="changes"]')).toContainText('cdn.colourama.test');
    await expect(rep.locator('[data-section="timeline"]')).toContainText('타임라인 기록 없음(격리되지 않았거나 기록이 생기기 전의 건)'); // 타임라인 없는 옛 건
  });

  test('진입 3곳(설치 시트 · 토폴로지 판정 카드 · 대시보드 판정 대기 행) · 인쇄 · Markdown 복사', async ({ page, backend, context }) => {
    void backend;
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/installs?id=ins-0012');
    await expect(page.locator('[data-sheet="install"] [data-action="report"]')).toHaveAttribute('href', '/report?install=ins-0012');
    await page.goto('/installs?id=ins-0010'); // 통과 세션에는 없다
    await expect(page.locator('[data-sheet="install"] [data-action="report"]')).toHaveCount(0);
    await page.goto('/topology?node=c%3Apkg-reqeusts');
    await expect(page.getByTestId('topology-decision').locator('[data-action="report"]')).toHaveAttribute('href', '/report?case=case-0005');
    await page.goto('/');
    const row = page.getByTestId('pending-list').locator('li', { hasText: 'pip ./reqeusts' }).first();
    await row.locator('[data-action="report"]').click();
    await expect(page).toHaveURL(/\/report\?case=case-0004$/);
    const rep = page.getByTestId('report');
    await expect(rep.locator('[data-section="title"]')).toContainText('pip ./reqeusts');
    // 인쇄 — window.print 호출
    await page.evaluate(() => {
      (window as unknown as { __printed: number }).__printed = 0;
      window.print = () => {
        (window as unknown as { __printed: number }).__printed++;
      };
    });
    await page.getByRole('button', { name: '인쇄' }).click();
    expect(await page.evaluate(() => (window as unknown as { __printed: number }).__printed)).toBe(1);
    // Markdown 복사 — 같은 내용
    await page.getByRole('button', { name: 'Markdown 복사' }).click();
    await expect(page.locator('[data-toast="report-copy"]')).toContainText('복사');
    const md = await page.evaluate(() => navigator.clipboard.readText());
    expect(md.startsWith('# ')).toBe(true);
    for (const h of ['## 요약', '## 격리 타임라인', '## 위반', '## 증거', '## 판정', '## 정책 변경 · 차단 목록']) expect(md).toContain(h);
    expect(md).toContain('pipe-to-shell');
    expect(md).toContain('| 시각 | 종류 | 정책 | 상세 | 탐지 결과 |');
    // 사이드바 · 머리는 인쇄에서 숨긴다
    await page.emulateMedia({ media: 'print' });
    await expect(page.locator('aside[data-part="sidebar"]')).toBeHidden();
    await expect(rep).toBeVisible();
    await page.emulateMedia({ media: 'screen' });
  });
});
