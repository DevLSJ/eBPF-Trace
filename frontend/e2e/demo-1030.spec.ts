import type { Page } from '@playwright/test';
import type { Evidence } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';
import { demoRun } from './mock-backend';

// 10/30 F2 시연 패널(계약 §4) · F3 격리 타임라인(§3) · F4 상태 신호등(§5) · F5 건 보고서 1장(§5)

const DEMO = '[data-testid="demo"]';
const PILLS = '[data-testid="signal-pills"]';
const step = (page: Page, n: number) => page.locator(`${DEMO} [data-testid="demo-rail"] [data-step="${n}"]`);

test.describe('시연 패널', () => {
  test('관리자 + /api/info.demo 일 때만 대시보드 맨 위 「시연」 카드 — 조회자 · demo false 면 카드 없음', async ({ page, backend }) => {
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await expect(page.locator(DEMO)).toHaveCount(0);
    backend.enableDemo();
    await page.reload();
    await expect(page.locator(DEMO)).toBeVisible();
    const [d, p] = await Promise.all([page.locator(DEMO).boundingBox(), page.getByTestId('pending').boundingBox()]);
    expect(d!.y).toBeLessThan(p!.y);
    backend.auth.asViewer();
    await page.reload();
    await expect(page.getByTestId('pending')).toBeVisible();
    await expect(page.locator(DEMO)).toHaveCount(0);
  });

  test('시나리오 6개(기본 all) · 한 줄 설명 · 시작 → POST {scenario}', async ({ page, backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 5000; // 진행 전 상태를 본다
    await page.goto('/');
    const sel = page.locator(`${DEMO} [data-testid="demo-scenario"]`);
    await expect(sel).toBeVisible();
    expect(await sel.locator('option').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))).toEqual(['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil']);
    await expect(sel).toHaveValue('all');
    await expect(page.locator(DEMO)).toContainText('전부 순서대로');
    await sel.selectOption('dns-exfil');
    await expect(page.locator(DEMO)).toContainText('DNS 질의로 데이터 실어 보내기');
    await page.locator(DEMO).getByRole('button', { name: '시연 시작' }).click();
    const w = backend.writes().find((r) => r.path === '/demo/run')!;
    expect(JSON.parse(w.body!)).toEqual({ scenario: 'dns-exfil' });
    expect(w.auth).toBeNull();
    await expect(step(page, 1)).toHaveAttribute('data-state', 'done');
    await expect(step(page, 2)).toHaveAttribute('data-state', 'done'); // 설치 세션 생김
    await expect(step(page, 3)).toHaveAttribute('data-state', 'active');
    await expect(page.locator(`${DEMO} [data-part="demo-elapsed"]`)).toContainText(/\d+초/);
    await expect(page.locator(DEMO).getByRole('link', { name: '설치 검사에서 보기' })).toHaveAttribute('href', `/installs?id=${backend.demo.running!.installId}`);
    await page.screenshot({ path: `${SHOTS}/1030-demo.png` });
  });

  test('시작 → 단계 레일 진행 → 첫 위반에 설치 시트 자동 열림 → 돌아오면 결과 한 줄 · 타임라인 막대 · 다시 실행', async ({ page, backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 700;
    await page.goto('/');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await page.locator(DEMO).getByRole('button', { name: '시연 시작' }).click();
    await expect(step(page, 3)).toHaveAttribute('data-state', 'done'); // 커널 이벤트 1건
    await expect(step(page, 4)).toHaveAttribute('data-state', 'active');
    const run = backend.demo.running!;
    await expect(page).toHaveURL(new RegExp(`/installs\\?id=${run.installId}$`)); // 첫 위반 → 설치 시트
    await expect(page.locator('[data-sheet="install"]')).toBeVisible();
    await expect(page.locator('[data-sheet="install"] [data-status="isolated"]').first()).toBeVisible();
    // 시트의 결과 칸에도 타임라인 막대
    const bar = page.locator('[data-sheet="install"] [data-testid="timeline-bar"]');
    await expect(bar).toBeVisible();
    await expect(bar.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    await page.goto('/');
    await expect(page.locator(DEMO)).toBeVisible();
    for (let i = 1; i <= 6; i++) await expect(step(page, i)).toHaveAttribute('data-state', 'done');
    const result = page.locator(`${DEMO} [data-part="demo-result"]`);
    await expect(result).toContainText('격리됨 — 규칙 1개 · 0.42초');
    await expect(page.locator(`${DEMO} [data-testid="timeline-bar"] [data-seg="kill"]`)).toContainText(/\d+ ms/);
    await expect(page.locator(DEMO).getByRole('button', { name: '다시 실행' })).toBeVisible();
    expect(backend.demo.last?.status).toBe('finished');
    // 실행 중이 아니면 2초 폴링은 멈춘다
    const before = backend.requests.filter((r) => r.path === '/demo').length;
    await page.waitForTimeout(2600);
    expect(backend.requests.filter((r) => r.path === '/demo').length).toBe(before);
    await page.screenshot({ path: `${SHOTS}/1030-timeline.png` });
  });

  test('409 「이미 실행 중」 안내(실행 중인 Run 을 보인다) · 503 은 오류 띠 + 다시 시도 · 거부됨(차단 목록)', async ({ page, backend, allowConsole }) => {
    allowConsole(/Failed to load resource: the server responded with a status of (409|503)/);
    backend.enableDemo();
    await page.goto('/');
    const startBtn = page.locator(DEMO).getByRole('button', { name: '시연 시작' });
    await expect(startBtn).toBeVisible();
    // 다른 사람이 먼저 시작했다(세션은 진행 중인 ins-0013) — 화면은 아직 모른다
    const other = demoRun('shell', 'ins-0013');
    backend.demo.running = other;
    await startBtn.click();
    const err = page.locator(`${DEMO} [data-part="demo-error"]`);
    await expect(err).toContainText('이미 실행 중');
    await expect(page.locator(`${DEMO} [data-run="${other.id}"]`)).toBeVisible(); // 409 본문의 running 을 보인다
    await expect(page.locator(DEMO)).toContainText('shell');
    await expect(page.locator(DEMO).getByRole('button', { name: '실행 중…' })).toBeDisabled();
    // 503
    backend.demo.running = null;
    backend.demoDown = true;
    await page.reload();
    await page.locator(DEMO).getByRole('button', { name: '시연 시작' }).click();
    await expect(err).toContainText('Docker 에 연결할 수 없습니다');
    backend.demoDown = false;
    backend.demoRefused = true;
    await err.getByRole('button', { name: '다시 시도' }).click();
    await expect(err).toHaveCount(0);
    await expect(page.locator(`${DEMO} [data-part="demo-result"]`)).toContainText('거부됨(차단 목록)');
    await expect(page.locator(`${DEMO} [data-part="demo-result"]`)).toContainText('차단 해제 후 다시');
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
    await expect(bar.locator('[data-seg="notify"]')).toContainText('—'); // 설치 쪽은 알림 시각 없음
    await expect(bar.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    await page.goto('/topology?node=c%3Apkg-reqeusts');
    const tb = page.getByTestId('topology-decision').locator('[data-testid="timeline-bar"]');
    await expect(tb.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.38초');
    await expect(tb.locator('[data-seg="notify"]')).toContainText('10 ms');
  });

  test('대시보드 종합 「격리 지연 중앙값 N ms」 — count 0 이면 「—」', async ({ page, backend }) => {
    await page.goto('/');
    const v = page.locator('[data-section="overview"] [data-kpi="isolation"] [data-value]');
    await expect(v).toHaveText('—');
    await expect(page.locator('[data-section="overview"] [data-kpi="isolation"]')).toContainText('격리 지연 중앙값');
    backend.enableIsolation();
    await page.reload();
    await expect(v).toHaveText('380 ms');
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
    await expect(tone('kill')).toContainText('알림만');
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
    expect(await rep.locator('[data-section="violations"] thead th').allTextContents()).toEqual(['시각', '종류', '규칙', '상세', '판정']);
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
    await expect(rep.locator('[data-section="timeline"]')).toContainText('—'); // 타임라인 없는 옛 건
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
    expect(md).toContain('| 시각 | 종류 | 규칙 | 상세 | 판정 |');
    // 사이드바 · 머리는 인쇄에서 숨긴다
    await page.emulateMedia({ media: 'print' });
    await expect(page.locator('aside[data-part="sidebar"]')).toBeHidden();
    await expect(rep).toBeVisible();
    await page.emulateMedia({ media: 'screen' });
  });
});
