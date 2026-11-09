import { mkdirSync, readFileSync } from 'node:fs';
import type { Locator, Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// 11/09 밤 사용자 결정 ③ — 화면 주 버튼(정책 생성 · YAML 일괄 적용 · 결과 JSON · 모두 펼치기 등) = 본문 맨 위 화면 설명 줄의 오른쪽 끝.
//   주 버튼이 있는 모든 화면이 같은 규칙: 한 줄 = 왼쪽 설명(screen-copy) + 오른쪽 끝 버튼 자리(page-actions). 머리 줄에는 제목 + 상태 표시만.
//   768 미만은 버튼이 설명 아래 줄로(가로 넘침 0). 대시보드는 설명 줄이 없어 맨 위 줄(dash-top)의 오른쪽 끝이 같은 자리.
// 화면 사진은 HEAD_SHOTS(작업 폴더 밖 임시 폴더)가 있으면 그곳, 없으면 test-results 아래
const DIR = process.env.HEAD_SHOTS || `${SHOTS}/head-actions-1109`;
mkdirSync(DIR, { recursive: true });

const HEAD = 'header[data-part="header"]';
const SH = '[data-part="screen-head"]';
const DASH = '[data-part="dashboard"]';
const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as unknown;
const EVAL = { static: load('static'), runtime: load('runtime'), model: load('model'), modelAll: load('model-all') };

const evaluationApi = (page: Page) => page.route(/\/api\/evaluation$/, (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(EVAL) }));
// 가짜 백엔드에는 공급망 검사가 없다(404) — 빈 목록
const scansApi = (page: Page) => page.route(/\/api\/scans(\?|$)/, (r) => r.fulfill({ contentType: 'application/json', body: '[]' }));

// 주 버튼이 있는 화면 — [경로, 준비 확인, 버튼 자리 안에 있어야 하는 것들]
type Want = (a: Locator) => Locator[];
const WITH_ACTIONS: [string, string, Want][] = [
  ['/policies', 'table[data-table="policies"] tbody tr', (a) => [a.getByRole('button', { name: 'YAML 일괄 적용' }), a.getByRole('button', { name: '정책 생성' })]],
  ['/settings', '[data-part="settings-tabs"]', (a) => [a.locator('[data-action="layout-reset"]')]],
  ['/installs', '[data-testid="installs"]', (a) => [a.getByRole('button', { name: '사용 방법' }), a.getByRole('button', { name: '명령 복사' })]],
  ['/topology', '[data-testid="topology"]', (a) => [a.getByRole('combobox'), a.getByRole('slider')]],
  ['/evaluation', '[data-part="evaluation"][data-state="ready"]', (a) => [a.locator('[data-action="toggle-all"]'), a.locator('[data-action="download-json"]')]],
  ['/events', '[data-testid="events"]', (a) => [a.getByRole('button', { name: '일시정지' })]],
  ['/audit', '[data-testid="audit"]', (a) => [a.getByRole('button', { name: '위반 이력' }), a.getByRole('button', { name: '판정 · 변경 이력' })]],
  ['/report?case=case-0004', '[data-testid="report"]', (a) => [a.getByRole('button', { name: '인쇄' }), a.getByRole('button', { name: 'Markdown 복사' })]],
];
// 설명 줄은 있지만 화면 단위 주 버튼이 없는 화면(표 도구줄 · 거르기 · 검사 입력 칸 · 시나리오 실행은 제자리)
const NO_ACTIONS: [string, string][] = [
  ['/policies/blocklist', '[data-testid="blocklist"]'],
  ['/policies/changes', '[data-testid="changes"]'],
  ['/scans', '[data-part="scan-form"]'],
  ['/demo', '[data-part="demo-page"]'],
];

async function open(page: Page, url: string, ready: string) {
  await page.goto(url);
  await expect(page.locator(ready).first()).toBeVisible({ timeout: 10_000 });
}
const box = async (l: Locator) => {
  await expect(l).toBeVisible();
  return (await l.boundingBox())!;
};

// 한 줄 · 오른쪽 끝: 버튼 자리의 세로 가운데가 설명 줄과 같고, 오른쪽 끝이 줄의 오른쪽 끝, 설명은 왼쪽 끝에서 시작
async function expectRightOfCopy(page: Page, url: string) {
  const head = page.locator(SH);
  await expect(head, url).toHaveCount(1);
  const [h, c, a] = await Promise.all([box(head), box(head.locator('[data-part="screen-copy"]')), box(head.locator('[data-part="page-actions"]'))]);
  expect(Math.abs(c.y + c.height / 2 - (a.y + a.height / 2)), `${url} 같은 줄`).toBeLessThanOrEqual(2);
  expect(Math.abs(h.x + h.width - (a.x + a.width)), `${url} 오른쪽 끝`).toBeLessThanOrEqual(1);
  expect(Math.abs(c.x - h.x), `${url} 설명은 왼쪽 끝`).toBeLessThanOrEqual(1);
  expect(c.x + c.width, `${url} 설명과 버튼이 겹치지 않음`).toBeLessThanOrEqual(a.x);
  // 줄은 본문 칸의 오른쪽 끝까지(머리 줄 아래 본문 폭 전부)
  const inner = await page.locator('main').evaluate((m) => {
    const r = m.getBoundingClientRect();
    return r.right - parseFloat(getComputedStyle(m).paddingRight);
  });
  expect(Math.abs(h.x + h.width - inner), `${url} 줄이 본문 오른쪽 끝까지`).toBeLessThanOrEqual(1);
}

async function headerHasNoActions(page: Page, url: string) {
  const header = page.locator(HEAD);
  await expect(header.locator('[data-testid="page-actions"], [data-part="page-actions"]'), `${url} 머리 줄에 버튼 칸 없음`).toHaveCount(0);
  // 머리 줄 = 메뉴(768 미만) · 제목 · 실시간 연결 · 알림 · 해/달 · 사용 안내 · 계정만 — 화면 버튼 · 입력 없음
  const names = await header.locator('button, select, input, [role="group"]').evaluateAll((els) =>
    els.filter((e) => (e as HTMLElement).offsetParent !== null).map((e) => e.getAttribute('aria-label') ?? e.getAttribute('data-part') ?? e.textContent?.trim() ?? ''),
  );
  for (const n of names) expect(n, `${url} 머리 줄 단추`).toMatch(/^(메뉴|알림 \d+건 안 읽음|밝은 화면으로|어두운 화면으로|사용 안내 \(\?\)|account)$/);
  expect(await header.innerText(), `${url} 머리 줄 「—」 없음`).not.toContain('—');
}

test.describe('③ 주 버튼 = 화면 설명 줄 오른쪽 끝(1440)', () => {
  test('정책: 「YAML 일괄 적용」 · 「정책 생성」이 설명 줄과 같은 줄 오른쪽 끝, 머리 줄에는 없음', async ({ page, backend }) => {
    void backend;
    await open(page, '/policies', 'table[data-table="policies"] tbody tr');
    const head = page.locator(SH);
    const acts = head.locator('[data-part="page-actions"]');
    await expect(acts.getByRole('button')).toHaveText(['YAML 일괄 적용', '정책 생성']);
    // 예전 시험이 찾는 이름(getByTestId('page-actions'))도 이 자리 하나뿐
    await expect(page.getByTestId('page-actions')).toHaveCount(1);
    await expect(head.getByTestId('page-actions')).toHaveCount(1);
    await expect(head.locator('[data-part="screen-copy"]')).toHaveText('컨테이너 행동을 판정하는 정책을 만들고 적용 범위를 관리합니다.');
    await expect(head.locator('[data-part="screen-copy"]')).toHaveAttribute('data-screen', 'policies');
    await expectRightOfCopy(page, '/policies');
    await headerHasNoActions(page, '/policies');
    await expect(page.locator(HEAD).getByRole('button', { name: '정책 생성' })).toHaveCount(0);
    // 설명 줄은 화면 맨 위(본문 첫 줄)
    const [m, h] = await Promise.all([box(page.locator('main')), box(head)]);
    expect(h.y - m.y).toBeLessThanOrEqual(25);
    // 단추는 그대로 동작
    await acts.getByRole('button', { name: '정책 생성' }).click();
    await expect(page).toHaveURL(/[?&]id=/);
    await noPageOverflow(page);
  });

  test('주 버튼이 있는 화면 전부 같은 규칙 · 버튼 없는 화면은 빈 버튼 칸이 자리를 차지하지 않음', async ({ page, backend }) => {
    test.setTimeout(120_000);
    backend.enableDemo();
    await evaluationApi(page);
    await scansApi(page);
    for (const [url, ready, want] of WITH_ACTIONS) {
      await open(page, url, ready);
      const acts = page.locator(`${SH} [data-part="page-actions"]`);
      for (const l of want(acts)) await expect(l, `${url} 버튼 자리 안`).toBeVisible();
      await expectRightOfCopy(page, url);
      await headerHasNoActions(page, url);
      await noPageOverflow(page);
      expect(await page.locator(SH).innerText(), `${url} 「—」 없음`).not.toContain('—');
    }
    for (const [url, ready] of NO_ACTIONS) {
      await open(page, url, ready);
      const head = page.locator(SH);
      await expect(head, url).toHaveCount(1);
      await expect(head.locator('[data-part="screen-copy"]'), url).toHaveCount(1);
      await expect(head.locator('[data-part="page-actions"]'), url).toBeHidden();
      await headerHasNoActions(page, url);
      await noPageOverflow(page);
    }
    // 인쇄(건 보고서)에서는 버튼 칸을 숨긴다 — 예전 머리 줄처럼
    await open(page, '/report?case=case-0004', '[data-testid="report"]');
    await page.emulateMedia({ media: 'print' });
    await expect(page.locator(`${SH} [data-part="page-actions"]`)).toBeHidden();
    await expect(page.getByTestId('report')).toBeVisible();
    await page.emulateMedia({ media: 'screen' });
    await expect(page.locator(`${SH} [data-part="page-actions"]`)).toBeVisible();
  });

  test('조회자: 정책 화면 버튼 칸은 비어 숨고 오류 없음 · 화면을 옮겨도 버튼이 남지 않음', async ({ page, backend }) => {
    backend.auth.asViewer();
    await scansApi(page);
    await open(page, '/policies', 'table[data-table="policies"] tbody tr');
    await expect(page.locator(`${SH} [data-part="page-actions"]`)).toBeHidden();
    await expect(page.getByRole('button', { name: '정책 생성' })).toHaveCount(0);
    // 버튼이 있는 화면 → 없는 화면 → 있는 화면: 앞 화면 버튼이 남거나 사라지지 않는다
    await open(page, '/installs', '[data-testid="installs"]');
    await expect(page.locator(`${SH} [data-part="page-actions"]`).getByRole('button', { name: '사용 방법' })).toBeVisible();
    await page.locator('nav[aria-label="화면"]').getByRole('link', { name: '공급망 검사' }).click();
    await expect(page.locator('[data-part="scan-form"]')).toBeVisible();
    await expect(page.getByRole('button', { name: '사용 방법' })).toHaveCount(0);
    await page.locator('nav[aria-label="화면"]').getByRole('link', { name: '설치 검사' }).first().click();
    await expect(page.locator(`${SH} [data-part="page-actions"]`).getByRole('button', { name: '사용 방법' })).toBeVisible();
    await expect(page.getByRole('button', { name: '사용 방법' })).toHaveCount(1);
  });

  test('대시보드: 최종 갱신 · 새로고침 · 기간이 맨 위 줄 오른쪽 끝(같은 줄), 머리 줄에는 없음', async ({ page, backend }) => {
    void backend;
    await open(page, '/', '[data-testid="pending"]');
    const top = page.locator(`${DASH} [data-part="dash-top"]`);
    const acts = top.locator('[data-part="page-actions"]');
    await expect(acts).toHaveCount(1);
    await expect(acts.locator('[data-part="dash-updated"]')).toBeVisible();
    await expect(acts.getByRole('button', { name: '새로고침(대시보드)' })).toBeVisible();
    await expect(acts.locator('[data-range]')).toHaveCount(3);
    const [t, a, p] = await Promise.all([box(top), box(acts), box(top.getByTestId('signal-pills'))]);
    expect(Math.abs(t.x + t.width - (a.x + a.width)), '오른쪽 끝').toBeLessThanOrEqual(1);
    expect(Math.abs(p.y + p.height / 2 - (a.y + a.height / 2)), '신호등과 같은 줄').toBeLessThanOrEqual(2);
    expect(t.height, '맨 위 줄 한 줄').toBeLessThan(48);
    await headerHasNoActions(page, '/');
    await noPageOverflow(page);
  });
});

test.describe('1280×720 — 한 줄 · 화면 스크롤 0', () => {
  test.use({ viewport: { width: 1280, height: 720 } });
  test('정책 · 감사 로그 · 평가 · 설치 검사 · 대시보드', async ({ page, backend }) => {
    test.setTimeout(60_000);
    void backend;
    await evaluationApi(page);
    for (const [url, ready] of WITH_ACTIONS.filter(([u]) => ['/policies', '/audit', '/evaluation', '/installs'].includes(u))) {
      await open(page, url, ready);
      await expectRightOfCopy(page, url);
      await noPageOverflow(page);
    }
    await open(page, '/', '[data-testid="pending"]');
    const top = page.locator(`${DASH} [data-part="dash-top"]`);
    expect((await box(top)).height).toBeLessThan(48);
    const [t, a] = await Promise.all([box(top), box(top.locator('[data-part="page-actions"]'))]);
    expect(Math.abs(t.x + t.width - (a.x + a.width))).toBeLessThanOrEqual(1);
    expect(await page.locator(DASH).evaluate((d) => d.scrollHeight - d.clientHeight), '대시보드 스크롤').toBe(0);
    await noPageOverflow(page);
  });
});

test.describe('390 — 버튼은 설명 아래 줄 · 가로 넘침 0', () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test('정책 · 설치 검사 · 평가 · 감사 로그 · 건 보고서 · 대시보드', async ({ page, backend }) => {
    test.setTimeout(60_000);
    void backend;
    await evaluationApi(page);
    for (const [url, ready] of WITH_ACTIONS.filter(([u]) => ['/policies', '/installs', '/evaluation', '/audit', '/report?case=case-0004', '/topology'].includes(u))) {
      await open(page, url, ready);
      const head = page.locator(SH);
      const [c, a] = await Promise.all([box(head.locator('[data-part="screen-copy"]')), box(head.locator('[data-part="page-actions"]'))]);
      expect(a.y, `${url} 버튼은 설명 아래 줄`).toBeGreaterThanOrEqual(c.y + c.height - 1);
      expect(a.x + a.width, `${url} 버튼이 화면 안`).toBeLessThanOrEqual(390 - 16 + 1);
      expect(await head.evaluate((e) => e.scrollWidth - e.clientWidth), `${url} 줄 넘침`).toBe(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth), `${url} 가로 넘침`).toBe(0);
      await headerHasNoActions(page, url);
    }
    await open(page, '/', '[data-testid="pending"]');
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth), '대시보드 가로 넘침').toBe(0);
  });
});

test.describe('사진(1440 밝은 · 어두운 — 정책 · 감사 로그 · 대시보드, 390 정책)', () => {
  for (const theme of ['light', 'dark'] as const) {
    test(`1440 ${theme}`, async ({ page, backend }) => {
      void backend;
      await page.addInitScript((t) => localStorage.setItem('supplyguard.theme', t), theme);
      await open(page, '/policies', 'table[data-table="policies"] tbody tr');
      await page.screenshot({ path: `${DIR}/head-policies-1440-${theme}.png` });
      await open(page, '/audit', '[data-testid="audit"]');
      await page.screenshot({ path: `${DIR}/head-audit-1440-${theme}.png` });
      await open(page, '/', '[data-testid="pending"]');
      await page.waitForTimeout(900); // 카운트업이 끝난 뒤
      await page.screenshot({ path: `${DIR}/head-dashboard-1440-${theme}.png` });
    });
  }
  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390 정책', async ({ page, backend }) => {
      void backend;
      await open(page, '/policies', 'table[data-table="policies"] tbody tr');
      await page.screenshot({ path: `${DIR}/head-policies-390-light.png` });
    });
  });
});
