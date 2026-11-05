import type { Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 10/30 2단계 — F6 디자인 토큰 · 공통 부품 · 모션, F7 다크 모드, F8 768px 미만(계약 §7). 문구 · 선택자 · URL · 동작은 그대로

const THEME_KEY = 'supplyguard.theme';
const rgb = (hex: string) => {
  const n = parseInt(hex.replace('#', ''), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
};
// WCAG 대비(토큰 hex 두 개)
const lum = (hex: string) => {
  const n = parseInt(hex.replace('#', ''), 16);
  const c = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const contrast = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};
const token = (page: Page, name: string) => page.evaluate((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim(), name);
const themeOf = (page: Page) => page.evaluate(() => document.documentElement.dataset.theme);
async function pickTheme(page: Page, t: 'system' | 'light' | 'dark') {
  const btn = page.locator('[data-part="account"]');
  if ((await btn.getAttribute('aria-expanded')) !== 'true') await btn.click();
  await page.locator(`[data-part="account-menu"] [data-theme-pick="${t}"]`).click();
}
// 공급망 검사 목록 API 는 가짜 백엔드에 없다(scans.spec 처럼 화면 스텁) — 빈 목록
const stubScans = (page: Page) => page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));

const SCREENS: [string, string, string][] = [
  ['dashboard', '/', 'pending'],
  ['installs', '/installs?id=ins-0012', 'installs'],
  ['scans', '/scans', 'scans'],
  ['events', '/events?id=7', 'events'],
  ['topology', '/topology?node=c%3Apkg-reqeusts', 'topology'],
  ['policies', '/policies?id=egress-allowlist', 'rules'],
  ['audit', '/audit', 'audit'],
  ['settings', '/settings', 'settings-tabs'],
];
async function settle(page: Page, url: string, testId: string) {
  await page.goto(url);
  const el = testId === 'settings-tabs' ? page.locator('[data-part="settings-tabs"]') : page.getByTestId(testId);
  await expect(el).toBeVisible();
  if (testId === 'topology') await expect(page.locator('.react-flow__node').first()).toBeVisible();
  await page.waitForTimeout(350);
}

test.describe('F6 디자인 토큰 · 부품 · 모션', () => {
  test('계약 §7 토큰이 :root 에 값 그대로 · 몸통 · 카드 · 표 머리 · 버튼 · 시트가 토큰을 쓴다', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=egress-allowlist');
    await expect(page.getByTestId('editor')).toBeVisible();
    for (const [k, v] of [
      // 11/05: 참고 대시보드 값으로 교체(10/30 계약 §7 값 대체)
      ['--bg', '#F6F7FB'], ['--surface', '#FFFFFF'], ['--surface-2', '#EEF0F4'], ['--border', '#ECEEF4'], ['--text', '#202534'], ['--text-2', '#7A8090'], ['--text-3', '#7A8090'],
      ['--accent', '#1769E8'], ['--accent-soft', '#DCE9FF'], ['--danger', '#E4516F'], ['--warn', '#F5A623'], ['--warn-soft', '#FFF5DF'], ['--ok', '#25B884'], ['--info', '#0288D1'],
      ['--r-lg', '8px'], ['--t-base', '200ms'], ['--sidebar-w', '240px'], ['--header-h', '56px'],
    ]) expect(await token(page, k), k).toBe(v);
    expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(rgb('#F6F7FB'));
    expect(await page.getByTestId('rules').evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#FFFFFF'));
    // 표 머리(11/05 참고 대시보드): 12/600 · 보조색 · 회색 바탕
    await page.goto('/audit');
    const th = page.locator('[data-testid="audit"] thead th').first();
    await expect(th).toBeVisible();
    const thStyle = await th.evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight, getComputedStyle(e).color]);
    expect(thStyle).toEqual(['12px', '600', rgb('#7A8090')]);
    expect(await th.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#EEF0F4'));
    // 버튼(11/05): 패딩 6/16 · 14.4/1.5 → 높이 33.6 · 반경 6 · 700, 시트
    await page.goto('/policies?id=egress-allowlist');
    const btn = page.locator('[data-view="rule-editor"]').getByRole('button', { name: '저장 전 확인' });
    expect((await btn.boundingBox())!.height).toBeCloseTo(33.6, 0);
    expect(await btn.evaluate((e) => getComputedStyle(e).fontWeight)).toBe('700');
    expect(await btn.evaluate((e) => getComputedStyle(e).borderRadius)).toBe('6px');
    await page.goto('/installs?id=ins-0012');
    await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
    expect((await page.locator('[data-sheet="install"]').boundingBox())!.width).toBeCloseTo(840, 0); // 11/05: 설치 검사 패널 = 본문 70%(1440 → 840), 옛 계약 480 은 바뀜
    expect(await page.locator('[data-sheet="install"]').evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#FFFFFF'));
    // dns 배지는 warn 토큰
    await page.goto('/policies');
    await page.getByRole('button', { name: '새 정책' }).click();
    await page.locator('[data-template="dns-exfil"]').click();
    await page.locator('[data-view="rule-editor"]').getByRole('button', { name: '저장 전 확인' }).click();
    await page.locator('[data-part="save-check"]').getByRole('button', { name: '저장 후 적용' }).click();
    const badge = page.locator('[data-rule^="runtime-dns-exfil"] [data-kind-badge="dns"]').first();
    expect(await badge.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color])).toEqual([rgb('#FFF5DF'), rgb('#946000')]);
  });

  test('모션: 화면 전환 · 새 위반 행 하이라이트 · 단계 레일 — prefers-reduced-motion: reduce 면 전부 끔', async ({ page, backend }) => {
    await page.goto('/events');
    const screen = page.locator('main [data-part="screen"]');
    await expect(screen).toBeVisible();
    expect(await screen.evaluate((e) => getComputedStyle(e).animationName)).toBe('sg-enter');
    expect(await screen.evaluate((e) => getComputedStyle(e).animationDuration)).toBe('0.2s');
    await expect(page.locator('li[data-key]').first()).toBeVisible();
    backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    const fresh = page.locator('li[data-key]').first();
    await expect(fresh).toContainText('api-gw');
    await expect(fresh).toHaveAttribute('data-fresh', 'true');
    expect(await fresh.evaluate((e) => getComputedStyle(e).animationName)).toBe('sg-flash');
    await expect(page.locator('li[data-key]').nth(1)).not.toHaveAttribute('data-fresh', 'true');
    // reduced motion
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/events');
    await expect(screen).toBeVisible();
    expect(await screen.evaluate((e) => getComputedStyle(e).animationName)).toBe('none');
    backend.send({ type: 'verdict', data: killedVerdict('api-gw2') });
    await expect(page.locator('li[data-key]').first()).toContainText('api-gw2');
    expect(await page.locator('li[data-key]').first().evaluate((e) => getComputedStyle(e).animationName)).toBe('none');
    expect(await page.locator('[data-part="sidebar"] nav a[href="/"]').evaluate((e) => getComputedStyle(e).transitionDuration)).toBe('0s');
  });
});

test.describe('F7 다크 모드', () => {
  test('기본은 시스템(prefers-color-scheme) · 첫 그리기 전에 data-theme · color-scheme', async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');
    expect(await themeOf(page)).toBe('dark');
    expect(await page.evaluate(() => localStorage.getItem('supplyguard.theme'))).toBeNull();
    // React 가 뜨기 전(머리 스크립트)에 이미 적용 — 첫 그리기 깜빡임 없음
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await expect.poll(() => themeOf(page)).toBe('light');
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('light');
  });

  test('계정 메뉴 「테마」(시스템 · 라이트 · 다크) → localStorage 저장 · 새로고침 뒤에도 · 토큰이 다크 값', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await page.locator('[data-part="account"]').click();
    const picks = page.locator('[data-part="account-menu"] [data-theme-pick]');
    expect(await picks.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.themePick))).toEqual(['system', 'light', 'dark']);
    await expect(page.locator('[data-part="account-menu"]')).toContainText('테마');
    await expect(picks.nth(0)).toHaveAttribute('aria-checked', 'true');
    await picks.nth(2).click();
    expect(await themeOf(page)).toBe('dark');
    expect(await page.evaluate((k) => localStorage.getItem(k), THEME_KEY)).toBe('dark');
    for (const [k, v] of [['--bg', '#11131A'], ['--surface', '#1B1E28'], ['--text', '#F2F3F7'], ['--accent', '#1769E8'], ['--danger', '#E4516F'], ['--warn', '#F5A623'], ['--warn-soft', '#423627']])
      expect(await token(page, k), k).toBe(v);
    expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(rgb('#11131A'));
    expect(await page.getByTestId('pending').evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#1B1E28'));
    expect(await page.getByTestId('page-title').evaluate((e) => getComputedStyle(e).color)).toBe(rgb('#F2F3F7'));
    await page.reload();
    expect(await themeOf(page)).toBe('dark');
    await expect(page.getByTestId('pending')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/1030-dark.png` });
    // 시스템이 다크여도 「라이트」를 고르면 라이트
    await page.emulateMedia({ colorScheme: 'dark' });
    await pickTheme(page, 'light');
    expect(await themeOf(page)).toBe('light');
    expect(await page.evaluate((k) => localStorage.getItem(k), THEME_KEY)).toBe('light');
    await pickTheme(page, 'system');
    expect(await themeOf(page)).toBe('dark');
    expect(await page.evaluate((k) => localStorage.getItem(k), THEME_KEY)).toBe('system');
  });

  test('다크에서 본문 대비 AA(text · text-2 · text-3 on surface) · 차트 · 토폴로지 색이 토큰', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await pickTheme(page, 'dark');
    for (const t of ['--text', '--text-2', '--text-3']) {
      const ratio = contrast(await token(page, t), await token(page, '--surface'));
      expect(ratio, `${t} on --surface`).toBeGreaterThanOrEqual(4.5);
      expect(contrast(await token(page, t), await token(page, '--bg')), `${t} on --bg`).toBeGreaterThanOrEqual(4.5);
    }
    expect(contrast(await token(page, '--text-inverse'), await token(page, '--accent'))).toBeGreaterThanOrEqual(4.5);
    const legend = page.locator('[data-section="overview"] [data-chart="violations"] .chart-legend .sw.k-killed'); // R2 11/04: R1 막대 차트 범례(.sw.k-killed)
    await expect(legend).toBeVisible();
    expect(await legend.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#E4516F'));
    await page.goto('/topology?node=c%3Apkg-reqeusts');
    const node = page.locator('.react-flow__node', { hasText: /^pkg-reqeusts/ }).first();
    await expect(node).toBeVisible();
    expect(await node.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#E4516F'));
  });
});

test.describe('F8 768px 미만 · 뷰포트별 넘침 0', () => {
  test.describe('390 서랍 사이드바', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('사이드바는 서랍(메뉴 버튼 · dim · Esc) · 머리 56px · 시트 전체 화면 · 표 가로 스크롤', async ({ page, backend }) => {
      void backend;
      await stubScans(page);
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      const side = page.locator('aside[data-part="sidebar"]');
      await expect(side).toBeHidden();
      expect((await page.locator('header[data-part="header"]').boundingBox())!.height).toBe(56);
      const menu = page.getByRole('button', { name: '메뉴' });
      await menu.click();
      await expect(side).toBeVisible();
      await expect(page.locator('[data-part="sidebar-dim"]')).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(side).toBeHidden();
      await menu.click();
      await side.getByRole('link', { name: '설치 검사' }).first().click();
      await expect(page.getByTestId('page-title')).toHaveText('설치 검사');
      await expect(side).toBeHidden(); // 이동하면 닫힘
      await page.locator('tr[data-install]').first().click();
      const sheet = page.locator('[data-sheet="install"]');
      await expect(sheet).toBeVisible();
      await page.waitForTimeout(350); // 들어오는 애니메이션(translateX 16px → 0, 200ms)이 끝난 뒤 잰다
      const box = (await sheet.boundingBox())!;
      expect(box.width).toBeCloseTo(390, 0);
      expect(box.x).toBeCloseTo(0, 0);
      await page.keyboard.press('Escape');
      await expect(sheet).toHaveCount(0);
      // 표는 overflow-x:auto 컨테이너 안(최소 폭 640), 본문은 안 넘친다
      await page.goto('/audit');
      await expect(page.locator('tr[data-audit]').first()).toBeVisible();
      const scroll = page.getByTestId('audit-scroll');
      expect(await scroll.evaluate((e) => [getComputedStyle(e).overflowX, e.scrollWidth > e.clientWidth, e.querySelector('table')!.getBoundingClientRect().width >= 640])).toEqual(['auto', true, true]);
      await noPageOverflow(page);
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      await page.screenshot({ path: `${SHOTS}/1030-mobile.png`, fullPage: false });
      // R2 11/04: 시연 카드는 대시보드에서 뺐다(시연 페이지 — R3) — 시연이 켜져도 대시보드에는 없다
      backend.enableDemo();
      await page.reload();
      await expect(page.getByTestId('pending')).toBeVisible();
      await expect(page.getByTestId('demo')).toHaveCount(0);
      await page.goto('/report?install=ins-0012');
      await expect(page.getByTestId('report').locator('[data-section="meta"]')).toBeVisible();
      await noPageOverflow(page);
      await page.screenshot({ path: `${SHOTS}/1030-report-390.png` });
      // 390 스크린샷: 타임라인(설치 시트 전체 화면) · 신호등 · 다크
      backend.enableIsolation();
      await page.goto('/installs?id=ins-0012');
      await expect(page.locator('[data-sheet="install"] [data-testid="timeline-bar"]')).toBeVisible();
      await page.screenshot({ path: `${SHOTS}/1030-timeline-390.png` });
      await page.goto('/');
      await expect(page.getByTestId('signal-pills')).toBeVisible();
      await page.screenshot({ path: `${SHOTS}/1030-signal-390.png` });
      await pickTheme(page, 'dark');
      await page.keyboard.press('Escape');
      await expect(page.getByTestId('pending')).toBeVisible();
      await page.screenshot({ path: `${SHOTS}/1030-dark-390.png` });
    });
  });

  for (const [w, h] of [
    [390, 844],
    [768, 700],
    [1024, 768],
    [1280, 800],
    [1440, 900],
  ]) {
    for (const theme of ['light', 'dark'] as const) {
      test.describe(`${w}×${h} ${theme}`, () => {
        test.use({ viewport: { width: w, height: h } });
        test(`8화면 넘침 0`, async ({ page, backend }) => {
          void backend;
          await stubScans(page);
          await page.addInitScript((t) => localStorage.setItem('supplyguard.theme', t), theme);
          for (const [name, url, testId] of SCREENS) {
            await settle(page, url, testId);
            expect(await themeOf(page), name).toBe(theme);
            await noPageOverflow(page);
            // 머리 줄도 잘리지 않는다
            const hdr = await page.locator('header[data-part="header"]').evaluate((e) => ({ over: e.scrollWidth - e.clientWidth, kids: [...e.children].map((c) => `${c.tagName}${c.getAttribute('data-testid') ?? c.getAttribute('data-part') ?? ''}:${Math.round(c.getBoundingClientRect().right)}`) }));
            expect(hdr.over, `${name} header ${JSON.stringify(hdr.kids)}`).toBe(0);
            if (w === 1440 && theme === 'dark' && name === 'dashboard') await page.screenshot({ path: `${SHOTS}/1030-dark-dashboard.png` });
          }
        });
      });
    }
  }
});
