import type { Page } from '@playwright/test';
import { expect, noPageOverflow, test } from './fixtures';

// 11/09 저녁 묶음 A(셸 · 상단) — 참고 제품 UI 문서와 대조해 빠진 항목을 채운다(번호는 메인 항목 표).
// G43 화면 제목 21/700 · G01 테마 = 상단 해/달 단추 하나(처음은 PC 설정 · 누르면 기억 · 전환 450ms · 동작 줄이기면 즉시)

const THEME_KEY = 'supplyguard.theme';
const TOGGLE = '[data-part="theme-toggle"]';
const rgb = (hex: string) => {
  const n = parseInt(hex.replace('#', ''), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
};
const themeOf = (p: Page) => p.evaluate(() => document.documentElement.dataset.theme);
const stored = (p: Page) => p.evaluate((k) => localStorage.getItem(k), THEME_KEY);
const bodyBg = (p: Page) => p.evaluate(() => getComputedStyle(document.body).backgroundColor);
// 전환(html.sg-theme-anim)이 끝날 때까지
const settled = (p: Page) => p.waitForFunction(() => !document.documentElement.classList.contains('sg-theme-anim'));
async function ready(page: Page, path = '/') {
  await page.goto(path);
  await expect(page.getByText('실시간 연결됨')).toBeVisible();
}

test.describe('G43 화면 제목', () => {
  test('제목 = 21px/700(--fs-xl) · 머리 56px 그대로 · 1440×900 넘침 0', async ({ page, backend }) => {
    void backend;
    for (const path of ['/', '/policies', '/settings']) {
      await page.goto(path);
      const title = page.getByTestId('page-title');
      await expect(title).not.toBeEmpty();
      expect(await title.evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight])).toEqual(['21px', '700']);
      expect((await page.locator('header[data-part="header"]').boundingBox())!.height).toBe(56);
      await noPageOverflow(page);
    }
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390 에서도 21px · 머리 56px · 넘침 0', async ({ page, backend }) => {
      void backend;
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      expect(await page.getByTestId('page-title').evaluate((e) => getComputedStyle(e).fontSize)).toBe('21px');
      expect((await page.locator('header[data-part="header"]').boundingBox())!.height).toBe(56);
      await noPageOverflow(page);
    });
  });
});

test.describe('G01 테마 = 상단 해/달 단추 하나', () => {
  test('처음은 PC 설정 · 누르면 반대로 · 이름은 할 동작(aria-pressed 아님) · 새로고침 뒤 유지', async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ colorScheme: 'dark' });
    await ready(page);
    const btn = page.locator(`header[data-part="header"] ${TOGGLE}`);
    await expect(btn).toBeVisible();
    expect(await themeOf(page)).toBe('dark');
    expect(await stored(page)).toBeNull();
    await expect(btn).toHaveAttribute('aria-label', '밝은 화면으로');
    await expect(btn).toHaveAttribute('title', '밝은 화면으로');
    expect(await btn.getAttribute('aria-pressed')).toBeNull();
    await btn.click();
    expect(await themeOf(page)).toBe('light');
    expect(await stored(page)).toBe('light');
    await expect(btn).toHaveAttribute('aria-label', '어두운 화면으로');
    await expect(btn).toHaveAttribute('title', '어두운 화면으로');
    // PC 가 다크여도 고른 라이트가 남는다
    await page.reload();
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    expect(await themeOf(page)).toBe('light');
    await btn.click();
    expect(await themeOf(page)).toBe('dark');
    expect(await stored(page)).toBe('dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await page.reload();
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    expect(await themeOf(page)).toBe('dark');
    // 기억을 지우면 다시 PC 설정(라이트)
    await page.evaluate((k) => localStorage.removeItem(k), THEME_KEY);
    await page.reload();
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    expect(await themeOf(page)).toBe('light');
    await expect(btn).toHaveAttribute('aria-label', '어두운 화면으로');
    // 오른쪽 위 묶음: 종(알림) 오른쪽 · 계정 왼쪽
    const [bell, toggle, account] = await Promise.all(['[data-part="bell"]', TOGGLE, '[data-part="account"]'].map((s) => page.locator(`header ${s}`).boundingBox()));
    expect(toggle!.x).toBeGreaterThan(bell!.x);
    expect(toggle!.x).toBeLessThan(account!.x);
  });

  test('전환 450ms(--dur-slow) — 색만 바뀌고 끝나면 규칙을 뗀다 · 동작 줄이기면 즉시', async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ colorScheme: 'light' });
    await ready(page);
    expect(await bodyBg(page)).toBe(rgb('#F6F7FB'));
    await page.locator(TOGGLE).click();
    const during = await page.evaluate(() => ({
      anim: document.documentElement.classList.contains('sg-theme-anim'),
      dur: getComputedStyle(document.body).transitionDuration,
      prop: getComputedStyle(document.body).transitionProperty,
    }));
    expect(during.anim).toBe(true);
    expect(during.dur.split(', ')[0]).toBe('0.45s');
    expect(during.prop).toContain('background-color');
    await settled(page);
    expect(await bodyBg(page)).toBe(rgb('#11131A'));
    expect(await page.evaluate(() => getComputedStyle(document.body).transitionDuration)).toBe('0s');
    // 동작 줄이기: 전환 규칙을 붙이지 않고 바로 바뀐다
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.locator(TOGGLE).click();
    expect(await page.evaluate(() => document.documentElement.classList.contains('sg-theme-anim'))).toBe(false);
    expect(await themeOf(page)).toBe('light');
    expect(await bodyBg(page)).toBe(rgb('#F6F7FB'));
  });

  test('계정 메뉴에는 테마 칸이 없다', async ({ page, backend }) => {
    void backend;
    await ready(page);
    await page.locator('[data-part="account"]').click();
    const menu = page.locator('[data-part="account-menu"]');
    await expect(menu).toBeVisible();
    await expect(menu.locator('[data-theme-pick]')).toHaveCount(0);
    await expect(menu).not.toContainText('테마');
    await expect(menu.getByRole('menuitem')).toHaveText(['내 정보', '비밀번호 변경', '로그아웃']);
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390: 도움말 단추는 숨어도 해/달 단추는 머리에 보인다', async ({ page, backend }) => {
      void backend;
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      const btn = page.locator(`header ${TOGGLE}`);
      await expect(btn).toBeVisible();
      const box = (await btn.boundingBox())!;
      expect(box.x + box.width).toBeLessThanOrEqual(390);
      await btn.click();
      expect(await themeOf(page)).toBe('dark');
      await noPageOverflow(page);
    });
  });
});
