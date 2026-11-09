import { mkdirSync } from 'node:fs';
import type { Locator, Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 11/10 셸 배치 — 참고 사이트의 배치 원리(값 · 원리만 옮긴다, 이름 · 로고 · 문구 · 아이콘 · 글꼴은 넣지 않음).
//   사이드바 = 큰 아이콘 24 + 글자 16/500, 지금 화면 700 · hover = 알약 모양 옅은 바탕 · 상자 · 테두리 없는 평평한 목록 · 계정은 맨 아래(메뉴는 위로)
//   폭 단계 = 1280 이상 글자 있는 사이드바 · 768~1279 아이콘만(자동) · 768 미만 서랍
//   제목 줄 = 본문 단 맨 위 고정(높이 53 · 바탕 85% 반투명 + 뒤 흐림 12 · 아래 1px 선 · 제목 21/700), 오른쪽 끝에 작은 상태 묶음
//   본문 단 = 좌우 1px 세로선 · 최대 폭 --content-max, 넓은 화면은 사이드바와 본문 단이 함께 가운데
// 화면 사진: X2_SHOTS(작업 폴더 밖 임시 폴더)/X2_PHASE(before | after)
const DIR = `${process.env.X2_SHOTS || `${SHOTS}/x-shell-1109`}/${process.env.X2_PHASE || 'after'}`;
mkdirSync(DIR, { recursive: true });

const ASIDE = 'aside[data-part="sidebar"]';
const NAV = `${ASIDE} nav[aria-label="화면"]`;
const HEAD = 'header[data-part="header"]';
const COL = '[data-part="column"]';
const ACCOUNT = '[data-part="account"]';
const MENU = '[data-part="account-menu"]';

// 계산된 색 → [r, g, b, a] (rgb · rgba · color(srgb …) 모두)
function parseColor(s: string): number[] {
  const m = s.match(/^color\(srgb ([-\d.e]+) ([-\d.e]+) ([-\d.e]+)(?: \/ ([-\d.e]+))?\)$/);
  if (m) return [+m[1] * 255, +m[2] * 255, +m[3] * 255, m[4] === undefined ? 1 : +m[4]];
  const n = (s.match(/[-\d.]+/g) ?? []).map(Number);
  return [n[0], n[1], n[2], n[3] ?? 1];
}
const hexRgb = (hex: string) => {
  const n = parseInt(hex.trim().replace('#', ''), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};
const near = (a: number[], b: number[], tol = 1.5) => a.length === b.length && a.every((x, i) => Math.abs(x - b[i]) <= tol);
const css = (l: Locator, p: string) => l.evaluate((e, prop) => getComputedStyle(e).getPropertyValue(prop), p);
const box = async (l: Locator) => {
  await expect(l).toBeVisible();
  return (await l.boundingBox())!;
};
const tokenOf = (page: Page, name: string) => page.evaluate((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim(), name);
// 들어오는 움직임(팝오버 · 서랍 · 화면 전환)이 끝날 때까지(반복 애니메이션 제외)
const still = (p: Page) =>
  p.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity));

const scansApi = (page: Page) => page.route(/\/api\/scans(\?|$)/, (r) => r.fulfill({ contentType: 'application/json', body: '[]' }));

const SCREENS: [string, string, string][] = [
  ['dashboard', '/', '[data-testid="pending"]'],
  ['policies', '/policies', 'table[data-table="policies"] tbody tr'],
  ['audit', '/audit', '[data-testid="audit"]'],
  ['integration', '/integration', '[data-part="integration"][data-page="setup"][data-state="ready"]'],
];
async function open(page: Page, url: string, ready: string) {
  await page.goto(url);
  await expect(page.locator(ready).first()).toBeVisible({ timeout: 10_000 });
}

// 셸(사이드바 · 제목 줄)에 보이는 「—」 없음
async function shellDashes(page: Page) {
  return page.evaluate(
    ([a, h]) => [a, h].flatMap((s) => Array.from(document.querySelectorAll(s))).flatMap((el) => ((el as HTMLElement).innerText.includes('—') ? [(el as HTMLElement).innerText.slice(0, 80)] : [])),
    [ASIDE, HEAD],
  );
}

test.describe('사이드바 모양', () => {
  test('아이콘 24 · 글자 16/500 · 지금 화면 700 · hover 알약(밝은 rgba(15,20,25,.1)) · 상자 · 테두리 · 그림자 없음', async ({ page, backend }) => {
    void backend;
    await open(page, '/', '[data-testid="pending"]');
    const side = page.locator(ASIDE);
    await expect(side).toHaveAttribute('data-collapsed', 'false');
    // 평평: 사이드바 오른쪽 선 · 그림자 없음(본문 단의 왼쪽 세로선이 경계)
    expect(await css(side, 'border-right-width')).toBe('0px');
    expect(await css(side, 'box-shadow')).toBe('none');
    const ev = page.locator(`${NAV} a[href="/events"]`);
    const home = page.locator(`${NAV} a[href="/"]`);
    for (const a of [ev, home]) {
      const icon = a.locator('svg').first();
      const ib = await box(icon);
      expect([Math.round(ib.width), Math.round(ib.height)]).toEqual([24, 24]);
      expect(await css(a, 'font-size')).toBe('16px');
      expect(await css(a, 'border-top-width')).toBe('0px');
    }
    expect(await css(ev, 'font-weight')).toBe('500');
    await expect(home).toHaveAttribute('aria-current', 'page');
    expect(await css(home, 'font-weight')).toBe('700');
    // 지금 화면은 굵기만이 아니라 색도 다르다
    expect(await css(home, 'color')).not.toBe(await css(ev, 'color'));
    // 지금 화면도 상자(바탕)가 없다 — hover 때만 알약
    expect(parseColor(await css(home, 'background-color'))[3]).toBe(0);
    expect(parseColor(await css(ev, 'background-color'))[3]).toBe(0);
    await ev.hover();
    await expect.poll(async () => parseColor(await css(ev, 'background-color'))).toEqual([15, 20, 25, 0.1]);
    const eb = await box(ev);
    expect(parseFloat(await css(ev, 'border-top-left-radius'))).toBeGreaterThanOrEqual(eb.height / 2);
    // 하위 메뉴 묶음 머리도 같은 모양(지금 화면 묶음이 아니면 500)
    const head = page.locator(`${NAV} [data-nav-sub="policies"] [data-part="subnav-toggle"]`);
    expect(await css(head, 'font-size')).toBe('16px');
    expect(await css(head, 'font-weight')).toBe('500');
    const hb = await box(head.locator('svg').first());
    expect(Math.round(hb.width)).toBe(24);
    await head.hover();
    await expect.poll(async () => parseColor(await css(head, 'background-color'))).toEqual([15, 20, 25, 0.1]);
    // 하위 화면: 묶음 머리 · 지금 하위 링크 = 700
    await open(page, '/policies/blocklist', '[data-testid="blocklist"]');
    expect(await css(head, 'font-weight')).toBe('700');
    const cur = page.locator(`${NAV} [data-part="subnav"] a[href="/policies/blocklist"]`);
    await expect(cur).toHaveAttribute('aria-current', 'page');
    expect(await css(cur, 'font-weight')).toBe('700');
    expect(await css(page.locator(`${NAV} [data-part="subnav"] a[href="/policies/changes"]`), 'font-weight')).toBe('500');
    // 묶음 이름표 · 접고 펴기 · 길게 눌러 옮기기는 그대로(다른 시험) — 이름표가 남아 있는지만
    await expect(page.locator(`${NAV} [data-nav-group="런타임 감시"]`)).toContainText('런타임 감시');
  });

  test('어두운 화면 hover = rgba(247,249,249,.1)', async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ colorScheme: 'dark' });
    await open(page, '/', '[data-testid="pending"]');
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    const ev = page.locator(`${NAV} a[href="/events"]`);
    await ev.hover();
    await expect.poll(async () => parseColor(await css(ev, 'background-color'))).toEqual([247, 249, 249, 0.1]);
  });
});

test.describe('계정 = 사이드바 맨 아래', () => {
  test('표시 이름 · 역할 · 제목 줄에는 없음 · 누르면 메뉴가 위로 · Esc 닫힘 · 접힌 사이드바에서도 위로', async ({ page, backend }) => {
    void backend;
    await open(page, '/', '[data-testid="pending"]');
    await expect(page.locator(`${HEAD} ${ACCOUNT}`)).toHaveCount(0);
    const side = page.locator(ASIDE);
    const acc = side.locator(ACCOUNT);
    await expect(acc).toHaveCount(1);
    await expect(acc).toContainText('관리자');
    const [s, a] = [await box(side), await box(acc)];
    expect(s.y + s.height - (a.y + a.height)).toBeLessThanOrEqual(16);
    expect(s.y + s.height - (a.y + a.height)).toBeGreaterThanOrEqual(0);
    // 계정 아래에 다른 칸이 없다(맨 아래)
    const below = await side.evaluate((el, sel) => {
      const accBox = el.querySelector(sel)!.getBoundingClientRect();
      return Array.from(el.querySelectorAll('a, button, [role="button"]')).filter((x) => x.getBoundingClientRect().top >= accBox.bottom && x.getBoundingClientRect().height > 0).length;
    }, ACCOUNT);
    expect(below).toBe(0);
    await acc.click();
    const menu = page.locator(MENU);
    await expect(menu).toBeVisible();
    await expect(menu.getByRole('menuitem')).toHaveText(['내 정보', '비밀번호 변경', '로그아웃']);
    await still(page);
    const m = await box(menu);
    expect(m.y + m.height).toBeLessThanOrEqual(a.y + 1);
    expect(m.y).toBeGreaterThanOrEqual(0);
    await page.keyboard.press('Escape');
    await expect(menu).toHaveCount(0);
    // 접힌 사이드바(아이콘만): 계정은 맨 아래 아이콘 · 이름은 툴팁 · 메뉴는 위로(화면 안)
    await page.keyboard.press('[');
    await expect(side).toHaveAttribute('data-collapsed', 'true');
    const a2 = await box(acc);
    expect(a2.width).toBeLessThanOrEqual(56);
    await expect(acc).toHaveAttribute('title', /관리자/);
    await acc.click();
    await expect(menu).toBeVisible();
    await still(page);
    const m2 = await box(menu);
    expect(m2.y + m2.height).toBeLessThanOrEqual(a2.y + 1);
    expect(m2.x + m2.width).toBeLessThanOrEqual(1440);
    await menu.getByRole('menuitem', { name: '내 정보' }).click();
    await expect(page.locator('[data-part="profile"]')).toContainText('admin');
  });
});

test.describe('폭 단계', () => {
  test('1280 이상 = 글자 있는 사이드바 · 1279 = 아이콘만(자동)', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 1280, height: 720 });
    await open(page, '/', '[data-testid="pending"]');
    const side = page.locator(ASIDE);
    await expect(side).toHaveAttribute('data-collapsed', 'false');
    expect(Math.round((await box(side)).width)).toBe(240);
    await expect(page.locator(`${NAV} a[href="/events"]`)).toContainText('이벤트');
    expect((await box(page.locator(`${NAV} a[href="/events"] [data-part="nav-label"]`))).width).toBeGreaterThan(20);
    await page.setViewportSize({ width: 1279, height: 720 });
    await expect(side).toHaveAttribute('data-collapsed', 'true');
    expect(Math.round((await box(side)).width)).toBe(56);
  });

  test.describe('1024', () => {
    test.use({ viewport: { width: 1024, height: 768 } });
    test('아이콘만(56) · 이름은 접근성 이름 · [ 로 펼치면 본문 위에 겹침(넘침 0) · 화면을 옮기면 다시 아이콘만', async ({ page, backend }) => {
      void backend;
      await open(page, '/', '[data-testid="pending"]');
      const side = page.locator(ASIDE);
      await expect(side).toHaveAttribute('data-collapsed', 'true');
      expect(Math.round((await box(side)).width)).toBe(56);
      const ev = page.locator(`${NAV} a[href="/events"]`);
      await expect(page.getByRole('navigation', { name: '화면' }).getByRole('link', { name: '이벤트' })).toBeVisible();
      const ib = await box(ev.locator('svg').first());
      expect(Math.round(ib.width)).toBe(24);
      expect((await box(ev)).width).toBeLessThanOrEqual(56);
      await ev.hover();
      await expect.poll(async () => parseColor(await css(ev, 'background-color'))).toEqual([15, 20, 25, 0.1]);
      // 본문은 사이드바 바로 옆(본문 단 왼쪽 세로선은 사이드바 끝 1px 과 겹침)
      expect(Math.round((await box(page.locator('main'))).x)).toBe(56);
      await page.keyboard.press('[');
      await expect(side).toHaveAttribute('data-collapsed', 'false');
      expect(await css(side, 'position')).toBe('fixed');
      expect(Math.round((await box(page.locator('main'))).x)).toBe(56); // 본문을 밀지 않음
      await noPageOverflow(page);
      await ev.click();
      await expect(page).toHaveURL(/\/events$/);
      await expect(side).toHaveAttribute('data-collapsed', 'true');
      await still(page);
      await page.screenshot({ path: `${DIR}/dashboard-1024-light.png` });
    });
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('서랍: 닫힘 · 메뉴로 열면 글자 있는 사이드바 + 맨 아래 계정 · 본문 단 세로선 없음 · 넘침 0', async ({ page, backend }) => {
      void backend;
      await open(page, '/', '[data-testid="pending"]');
      await expect(page.locator(ASIDE)).toHaveCount(0);
      const col = page.locator(COL);
      expect(await css(col, 'border-left-width')).toBe('0px');
      expect(await css(col, 'border-right-width')).toBe('0px');
      expect(Math.round((await box(col)).width)).toBe(390);
      expect(Math.round((await box(page.locator(HEAD))).height)).toBe(53);
      await noPageOverflow(page);
      await page.getByRole('button', { name: '메뉴', exact: true }).click();
      const side = page.locator(ASIDE);
      await expect(side).toBeVisible();
      await expect(side).toHaveAttribute('data-collapsed', 'false');
      await expect(side.locator(ACCOUNT)).toContainText('관리자');
      const [s, a] = [await box(side), await box(side.locator(ACCOUNT))];
      expect(s.y + s.height - (a.y + a.height)).toBeLessThanOrEqual(16);
      await side.locator(ACCOUNT).click();
      await expect(page.locator(MENU)).toBeVisible();
      await still(page);
      const m = await box(page.locator(MENU));
      expect(m.y + m.height).toBeLessThanOrEqual(a.y + 1);
      expect(m.x + m.width).toBeLessThanOrEqual(390);
      await page.keyboard.press('Escape');
      await page.keyboard.press('Escape');
      await expect(page.locator(ASIDE)).toHaveCount(0);
      await noPageOverflow(page);
    });
  });
});

test.describe('제목 줄', () => {
  test('본문 단 맨 위 · 높이 53 · 반투명(바탕 85%) + 뒤 흐림 12 · 아래 1px 선 · 제목 21/700 · 상태 묶음 오른쪽 끝(실시간 · 종 · 해/달 · ? · 라이선스)', async ({ page, backend }) => {
    void backend;
    await open(page, '/', '[data-testid="pending"]');
    const head = page.locator(HEAD);
    const col = page.locator(COL);
    await expect(col.locator(HEAD)).toHaveCount(1);
    const [h, c] = [await box(head), await box(col)];
    expect(Math.round(h.height)).toBe(53);
    expect(Math.round(h.y)).toBe(0);
    expect(Math.round(h.x)).toBe(Math.round(c.x) + 1); // 본문 단 세로선 안쪽
    expect(Math.round(h.x + h.width)).toBe(Math.round(c.x + c.width) - 1);
    expect(await css(head, 'position')).toBe('sticky');
    expect(await css(head, 'backdrop-filter')).toBe('blur(12px)');
    expect(await css(head, 'border-bottom-width')).toBe('1px');
    const bg = parseColor(await css(head, 'background-color'));
    expect(bg[3]).toBeCloseTo(0.85, 2);
    expect(near(bg.slice(0, 3), hexRgb(await tokenOf(page, '--bg')))).toBe(true);
    const title = page.getByTestId('page-title');
    expect(await title.evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight])).toEqual(['21px', '700']);
    // 상태 묶음: 순서 = 실시간 연결 · 종 · 해/달 · 사용 안내 · 라이선스, 묶음 오른쪽 끝 = 제목 줄 안쪽 오른쪽 끝
    const st = head.locator('[data-part="title-status"]');
    const parts = ['[role="status"]', '[data-part="bell"]', '[data-part="theme-toggle"]', 'button[aria-label="사용 안내 (?)"]', '[data-part="license-chip"]'];
    const xs: number[] = [];
    for (const p of parts) xs.push((await box(st.locator(p))).x);
    expect([...xs].sort((a, b) => a - b)).toEqual(xs);
    const sb = await box(st);
    const padR = parseFloat(await css(head, 'padding-right'));
    expect(Math.abs(sb.x + sb.width - (h.x + h.width - padR))).toBeLessThanOrEqual(1);
    await expect(st).toContainText('실시간 연결됨');
    // 작게: 아이콘 단추는 머리 줄보다 한참 낮다
    for (const p of ['[data-part="bell"]', '[data-part="theme-toggle"]']) expect((await box(st.locator(p))).height).toBeLessThanOrEqual(36);
    // 하위 화면 제목 앞 「정책 ›」 그대로
    await open(page, '/policies/blocklist', '[data-testid="blocklist"]');
    await expect(head.locator('[data-part="title-parent"]')).toHaveText('정책');
    await expect(title).toHaveText('차단 목록');
  });

  test('본문 채움 칸을 스크롤해도 제목 줄은 제자리 · 문서 · main 스크롤 0', async ({ page, backend }) => {
    const base = backend.cases.find((c) => c.state === 'open')!;
    for (let i = 0; i < 30; i++) backend.cases.push({ ...base, id: `case-9${String(i).padStart(3, '0')}`, openedAt: new Date(Date.now() - i * 60000).toISOString() });
    await open(page, '/', '[data-testid="pending"]');
    const head = page.locator(HEAD);
    const before = await box(head);
    const fill = page.getByTestId('pending').locator('[data-fill]').first();
    expect(await fill.evaluate((e) => e.scrollHeight > e.clientHeight)).toBe(true);
    await fill.evaluate((e) => (e.scrollTop = e.scrollHeight));
    await fill.hover();
    await page.mouse.wheel(0, 400);
    expect(await fill.evaluate((e) => e.scrollTop)).toBeGreaterThan(0);
    expect(await box(head)).toEqual(before);
    await noPageOverflow(page);
  });

  test('어두운 화면: 제목 줄 바탕 = 어두운 바탕 85%', async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ colorScheme: 'dark' });
    await open(page, '/', '[data-testid="pending"]');
    const bg = parseColor(await css(page.locator(HEAD), 'background-color'));
    expect(bg[3]).toBeCloseTo(0.85, 2);
    expect(near(bg.slice(0, 3), hexRgb(await tokenOf(page, '--bg')))).toBe(true);
  });
});

test.describe('본문 단', () => {
  test('1440: 사이드바 바로 옆 · 좌우 1px 세로선 · 본문 폭은 옛 배치 그대로(1200)', async ({ page, backend }) => {
    void backend;
    await open(page, '/', '[data-testid="pending"]');
    const col = page.locator(COL);
    const s = await box(page.locator(ASIDE));
    expect(await css(col, 'border-left-width')).toBe('1px');
    expect(await css(col, 'border-right-width')).toBe('1px');
    expect(parseColor(await css(col, 'border-left-color'))[3]).toBe(1);
    // 세로선은 사이드바 끝 · 화면 끝과 1px 겹치고, main 은 사이드바 바로 옆부터 화면 오른쪽 끝까지(표 칸이 줄지 않음)
    const m = await box(page.locator('main'));
    expect(Math.round(m.x)).toBe(Math.round(s.x + s.width));
    expect(Math.round(m.x + m.width)).toBe(1440);
    expect(Math.round(m.width)).toBe(1200);
  });

  test.describe('1920', () => {
    test.use({ viewport: { width: 1920, height: 1080 } });
    test('넓은 화면: 본문 단 = --content-max · 사이드바와 함께 가운데 · 토스트는 사이드바 바로 옆', async ({ page, backend }) => {
      await open(page, '/events', '[data-testid="events"]');
      const max = parseFloat(await tokenOf(page, '--content-max'));
      const [s, c] = [await box(page.locator(ASIDE)), await box(page.locator(COL))];
      expect(Math.round(c.width)).toBe(max);
      expect(Math.round(c.x)).toBe(Math.round(s.x + s.width) - 1); // 왼쪽 세로선 = 사이드바 끝 1px
      expect(Math.abs(s.x - (1920 - (c.x + c.width)))).toBeLessThanOrEqual(2);
      expect(s.x).toBeGreaterThan(0);
      await noPageOverflow(page);
      backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
      const t = page.locator('[data-toast="kill:api-gw"]');
      const r = await box(t);
      expect(r.x).toBeGreaterThanOrEqual(s.x + s.width);
      expect(r.x).toBeLessThan(s.x + s.width + 40);
    });
  });
});

test.describe('넘침 0 · KPI · 「—」', () => {
  for (const [w, hh] of [
    [1440, 900],
    [1280, 720],
    [390, 844],
  ] as const) {
    test.describe(`${w}×${hh}`, () => {
      test.use({ viewport: { width: w, height: hh } });
      for (const theme of ['light', 'dark'] as const)
        test(`${theme} 대시보드 · 정책 · 감사 로그 · 연동 넘침 0 · 제목 줄 안 잘림 · 셸 「—」 없음`, async ({ page, backend }) => {
          void backend;
          await scansApi(page);
          await page.emulateMedia({ colorScheme: theme });
          for (const [name, url, ready] of SCREENS) {
            await open(page, url, ready);
            await page.waitForTimeout(200);
            await noPageOverflow(page);
            expect(await page.locator(HEAD).evaluate((e) => e.scrollWidth - e.clientWidth), `${name} 제목 줄`).toBe(0);
            expect(await shellDashes(page), name).toEqual([]);
            if (name === 'dashboard' && w === 1280) {
              // 대시보드 KPI 잘림 0: 카드 안 넘침 없음 · 숫자가 카드 안 · 화면 안
              const bad = await page.evaluate(() =>
                Array.from(document.querySelectorAll('[data-part="dashboard"] [data-kpi]')).flatMap((k) => {
                  const e = k as HTMLElement;
                  const r = e.getBoundingClientRect();
                  const v = e.querySelector('[data-value]')?.getBoundingClientRect();
                  const out: string[] = [];
                  if (e.scrollHeight > e.clientHeight + 1 || e.scrollWidth > e.clientWidth + 1) out.push(`${e.dataset.kpi} 넘침`);
                  if (v && (v.bottom > r.bottom + 0.5 || v.right > r.right + 0.5)) out.push(`${e.dataset.kpi} 숫자 잘림`);
                  if (r.bottom > innerHeight || r.right > innerWidth) out.push(`${e.dataset.kpi} 화면 밖`);
                  return out;
                }),
              );
              expect(bad).toEqual([]);
              expect(await page.locator('[data-part="dashboard"] [data-kpi]').count()).toBeGreaterThanOrEqual(4);
            }
          }
        });
    });
  }
});

// 전후 사진 — X2_PHASE=before 는 기준 커밋, after 는 이 변경. 1440 밝은 · 어두운 · 390 밝은 + 390 서랍
test.describe('화면 사진', () => {
  test('1440 밝은 · 어두운', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    for (const theme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: theme });
      for (const [name, url, ready] of SCREENS) {
        await open(page, url, ready);
        await page.waitForTimeout(300);
        await still(page);
        await page.screenshot({ path: `${DIR}/${name}-1440-${theme}.png` });
      }
    }
  });
  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390 밝은 · 서랍', async ({ page, backend }) => {
      void backend;
      await scansApi(page);
      for (const [name, url, ready] of SCREENS) {
        await open(page, url, ready);
        await page.waitForTimeout(300);
        await still(page);
        await page.screenshot({ path: `${DIR}/${name}-390-light.png` });
      }
      await page.getByRole('button', { name: '메뉴', exact: true }).click();
      await expect(page.locator(ASIDE)).toBeVisible();
      await still(page);
      await page.screenshot({ path: `${DIR}/drawer-390-light.png` });
    });
  });
});
