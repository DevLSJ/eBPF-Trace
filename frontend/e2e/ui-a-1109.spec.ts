import type { Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';
import { ADMIN_PW } from './mock-auth';

// 11/09 저녁 묶음 A(셸 · 상단) — 참고 제품 UI 문서와 대조해 빠진 항목을 채운다(번호는 메인 항목 표).
// G43 화면 제목 21/700 · G01 테마 = 상단 해/달 단추 하나(처음은 PC 설정 · 누르면 기억 · 전환 450ms · 동작 줄이기면 즉시)
// G09 알림 팝오버 문구 · 모두 읽음 꺼짐 사유 · G10 도움말 「~합니다」체 · G24 아이콘 단추 title = aria-label · G20 비밀번호 알림 마침표
// G07 통합 검색에 화면 이름 · G11 로그아웃 위험 글자색 · G17 하위 화면 「정책 ›」 · G38 내부 이름 → 쉬운 말(설정 이름은 보조 글 · 툴팁만)

const SHOT = process.env.UI_A_SHOTS ?? `${SHOTS}/ui-a-1109`;

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
    // 누름과 측정을 한 작업 안에서(부하로 측정이 450ms 뒤로 밀리지 않게)
    const during = await page.evaluate((sel) => {
      (document.querySelector(sel) as HTMLElement).click();
      return {
        anim: document.documentElement.classList.contains('sg-theme-anim'),
        dur: getComputedStyle(document.body).transitionDuration,
        prop: getComputedStyle(document.body).transitionProperty,
      };
    }, TOGGLE);
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

// ── 2차: 알림 · 도움말 · 아이콘 단추 · 토스트 · 검색 · 계정 메뉴 · 하위 화면 · 내부 이름 ──

test.describe('G09 알림 팝오버', () => {
  test('알림 0개 = 「새 알림이 없습니다.」 · 「모두 읽음」 꺼짐 + 사유 / 안 읽은 알림이 있으면 켜짐 → 누르면 다시 꺼짐', async ({ page, backend }) => {
    backend.empty();
    await ready(page);
    await page.locator('[data-part="bell"]').click();
    const box = page.locator('[data-part="notices"]');
    await expect(box).toBeVisible();
    await expect(box.locator('[data-notice]')).toHaveCount(0);
    await expect(box).toContainText('새 알림이 없습니다.');
    const all = box.getByRole('button', { name: '모두 읽음' });
    await expect(all).toHaveAttribute('aria-disabled', 'true');
    await expect(all).toHaveAttribute('title', '안 읽은 알림이 없습니다');
    backend.info.dnsResolve = 'off';
    await ready(page);
    await page.locator('[data-part="bell"]').click();
    await expect(box.locator('[data-notice="dns"]')).toHaveAttribute('data-unread', 'true');
    await expect(all).not.toHaveAttribute('aria-disabled', 'true');
    expect(await all.getAttribute('title')).toBeNull();
    await all.click();
    await expect(box.locator('[data-notice="dns"]')).toHaveAttribute('data-unread', 'false');
    await expect(all).toHaveAttribute('aria-disabled', 'true');
  });
});

test('G10 도움말: 설명은 「~합니다」체 — 「~다.」로 끝나는 문장 없음', async ({ page, backend }) => {
  void backend;
  await ready(page);
  await page.keyboard.press('?');
  const help = page.locator('dialog[data-part="help"]');
  await expect(help).toBeVisible();
  const flow = await help.locator('[data-part="flow"] p').allTextContents();
  expect(flow).toHaveLength(6);
  for (const l of flow) expect(l).toMatch(/니다\.$/);
  const sentences = (await help.locator('p, dd').allTextContents()).flatMap((t) => t.split(/(?<=\.)\s+/)).map((x) => x.trim()).filter(Boolean);
  expect(sentences.filter((x) => /다\.?$/.test(x) && !/니다\.?$/.test(x))).toEqual([]);
});

// 아이콘 단추: title 과 aria-label 이 같은 이름(꺼진 단추는 사유가 title — 셸에는 없음)
async function iconButtonGaps(page: Page, roots: string[]) {
  return page.evaluate((sels) => {
    const seen: string[] = [];
    const bad: string[] = [];
    for (const sel of sels)
      for (const root of Array.from(document.querySelectorAll(sel))) {
        const btns = [...(root.matches('button[aria-label]') ? [root] : []), ...Array.from(root.querySelectorAll('button[aria-label]'))];
        for (const b of btns) {
          const name = b.getAttribute('aria-label') ?? '';
          seen.push(name);
          if (b.getAttribute('title') !== name) bad.push(`${name} ≠ ${b.getAttribute('title')}`);
        }
      }
    return { seen, bad };
  }, roots);
}

test.describe('G24 아이콘 단추 title', () => {
  test('머리 · 사이드바 · 도메인 배너 · 도우미: title = aria-label', async ({ page, backend }) => {
    backend.info.dnsResolve = 'off';
    await ready(page);
    await page.locator('[data-part="assistant-fab"]').click();
    await expect(page.locator('[data-part="assistant"]')).toBeVisible();
    const { seen, bad } = await iconButtonGaps(page, ['header[data-part="header"]', 'aside[data-part="sidebar"]', '[data-banner="dns"]', '[data-part="assistant"] > header', '[data-part="assistant-fab"]']);
    expect(bad).toEqual([]);
    for (const n of [/^알림 \d+건 안 읽음$/, /^사용 안내/, /화면으로$/, /^사이드바 접기/, /^닫기$/, /^도우미 열기/]) expect(seen.some((x) => n.test(x)), String(n)).toBe(true);
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390: 메뉴 · 메뉴 닫기도 title = aria-label', async ({ page, backend }) => {
      void backend;
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      await page.getByRole('button', { name: '메뉴', exact: true }).click();
      await expect(page.locator('aside[data-part="sidebar"]')).toBeVisible();
      const { seen, bad } = await iconButtonGaps(page, ['header[data-part="header"]', 'aside[data-part="sidebar"]']);
      expect(bad).toEqual([]);
      expect(seen).toEqual(expect.arrayContaining(['메뉴', '메뉴 닫기']));
    });
  });
});

test('G20 비밀번호를 바꾸면 알림 문장이 마침표로 끝난다', async ({ page, backend }) => {
  await ready(page);
  await page.locator('[data-part="account"]').click();
  await page.getByRole('menuitem', { name: '비밀번호 변경' }).click();
  const pw = page.locator('[data-part="password"]');
  await pw.getByLabel('지금 비밀번호').fill(ADMIN_PW);
  await pw.getByLabel(/^새 비밀번호 \(/).fill('changed-pass-2026');
  await pw.getByLabel('새 비밀번호 확인').fill('changed-pass-2026');
  await pw.getByRole('button', { name: '바꾸기' }).click();
  await expect(pw).toHaveCount(0);
  expect(backend.auth.user('admin').pw).toBe('changed-pass-2026');
  await expect(page.locator('[data-toast="password"]')).toContainText('비밀번호를 바꿨습니다.');
});

test.describe('G07 통합 검색에 화면 이름', () => {
  test('화면 이름이 결과 맨 앞(「화면」 묶음) · 누르거나 Enter 면 그 화면 · 시연은 켜졌을 때만 · 건 보고서는 없음', async ({ page, backend }) => {
    await page.route(/\/api\/scans(\/|$|\?)/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
    await ready(page);
    const box = page.getByRole('combobox', { name: /통합 검색/ });
    const results = page.locator('[data-part="search-results"]');
    await box.fill('정책');
    await expect(results.locator('[data-result]').first()).toHaveAttribute('data-type', 'screen');
    await expect(results.locator('[data-part="search-group"]').first()).toHaveText('화면');
    await expect(results.locator('[data-type="screen"]')).toHaveText([/^정책/, /^차단 목록/, /^변경 이력/]);
    await results.locator('[data-type="screen"]').filter({ hasText: '차단 목록' }).click();
    await expect(page).toHaveURL(/\/policies\/blocklist$/);
    await expect(page.getByTestId('page-title')).toHaveText('차단 목록');
    await box.fill('감사');
    await expect(results.locator('[data-result]').first()).toHaveAttribute('data-type', 'screen');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/audit$/);
    await expect(page.getByTestId('page-title')).toHaveText('감사 로그');
    for (const q of ['시연', '보고서']) {
      await box.fill(q);
      await expect(results).toBeVisible();
      await expect(results.locator('[data-type="screen"]'), q).toHaveCount(0);
    }
    backend.enableDemo();
    await ready(page);
    await box.fill('시연');
    await expect(results.locator('[data-type="screen"]')).toHaveText([/^시연/]);
  });
});

test('G11 계정 메뉴 「로그아웃」 = 위험 글자색(--danger-text), 다른 항목은 보통 글자', async ({ page, backend }) => {
  void backend;
  await ready(page);
  await page.locator('[data-part="account"]').click();
  const out = page.getByRole('menuitem', { name: '로그아웃' });
  await expect(out).toBeVisible();
  const [color, token] = await out.evaluate((e) => [getComputedStyle(e).color, getComputedStyle(document.documentElement).getPropertyValue('--danger-text').trim()]);
  expect(color).toBe(rgb(token));
  expect(await page.getByRole('menuitem', { name: '내 정보' }).evaluate((e) => getComputedStyle(e).color)).not.toBe(color);
});

test('G17 하위 화면은 제목 앞에 「정책 ›」 — 누르면 상위 화면 · 상위 · 다른 화면에는 없음', async ({ page, backend }) => {
  void backend;
  const up = page.locator('[data-part="title-parent"]');
  const title = page.getByTestId('page-title');
  for (const [path, name] of [['/policies/blocklist', '차단 목록'], ['/policies/changes', '변경 이력']]) {
    await page.goto(path);
    await expect(title).toHaveText(name);
    await expect(up).toHaveText('정책');
    await expect(page.locator('[data-part="title-sep"]')).toHaveText('›');
    const [a, b] = [(await up.boundingBox())!, (await title.boundingBox())!];
    expect(a.x + a.width).toBeLessThan(b.x);
    expect(Math.abs(a.y + a.height / 2 - (b.y + b.height / 2))).toBeLessThan(3);
    expect(await up.evaluate((e) => getComputedStyle(e).fontSize)).toBe('21px');
  }
  await up.click();
  await expect(page).toHaveURL(/\/policies$/);
  await expect(title).toHaveText('정책');
  await expect(up).toHaveCount(0);
  for (const path of ['/', '/settings', '/audit']) {
    await page.goto(path);
    await expect(title).not.toBeEmpty();
    await expect(up).toHaveCount(0);
  }
});

// 보이는 글자에서 설정 이름(대문자 · 밑줄 4자 이상)을 찾는다 — 보조 글 칸([data-part="setting-name"]) · 툴팁(title 속성)은 제외
async function settingNames(page: Page, roots: string[]) {
  return page.evaluate((sels) => {
    const re = /\b[A-Z][A-Z_]{3,}\b/g;
    const out: string[] = [];
    for (const sel of sels)
      for (const root of Array.from(document.querySelectorAll(sel))) {
        const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        while (w.nextNode()) {
          const n = w.currentNode as Text;
          const el = n.parentElement;
          if (!el || el.closest('[data-part="setting-name"]') || !el.checkVisibility({ checkVisibilityCSS: true })) continue;
          for (const m of n.data.match(re) ?? []) out.push(`${sel}: ${m} ← ${n.data.trim().slice(0, 70)}`);
        }
      }
    return out;
  }, roots);
}

test.describe('G38 내부 이름 → 쉬운 말', () => {
  test('셸(사이드바 · 머리 · 배너 · 알림 · 도우미) · 설정 화면: 보이는 문장에 설정 이름 없음 · 보조 글 · 툴팁에만', async ({ page, backend }) => {
    backend.info.dnsResolve = 'off';
    backend.info.enforceKill = false;
    backend.stats.enforceKill = false;
    await ready(page, '/settings');
    const side = page.locator('aside[data-part="sidebar"]');
    await expect(side).toContainText('모의 재생');
    await expect(side).toContainText('알림만(dry-run)');
    await expect(side).not.toContainText('Mock');
    const banner = page.locator('[data-banner="dns"]');
    await expect(banner).toContainText('도메인 판단 꺼짐');
    await expect(banner).not.toContainText('trace_dns');
    await expect(banner).not.toContainText('kind: dns');
    await expect(banner.locator('[title*="trace_dns"]')).toHaveCount(1);
    const server = page.locator('[data-view="server"]');
    await expect(server.locator('[data-part="dns"]')).toContainText('도메인 조회 감시');
    await expect(server.locator('[data-part="discovery"]')).not.toContainText('mock');
    await expect(server.locator('[data-part="setting-name"]').first()).toHaveText('ENFORCE_KILL');
    expect(await settingNames(page, ['aside[data-part="sidebar"]', 'header[data-part="header"]', '[data-banner]', '[data-view="server"]'])).toEqual([]);
    // 알림 채널이 없을 때의 안내 · AI 도우미 꺼짐 안내
    backend.info.notify = { enabled: false, channels: [], sent: 0, failed: 0, dropped: 0, suppressed: 0 };
    await ready(page, '/settings');
    await expect(server.locator('[data-part="notify"] [data-part="setting-name"]')).toContainText('NOTIFY_WEBHOOK_URL');
    await expect(server.locator('[data-part="ai"] [data-part="setting-name"]')).toContainText('OLLAMA_URL');
    expect(await settingNames(page, ['[data-view="server"]'])).toEqual([]);
    // 알림 팝오버(격리 꺼짐 · 도메인 판단 꺼짐)
    await page.locator('[data-part="bell"]').click();
    await expect(page.locator('[data-notice="dryrun"]')).toContainText('알림만(dry-run)');
    expect(await settingNames(page, ['[data-part="notices"]'])).toEqual([]);
    await page.keyboard.press('Escape');
    // 도우미 「AI 도우미」 탭의 꺼짐 안내
    await page.locator('[data-part="assistant-fab"]').click();
    await page.locator('[data-part="assistant"]').getByRole('tab', { name: 'AI 도우미' }).click();
    const off = page.locator('[data-part="chat-off"]');
    await expect(off).toContainText('AI 도우미가 꺼져 있습니다');
    await expect(off.locator('[data-part="setting-name"]')).toContainText('ANTHROPIC_API_KEY');
    expect(await settingNames(page, ['[data-part="assistant"]'])).toEqual([]);
  });
});

// 화면 사진(1440 밝은 · 어두운, 390) — 하위 화면 제목 · 해/달 단추 · 알림 팝오버 · 계정 메뉴 · 설정.
// 찍기 전에 들어오는 움직임(팝오버 · 서랍 · 화면 전환)이 끝날 때까지(반복 애니메이션은 빼고)
const still = (p: Page) =>
  p.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity));
test.describe('화면 사진', () => {
  test('1440 밝은 · 어두운', async ({ page, backend }) => {
    backend.info.dnsResolve = 'off';
    for (const theme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: theme });
      await ready(page, '/policies/blocklist');
      expect(await themeOf(page)).toBe(theme);
      await still(page);
      await page.screenshot({ path: `${SHOT}/1440-${theme}-blocklist.png` });
      await page.locator('[data-part="bell"]').click();
      await expect(page.locator('[data-part="notices"]')).toBeVisible();
      await still(page);
      await page.screenshot({ path: `${SHOT}/1440-${theme}-notices.png` });
      await page.keyboard.press('Escape');
      await ready(page, '/settings');
      await page.locator('[data-part="account"]').click();
      await expect(page.locator('[data-part="account-menu"]')).toBeVisible();
      await still(page);
      await page.screenshot({ path: `${SHOT}/1440-${theme}-settings-account.png` });
      await noPageOverflow(page);
    }
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390 밝은 · 어두운 · 서랍', async ({ page, backend }) => {
      void backend;
      for (const theme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: theme });
        await page.goto('/policies/blocklist');
        await expect(page.getByTestId('page-title')).toHaveText('차단 목록');
        await still(page);
        await page.screenshot({ path: `${SHOT}/390-${theme}-blocklist.png` });
        await noPageOverflow(page);
      }
      await page.getByRole('button', { name: '메뉴', exact: true }).click();
      await expect(page.locator('aside[data-part="sidebar"]')).toBeVisible();
      await still(page);
      await page.screenshot({ path: `${SHOT}/390-dark-drawer.png` });
    });
  });
});
