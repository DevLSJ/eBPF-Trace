import type { Page } from '@playwright/test';
import type { Scan } from '../src/lib/types';
import { SHOTS, expect, test } from './fixtures';

// 11/05 슬라이드 패널(목업 mock/tests/sheet-1105.cjs 와 같은 결정 — 사용자 결정 4건 모두 추천안)
//   ① 폭 화면별: 공급망 검사 · 설치 검사 = 본문 70%(최대 1080), 이벤트 · 감사 로그 · 토폴로지 = 720
//   ② 표 옆 칸이 아니라 본문(main) 위에 겹쳐 오른쪽에서 · 뒤 어둡게(누르면 닫힘) · Esc · ✕ · 「n / m ‹ ›」 · ↑↓
//   ③ 공통 시트 4화면 + 토폴로지 노드 상세(오른쪽 칸에는 공격 체인만)
//   ④ 주제별 블록(소제목 15px 굵게 · 구분선) · 「이름 | 값」 2열(8.5rem) · 본문 14px
const box = (page: Page, sel: string) =>
  page.locator(sel).first().evaluate((e) => {
    const r = e.getBoundingClientRect();
    return { x: r.x, y: r.y, w: r.width, right: r.right };
  });
const near = (a: number, b: number, d = 2) => Math.abs(a - b) <= d;
const S = (k: string) => `.sg-sheet-layer [data-sheet="${k}"]`;
// mock-backend 에는 /api/scans 가 없다 — scans.spec 과 같은 모양으로 두 건만 가로챈다
const now = new Date().toISOString();
const scan = (id: string, label: string): Scan => ({
  id,
  target: { kind: 'repo', name: 'requests', url: `https://${label}`, label },
  status: 'done', startedAt: now, finishedAt: now, verdict: 'clean', risk: { score: 0, label: 'no_risks_detected' },
  engines: [{ name: 'GuardDog', version: '3.2.0' }, { name: 'OSV-Scanner', version: '2.7.0' }],
  findings: [], vulns: [], packages: [{ manager: 'pip', name: 'urllib3', version: '2.2.1', ecosystem: 'PyPI', source: 'requirements.txt', direct: true, vulns: 0 }], files: {},
  caseId: null, threats: 0, capabilities: 0, vulnCount: 0, vulnMax: null,
});
async function scansApi(page: Page) {
  const scans = [scan('scan-0002', 'github.com/psf/requests@v2.31.0'), scan('scan-0001', 'github.com/psf/requests')];
  await page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (path === '/scans') return json(scans);
    const s = scans.find((x) => path === `/scans/${x.id}`);
    return s ? json(s) : json({ error: '검사 없음' }, 404);
  });
}
const settle = (page: Page) => page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));

test.describe('상세 패널 — 본문 위에 오른쪽에서(11/05)', () => {
  test('① 공급망 검사: main 위에 겹치고 표 폭은 그대로 · 패널 = 본문 70% · 미끄러져 들어옴 · 뒤 어둡게 · role=dialog', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 1440, height: 900 });
    await scansApi(page);
    await page.goto('/scans');
    const table = page.locator('table[data-table="scans"]');
    await expect(table.locator('tbody tr').first()).toBeVisible();
    const before = await box(page, 'table[data-table="scans"]');
    await table.locator('tbody tr[data-scan="scan-0002"]').click();
    const sheet = page.locator(S('scan'));
    await expect(sheet).toBeVisible();
    expect(await sheet.evaluate((e) => getComputedStyle(e).animationName)).toBe('sg-slide-in');
    await settle(page);
    const main = await box(page, 'main');
    const layer = await box(page, '.sg-sheet-layer');
    const s = await box(page, S('scan'));
    const after = await box(page, 'table[data-table="scans"]');
    expect(near(after.w, before.w), `표 폭 ${before.w} → ${after.w}`).toBe(true);
    expect(near(layer.x, main.x) && near(layer.right, main.right) && near(layer.y, main.y), `층 ${JSON.stringify(layer)} main ${JSON.stringify(main)}`).toBe(true);
    expect(near(s.right, main.right) && near(s.w, Math.min(1080, main.w * 0.7)), `패널 폭 ${s.w} (본문 ${main.w})`).toBe(true);
    expect(await page.locator('.sg-sheet-layer').evaluate((e) => getComputedStyle(e).backgroundColor)).toMatch(/rgba\(15, 23, 42, 0\.2\d*\)/);
    await expect(sheet).toHaveAttribute('role', 'dialog');
    await page.screenshot({ path: `${SHOTS}/1105-scan-sheet.png` });
  });

  test('② 내용: 소제목 15px 굵게 · 블록 구분선 · 2열 8.5rem · 본문 14px · 제목 16px', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0012');
    const sheet = page.locator(S('install'));
    await expect(sheet.locator('.sg-sheet-h3').first()).toBeVisible();
    const st = await sheet.evaluate((e) => {
      const cs = (x: Element) => getComputedStyle(x);
      const h3 = e.querySelector('.sg-sheet-h3')!, dl = e.querySelector('.sg-sheet-section dl')!, body = e.querySelector('.sg-sheet-body')!, h2 = e.querySelector('h2')!;
      const secs = [...e.querySelectorAll('.sg-sheet-section')];
      return { h3: [cs(h3).fontSize, cs(h3).fontWeight], dl: cs(dl).gridTemplateColumns, body: cs(body).fontSize, h2: cs(h2).fontSize, borders: secs.slice(1).map((x) => cs(x).borderTopWidth), n: secs.length };
    });
    expect(st.h3[0]).toBe('15px');
    expect(Number(st.h3[1])).toBeGreaterThanOrEqual(600);
    expect(st.dl).toMatch(/^136px /);
    expect([st.body, st.h2]).toEqual(['14px', '16px']);
    expect(st.n).toBeGreaterThanOrEqual(3);
    expect(st.borders.every((b) => b === '1px')).toBe(true);
  });

  test('③ 이전/다음: 「1 / n」 · ‹ 비활성 · › · ↓ 는 다음 행(?id) · 애니메이션 되풀이 없음 · ↑ 는 앞으로', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?status=all');
    const rows = page.locator('table tbody tr[data-install]');
    await expect(rows.first()).toBeVisible();
    const ids = await rows.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.install!));
    expect(ids.length).toBeGreaterThanOrEqual(3);
    await rows.first().click();
    const sheet = page.locator(S('install'));
    await expect(sheet.locator('[data-part="sheet-pos"]')).toHaveText(`1 / ${ids.length}`);
    await expect(sheet.locator('[data-action="sheet-prev"]')).toBeDisabled();
    await settle(page);
    await sheet.locator('[data-action="sheet-next"]').click();
    await expect(page).toHaveURL(new RegExp(`id=${ids[1]}`));
    expect(await sheet.evaluate((e) => e.getAnimations().filter((a) => a.playState === 'running').length), '다음으로 넘길 때 다시 미끄러진다').toBe(0);
    await page.keyboard.press('ArrowDown');
    await expect(page).toHaveURL(new RegExp(`id=${ids[2]}`));
    await expect(sheet.locator('[data-part="sheet-pos"]')).toHaveText(`3 / ${ids.length}`);
    await page.keyboard.press('ArrowUp');
    await expect(page).toHaveURL(new RegExp(`id=${ids[1]}`));
  });

  test('④ 닫기: Esc · 어두운 곳 · ✕ — 미끄러져 나가고 ?id 비움 · 패널 안 클릭은 그대로 · 열린 동안 뒤 표는 가려진다', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/installs?status=all');
    const row = page.locator('table tbody tr[data-install]').first();
    await expect(row).toBeVisible();
    for (const how of ['inside', 'esc', 'scrim', 'x'] as const) {
      await row.click();
      const layer = page.locator('.sg-sheet-layer[data-layer="install"]');
      await expect(layer).toBeVisible();
      await settle(page);
      if (how === 'inside') {
        await page.locator(`${S('install')} .sg-sheet-body`).click({ position: { x: 20, y: 10 } });
        await expect(layer).toBeVisible();
        const covered = await row.evaluate((r) => {
          const b = r.getBoundingClientRect();
          return document.elementFromPoint(b.x + 20, b.y + b.height / 2)?.classList.contains('sg-sheet-layer');
        });
        expect(covered, '열린 동안 뒤 표가 눌린다').toBe(true);
        await page.keyboard.press('Escape');
        await expect(layer).toHaveCount(0);
        continue;
      }
      if (how === 'esc') await page.keyboard.press('Escape');
      if (how === 'scrim') await page.mouse.click(400, 500);
      if (how === 'x') await page.locator(`${S('install')} [data-action="sheet-close"]`).click();
      await expect(page.locator('.sg-sheet-layer.closing')).toHaveCount(1);
      await expect(layer).toHaveCount(0);
      expect(new URL(page.url()).searchParams.get('id')).toBeNull();
    }
  });

  test('⑤ 화면별 폭(1440): 설치 검사 840 · 이벤트 · 감사 로그 720 — 오른쪽 끝 · 위치 표시', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 1440, height: 900 });
    for (const [path, kind, click, w] of [
      ['/installs?status=all', 'install', 'table tbody tr[data-install]', 840],
      ['/events', 'event', 'li[data-key]', 720],
      ['/audit', 'audit', 'table tbody tr[data-audit]', 720],
    ] as const) {
      await page.goto(path);
      await page.locator(click).first().click();
      await expect(page.locator(S(kind))).toBeVisible();
      await settle(page);
      const b = await box(page, S(kind));
      expect(near(b.w, w) && near(b.right, 1440), `${kind} 폭 ${b.w} 오른쪽 ${b.right}`).toBe(true);
      await expect(page.locator(`${S(kind)} [data-part="sheet-pos"]`)).toHaveText(/^1 \/ \d+$/);
    }
  });

  test('⑥ 토폴로지: 고른 노드 · 판정은 패널(720) 안, 오른쪽 칸은 공격 체인만 · Esc 로 닫으면 ?node 비움', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/topology?node=c%3Apkg-reqeusts');
    const sheet = page.locator(S('topo'));
    await expect(sheet.getByTestId('node-detail')).toContainText('pkg-reqeusts');
    await expect(sheet.getByTestId('topology-decision')).toBeVisible();
    await settle(page);
    const b = await box(page, S('topo'));
    expect(near(b.w, 720)).toBe(true);
    await expect(page.locator('aside:not([data-sheet])').getByTestId('node-detail')).toHaveCount(0);
    await expect(page.getByTestId('chains')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(sheet).toHaveCount(0);
    expect(new URL(page.url()).searchParams.get('node')).toBeNull();
  });

  test('⑦ 768 미만(390): 전체 화면 · 가로 넘침 0 · 다크: 뒤가 더 진함', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/installs?id=ins-0012');
    await expect(page.locator(S('install'))).toBeVisible();
    await settle(page);
    const b = await box(page, S('install'));
    expect(near(b.x, 0) && near(b.w, 390) && near(b.y, 0), JSON.stringify(b)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.evaluate(() => localStorage.removeItem('supplyguard.theme'));
    await page.goto('/audit');
    await page.locator('table tbody tr[data-audit]').first().click();
    await expect(page.locator(S('audit'))).toBeVisible();
    await settle(page);
    expect(await page.locator('.sg-sheet-layer').evaluate((e) => getComputedStyle(e).backgroundColor)).toMatch(/rgba\(0, 0, 0, 0\.4\d*\)/);
  });
  test('⑧ 맨 위부터 닫기: 도우미 · 알림이 열려 있으면 Esc 는 그것만 닫고, 다음 Esc 에 패널 · 토스트는 패널 위', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0012');
    const layer = page.locator('.sg-sheet-layer[data-layer="install"]');
    await expect(layer).toBeVisible();
    await settle(page);
    await page.getByRole('button', { name: /^도우미 열기/ }).click();
    const asst = page.locator('[data-part="assistant"]');
    await expect(asst).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(asst).toBeHidden();
    await expect(layer, '도우미와 패널이 함께 닫힘').toBeVisible();
    await page.keyboard.press('Escape');
    await expect(layer).toHaveCount(0);
    // 토스트(z-50)는 패널 층(z-40) 위 — 패널을 연 채 토스트 자리의 맨 위 요소가 토스트 칸
    await page.goto('/installs?id=ins-0012');
    await expect(layer).toBeVisible();
    const z = await page.evaluate(() => {
      const host = document.querySelector('.sg-sheet-host')!;
      const toasts = [...document.querySelectorAll('[class*="fixed"][class*="bottom-5"]')][0];
      return [Number(getComputedStyle(host).zIndex), toasts ? Number(getComputedStyle(toasts).zIndex) : NaN];
    });
    expect(z[1], `토스트 z ${z[1]} · 패널 층 z ${z[0]}`).toBeGreaterThan(z[0]);
  });
});
