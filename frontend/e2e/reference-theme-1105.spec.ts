import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';

// 설치 기록을 늘려 쪽이 여러 개가 되게(r4-tables 와 같은 방식 — 마지막 기록을 복제해 통과로)
function seedInstalls(b: MockBackend, n: number) {
  const last = b.installs[b.installs.length - 1];
  const at = new Date(last.startedAt).getTime();
  for (let i = 1; i <= n; i++)
    b.installs.push({ ...last, id: `ins-2${String(i).padStart(3, '0')}`, packages: [`bulk-${i}`], startedAt: new Date(at - i * 60_000).toISOString(), finishedAt: new Date(at - i * 60_000 + 5_000).toISOString(), status: 'passed', caseId: null, violations: [], isolation: null, scan: undefined, scanId: null });
}

// 11/05 참고 대시보드 스타일 이식 — 글꼴 · 색(라이트/다크) · 버튼 · 표(48px) · 상태 배지(27 · 12.5/750 · 톤 테두리) · 쪽 넘김 · 빈 상태 · 카드/패널.
// 값은 참고 대시보드 소스 그대로(MUI 기본값 포함). 브랜드(제품명 · 로고 · 사이드바 그라데이션)는 옮기지 않는다

const rgb = (hex: string) => {
  const n = parseInt(hex.replace('#', ''), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
};
const css = (page: Page, sel: string, props: string[]) =>
  page.locator(sel).first().evaluate((e, ps) => {
    const cs = getComputedStyle(e);
    return Object.fromEntries(ps.map((p) => [p, cs.getPropertyValue(p)]));
  }, props);
async function pickTheme(page: Page, t: 'light' | 'dark') {
  const btn = page.locator('[data-part="account"]');
  if ((await btn.getAttribute('aria-expanded')) !== 'true') await btn.click();
  await page.locator(`[data-part="account-menu"] [data-theme-pick="${t}"]`).click();
  await page.keyboard.press('Escape');
}
// 버튼 클래스 견본 — 화면마다 있는 버튼 종류가 달라 본문에 견본을 붙여 클래스 값만 본다
async function mountButtons(page: Page) {
  await page.evaluate(() => {
    const box = document.createElement('div');
    box.id = 'btn-probe';
    box.innerHTML = '<button class="sg-btn sg-btn-sm sg-btn-secondary" data-k="sm">확인</button><button class="sg-btn sg-btn-sm sg-btn-outline-danger" data-k="sm-danger">확인</button>' + ['primary', 'secondary', 'danger'].map((k) => `<button class="sg-btn sg-btn-${k}" data-k="${k}">확인</button><button class="sg-btn sg-btn-${k}" data-k="${k}-off" disabled>확인</button>`).join('');
    document.querySelector('main')!.append(box);
  });
}

test.describe('11/05 참고 대시보드 스타일', () => {
  test('글꼴 · 바탕 · 본문 줄 높이 — 웹폰트를 내려받지 않는다', async ({ page, backend }) => {
    void backend;
    const fonts: string[] = [];
    page.on('request', (r) => r.resourceType() === 'font' && fonts.push(r.url()));
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const b = await css(page, 'body', ['font-family', 'background-color', 'color', 'line-height', 'font-size']);
    expect(b['font-family']).toMatch(/^Inter, Pretendard, -apple-system, ("system-ui"|BlinkMacSystemFont), "Segoe UI", sans-serif$/); // Chromium 은 BlinkMacSystemFont 를 system-ui 로 적는다
    expect(b['background-color']).toBe(rgb('#F6F7FB'));
    expect(b.color).toBe(rgb('#202534'));
    expect(b['line-height']).toBe('26.4px'); // 16 × 1.65
    expect(await css(page, '[data-testid="page-title"]', ['font-size', 'font-weight', 'letter-spacing'])).toEqual({ 'font-size': '26.4px', 'font-weight': '700', 'letter-spacing': '-0.528px' });
    expect(fonts).toEqual([]);
  });

  test('버튼: 기본 · 보조(외곽선) · 위험 · 비활성 — 반경 6 · 14.4/700 · 높이 33.6 · 호버 색', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await mountButtons(page);
    const P = ['background-color', 'color', 'border-top-color', 'border-top-width', 'border-radius', 'font-size', 'font-weight', 'box-shadow'];
    const primary = await css(page, '#btn-probe [data-k="primary"]', P);
    expect(primary).toMatchObject({ 'background-color': rgb('#1769E8'), color: rgb('#FFFFFF'), 'border-radius': '6px', 'font-size': '14.4px', 'font-weight': '700', 'box-shadow': 'none' });
    expect((await page.locator('#btn-probe [data-k="primary"]').boundingBox())!.height).toBeCloseTo(33.6, 1);
    expect((await page.locator('#btn-probe [data-k="secondary"]').boundingBox())!.height).toBeCloseTo(33.6, 1);
    expect(await css(page, '#btn-probe [data-k="secondary"]', P)).toMatchObject({ 'background-color': 'rgba(0, 0, 0, 0)', color: rgb('#1769E8'), 'border-top-color': 'rgba(23, 105, 232, 0.5)', 'border-top-width': '1px' });
    expect(await css(page, '#btn-probe [data-k="danger"]', P)).toMatchObject({ 'background-color': rgb('#E4516F'), color: rgb('#FFFFFF') });
    for (const k of ['primary-off', 'danger-off'])
      expect(await css(page, `#btn-probe [data-k="${k}"]`, P), k).toMatchObject({ 'background-color': 'rgba(0, 0, 0, 0.12)', color: 'rgba(0, 0, 0, 0.26)' });
    expect(await css(page, '#btn-probe [data-k="secondary-off"]', P)).toMatchObject({ 'border-top-color': 'rgba(0, 0, 0, 0.12)', color: 'rgba(0, 0, 0, 0.26)' });
    // 작은 크기(size=small): 외곽선 패딩 3/9 · 높이 29.6, 위험 외곽선
    expect(await css(page, '#btn-probe [data-k="sm"]', ['padding-top', 'padding-left', 'font-size'])).toEqual({ 'padding-top': '3px', 'padding-left': '9px', 'font-size': '14.4px' });
    expect((await page.locator('#btn-probe [data-k="sm"]').boundingBox())!.height).toBeCloseTo(29.6, 1);
    expect(await css(page, '#btn-probe [data-k="sm-danger"]', ['color', 'border-top-color'])).toEqual({ color: rgb('#E4516F'), 'border-top-color': 'rgba(228, 81, 111, 0.5)' });
    // 호버(전환 250ms 를 기다린다)
    await page.locator('#btn-probe [data-k="primary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="primary"]', ['background-color']).then((v) => v['background-color'])).toBe(rgb('#0D47B8'));
    await page.locator('#btn-probe [data-k="secondary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="secondary"]', ['border-top-color']).then((v) => v['border-top-color'])).toBe(rgb('#1769E8'));
    await page.locator('#btn-probe [data-k="danger"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="danger"]', ['background-color']).then((v) => v['background-color'])).toBe(rgb('#A0394E'));
  });

  test('표 · 배지 · 쪽 넘김 · 패널: 머리 42 회색 12/600 · 행 48 · 배지 27 12.5/750 톤 테두리 · 「총 N건 · p/P 페이지」 · 「N개씩」 · 원형 쪽 칸', async ({ page, backend }) => {
    seedInstalls(backend, 37); // 8 + 37 = 45 → 3쪽
    await page.goto('/installs?status=all');
    const T = 'table[data-table="installs"]';
    await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
    expect(await css(page, `${T} thead th`, ['height', 'background-color', 'font-size', 'font-weight', 'color', 'padding-left'])).toEqual({
      height: '42px', 'background-color': rgb('#EEF0F4'), 'font-size': '12px', 'font-weight': '600', color: rgb('#7A8090'), 'padding-left': '16px',
    });
    const td = await css(page, `${T} tbody td`, ['font-size', 'padding-left', 'padding-top', 'border-bottom-color']);
    expect(td).toEqual({ 'font-size': '12.5px', 'padding-left': '16px', 'padding-top': '8px', 'border-bottom-color': rgb('#ECEEF4') });
    expect(Math.round((await page.locator(`${T} tbody tr`).first().boundingBox())!.height)).toBe(48);
    // 줄무늬 없음 — 홀짝 행 바탕이 같다
    const zebra = await page.locator(`${T} tbody tr`).evaluateAll((rows) => rows.slice(0, 2).map((r) => getComputedStyle(r).backgroundColor));
    expect(zebra[0]).toBe(zebra[1]);
    // 상태 배지
    const pill = page.locator(`${T} tbody .sg-pill-ok`).first();
    await expect(pill).toBeVisible();
    expect(await pill.evaluate((e) => { const c = getComputedStyle(e); return [c.height, c.fontSize, c.fontWeight, c.borderTopWidth, c.borderTopColor, c.backgroundColor, c.color, c.minWidth]; })).toEqual([
      '27px', '12.5px', '750', '1px', rgb('#BDE7D6'), rgb('#EAF7F1'), rgb('#137653'), '62px',
    ]);
    // 격리 배지 = 위험 톤(11/05 결정)
    const iso = page.locator(`${T} tbody [data-status="isolated"]`).first();
    await expect(iso).toBeVisible();
    expect(await iso.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color, getComputedStyle(e).borderTopColor])).toEqual([rgb('#FDECEF'), rgb('#B52D49'), rgb('#F4C4CE')]);
    // 쪽 넘김
    const foot = page.locator('[data-table-foot="installs"]');
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 1/3 페이지');
    expect(await foot.locator('[data-part="page-size"] option').allTextContents()).toEqual(['20개씩', '50개씩', '100개씩']);
    expect(await css(page, '[data-table-foot="installs"] [data-part="range"]', ['font-size', 'color'])).toEqual({ 'font-size': '14px', color: rgb('#7A8090') });
    expect(await css(page, '[data-table-foot="installs"] [data-part="page-size"]', ['height', 'border-radius', 'font-size'])).toEqual({ height: '40px', 'border-radius': '8px', 'font-size': '14px' });
    for (const k of ['first', 'prev', 'next', 'last']) await expect(foot.locator(`[data-page="${k}"]`)).toBeVisible();
    await expect(foot.locator('[data-page="first"]')).toBeDisabled();
    const cur = await css(page, '[data-table-foot="installs"] .tk-page.on', ['width', 'height', 'border-radius', 'background-color', 'color']);
    expect(cur).toEqual({ width: '26px', height: '26px', 'border-radius': '13px', 'background-color': rgb('#1769E8'), color: rgb('#FFFFFF') });
    expect(await css(page, '[data-table-foot="installs"]', ['padding-top', 'padding-left'])).toEqual({ 'padding-top': '16px', 'padding-left': '16px' });
    await foot.locator('[data-page="last"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 3/3 페이지');
    await expect(foot.locator('[data-page="last"]')).toBeDisabled();
    // 패널(표를 감싼 카드): 반경 8 · 그림자 없음 · 머리 56 · 좌우 20 · 제목 17.92/700
    const panel = page.locator('.sg-panel').filter({ has: page.locator(T) }).first();
    await page.mouse.move(0, 0);
    await expect.poll(() => panel.evaluate((e) => [getComputedStyle(e).borderRadius, getComputedStyle(e).boxShadow])).toEqual(['8px', 'none']);
    const head = panel.locator('.sg-panel-head');
    expect(await head.evaluate((e) => [getComputedStyle(e).minHeight, getComputedStyle(e).paddingLeft])).toEqual(['56px', '20px']);
    expect(await panel.locator('.sg-panel-title').evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight])).toEqual(['17.92px', '700']);
    await panel.hover();
    await expect.poll(() => panel.evaluate((e) => getComputedStyle(e).borderTopColor)).toBe('rgba(23, 105, 232, 0.24)');
    await page.screenshot({ path: `${SHOTS}/1105-reference-installs.png` });
  });

  test('빈 상태: 가운데 · 보조색 14px · 높이 180 이상', async ({ page, backend }) => {
    void backend;
    await page.route(/\/api\/installs(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));
    await page.goto('/installs');
    const empty = page.locator('.sg-empty').first();
    await expect(empty).toBeVisible();
    const e = await empty.evaluate((el) => { const c = getComputedStyle(el); return [c.textAlign, c.fontSize, c.color, el.getBoundingClientRect().height >= 180]; });
    expect(e).toEqual(['center', '14px', rgb('#7A8090'), true]);
  });

  test('카드: 반경 8 · 1px 선 · 그림자 0 10px 32px rgba(39,76,142,.07)', async ({ page, backend }) => {
    void backend;
    await page.goto('/settings');
    await expect(page.locator('[data-part="settings-tabs"]')).toBeVisible();
    const card = await css(page, '.sg-card:not(.sg-panel)', ['border-radius', 'border-top-width', 'border-top-color', 'box-shadow']);
    expect(card).toEqual({ 'border-radius': '8px', 'border-top-width': '1px', 'border-top-color': rgb('#ECEEF4'), 'box-shadow': 'rgba(39, 76, 142, 0.07) 0px 10px 32px 0px' });
  });

  test('다크: 바탕 · 면 · 표 머리 · 행 호버 · 비활성 버튼 · 배지는 라이트와 같은 톤 값', async ({ page, backend }) => {
    seedInstalls(backend, 5);
    await page.goto('/installs?status=all');
    await expect(page.locator('table[data-table="installs"] tbody tr').first()).toBeVisible();
    await pickTheme(page, 'dark');
    expect((await css(page, 'body', ['background-color']))['background-color']).toBe(rgb('#11131A'));
    expect((await css(page, '.sg-panel', ['background-color']))['background-color']).toBe(rgb('#1B1E28'));
    expect((await css(page, 'table[data-table="installs"] thead th', ['background-color', 'color']))).toEqual({ 'background-color': rgb('#282D38'), color: rgb('#AEB3C2') });
    const row = page.locator('table[data-table="installs"] tbody tr').nth(1);
    await row.hover();
    await expect.poll(() => row.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe('rgba(255, 255, 255, 0.08)');
    await mountButtons(page);
    expect(await css(page, '#btn-probe [data-k="primary-off"]', ['background-color', 'color'])).toEqual({ 'background-color': 'rgba(255, 255, 255, 0.12)', color: 'rgba(255, 255, 255, 0.3)' });
    const pill = page.locator('table[data-table="installs"] tbody .sg-pill-ok').first();
    await expect(pill).toBeVisible();
    expect(await pill.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color])).toEqual([rgb('#EAF7F1'), rgb('#137653')]);
    await page.screenshot({ path: `${SHOTS}/1105-reference-installs-dark.png` });
  });
});
