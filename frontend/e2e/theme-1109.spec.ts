import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';

// 11/09 참고 홈페이지 구조값 — 미색 회색 단계 · 거의 검정 주 버튼 · 반경(버튼 8 · 입력 12 · 카드 16 · 대화상자 24) · 아주 옅은 그림자 · 가는 테두리 · 다크 색 · 전환 시간.
// 강조 파랑 #1769E8(hover · soft · text 짝)은 그대로 — 링크 · 포커스 · 선택된 메뉴 · 정보 톤 · 차트 강조에만. 표 밀도(머리 42 · 행 48) · 배지 크기 · 쪽 넘김 구조도 그대로.
// 참고 쪽 이름 · 로고 · 세리프 · 테라코타 계열 · 브랜드 색 이름은 옮기지 않는다(공개 저장소). 11/05 참고 대시보드 값 회귀를 대체

// 설치 기록을 늘려 쪽이 여러 개가 되게(r4-tables 와 같은 방식 — 마지막 기록을 복제해 통과로)
function seedInstalls(b: MockBackend, n: number) {
  const last = b.installs[b.installs.length - 1];
  const at = new Date(last.startedAt).getTime();
  for (let i = 1; i <= n; i++)
    b.installs.push({ ...last, id: `ins-2${String(i).padStart(3, '0')}`, packages: [`bulk-${i}`], startedAt: new Date(at - i * 60_000).toISOString(), finishedAt: new Date(at - i * 60_000 + 5_000).toISOString(), status: 'passed', caseId: null, violations: [], isolation: null, scan: undefined, scanId: null });
}

const rgb = (hex: string) => {
  const n = parseInt(hex.replace('#', ''), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
};
// WCAG 대비(hex 두 개)
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
const SH_SM = 'rgba(0, 0, 0, 0.04) 0px 2px 8px 0px';
const SH_MD = 'rgba(0, 0, 0, 0.04) 0px 4px 20px 0px';
const SH_FLOAT = 'rgba(0, 0, 0, 0.1) 0px 4px 16px 0px';
const EASE_PANEL = 'cubic-bezier(0.4, 0, 0.2, 1)';
// Tailwind shadow-[…] 는 링 · 안쪽 그림자 자리(투명 0)를 앞에 붙인다 — 보이는 그림자만 비교
const visible = (s: string) => s.replace(/rgba\(0, 0, 0, 0\) 0px 0px 0px 0px, /g, '');

const css = (page: Page, sel: string, props: string[]) =>
  page.locator(sel).first().evaluate((e, ps) => {
    const cs = getComputedStyle(e);
    return Object.fromEntries(ps.map((p) => [p, cs.getPropertyValue(p)]));
  }, props);
const tokens = (page: Page, names: string[]) =>
  page.evaluate((ns) => Object.fromEntries(ns.map((n) => [n, getComputedStyle(document.documentElement).getPropertyValue(n).trim().toUpperCase()])), names);
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
// 공급망 검사 목록 API 는 가짜 백엔드에 없다 — 빈 목록
const stubScans = (page: Page) => page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));

// 실측표(11/09) — 토큰 이름은 일반 이름(브랜드 색 이름 없음). 다크 흐림(--text-3)만 대비 4.5 때문에 한 단계 밝힘(#87867F → #9C9A92)
const LIGHT: Record<string, string> = {
  '--bg': '#FAF9F5', '--surface-2': '#F5F4ED', '--surface-3': '#F0EEE6', '--surface-raised': '#FFFFFF', '--surface': '#FFFFFF', '--card-line': '#F0EEE6',
  '--field-bg': '#FFFFFF', '--field-placeholder': '#5E5D59',
  '--text': '#141413', '--text-2': '#30302E', '--text-3': '#5E5D59',
  '--border-heavy': '#B0AEA5', '--border-strong': '#D1CFC5', '--border': '#E8E6DC',
  '--btn-primary-bg': '#141413', '--btn-primary-fg': '#FAF9F5', '--btn-secondary-bg': '#E8E6DC', '--btn-secondary-fg': '#4D4C48',
  '--accent': '#1769E8', '--accent-hover': '#0D47B8', '--accent-soft': '#DCE9FF', '--accent-text': '#0D47B8',
  '--r-sm': '8PX', '--r-md': '12PX', '--r-lg': '16PX', '--r-xl': '24PX', '--t-btn': '200MS', '--t-panel': '250MS',
};
const DARK: Record<string, string> = {
  '--bg': '#141413', '--surface-2': '#1A1918', '--surface-3': '#262624', '--surface-raised': '#1F1E1D', // 떠 있는 면 = 카드(11/09 메인: 안의 보조 바탕과 구분) '--surface': '#1F1E1D', '--card-line': '#30302E',
  '--field-bg': '#262624', '--field-placeholder': '#9C9A92',
  '--text': '#FAF9F5', '--text-2': '#B0AEA5', '--text-3': '#9C9A92',
  '--border-heavy': '#5E5D59', '--border-strong': '#3D3D3A', '--border': '#30302E',
  '--btn-primary-bg': '#FAF9F5', '--btn-primary-fg': '#141413', '--btn-secondary-bg': '#30302E', '--btn-secondary-fg': '#FAF9F5',
  '--accent': '#1769E8', '--accent-hover': '#0D47B8', '--accent-soft': '#1A2D4E', '--accent-text': '#DCE9FF',
};

test.describe('11/09 참고 홈페이지 구조값', () => {
  test('토큰: 미색 회색 단계 · 글자 3단 · 테두리 3단 · 주/보조 버튼 · 반경 · 전환 — 라이트 · 다크 실측표 그대로, 강조 파랑 짝은 그대로', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    expect(await tokens(page, Object.keys(LIGHT))).toEqual(LIGHT);
    await pickTheme(page, 'dark');
    expect(await tokens(page, Object.keys(DARK))).toEqual(DARK);
  });

  test('글꼴 · 바탕 · 제목 굵기 600 — 웹폰트 · 세리프를 쓰지 않는다', async ({ page, backend }) => {
    void backend;
    const fonts: string[] = [];
    page.on('request', (r) => r.resourceType() === 'font' && fonts.push(r.url()));
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const b = await css(page, 'body', ['font-family', 'background-color', 'color', 'line-height']);
    expect(b['font-family']).toMatch(/^Inter, Pretendard, -apple-system, ("system-ui"|BlinkMacSystemFont), "Segoe UI", sans-serif$/); // Chromium 은 BlinkMacSystemFont 를 system-ui 로 적는다
    expect(b['background-color']).toBe(rgb('#FAF9F5'));
    expect(b.color).toBe(rgb('#141413'));
    expect(b['line-height']).toBe('26.4px'); // 16 × 1.65
    expect(await css(page, '[data-testid="page-title"]', ['font-size', 'font-weight', 'letter-spacing', 'font-family'])).toEqual({ 'font-size': '26.4px', 'font-weight': '600', 'letter-spacing': '-0.528px', 'font-family': b['font-family'] });
    expect(await css(page, '.sg-panel-title', ['font-weight', 'font-family'])).toEqual({ 'font-weight': '600', 'font-family': b['font-family'] });
    expect(fonts).toEqual([]);
  });

  test('버튼: 주 = 거의 검정 · 보조 = 미색 회색 + 1px 링(hover 2px) · 위험 · 비활성 — 반경 8 · 14/500 · 높이 36(작은 28) · 전환 .2s ease-in-out · 포커스 2px 파랑 링 offset 2', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await mountButtons(page);
    const P = ['background-color', 'color', 'border-top-width', 'border-radius', 'font-size', 'font-weight', 'box-shadow', 'transition-duration', 'transition-timing-function'];
    const primary = await css(page, '#btn-probe [data-k="primary"]', P);
    expect(primary).toMatchObject({ 'background-color': rgb('#141413'), color: rgb('#FAF9F5'), 'border-radius': '8px', 'font-size': '14px', 'font-weight': '500', 'box-shadow': 'none' });
    expect(primary['transition-duration']).toMatch(/^0\.2s(, 0\.2s)*$/);
    expect(primary['transition-timing-function']).toMatch(/^ease-in-out(, ease-in-out)*$/);
    for (const k of ['primary', 'secondary', 'danger']) expect(Math.round((await page.locator(`#btn-probe [data-k="${k}"]`).boundingBox())!.height), k).toBe(36);
    expect(await css(page, '#btn-probe [data-k="secondary"]', P)).toMatchObject({ 'background-color': rgb('#E8E6DC'), color: rgb('#4D4C48'), 'border-top-width': '0px', 'border-radius': '8px', 'box-shadow': 'rgb(209, 207, 197) 0px 0px 0px 1px' });
    expect(await css(page, '#btn-probe [data-k="danger"]', P)).toMatchObject({ 'background-color': rgb('#B52D49'), color: rgb('#FFFFFF') }); // #E4516F 위 흰 글자는 3.7:1 — 한 단계 진한 위험색
    for (const k of ['primary-off', 'secondary-off', 'danger-off'])
      expect(await css(page, `#btn-probe [data-k="${k}"]`, P), k).toMatchObject({ 'background-color': rgb('#F0EEE6'), color: rgb('#87867F') });
    // 작은 크기: 높이 28 · 좌우 12 · 글자 14, 위험 외곽선 = 위험 글자색 + 1px 링
    expect(await css(page, '#btn-probe [data-k="sm"]', ['padding-left', 'font-size'])).toEqual({ 'padding-left': '12px', 'font-size': '14px' });
    expect(Math.round((await page.locator('#btn-probe [data-k="sm"]').boundingBox())!.height)).toBe(28);
    expect(await css(page, '#btn-probe [data-k="sm-danger"]', ['color', 'border-top-width', 'box-shadow'])).toEqual({ color: rgb('#B52D49'), 'border-top-width': '0px', 'box-shadow': 'rgba(228, 81, 111, 0.5) 0px 0px 0px 1px' });
    // 호버
    await page.locator('#btn-probe [data-k="primary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="primary"]', ['background-color']).then((v) => v['background-color'])).toBe(rgb('#30302E'));
    await page.locator('#btn-probe [data-k="secondary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="secondary"]', ['box-shadow']).then((v) => v['box-shadow'])).toBe('rgb(209, 207, 197) 0px 0px 0px 2px');
    await page.locator('#btn-probe [data-k="danger"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="danger"]', ['background-color']).then((v) => v['background-color'])).toBe(rgb('#A0394E'));
    // 키보드 포커스: 2px 파랑 링 · offset 2
    await page.mouse.move(0, 0);
    await page.locator('#btn-probe [data-k="primary"]').focus();
    await page.keyboard.press('Shift');
    expect(await css(page, '#btn-probe [data-k="primary"]', ['outline-style', 'outline-width', 'outline-color', 'outline-offset'])).toEqual({ 'outline-style': 'solid', 'outline-width': '2px', 'outline-color': rgb('#1769E8'), 'outline-offset': '2px' });
  });

  test('표 · 배지 · 쪽 넘김 · 패널: 머리 42 미색 회색 12/600 · 행 48 · 배지 27 그대로 · 패널 반경 16 · 옅은 그림자 · hover 회색 선 .25s', async ({ page, backend }) => {
    seedInstalls(backend, 37); // 8 + 37 = 45 → 3쪽
    await page.goto('/installs?status=all');
    const T = 'table[data-table="installs"]';
    await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
    expect(await css(page, `${T} thead th`, ['height', 'background-color', 'font-size', 'font-weight', 'color', 'padding-left', 'border-bottom-color'])).toEqual({
      height: '42px', 'background-color': rgb('#F5F4ED'), 'font-size': '12px', 'font-weight': '600', color: rgb('#5E5D59'), 'padding-left': '16px', 'border-bottom-color': rgb('#E8E6DC'),
    });
    const td = await css(page, `${T} tbody td`, ['font-size', 'padding-left', 'padding-top', 'border-bottom-color', 'border-bottom-width']);
    expect(td).toEqual({ 'font-size': '12.5px', 'padding-left': '16px', 'padding-top': '8px', 'border-bottom-color': rgb('#F0EEE6'), 'border-bottom-width': '1px' });
    expect(Math.round((await page.locator(`${T} tbody tr`).first().boundingBox())!.height)).toBe(48);
    const zebra = await page.locator(`${T} tbody tr`).evaluateAll((rows) => rows.slice(0, 2).map((r) => getComputedStyle(r).backgroundColor));
    expect(zebra[0]).toBe(zebra[1]);
    const row = page.locator(`${T} tbody tr`).nth(1);
    await row.hover();
    await expect.poll(() => row.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe('rgba(20, 20, 19, 0.04)');
    // 상태 배지 — 크기 · 톤 그대로
    const pill = page.locator(`${T} tbody .sg-pill-ok`).first();
    await expect(pill).toBeVisible();
    expect(await pill.evaluate((e) => { const c = getComputedStyle(e); return [c.height, c.fontSize, c.fontWeight, c.borderTopWidth, c.borderTopColor, c.backgroundColor, c.color, c.minWidth]; })).toEqual([
      '27px', '12.5px', '750', '1px', rgb('#BDE7D6'), rgb('#EAF7F1'), rgb('#137653'), '62px',
    ]);
    const iso = page.locator(`${T} tbody [data-status="isolated"]`).first();
    await expect(iso).toBeVisible();
    expect(await iso.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color, getComputedStyle(e).borderTopColor])).toEqual([rgb('#FDECEF'), rgb('#B52D49'), rgb('#F4C4CE')]);
    // 쪽 넘김 — 구조 그대로, 글자 · 선택칸만 새 단계
    const foot = page.locator('[data-table-foot="installs"]');
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 1/3 페이지');
    expect(await foot.locator('[data-part="page-size"] option').allTextContents()).toEqual(['20개씩', '50개씩', '100개씩']);
    expect(await css(page, '[data-table-foot="installs"] [data-part="range"]', ['font-size', 'color'])).toEqual({ 'font-size': '14px', color: rgb('#5E5D59') });
    expect(await css(page, '[data-table-foot="installs"] [data-part="page-size"]', ['height', 'border-radius', 'font-size', 'border-top-color', 'background-color'])).toEqual({ height: '40px', 'border-radius': '12px', 'font-size': '14px', 'border-top-color': rgb('#D1CFC5'), 'background-color': rgb('#FFFFFF') });
    for (const k of ['first', 'prev', 'next', 'last']) await expect(foot.locator(`[data-page="${k}"]`)).toBeVisible();
    const cur = await css(page, '[data-table-foot="installs"] .tk-page.on', ['width', 'height', 'border-radius', 'background-color', 'color']);
    expect(cur).toEqual({ width: '26px', height: '26px', 'border-radius': '13px', 'background-color': rgb('#1769E8'), color: rgb('#FFFFFF') });
    await foot.locator('[data-page="last"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 3/3 페이지');
    // 패널(표를 감싼 카드)
    const panel = page.locator('.sg-panel').filter({ has: page.locator(T) }).first();
    await page.mouse.move(0, 0);
    await expect.poll(() => panel.evaluate((e) => { const c = getComputedStyle(e); return [c.borderRadius, c.boxShadow, c.borderTopColor, c.borderTopWidth, c.backgroundColor]; })).toEqual(['16px', SH_SM, rgb('#F0EEE6'), '1px', rgb('#FFFFFF')]);
    expect(await panel.evaluate((e) => [getComputedStyle(e).transitionDuration, getComputedStyle(e).transitionTimingFunction])).toEqual(['0.25s, 0.25s', `${EASE_PANEL}, ${EASE_PANEL}`]);
    const head = panel.locator('.sg-panel-head');
    expect(await head.evaluate((e) => [getComputedStyle(e).minHeight, getComputedStyle(e).paddingLeft, getComputedStyle(e).borderBottomColor])).toEqual(['56px', '20px', rgb('#F0EEE6')]);
    expect(await panel.locator('.sg-panel-title').evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight])).toEqual(['17.92px', '600']);
    await panel.hover();
    await expect.poll(() => panel.evaluate((e) => [getComputedStyle(e).borderTopColor, getComputedStyle(e).boxShadow])).toEqual([rgb('#D1CFC5'), SH_MD]);
    await page.screenshot({ path: `${SHOTS}/1109-theme-installs.png` });
  });

  test('빈 상태 · 카드: 가운데 흐림 14px · 카드 반경 16 · 1px 미색 선 · 그림자 sm', async ({ page, backend }) => {
    void backend;
    await page.route(/\/api\/installs(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));
    await page.goto('/installs');
    const empty = page.locator('.sg-empty').first();
    await expect(empty).toBeVisible();
    expect(await empty.evaluate((el) => { const c = getComputedStyle(el); return [c.textAlign, c.fontSize, c.color, el.getBoundingClientRect().height >= 180]; })).toEqual(['center', '14px', rgb('#5E5D59'), true]);
    await page.goto('/topology?node=c%3Apkg-reqeusts');
    await expect(page.getByTestId('chains')).toBeVisible();
    expect(await css(page, '[data-testid="chains"]', ['border-radius', 'border-top-width', 'border-top-color', 'box-shadow', 'background-color'])).toEqual({
      'border-radius': '16px', 'border-top-width': '1px', 'border-top-color': rgb('#F0EEE6'), 'box-shadow': SH_SM, 'background-color': rgb('#FFFFFF'),
    });
  });

  test('입력창 반경 12 · 흰 바탕 · 안내 글자 흐림 · 떠 있는 면(드롭다운 · 대화상자) = 흰 면 + 떠 있는 그림자, 대화상자 반경 24', async ({ page, backend }) => {
    void backend;
    await stubScans(page);
    await page.goto('/scans');
    const name = page.locator('[data-part="scan-form"] [data-field="name"]');
    await expect(name).toBeVisible();
    expect(await name.evaluate((e) => { const c = getComputedStyle(e); return [c.borderRadius, c.backgroundColor, c.borderTopColor, getComputedStyle(e, '::placeholder').color]; })).toEqual(['12px', rgb('#FFFFFF'), rgb('#D1CFC5'), rgb('#5E5D59')]);
    await page.locator('[data-part="account"]').click();
    const menu = page.locator('[data-part="account-menu"]');
    await expect(menu).toBeVisible();
    expect(await menu.evaluate((e) => { const c = getComputedStyle(e); return [c.backgroundColor, c.borderRadius, c.boxShadow]; }).then(([b, r, sh]) => [b, r, visible(sh)])).toEqual([rgb('#FFFFFF'), '12px', SH_FLOAT]);
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: '사용 안내 (?)' }).click();
    const dlg = page.locator('dialog[data-part="help"]');
    await expect(dlg).toBeVisible();
    expect(await dlg.evaluate((e) => { const c = getComputedStyle(e); return [c.backgroundColor, c.borderRadius, c.boxShadow]; }).then(([b, r, sh]) => [b, r, visible(sh)])).toEqual([rgb('#FFFFFF'), '24px', SH_FLOAT]);
    expect(await css(page, 'dialog[data-part="help"] button:text("닫기")', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#141413'), color: rgb('#FAF9F5') });
  });

  test('로그인: 미색 바탕(그라데이션 없음) · 카드 반경 24 · 주 버튼 거의 검정 · 입력창 반경 12', async ({ page, backend, allowConsole }) => {
    allowConsole(/^Failed to load resource: the server responded with a status of 401 /);
    backend.auth.loggedOut();
    await page.goto('/');
    const auth = page.locator('[data-part="auth"]');
    await expect(auth).toHaveAttribute('data-step', 'login');
    expect(await auth.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).backgroundImage])).toEqual([rgb('#FAF9F5'), 'none']);
    const card = await css(page, '[data-part="auth"] > div', ['border-radius', 'background-color', 'border-top-color', 'box-shadow']);
    expect({ ...card, 'box-shadow': visible(card['box-shadow']) }).toEqual({ 'border-radius': '24px', 'background-color': rgb('#FFFFFF'), 'border-top-color': rgb('#F0EEE6'), 'box-shadow': SH_MD });
    const go = auth.getByRole('button', { name: '로그인' });
    expect(await go.evaluate((e) => { const c = getComputedStyle(e); return [c.backgroundColor, c.color, c.borderRadius, Math.round(e.getBoundingClientRect().height)]; })).toEqual([rgb('#141413'), rgb('#FAF9F5'), '8px', 36]);
    expect(await auth.getByLabel('아이디').evaluate((e) => [getComputedStyle(e).borderRadius, getComputedStyle(e).backgroundColor])).toEqual(['12px', rgb('#FFFFFF')]);
  });

  test('다크: 바탕 · 카드 · 표 머리 · 행 호버 · 주/보조/비활성 버튼 · 입력창 · 대화상자 = 다크 실측값, 배지는 라이트와 같은 톤 값', async ({ page, backend }) => {
    seedInstalls(backend, 5);
    await page.goto('/installs?status=all');
    await expect(page.locator('table[data-table="installs"] tbody tr').first()).toBeVisible();
    await pickTheme(page, 'dark');
    expect((await css(page, 'body', ['background-color']))['background-color']).toBe(rgb('#141413'));
    await page.mouse.move(0, 0); // 테마 메뉴가 닫힌 자리 아래 패널이 hover 되지 않게
    await expect.poll(() => css(page, '.sg-panel', ['background-color', 'border-top-color'])).toEqual({ 'background-color': rgb('#1F1E1D'), 'border-top-color': rgb('#30302E') }); // 선 색은 .25s 전환
    expect(await css(page, 'table[data-table="installs"] thead th', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#1A1918'), color: rgb('#9C9A92') });
    const row = page.locator('table[data-table="installs"] tbody tr').nth(1);
    await row.hover();
    await expect.poll(() => row.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe('rgba(250, 249, 245, 0.06)');
    await mountButtons(page);
    expect(await css(page, '#btn-probe [data-k="primary"]', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#FAF9F5'), color: rgb('#141413') });
    expect(await css(page, '#btn-probe [data-k="secondary"]', ['background-color', 'color', 'box-shadow'])).toEqual({ 'background-color': rgb('#30302E'), color: rgb('#FAF9F5'), 'box-shadow': 'rgb(61, 61, 58) 0px 0px 0px 1px' });
    expect(await css(page, '#btn-probe [data-k="primary-off"]', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#262624'), color: rgb('#5E5D59') });
    const pill = page.locator('table[data-table="installs"] tbody .sg-pill-ok').first();
    await expect(pill).toBeVisible();
    expect(await pill.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color])).toEqual([rgb('#EAF7F1'), rgb('#137653')]);
    await page.screenshot({ path: `${SHOTS}/1109-theme-installs-dark.png` });
    await page.goto('/events');
    const search = page.getByPlaceholder('이름 검색');
    await expect(search).toBeVisible();
    expect(await search.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).borderRadius, getComputedStyle(e, '::placeholder').color])).toEqual([rgb('#262624'), '12px', rgb('#9C9A92')]);
    await page.getByRole('button', { name: '사용 안내 (?)' }).click();
    const dlg = page.locator('dialog[data-part="help"]');
    await expect(dlg).toBeVisible();
    expect(await dlg.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#1F1E1D'));
    await page.keyboard.press('Escape');
    // 강조 파랑 글자는 다크 카드 위 3.35:1 — 글자에만 밝은 짝(--accent-text #DCE9FF). 채움(현재 쪽 · 선택 칩)은 그대로 파랑
    await page.goto('/');
    const more = page.locator('.sg-panel a[data-more]').first();
    await expect(more).toBeVisible();
    expect(await more.evaluate((e) => getComputedStyle(e).color)).toBe(rgb('#DCE9FF'));
  });

  test('대비: 글자 3단 · 안내 글자 · 버튼 글자가 모든 바탕 위에서 4.5:1 이상(라이트 · 다크)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    for (const theme of ['light', 'dark'] as const) {
      if (theme === 'dark') await pickTheme(page, 'dark');
      const t = await tokens(page, ['--text', '--text-2', '--text-3', '--field-placeholder', '--bg', '--surface', '--surface-2', '--surface-3', '--surface-raised', '--field-bg',
        '--btn-primary-bg', '--btn-primary-fg', '--btn-secondary-bg', '--btn-secondary-fg', '--btn-danger-bg', '--text-inverse', '--accent']);
      for (const fg of ['--text', '--text-2', '--text-3', '--field-placeholder'])
        for (const bg of ['--bg', '--surface', '--surface-2', '--surface-3', '--surface-raised', '--field-bg'])
          expect(contrast(t[fg], t[bg]), `${theme} ${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      for (const [fg, bg] of [['--btn-primary-fg', '--btn-primary-bg'], ['--btn-secondary-fg', '--btn-secondary-bg'], ['--text-inverse', '--btn-danger-bg'], ['--text-inverse', '--accent']])
        expect(contrast(t[fg], t[bg]), `${theme} ${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  test('쓰지 않는 것: 테라코타 계열 값 · 0.5px 선', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const found = await page.evaluate(() => {
      const text: string[] = [];
      const walk = (rules: CSSRuleList) => {
        for (const r of Array.from(rules)) {
          text.push(r.cssText);
          if ('cssRules' in r && (r as CSSGroupingRule).cssRules) walk((r as CSSGroupingRule).cssRules);
        }
      };
      for (const s of Array.from(document.styleSheets)) walk(s.cssRules);
      const all = text.join('\n');
      return {
        terracotta: all.match(/#(D97757|C6613F|C46849)\b/gi) ?? [],
        halfPx: all.match(/\b0?\.5px solid/g) ?? [],
      };
    });
    expect(found).toEqual({ terracotta: [], halfPx: [] });
  });
});
