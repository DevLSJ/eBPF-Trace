import { mkdirSync, readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';

// 11/09 밤 사용자 결정 「참고 사이트 화면을 참고해 깔끔하게」 — 토큰 · 공통 부품 모양(값 · 원리만 옮긴다, 이름 · 로고 · 문구 · 아이콘 · 전용 글꼴 없음).
//   밝은: 바탕 하나 #FFFFFF(회색 바탕 없앰) · 글자 #0F1419 · 흐림 #536471 · 구분 선 #EFF3F4 · 입력 테두리 #CFD9DE · 줄 hover #F7F9F9
//   어두운(남색): 바탕 #15202B · 한 단 위 #1E2732 · 선 #38444D · 글자 #F7F9F9 · 흐림 #8B98A5 · 주 버튼 파랑은 흰 글자 4.5:1 안에서 한 단계 밝게
//   평평: 카드 · 패널 · 표 패널 · KPI 카드 · 로그인 카드 = 그림자 없음 + 1px 선. 떠 있는 면(시트 · 창 · 팝오버 · 메뉴)만 위치 구분용 옅은 그림자
//   버튼: 알약(9999px) · 주 = 파란 채움 · 보조 = 투명 + 입력 테두리색 선 + 본문 글자색 · 높이 그대로(33.6 · 작은 29.6)
//   표: 머리 바탕 없음(본문 면 — 고정 머리라 불투명) + 아래 선 · 줄 구분 #EFF3F4 · hover #F7F9F9 · 머리 42 · 행 48
//   그대로: 움직임 · 포커스 링 · 글자 5단 · 다크 전환 방식 · 768 미만 · 상태 배지(12.5/700 · 테두리 = 글자색) · 위험 빨강 값

const DIR = process.env.X1_SHOTS || `${SHOTS}/x-tokens-1109`;
mkdirSync(DIR, { recursive: true });

const rgb = (hex: string) => {
  const n = parseInt(hex.replace('#', ''), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
};
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
// 그림자 없음 = none, 또는 투명 0 그림자만(Tailwind shadow-[…] 자리 · 투명 토큰)
const flat = (s: string) => s === 'none' || s.split(/,(?![^(]*\))/).every((x) => /^rgba\(0, 0, 0, 0\) 0px 0px 0px 0px$/.test(x.trim()));
const visible = (s: string) => s.split(/,(?![^(]*\))/).map((x) => x.trim()).filter((x) => !/^rgba\(0, 0, 0, 0\)/.test(x)).join(', ');
// 떠 있는 면 그림자(위치 구분용 옅은 그림자 — 넓은 번짐 15 + 가는 테 3)
const FLOAT_LIGHT = 'rgba(101, 119, 134, 0.2) 0px 0px 15px 0px, rgba(101, 119, 134, 0.15) 0px 0px 3px 1px';
const FLOAT_DARK = 'rgba(136, 153, 166, 0.2) 0px 0px 15px 0px, rgba(136, 153, 166, 0.15) 0px 0px 3px 1px';

const css = (page: Page, sel: string, props: string[]) =>
  page.locator(sel).first().evaluate((e, ps) => {
    const cs = getComputedStyle(e);
    return Object.fromEntries(ps.map((p) => [p, cs.getPropertyValue(p)]));
  }, props);
const tokens = (page: Page, names: string[]) =>
  page.evaluate((ns) => Object.fromEntries(ns.map((n) => [n, getComputedStyle(document.documentElement).getPropertyValue(n).trim().toUpperCase()])), names);
async function pickTheme(page: Page, t: 'light' | 'dark') {
  if ((await page.evaluate(() => document.documentElement.dataset.theme)) !== t) await page.locator('[data-part="theme-toggle"]').click();
  await page.waitForFunction(() => !document.documentElement.classList.contains('sg-theme-anim'));
}
const settled = (page: Page) => page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity));
async function mountButtons(page: Page) {
  await page.evaluate(() => {
    document.getElementById('btn-probe')?.remove();
    const box = document.createElement('div');
    box.id = 'btn-probe';
    box.innerHTML =
      '<button class="sg-btn sg-btn-sm sg-btn-secondary" data-k="sm">확인</button><button class="sg-btn sg-btn-sm sg-btn-outline-danger" data-k="sm-danger">확인</button><button class="sg-btn sg-btn-sm sg-btn-primary" data-k="sm-primary">확인</button>' +
      ['primary', 'secondary', 'danger'].map((k) => `<button class="sg-btn sg-btn-${k}" data-k="${k}">확인</button>`).join('');
    document.querySelector('main')!.append(box);
  });
}
function seedInstalls(b: MockBackend, n: number) {
  const last = b.installs[b.installs.length - 1];
  const at = new Date(last.startedAt).getTime();
  for (let i = 1; i <= n; i++)
    b.installs.push({ ...last, id: `ins-3${String(i).padStart(3, '0')}`, packages: [`bulk-${i}`], startedAt: new Date(at - i * 60_000).toISOString(), finishedAt: new Date(at - i * 60_000 + 5_000).toISOString(), status: 'passed', caseId: null, violations: [], isolation: null, scan: undefined, scanId: null });
}
const stubScans = (page: Page) => page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));
const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as unknown;
const EVAL = { static: load('static'), runtime: load('runtime'), model: load('model'), modelAll: load('model-all') };

const LIGHT: Record<string, string> = {
  '--bg': '#FFFFFF', '--surface': '#FFFFFF', '--surface-2': '#F7F9F9', '--surface-3': '#EFF3F4', '--surface-raised': '#FFFFFF', '--field-bg': '#FFFFFF',
  '--text': '#0F1419', '--text-2': '#536471', '--text-3': '#536471', '--field-placeholder': '#536471',
  '--border': '#EFF3F4', '--card-line': '#EFF3F4', '--line-soft': '#EFF3F4', '--border-strong': '#CFD9DE', '--field-line': '#CFD9DE',
  '--row-hover': '#F7F9F9', '--table-head-bg': '#FFFFFF',
  '--accent': '#1769E8', '--btn-primary-bg': '#1769E8', '--btn-primary-fg': '#FFFFFF', '--btn-primary-hover': '#0D47B8',
  '--btn-secondary-bg': 'TRANSPARENT', '--btn-secondary-fg': '#0F1419', '--btn-secondary-ring': '#CFD9DE', '--btn-secondary-hover': 'RGBA(15, 20, 25, .1)',
  '--danger': '#E4516F', '--danger-text': '#B52D49', '--btn-danger-bg': '#B52D49',
  '--r-pill': '9999PX',
};
const DARK: Record<string, string> = {
  '--bg': '#15202B', '--surface': '#15202B', '--surface-2': '#1E2732', '--surface-3': '#22303C', '--surface-raised': '#15202B', '--field-bg': '#15202B',
  '--text': '#F7F9F9', '--text-2': '#8B98A5', '--text-3': '#8B98A5', '--field-placeholder': '#8B98A5',
  '--border': '#38444D', '--card-line': '#38444D', '--line-soft': '#38444D', '--border-strong': '#435260', '--field-line': '#536471',
  '--row-hover': '#1E2732', '--table-head-bg': '#15202B',
  '--accent': '#1B70EE', '--btn-primary-bg': '#1B70EE', '--btn-primary-fg': '#FFFFFF', '--btn-primary-hover': '#0D47B8',
  '--btn-secondary-fg': '#F7F9F9', '--btn-secondary-ring': '#536471', '--btn-secondary-hover': 'RGBA(247, 249, 249, .1)',
  '--danger': '#E4516F', '--danger-text': '#F4C4CE', '--btn-danger-bg': '#B52D49',
};

test.describe('11/09 밤 깔끔한 화면 — 토큰 · 부품 모양(X1)', () => {
  test('토큰: 밝은 · 어두운(남색) 값표', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    expect(await tokens(page, Object.keys(LIGHT))).toEqual(LIGHT);
    await pickTheme(page, 'dark');
    expect(await tokens(page, Object.keys(DARK))).toEqual(DARK);
  });

  test('바탕 하나 · 평평한 카드: 몸통 흰색 · 글자 거의 검정 · 패널 · KPI 카드 · 설정 카드 · 검사 폼 = 그림자 없음 + 1px 선(hover 에도 그림자 없음)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await page.mouse.move(0, 0);
    expect(await css(page, 'body', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#FFFFFF'), color: rgb('#0F1419') });
    expect((await css(page, '[data-testid="page-title"]', ['color'])).color).toBe(rgb('#0F1419'));
    const panel = page.locator('.sg-panel').first();
    const look = (sel: string) =>
      page.locator(sel).first().evaluate((e) => { const c = getComputedStyle(e); return { bg: c.backgroundColor, line: c.borderTopColor, w: c.borderTopWidth, sh: c.boxShadow }; });
    await expect.poll(() => look('.sg-panel').then((v) => ({ ...v, sh: flat(v.sh) }))).toEqual({ bg: rgb('#FFFFFF'), line: rgb('#EFF3F4'), w: '1px', sh: true });
    const kpi = await look('.kpi-card');
    expect({ ...kpi, sh: flat(kpi.sh) }).toEqual({ bg: rgb('#FFFFFF'), line: rgb('#EFF3F4'), w: '1px', sh: true });
    expect(await page.locator('.kpi-card').first().evaluate((e) => getComputedStyle(e).borderLeftWidth)).toBe('4px'); // 종류 띠는 그대로
    // hover: 패널 · 누르는 KPI 카드 · 들리는 카드 견본 모두 그림자 없음
    await panel.hover();
    await page.waitForTimeout(250);
    expect(flat(await panel.evaluate((e) => getComputedStyle(e).boxShadow)), '패널 hover').toBe(true);
    const link = page.locator('a.kpi-card').first();
    if (await link.count()) {
      await link.hover();
      await page.waitForTimeout(250);
      expect(flat(await link.evaluate((e) => getComputedStyle(e).boxShadow)), 'KPI hover').toBe(true);
    }
    await page.evaluate(() => {
      const d = document.createElement('div');
      d.id = 'card-probe';
      d.className = 'sg-card sg-card-hover';
      d.style.cssText = 'width:120px;height:60px';
      document.querySelector('main')!.prepend(d);
    });
    const probe = page.locator('#card-probe');
    expect(flat(await probe.evaluate((e) => getComputedStyle(e).boxShadow)), '카드').toBe(true);
    await probe.hover();
    await page.waitForTimeout(250);
    expect(flat(await probe.evaluate((e) => getComputedStyle(e).boxShadow)), '들리는 카드 hover').toBe(true);
    // 설정 카드 · 공급망 검사 폼
    await page.goto('/settings');
    await expect(page.locator('[data-part="settings-tabs"]')).toBeVisible();
    const card = await look('.sg-card:not(.sg-panel)');
    expect({ ...card, sh: flat(card.sh) }).toEqual({ bg: rgb('#FFFFFF'), line: rgb('#EFF3F4'), w: '1px', sh: true });
    await stubScans(page);
    await page.goto('/scans');
    await expect(page.locator('[data-part="scan-form"]')).toBeVisible();
    const form = await look('[data-part="scan-form"]');
    expect({ ...form, sh: flat(form.sh) }).toEqual({ bg: rgb('#FFFFFF'), line: rgb('#EFF3F4'), w: '1px', sh: true });
    // 어두운(남색)
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await pickTheme(page, 'dark');
    await page.mouse.move(0, 0);
    expect(await css(page, 'body', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#15202B'), color: rgb('#F7F9F9') });
    await expect.poll(() => look('.sg-panel').then((v) => ({ ...v, sh: flat(v.sh) }))).toEqual({ bg: rgb('#15202B'), line: rgb('#38444D'), w: '1px', sh: true });
    const kd = await look('.kpi-card');
    expect({ ...kd, sh: flat(kd.sh) }).toEqual({ bg: rgb('#15202B'), line: rgb('#38444D'), w: '1px', sh: true });
  });

  test('로그인: 흰 바탕 하나 · 카드 그림자 없음 + 1px 선', async ({ page, backend, allowConsole }) => {
    allowConsole(/^Failed to load resource: the server responded with a status of 401 /);
    backend.auth.loggedOut();
    await page.goto('/');
    const auth = page.locator('[data-part="auth"]');
    await expect(auth).toHaveAttribute('data-step', 'login');
    expect(await auth.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#FFFFFF'));
    const card = await css(page, '[data-part="auth"] > div', ['border-top-color', 'border-top-width', 'box-shadow', 'background-color']);
    expect({ ...card, 'box-shadow': flat(card['box-shadow']) }).toEqual({ 'border-top-color': rgb('#EFF3F4'), 'border-top-width': '1px', 'box-shadow': true, 'background-color': rgb('#FFFFFF') });
  });

  test('버튼 알약: 주 = 파란 채움 · 보조 = 투명 + #CFD9DE 선 + 본문 글자색 · 위험 · 작은 크기 — 반경 9999 · 높이 그대로(33.6 · 29.6) · 어두운 = 밝힌 파랑', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await mountButtons(page);
    const P = ['background-color', 'color', 'border-top-color', 'border-top-width', 'border-top-left-radius', 'border-bottom-right-radius', 'box-shadow'];
    for (const k of ['primary', 'secondary', 'danger', 'sm', 'sm-danger', 'sm-primary']) {
      const v = await css(page, `#btn-probe [data-k="${k}"]`, P);
      expect([v['border-top-left-radius'], v['border-bottom-right-radius'], v['box-shadow']], k).toEqual(['9999px', '9999px', 'none']);
    }
    for (const k of ['primary', 'secondary', 'danger']) expect((await page.locator(`#btn-probe [data-k="${k}"]`).boundingBox())!.height, k).toBeCloseTo(33.6, 1);
    for (const k of ['sm', 'sm-danger', 'sm-primary']) expect((await page.locator(`#btn-probe [data-k="${k}"]`).boundingBox())!.height, k).toBeCloseTo(29.6, 1);
    expect(await css(page, '#btn-probe [data-k="primary"]', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#1769E8'), color: rgb('#FFFFFF') });
    expect(await css(page, '#btn-probe [data-k="secondary"]', ['background-color', 'color', 'border-top-color', 'border-top-width'])).toEqual({ 'background-color': 'rgba(0, 0, 0, 0)', color: rgb('#0F1419'), 'border-top-color': rgb('#CFD9DE'), 'border-top-width': '1px' });
    expect(await css(page, '#btn-probe [data-k="danger"]', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#B52D49'), color: rgb('#FFFFFF') });
    await page.locator('#btn-probe [data-k="primary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="primary"]', ['background-color']).then((v) => v['background-color'])).toBe(rgb('#0D47B8'));
    await page.locator('#btn-probe [data-k="secondary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="secondary"]', ['background-color', 'border-top-color'])).toEqual({ 'background-color': 'rgba(15, 20, 25, 0.1)', 'border-top-color': rgb('#CFD9DE') });
    // 화면 단추도 같은 모양(정책 편집 「저장 전 확인」)
    await page.goto('/policies?id=egress-allowlist');
    const save = page.locator('[data-view="rule-editor"]').getByRole('button', { name: '저장 전 확인' });
    await expect(save).toBeVisible();
    expect(await save.evaluate((e) => getComputedStyle(e).borderTopLeftRadius)).toBe('9999px');
    expect((await save.boundingBox())!.height).toBeCloseTo(33.6, 0);
    // 어두운: 주 = 밝힌 파랑(흰 글자 4.5:1 이상) · 보조 = 밝은 글자 + #536471 선
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await pickTheme(page, 'dark');
    await mountButtons(page);
    await page.mouse.move(0, 0);
    expect(await css(page, '#btn-probe [data-k="primary"]', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#1B70EE'), color: rgb('#FFFFFF') });
    expect(await css(page, '#btn-probe [data-k="secondary"]', ['background-color', 'color', 'border-top-color'])).toEqual({ 'background-color': 'rgba(0, 0, 0, 0)', color: rgb('#F7F9F9'), 'border-top-color': rgb('#536471') });
    await page.locator('#btn-probe [data-k="secondary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="secondary"]', ['background-color']).then((v) => v['background-color'])).toBe('rgba(247, 249, 249, 0.1)');
  });

  test('표: 머리 바탕 없음 + 아래 선 · 줄 구분 #EFF3F4 · hover #F7F9F9 · 머리 42 · 행 48 · 표 패널 평평 · 쪽 크기 상자 #CFD9DE(밝은 · 어두운)', async ({ page, backend }) => {
    seedInstalls(backend, 12);
    await page.goto('/installs?status=all');
    const T = 'table[data-table="installs"]';
    await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
    await page.mouse.move(0, 0);
    expect(await css(page, `${T} thead th`, ['height', 'background-color', 'border-bottom-color', 'border-bottom-width', 'color', 'font-size', 'font-weight'])).toEqual({
      height: '42px', 'background-color': rgb('#FFFFFF'), 'border-bottom-color': rgb('#EFF3F4'), 'border-bottom-width': '1px', color: rgb('#536471'), 'font-size': '12px', 'font-weight': '600',
    });
    expect(await css(page, `${T} tbody td`, ['border-bottom-color', 'border-bottom-width'])).toEqual({ 'border-bottom-color': rgb('#EFF3F4'), 'border-bottom-width': '1px' });
    expect(Math.round((await page.locator(`${T} tbody tr`).first().boundingBox())!.height)).toBe(48);
    const row = page.locator(`${T} tbody tr`).nth(1);
    await row.hover();
    await expect.poll(() => row.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#F7F9F9'));
    await page.mouse.move(0, 0);
    const panel = page.locator('.sg-panel').filter({ has: page.locator(T) }).first();
    await expect.poll(() => panel.evaluate((e) => [getComputedStyle(e).boxShadow, getComputedStyle(e).borderTopColor]).then(([s, l]) => [flat(s), l])).toEqual([true, rgb('#EFF3F4')]);
    expect(await css(page, '[data-table-foot="installs"] [data-part="page-size"]', ['border-top-color'])).toEqual({ 'border-top-color': rgb('#CFD9DE') });
    // 배지는 그대로(12.5/700 · 테두리 = 글자색)
    const pill = page.locator(`${T} tbody .sg-pill-ok`).first();
    expect(await pill.evaluate((e) => { const c = getComputedStyle(e); return [c.height, c.fontSize, c.fontWeight, c.borderTopColor, c.color]; })).toEqual(['27px', '12.5px', '700', rgb('#137653'), rgb('#137653')]);
    // 어두운
    await pickTheme(page, 'dark');
    await page.mouse.move(0, 0);
    await expect.poll(() => css(page, `${T} thead th`, ['background-color', 'border-bottom-color', 'color'])).toEqual({ 'background-color': rgb('#15202B'), 'border-bottom-color': rgb('#38444D'), color: rgb('#8B98A5') });
    expect((await css(page, `${T} tbody td`, ['border-bottom-color']))['border-bottom-color']).toBe(rgb('#38444D'));
    await row.hover();
    await expect.poll(() => row.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#1E2732'));
    expect((await css(page, '[data-table-foot="installs"]', ['background-color']))['background-color']).toBe(rgb('#15202B'));
  });

  test('떠 있는 면만 옅은 그림자: 계정 메뉴 · 사용 안내 창 · 칸 고르기 팝오버 · 상세 시트(밝은 · 어두운)', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?status=all');
    await expect(page.locator('table[data-table="installs"] tbody tr').first()).toBeVisible();
    const shadowOf = (sel: string) => page.locator(sel).first().evaluate((e) => getComputedStyle(e).boxShadow);
    for (const theme of ['light', 'dark'] as const) {
      if (theme === 'dark') await pickTheme(page, 'dark');
      const want = theme === 'light' ? FLOAT_LIGHT : FLOAT_DARK;
      await page.locator('[data-part="account"]').click();
      await expect(page.locator('[data-part="account-menu"]')).toBeVisible();
      expect(visible(await shadowOf('[data-part="account-menu"]')), `${theme} 계정 메뉴`).toBe(want);
      await page.keyboard.press('Escape');
      await page.locator('[data-action="table-columns"]').click();
      await expect(page.locator('[data-part="column-picker"]')).toBeVisible();
      await expect.poll(() => shadowOf('[data-part="column-picker"]').then(visible), { message: `${theme} 팝오버` }).toBe(want);
      await page.keyboard.press('Escape');
      await page.getByRole('button', { name: '사용 안내 (?)' }).click();
      const dlg = page.locator('dialog[data-part="help"]');
      await expect(dlg).toBeVisible();
      expect(visible(await dlg.evaluate((e) => getComputedStyle(e).boxShadow)), `${theme} 창`).toBe(want);
      await page.keyboard.press('Escape');
      await expect(dlg).toBeHidden();
    }
    await page.goto('/installs?id=ins-0012');
    const sheet = page.locator('.sg-sheet-layer > .sg-sheet');
    await expect(sheet).toBeVisible();
    expect(visible(await sheet.evaluate((e) => getComputedStyle(e).boxShadow)), '시트').toBe(FLOAT_DARK);
  });

  test('대비(계산): 글자 · 흐림 · 안내 글자가 모든 면 위 4.5:1 이상 · 주/보조/위험 단추 글자 4.5:1 · 어두운 주 파랑은 밝은 쪽보다 밝고 바탕 대비 3:1 이상', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const rows: string[] = [];
    const t: Record<'light' | 'dark', Record<string, string>> = { light: {}, dark: {} };
    for (const theme of ['light', 'dark'] as const) {
      if (theme === 'dark') await pickTheme(page, 'dark');
      t[theme] = await tokens(page, ['--text', '--text-2', '--text-3', '--field-placeholder', '--bg', '--surface', '--surface-2', '--surface-3', '--surface-raised', '--field-bg', '--row-hover',
        '--btn-primary-bg', '--btn-primary-fg', '--btn-primary-hover', '--btn-secondary-fg', '--btn-danger-bg', '--text-inverse', '--accent', '--accent-text', '--accent-soft', '--danger-text', '--danger-soft']);
      const v = t[theme];
      for (const fg of ['--text', '--text-2', '--text-3', '--field-placeholder'])
        for (const bg of ['--bg', '--surface', '--surface-2', '--surface-3', '--surface-raised', '--field-bg', '--row-hover']) {
          const r = contrast(v[fg], v[bg]);
          rows.push(`${theme} ${fg}(${v[fg]}) / ${bg}(${v[bg]}) ${r.toFixed(2)}`);
          expect(r, `${theme} ${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
        }
      for (const [fg, bg] of [['--btn-primary-fg', '--btn-primary-bg'], ['--btn-primary-fg', '--btn-primary-hover'], ['--btn-secondary-fg', '--surface'], ['--btn-secondary-fg', '--surface-2'], ['--text-inverse', '--btn-danger-bg'],
        ['--danger-text', '--surface'], ['--danger-text', '--danger-soft'], ['--accent-text', '--surface'], ['--accent-text', '--accent-soft']] as const) {
        const r = contrast(v[fg], v[bg]);
        rows.push(`${theme} ${fg}(${v[fg]}) / ${bg}(${v[bg]}) ${r.toFixed(2)}`);
        expect(r, `${theme} ${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
    }
    expect(lum(t.dark['--btn-primary-bg']), '어두운 주 파랑 = 한 단계 밝게').toBeGreaterThan(lum(t.light['--btn-primary-bg']));
    expect(contrast(t.dark['--btn-primary-bg'], t.dark['--bg']), '어두운 주 버튼 면 / 바탕(비글자 3:1)').toBeGreaterThanOrEqual(3);
    test.info().annotations.push({ type: '대비', description: rows.join('\n') });
  });

  test('쓰지 않는 것: 옛 회색 바탕 #F6F7FB · 옛 글자 #202534 · 옛 흐림 #5F6675 · 넓은 카드 그림자 · 높이 8 그림자 · 옛 팝오버 그림자', async ({ page, backend }) => {
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
        oldBg: all.match(/(#|%23)(F6F7FB|11131A|1B1E28)\b/gi) ?? [],
        oldText: all.match(/(#|%23)(202534|5F6675|F2F3F7|AEB3C2)\b/gi) ?? [],
        wideCard: all.match(/39,\s*76,\s*142|31,\s*38,\s*54/g) ?? [],
        elevation8: all.match(/5px 5px -3px/g) ?? [],
        oldPop: all.match(/12px 28px rgba\(9,\s*30,\s*66/g) ?? [],
      };
    });
    expect(found).toEqual({ oldBg: [], oldText: [], wideCard: [], elevation8: [], oldPop: [] });
  });

  test('「—」 없음 · 사진: 정책 · 감사 로그 · 대시보드 · 평가 — 1440 밝은 · 어두운, 390 밝은', async ({ page, backend }) => {
    void backend;
    test.setTimeout(120_000);
    await page.route(/\/api\/evaluation$/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(EVAL) }));
    const views: [string, string, (p: Page) => Promise<void>][] = [
      ['policies', '/policies', (p) => expect(p.getByTestId('rules')).toBeVisible()],
      ['audit', '/audit', (p) => expect(p.locator('tr[data-audit]').first()).toBeVisible()],
      ['dashboard', '/', (p) => expect(p.getByTestId('pending')).toBeVisible()],
      ['evaluation', '/evaluation', (p) => expect(p.locator('[data-part="evaluation"][data-state="ready"]')).toBeVisible()],
    ];
    const dashes = () =>
      page.evaluate(() => {
        const out: string[] = [];
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
          const n = walker.currentNode as Text;
          const el = n.parentElement;
          if (!n.data.includes('—') || !el || el.closest('[data-part="code"], pre, code, script, style')) continue;
          if (el.tagName !== 'OPTION' && !el.checkVisibility({ checkVisibilityCSS: true })) continue;
          out.push(n.data.trim().slice(0, 60));
        }
        return out;
      });
    for (const [theme, w, h] of [['light', 1440, 900], ['dark', 1440, 900], ['light', 390, 844]] as const) {
      await page.setViewportSize({ width: w, height: h });
      await page.goto('/');
      await page.evaluate((v) => localStorage.setItem('supplyguard.theme', v), theme);
      for (const [name, url, ready] of views) {
        await page.goto(url);
        await ready(page);
        expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
        await page.mouse.move(0, 0);
        await settled(page);
        expect(await dashes(), `${name} ${theme} ${w}`).toEqual([]);
        await page.screenshot({ path: `${DIR}/${name}-${w}-${theme}.png` });
      }
    }
  });
});
