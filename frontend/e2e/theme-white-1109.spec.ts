import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';

// 11/09 사용자 결정 「11/05 판 + 대비 수정」 — 흰 배경(11/05 참고 대시보드 값)으로 되돌리고, 대비 4.5:1 을 못 맞추던 값만 바로잡는다.
// 11/05 값: 바탕 #F6F7FB · 카드 흰색 · 주 버튼 파랑 #1769E8 · 보조 버튼 파란 외곽선 · 반경 8(버튼 6) · 넓고 옅은 카드 그림자 · 버튼 14.4/700 · 표 머리 42 · 행 48 · 배지 27 · 쪽 넘김.
// 대비 수정: 흐림 글자 #7A8090 → #5F6675(흰 카드 3.95 → 5.76:1) · 위험 채움 버튼 #E4516F → #B52D49(흰 글자 3.68 → 6.11:1) · 위험 글자 = danger-text ·
// 다크 파랑 글자 = accent-text · 다크 떠 있는 면 = 카드 값 · 다크 반전 툴팁 흐림 글자 #7E8696 → #9AA3B2(3.83 → 5.50:1).
// 11/09 밤(사용자 「참고 사이트처럼 깔끔하게」 — x-tokens-1109): 바탕 하나 흰색 · 글자 #0F1419 · 흐림 #536471 · 선 #EFF3F4 · 입력 테두리 #CFD9DE · 줄 hover #F7F9F9 ·
// 카드 · 패널 그림자 없음 · 떠 있는 면만 옅은 그림자 · 버튼 알약 · 보조 = 투명 + #CFD9DE 선 + 본문 글자색 · 표 머리 바탕 없음 · 어두운 = 남색(#15202B) — 아래 값 줄은 그 값으로 바뀜
// 11/09 에 생긴 토큰 이름(--surface-raised · --field-* · --card-line · --border-heavy · --btn-* · --t-btn · --t-panel …)과 Tailwind 별칭(bg-primary · bg-raised · bg-field · border-card-line)은 남긴다

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
// 그림자(11/09 밤 평평): 카드 · 패널 · 로그인 카드 = 없음(투명 0 그림자 토큰) · 떠 있는 면(메뉴 · 대화상자) = 위치 구분용 옅은 그림자 · 패널 hover = 선만
const SH_FLAT = 'rgba(0, 0, 0, 0) 0px 0px 0px 0px';
const SH_FLOAT = 'rgba(101, 119, 134, 0.2) 0px 0px 15px 0px, rgba(101, 119, 134, 0.15) 0px 0px 3px 1px';
// 11/09 SPEC 움직임 토큰: 색 전환 = 빠름 120 · ease-color, 들림 · 그림자 = 보통 180 · ease-move
const EASE_COLOR = 'cubic-bezier(0.35, 0, 0.35, 1)';
const EASE_MOVE = 'cubic-bezier(0.2, 0, 0, 1)';
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
  // 11/09 G01: 테마는 상단 해/달 단추 하나 — 지금과 다르면 누르고, 색 전환(450ms)이 끝날 때까지 기다린다
  if ((await page.evaluate(() => document.documentElement.dataset.theme)) !== t) await page.locator('[data-part="theme-toggle"]').click();
  await page.waitForFunction(() => !document.documentElement.classList.contains('sg-theme-anim'));
}
// 버튼 클래스 견본 — 화면마다 있는 버튼 종류가 달라 본문에 견본을 붙여 클래스 값만 본다
async function mountButtons(page: Page) {
  await page.evaluate(() => {
    const box = document.createElement('div');
    box.id = 'btn-probe';
    box.innerHTML = '<button class="sg-btn sg-btn-sm sg-btn-secondary" data-k="sm">확인</button><button class="sg-btn sg-btn-sm sg-btn-outline-danger" data-k="sm-danger">확인</button><button class="sg-btn sg-btn-sm sg-btn-primary" data-k="sm-primary">확인</button>' + ['primary', 'secondary', 'danger'].map((k) => `<button class="sg-btn sg-btn-${k}" data-k="${k}">확인</button><button class="sg-btn sg-btn-${k}" data-k="${k}-off" disabled>확인</button>`).join('');
    document.querySelector('main')!.append(box);
  });
}
// 공급망 검사 목록 API 는 가짜 백엔드에 없다 — 빈 목록
const stubScans = (page: Page) => page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));
// 끝나는 전환 · 등장 애니메이션만 기다린다(무한 반복 — 실시간 점 · 흐름 그림 — 은 제외)
const settled = (page: Page) => page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity));

// 실측표 — 11/05 값, 대비 수정만 바뀜(흐림 글자 · 위험 채움 버튼 · 다크 보조 버튼 글자 · 다크 툴팁 흐림)
const LIGHT: Record<string, string> = {
  '--bg': '#FFFFFF', '--surface': '#FFFFFF', '--surface-2': '#F7F9F9', '--surface-3': '#EFF3F4', '--surface-raised': '#FFFFFF', '--card-line': '#EFF3F4',
  '--field-bg': '#FFFFFF', '--field-placeholder': '#536471',
  '--text': '#0F1419', '--text-2': '#536471', '--text-3': '#536471', '--text-inverse': '#FFFFFF',
  '--border': '#EFF3F4', '--border-strong': '#CFD9DE', '--border-heavy': '#B6BCC8', '--line-soft': '#EFF3F4',
  '--btn-primary-bg': '#1769E8', '--btn-primary-fg': '#FFFFFF', '--btn-primary-hover': '#0D47B8',
  '--btn-secondary-bg': 'TRANSPARENT', '--btn-secondary-fg': '#0F1419',
  '--btn-danger-bg': '#B52D49', '--btn-danger-hover': '#A0394E',
  '--accent': '#1769E8', '--accent-hover': '#0D47B8', '--accent-soft': '#DCE9FF', '--accent-text': '#0D47B8',
  '--danger': '#E4516F', '--danger-text': '#B52D49',
  '--pill-neutral-bg': '#F1F3F6', '--pill-neutral-fg': '#596273', '--pill-neutral-line': '#DCE1E8', '--pill-dark-bg': '#30343B',
  '--ink': '#111827', '--ink-text': '#F3F4F6', '--ink-muted': '#9CA3AF',
  '--r-sm': '6PX', '--r-md': '8PX', '--r-lg': '8PX', '--r-xl': '8PX', '--t-btn': '120MS', '--t-panel': '180MS',
};
const DARK: Record<string, string> = {
  '--bg': '#15202B', '--surface': '#15202B', '--surface-2': '#1E2732', '--surface-3': '#22303C', '--surface-raised': '#15202B', '--card-line': '#38444D', // 11/09 밤 남색: 바탕 하나 · 떠 있는 면 = 카드
  '--field-bg': '#15202B', '--field-placeholder': '#8B98A5',
  '--text': '#F7F9F9', '--text-2': '#8B98A5', '--text-3': '#8B98A5',
  '--border': '#38444D', '--border-strong': '#435260', '--border-heavy': '#5B7083', '--line-soft': '#38444D',
  '--btn-primary-bg': '#1B70EE', '--btn-primary-fg': '#FFFFFF', '--btn-secondary-fg': '#F7F9F9', '--btn-danger-bg': '#B52D49',
  '--accent': '#1B70EE', '--accent-soft': '#1A2D4E', '--accent-text': '#DCE9FF',
  '--danger-soft': '#3F2735', '--danger-text': '#F4C4CE', '--warn-soft': '#423627', '--ok-soft': '#1D3A39', '--info-soft': '#1E394D',
  '--ink': '#272C36', '--ink-text': '#E6E8EE', '--ink-muted': '#9AA3B2',
};

test.describe('11/09 흰 배경 — 11/05 참고 대시보드 값 + 대비 수정', () => {
  test('토큰: 라이트 · 다크 실측표 그대로(11/09 밤 값 · 흐림 #536471 · 위험 버튼 #B52D49 · 주 버튼 파랑)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    expect(await tokens(page, Object.keys(LIGHT))).toEqual(LIGHT);
    await pickTheme(page, 'dark');
    expect(await tokens(page, Object.keys(DARK))).toEqual(DARK);
  });

  test('글꼴 · 바탕 · 본문 줄 높이 · 패널 제목 700 — 글꼴은 저장소 안 파일만(외부 요청 없음)', async ({ page, backend }) => {
    void backend;
    const fonts: string[] = [];
    page.on('request', (r) => r.resourceType() === 'font' && fonts.push(r.url()));
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const b = await css(page, 'body', ['font-family', 'background-color', 'color', 'line-height']);
    expect(b['font-family']).toMatch(/^"Pretendard Variable", Pretendard, Inter, -apple-system, ("system-ui"|BlinkMacSystemFont), "Segoe UI", sans-serif$/); // 11/09 저장소 안 글꼴 먼저. Chromium 은 BlinkMacSystemFont 를 system-ui 로 적는다
    expect(b['background-color']).toBe(rgb('#FFFFFF'));
    expect(b.color).toBe(rgb('#0F1419'));
    expect(b['line-height']).toBe('26.4px'); // 16 × 1.65
    expect(await css(page, '[data-testid="page-title"]', ['font-size', 'letter-spacing', 'color'])).toEqual({ 'font-size': '21px', 'letter-spacing': '-0.42px', color: rgb('#0F1419') }); // 11/09 G43: 화면 제목 21/700(--fs-xl)
    expect(await css(page, '.sg-panel-title', ['font-size', 'font-weight'])).toEqual({ 'font-size': '17.92px', 'font-weight': '700' });
    const origin = new URL(page.url()).origin;
    expect(fonts.filter((u) => new URL(u).origin !== origin), '외부 도메인 글꼴 요청').toEqual([]);
  });

  test('버튼: 주 = 파란 채움 · 보조 = 투명 + #CFD9DE 선 + 본문 글자 · 위험 = #B52D49 · 비활성 — 알약(9999) · 14.4/700 · 높이 33.6(작은 29.6) · 색 전환 120ms · 포커스 2px 파랑 링 offset 2', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await mountButtons(page);
    const P = ['background-color', 'color', 'border-top-color', 'border-top-width', 'border-radius', 'font-size', 'font-weight', 'box-shadow', 'transition-duration', 'transition-timing-function'];
    const primary = await css(page, '#btn-probe [data-k="primary"]', P);
    expect(primary).toMatchObject({ 'background-color': rgb('#1769E8'), color: rgb('#FFFFFF'), 'border-radius': '9999px', 'font-size': '14.4px', 'font-weight': '700', 'box-shadow': 'none' });
    expect(primary['transition-duration']).toMatch(/^0\.12s(, 0\.12s)*$/);
    expect(primary['transition-timing-function']).toBe([EASE_COLOR, EASE_COLOR, EASE_COLOR, EASE_COLOR].join(', '));
    for (const k of ['primary', 'secondary', 'danger']) expect((await page.locator(`#btn-probe [data-k="${k}"]`).boundingBox())!.height, k).toBeCloseTo(33.6, 1);
    expect(await css(page, '#btn-probe [data-k="secondary"]', P)).toMatchObject({ 'background-color': 'rgba(0, 0, 0, 0)', color: rgb('#0F1419'), 'border-top-color': rgb('#CFD9DE'), 'border-top-width': '1px', 'border-radius': '9999px', 'box-shadow': 'none' });
    expect(await css(page, '#btn-probe [data-k="danger"]', P)).toMatchObject({ 'background-color': rgb('#B52D49'), color: rgb('#FFFFFF') }); // #E4516F 위 흰 글자는 3.68:1 — 한 단계 진한 위험색
    for (const k of ['primary-off', 'danger-off'])
      expect(await css(page, `#btn-probe [data-k="${k}"]`, P), k).toMatchObject({ 'background-color': 'rgba(0, 0, 0, 0.12)', color: 'rgba(0, 0, 0, 0.26)' });
    expect(await css(page, '#btn-probe [data-k="secondary-off"]', P)).toMatchObject({ 'background-color': 'rgba(0, 0, 0, 0)', 'border-top-color': 'rgba(0, 0, 0, 0.12)', color: 'rgba(0, 0, 0, 0.26)' });
    // 작은 크기(size=small): 채움 4/10 · 외곽선 3/9 · 글자 14.4 → 높이 29.6. 위험 외곽선 = 위험 글자색(danger-text) + 1px 위험 50% 테두리
    expect(await css(page, '#btn-probe [data-k="sm"]', ['padding-top', 'padding-left', 'font-size'])).toEqual({ 'padding-top': '3px', 'padding-left': '9px', 'font-size': '14.4px' });
    expect(await css(page, '#btn-probe [data-k="sm-primary"]', ['padding-top', 'padding-left'])).toEqual({ 'padding-top': '4px', 'padding-left': '10px' });
    for (const k of ['sm', 'sm-danger', 'sm-primary']) expect((await page.locator(`#btn-probe [data-k="${k}"]`).boundingBox())!.height, k).toBeCloseTo(29.6, 1);
    expect(await css(page, '#btn-probe [data-k="sm-danger"]', ['color', 'border-top-color', 'border-top-width'])).toEqual({ color: rgb('#B52D49'), 'border-top-color': 'rgba(228, 81, 111, 0.5)', 'border-top-width': '1px' });
    // 호버(전환 120ms 를 기다린다)
    await page.locator('#btn-probe [data-k="primary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="primary"]', ['background-color']).then((v) => v['background-color'])).toBe(rgb('#0D47B8'));
    await page.locator('#btn-probe [data-k="secondary"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="secondary"]', ['border-top-color', 'background-color'])).toEqual({ 'border-top-color': rgb('#CFD9DE'), 'background-color': 'rgba(15, 20, 25, 0.1)' });
    await page.locator('#btn-probe [data-k="danger"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="danger"]', ['background-color']).then((v) => v['background-color'])).toBe(rgb('#A0394E'));
    await page.locator('#btn-probe [data-k="sm-danger"]').hover();
    await expect.poll(() => css(page, '#btn-probe [data-k="sm-danger"]', ['border-top-color', 'background-color'])).toEqual({ 'border-top-color': rgb('#E4516F'), 'background-color': 'rgba(228, 81, 111, 0.04)' });
    // 키보드 포커스: 2px 파랑 링 · offset 2
    await page.mouse.move(0, 0);
    await page.locator('#btn-probe [data-k="primary"]').focus();
    await page.keyboard.press('Shift');
    expect(await css(page, '#btn-probe [data-k="primary"]', ['outline-style', 'outline-width', 'outline-color', 'outline-offset'])).toEqual({ 'outline-style': 'solid', 'outline-width': '2px', 'outline-color': rgb('#1769E8'), 'outline-offset': '2px' });
  });

  test('표 · 배지 · 쪽 넘김 · 패널: 머리 42 바탕 없음 12/600 흐림 #536471 · 행 48 · 배지 27 · 「총 N건 · p/P 페이지」 · 패널 반경 8 · 그림자 없음 · hover 파란 선', async ({ page, backend }) => {
    seedInstalls(backend, 37); // 8 + 37 = 45 → 3쪽
    await page.goto('/installs?status=all');
    const T = 'table[data-table="installs"]';
    await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
    expect(await css(page, `${T} thead th`, ['height', 'background-color', 'font-size', 'font-weight', 'color', 'padding-left', 'border-bottom-color'])).toEqual({
      height: '42px', 'background-color': rgb('#FFFFFF'), 'font-size': '12px', 'font-weight': '600', color: rgb('#536471'), 'padding-left': '16px', 'border-bottom-color': rgb('#EFF3F4'),
    });
    const td = await css(page, `${T} tbody td`, ['font-size', 'padding-left', 'padding-top', 'border-bottom-color', 'border-bottom-width']);
    expect(td).toEqual({ 'font-size': '13.5px', 'padding-left': '16px', 'padding-top': '8px', 'border-bottom-color': rgb('#EFF3F4'), 'border-bottom-width': '1px' });
    expect(Math.round((await page.locator(`${T} tbody tr`).first().boundingBox())!.height)).toBe(48);
    // 줄무늬 없음 — 홀짝 행 바탕이 같다, 행 hover #F7F9F9(11/09 밤)
    const zebra = await page.locator(`${T} tbody tr`).evaluateAll((rows) => rows.slice(0, 2).map((r) => getComputedStyle(r).backgroundColor));
    expect(zebra[0]).toBe(zebra[1]);
    const row = page.locator(`${T} tbody tr`).nth(1);
    await row.hover();
    await expect.poll(() => row.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#F7F9F9'));
    // 상태 배지 — 크기 · 톤 그대로, 11/09 SPEC: 굵기 700 · 테두리 = 글자색(11/02 「태그 글자 · 테두리를 진하게」)
    const pill = page.locator(`${T} tbody .sg-pill-ok`).first();
    await expect(pill).toBeVisible();
    expect(await pill.evaluate((e) => { const c = getComputedStyle(e); return [c.height, c.fontSize, c.fontWeight, c.borderTopWidth, c.borderTopColor, c.backgroundColor, c.color, c.minWidth]; })).toEqual([
      '27px', '12.5px', '700', '1px', rgb('#137653'), rgb('#EAF7F1'), rgb('#137653'), '62px',
    ]);
    // 격리 배지 = 위험 톤(11/05 결정)
    const iso = page.locator(`${T} tbody [data-status="isolated"]`).first();
    await expect(iso).toBeVisible();
    expect(await iso.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color, getComputedStyle(e).borderTopColor])).toEqual([rgb('#FDECEF'), rgb('#B52D49'), rgb('#B52D49')]);
    // 쪽 넘김
    const foot = page.locator('[data-table-foot="installs"]');
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 1/3 페이지');
    expect(await foot.locator('[data-part="page-size"] option').allTextContents()).toEqual(['20개씩', '50개씩', '100개씩']);
    expect(await css(page, '[data-table-foot="installs"] [data-part="range"]', ['font-size', 'color'])).toEqual({ 'font-size': '14px', color: rgb('#536471') });
    expect(await css(page, '[data-table-foot="installs"] [data-part="page-size"]', ['height', 'border-radius', 'font-size', 'border-top-color', 'background-color'])).toEqual({ height: '40px', 'border-radius': '8px', 'font-size': '14px', 'border-top-color': rgb('#CFD9DE'), 'background-color': rgb('#FFFFFF') });
    for (const k of ['first', 'prev', 'next', 'last']) await expect(foot.locator(`[data-page="${k}"]`)).toBeVisible();
    await expect(foot.locator('[data-page="first"]')).toBeDisabled();
    const cur = await css(page, '[data-table-foot="installs"] .tk-page.on', ['width', 'height', 'border-radius', 'background-color', 'color']);
    expect(cur).toEqual({ width: '26px', height: '26px', 'border-radius': '13px', 'background-color': rgb('#1769E8'), color: rgb('#FFFFFF') });
    expect(await css(page, '[data-table-foot="installs"]', ['padding-top', 'padding-left'])).toEqual({ 'padding-top': '16px', 'padding-left': '16px' });
    await foot.locator('[data-page="last"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 3/3 페이지');
    await expect(foot.locator('[data-page="last"]')).toBeDisabled();
    // 패널(표를 감싼 카드): 반경 8 · 그림자 없음 · 1px 선 · 머리 56 · 좌우 20 · 머리 선 = 구분 선 #EFF3F4(11/09 밤) · 제목 17.92/700
    const panel = page.locator('.sg-panel').filter({ has: page.locator(T) }).first();
    await page.mouse.move(0, 0);
    await expect.poll(() => panel.evaluate((e) => { const c = getComputedStyle(e); return [c.borderRadius, c.boxShadow, c.borderTopColor, c.borderTopWidth, c.backgroundColor]; })).toEqual(['8px', 'none', rgb('#EFF3F4'), '1px', rgb('#FFFFFF')]);
    expect(await panel.evaluate((e) => [getComputedStyle(e).transitionDuration, getComputedStyle(e).transitionTimingFunction])).toEqual(['0.12s, 0.18s', `${EASE_COLOR}, ${EASE_MOVE}`]);
    const head = panel.locator('.sg-panel-head');
    expect(await head.evaluate((e) => [getComputedStyle(e).minHeight, getComputedStyle(e).paddingLeft, getComputedStyle(e).borderBottomColor])).toEqual(['56px', '20px', rgb('#EFF3F4')]);
    expect(await panel.locator('.sg-panel-title').evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight])).toEqual(['17.92px', '700']);
    await panel.hover();
    await expect.poll(() => panel.evaluate((e) => [getComputedStyle(e).borderTopColor, getComputedStyle(e).boxShadow])).toEqual(['rgba(23, 105, 232, 0.24)', 'none']); // 11/09 밤: hover 도 그림자 없음(선만)
  });

  test('빈 상태 · 카드: 가운데 흐림 14px · 카드 반경 8 · 1px 선 · 그림자 없음(11/09 밤 평평), hover 카드도 그림자 없음', async ({ page, backend }) => {
    void backend;
    await page.route(/\/api\/installs(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));
    await page.goto('/installs');
    const empty = page.locator('.sg-empty').first();
    await expect(empty).toBeVisible();
    expect(await empty.evaluate((el) => { const c = getComputedStyle(el); return [c.textAlign, c.fontSize, c.color, el.getBoundingClientRect().height >= 180]; })).toEqual(['center', '14px', rgb('#536471'), true]);
    await page.goto('/settings');
    await expect(page.locator('[data-part="settings-tabs"]')).toBeVisible();
    expect(await css(page, '.sg-card:not(.sg-panel)', ['border-radius', 'border-top-width', 'border-top-color', 'box-shadow', 'background-color'])).toEqual({
      'border-radius': '8px', 'border-top-width': '1px', 'border-top-color': rgb('#EFF3F4'), 'box-shadow': 'none', 'background-color': rgb('#FFFFFF'),
    });
    // 들리는 카드(sg-card-hover) 견본: hover 에 5px 위로(움직임 그대로) · 그림자 없음(11/09 밤), 들림 180ms ease-move · 선 색 120ms ease-color
    await page.evaluate(() => {
      const d = document.createElement('div');
      d.id = 'card-probe';
      d.className = 'sg-card sg-card-hover';
      d.style.cssText = 'width:120px;height:60px';
      document.querySelector('main')!.prepend(d);
    });
    const probe = page.locator('#card-probe');
    expect(await probe.evaluate((e) => [getComputedStyle(e).transitionDuration, getComputedStyle(e).transitionTimingFunction])).toEqual(['0.18s, 0.18s, 0.12s', `${EASE_MOVE}, ${EASE_MOVE}, ${EASE_COLOR}`]);
    await probe.hover();
    await expect.poll(() => probe.evaluate((e) => getComputedStyle(e).transform)).toBe('matrix(1, 0, 0, 1, 0, -5)');
    expect(await probe.evaluate((e) => getComputedStyle(e).boxShadow)).toBe('none');
  });

  test('입력창 · 떠 있는 면: 입력 반경 8 · 흰 바탕 · 안내 글자 흐림 #536471 · 계정 메뉴 · 대화상자 = 흰 면 + 옅은 그림자 · 대화상자 닫기 = 파란 주 버튼', async ({ page, backend }) => {
    void backend;
    await stubScans(page);
    await page.goto('/scans');
    const name = page.locator('[data-part="scan-form"] [data-field="name"]');
    await expect(name).toBeVisible();
    expect(await name.evaluate((e) => { const c = getComputedStyle(e); return [c.borderRadius, c.backgroundColor, getComputedStyle(e, '::placeholder').color]; })).toEqual(['8px', rgb('#FFFFFF'), rgb('#536471')]);
    const form = await css(page, '[data-part="scan-form"]', ['border-radius', 'border-top-color', 'box-shadow', 'background-color']);
    expect({ ...form, 'box-shadow': visible(form['box-shadow']) }).toEqual({ 'border-radius': '8px', 'border-top-color': rgb('#EFF3F4'), 'box-shadow': SH_FLAT, 'background-color': rgb('#FFFFFF') });
    await page.locator('[data-part="account"]').click();
    const menu = page.locator('[data-part="account-menu"]');
    await expect(menu).toBeVisible();
    expect(await menu.evaluate((e) => { const c = getComputedStyle(e); return [c.backgroundColor, c.borderRadius, c.boxShadow]; }).then(([b, r, sh]) => [b, r, visible(sh)])).toEqual([rgb('#FFFFFF'), '8px', SH_FLOAT]);
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: '사용 안내 (?)' }).click();
    const dlg = page.locator('dialog[data-part="help"]');
    await expect(dlg).toBeVisible();
    expect(await dlg.evaluate((e) => { const c = getComputedStyle(e); return [c.backgroundColor, c.borderRadius, c.boxShadow]; }).then(([b, r, sh]) => [b, r, visible(sh)])).toEqual([rgb('#FFFFFF'), '8px', SH_FLOAT]);
    expect(await css(page, 'dialog[data-part="help"] button:text("닫기")', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#1769E8'), color: rgb('#FFFFFF') });
  });

  test('로그인: 흰 바탕(그라데이션 없음) · 카드 반경 12 · 입력 반경 6(11/05 값) · 카드 그림자 없음(11/09 밤) · 주 버튼 파랑 · 입력창 흰 바탕', async ({ page, backend, allowConsole }) => {
    allowConsole(/^Failed to load resource: the server responded with a status of 401 /);
    backend.auth.loggedOut();
    await page.goto('/');
    const auth = page.locator('[data-part="auth"]');
    await expect(auth).toHaveAttribute('data-step', 'login');
    expect(await auth.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).backgroundImage])).toEqual([rgb('#FFFFFF'), 'none']);
    const card = await css(page, '[data-part="auth"] > div', ['border-radius', 'background-color', 'border-top-color', 'box-shadow']);
    expect({ ...card, 'box-shadow': visible(card['box-shadow']) }).toEqual({ 'border-radius': '12px', 'background-color': rgb('#FFFFFF'), 'border-top-color': rgb('#EFF3F4'), 'box-shadow': SH_FLAT });
    const go = auth.getByRole('button', { name: '로그인' });
    expect(await go.evaluate((e) => { const c = getComputedStyle(e); return [c.backgroundColor, c.color, parseFloat(c.borderRadius) >= e.getBoundingClientRect().height / 2, Math.round(e.getBoundingClientRect().height)]; })).toEqual([rgb('#1769E8'), rgb('#FFFFFF'), true, 36] /* 11/10: 로그인 주 버튼도 알약 */);
    expect(await auth.getByLabel('아이디').evaluate((e) => [getComputedStyle(e).borderRadius, getComputedStyle(e).backgroundColor])).toEqual(['6px', rgb('#FFFFFF')]);
  });

  test('다크: 바탕 · 카드 · 표 머리 · 행 호버 · 주/보조/비활성 버튼 · 입력창 · 대화상자 = 11/09 밤 남색 값, 파랑 글자는 밝은 짝 · 배지는 라이트와 같은 톤', async ({ page, backend }) => {
    seedInstalls(backend, 5);
    await page.goto('/installs?status=all');
    await expect(page.locator('table[data-table="installs"] tbody tr').first()).toBeVisible();
    await pickTheme(page, 'dark');
    expect((await css(page, 'body', ['background-color']))['background-color']).toBe(rgb('#15202B'));
    await page.mouse.move(0, 0); // 테마 메뉴가 닫힌 자리 아래 패널이 hover 되지 않게
    await expect.poll(() => css(page, '.sg-panel', ['background-color', 'border-top-color', 'box-shadow'])).toEqual({ 'background-color': rgb('#15202B'), 'border-top-color': rgb('#38444D'), 'box-shadow': 'none' });
    expect(await css(page, 'table[data-table="installs"] thead th', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#15202B'), color: rgb('#8B98A5') });
    const row = page.locator('table[data-table="installs"] tbody tr').nth(1);
    await row.hover();
    await expect.poll(() => row.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#1E2732'));
    await mountButtons(page);
    expect(await css(page, '#btn-probe [data-k="primary"]', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#1B70EE'), color: rgb('#FFFFFF') }); // 11/09 밤: 흰 글자 4.5:1 안에서 한 단계 밝게
    // 보조 버튼(11/09 밤): 투명 + #536471 선 + 본문 글자색
    expect(await css(page, '#btn-probe [data-k="secondary"]', ['background-color', 'color', 'border-top-color'])).toEqual({ 'background-color': 'rgba(0, 0, 0, 0)', color: rgb('#F7F9F9'), 'border-top-color': rgb('#536471') });
    expect(await css(page, '#btn-probe [data-k="danger"]', ['background-color', 'color'])).toEqual({ 'background-color': rgb('#B52D49'), color: rgb('#FFFFFF') });
    expect(await css(page, '#btn-probe [data-k="sm-danger"]', ['color'])).toEqual({ color: rgb('#F4C4CE') });
    expect(await css(page, '#btn-probe [data-k="primary-off"]', ['background-color', 'color'])).toEqual({ 'background-color': 'rgba(255, 255, 255, 0.12)', color: 'rgba(255, 255, 255, 0.3)' });
    const pill = page.locator('table[data-table="installs"] tbody .sg-pill-ok').first();
    await expect(pill).toBeVisible();
    expect(await pill.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color, getComputedStyle(e).borderTopColor, getComputedStyle(e).fontWeight])).toEqual([rgb('#EAF7F1'), rgb('#137653'), rgb('#137653'), '700']);
    await page.goto('/events');
    const search = page.getByPlaceholder('컨테이너 이름');
    await expect(search).toBeVisible();
    expect(await search.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).borderRadius, getComputedStyle(e, '::placeholder').color])).toEqual([rgb('#15202B'), '8px', rgb('#8B98A5')]);
    await page.getByRole('button', { name: '사용 안내 (?)' }).click();
    const dlg = page.locator('dialog[data-part="help"]');
    await expect(dlg).toBeVisible();
    expect(await dlg.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(rgb('#15202B'));
    await page.keyboard.press('Escape');
    // 강조 파랑 글자는 다크 카드 위 3.34:1 — 글자에만 밝은 짝(--accent-text #DCE9FF). 채움(현재 쪽 · 선택 칩)은 그대로 파랑
    await page.goto('/');
    const more = page.locator('.sg-panel a[data-more]').first();
    await expect(more).toBeVisible();
    expect(await more.evaluate((e) => getComputedStyle(e).color)).toBe(rgb('#DCE9FF'));
  });

  test('어두운 배지 예외(11/09 사용자): 「설치 전 거부」는 테두리 = 바탕색 — 흰 글자색 테두리 없음(라이트 · 다크)', async ({ page, backend }) => {
    backend.installs.unshift({
      id: 'ins-0099',
      manager: 'pip',
      packages: ['reqeusts'],
      container: '',
      image: 'python:3.12-slim',
      startedAt: new Date().toISOString(),
      status: 'refused',
      refusedBy: { list: 'packages', value: 'pip:colourama' },
      caseId: null,
    });
    await page.goto('/installs?status=refused');
    const pill = page.locator('tr[data-install="ins-0099"] [data-status="refused"]');
    await expect(pill).toHaveText('설치 전 거부');
    for (const theme of ['light', 'dark'] as const) {
      if (theme === 'dark') await pickTheme(page, 'dark');
      await expect
        .poll(() => pill.evaluate((e) => { const c = getComputedStyle(e); return [c.backgroundColor, c.color, c.borderTopColor, c.borderTopWidth]; }), { message: theme })
        .toEqual([rgb('#30343B'), rgb('#FFFFFF'), rgb('#30343B'), '1px']);
    }
  });

  test('대비: 글자 3단 · 안내 글자 · 버튼 글자 · 위험 글자 · 링크 · 반전 툴팁이 바탕 위에서 4.5:1 이상(라이트 · 다크)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    for (const theme of ['light', 'dark'] as const) {
      if (theme === 'dark') await pickTheme(page, 'dark');
      const t = await tokens(page, ['--text', '--text-2', '--text-3', '--field-placeholder', '--bg', '--surface', '--surface-2', '--surface-3', '--surface-raised', '--field-bg',
        '--btn-primary-bg', '--btn-primary-fg', '--btn-primary-hover', '--btn-secondary-fg', '--btn-danger-bg', '--btn-danger-hover', '--text-inverse', '--accent', '--accent-text', '--accent-soft',
        '--danger-text', '--danger-soft', '--ink', '--ink-2', '--ink-text', '--ink-muted',
        ...['ok', 'warn', 'neutral', 'danger', 'info', 'accent', 'dark'].flatMap((k) => [`--pill-${k}-fg`, `--pill-${k}-bg`])]);
      for (const fg of ['--text', '--text-2', '--text-3', '--field-placeholder'])
        for (const bg of ['--bg', '--surface', '--surface-2', '--surface-3', '--surface-raised', '--field-bg'])
          expect(contrast(t[fg], t[bg]), `${theme} ${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      const pairs: [string, string][] = [
        ['--btn-primary-fg', '--btn-primary-bg'], ['--btn-primary-fg', '--btn-primary-hover'], ['--text-inverse', '--btn-danger-bg'], ['--text-inverse', '--btn-danger-hover'], ['--text-inverse', '--accent'],
        // 보조 · 위험 외곽선 버튼은 바탕이 투명 — 카드 · 페이지 · 떠 있는 면 위 글자
        ['--btn-secondary-fg', '--surface'], ['--btn-secondary-fg', '--bg'], ['--btn-secondary-fg', '--surface-raised'],
        ['--danger-text', '--surface'], ['--danger-text', '--bg'], ['--danger-text', '--danger-soft'], ['--accent-text', '--accent-soft'], ['--accent-text', '--surface'],
        ['--ink-text', '--ink'], ['--ink-muted', '--ink'], ['--ink-muted', '--ink-2'],
        // 상태 배지: 글자 = 테두리(currentColor) — 배지 바탕 위 4.5:1
        ...['ok', 'warn', 'neutral', 'danger', 'info', 'accent', 'dark'].map((k): [string, string] => [`--pill-${k}-fg`, `--pill-${k}-bg`]),
      ];
      for (const [fg, bg] of pairs) expect(contrast(t[fg], t[bg]), `${theme} ${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  test('쓰지 않는 것: 11/09 미색 회색 단계 값 · 대비 미달 흐림 #7A8090 · 0.5px 선', async ({ page, backend }) => {
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
        warm: all.match(/(#|%23)(FAF9F5|F5F4ED|F0EEE6|E8E6DC|D1CFC5|B0AEA5|141413|30302E|5E5D59|1F1E1D|1A1918|262624|9C9A92|87867F|4D4C48|3D3D3A)\b/gi) ?? [],
        lowGray: all.match(/(#|%23)7A8090\b/gi) ?? [],
        halfPx: all.match(/\b0?\.5px solid/g) ?? [],
      };
    });
    expect(found).toEqual({ warm: [], lowGray: [], halfPx: [] });
  });

  test('화면 1440×900 밝은 · 어두운 — 대시보드 · 설치 검사 · 정책', async ({ page, backend }) => {
    void backend;
    test.setTimeout(60_000);
    const views: [string, string, (p: Page) => Promise<void>][] = [
      ['dashboard', '/', (p) => expect(p.getByTestId('pending')).toBeVisible()],
      ['installs', '/installs?status=all', (p) => expect(p.locator('table[data-table="installs"] tbody tr').first()).toBeVisible()],
      ['policies', '/policies', (p) => expect(p.getByTestId('rules')).toBeVisible()],
    ];
    for (const theme of ['light', 'dark'] as const) {
      for (const [name, url, ready] of views) {
        await page.goto(url);
        await ready(page);
        if (theme === 'dark' && name === 'dashboard') await pickTheme(page, 'dark');
        await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur()); // 테마 메뉴를 닫은 뒤 계정 단추의 포커스 링이 찍히지 않게
        await page.mouse.move(0, 0);
        await settled(page);
        expect(await page.evaluate(() => document.documentElement.dataset.theme ?? 'light')).toBe(theme);
        await page.screenshot({ path: `${SHOTS}/theme-white-1109/${name}-${theme}.png` });
      }
    }
  });
});
