import type { Locator, Page } from '@playwright/test';
import { expect, test } from './fixtures';

// 11/09 규격(SPEC-1109 「1. 토큰」) — 참고 제품 답변의 권고대로 흩어진 값을 토큰으로 묶는다(값 · 동작만, 이름 · 문구는 옮기지 않음).
// 움직임 3단 · 곡선 3종 · 포커스 링 하나 · 글자 5단 · 스켈레톤 반짝임 끝 색 · 저장소 안 글꼴(Pretendard Variable 한글 서브셋, SIL OFL 1.1) · 동작 줄이기

const raw = (page: Page, names: string[]) =>
  page.evaluate((ns) => Object.fromEntries(ns.map((n) => [n, getComputedStyle(document.documentElement).getPropertyValue(n).trim()])), names);
const cs = (loc: Locator, props: string[]) =>
  loc.evaluate((e, ps) => {
    const c = getComputedStyle(e);
    return Object.fromEntries(ps.map((p) => [p, c.getPropertyValue(p)]));
  }, props);
async function pickTheme(page: Page, t: 'light' | 'dark') {
  const btn = page.locator('[data-part="account"]');
  if ((await btn.getAttribute('aria-expanded')) !== 'true') await btn.click();
  await page.locator(`[data-part="account-menu"] [data-theme-pick="${t}"]`).click();
  await page.keyboard.press('Escape');
}
// rgb(...) → 상대 휘도
const lumRgb = (s: string) => {
  const [r, g, b] = s.match(/\d+(\.\d+)?/g)!.slice(0, 3).map(Number).map((v) => {
    const x = v / 255;
    return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a: string, b: string) => {
  const [x, y] = [lumRgb(a), lumRgb(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};
// 본문에 견본을 붙인다(화면마다 부품이 달라 클래스 값만 본다)
async function mountProbes(page: Page) {
  await page.evaluate(() => {
    const box = document.createElement('div');
    box.id = 'tok-probe';
    box.innerHTML = '<button class="sg-btn sg-btn-primary" data-k="btn">확인</button><div class="sg-skeleton" data-k="skel" style="width:200px;height:14px"></div><div class="tk-busy" data-k="busy"><i></i></div>';
    document.querySelector('main')!.prepend(box);
  });
}
const RING = { 'outline-style': 'solid', 'outline-width': '2px', 'outline-color': 'rgb(23, 105, 232)', 'outline-offset': '2px' };
const RING_P = Object.keys(RING);

test.describe('11/09 규격 토큰', () => {
  test('토큰 값: 움직임 3단 · 곡선 3종 · 포커스 링 · 글자 5단 · 스켈레톤 · 글꼴', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    expect(await raw(page, ['--dur-fast', '--dur-base', '--dur-slow', '--ease-enter', '--ease-move', '--ease-color', '--focus-ring', '--focus-ring-offset', '--fs-xs', '--fs-sm', '--fs-md', '--fs-lg', '--fs-xl'])).toEqual({
      '--dur-fast': '120ms', '--dur-base': '180ms', '--dur-slow': '450ms',
      '--ease-enter': 'cubic-bezier(.16, 1, .3, 1)', '--ease-move': 'cubic-bezier(.2, 0, 0, 1)', '--ease-color': 'cubic-bezier(.35, 0, .35, 1)',
      '--focus-ring': '2px solid #1769E8', '--focus-ring-offset': '2px',
      '--fs-xs': '12px', '--fs-sm': '13.5px', '--fs-md': '14px', '--fs-lg': '16px', '--fs-xl': '21px',
    });
    // 옛 이름은 새 토큰의 별칭(시연 · 연동 · 로그인 화면이 쓴다)
    expect(await raw(page, ['--t-btn', '--ease-btn', '--t-panel', '--ease-panel'])).toEqual({ '--t-btn': '120ms', '--ease-btn': 'cubic-bezier(.35, 0, .35, 1)', '--t-panel': '180ms', '--ease-panel': 'cubic-bezier(.35, 0, .35, 1)' });
    expect((await raw(page, ['--font']))['--font']).toBe(`'Pretendard Variable', Pretendard, Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`);
  });

  test('움직임 토큰을 쓴다: 버튼 · 패널 = 색 전환(빠름) · 들리는 카드 = 자리 이동(보통) · 시트 · 화면 = 들어옴(보통)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await mountProbes(page);
    const COLOR = 'cubic-bezier(0.35, 0, 0.35, 1)';
    const MOVE = 'cubic-bezier(0.2, 0, 0, 1)';
    const ENTER = 'cubic-bezier(0.16, 1, 0.3, 1)';
    expect(await cs(page.locator('#tok-probe [data-k="btn"]'), ['transition-duration', 'transition-timing-function'])).toEqual({ 'transition-duration': '0.12s, 0.12s, 0.12s, 0.12s', 'transition-timing-function': [COLOR, COLOR, COLOR, COLOR].join(', ') });
    expect(await cs(page.locator('.sg-panel').first(), ['transition-duration', 'transition-timing-function'])).toEqual({ 'transition-duration': '0.12s, 0.18s', 'transition-timing-function': `${COLOR}, ${MOVE}` });
    await page.evaluate(() => {
      const d = document.createElement('div');
      d.id = 'lift-probe';
      d.className = 'sg-card sg-card-hover';
      document.querySelector('main')!.prepend(d);
    });
    expect(await cs(page.locator('#lift-probe'), ['transition-duration', 'transition-timing-function'])).toEqual({ 'transition-duration': '0.18s, 0.18s, 0.12s', 'transition-timing-function': `${MOVE}, ${MOVE}, ${COLOR}` });
    expect(await cs(page.locator('main [data-part="screen"]').first(), ['animation-name', 'animation-duration', 'animation-timing-function'])).toEqual({ 'animation-name': 'sg-enter', 'animation-duration': '0.18s', 'animation-timing-function': ENTER });
    await page.goto('/installs?id=ins-0012');
    const sheet = page.locator('.sg-sheet-layer > .sg-sheet');
    await expect(sheet).toBeVisible();
    expect(await cs(sheet, ['animation-name', 'animation-duration', 'animation-timing-function'])).toEqual({ 'animation-name': 'sg-slide-in', 'animation-duration': '0.18s', 'animation-timing-function': ENTER });
    expect(await cs(page.locator('.sg-sheet-layer'), ['animation-name', 'animation-duration'])).toEqual({ 'animation-name': 'sg-scrim-in', 'animation-duration': '0.12s' });
  });

  test('포커스 링 하나: 버튼 · 입력(focus:outline-none 이 있어도) · 링크 = 2px 파랑 · 바깥 2px, 표 행은 같은 링을 안쪽에', async ({ page, backend }) => {
    void backend;
    await page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));
    await page.goto('/scans');
    await expect(page.locator('[data-part="scan-form"] [data-field="name"]')).toBeVisible();
    await mountProbes(page);
    // 화면 쪽 transition-colors 는 outline-color 도 옮긴다 — 끝난 값을 기다린다
    const ring = async (loc: Locator, want: Record<string, string>, name: string) => {
      await page.keyboard.press('Shift'); // 마지막 입력을 키보드로 — 프로그램 포커스도 :focus-visible
      await loc.focus();
      await expect.poll(() => cs(loc, RING_P), { message: name }).toEqual(want);
    };
    await ring(page.locator('#tok-probe [data-k="btn"]'), RING, '버튼');
    await ring(page.locator('[data-part="scan-form"] [data-field="name"]'), RING, '입력');
    await ring(page.locator('[data-part="scan-form"] [data-field="manager"]'), RING, '선택 상자');
    await ring(page.locator('[data-part="sidebar"] nav a[href="/installs"]'), RING, '링크');
    await page.goto('/installs?status=all');
    const row = page.locator('table[data-table="installs"] tbody tr').first();
    await expect(row).toBeVisible();
    await ring(row, { ...RING, 'outline-offset': '-2px' }, '표 행');
  });

  test('글자 단계: 표 본문 · 입력 13.5 · 표 머리 12', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?status=all');
    const T = 'table[data-table="installs"]';
    await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
    expect(await cs(page.locator(`${T} tbody td`).first(), ['font-size'])).toEqual({ 'font-size': '13.5px' });
    expect(await cs(page.locator(`${T} thead th`).first(), ['font-size'])).toEqual({ 'font-size': '12px' });
    await page.goto('/events');
    const search = page.getByPlaceholder('컨테이너 이름');
    await expect(search).toBeVisible();
    expect(await cs(search, ['font-size'])).toEqual({ 'font-size': '13.5px' }); // 화면 쪽 text-sm(14) 이 있어도
  });

  test('스켈레톤 반짝임: 끝 색이 바탕보다 한 단계 진하다(라이트 · 다크, 같은 색 아님)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const colors = async () => {
      await mountProbes(page);
      const img = (await cs(page.locator('#tok-probe [data-k="skel"]'), ['background-image']))['background-image'];
      await page.evaluate(() => document.getElementById('tok-probe')!.remove());
      const c = img.match(/rgba?\([^)]+\)/g)!;
      const t = await page.evaluate(() => {
        const probe = (v: string) => {
          const e = document.createElement('i');
          e.style.color = `var(${v})`;
          document.body.append(e);
          const out = getComputedStyle(e).color;
          e.remove();
          return out;
        };
        return { s2: probe('--surface-2'), s3: probe('--surface-3') };
      });
      return { base: c[0], shine: c[1], ...t };
    };
    const light = await colors();
    expect(light.base).toBe(light.s2);
    expect(light.shine).not.toBe(light.base);
    expect(light.shine).not.toBe(light.s3);
    expect(lumRgb(light.shine), '라이트: 3단 바탕보다 진한 회색').toBeLessThan(lumRgb(light.s3));
    await pickTheme(page, 'dark');
    const dark = await colors();
    expect(dark.base).toBe(dark.s2);
    expect(dark.shine).not.toBe(dark.base);
    expect(dark.shine).not.toBe(dark.s3);
    expect(lumRgb(dark.shine), '다크: 3단 바탕보다 한 단계 밝은(진한) 면').toBeGreaterThan(lumRgb(dark.s3));
    test.info().annotations.push({ type: '반짝임 대비', description: `라이트 ${light.base} → ${light.shine} ${ratio(light.base, light.shine).toFixed(2)}:1 · 다크 ${dark.base} → ${dark.shine} ${ratio(dark.base, dark.shine).toFixed(2)}:1` });
  });

  test('글꼴: 저장소 안 Pretendard Variable 을 불러 쓴다 — 외부 도메인 요청 0', async ({ page, backend }) => {
    void backend;
    const fonts: string[] = [];
    page.on('request', (r) => r.resourceType() === 'font' && fonts.push(r.url()));
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const f = await page.evaluate(async () => {
      await document.fonts.ready;
      await document.fonts.load('13.5px "Pretendard Variable"', '가');
      const faces = [...document.fonts].filter((x) => x.family.replace(/["']/g, '') === 'Pretendard Variable');
      return { check: document.fonts.check('13.5px "Pretendard Variable"', '가'), faces: faces.map((x) => [x.status, x.weight, x.style, x.display]), body: getComputedStyle(document.body).fontFamily };
    });
    expect(f.faces).toEqual([['loaded', '45 920', 'normal', 'swap']]);
    expect(f.check).toBe(true);
    expect(f.body).toMatch(/^"Pretendard Variable", Pretendard, Inter, -apple-system, /);
    const origin = new URL(page.url()).origin;
    expect(fonts.length, '글꼴 요청').toBeGreaterThan(0);
    expect(fonts.filter((u) => new URL(u).origin !== origin), '외부 도메인 글꼴 요청').toEqual([]);
    expect(fonts.every((u) => /PretendardVariable\.subset[^/]*\.woff2/.test(u)), fonts.join(' ')).toBe(true);
  });

  test('동작 줄이기: 진행 띠 · 반짝임이 멈추고 스켈레톤은 바탕 한 색', async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await mountProbes(page);
    const skel = await cs(page.locator('#tok-probe [data-k="skel"]'), ['animation-name', 'background-image', 'background-color']);
    const s2 = await page.evaluate(() => {
      const e = document.createElement('i');
      e.style.color = 'var(--surface-2)';
      document.body.append(e);
      const out = getComputedStyle(e).color;
      e.remove();
      return out;
    });
    expect(skel).toEqual({ 'animation-name': 'none', 'background-image': 'none', 'background-color': s2 });
    expect(await cs(page.locator('#tok-probe [data-k="busy"] > i'), ['animation-name'])).toEqual({ 'animation-name': 'none' });
  });
});
