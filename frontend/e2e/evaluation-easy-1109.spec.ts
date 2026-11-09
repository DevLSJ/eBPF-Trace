import { mkdirSync, readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// 11/09 사용자 결정 — 「평가 = 요점 3줄 + 쉬운 이름 + 용어 툴팁 + 자세한 표 접기」(평가 탭은 용어 · 글씨가 많아 읽기 어렵다).
// 데이터는 evaluation-1104 와 같은 실측 사본(e2e/evaluation/*.json). 요점 숫자는 API 값에서 계산 — 응답을 바꾸면 따라 바뀌어야 한다.

type Json = Record<string, unknown>;
type Any = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as Json;
const REAL = { static: load('static'), runtime: load('runtime'), model: load('model'), modelAll: load('model-all') };
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

const W = '[data-part="evaluation"]';
const DIR = `${SHOTS}/evaluation-1109`;
mkdirSync(DIR, { recursive: true });

async function open(page: Page, body: unknown = REAL) {
  await page.route(/\/api\/evaluation$/, (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(body) }));
  await page.goto('/evaluation');
  await expect(page.locator(`${W}[data-state="ready"]`)).toBeVisible();
}
const points = (page: Page) =>
  page.locator('[data-part="key-points"] > li').evaluateAll((els) =>
    els.map((e) => [(e as HTMLElement).dataset.point, e.querySelector('[data-num]')?.textContent, e.querySelector('[data-label]')?.textContent, e.querySelector('[data-basis]')?.textContent?.replace(/\u00a0/g, ' ')]),
  );
const tok = (page: Page, v: string, prop: 'color' | 'backgroundColor' = 'color') =>
  page.evaluate(
    ([name, p]) => {
      const el = document.createElement('i');
      el.style[p as 'color'] = `var(${name})`;
      document.body.append(el);
      const c = getComputedStyle(el)[p as 'color'];
      el.remove();
      return c;
    },
    [v, prop] as const,
  );
const fold = (page: Page, part: string) => page.locator(`[data-part="${part}"] [data-action="toggle-detail"]`).first();
// 화면 전체(몸통 스크롤 칸까지) 한 장 — 창 높이를 내용만큼 늘린다
async function shot(page: Page, name: string, full = true) {
  const vp = page.viewportSize()!;
  if (full) {
    const need = await page.evaluate(() => {
      const b = document.querySelector('[data-part="eval-body"]') as HTMLElement | null;
      const root = document.querySelector('[data-part="evaluation"]') as HTMLElement;
      const bottom = b && getComputedStyle(b).overflowY !== 'visible' ? b.getBoundingClientRect().top + b.scrollHeight : root.getBoundingClientRect().top + root.scrollHeight;
      return Math.ceil(bottom + 32);
    });
    if (need > vp.height) await page.setViewportSize({ width: vp.width, height: need });
  }
  await page.waitForTimeout(250);
  await page.screenshot({ path: `${DIR}/${name}.png` });
  if (full) await page.setViewportSize(vp);
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
// 눈에 보이는 글(용어 단추 · 접힌 칸 · 툴팁 밖)에 남으면 안 되는 원래 용어
const HARD = ['정밀도', '재현율', '혼동 행렬', '오탐', 'F1', 'p50', 'p95', '보정', 'dryRun', 'kill 호출'];

test.describe('평가 쉬운 화면(11/09)', () => {
  test('1 요점 3줄: 머리 맨 위 · 숫자 먼저 · 실측값 그대로', async ({ page, backend }) => {
    void backend;
    await open(page);
    const st = REAL.static as Any;
    const c = st.confusion;
    expect(await points(page)).toEqual([
      ['static-detection', pct(st.metrics.detectionRate), '정적 악성 탐지율', `실제 악성 패키지 ${c.tp + c.fn}개 중 ${c.tp}개 탐지됨`],
      ['false-alarm', pct(st.metrics.falsePositiveRate), '정상 패키지 오판율', `정상 패키지 ${c.fp + c.tn}개 중 ${c.fp}개 오판 · 정상 설치 50건 중 위반 0건`],
      ['runtime', '100.0%', '런타임 공격 탐지율', '공격 30회 모두 탐지 · 20회 격리 · 격리까지 중간값 296.9 ms'],
    ]);
    // 숫자 먼저(같은 줄 왼쪽) · 머리 안 · 지표 6칸 위
    const order = await page.locator('[data-part="key-points"] > li').first().evaluate((li) => [...li.children].map((e) => Object.keys((e as HTMLElement).dataset)[0]));
    expect(order.slice(0, 2)).toEqual(['num', 'label']);
    await expect(page.locator('[data-part="eval-head"] [data-part="key-points"]')).toBeVisible();
    const [kp, kpis] = [await page.locator('[data-part="key-points"]').boundingBox(), await page.locator('[data-part="kpis"]').boundingBox()];
    expect(kp!.y + kp!.height).toBeLessThanOrEqual(kpis!.y);
    // 예전 한 줄 결론은 요점으로 바뀌었다
    await expect(page.locator('[data-part="conclusion"]')).toHaveCount(0);
    // 숫자는 기본 글자색(빨강은 위험에만)
    expect(await page.locator('[data-part="key-points"] [data-num]').first().evaluate((e) => getComputedStyle(e).color)).toBe(await tok(page, '--text'));
    await noPageOverflow(page);
  });

  test('2 요점 숫자는 응답에서 계산 — 값을 바꾸면 따라 바뀜 · 없는 쪽은 「결과 없음」', async ({ page, backend }) => {
    void backend;
    const body = clone(REAL) as Any;
    body.static.metrics.detectionRate = 0.5;
    body.static.metrics.falsePositiveRate = 0.025;
    body.static.confusion = { tp: 150, fn: 150, fp: 10, tn: 390 };
    body.runtime.scenarios[0].detected = 7;
    body.runtime.scenarios[0].killed = 7;
    body.runtime.killLatencyMs.p50 = 123.4;
    body.runtime.benign.installs = 40;
    body.runtime.benign.violations = 2;
    await open(page, body);
    expect(await points(page)).toEqual([
      ['static-detection', '50.0%', '정적 악성 탐지율', '실제 악성 패키지 300개 중 150개 탐지됨'],
      ['false-alarm', '2.5%', '정상 패키지 오판율', '정상 패키지 400개 중 10개 오판 · 정상 설치 40건 중 위반 2건'],
      ['runtime', '90.0%', '런타임 공격 탐지율', '공격 30회 중 27회 탐지 · 17회 격리 · 격리까지 중간값 123.4 ms'],
    ]);
    await page.unroute(/\/api\/evaluation$/);
    await open(page, { static: null, runtime: REAL.runtime, model: null });
    expect(await points(page)).toEqual([
      ['static-detection', '', '정적 악성 탐지율', '정적 검사 결과 없음'],
      ['false-alarm', '0.0%', '정상 설치 오판율', '정상 설치 50건 중 위반 0건'],
      ['runtime', '100.0%', '런타임 공격 탐지율', '공격 30회 모두 탐지 · 20회 격리 · 격리까지 중간값 296.9 ms'],
    ]);
  });

  test('3 쉬운 이름: 지표 · 카드 제목 · 모델 표 머리 — 원래 용어는 용어 단추 · 접힌 칸에만', async ({ page, backend }) => {
    void backend;
    await open(page);
    await expect(page.locator('[data-part="kpis"] [data-kpi] .kpi-name')).toHaveText(['정적 악성 탐지율', '정상 패키지 오판율', '런타임 공격 탐지율', '정상 설치 오판율', '격리까지 걸린 시간', 'ML 모델 종합 점수']);
    const titles = await page.locator('[data-part="eval-body"] section[data-part] > header :is(h2, h3)').evaluateAll((els) => els.map((e) => [(e.closest('section') as HTMLElement).dataset.part, e.textContent]));
    expect(titles).toEqual([
      ['dist', '데이터별 판정 결과'],
      ['rules', '많이 걸린 GuardDog 규칙 상위 10'],
      ['confusion', '판정 정확도'],
      ['scenarios', '공격 시나리오별 탐지율'],
      ['latency', '격리까지 걸린 시간 (ms)'],
      ['benign', '정상 설치 위반 0건'],
      ['model', '규칙 vs ML 모델'],
      ['limits', '결과의 한계'],
    ]);
    // 두 열 머리: 정적 · 런타임을 쉬운 말과 함께
    await expect(page.locator('[data-col] > [data-col-title]')).toHaveText(['정적 · 패키지 코드 검사', '런타임 · 설치 · 실행 감시']);
    // 판정 정확도 요약: 적중률 · 탐지율 · 종합 점수(원래 용어는 툴팁)
    await expect(page.locator('[data-part="confusion"] [data-stat]')).toHaveText(['97.8%적중률', '68.0%탐지율', '0.80종합 점수']);
    // 모델 표 머리(펼친 뒤)
    await fold(page, 'model').click();
    await expect(page.locator('[data-table="models"] thead th')).toHaveText(['후보', '종합 점수(선택용)', '종합 점수(시험)', '적중률', '탐지율', '오판율']);
    await fold(page, 'model').click();
    // 보이는 글에 원래 용어가 남지 않는다(용어 단추 · 접힌 칸 · 툴팁은 제외)
    const leaks = await page.evaluate((hard) => {
      const root = document.querySelector('[data-part="evaluation"]')!;
      const out: string[] = [];
      const tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      for (let n = tw.nextNode(); n; n = tw.nextNode()) {
        const el = n.parentElement!;
        if (el.closest('[data-term]') || !el.checkVisibility()) continue;
        for (const h of hard) if (n.textContent!.includes(h)) out.push(`${h}: ${n.textContent!.trim().slice(0, 50)}`);
      }
      return out;
    }, HARD);
    expect(leaks).toEqual([]);
    // 어려운 용어마다 설명 단추가 화면 어딘가(접힌 칸 포함)에 있다
    for (const k of ['precision', 'recall', 'f1', 'fpr', 'p50', 'p95', 'confusion', 'hgb', 'guarddog', 'dryrun', 'split']) expect(await page.locator(`[data-term="${k}"]`).count(), k).toBeGreaterThan(0);
  });

  test('4 용어 툴팁: 마우스를 올리면 열림 · 툴팁 위로 옮겨도 유지 · 벗어나면 닫힘', async ({ page, backend }) => {
    void backend;
    await open(page);
    const term = page.locator('[data-kpi="static-fpr"] [data-term="fpr"]');
    await expect(term).toHaveText('오탐률');
    expect(await term.evaluate((e) => e.tagName)).toBe('BUTTON');
    const id = (await term.getAttribute('aria-describedby'))!;
    expect(id).toBeTruthy();
    const tip = page.locator(`[id="${id}"]`);
    await expect(tip).toHaveAttribute('role', 'tooltip');
    await expect(tip).toBeHidden();
    await term.hover();
    await expect(tip).toBeVisible();
    await expect(tip).toContainText('오탐률');
    await expect(tip).toContainText('오판율');
    await expect(tip).toContainText('정상인데 악성으로 잘못 판정한 비율');
    // 툴팁은 화면 안 · 단추 가까이
    const [tb, bb] = [(await tip.boundingBox())!, (await term.boundingBox())!];
    expect(tb.x).toBeGreaterThanOrEqual(0);
    expect(tb.x + tb.width).toBeLessThanOrEqual(1440);
    expect(Math.abs(tb.y - (bb.y + bb.height))).toBeLessThan(16);
    // 툴팁 위로 옮겨도 닫히지 않는다(WCAG 1.4.13)
    await tip.hover();
    await page.waitForTimeout(300);
    await expect(tip).toBeVisible();
    await page.mouse.move(5, 5);
    await expect(tip).toBeHidden();
    // 한 번에 하나만
    await page.locator('[data-kpi="model-f1"] [data-term="f1"]').hover();
    await expect(page.locator('[role="tooltip"][data-part="term-tip"]:visible')).toHaveCount(1);
    await expect(page.locator('[role="tooltip"][data-part="term-tip"]:visible')).toContainText('적중률과 탐지율을 함께 본 점수');
  });

  test('5 용어 툴팁: 키보드 Tab 포커스로 열림 · Esc 로 닫힘 · 다음 칸으로 가면 닫힘', async ({ page, backend }) => {
    void backend;
    await open(page);
    await fold(page, 'eval-head').focus();
    let tag = '';
    for (let i = 0; i < 12 && !tag; i++) {
      await page.keyboard.press('Tab');
      tag = await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.term ?? '');
    }
    expect(tag).toBe('p50'); // 요점 3번째 줄 「중간값」
    const id = await page.evaluate(() => document.activeElement!.getAttribute('aria-describedby'));
    const tip = page.locator(`[id="${id}"]`);
    await expect(tip).toBeVisible();
    await expect(tip).toContainText('p50');
    await expect(tip).toContainText('중간값');
    await page.keyboard.press('Escape');
    await expect(tip).toBeHidden();
    expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.term)).toBe('p50');
    // 다시 열고 Tab 으로 떠나면 닫힌다
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    await expect(tip).toBeVisible();
    await page.keyboard.press('Tab');
    await expect(tip).toBeHidden();
    // 조회자 읽기 전용 검사(data-action 없는 단추 0)와 맞물리게 — 용어 · 접기 단추는 data-action 이 있다
    expect(await page.locator(`${W} [data-term]:not([data-action="term"])`).count()).toBe(0);
  });

  test('6 자세한 표: 기본 접힘 → 「자세히」 → 펼침 → 「접기」, 차트 · 요약은 그대로 보임', async ({ page, backend }) => {
    void backend;
    await open(page);
    // 보이는 것: 요점 · 지표 6칸 · 주요 차트 · 모델 요약 · 규칙 우세 한 줄
    await expect(page.locator('[data-part="kpis"] [data-kpi]')).toHaveCount(6);
    for (const c of ['verdict-dist', 'scenario-rate', 'latency', 'kill-stages']) await expect(page.locator(`[data-chart="${c}"] svg`), c).toBeVisible();
    await expect(page.locator('[data-part="model-summary"] [data-sum]')).toHaveCount(2);
    await expect(page.locator('[data-part="rule-wins"]')).toHaveText('[규칙 우세] 시험 결과에 따라 운영은 규칙 판정 사용');
    // 접힌 것: 측정 출처 · 데이터별 표 · 규칙 적중 · 판정 4칸 표 · 모델 비교 표 · 한계 목록
    const FOLDS: [string, string][] = [
      ['eval-head', '[data-part="tags"]'],
      ['dist', 'table[data-table="datasets"]'],
      ['rules', '[data-chart="rule-hits"]'],
      ['confusion', 'td[data-cell="tp"]'],
      ['model', 'table[data-table="models"]'],
      ['limits', '[data-part="limits"] li'],
    ];
    for (const [part, inner] of FOLDS) {
      const b = fold(page, part);
      await expect(b, part).toHaveText('자세히');
      await expect(b, part).toHaveAttribute('aria-expanded', 'false');
      const region = page.locator(`[id="${await b.getAttribute('aria-controls')}"]`);
      await expect(region, part).toBeHidden();
      await expect(page.locator(inner).first(), part).toBeHidden();
    }
    await shot(page, '1440-light-folded', false);
    await shot(page, '1440-light-folded-full');
    for (const [part, inner] of FOLDS) {
      await fold(page, part).click();
      await expect(fold(page, part), part).toHaveText('접기');
      await expect(fold(page, part), part).toHaveAttribute('aria-expanded', 'true');
      await expect(page.locator(inner).first(), part).toBeVisible();
    }
    // 펼친 규칙 적중 차트는 10행, 데이터별 표는 세트 5개
    await expect(page.locator('[data-chart="rule-hits"] g[data-row]')).toHaveCount(10);
    await expect(page.locator('table[data-table="datasets"] tbody tr')).toHaveCount(5);
    await expect(page.locator('table[data-table="datasets"] tbody tr').first().locator('td')).toHaveText(['DataDog 실제 악성 (PyPI)', '297', '210', '30', '3', '54']);
    await noPageOverflow(page);
    await shot(page, '1440-light-open-full');
    await fold(page, 'model').click();
    await expect(page.locator('table[data-table="models"]')).toBeHidden();
    await expect(fold(page, 'model')).toHaveText('자세히');
  });

  test('7 다크: 요점 · 툴팁 · 접기 단추가 다크 토큰 · 넘침 0', async ({ page, backend }) => {
    void backend;
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await open(page);
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    expect(await page.locator('[data-part="eval-head"]').evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(await tok(page, '--surface', 'backgroundColor'));
    expect(await page.locator('[data-part="key-points"] [data-num]').first().evaluate((e) => getComputedStyle(e).color)).toBe(await tok(page, '--text'));
    const term = page.locator('[data-kpi="latency"] [data-term]').first();
    await term.hover();
    const tip = page.locator('[role="tooltip"][data-part="term-tip"]:visible');
    await expect(tip).toHaveCount(1);
    expect(await tip.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color])).toEqual([await tok(page, '--ink', 'backgroundColor'), await tok(page, '--ink-text')]);
    await page.mouse.move(5, 5);
    await noPageOverflow(page);
    await shot(page, '1440-dark-folded', false);
    for (const part of ['eval-head', 'dist', 'rules', 'confusion', 'model', 'limits']) await fold(page, part).click();
    await expect(page.locator('table[data-table="models"]')).toBeVisible();
    await shot(page, '1440-dark-open-full');
  });

  test('8 길게 눌러 옮기기 그대로: Alt+→ 순서 바뀜 · 칸 안 용어 단추를 눌러도 끌기 시작 안 함', async ({ page, backend }) => {
    void backend;
    await open(page);
    const ids = () => page.locator('[data-part="kpis"] [data-kpi]').evaluateAll((e) => e.map((x) => (x as HTMLElement).dataset.kpi));
    const DEF = ['static-detection', 'static-fpr', 'runtime-detection', 'runtime-fpr', 'latency', 'model-f1'];
    expect(await ids()).toEqual(DEF);
    // 용어 단추를 0.6초 눌렀다 떼면 집히지 않고 툴팁만 열린다
    const term = page.locator('[data-kpi="static-fpr"] [data-term="fpr"]');
    const b = (await term.boundingBox())!;
    await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2);
    await page.mouse.down();
    await page.waitForTimeout(600);
    await page.mouse.move(b.x + b.width / 2 + 200, b.y + b.height / 2, { steps: 5 });
    await page.mouse.up();
    expect(await ids()).toEqual(DEF);
    // 카드 키보드 옮기기
    await page.locator('[data-kpi="static-detection"]').focus();
    await page.keyboard.press('Alt+ArrowRight');
    expect(await ids()).toEqual(['static-fpr', 'static-detection', ...DEF.slice(2)]);
  });

  test.describe('390 모바일', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('9 넘침 0 · 요점 3줄 · 툴팁은 화면 안(누르면 열림)', async ({ page, backend }) => {
      void backend;
      await open(page);
      await noPageOverflow(page);
      expect(await page.locator(W).evaluate((e) => e.scrollWidth - e.clientWidth)).toBe(0);
      await expect(page.locator('[data-part="key-points"] > li')).toHaveCount(3);
      const term = page.locator('[data-kpi="latency"] [data-term]').first();
      await term.scrollIntoViewIfNeeded();
      await term.click();
      const tip = page.locator('[role="tooltip"][data-part="term-tip"]:visible');
      await expect(tip).toHaveCount(1);
      const tb = (await tip.boundingBox())!;
      expect(tb.x).toBeGreaterThanOrEqual(0);
      expect(tb.x + tb.width).toBeLessThanOrEqual(390);
      await page.keyboard.press('Escape');
      await expect(tip).toHaveCount(0);
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await page.locator(W).evaluate((e) => e.scrollTo(0, 0));
      await shot(page, '390-light-full');
    });
  });
});
