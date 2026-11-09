import { mkdirSync, readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// 11/09 사용자 결정 — 「평가 = 요점 3줄 + 쉬운 이름 + 용어 툴팁 + 자세한 표 접기」(평가 탭은 용어 · 글씨가 많아 읽기 어렵다).
// 데이터는 evaluation-1104 와 같은 실측 사본(e2e/evaluation/*.json). 요점 숫자는 API 값에서 계산 — 응답을 바꾸면 따라 바뀌어야 한다.
// 11/09 저녁(위 3칸 + 접는 목록 8줄, eval-accordion-1109.spec.ts): 요점 3줄 · 지표 6칸 → 위 3칸 + 줄 요약, 카드 → 목록 줄 안쪽.
//   이 시험의 뜻(숫자 먼저 · 응답에서 계산 · 쉬운 이름 · 용어 툴팁 · 자세한 표 접기)은 새 자리에서 그대로 확인한다.

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
// 위 3칸 [id, 숫자, 이름, 근거] — 예전 요점 3줄 [id, 숫자, 이름, 근거]의 새 자리
const points = (page: Page) =>
  page.locator('[data-part="eval-top"] [data-kpi]').evaluateAll((els) =>
    els.map((e) => [(e as HTMLElement).dataset.kpi, e.querySelector('[data-value]')?.textContent, e.querySelector('.kpi-name')?.textContent, e.querySelector('[data-hint]')?.textContent?.replace(/\u00a0/g, ' ')]),
  );
// 목록 줄 요약 [값, 보조]
const sum = async (page: Page, id: string) => {
  const b = page.locator(`[data-part="eval-list"] [data-item="${id}"] [data-action="toggle-row"]`);
  return [await b.locator('[data-value]').textContent(), (await b.locator('[data-sub]').textContent())!.replace(/\u00a0/g, ' ')];
};
const rowBtn = (page: Page, id: string) => page.locator(`[data-part="eval-list"] [data-item="${id}"] [data-action="toggle-row"]`);
async function expand(page: Page, ...ids: string[]) {
  for (const id of ids) {
    const b = rowBtn(page, id);
    if ((await b.getAttribute('aria-expanded')) !== 'true') await b.click();
    await expect(page.locator(`[id="${await b.getAttribute('aria-controls')}"]`)).toBeVisible();
  }
}
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
  test('1 위 3칸(예전 요점 3줄): 맨 위 · 숫자 크게 · 실측값 그대로 · 나머지 근거는 줄 요약', async ({ page, backend }) => {
    void backend;
    await open(page);
    const st = REAL.static as Any;
    const c = st.confusion;
    expect(await points(page)).toEqual([
      ['static-detection', pct(st.metrics.detectionRate), '정적 악성 탐지율', `악성 ${c.tp + c.fn}개 중 ${c.tp}개 · 재현율`],
      ['static-fpr', pct(st.metrics.falsePositiveRate), '정상 패키지 오판율', `정상 ${c.fp + c.tn}개 중 ${c.fp}개 · 오탐률`],
      ['runtime-detection', '100.0%', '런타임 공격 탐지율', '공격 30회 중 30회 · 격리 20회'],
    ]);
    // 예전 요점 근거 중 위 3칸에 없는 것 → 줄 요약(정상 설치 위반 · 격리까지 중간값)
    expect(await sum(page, 'benign')).toEqual(['0 / 50건 위반', '오판율 0.0% · pip 35 · npm 15']);
    expect(await sum(page, 'latency')).toEqual(['296.9 ms 중간값', '95% 이내 395.3 ms · 격리 20회 기준']);
    // 숫자는 이름 아래 크게(28px) · 위 3칸이 목록 위
    const big = await page.locator('[data-kpi="static-detection"] [data-value] b').evaluate((e) => parseFloat(getComputedStyle(e).fontSize));
    expect(big).toBeGreaterThanOrEqual(28);
    const [top, list] = [await page.locator('[data-part="eval-top"]').boundingBox(), await page.locator('[data-part="eval-list"]').boundingBox()];
    expect(top!.y + top!.height).toBeLessThanOrEqual(list!.y);
    // 예전 한 줄 결론 · 요점 3줄은 없다
    await expect(page.locator('[data-part="conclusion"]')).toHaveCount(0);
    await expect(page.locator('[data-part="key-points"]')).toHaveCount(0);
    // 숫자는 기본 글자색(빨강은 위험에만)
    expect(await page.locator('[data-part="eval-top"] [data-value] b').first().evaluate((e) => getComputedStyle(e).color)).toBe(await tok(page, '--text'));
    await noPageOverflow(page);
  });

  test('2 위 3칸 · 줄 요약 숫자는 응답에서 계산 — 값을 바꾸면 따라 바뀜 · 없는 쪽은 「결과 없음」', async ({ page, backend }) => {
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
      ['static-detection', '50.0%', '정적 악성 탐지율', '악성 300개 중 150개 · 재현율'],
      ['static-fpr', '2.5%', '정상 패키지 오판율', '정상 400개 중 10개 · 오탐률'],
      ['runtime-detection', '90.0%', '런타임 공격 탐지율', '공격 30회 중 27회 · 격리 17회'],
    ]);
    expect((await sum(page, 'benign'))[0]).toBe('2 / 40건 위반');
    expect((await sum(page, 'latency'))[0]).toBe('123.4 ms 중간값');
    await page.unroute(/\/api\/evaluation$/);
    await open(page, { static: null, runtime: REAL.runtime, model: null });
    // 정적이 없으면 위 두 칸은 빈 값 + 「정적 결과 없음」, 정상 설치 오판율은 줄 요약에(예전 요점 2번째 줄의 대체 값)
    expect(await points(page)).toEqual([
      ['static-detection', '', '정적 악성 탐지율', '정적 결과 없음'],
      ['static-fpr', '', '정상 패키지 오판율', '정적 결과 없음'],
      ['runtime-detection', '100.0%', '런타임 공격 탐지율', '공격 30회 중 30회 · 격리 20회'],
    ]);
    expect(await sum(page, 'benign')).toEqual(['0 / 50건 위반', '오판율 0.0% · pip 35 · npm 15']);
    await expect(page.locator('[data-item="dist"] [data-chip]')).toHaveText('결과 없음');
  });

  test('3 쉬운 이름: 지표 · 카드 제목 · 모델 표 머리 — 원래 용어는 용어 단추 · 접힌 칸에만', async ({ page, backend }) => {
    void backend;
    await open(page);
    // 위 3칸 이름(예전 지표 6칸 중 앞 3칸 — 뒤 3칸의 쉬운 이름은 줄 요약 글자: 오판율 · 중간값 · 종합 점수)
    await expect(page.locator('[data-part="eval-top"] [data-kpi] .kpi-name')).toHaveText(['정적 악성 탐지율', '정상 패키지 오판율', '런타임 공격 탐지율']);
    // 예전 카드 제목 → 목록 줄 이름(정적 · 런타임 묶음 이름을 앞에)
    const names = await page.locator('[data-part="eval-list"] [data-item]').evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.item, e.querySelector('[data-name]')!.textContent]));
    expect(names).toEqual([
      ['dist', '정적 · 데이터별 판정'],
      ['rules', '정적 · 규칙 적중'],
      ['confusion', '정적 · 판정 4칸'],
      ['scenarios', '런타임 · 공격 시나리오'],
      ['latency', '런타임 · 격리까지 걸린 시간'],
      ['benign', '런타임 · 정상 설치 위반'],
      ['model', '규칙 · 모델 비교'],
      ['limits', '결과의 한계'],
    ]);
    // 예전 두 열 머리(정적 · 패키지 코드 검사 / 런타임 · 설치 · 실행 감시) → 「항목」 칸 머리 (?) 툴팁
    await page.locator('[data-part="eval-list-head"] [data-term]').first().hover();
    const headTip = page.locator('[role="tooltip"][data-part="term-tip"]:visible');
    await expect(headTip).toContainText('패키지 코드');
    await expect(headTip).toContainText('설치 · 실행');
    await page.mouse.move(5, 5);
    // 판정 4칸 줄 안 요약: 적중률 · 탐지율 · 종합 점수(원래 용어는 툴팁)
    await expand(page, 'confusion');
    await expect(page.locator('[data-part="confusion"] [data-stat]')).toHaveText(['97.8%적중률', '68.0%탐지율', '0.80종합 점수']);
    // 모델 표 머리(줄 · 「자세히」 펼친 뒤)
    await expand(page, 'model');
    await fold(page, 'model').click();
    await expect(page.locator('[data-table="models"] thead th')).toHaveText(['후보', '종합 점수(선택용)', '종합 점수(시험)', '적중률', '탐지율', '오판율']);
    await fold(page, 'model').click();
    // 모든 줄을 펼쳐도 보이는 글에 원래 용어가 남지 않는다(용어 단추 · 안쪽 「자세히」 칸 · 툴팁은 제외)
    await page.locator('[data-action="toggle-all"]').click();
    await page.waitForTimeout(300);
    const leaks = await page.evaluate((hard) => {
      const root = document.querySelector('[data-part="evaluation"]')!;
      const out: string[] = [];
      const tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      for (let n = tw.nextNode(); n; n = tw.nextNode()) {
        const el = n.parentElement!;
        if (el.closest('[data-term]') || !el.checkVisibility({ checkVisibilityCSS: true })) continue;
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
    // 한 번에 하나만(예전 「ML 모델 종합 점수」 칸은 없어져 위 1칸의 「재현율」로)
    await page.locator('[data-kpi="static-detection"] [data-term="recall"]').hover();
    await expect(page.locator('[role="tooltip"][data-part="term-tip"]:visible')).toHaveCount(1);
    await expect(page.locator('[role="tooltip"][data-part="term-tip"]:visible')).toContainText('실제 악성 중 악성으로 잡아낸 비율');
  });

  test('5 용어 툴팁: 키보드 Tab 포커스로 열림 · Esc 로 닫힘 · 다음 칸으로 가면 닫힘', async ({ page, backend }) => {
    void backend;
    await open(page);
    // 예전 출발점(요점 머리 「자세히」 → 요점 「중간값」)은 없어졌다 — 격리 시간 줄 머리에서 Tab → 줄 안 첫 용어 단추
    await expand(page, 'latency');
    await rowBtn(page, 'latency').focus();
    let tag = '';
    for (let i = 0; i < 12 && !tag; i++) {
      await page.keyboard.press('Tab');
      tag = await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.term ?? '');
    }
    expect(tag).toBe('dryrun'); // 격리 시간 줄 안 「격리하지 않아 빠짐: … (시험 운영)」
    const id = await page.evaluate(() => document.activeElement!.getAttribute('aria-describedby'));
    const tip = page.locator(`[id="${id}"]`);
    await expect(tip).toBeVisible();
    await expect(tip).toContainText('dryRun');
    await expect(tip).toContainText('시험 운영');
    await page.keyboard.press('Escape');
    await expect(tip).toBeHidden();
    expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.term)).toBe('dryrun');
    // 다시 열고 Tab 으로 떠나면 닫힌다
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    await expect(tip).toBeVisible();
    await page.keyboard.press('Tab');
    await expect(tip).toBeHidden();
    // 조회자 읽기 전용 검사(data-action 없는 단추 0)와 맞물리게 — 용어 · 접기 단추는 data-action 이 있다
    expect(await page.locator(`${W} [data-term]:not([data-action="term"])`).count()).toBe(0);
  });

  test('6 자세한 표: 기본 접힘 → 줄 펼침 → 「자세히」 → 펼침 → 「접기」, 차트 · 요약은 줄을 펼치면 바로 보임', async ({ page, backend }) => {
    void backend;
    await open(page);
    // 처음 보이는 것: 위 3칸 · 목록 8줄(요약). 차트 · 표는 모두 접힘
    await expect(page.locator('[data-part="eval-top"] [data-kpi]')).toHaveCount(3);
    for (const c of ['verdict-dist', 'scenario-rate', 'latency', 'kill-stages', 'rule-hits']) await expect(page.locator(`[data-chart="${c}"] svg`), c).toBeHidden();
    await shot(page, '1440-light-folded', false);
    // 줄을 펼치면 바로 보이는 것: 주요 차트 · 모델 요약 · 규칙 우세 한 줄 · (예전 「자세히」였던) 측정 출처 · 규칙 적중 · 한계 목록
    await page.locator('[data-action="toggle-all"]').click();
    for (const c of ['verdict-dist', 'scenario-rate', 'latency', 'kill-stages', 'rule-hits']) await expect(page.locator(`[data-chart="${c}"] svg`), c).toBeVisible();
    await expect(page.locator('[data-part="model-summary"] [data-sum]')).toHaveCount(2);
    await expect(page.locator('[data-part="rule-wins"]')).toHaveText('[규칙 우세] 시험 결과에 따라 운영은 규칙 판정 사용');
    await expect(page.locator('[data-part="tags"]')).toBeVisible();
    await expect(page.locator('[data-part="limits"] li').first()).toBeVisible();
    await expect(page.locator('[data-chart="rule-hits"] g[data-row]')).toHaveCount(10);
    // 줄 안에서도 접힌 것: 데이터별 표 · 판정 4칸 표 · 모델 비교 표
    const FOLDS: [string, string][] = [
      ['dist', 'table[data-table="datasets"]'],
      ['confusion', 'td[data-cell="tp"]'],
      ['model', 'table[data-table="models"]'],
    ];
    await expect(page.locator('[data-part="eval-list"] [data-action="toggle-detail"]')).toHaveCount(FOLDS.length);
    for (const [part, inner] of FOLDS) {
      const b = fold(page, part);
      await expect(b, part).toHaveText('자세히');
      await expect(b, part).toHaveAttribute('aria-expanded', 'false');
      const region = page.locator(`[id="${await b.getAttribute('aria-controls')}"]`);
      await expect(region, part).toBeHidden();
      await expect(page.locator(inner).first(), part).toBeHidden();
    }
    await shot(page, '1440-light-rows-open-full');
    for (const [part, inner] of FOLDS) {
      await fold(page, part).click();
      await expect(fold(page, part), part).toHaveText('접기');
      await expect(fold(page, part), part).toHaveAttribute('aria-expanded', 'true');
      await expect(page.locator(inner).first(), part).toBeVisible();
    }
    // 펼친 데이터별 표는 세트 5개
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
    expect(await page.locator('[data-part="eval-list"]').evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(await tok(page, '--surface', 'backgroundColor'));
    expect(await page.locator('[data-part="eval-top"] [data-value] b').first().evaluate((e) => getComputedStyle(e).color)).toBe(await tok(page, '--text'));
    const term = page.locator('[data-kpi="static-fpr"] [data-term]').first();
    await term.hover();
    const tip = page.locator('[role="tooltip"][data-part="term-tip"]:visible');
    await expect(tip).toHaveCount(1);
    expect(await tip.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color])).toEqual([await tok(page, '--ink', 'backgroundColor'), await tok(page, '--ink-text')]);
    await page.mouse.move(5, 5);
    await noPageOverflow(page);
    await shot(page, '1440-dark-folded', false);
    await page.locator('[data-action="toggle-all"]').click();
    for (const part of ['dist', 'confusion', 'model']) await fold(page, part).click();
    await expect(page.locator('table[data-table="models"]')).toBeVisible();
    await shot(page, '1440-dark-open-full');
  });

  test('8 길게 눌러 옮기기 그대로: Alt+→ 순서 바뀜 · 칸 안 용어 단추를 눌러도 끌기 시작 안 함', async ({ page, backend }) => {
    void backend;
    await open(page);
    const ids = () => page.locator('[data-part="eval-top"] [data-kpi]').evaluateAll((e) => e.map((x) => (x as HTMLElement).dataset.kpi));
    const DEF = ['static-detection', 'static-fpr', 'runtime-detection']; // 11/09 저녁: 위 3칸
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
    test('9 넘침 0 · 위 3칸 · 툴팁은 화면 안(누르면 열림)', async ({ page, backend }) => {
      void backend;
      await open(page);
      await noPageOverflow(page);
      expect(await page.locator(W).evaluate((e) => e.scrollWidth - e.clientWidth)).toBe(0);
      await expect(page.locator('[data-part="eval-top"] [data-kpi]')).toHaveCount(3);
      const term = page.locator('[data-kpi="static-fpr"] [data-term]').first();
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
