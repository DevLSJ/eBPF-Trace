import { mkdirSync, readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// 11/09 저녁 사용자 결정 — 평가 화면 = 「위 큰 숫자 3칸 + 접고 펼치는 목록 8줄」(참고 그림의 가독성 원리, A안).
//   목록 줄 = ▶ · 항목 이름 · 핵심 값 · 비율이면 얇은 막대 · 상태 칩(글자). 여러 줄 동시에 열림 · 머리 「모두 펼치기 · 모두 접기」 단추 하나 ·
//   기본 모두 접힘(기억하지 않음). 요점 3줄 · 지표 6칸은 없애고 그 정보는 위 3칸과 줄 요약으로 옮겼다. 펼친 안쪽 = 예전 카드 내용 그대로.
// 11/09 저녁 사용자 답 「정적 줄에 목표치」 + 「탐지율은 92%로 조정」: ③ 판정 4칸 = 탐지율 92% 이상 · 오판율 2% 이하 둘 다 맞으면 통과, 하나라도 못 미치면 주의(①② 는 참고 그대로).
// 데이터는 evaluation-1104 와 같은 실측 사본(e2e/evaluation/*.json). 숫자는 응답에서 계산 — 응답을 바꾸면 따라 바뀌어야 한다.

type Json = Record<string, unknown>;
type Any = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as Json;
const REAL = { static: load('static'), runtime: load('runtime'), model: load('model'), modelAll: load('model-all') };
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

const W = '[data-part="evaluation"]';
const LIST = '[data-part="eval-list"]';
const ITEMS = ['dist', 'rules', 'confusion', 'scenarios', 'latency', 'benign', 'model', 'limits'];
// 화면 사진 — EVAL_SHOTS 가 있으면 그 폴더(작업 폴더 밖 임시 폴더), 없으면 test-results 아래
const DIR = process.env.EVAL_SHOTS || `${SHOTS}/eval-accordion-1109`;
mkdirSync(DIR, { recursive: true });

async function open(page: Page, body: unknown = REAL) {
  await page.unroute(/\/api\/evaluation$/);
  await page.route(/\/api\/evaluation$/, (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(body) }));
  await page.goto('/evaluation');
  await expect(page.locator(`${W}[data-state="ready"]`)).toBeVisible();
}
const row = (page: Page, id: string) => page.locator(`${LIST} [data-item="${id}"] [data-action="toggle-row"]`);
const panel = async (page: Page, id: string) => page.locator(`[id="${await row(page, id).getAttribute('aria-controls')}"]`);
const expanded = (page: Page) => page.locator(`${LIST} [data-action="toggle-row"]`).evaluateAll((els) => els.map((e) => e.getAttribute('aria-expanded')));
const all = (v: string) => ITEMS.map(() => v);
const tiles = (page: Page) =>
  page.locator('[data-part="eval-top"] [data-kpi]').evaluateAll((els) =>
    els.map((e) => [(e as HTMLElement).dataset.kpi, e.querySelector('.kpi-name')!.textContent, e.querySelector('[data-value]')!.textContent, e.querySelector('[data-hint]')!.textContent!.replace(/\u00a0/g, ' ')]),
  );
// 줄 요약: [id, 이름, 값, 보조, 칩 글자, 칩 종류, 막대 값]
const sums = (page: Page) =>
  page.locator(`${LIST} [data-item]`).evaluateAll((els) =>
    els.map((e) => {
      const q = (s: string) => e.querySelector(`[data-action="toggle-row"] ${s}`);
      return [
        (e as HTMLElement).dataset.item,
        q('[data-name]')?.textContent ?? null,
        q('[data-value]')?.textContent ?? '',
        (q('[data-sub]')?.textContent ?? '').replace(/\u00a0/g, ' '),
        q('[data-chip]')?.textContent ?? null,
        (q('[data-chip]') as HTMLElement | null)?.dataset.chip ?? null,
        (q('[data-meter]') as HTMLElement | null)?.dataset.v ?? null,
      ];
    }),
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
// 보이는 글자 · title 에서 「—」(no-dash-1109 와 같은 규칙 — 코드 창 · pre · code 제외)
const dashes = (page: Page) =>
  page.evaluate(() => {
    const out: string[] = [];
    const skip = (el: Element) => !!el.closest('[data-part="code"], pre, code, script, style');
    const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (tw.nextNode()) {
      const n = tw.currentNode as Text;
      if (!n.data.includes('—')) continue;
      const el = n.parentElement;
      if (!el || skip(el) || !el.checkVisibility({ checkVisibilityCSS: true })) continue;
      out.push(n.data.trim().slice(0, 90));
    }
    for (const el of Array.from(document.querySelectorAll('[title], [aria-label]'))) {
      if (skip(el)) continue;
      for (const a of ['title', 'aria-label']) if (el.getAttribute(a)?.includes('—')) out.push(`@${a} ${el.getAttribute(a)!.slice(0, 90)}`);
    }
    return out;
  });
async function shot(page: Page, name: string, full = false) {
  const vp = page.viewportSize()!;
  if (full) {
    const need = await page.evaluate(() => {
      const b = document.querySelector('[data-part="eval-body"]') as HTMLElement;
      const root = document.querySelector('[data-part="evaluation"]') as HTMLElement;
      const bottom = getComputedStyle(b).overflowY !== 'visible' ? b.getBoundingClientRect().top + b.scrollHeight : root.getBoundingClientRect().top + root.scrollHeight;
      return Math.ceil(bottom + 32);
    });
    if (need > vp.height) await page.setViewportSize({ width: vp.width, height: need });
  }
  await page.mouse.move(2, 2);
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${DIR}/${name}.png` });
  if (full) await page.setViewportSize(vp);
}

const REAL_TILES = [
  ['static-detection', '정적 악성 탐지율', '68.0%', '악성 594개 중 404개 · 재현율'],
  ['static-fpr', '정상 패키지 오판율', '1.5%', '정상 600개 중 9개 · 오탐률'],
  ['runtime-detection', '런타임 공격 탐지율', '100.0%', '공격 30회 중 30회 · 격리 20회'],
];
const REAL_SUMS = [
  ['dist', '정적 · 데이터별 판정', '1,494 / 1,500개 검사', '세트 5개 · 오류 1건 · 건너뜀 6건', '참고', 'ref', '0.996'],
  ['rules', '정적 · 규칙 적중', '1위 capability-process-spawn', '악성 350개 · 정상 179개에서 걸림 · 적중 규칙 50개', '참고', 'ref', null],
  ['confusion', '정적 · 판정 4칸', '0.80 종합 점수', '적중률 97.8% · 탐지율 68.0%', '주의', 'warn', '0.8024'], // 탐지율 68.0% < 목표 92%
  ['scenarios', '런타임 · 공격 시나리오', '30 / 30회 탐지', '공격 3종 · 대조군 5회 중 탐지 0회', '통과', 'pass', '1'],
  ['latency', '런타임 · 격리까지 걸린 시간', '296.9 ms 중간값', '95% 이내 395.3 ms · 격리 20회 기준', '참고', 'ref', null],
  ['benign', '런타임 · 정상 설치 위반', '0 / 50건 위반', '오판율 0.0% · pip 35 · npm 15', '통과', 'pass', '0'],
  ['model', '규칙 · 모델 비교', '0.94 규칙 · 0.87 ML 모델', '종합 점수(시험) · HistGradientBoosting · 운영 미적용', '규칙 우세', 'rule', null],
  ['limits', '결과의 한계', '28건', '정적 8 · 런타임 10 · 모델 8 · 모델(전체) 2', '참고', 'ref', null],
];

test.describe('평가 접는 목록(11/09 저녁)', () => {
  test('1 처음: 위 3칸 + 8줄 모두 접힘 · 줄 요약 · 칩은 글자 · 빨강 없음 · 칸 머리 (?)', async ({ page, backend }) => {
    void backend;
    await open(page);
    expect(await tiles(page)).toEqual(REAL_TILES);
    // 예전 요점 3줄 · 지표 6칸 · 두 열 머리는 없다
    for (const p of ['eval-head', 'key-points', 'kpis']) await expect(page.locator(`[data-part="${p}"]`), p).toHaveCount(0);
    await expect(page.locator('[data-col-title]')).toHaveCount(0);
    // 8줄 = 정적 3 → 런타임 3 → 모델 비교 → 한계, 모두 접힘(aria-expanded · aria-controls · 안쪽 숨김)
    expect(await sums(page)).toEqual(REAL_SUMS);
    expect(await expanded(page)).toEqual(all('false'));
    for (const id of ITEMS) {
      const b = row(page, id);
      expect(await b.evaluate((e) => e.tagName), id).toBe('BUTTON');
      const p = await panel(page, id);
      await expect(p, id).toHaveCount(1);
      await expect(p, id).toBeHidden();
      await expect(p.locator(`[data-part="${id}"]`), id).toBeHidden();
    }
    // 위 3칸은 목록 위
    const [top, list] = [(await page.locator('[data-part="eval-top"]').boundingBox())!, (await page.locator(LIST).boundingBox())!];
    expect(top.y + top.height).toBeLessThanOrEqual(list.y);
    // 색: 숫자는 기본 글자색 · 칩 · 막대에 위험(빨강) 없음
    const text = await tok(page, '--text');
    const danger = await tok(page, '--danger');
    expect(await page.locator('[data-part="eval-top"] [data-value] b').first().evaluate((e) => getComputedStyle(e).color)).toBe(text);
    const used = await page.locator(`${LIST} :is([data-chip], [data-meter] > i)`).evaluateAll((els) => els.flatMap((e) => [getComputedStyle(e).color, getComputedStyle(e).backgroundColor]));
    expect(used).not.toContain(danger);
    // 칸 머리 (?) 세 개 — 용어 단추(툴팁), 설명 문장은 줄에 없다
    const q = page.locator('[data-part="eval-list-head"] [data-term]');
    await expect(q).toHaveCount(3);
    // (?) 글자도 12px 이상(화면 글자 하한 — r4-tables G)
    expect(await q.evaluateAll((els) => els.map((e) => parseFloat(getComputedStyle(e).fontSize)))).toEqual([12, 12, 12]);
    expect(await q.evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')))).toEqual(['항목 설명', '결과 설명', '상태 설명']);
    await q.nth(2).hover();
    const tip = page.locator('[role="tooltip"][data-part="term-tip"]:visible');
    await expect(tip).toHaveCount(1);
    await expect(tip).toContainText('통과');
    await expect(tip).toContainText('결과 없음');
    await expect(tip).toContainText('탐지율 92% 이상 · 오판율 2% 이하');
    await q.nth(0).hover();
    await expect(tip).toContainText('정적');
    await expect(tip).toContainText('런타임');
  });

  test('2 응답 값을 바꾸면 위 3칸 · 줄 요약 · 칩이 따라 바뀜', async ({ page, backend }) => {
    void backend;
    const body = clone(REAL) as Any;
    Object.assign(body.static.metrics, { detectionRate: 0.5, recall: 0.5, falsePositiveRate: 0.025, precision: 0.9375, f1: 0.6 });
    body.static.confusion = { tp: 150, fn: 150, fp: 10, tn: 390 };
    body.runtime.scenarios[0].detected = 7;
    body.runtime.scenarios[0].killed = 7;
    body.runtime.scenarios[3].detected = 1;
    body.runtime.killLatencyMs.p50 = 123.4;
    Object.assign(body.runtime.benign, { installs: 40, violations: 2, falsePositiveRate: 0.05 });
    body.model.candidates.find((x: Any) => x.id === 'hgb').test.f1 = 0.95;
    await open(page, body);
    expect(await tiles(page)).toEqual([
      ['static-detection', '정적 악성 탐지율', '50.0%', '악성 300개 중 150개 · 재현율'],
      ['static-fpr', '정상 패키지 오판율', '2.5%', '정상 400개 중 10개 · 오탐률'],
      ['runtime-detection', '런타임 공격 탐지율', '90.0%', '공격 30회 중 27회 · 격리 17회'],
    ]);
    const s = await sums(page);
    expect(s[2].slice(2)).toEqual(['0.60 종합 점수', '적중률 93.8% · 탐지율 50.0%', '주의', 'warn', '0.6']); // 탐지율 50% · 오판율 2.5% 둘 다 못 미침
    expect(s[3].slice(2)).toEqual(['27 / 30회 탐지', '공격 3종 · 대조군 5회 중 탐지 1회', '주의', 'warn', '0.9']);
    expect(s[4].slice(2)).toEqual(['123.4 ms 중간값', '95% 이내 395.3 ms · 격리 20회 기준', '참고', 'ref', null]);
    expect(s[5].slice(2)).toEqual(['2 / 40건 위반', '오판율 5.0% · pip 35 · npm 15', '주의', 'warn', '0.05']);
    expect(s[6].slice(2)).toEqual(['0.94 규칙 · 0.95 ML 모델', '종합 점수(시험) · HistGradientBoosting · 운영 미적용', '참고', 'ref', null]);
  });

  test('2-1 ③ 판정 4칸 칩 = 정적 목표치(탐지율 92% 이상 · 오판율 2% 이하) — 경계 포함 · 하나라도 못 미치면 주의 · 칩 툴팁', async ({ page, backend }) => {
    void backend;
    const chip = page.locator('[data-item="confusion"] [data-action="toggle-row"] [data-chip]');
    const at = async (detectionRate: number, falsePositiveRate: number) => {
      const body = clone(REAL) as Any;
      Object.assign(body.static.metrics, { detectionRate, falsePositiveRate });
      await open(page, body);
      return [await chip.textContent(), await chip.getAttribute('data-chip')];
    };
    expect(await at(0.92, 0.02)).toEqual(['통과', 'pass']); // 경계 = 목표 충족
    expect(await at(0.93, 0.004)).toEqual(['통과', 'pass']);
    expect(await at(0.9199, 0.01)).toEqual(['주의', 'warn']); // 탐지율만 못 미침
    expect(await at(0.85, 0.01)).toEqual(['주의', 'warn']); // 예전 목표(80%)는 넘지만 92% 에 못 미침
    expect(await at(0.95, 0.0201)).toEqual(['주의', 'warn']); // 오판율만 못 미침
    // 칩 툴팁 · 화면 낭독(줄 머리 설명에 목표 포함)
    await expect(chip).toHaveAttribute('title', '목표: 탐지율 92% 이상 · 오판율 2% 이하');
    const desc = await page.locator('[data-item="confusion"] [data-action="toggle-row"]').evaluate((b) =>
      b.getAttribute('aria-describedby')!.split(' ').map((id) => document.getElementById(id)?.textContent ?? '').join(' '),
    );
    expect(desc).toContain('목표: 탐지율 92% 이상 · 오판율 2% 이하');
    // ① ② 는 참고 그대로, 다른 줄에는 목표 툴팁 없음
    for (const id of ['dist', 'rules']) await expect(page.locator(`[data-item="${id}"] [data-chip]`), id).toHaveText('참고');
    await expect(page.locator('[data-chip][title]')).toHaveCount(1);
  });

  test('3 줄 하나씩: 누른 줄만 열림 · 두 줄 동시에 · 다시 누르면 닫힘 · 움직임 토큰 · 동작 줄이기면 즉시', async ({ page, backend }) => {
    void backend;
    await open(page);
    await row(page, 'scenarios').click();
    expect(await expanded(page)).toEqual(ITEMS.map((x) => String(x === 'scenarios')));
    await expect(await panel(page, 'scenarios')).toBeVisible();
    await expect(page.locator('[data-chart="scenario-rate"] svg')).toBeVisible();
    await expect(await panel(page, 'dist')).toBeHidden();
    await row(page, 'model').click();
    expect(await expanded(page)).toEqual(ITEMS.map((x) => String(x === 'scenarios' || x === 'model')));
    await expect(page.locator('[data-part="model-summary"] [data-sum]')).toHaveCount(2);
    await expect(await panel(page, 'scenarios')).toBeVisible();
    // 펼친 안쪽에 카드 제목 줄은 없다(줄 이름이 제목)
    await expect(page.locator(`${LIST} [data-part="model"] > header, ${LIST} [data-part="scenarios"] > header`)).toHaveCount(0);
    await row(page, 'scenarios').click();
    expect(await expanded(page)).toEqual(ITEMS.map((x) => String(x === 'model')));
    await expect(await panel(page, 'scenarios')).toBeHidden();
    // 높이 전환 = --dur-base(180ms) · --ease-move, 열 때 · 닫을 때 같은 값 · ▶ 회전
    const want = await page.evaluate(() => {
      const el = document.createElement('i');
      el.style.transition = 'grid-template-rows var(--dur-base) var(--ease-move)';
      document.body.append(el);
      const s = getComputedStyle(el);
      const out = [s.transitionDuration, s.transitionTimingFunction];
      el.remove();
      return out;
    });
    expect(want[0]).toBe('0.18s');
    const tr = async (id: string) => (await panel(page, id)).evaluate((e) => [getComputedStyle(e).transitionDuration, getComputedStyle(e).transitionTimingFunction]);
    expect(await tr('model')).toEqual(want);
    expect(await tr('dist')).toEqual(want);
    const caret = (id: string) => page.locator(`[data-item="${id}"] [data-part="caret"]`).evaluate((e) => getComputedStyle(e).transform);
    expect(await caret('dist')).toBe('none');
    await expect.poll(() => caret('model')).not.toBe('none');
    // 동작 줄이기: 전환 없이 바로
    await page.emulateMedia({ reducedMotion: 'reduce' });
    expect((await tr('dist'))[0]).toBe('0s');
    await row(page, 'dist').click();
    await expect(page.locator('[data-chart="verdict-dist"] svg')).toBeVisible({ timeout: 100 });
  });

  test('4 「모두 펼치기 · 모두 접기」 단추 하나(머리 「결과 JSON」 옆) · 누를 때마다 바뀜', async ({ page, backend }) => {
    void backend;
    await open(page);
    const t = page.locator('[data-action="toggle-all"]');
    const dl = page.locator('[data-action="download-json"]');
    await expect(t).toHaveText('모두 펼치기');
    await expect(t).toHaveAttribute('aria-expanded', 'false');
    // 화면 머리 같은 칸 · 「결과 JSON」 바로 옆
    expect(await t.evaluate((e, d) => e.parentElement === d!.parentElement, await dl.elementHandle())).toBe(true);
    const [tb, db] = [(await t.boundingBox())!, (await dl.boundingBox())!];
    expect(Math.abs(tb.y - db.y)).toBeLessThan(2);
    expect(Math.abs(tb.x + tb.width - db.x)).toBeLessThan(24);
    await t.click();
    expect(await expanded(page)).toEqual(all('true'));
    await expect(t).toHaveText('모두 접기');
    await expect(t).toHaveAttribute('aria-expanded', 'true');
    for (const id of ITEMS) await expect(await panel(page, id), id).toBeVisible();
    await t.click();
    expect(await expanded(page)).toEqual(all('false'));
    await expect(t).toHaveText('모두 펼치기');
    for (const id of ITEMS) await expect(await panel(page, id), id).toBeHidden();
    // 일부만 열려 있으면 「모두 펼치기」 → 전부 열림
    await row(page, 'benign').click();
    await expect(t).toHaveText('모두 펼치기');
    await t.click();
    expect(await expanded(page)).toEqual(all('true'));
    // 한 줄을 닫으면 다시 「모두 펼치기」
    await row(page, 'rules').click();
    await expect(t).toHaveText('모두 펼치기');
    // 기억하지 않음: 다시 들어오면 모두 접힘
    await page.reload();
    await expect(page.locator(`${W}[data-state="ready"]`)).toBeVisible();
    expect(await expanded(page)).toEqual(all('false'));
  });

  test('5 키보드: Enter · Space 로 열고 닫음 · 접힌 안쪽은 Tab 으로 가지 않음', async ({ page, backend }) => {
    void backend;
    await open(page);
    const b = row(page, 'confusion');
    await b.focus();
    await page.keyboard.press('Enter');
    await expect(b).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('[data-part="confusion-stats"]')).toBeVisible();
    await page.keyboard.press('Space');
    await expect(b).toHaveAttribute('aria-expanded', 'false');
    await expect(await panel(page, 'confusion')).toBeHidden();
    await page.keyboard.press(' ');
    await expect(b).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('Enter');
    await expect(b).toHaveAttribute('aria-expanded', 'false');
    // 접힌 줄 다음 Tab = 다음 줄 머리(안쪽 단추 · 용어로 가지 않음)
    await row(page, 'dist').focus();
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => (document.activeElement?.closest('[data-item]') as HTMLElement | null)?.dataset.item)).toBe('rules');
    expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.action)).toBe('toggle-row');
    // 포커스 링은 공통 하나(2px 주색)
    const ring = await page.evaluate(() => {
      const s = getComputedStyle(document.activeElement!);
      return [s.outlineStyle, s.outlineWidth];
    });
    expect(ring).toEqual(['solid', '2px']);
  });

  test('6 결과 없는 쪽: 정적만 · 런타임만 → 줄 요약 「결과 없음」(값 · 보조 빈 칸)', async ({ page, backend }) => {
    void backend;
    await open(page, { static: REAL.static, runtime: null, model: null });
    expect((await tiles(page)).map((x) => x.slice(2))).toEqual([
      ['68.0%', '악성 594개 중 404개 · 재현율'],
      ['1.5%', '정상 600개 중 9개 · 오탐률'],
      ['', '런타임 결과 없음'],
    ]);
    let s = await sums(page);
    expect(s.map((x) => x[4])).toEqual(['참고', '참고', '주의', '결과 없음', '결과 없음', '결과 없음', '결과 없음', '참고']); // ③ = 정적 목표치(탐지율 68% < 92%)
    for (const x of s.slice(3, 7)) expect([x[2], x[3], x[5], x[6]], x[0]!).toEqual(['', '', 'none', null]);
    expect(s[7].slice(2, 4)).toEqual(['8건', '정적 8']);
    await row(page, 'latency').click();
    await expect(page.locator('[data-part="latency"] [data-part="none"]')).toHaveText('런타임 결과 없음');

    await open(page, { static: null, runtime: REAL.runtime, model: null });
    expect((await tiles(page)).map((x) => x.slice(2))).toEqual([
      ['', '정적 결과 없음'],
      ['', '정적 결과 없음'],
      ['100.0%', '공격 30회 중 30회 · 격리 20회'],
    ]);
    s = await sums(page);
    expect(s.map((x) => x[4])).toEqual(['결과 없음', '결과 없음', '결과 없음', '통과', '참고', '통과', '결과 없음', '참고']);
    for (const x of [...s.slice(0, 3), s[6]]) expect([x[2], x[3], x[5]], x[0]!).toEqual(['', '', 'none']);
    await row(page, 'dist').click();
    await expect(page.locator('[data-part="dist"] [data-part="none"]')).toHaveText('정적 결과 없음');
  });

  test('7 「—」 없음: 접힘 · 모두 펼침 · 안쪽 「자세히」까지', async ({ page, backend }) => {
    void backend;
    await open(page);
    expect(await dashes(page)).toEqual([]);
    await page.locator('[data-action="toggle-all"]').click();
    for (const b of await page.locator(`${LIST} [data-action="toggle-detail"]`).all()) await b.click();
    await page.waitForTimeout(300);
    expect(await dashes(page)).toEqual([]);
  });

  test('8 1440×900: 페이지 스크롤 없음 · 위 3칸 제자리 · 목록만 스크롤 + 화면 사진(밝은 · 모두 펼침)', async ({ page, backend }) => {
    void backend;
    await open(page);
    await noPageOverflow(page);
    await shot(page, '1440-light');
    const body = page.locator('[data-part="eval-body"]');
    expect(await body.evaluate((e) => getComputedStyle(e).overflowY)).toBe('auto');
    // 접힌 8줄은 한 화면에 다 들어간다
    expect(await body.evaluate((e) => e.scrollHeight - e.clientHeight)).toBeLessThanOrEqual(1);
    const before = (await page.locator('[data-part="eval-top"]').boundingBox())!;
    await page.locator('[data-action="toggle-all"]').click();
    await page.waitForTimeout(300);
    await noPageOverflow(page);
    expect(await body.evaluate((e) => e.scrollHeight - e.clientHeight)).toBeGreaterThan(200);
    await body.evaluate((e) => e.scrollTo(0, e.scrollHeight));
    await page.waitForTimeout(100);
    const after = (await page.locator('[data-part="eval-top"]').boundingBox())!;
    expect(after.y).toBe(before.y);
    // 칸 머리는 목록을 내려도 위에 붙어 있다
    const [hd, bd] = [(await page.locator('[data-part="eval-list-head"]').boundingBox())!, (await body.boundingBox())!];
    expect(Math.abs(hd.y - bd.y)).toBeLessThan(2);
    await body.evaluate((e) => e.scrollTo(0, 0));
    await shot(page, '1440-light-open-full', true);
  });

  test('9 다크: 목록 · 칩 · 위 3칸 토큰 색 · 넘침 0 + 화면 사진', async ({ page, backend }) => {
    void backend;
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await open(page);
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    expect(await page.locator(LIST).evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(await tok(page, '--surface', 'backgroundColor'));
    expect(await page.locator(`${LIST} [data-name]`).first().evaluate((e) => getComputedStyle(e.lastElementChild!).color)).toBe(await tok(page, '--text'));
    expect(await page.locator('[data-part="eval-top"] [data-value] b').first().evaluate((e) => getComputedStyle(e).color)).toBe(await tok(page, '--text'));
    await noPageOverflow(page);
    await shot(page, '1440-dark');
  });

  test.describe('390 모바일', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('10 한 열 · 화면 전체 스크롤 · 넘침 0 · 위 3칸 2열 + 화면 사진', async ({ page, backend }) => {
      void backend;
      await open(page);
      await noPageOverflow(page);
      expect(await page.locator(W).evaluate((e) => e.scrollWidth - e.clientWidth)).toBe(0);
      expect(await page.locator('[data-part="eval-body"]').evaluate((e) => getComputedStyle(e).overflowY)).toBe('visible');
      expect(await page.locator('[data-part="eval-top"]').evaluate((e) => getComputedStyle(e).gridTemplateColumns.split(' ').length)).toBe(2);
      // 줄은 한 열(같은 x · 같은 폭 · 위에서 아래로), 이름 · 칩 다음 줄에 값
      const boxes = await page.locator(`${LIST} [data-action="toggle-row"]`).evaluateAll((els) => els.map((e) => e.getBoundingClientRect().toJSON() as DOMRect));
      for (const b of boxes) {
        expect(Math.abs(b.x - boxes[0].x)).toBeLessThan(1);
        expect(Math.abs(b.width - boxes[0].width)).toBeLessThan(1);
      }
      for (let i = 1; i < boxes.length; i++) expect(boxes[i].y).toBeGreaterThan(boxes[i - 1].y);
      const r = row(page, 'benign');
      const [nm, val] = [(await r.locator('[data-name]').boundingBox())!, (await r.locator('[data-value]').boundingBox())!];
      expect(val.y).toBeGreaterThanOrEqual(nm.y + nm.height - 1);
      await page.locator('[data-action="toggle-all"]').click();
      await page.waitForTimeout(300);
      await noPageOverflow(page);
      expect(await page.locator(W).evaluate((e) => e.scrollWidth - e.clientWidth)).toBe(0);
      expect(await page.locator(W).evaluate((e) => e.scrollHeight - e.clientHeight)).toBeGreaterThan(400);
      await page.locator('[data-action="toggle-all"]').click();
      await page.waitForTimeout(300);
      await shot(page, '390-light', true);
    });
  });
});
