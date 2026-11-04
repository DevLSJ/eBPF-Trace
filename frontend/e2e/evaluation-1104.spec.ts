import { readFileSync } from 'node:fs';
import type { Page, Route } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// 11/04 「평가」 화면 React 이식(목업 mock/shared/eval.js · mock/tests/eval-1104.cjs 확정본 + 11/04c).
// 데이터 = GET /api/evaluation → {static, runtime, model, modelAll}(없는 쪽 null, 결과 없음 404).
// 픽스처는 bench/reports 실측 파일 그대로(e2e/evaluation/*.json 사본, main 672a1e6 — static 은 benign-npm 포함 재생성본) — 화면에 실측 수치가 그대로 나와야 한다.

type Json = Record<string, unknown>;
const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as Json;
// 백엔드(api/evaluation.go)가 내려 주는 모양 그대로 — 파일 4개
const REAL = { static: load('static'), runtime: load('runtime'), model: load('model'), modelAll: load('model-all') };
const NO_ALL = { ...REAL, modelAll: null };
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

const W = '[data-part="evaluation"]';
const ready = (page: Page) => expect(page.locator(`${W}[data-state="ready"]`)).toBeVisible();

// 가짜 GET /api/evaluation — reply 를 바꾸면 다음 호출부터 그 응답(개발 모드 StrictMode 는 처음에 두 번 부른다). calls = 응답한 상태 코드들
type Reply = { status: number; body?: unknown };
async function evalApi(page: Page, first: Reply) {
  const api = { reply: first, calls: [] as number[] };
  await page.route(/\/api\/evaluation$/, (route: Route) => {
    const r = api.reply;
    api.calls.push(r.status);
    return route.fulfill({ status: r.status, contentType: 'application/json', body: JSON.stringify(r.body ?? { error: '평가 결과 없음' }) });
  });
  return api;
}
const ok = (body: unknown = REAL): Reply => ({ status: 200, body });

async function kpis(page: Page) {
  return page.locator('[data-part="kpis"] [data-kpi]').evaluateAll((els) =>
    els.map((e) => [(e as HTMLElement).dataset.kpi, e.querySelector('[data-value]')!.textContent, e.querySelector('[data-hint]')!.textContent!.replace(/\u00a0/g, ' ')]),
  );
}
async function rows(page: Page, chart: string) {
  return page.locator(`[data-chart="${chart}"] g[data-row]`).evaluateAll((gs) => gs.map((g) => (g as SVGGElement).dataset.row));
}
// 스크린샷: 본문 칸만 스크롤하므로 내용 높이만큼 창을 늘려 한 장에 담는다
async function shot(page: Page, name: string) {
  const vp = page.viewportSize()!;
  const need = await page.locator(W).evaluate((e) => Math.ceil(e.scrollHeight + e.getBoundingClientRect().top + 24));
  if (need > vp.height) await page.setViewportSize({ width: vp.width, height: need });
  await page.waitForTimeout(250);
  await page.screenshot({ path: `${SHOTS}/eval-1104-${name}.png` });
  if (need > vp.height) await page.setViewportSize(vp);
}

test.describe('평가 화면(11/04)', () => {
  test('1 사이드바: 설치 검사 묶음 끝(공급망 검사 다음)에 평가 · 화면 이름', async ({ page, backend }) => {
    void backend;
    const api = await evalApi(page, ok());
    await page.goto('/');
    const nav = page.getByRole('navigation', { name: '화면' });
    await expect(nav.locator('[data-nav-group="설치 검사"] a')).toHaveText(['설치 검사', '공급망 검사', '평가']);
    await nav.getByRole('link', { name: '평가' }).click();
    await expect(page).toHaveURL(/\/evaluation$/);
    await expect(page.getByTestId('page-title')).toHaveText('평가');
    await ready(page);
    expect(api.calls.length).toBeGreaterThan(0);
  });

  test('2 머리 · 지표 6칸 = 실측값 그대로', async ({ page, backend }) => {
    void backend;
    await evalApi(page, ok());
    await page.goto('/evaluation');
    await ready(page);
    await expect(page.locator('[data-part="sample-badge"]')).toHaveCount(0);
    await expect(page.locator('[data-part="conclusion"]')).toHaveText(
      '정적 검사: 실제 악성 594개 중 404개 탐지 · 정상 600개 중 9개 오탐 — 런타임: 공격 30회 중 30회 탐지 · 정상 설치 50건 중 0건 위반',
    );
    // 출처 태그: 세트 5개 · 런타임 호스트 · 생성 시각 · 백엔드 커밋(앞 7자리)
    const tags = await page.locator('[data-part="tags"] [data-tag]').evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.tag, e.textContent]));
    expect(tags.map((t) => t[0])).toEqual(['dataset-datadog-pypi', 'dataset-datadog-npm', 'dataset-benign-pypi', 'dataset-benign-pypi-sdist', 'dataset-benign-npm', 'host', 'generated', 'commit']);
    expect(tags[0][1]).toBe('악성 세트DataDog 실제 악성 (PyPI)');
    expect(tags[2][1]).toBe('정상 세트인기 PyPI wheel 300 (정상)');
    expect(tags[4][1]).toBe('정상 세트인기 npm 300 (정상)');
    expect(tags[5][1]).toBe('런타임sg-vm · 커널 5.15.0-202-generic · fanotify');
    expect(tags[6][1]).toBe('생성2026-11-04 10:47'); // 가장 늦은 생성 시각(model-all 01:47Z) — 서울 시각
    expect(tags[7][1]).toBe('백엔드a5af1f9 · 845907c');
    expect(await kpis(page)).toEqual([
      ['static-detection', '68.0%', '악성 404 / 594 · 주의 포함 79.0%'],
      ['static-fpr', '1.5%', '인기 패키지 9 / 600 · 주의 포함 2.8%'],
      ['runtime-detection', '100.0%', '공격 30 / 30회 · 3종'],
      ['runtime-fpr', '0.0%', '위반 0 / 50건 · pip 35, npm 15'],
      ['latency', '296.9 / 395.3 ms', '격리된 공격 20회 기준 · 백엔드 수신→격리'],
      ['model-f1', '0.87', 'HistGradientBoosting · 운영 미적용'],
    ]);
    // 숫자는 기본 글자색 — 빨강은 위험에만
    const colors = await page.locator('[data-part="kpis"] [data-value]').evaluateAll((els) => [...new Set(els.map((e) => getComputedStyle(e).color))]);
    expect(colors).toHaveLength(1);
    // 두 열: 왼쪽 정적 · 오른쪽 런타임, 모델 비교 · 한계는 전체 폭
    expect(await page.locator('[data-col="static"] > [data-part]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.part))).toEqual(['dist', 'rules', 'confusion']);
    expect(await page.locator('[data-col="runtime"] > [data-part]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.part))).toEqual(['scenarios', 'latency', 'benign']);
    const box = async (sel: string) => (await page.locator(sel).boundingBox())!;
    const [sc, rc, md, grid] = [await box('[data-col="static"]'), await box('[data-col="runtime"]'), await box('[data-part="model"]'), await box('[data-part="eval-grid"]')];
    expect(sc.x).toBeLessThan(rc.x);
    expect(Math.abs(sc.y - rc.y)).toBeLessThan(1);
    expect(Math.abs(md.width - grid.width)).toBeLessThan(1.5);
    await noPageOverflow(page);
    await shot(page, 'desktop');
  });

  test('3 차트: 판정 분포 · 시나리오 탐지율 · 지연 범위 · 규칙 적중 상위 10 · 툴팁', async ({ page, backend }) => {
    void backend;
    await evalApi(page, ok());
    await page.goto('/evaluation');
    await ready(page);
    for (const c of ['verdict-dist', 'rule-hits', 'scenario-rate', 'latency', 'kill-stages']) await expect(page.locator(`[data-chart="${c}"] svg`), c).toBeVisible();
    expect(await rows(page, 'verdict-dist')).toEqual(['datadog-pypi', 'datadog-npm', 'benign-pypi', 'benign-pypi-sdist', 'benign-npm']);
    // 쌓은 막대 조각 = 판정 비율(악성 → 주의 → 취약 → 정상 → 오류 순서, 0 인 조각은 없음)
    const segs = await page.locator('[data-chart="verdict-dist"] g[data-row="datadog-pypi"] rect[data-key]').evaluateAll((els) => els.map((e) => [(e as SVGRectElement).dataset.key, Number((e as SVGRectElement).dataset.v).toFixed(4)]));
    expect(segs).toEqual([['malicious', (210 / 297).toFixed(4)], ['suspicious', (30 / 297).toFixed(4)], ['vulnerable', (3 / 297).toFixed(4)], ['clean', (54 / 297).toFixed(4)]]);
    await expect(page.locator('[data-chart="verdict-dist"] [data-part="legend"] > span')).toHaveText(['악성', '주의', '취약', '정상', '오류']);
    expect(await rows(page, 'scenario-rate')).toEqual(['sandbox-typosquat', 'sandbox-dns-exfil', 'runtime-chain', 'chain-gap-control']);
    // 지연 범위: 격리한 시나리오만(연쇄는 dryRun — 빠짐 안내)
    const lat = await page.locator('[data-chart="latency"] g[data-row]').evaluateAll((gs) => gs.map((g) => [(g as SVGGElement).dataset.row, (g as SVGGElement).dataset.p50, (g as SVGGElement).dataset.p95]));
    expect(lat).toEqual([['sandbox-typosquat', '293.7', '332.4'], ['sandbox-dns-exfil', '308.8', '484.6']]);
    await expect(page.locator('[data-part="latency"] [data-part="latency-skipped"]')).toHaveText('격리하지 않아 빠짐: 런타임 — 연쇄(다운로드 → 외부 연결 → 자격 증명 파일) (dryRun)');
    // 규칙 적중 상위 10: 합 → 악성 적중 → 이름 순서
    const ruleRows = await rows(page, 'rule-hits');
    expect(ruleRows).toHaveLength(10);
    expect(ruleRows[0]).toBe('capability-process-spawn');
    // 마우스 → 툴팁
    await page.locator('[data-chart="scenario-rate"] g[data-row="sandbox-dns-exfil"] rect[data-hit]').hover();
    const tip = page.locator('[data-chart="scenario-rate"] [data-part="chart-tip"]');
    await expect(tip).toBeVisible();
    await expect(tip.locator('> div')).toHaveText(['설치 샌드박스 — DNS 유출 질의', '공격 · 탐지 10 / 10회', '격리 10회 · 규칙 sandbox-dns']);
  });

  test('4 지연 카드 단계별 p50 누적 막대(판정 → 증거 수집 → kill 호출) · x축은 범위 그림과 따로', async ({ page, backend }) => {
    void backend;
    await evalApi(page, ok());
    await page.goto('/evaluation');
    await ready(page);
    const C = '[data-chart="kill-stages"]';
    await expect(page.locator('[data-part="stages-title"]')).toHaveText('단계별 시간 (p50)');
    const st = await page.locator(`${C} g[data-row]`).evaluateAll((gs) =>
      gs.map((g) => [(g as SVGGElement).dataset.row, [...g.querySelectorAll('rect[data-key]')].map((r) => [(r as SVGRectElement).dataset.key, Number((r as SVGRectElement).dataset.v)]), g.querySelector('[data-part="row-value"]')!.textContent]),
    );
    expect(st).toEqual([
      ['all', [['match', 0.1], ['evidence', 132], ['killApi', 181.8]], '합계 314 ms'],
      ['sandbox-typosquat', [['evidence', 119], ['killApi', 176]], '합계 295 ms'], // 판정 p50 0 → 조각 없음
      ['sandbox-dns-exfil', [['match', 0.1], ['evidence', 138.3], ['killApi', 185.6]], '합계 324 ms'],
    ]);
    await expect(page.locator(`${C} g[data-row="all"] [data-part="row-label"]`)).toHaveText('격리된 공격 전체');
    await expect(page.locator(`${C} [data-part="legend"] > span`)).toHaveText(['판정', '증거 수집', 'kill 호출']);
    await expect(page.locator('[data-part="stages-caption"]')).toHaveText('증거를 먼저 모으고(≤0.7초) 격리합니다');
    // 「판정」 조각은 최소 폭 없음 — 0.1ms 는 1px 보다 좁다
    const matchW = await page.locator(`${C} g[data-row="all"] rect[data-key="match"]`).evaluate((e) => (e as SVGRectElement).width.baseVal.value);
    expect(matchW).toBeLessThan(1);
    // 빨강은 위험에만 — 단계 조각 색 3가지, 위험색 없음
    const fills = await page.locator(`${C} rect[data-key]`).evaluateAll((els) => [...new Set(els.map((e) => getComputedStyle(e).fill))]);
    const danger = await page.evaluate(() => {
      const el = document.createElement('i');
      el.style.color = 'var(--danger)';
      document.body.append(el);
      const c = getComputedStyle(el).color;
      el.remove();
      return c;
    });
    expect(fills).toHaveLength(3);
    expect(fills).not.toContain(danger);
    // 툴팁: 단계마다 p50 · p95 + 격리 n회
    await page.locator(`${C} g[data-row="all"] rect[data-hit]`).hover();
    await expect(page.locator(`${C} [data-part="chart-tip"] > div`)).toHaveText(['격리된 공격 전체', '판정 p50 0.1 ms · p95 0.1 ms', '증거 수집 p50 132 ms · p95 162 ms', 'kill 호출 p50 182 ms · p95 234 ms', '격리 20회 기준']);
    // 두 그림 x축은 따로(범위 그림 max 484.6 → 600, 단계 합 max 324 → 400)
    const ticks = (c: string) => page.locator(`[data-chart="${c}"] text[data-part="tick"]`).allTextContents();
    expect(await ticks('latency')).toEqual(['0', '200', '400', '600']);
    expect(await ticks('kill-stages')).toEqual(['0', '100', '200', '300', '400']);
  });

  test('5 모델 비교: 보정 기준 선택 배지 · 규칙 우세 한 줄 · 운영 미적용 · 탭 없음(modelAll 없음)', async ({ page, backend }) => {
    void backend;
    await evalApi(page, ok(NO_ALL));
    await page.goto('/evaluation');
    await ready(page);
    const M = '[data-part="model"]';
    await expect(page.locator(`${M} [data-table="models"] thead th`)).toHaveText(['후보', '보정 F1', '시험 F1', '정밀도', '재현율', '오탐률']);
    const trs = await page.locator(`${M} [data-table="models"] tbody tr`).evaluateAll((els) =>
      els.map((e) => [(e as HTMLElement).dataset.model, e.getAttribute('aria-current'), [...e.querySelectorAll('td')].map((td) => td.textContent)]),
    );
    expect(trs).toEqual([
      ['rule-malicious', null, ['규칙 판정 (악성)', '0.75', '0.90', '98.0%', '83.0%', '0.8%']],
      ['rule-suspicious', null, ['규칙 판정 (악성+주의)', '0.80', '0.94', '98.2%', '89.8%', '0.8%']],
      ['logreg', null, ['로지스틱 회귀', '0.88', '0.85', '77.8%', '94.9%', '13.3%']],
      ['hgb', 'true', ['HistGradientBoosting보정 기준 선택', '0.89', '0.87', '80.9%', '93.2%', '10.8%']],
    ]);
    await expect(page.locator(`${M} [data-part="pick-badge"]`)).toHaveCount(1);
    await expect(page.locator(`${M} [data-part="rule-wins"]`)).toHaveText('시험에서는 규칙 판정이 우세 — 운영은 규칙');
    await expect(page.locator(`${M} [data-part="not-deployed"]`)).toHaveText('운영 미적용');
    await expect(page.locator(`${M} [data-part="model-scope"]`)).toHaveCount(0);
    await expect(page.locator(`${M} [data-part="protocol"]`)).toContainText('seed 42 · packageGroup 그룹 분할 60/20/20 (PyPI) · 선택 기준: 보정 FPR≤5% 에서 F1 최대 · 시험은 선택에 쓰지 않음 · 특징 38개');
    // 결과의 한계 = 세 파일 limits 전부
    const lim = await page.locator('[data-part="limits"] li').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.src));
    const want = (['static', 'runtime', 'model'] as const).flatMap((k) => (REAL[k].limits as string[]).map(() => k));
    expect(lim).toEqual(want);
    await expect(page.locator(`${M} [data-table="models-by-ecosystem"]`)).toHaveCount(0);
  });

  test('6 modelAll(model-all.json 실측) → 「PyPI / 전체」 탭 · 「규칙 우세」 는 PyPI 탭에서만', async ({ page, backend }) => {
    void backend;
    await evalApi(page, ok());
    await page.goto('/evaluation');
    await ready(page);
    const M = '[data-part="model"]';
    const tabs = page.locator(`${M} [data-part="model-scope"] button`);
    await expect(tabs).toHaveText(['PyPI', '전체']);
    await expect(tabs.first()).toHaveAttribute('aria-pressed', 'true');
    // PyPI: 규칙(악성+주의) 시험 F1 0.94 > HGB 0.87 → 한 줄
    await expect(page.locator(`${M} tr[data-model="hgb"] td`).nth(2)).toHaveText('0.87');
    await expect(page.locator(`${M} [data-part="rule-wins"]`)).toHaveText('시험에서는 규칙 판정이 우세 — 운영은 규칙');
    await expect(page.locator(`${M} [data-table="models-by-ecosystem"]`)).toHaveCount(0);
    await tabs.nth(1).click();
    await expect(tabs.nth(1)).toHaveAttribute('aria-pressed', 'true');
    // 전체(PyPI + npm): HGB 0.89 · 오탐 2.2% > 규칙(악성+주의) 0.86 · 1.7% → 규칙 우세 아님
    const trs = await page.locator(`${M} [data-table="models"] tbody tr`).evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.model, [...e.querySelectorAll('td')].map((td) => td.textContent)]));
    expect(trs).toEqual([
      ['rule-malicious', ['규칙 판정 (악성)', '0.85', '0.77', '98.7%', '62.8%', '0.6%']],
      ['rule-suspicious', ['규칙 판정 (악성+주의)', '0.90', '0.86', '96.9%', '76.9%', '1.7%']],
      ['logreg', ['로지스틱 회귀', '0.92', '0.88', '93.5%', '82.6%', '3.9%']],
      ['hgb', ['HistGradientBoosting보정 기준 선택', '0.94', '0.89', '96.2%', '82.6%', '2.2%']],
    ]);
    await expect(page.locator(`${M} [data-part="rule-wins"]`)).toHaveCount(0);
    await expect(page.locator(`${M} [data-part="protocol"]`)).toContainText('packageGroup 그룹 분할 60/20/20 (PyPI + npm, 생태계 · 라벨 층화)');
    await expect(page.locator(`${M} [data-part="protocol"]`)).toContainText('시험 악성 121 · 정상 180');
    // 생태계별 시험 표(byEcosystem)
    const eco = page.locator(`${M} [data-table="models-by-ecosystem"]`);
    await expect(eco.locator('thead th')).toHaveText(['생태계별 시험', 'npm F1 · 오탐률', 'pypi F1 · 오탐률']);
    await expect(eco.locator('tr[data-model="hgb"] td')).toHaveText(['HistGradientBoosting', '0.89', '6.7%', '0.88', '0.0%']);
    // 지표 칸은 PyPI 모델 그대로
    expect((await kpis(page))[5]).toEqual(['model-f1', '0.87', 'HistGradientBoosting · 운영 미적용']);
    // 한계: 전체 범위 모델만의 한계는 「모델(전체)」 태그로 덧붙는다
    const lim = await page.locator('[data-part="limits"] li').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.src));
    expect(lim.filter((x) => x === 'modelAll')).toHaveLength(2);
    await tabs.first().click();
    await expect(page.locator(`${M} [data-part="rule-wins"]`)).toHaveCount(1);
    await shot(page, 'model-all');
  });

  test('7 결과 JSON 내려받기 = 받은 값 그대로', async ({ page, backend }) => {
    void backend;
    await evalApi(page, ok());
    await page.goto('/evaluation');
    await ready(page);
    const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('[data-action="download-json"]').click()]);
    expect(dl.suggestedFilename()).toBe('supplyguard-evaluation-2026-11-04.json');
    const body = JSON.parse(readFileSync((await dl.path())!, 'utf8')) as Json;
    expect(body).toEqual(REAL);
  });

  test('8 결과 없음(404) → 「평가 결과 없음」 · 내려받기 버튼 없음', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/status of 404/);
    await evalApi(page, { status: 404 });
    await page.goto('/evaluation');
    await expect(page.locator(`${W}[data-state="empty"]`)).toBeVisible();
    await expect(page.locator(`${W} [data-part="empty"]`)).toContainText('평가 결과 없음');
    await expect(page.locator('[data-action="download-json"]')).toHaveCount(0);
    await shot(page, 'empty');
  });

  test('9 오류 → 「다시 시도」 → 성공', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/status of 500/);
    const api = await evalApi(page, { status: 500, body: { error: '모의 오류' } });
    await page.goto('/evaluation');
    await expect(page.locator(`${W}[data-state="error"]`)).toBeVisible();
    await expect(page.locator(`${W} [data-part="error"]`)).toContainText('500 · 모의 오류');
    await expect(page.locator('[data-action="download-json"]')).toHaveCount(0);
    api.reply = ok();
    await page.locator(`${W} [data-action="retry"]`).click();
    await ready(page);
    expect(api.calls.at(-1)).toBe(200);
    expect(api.calls.filter((s) => s === 500).length).toBeGreaterThan(0);
  });

  test('10 부분 결과: 없는 쪽 칸만 「… 결과 없음」 · 옛 런타임 파일은 지연 폴백 · 단계 막대 숨김', async ({ page, backend }) => {
    void backend;
    // 정적만
    await evalApi(page, ok({ static: REAL.static, runtime: null, model: null }));
    await page.goto('/evaluation');
    await ready(page);
    await expect(page.locator('[data-chart="verdict-dist"]')).toBeVisible();
    for (const p of ['scenarios', 'latency', 'benign']) await expect(page.locator(`[data-part="${p}"] [data-part="none"]`), p).toHaveText('런타임 결과 없음');
    await expect(page.locator('[data-part="model"] [data-part="none"]')).toHaveText('모델 결과 없음');
    const k = await kpis(page);
    expect(k.map((x) => x[1])).toEqual(['68.0%', '1.5%', '—', '—', '—', '—']);
    await expect(page.locator('[data-part="conclusion"]')).toHaveText('정적 검사: 실제 악성 594개 중 404개 탐지 · 정상 600개 중 9개 오탐');
    await expect(page.locator('[data-part="limits"] li')).toHaveCount((REAL.static.limits as string[]).length);

    // 런타임만 + 옛 파일(killLatencyMs · killStagesMs 없음)
    const old = clone(REAL.runtime);
    delete old.killLatencyMs;
    delete old.killStagesMs;
    await page.unroute(/\/api\/evaluation$/);
    await evalApi(page, ok({ static: null, runtime: old, model: null }));
    await page.reload();
    await ready(page);
    for (const p of ['dist', 'rules', 'confusion']) await expect(page.locator(`[data-part="${p}"] [data-part="none"]`), p).toHaveText('정적 결과 없음');
    const k2 = await kpis(page);
    expect(k2[4]).toEqual(['latency', '308.8 / 484.6 ms', '공격 시나리오 중 가장 느린 값']);
    await expect(page.locator('[data-chart="latency"]')).toBeVisible();
    await expect(page.locator('[data-chart="kill-stages"]')).toHaveCount(0);
    await expect(page.locator('[data-part="stages-caption"]')).toHaveCount(0);
  });

  test('11 다크: 토큰 색(카드 배경 · 악성 막대 · 글자) · 넘침 0', async ({ page, backend }) => {
    void backend;
    await evalApi(page, ok());
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await page.goto('/evaluation');
    await ready(page);
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    const css = await page.evaluate(() => {
      const tok = (v: string) => {
        const el = document.createElement('i');
        el.style.color = `var(${v})`;
        document.body.append(el);
        const c = getComputedStyle(el).color;
        el.remove();
        return c;
      };
      const card = document.querySelector('[data-part="dist"]')!;
      const mal = document.querySelector('[data-chart="verdict-dist"] rect[data-key="malicious"]')!;
      const val = document.querySelector('[data-part="kpis"] [data-value]')!;
      return { card: getComputedStyle(card).backgroundColor, surface: tok('--surface'), mal: getComputedStyle(mal).fill, danger: tok('--danger'), val: getComputedStyle(val).color, text: tok('--text') };
    });
    expect(css.card).toBe(css.surface);
    expect(css.mal).toBe(css.danger);
    expect(css.val).toBe(css.text);
    await noPageOverflow(page);
    await shot(page, 'dark');
  });

  test.describe('390 모바일', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('12 넘침 0 · 한 열(정적 → 런타임) · 지표 2열', async ({ page, backend }) => {
      void backend;
      await evalApi(page, ok());
      await page.goto('/evaluation');
      await ready(page);
      await noPageOverflow(page);
      const over = await page.locator(W).evaluate((e) => e.scrollWidth - e.clientWidth);
      expect(over).toBe(0);
      const cols = await page.locator('[data-part="kpis"]').evaluate((e) => getComputedStyle(e).gridTemplateColumns.split(' ').length);
      expect(cols).toBe(2);
      const sc = (await page.locator('[data-col="static"]').boundingBox())!;
      const rc = (await page.locator('[data-col="runtime"]').boundingBox())!;
      expect(Math.abs(sc.x - rc.x)).toBeLessThan(1);
      expect(rc.y).toBeGreaterThan(sc.y + sc.height - 1);
      await shot(page, 'mobile');
    });
  });

  test('13 조회자도 같은 화면(읽기 전용) · 내려받기 가능', async ({ page, backend }) => {
    backend.auth.asViewer();
    await evalApi(page, ok());
    await page.goto('/evaluation');
    await ready(page);
    await expect(page.getByTestId('page-title')).toHaveText('평가');
    await expect(page.locator('[data-part="kpis"] [data-kpi]')).toHaveCount(6);
    await expect(page.locator('[data-action="download-json"]')).toBeVisible();
    await expect(page.locator(`${W} button:not([data-action]):not([data-part="model-scope"] button)`)).toHaveCount(0);
  });
});
