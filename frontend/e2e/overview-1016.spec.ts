import { expect, SHOTS, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 10/16 eBPF 수집 종합(목업 mock/tests/overview-1016.cjs 확정 → 이식): 판정 대기 아래, 저장된 기록 기반(GET /api/summary)
const OV = '[data-section="overview"]';
const num = (s: string | null) => Number((s ?? '').replace(/[^\d]/g, ''));

test.describe('eBPF 수집 종합', () => {
  // R2 11/04(11/04e 재배치): 「eBPF 수집 종합」 카드 대신 대시보드 전체가 종합 — KPI 줄 → 차트 줄 → 아래 줄(판정 대기가 첫 칸)
  test('KPI · 차트 아래 판정 대기(아래 줄 첫 칸) + 기간 칩(기본 24시간)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    const ov = page.locator(OV);
    await expect(ov.getByTestId('pending')).toBeVisible();
    const [p, k] = await Promise.all([page.getByTestId('pending').boundingBox(), ov.locator('[data-part="kpis"]').boundingBox()]);
    expect(k!.y).toBeLessThan(p!.y);
    await expect.poll(() => ov.locator('[data-range]').evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.range, e.getAttribute('aria-pressed')]))).toEqual([
      ['1h', 'false'],
      ['24h', 'true'],
      ['7d', 'false'],
    ]);
    await page.screenshot({ path: `${SHOTS}/1440-12-dashboard-overview.png` });
  });

  test('숫자 칸 = API 값(수집 · 위반 · 격리 · 설치 검사 · 판정), 종류별 표시', async ({ page, backend }) => {
    await page.goto('/');
    const s = backend.summary('24h');
    const v = (k: string) => page.locator(`${OV} [data-kpi="${k}"] [data-value]`);
    await expect(v('collected')).toHaveText(s.collected.total.toLocaleString('ko-KR'));
    await expect.poll(async () => num(await v('violations').textContent())).toBe(s.violations.total);
    await expect.poll(async () => num(await v('isolated').textContent())).toBe(s.isolatedContainers);
    await expect.poll(async () => num(await v('installs').textContent())).toBe(s.installs.total);
    await expect.poll(async () => num(await v('decided').textContent())).toBe(s.decisions.malicious + s.decisions.falsePositive);
    const kinds = page.locator(`${OV} [data-kpi="collected"]`);
    for (const w of ['실행', '파일', '통신']) await expect(kinds).toContainText(w);
  });

  // R2 11/04(11/04e): 수집량 추이는 종류별 선(path.line[data-kind]), 위반 추이는 쌓은 막대
  test('추이 2개: 24시간 = 24칸, 수집은 종류별 선, 위반은 격리 · 경고', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.locator(`${OV} [data-chart="collected"] [data-bucket]`)).toHaveCount(24);
    await expect(page.locator(`${OV} [data-chart="violations"] [data-bucket]`)).toHaveCount(24);
    const kinds = await page.locator(`${OV} [data-chart="collected"] path.line[data-kind]`).evaluateAll((els) => [...new Set(els.map((e) => (e as SVGElement).dataset.kind))].sort());
    expect(kinds).toEqual(['connect', 'exec', 'open']);
    await expect(page.locator(`${OV} [data-chart="violations"]`)).toContainText('격리');
    await expect(page.locator(`${OV} [data-chart="violations"]`)).toContainText('경고');
  });

  test('상위 규칙 · 컨테이너: 5개 이하, 많은 순, API 와 같다(설치 검사는 패키지 이름)', async ({ page, backend }) => {
    await page.goto('/');
    const s = backend.summary('24h');
    for (const [k, want] of [
      ['rules', s.topRules.slice(0, 5).map((x) => [x.ruleId, x.count])],
      ['containers', s.topContainers.slice(0, 5).map((x) => [x.container, x.count])],
    ] as const) {
      const rows = page.locator(`${OV} [data-top="${k}"] [data-row]`);
      await expect(rows).toHaveCount(want.length);
      expect(await rows.evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.row, Number((e as HTMLElement).dataset.count)]))).toEqual(want);
    }
    await expect(page.locator(`${OV} [data-top="containers"]`)).toContainText('pip ./reqeusts');
  });

  test('설치 검사 · 판정 · 차단 목록 결과', async ({ page, backend }) => {
    await page.goto('/');
    const s = backend.summary('24h');
    const r = page.locator(`${OV} [data-results]`);
    for (const w of ['통과', '격리', '설치 전 거부', '악성', '오탐', '차단 목록']) await expect(r).toContainText(w);
    await expect.poll(async () => num(await r.locator('[data-blocklist-total]').textContent())).toBe(s.blocklist.packages + s.blocklist.images + s.blocklist.hosts);
  });

  test('기간 1시간 → 60칸(주소에 남기지 않음, 10/21), 7일 → 28칸', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await page.locator(`${OV} [data-range="1h"]`).click();
    await expect(page.locator(`${OV} [data-range="1h"]`)).toHaveAttribute('aria-pressed', 'true');
    expect(new URL(page.url()).search).toBe('');
    await expect(page.locator(`${OV} [data-chart="collected"] [data-bucket]`)).toHaveCount(60);
    await page.locator(`${OV} [data-range="7d"]`).click();
    await expect(page.locator(`${OV} [data-chart="collected"] [data-bucket]`)).toHaveCount(28);
  });

  test('새 위반이 들어오면(WS) 위반 숫자가 다시 계산된다', async ({ page, backend }) => {
    await page.goto('/');
    const v = page.locator(`${OV} [data-kpi="violations"] [data-value]`);
    await expect(v).toHaveText(String(backend.summary('24h').violations.total));
    const k = killedVerdict('api-gw');
    backend.audit.unshift({ ...k, id: 999, caseId: null, install: null });
    backend.send({ type: 'verdict', data: k });
    await expect(v).toHaveText(String(backend.summary('24h').violations.total));
  });

  test('종합 API 가 없는 백엔드에서는 그 영역만 「백엔드 미지원」', async ({ page, backend, allowConsole }) => {
    backend.unsupported.add('/summary');
    allowConsole(/Failed to load resource: the server responded with a status of 404/);
    await page.goto('/');
    await expect(page.locator(OV)).toContainText('백엔드 미지원');
    await expect(page.getByTestId('pending')).toBeVisible();
  });
});
