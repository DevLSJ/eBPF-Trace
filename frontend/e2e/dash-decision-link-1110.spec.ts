import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';

// 11/10 사용자:
//   ① 대시보드 「설치 검사 결과」 판정 줄(악성 · 오탐 · 대기)을 누르면 감사 로그가 그 판정으로 걸러진 채 열린다.
//      판정만 걸고 기간은 걸지 않는다(사용자 선택). 필터는 화면 상태(주소에 남기지 않음, 10/21) — 새로고침하면 풀린다.
//   ② 1시간 · 24시간 · 7일 집계는 칸 단위로 맞춰져 있다(계산은 그대로 — 사용자 선택). KPI 카드 툴팁에 실제 집계 범위를 적는다.
const DEC = '[data-part="res-decisions"]';
const ROWS = '[data-view="violations"] tbody tr, table tbody tr';

async function openDecision(page: Page, d: 'malicious' | 'false_positive' | 'pending') {
  await page.goto('/');
  const link = page.locator(`${DEC} a[data-decision="${d}"]`);
  await expect(link).toBeVisible();
  await link.click();
  await expect(page).toHaveURL(/\/audit$/);
}

test.describe('11/10 대시보드 판정 줄 → 감사 로그 판정 필터', () => {
  test('악성: 감사 로그가 악성 건의 기록만 · 판정 칩 · 판정 선택 상자 「악성」 · 주소에 필터 없음 · 새로고침하면 풀림', async ({ page, backend }) => {
    // 악성으로 판정한 건(case-0002)에 묶인 기록 2줄
    const base = backend.audit[0];
    const top = Math.max(...backend.audit.map((a) => a.id));
    for (const i of [1, 2])
      backend.audit.unshift({ ...base, id: top + i, caseId: 'case-0002', install: null, event: { ...base.event, containerName: 'sg-install-pip-x' } });
    await openDecision(page, 'malicious');
    await expect(page.locator('[data-filter="decision"]')).toHaveAttribute('data-value', 'malicious');
    await expect(page.locator('[data-chip="decision"]')).toContainText('판정: 악성');
    await expect(page.getByText('총 2건')).toBeVisible();
    const cells = page.locator(`${ROWS} td[data-col="decision"]`);
    await expect(cells).toHaveCount(2);
    await expect(cells).toHaveText(['악성', '악성']);
    expect(new URL(page.url()).search).toBe('');
    await page.reload();
    await expect(page.locator('[data-filter="decision"]')).not.toHaveAttribute('data-value', 'malicious');
  });

  test('대기: 열린 건의 기록 전부(대시보드 「대기」와 같은 셈) · 모든 줄 「판정 대기」', async ({ page, backend }) => {
    const open = new Set(backend.cases.filter((c) => c.state === 'open').map((c) => c.id));
    const want = backend.audit.filter((a) => a.caseId && open.has(a.caseId)).length;
    expect(want).toBeGreaterThan(0);
    await openDecision(page, 'pending');
    await expect(page.locator('[data-chip="decision"]')).toContainText('판정: 판정 대기');
    await expect(page.getByText(`총 ${want}건`)).toBeVisible();
    const cells = page.locator(`${ROWS} td[data-col="decision"]`);
    expect(await cells.count()).toBeGreaterThan(0);
    for (const t of await cells.allInnerTexts()) expect(t).toBe('판정 대기');
  });

  test('오탐: 판정 필터 「오탐」 · 걸리는 기록이 없으면 빈 목록', async ({ page, backend }) => {
    void backend;
    await openDecision(page, 'false_positive');
    await expect(page.locator('[data-filter="decision"]')).toHaveAttribute('data-value', 'false_positive');
    await expect(page.locator('[data-chip="decision"]')).toContainText('판정: 오탐');
    await expect(page.getByText('총 0건')).toBeVisible();
  });

  test('감사 로그 거르기 줄에 「판정」 선택 상자 — 고르면 그 판정만', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await page.locator('[data-filter="decision"]').click();
    await page.getByRole('option', { name: '판정 대기' }).click();
    await expect(page.locator('[data-chip="decision"]')).toContainText('판정: 판정 대기');
    for (const t of await page.locator(`${ROWS} td[data-col="decision"]`).allInnerTexts()) expect(t).toBe('판정 대기');
  });
});

test.describe('11/10 대시보드 KPI 툴팁 — 실제 집계 범위', () => {
  for (const [range, re] of [
    ['24h', /집계 범위 \d{4}-\d{2}-\d{2} \d{2}:00:00 ~ 지금/],
    ['1h', /집계 범위 \d{4}-\d{2}-\d{2} \d{2}:\d{2}:00 ~ 지금/],
  ] as const) {
    test(`${range}: KPI 6칸 툴팁 끝 줄에 집계 범위(칸 경계 시각 ~ 지금)`, async ({ page, backend }) => {
      void backend;
      await page.goto('/');
      if (range !== '24h') await page.locator(`[data-range="${range}"]`).click();
      const cards = page.locator('[data-kpi]');
      await expect(cards).toHaveCount(6);
      for (const c of await cards.all()) await expect(c).toHaveAttribute('title', re);
    });
  }
});
