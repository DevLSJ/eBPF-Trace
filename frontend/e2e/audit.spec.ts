import { expect, test } from './fixtures';

test.describe('감사 로그 — 언제 무엇이 걸렸고, 어떻게 닫혔나?', () => {
  test('① 위반마다 판정 결과 열, 설치 검사 위반은 패키지 이름', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await expect(page.locator('tr[data-audit]')).toHaveCount(backend.audit.length);
    const install = page.locator('tr[data-audit]', { hasText: 'pip ./reqeusts' }).first();
    await expect(install).toContainText('설치 검사');
    await expect(install.locator('[data-col="decision"] [data-decision="pending"]')).toHaveText('판정 대기');
    // 설치 건이 없는 경고만 있는 위반은 건이 없다(런타임 경고는 열린 건에 묶임 — decisions-1015b)
    await expect(page.locator('tr[data-audit]', { hasText: 'egress-allowlist' }).filter({ hasText: 'tiny-git-dep' }).first().locator('[data-col="decision"] [data-decision="pending"]')).toBeVisible();
    // 사유 열은 없고 시트에
    expect(await page.locator('thead th').allTextContents()).not.toContain('사유');
    await install.click();
    await expect(page).toHaveURL(/id=\d+/);
    await expect(page.locator('[data-sheet="audit"]').getByTestId('audit-reason')).not.toBeEmpty();
  });

  test('② 판정 · 정책 변경 이력', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await page.getByRole('button', { name: '판정 · 변경 이력' }).click();
    await expect(page).toHaveURL(/view=changes/);
    const h = page.getByTestId('history');
    await expect(h.locator('[data-history="case:case-0002"]')).toContainText('악성');
    await expect(h.locator('[data-history="chg:chg-0001"]')).toContainText('제안 적용');
  });

  test('③ 기간 조회는 여기만 — 필터는 주소에 남기지 않고(10/21) 서버에 넘긴다', async ({ page, backend }) => {
    await page.goto('/audit');
    await page.getByLabel('기간 시작').fill('2020-01-01T00:00');
    await page.locator('[data-filter="kind"]').click(); // 11/09 공통 Select
    await page.getByRole('option', { name: 'connect', exact: true }).click();
    await expect(page.locator('[data-filter="kind"]')).toHaveAttribute('data-value', 'connect');
    await expect(page.getByLabel('기간 시작')).toHaveValue('2020-01-01T00:00');
    expect(new URL(page.url()).search).toBe('');
    await expect.poll(() => backend.requests.some((r) => r.path.startsWith('/audit?') && r.path.includes('kind=connect') && r.path.includes('since=2019-12-31T15'))).toBe(true);
    await expect(page.locator('tr[data-audit]')).toHaveCount(backend.audit.filter((a) => a.event.kind === 'connect').length);
  });

  test('페이지 고정 · 표만 스크롤', async ({ page, backend }) => {
    const base = backend.audit[0];
    backend.audit = Array.from({ length: 100 }, (_, i) => ({ ...base, id: 1000 - i }));
    await page.goto('/audit');
    // R4 11/04: 「더 보기」(100행씩) 대신 쪽 번호 바닥줄(페이지당 20 · 50 · 100) — 100행을 보려면 페이지당 100
    await expect(page.locator('tr[data-audit]')).toHaveCount(20);
    await page.locator('[data-table-foot="audit"] select[data-part="page-size"]').selectOption('100');
    await expect(page.locator('tr[data-audit]')).toHaveCount(100);
    const s = await page.getByTestId('audit-scroll').evaluate((el) => ({ sh: el.scrollHeight, ch: el.clientHeight }));
    expect(s.sh).toBeGreaterThan(s.ch);
    const doc = await page.evaluate(() => document.documentElement.scrollHeight - innerHeight);
    expect(doc).toBe(0);
    await expect(page.getByRole('button', { name: '더 보기' })).toHaveCount(0);
    await expect(page.locator('[data-table-foot="audit"] [data-part="range"]')).toHaveText('총 100건 · 1/1 페이지');
  });
});
