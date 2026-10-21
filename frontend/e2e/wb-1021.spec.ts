import { expect, test } from './fixtures';

// W-B (10/21): 「30초마다 저절로 다시 불러 봅니다」 문구와 실제 동작을 맞춘다
// — 증거 탭도 오류 동안 30초마다 다시 부르고, 「백엔드 미지원」(라우트 없음)은 다시 불러도 같으니 재시도하지 않는다

const reqs = (b: { requests: { method: string; path: string }[] }, re: RegExp) => b.requests.filter((r) => r.method === 'GET' && re.test(r.path));

test.describe('자동 재시도', () => {
  test('증거 탭: 불러오기 실패 동안 30초마다 다시 부르고, 풀리면 증거를 보인다(시계 조작)', async ({ page, backend, allowConsole }) => {
    allowConsole(/503/);
    await page.clock.install();
    const row = backend.audit.find((a) => a.enforced)!;
    backend.failing.set('/evidence', 503);
    await page.goto(`/audit?id=${row.id}&tab=evidence`);
    const err = page.locator('[data-sheet="audit"] [data-part="error"]');
    await expect(err).toContainText('30초마다');
    const first = reqs(backend, /^\/evidence\?/).length;
    await page.clock.fastForward(20_000);
    await page.waitForTimeout(200);
    expect(reqs(backend, /^\/evidence\?/).length).toBe(first);
    await page.clock.fastForward(11_000);
    await expect.poll(() => reqs(backend, /^\/evidence\?/).length).toBe(first + 1);
    await expect(err).toBeVisible();
    backend.failing.delete('/evidence');
    await page.clock.fastForward(30_000);
    await expect(page.locator('[data-sheet="audit"] [data-part="evidence-empty"]')).toBeVisible();
    await expect(err).toHaveCount(0);
  });

  test('백엔드 미지원(라우트 없음)은 30초가 지나도 다시 부르지 않는다', async ({ page, backend, allowConsole }) => {
    allowConsole(/404/);
    await page.clock.install();
    backend.unsupported.add('/installs');
    await page.goto('/installs?status=all');
    await expect(page.locator('[data-part="error"][data-unsupported]')).toContainText('백엔드 미지원');
    const first = reqs(backend, /^\/installs\?limit=/).length;
    expect(first).toBeGreaterThan(0);
    await page.clock.fastForward(31_000);
    await page.waitForTimeout(300);
    await page.clock.fastForward(31_000);
    await page.waitForTimeout(300);
    expect(reqs(backend, /^\/installs\?limit=/).length).toBe(first);
  });
});
