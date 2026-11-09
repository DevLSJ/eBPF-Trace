import { expect, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 새 API 가 아직 백엔드에 없을 때(라우트 없음 → 404): 그 영역만 「백엔드 미지원」, 기존 화면은 그대로 동작
test.describe('백엔드 미지원', () => {
  test.beforeEach(({ backend, allowConsole }) => {
    for (const p of ['/installs', '/cases', '/proposals', '/blocklist', '/changes', '/osv', '/policies/preview']) backend.unsupported.add(p);
    allowConsole(/Failed to load resource: the server responded with a status of 404/);
  });

  test('새 영역은 안내만, 앱은 깨지지 않는다', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByTestId('pending').locator('[data-unsupported]')).toContainText('백엔드 미지원');
    await page.goto('/installs');
    await expect(page.getByTestId('installs').locator('[data-unsupported]')).toContainText('백엔드 미지원');
    await page.goto('/policies');
    await expect(page.getByTestId('proposals').locator('[data-unsupported]')).toBeVisible();
    // 정책 목록은 그대로(11/09 — 시트는 저절로 열지 않음)
    await expect(page.locator('[data-rule="sensitive-files"]')).toBeVisible();
    // 11/09: 차단 목록 · 변경 이력은 「정책」 아래 각자 페이지
    await page.goto('/policies/blocklist');
    await expect(page.getByTestId('blocklist').locator('[data-unsupported]')).toBeVisible();
    await page.goto('/policies/changes');
    await expect(page.getByTestId('changes').locator('[data-unsupported]')).toBeVisible();
  });

  test('기존 동작: WS 피드 · 정책 저장 · 감사 조회', async ({ page, backend }) => {
    await page.goto('/events');
    backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    await expect(page.locator('li[data-key]').first()).toContainText('api-gw');

    await page.goto('/policies?id=pipe-to-shell');
    await page.locator('[data-view="rule-editor"] input[data-field="description"]').fill('curl | sh (수정)');
    await page.getByRole('button', { name: '저장 전 확인' }).click(); // 옛 백엔드엔 미리보기가 없어도 저장은 된다(10/16)
    await expect(page.locator('[data-part="save-check"]')).toContainText('미리보기를 계산하지 못했습니다');
    await page.locator('[data-part="save-check"]').getByRole('button', { name: '저장 후 적용' }).click();
    await expect(page.getByText('저장 후 엔진에 적용됨')).toBeVisible();
    expect(backend.writes().some((r) => r.method === 'POST' && r.path === '/policies')).toBe(true);

    await page.goto('/audit?kind=exec');
    await expect(page.locator('tr[data-audit]')).toHaveCount(backend.audit.filter((a) => a.event.kind === 'exec').length);
    await expect(page.locator('tr[data-audit] [data-col="decision"]').first()).toHaveText('—');
  });
});
