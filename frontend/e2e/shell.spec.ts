import { expect, test } from './fixtures';
import { killedVerdict } from './mock-backend';

test.describe('셸', () => {
  test('사이드바는 시나리오 묶음, 상단은 화면 이름', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    const nav = page.getByRole('navigation', { name: '화면' });
    await expect(nav.locator('[data-nav-group]')).toHaveCount(4);
    for (const g of ['설치 검사', '런타임 감시', '설정 · 기록']) await expect(nav.locator(`[data-nav-group="${g}"]`)).toBeVisible();
    await expect(nav.locator('[data-nav-group="런타임 감시"] a')).toHaveText(['이벤트', '토폴로지']);
    await expect(nav.locator('[data-nav-group="설정 · 기록"] a')).toHaveText(['정책', '감사 로그']);
    for (const [label, title] of [
      ['설치 검사', '설치 검사'],
      ['이벤트', '이벤트'],
      ['토폴로지', '토폴로지'],
      ['정책', '정책'],
      ['감사 로그', '감사 로그'],
      ['대시보드', '대시보드'],
    ]) {
      await nav.getByRole('link', { name: label, exact: false }).first().click();
      await expect(page.getByTestId('page-title')).toHaveText(title);
    }
  });

  test('토스트: 같은 대상끼리 묶음(×N), 8초 뒤 닫힘', async ({ page, backend }) => {
    await page.goto('/events');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    for (let i = 0; i < 3; i++) backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    backend.send({ type: 'verdict', data: killedVerdict('billing') });
    const gw = page.locator('[data-toast="kill:api-gw"]');
    await expect(gw).toHaveCount(1);
    await expect(gw.locator('[data-toast-count]')).toHaveText('×3');
    await expect(page.locator('[data-toast="kill:billing"]')).toHaveCount(1);
    // 알림 배지에 쌓인다
    await expect(page.getByRole('link', { name: /새 위반 \d+건/ })).toContainText(/\d/);
    await page.waitForTimeout(8_400);
    await expect(page.locator('[data-toast]')).toHaveCount(0);
  });

  test('alert/confirm 대화상자를 쓰지 않는다', async ({ page, backend }) => {
    void backend;
    let dialogs = 0;
    page.on('dialog', (d) => {
      dialogs++;
      void d.dismiss();
    });
    await page.goto('/policies?id=sensitive-files');
    await page.getByRole('button', { name: '삭제' }).click();
    await expect(page.getByRole('button', { name: '눌러서 삭제 확정' })).toBeVisible();
    expect(dialogs).toBe(0);
  });
});
