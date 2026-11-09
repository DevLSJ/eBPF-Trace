import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';

// 11/06 결정 B(11/09 구현) — 설치 검사 화면 「사용 방법」: ① 내려받기(/api/tools/sg-install, 서버와 같은 판) ② 환경 변수
// (SUPPLYGUARD_API · 관리자는 SANDBOX_TOKEN 을 채운 명령, 화면에는 가린 채 — 녹화 · 발표 화면에 토큰이 보이지 않게) ③ 실행 · 결과(종료 코드).

const guide = (p: Page) => p.locator('[data-part="sginstall-guide"]');

async function openGuide(page: Page) {
  await page.goto('/installs');
  await page.getByTestId('page-actions').getByRole('button', { name: '사용 방법' }).click();
  await expect(guide(page)).toBeVisible();
}

test.describe('설치 검사 「사용 방법」 (11/09)', () => {
  test('1 세 단계 — 내려받기 링크 · 실행 주소 · 실행 명령 · 종료 코드 7개, mock 은 토큰 줄 없음', async ({ page, backend }) => {
    await openGuide(page);
    await expect(guide(page).locator('[data-step]')).toHaveCount(3);
    const dl = guide(page).getByRole('link', { name: 'sg-install 내려받기' });
    await expect(dl).toHaveAttribute('href', '/api/tools/sg-install');
    await expect(dl).toHaveAttribute('download', 'sg-install');
    await expect(guide(page).locator('[data-step="env"]')).toContainText('export SUPPLYGUARD_API=http://127.0.0.1:8000');
    await expect(guide(page).locator('[data-step="env"]')).not.toContainText('SUPPLYGUARD_SANDBOX_TOKEN');
    await expect(guide(page).locator('[data-step="run"]')).toContainText('./sg-install pip requests');
    await expect(guide(page).locator('[data-part="exit-codes"] tbody tr')).toHaveCount(7);
    await expect(guide(page)).toContainText('감시받는 서버');
    expect(backend.requests.some((r) => r.method === 'GET' && r.path === '/sginstall/setup')).toBe(true);
  });

  test('2 관리자 — 토큰을 채우되 화면에는 가림, 「보기」로만 펼침 · 복사는 실제 값', async ({ page, backend, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    backend.sgSetup = { download: '/api/tools/sg-install', api: 'http://127.0.0.1', tokenRequired: true, token: 'sbx-1234567890abcdef', reporting: true };
    await openGuide(page);
    const env = guide(page).locator('[data-step="env"]');
    await expect(env).toContainText('export SUPPLYGUARD_API=http://127.0.0.1');
    await expect(env).toContainText('export SUPPLYGUARD_SANDBOX_TOKEN=sbx-••••');
    await expect(env).not.toContainText('sbx-1234567890abcdef');
    await env.getByRole('button', { name: '토큰 보기' }).click();
    await expect(env).toContainText('export SUPPLYGUARD_SANDBOX_TOKEN=sbx-1234567890abcdef');
    await env.getByRole('button', { name: '토큰 가리기' }).click();
    await expect(env).not.toContainText('sbx-1234567890abcdef');
    await env.getByRole('button', { name: '환경 변수 복사' }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('export SUPPLYGUARD_SANDBOX_TOKEN=sbx-1234567890abcdef');
    await expect(page.locator('body')).not.toContainText('sbx-1234567890abcdef'); // 복사 알림에도 토큰을 보이지 않는다
  });

  test('3 조회자 — 토큰이 필요하다는 것만(자리 표시), 보고 꺼짐이면 경고 · 서버에 스크립트 없으면 저장소 안내', async ({ page, backend }) => {
    backend.sgSetup = { api: 'http://127.0.0.1', tokenRequired: true, reporting: true };
    await openGuide(page);
    await expect(guide(page).locator('[data-step="env"]')).toContainText('export SUPPLYGUARD_SANDBOX_TOKEN=<관리자에게 받은 SANDBOX_TOKEN>');
    await expect(guide(page).getByRole('link', { name: 'sg-install 내려받기' })).toHaveCount(0);
    await expect(guide(page).locator('[data-step="download"]')).toContainText('tools/sg-install');

    await page.keyboard.press('Escape');
    backend.sgSetup = { api: 'http://127.0.0.1', tokenRequired: false, reporting: false };
    await page.reload();
    await page.getByTestId('page-actions').getByRole('button', { name: '사용 방법' }).click();
    await expect(guide(page).locator('[data-part="reporting-off"]')).toContainText('SANDBOX_TOKEN');
  });

  test('4 설치 기록이 없을 때 빈 화면에서도 「사용 방법」을 연다', async ({ page, backend }) => {
    backend.installs = [];
    await page.goto('/installs');
    await page.getByTestId('installs-empty').getByRole('button', { name: '사용 방법' }).click();
    await expect(guide(page)).toBeVisible();
  });
});
