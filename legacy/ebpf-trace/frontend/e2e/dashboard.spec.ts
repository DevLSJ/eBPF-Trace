import { test, expect } from '@playwright/test';

test('filters, pagination, detail, export and capture selection', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '네트워크 대시보드' })).toBeVisible();
  await expect(page.locator('.pagination')).toContainText('25개 기록');
  await page.getByRole('button', { name: '다음 페이지' }).click();
  await expect(page.locator('.pagination')).toContainText('2 / 2');
  await expect(page.locator('tbody tr')).toHaveCount(5);
  await page.getByLabel('탐지 유형', { exact: true }).selectOption('PORT_SCAN');
  await expect(page.locator('.pagination')).toContainText('4개 기록');
  await expect(page.locator('tbody tr')).toHaveCount(4);
  await page.getByRole('button', { name: '이벤트 25 상세 보기' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('dialog')).toContainText('192.0.2.1:5024');
  await expect(page.getByRole('dialog')).toContainText('미제공 (규칙 기반)');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: '현재 페이지 내보내기' }).click();
  expect((await download).suggestedFilename()).toBe('ebpf-events.json');
  await page.getByLabel('심각도', { exact: true }).selectOption('low');
  await expect(page.locator('.pagination')).toContainText('0개 기록');
  await expect(page.getByText('조건에 맞는 탐지 이벤트가 없습니다.')).toBeVisible();
  await expect(page.getByLabel('캡처 파일')).toBeVisible();
  await page.getByLabel('캡처 파일').selectOption('Thursday-WorkingHours.pcap');
  await expect(page.locator('#capture')).toContainText('정답 레이블이 없어');
  await expect(page.locator('#capture')).toContainText('전체 파일 분석');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: `test-results/dashboard-${test.info().project.name}.png`, fullPage: true });
  expect(errors).toEqual([]);
});

test('threshold authentication, persistence and chart threshold', async ({ page, request }) => {
  const original = await (await request.get('/api/config/thresholds')).json();
  try {
    await page.goto('/#settings');
    await page.getByLabel('ML 이상 점수 임계값').fill('-0.2');
    await page.getByLabel('관리자 토큰').fill('incorrect');
    await page.getByRole('button', { name: '임계값 저장' }).click();
    await expect(page.locator('#settings [role=alert]')).toContainText('Administrator token required');
    await page.getByLabel('관리자 토큰').fill('browser-admin');
    await page.getByRole('button', { name: '임계값 저장' }).click();
    await expect(page.getByText('탐지 임계값을 저장했습니다.')).toBeVisible();
    await expect(page.getByLabel('관리자 토큰')).toHaveValue('');
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('browser-admin');
    await page.reload();
    await expect(page.getByLabel('ML 이상 점수 임계값')).toHaveValue('-0.2');
    await expect(page.getByText('임계값 -0.2', { exact: true })).toBeVisible();
  } finally {
    await request.put('/api/config/thresholds', { data: original, headers: { Authorization: 'Bearer browser-admin' } });
  }
});

test('API error recovery and websocket reconnect restore events', async ({ page }) => {
  let failed = true;
  await page.route('**/api/events?**', route => failed ? route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { message: '테스트 연결 오류' } }) }) : route.continue());
  await page.goto('/');
  await expect(page.getByRole('alert').filter({ hasText: '테스트 연결 오류' })).toBeVisible();
  failed = false;
  await page.getByRole('button', { name: '다시 시도' }).first().click();
  await expect(page.locator('.pagination')).toContainText('25개 기록');
  await expect(page.getByText('실시간 연결됨', { exact: true })).toBeVisible();
  await page.context().setOffline(true);
  await expect(page.locator('.connection')).not.toHaveText('실시간 연결됨', { timeout: 15000 });
  await page.context().setOffline(false);
  await expect(page.getByText('실시간 연결됨', { exact: true })).toBeVisible({ timeout: 15000 });
  await expect(page.locator('tbody tr')).toHaveCount(20);
});
