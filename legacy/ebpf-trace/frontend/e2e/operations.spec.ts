import { test, expect, type Page } from '@playwright/test';

async function signIn(page: Page, username = 'operator') {
  await page.goto('/#incidents');
  await page.getByLabel('사용자 이름', { exact: true }).fill(username);
  await page.getByLabel('비밀번호', { exact: true }).fill('browser-test-password');
  await page.getByRole('button', { name: '워크스페이스 열기' }).click();
  await expect(page.getByRole('heading', { name: '사건 받은편지함' })).toBeVisible();
}

test('incident ownership, separate approval, agent receipts and verified recovery', async ({ page, browser }) => {
  test.setTimeout(90000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  const stateBadge = page.locator('.ops-case-top .ops-badge').nth(1);
  await signIn(page);
  await page.getByRole('button', { name: '대응 훈련 시작' }).click();
  await expect(page.getByLabel('관제 데이터 출처')).toHaveValue('simulation');
  await expect(page.locator('.ops-case-header')).toContainText('SIMULATION', { timeout: 20000 });
  await expect(page.locator('.ops-case-header')).toContainText('훈련용 결제 API');
  await page.getByRole('button', { name: '확인하고 맡기', exact: true }).click();
  await expect(page.locator('.ops-case-meta')).toContainText('김민서');
  await page.getByLabel('상태 변경 근거').fill('SYN 유입과 정상 서비스 관측 확인');
  await page.getByRole('button', { name: '조사 시작', exact: true }).click();
  await expect(stateBadge).toHaveText('조사 중');
  await page.getByRole('tab', { name: '대응', exact: true }).click();
  await page.getByLabel('대응 요청 근거').fill('격리된 훈련 대상과 기한부 정책을 검토했습니다');
  await page.getByRole('button', { name: '대응 미리보기 생성' }).click();
  await expect(page.locator('.ops-preview')).toContainText('본인이 요청한 대응은 다른 승인자가');
  const incidentUrl = page.url();
  await page.screenshot({ path: `test-results/response-preview-${test.info().project.name}.png`, fullPage: true });
  const otherContext = await browser.newContext({ viewport: { width: 1440, height: 1000 }, baseURL: 'http://127.0.0.1:15173' });
  const approvalPage = await otherContext.newPage();
  await signIn(approvalPage, 'approver');
  await approvalPage.goto(incidentUrl);
  await approvalPage.getByRole('tab', { name: '대응', exact: true }).click();
  await approvalPage.getByLabel('대상·보호 주소·기한과 정상 서비스 영향을 검토했습니다.').check();
  await approvalPage.getByLabel('승인 근거', { exact: true }).fill('별도 승인자 검토 및 제한 범위 확인');
  await approvalPage.getByRole('button', { name: '대응 승인 및 실행' }).click();
  await expect(approvalPage.locator('.ops-run').first()).toContainText('적용 확인', { timeout: 12000 });
  await otherContext.close();
  await expect(page.locator('.ops-run .ops-badge')).toHaveText('적용 확인', { timeout: 12000 });
  await expect(stateBadge).toHaveText('적용 대기');
  await page.getByLabel('상태 변경 근거').fill('유입 감소와 정상 요청 성공률 100% 확인');
  await expect(page.getByRole('button', { name: '억제 효과 확인', exact: true })).toBeEnabled({ timeout: 12000 });
  await page.getByRole('button', { name: '억제 효과 확인', exact: true }).click();
  await expect(stateBadge).toHaveText('억제 확인');
  await page.getByRole('tab', { name: '대응', exact: true }).click();
  await page.getByLabel(/^해제 근거 /).fill('억제 검증 후 정상 서비스 복구 관찰');
  await page.getByRole('button', { name: '즉시 해제 요청' }).click();
  await expect(page.locator('.ops-run .ops-badge')).toHaveText('해제 확인', { timeout: 12000 });
  await page.getByLabel('상태 변경 근거').fill('정책 해제 보고와 연속 정상 서비스 관측');
  await expect(page.getByRole('button', { name: '복구 관찰 시작' })).toBeEnabled({ timeout: 12000 });
  await page.getByRole('button', { name: '복구 관찰 시작' }).click();
  await expect(stateBadge).toHaveText('복구 관찰');
  await page.getByLabel('상태 변경 근거').fill('안정화 관찰 후 정상 서비스 복구 확인');
  await expect(page.getByRole('button', { name: '정상 복구 확인' })).toBeDisabled();
  await expect(page.getByRole('button', { name: '정상 복구 확인' })).toBeEnabled({ timeout: 22000 });
  await page.getByRole('button', { name: '정상 복구 확인' }).click();
  await expect(stateBadge).toHaveText('복구 완료');
  await page.getByRole('tab', { name: '타임라인' }).click();
  await expect(page.locator('.ops-timeline')).toContainText('별도 승인자 승인');
  await expect(page.locator('.ops-timeline')).toContainText('정상 복구 확인');
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: '보고서', exact: true }).click();
  expect((await pending).suggestedFilename()).toMatch(/^incident-.*\.json$/);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: `test-results/incident-recovered-${test.info().project.name}.png`, fullPage: true });
  await page.reload();
  await expect(stateBadge).toHaveText('복구 완료');
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('browser-test-password');
  expect(errors).toEqual([]);
});

test('operations dashboard, asset registration, delivery evidence and model gates', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await signIn(page);
  await page.goto('/#assets');
  await page.getByRole('button', { name: '자산 등록', exact: true }).click();
  await page.getByLabel('자산 이름').fill(`검증 API ${test.info().project.name}`);
  await page.getByLabel('자산 IP').fill(test.info().project.name === 'desktop' ? '192.0.2.42' : '192.0.2.43');
  await page.getByLabel('보호 CIDR').fill('192.0.2.1/32');
  await page.getByRole('button', { name: '자산 저장' }).click();
  await expect(page.locator('.ops-asset-grid')).toContainText(`검증 API ${test.info().project.name}`);
  for (const path of ['#operations', '#actions', '#notifications', '#models', '#assets']) {
    await page.goto('/' + path);
    await expect(page.locator('.ops-page-head h1')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await page.screenshot({ path: `test-results/ops-${path.slice(1)}-${test.info().project.name}.png`, fullPage: true });
  }
  await page.goto('/#models');
  await expect(page.getByText('등록된 Shadow 후보가 없습니다')).toBeVisible();
  await page.getByRole('button', { name: '운영자 로그아웃' }).click();
  await expect(page.getByRole('heading', { name: '운영자 로그인' })).toBeVisible();
  expect(errors).toEqual([]);
});
