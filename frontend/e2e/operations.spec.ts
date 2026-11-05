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

test('beginner guidance: next-step hints, plain-language gate reasons and friendly feedback', async ({ page }) => {
  test.setTimeout(60000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await signIn(page);
  // 게이트 거부 훈련: 왜 승인이 필요한지 쉬운 문장으로 설명되는지
  await page.getByRole('button', { name: '공유 출발지 훈련 · 게이트 거부 확인' }).click();
  await expect(page.locator('.ops-case-header')).toContainText('SIMULATION', { timeout: 20000 });
  await expect(page.locator('.ops-notice')).toContainText('차단 안전 점검(Gate)');
  await expect(page.locator('.ops-next .ops-guide')).toContainText('확인 기한 타이머가 멈추고');
  // 인수 → 친절한 피드백과 다음 단계 안내
  await page.getByRole('button', { name: '확인하고 맡기', exact: true }).click();
  await expect(page.locator('.ops-notice')).toContainText('이 사건을 맡았어요');
  await expect(page.locator('.ops-next .ops-guide')).toContainText('[조사 시작]');
  await (test.info().project.name === 'desktop' ? page.locator('.ops-case-side') : page).screenshot({ path: `test-results/next-step-${test.info().project.name}.png` });
  // 대응 탭: 출발지별 차단 안전 점검(Gate) 결과가 쉬운 문장으로 설명되는지
  await page.getByRole('tab', { name: '대응', exact: true }).click();
  await expect(page.locator('.ops-auto-line')).toContainText('자동 해제 시간(TTL)');
  const gate = page.locator('.ops-gate').first();
  await expect(gate).toBeVisible();
  await expect(gate.locator('.ops-gate-why')).toContainText(/승인이 필요해요|자동 차단이 가능해요/);
  await expect(gate).toContainText('기준선');
  await gate.locator('summary').click();
  await expect(gate.locator('.ops-gate-signals')).toBeVisible();
  await expect(gate.locator('.ops-gate-signals')).toContainText('가중치');
  await gate.screenshot({ path: `test-results/gate-explained-${test.info().project.name}.png` });
  // 정리: 훈련 사건을 오탐으로 종결해 다음 프로젝트(모바일)의 훈련이 이 사건에 합쳐지지 않게 한다
  await page.getByLabel('상태 변경 근거').fill('훈련 종료 · 게이트 설명 확인 완료');
  await page.getByText('다른 종결 사유', { exact: true }).click();
  await page.getByRole('button', { name: '오탐으로 종결', exact: true }).click();
  await expect(page.locator('.ops-notice')).toContainText('오탐으로 종결했어요');
  await expect(page.locator('.ops-case-top .ops-badge').nth(1)).toHaveText('오탐 종결');
  await expect(page.locator('.ops-next .ops-guide')).toContainText('[타임라인]');
  // 훈련 시나리오(9초)가 끝날 때까지 기다려 다음 테스트의 훈련 시작이 "이미 실행 중"으로 거부되지 않게 한다
  await expect.poll(async () => (await (await page.request.get('/api/scenarios/runs')).json()).items.some((r: { status: string }) => r.status === 'running'), { timeout: 20000 }).toBe(false);
  // 대응 관리: 킬 스위치·자동 경로 설명과 빈 값 문구
  await page.goto('/#actions');
  await expect(page.locator('.ops-control').first()).toContainText('모든 대응 멈춤(Kill switch)');
  await expect(page.locator('.ops-control').nth(1)).toContainText('자동 해제 시간(TTL)');
  await expect(page.locator('.ops-control').nth(1)).not.toContainText('—');
  await page.goto('/#operations');
  await expect(page.locator('.ops-outcomes')).toContainText(/아직 측정되지 않음|초|분/);
  await expect(page.locator('.ops-metric-grid')).not.toContainText('—');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);
});
