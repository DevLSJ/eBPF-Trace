import { test, expect } from '@playwright/test';

test('full-week evidence, model comparison and legacy context availability', async ({ page, request }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const analysis = await (await request.get('/api/analysis/model')).json();
  expect(analysis.context_evaluation.deployment_approved).toBe(false);
  expect(analysis.context_evaluation.candidates).toHaveLength(5);
  await page.goto('/#capture');
  await expect(page.locator('.dataset-day')).toHaveCount(5);
  await expect(page.locator('.benchmark-coverage')).toContainText('4 / 14종');
  await expect(page.locator('.benchmark-coverage')).toContainText('시험에 없는 유형');
  await page.getByLabel('캡처 파일').selectOption('Monday-WorkingHours.pcap');
  await expect(page.locator('.label-bars')).toContainText('BENIGN');
  await expect(page.locator('.label-row')).toHaveCount(1);
  await expect(page.locator('.evidence-panel')).toContainText('1초 불확실성');
  await page.getByLabel('비교 모델').selectOption('if_25');
  const candidate = analysis.context_evaluation.candidates.find((item: { id: string }) => item.id === 'if_25');
  await expect(page.locator('.benchmark-metrics')).toContainText(`${(candidate.performance.f1 * 100).toFixed(2)}%`);
  await page.getByRole('button', { name: '학습형 AI(HGB) · 25개', exact: true }).click();
  await expect(page.getByLabel('비교 모델')).toHaveValue('hgb_25');
  await page.getByText('유형별 표본·미탐·오탐 확인', { exact: true }).click();
  await expect(page.locator('.benchmark-label-details')).toContainText('BENIGN · 탐지는 오탐');
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: '실험 보고서', exact: true }).click();
  expect((await pending).suggestedFilename()).toBe('context-feature-benchmark.json');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.locator('.benchmark-panel').screenshot({ path: `test-results/benchmark-${test.info().project.name}.png` });
  await page.goto('/#overview');
  await page.getByRole('button', { name: '이벤트 25 상세 보기' }).click();
  await page.getByText('목적지·양방향 탐지 근거', { exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('이 기록은 이전 Collector 피처입니다');
  expect(errors).toEqual([]);
});

test('filters, pagination, detail, export and capture selection', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/#overview');
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
  await page.goto('/#capture');
  await expect(page.getByLabel('캡처 파일')).toBeVisible();
  await page.getByLabel('캡처 파일').selectOption('Thursday-WorkingHours.pcap');
  await expect(page.locator('#capture')).toContainText('정답 레이블 분포');
  await expect(page.locator('#capture')).toContainText('전체 파일 분석');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: `test-results/dashboard-${test.info().project.name}.png`, fullPage: true });
  expect(errors).toEqual([]);
});

test('threshold authentication, persistence and chart threshold', async ({ page, request }) => {
  const original = await (await request.get('/api/config/thresholds')).json();
  try {
    await page.goto('/#settings');
    await page.getByLabel('AI 이상 점수 임계값').fill('-0.2');
    await page.getByLabel('관리자 토큰').fill('incorrect');
    await page.getByRole('button', { name: '임계값 저장' }).click();
    await expect(page.locator('#settings [role=alert]')).toContainText('관리자 비밀키가 필요합니다');
    await page.getByLabel('관리자 토큰').fill('browser-admin');
    await page.getByRole('button', { name: '임계값 저장' }).click();
    await expect(page.getByText('탐지 임계값을 저장했습니다.')).toBeVisible();
    await expect(page.getByLabel('관리자 토큰')).toHaveValue('');
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('browser-admin');
    await page.reload();
    await expect(page.getByLabel('AI 이상 점수 임계값')).toHaveValue('-0.2');
    await page.goto('/#overview');
    await expect(page.getByText('임계값 -0.2', { exact: true })).toBeVisible();
  } finally {
    await request.put('/api/config/thresholds', { data: original, headers: { Authorization: 'Bearer browser-admin' } });
  }
});

test('API error recovery and websocket reconnect restore events', async ({ page }) => {
  let failed = true;
  await page.route('**/api/events?**', route => failed ? route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { message: '테스트 연결 오류' } }) }) : route.continue());
  await page.goto('/#overview');
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


test('analysis evidence, capture switching, download and navigation', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/#capture');
  await expect(page.getByRole('heading', { name: 'CIC-IDS-2017 분석 워크스페이스' })).toBeVisible();
  await expect(page.locator('.capture-stats')).toContainText('3,357,642');
  await expect(page.locator('.label-bars')).toContainText('DDoS');
  await expect(page.locator('.model-runtime')).toContainText('현재 운영 엔진: 규칙만 사용');
  await expect(page.locator('.evaluation-status')).toContainText('운영 미승인');
  await page.getByLabel('캡처 파일').selectOption('Thursday-WorkingHours.pcap');
  await expect(page.locator('.capture-stats')).toContainText('2,599,785');
  await expect(page.locator('.label-bars')).toContainText('Infiltration');
  await expect(page.locator('.label-bars')).not.toContainText('DDoS');
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: '분석 JSON' }).click();
  const download = await pending;
  expect(download.suggestedFilename()).toBe('Thursday-WorkingHours-analysis.json');
  const stream = await download.createReadStream();
  let body = '';
  for await (const chunk of stream!) body += chunk;
  const exported = JSON.parse(body);
  expect(exported.capture.source).toBe('Thursday-WorkingHours.pcap');
  expect(exported.capture.labels.counts.matched).toBe(2170602);
  expect(exported.capture.labels.alignment.capture_sha256).toBe(exported.capture.sha256);
  expect(exported.model.evaluation.deployment_approved).toBe(false);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: `test-results/analysis-${test.info().project.name}.png`, fullPage: true });
  expect(errors).toEqual([]);
});

test('IP search, reset and independent analysis error recovery', async ({ page }) => {
  await page.goto('/#overview');
  await page.getByLabel('IP 주소 검색').fill('192.0.2.99');
  await page.getByRole('button', { name: '검색', exact: true }).click();
  await expect(page.locator('.pagination')).toContainText('0개 기록');
  await page.getByRole('button', { name: '초기화', exact: true }).click();
  await expect(page.locator('.pagination')).toContainText('25개 기록');
  await page.getByLabel('IP 주소 검색').fill('192.0.2.2');
  await page.getByRole('button', { name: '검색', exact: true }).click();
  await expect(page.locator('.pagination')).toContainText('25개 기록');
  let failed = true;
  await page.route('**/api/analysis/model', route => failed ? route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { message: '평가 조회 테스트 오류' } }) }) : route.continue());
  await page.goto('/#capture');
  await expect(page.locator('.model-panel [role=alert]')).toContainText('평가 조회 테스트 오류');
  await expect(page.locator('.label-bars')).toContainText('DDoS');
  failed = false;
  await page.locator('.model-panel').getByRole('button', { name: '다시 시도' }).click();
  await expect(page.locator('.evaluation-metrics')).toBeVisible();
});

test('scenario execution persists graphs, isolates live traffic and links reviewed DB events', async ({ page }) => {
  test.setTimeout(45000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('/#scenarios');
  await expect(page.getByRole('heading', { name: '탐지 시나리오', exact: true })).toBeVisible();
  await page.getByLabel('관리자 토큰', { exact: true }).fill('browser-admin');
  const started = page.waitForResponse(response => response.url().endsWith('/api/scenarios/runs') && response.request().method() === 'POST' && response.ok());
  await page.getByRole('button', { name: '침입 탐지 리허설 실행' }).click();
  const runId = (await (await started).json()).id;
  await expect(page.locator('.run-title code')).toHaveText(runId);
  await expect(page.locator('.run-status')).toHaveText('완료', { timeout: 22000 });
  await expect(page.locator('.run-stats > div strong').first()).toHaveText(/^15\s*\/\s*15$/);
  await expect(page.getByLabel('관리자 토큰', { exact: true })).toHaveValue('');
  await page.reload();
  await expect(page.locator('.run-title code')).toHaveText(runId);
  await expect(page.locator('.run-stats > div strong').first()).toHaveText(/^15\s*\/\s*15$/);
  await expect(page.locator('.scenario-timeline .recorded')).toHaveCount(5);
  // 이야기형 진행 표시: 5단계 완료 체크 + 실측 기반 결과 요약 문장
  await expect(page.locator('.scenario-timeline .done')).toHaveCount(5);
  await expect(page.locator('.run-progress')).toHaveAttribute('aria-valuenow', '15');
  await expect(page.locator('.run-summary')).toContainText('5단계를 모두 실행했고');
  await expect(page.locator('.run-summary')).toContainText('9개 샘플 중 9개를 기대한 유형으로 탐지했어요');
  await expect(page.locator('.scenario-timeline')).toContainText('탐지가 멈춰야 정상이에요');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: `test-results/scenarios-${test.info().project.name}.png`, fullPage: true });
  await page.getByRole('link', { name: '탐지 이벤트에서 보기' }).click();
  await expect(page.getByRole('heading', { name: '탐지 이벤트', exact: true })).toBeVisible();
  await expect(page.locator('.pagination')).toContainText('9개 기록');
  await expect(page.locator('tbody tr')).toHaveCount(9);
  await expect(page.locator('.event-history-chart')).toBeVisible();
  await page.getByRole('button', { name: /이벤트 .* 상세 보기/ }).first().click();
  await expect(page.getByRole('dialog')).toContainText('SIMULATION · 모의 탐지');
  await page.getByLabel('판정', { exact: true }).selectOption('confirmed');
  await page.getByLabel('검토 메모').fill('시나리오 단계와 탐지 근거 일치');
  await page.getByLabel('검토용 관리자 토큰').fill('browser-admin');
  await page.getByRole('button', { name: '검토 저장', exact: true }).click();
  await expect(page.getByText('검토 결과를 저장했습니다.')).toBeVisible();
  await page.getByRole('button', { name: '상세 닫기' }).click();
  await page.getByLabel('검토 상태', { exact: true }).selectOption('confirmed');
  await expect(page.locator('.pagination')).toContainText('1개 기록');
  await page.reload();
  await expect(page.locator('tbody')).toContainText('정탐 확인');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: `test-results/events-${test.info().project.name}.png`, fullPage: true });
  await page.goto('/#overview');
  await expect(page.locator('.pagination')).toContainText('25개 기록');
  expect(errors).toEqual([]);
});

test('health traffic light states, empty-value wording and translated errors', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  const healthy = { status: 'ok', database: 'ok', redis: 'ok', detection_mode: 'rules', collector_connected: true };
  let health: Record<string, unknown> = healthy, healthStatus = 200;
  await page.route('**/health', route => route.fulfill({ status: healthStatus, contentType: 'application/json', body: JSON.stringify(healthStatus === 200 ? health : { error: { message: 'Database unavailable' } }) }));
  const banner = page.locator('.status-banner');
  const shot = (name: string) => banner.screenshot({ path: `test-results/status-${name}-${test.info().project.name}.png` });
  // 정상: 수집기 연결 + 저장소 정상
  await page.goto('/#overview');
  await expect(banner).toHaveAttribute('data-level', 'ok');
  await expect(banner).toContainText('정상');
  await expect(banner).toContainText('실시간으로 관찰하고 있어요');
  await expect(page.locator('.sidebar-bottom span')).toContainText('수집기 연결됨');
  await expect(page.locator('.summary-grid')).toContainText('수집 대기');
  await expect(page.locator('.metrics-panel')).toContainText('서버 지표 대기');
  await expect(page.locator('.traffic-panel .chart-empty')).toContainText('데이터 없음');
  await expect(page.locator('tbody')).toContainText('규칙 탐지');
  await shot('ok');
  // 주의: 수집기 연결 대기 → 원인 + [상태 확인]
  health = { ...healthy, collector_connected: false };
  await page.reload();
  await expect(banner).toHaveAttribute('data-level', 'warn');
  await expect(banner).toContainText('주의');
  await expect(banner).toContainText('네트워크 수집기(Collector)가 아직 연결되지 않았어요');
  await expect(page.locator('.sidebar-bottom span')).toContainText('수집기 연결 대기');
  await expect(page.locator('.traffic-panel .chart-empty')).toContainText('연결 대기');
  await shot('warn-collector');
  await banner.getByRole('link', { name: '상태 확인' }).click();
  await expect(page).toHaveURL(/#system$/);
  // 주의: 저장소 저하
  health = { ...healthy, redis: 'degraded' };
  await page.goto('/#overview');
  await page.reload();
  await expect(banner).toHaveAttribute('data-level', 'warn');
  await expect(banner).toContainText('실시간 저장소(Redis) 연결이 불안정해요');
  await shot('warn-redis');
  // 문제: 서버 상태 확인 불가 → [다시 시도]로 복구
  healthStatus = 503;
  await page.reload();
  await expect(banner).toHaveAttribute('data-level', 'error');
  await expect(banner).toContainText('문제');
  await expect(banner).toContainText('서버에 연결할 수 없어요');
  await expect(page.locator('.sidebar-bottom span')).toContainText('서버 확인 불가');
  await shot('error');
  healthStatus = 200; health = healthy;
  await banner.getByRole('button', { name: '다시 시도' }).click();
  await expect(banner).toHaveAttribute('data-level', 'ok');
  // 백엔드 영문 오류 → 한글 표시(원문은 백엔드에 그대로 남음)
  const messages = ['Permission required: incidents.ack', 'Session expired; sign in again', 'Unknown backend failure'];
  let index = 0;
  await page.route('**/api/events?**', route => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: { message: messages[index] } }) }));
  await page.reload();
  await expect(page.locator('.error-banner')).toContainText('권한이 부족합니다(필요 권한: incidents.ack).');
  index = 1;
  await page.locator('.error-banner').getByRole('button', { name: '다시 시도' }).click();
  await expect(page.locator('.error-banner')).toContainText('로그인이 만료되었습니다. 다시 로그인해 주세요.');
  index = 2;
  await page.locator('.error-banner').getByRole('button', { name: '다시 시도' }).click();
  await expect(page.locator('.error-banner')).toContainText('Unknown backend failure');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);
});

test('grouped navigation, korean breadcrumb and one-time onboarding card', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  const desktop = test.info().project.name === 'desktop';
  await page.goto('/#overview');
  // 메뉴 그룹: 모니터링이 맨 위, 첫 항목은 로그인 없이 보이는 대시보드
  const nav = page.locator('nav[aria-label="주 메뉴"]');
  await expect(nav.locator('.nav-group summary span')).toHaveText(['모니터링', '위협 대응', '실습·분석', '설정']);
  await expect(nav.locator('a').first()).toHaveText('대시보드');
  await expect(nav.locator('a[aria-current="page"]')).toHaveText('대시보드');
  await expect(nav.locator('.nav-group[open]')).toHaveCount(4);
  await expect(page.locator('.breadcrumb')).toContainText('대시보드');
  await expect(page.locator('.mobile-nav a').first()).toHaveText('대시보드');
  if (desktop) {
    await nav.locator('.nav-group summary').nth(1).click();
    await expect(nav.locator('.nav-group[open]')).toHaveCount(3);
    await expect(nav.getByRole('link', { name: '사건 대응' })).toBeHidden();
    await nav.locator('.nav-group summary').nth(1).click();
    await expect(nav.locator('.nav-group[open]')).toHaveCount(4);
  }
  // 온보딩: 처음엔 보이고, 닫으면 기억
  const onboarding = page.locator('.onboarding');
  await expect(onboarding).toBeVisible();
  await expect(onboarding).toContainText('탐지 시나리오');
  await expect(onboarding.getByRole('link', { name: '탐지 시나리오 실행해 보기' })).toHaveAttribute('href', '#scenarios');
  await page.screenshot({ path: `test-results/onboarding-${test.info().project.name}.png`, fullPage: false });
  await onboarding.getByRole('button', { name: '안내 닫기' }).click();
  await expect(onboarding).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.getItem('ebpf.onboarding.dismissed'))).toBe('1');
  await page.reload();
  await expect(page.getByRole('heading', { name: '네트워크 대시보드' })).toBeVisible();
  await expect(onboarding).toHaveCount(0);
  // 기억을 지우면 다시 보이고, 1차 행동을 누르면 시나리오로 이동하며 닫힌다
  await page.evaluate(() => localStorage.removeItem('ebpf.onboarding.dismissed'));
  await page.reload();
  await expect(onboarding).toBeVisible();
  await onboarding.getByRole('link', { name: '탐지 시나리오 실행해 보기' }).click();
  await expect(page.getByRole('heading', { name: '탐지 시나리오', exact: true })).toBeVisible();
  await expect(page.locator('.breadcrumb')).toContainText('탐지 시나리오');
  await page.goto('/#events');
  await expect(page.locator('.breadcrumb')).toContainText('탐지 이벤트');
  await page.goto('/#overview');
  await expect(onboarding).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);
});

test('event detail shows a human summary and folds raw features without hiding them from the DOM', async ({ page }) => {
  await page.goto('/#overview');
  await page.getByRole('button', { name: '이벤트 25 상세 보기' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.event-summary')).toContainText('192.0.2.1이(가) 192.0.2.2의 서로 다른 포트');
  await expect(dialog.locator('.event-summary')).toContainText('포트 스캔(Port Scan)으로 판단했어요');
  await expect(dialog.locator('.event-summary')).toContainText('심각도');
  // 접혀 있어도 DOM에는 남아 있고(텍스트 검사 통과), 펼치면 보인다
  const details = dialog.locator('.feature-details');
  await expect(details).not.toHaveAttribute('open', '');
  await expect(details).toContainText('초당 패킷(pps)');
  await expect(details.locator('dl')).toBeHidden();
  await details.locator('summary').click();
  await expect(details.locator('dl')).toBeVisible();
  await expect(details.locator('dl')).toContainText('목적지 포트 수 (10초)');
  await dialog.screenshot({ path: `test-results/event-detail-${test.info().project.name}.png` });
  await page.getByRole('button', { name: '상세 닫기' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('tablet breakpoints (1150px / 768px) keep every public screen free of horizontal overflow', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  for (const width of [1150, 1024, 768]) {
    await page.setViewportSize({ width, height: 900 });
    for (const hash of ['#overview', '#events', '#scenarios', '#capture', '#settings', '#incidents']) {
      await page.goto('/' + hash);
      await expect(page.locator('main, .ops-signin').first()).toBeVisible();
      await page.waitForTimeout(150);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      expect(overflow, `${hash} @ ${width}px`).toBeLessThanOrEqual(0);
    }
    await page.goto('/#settings');
    await page.screenshot({ path: `test-results/settings-${width}-${test.info().project.name}.png`, fullPage: true });
  }
  expect(errors).toEqual([]);
});

test('app shell: fixed viewport with inner scroll, notification center, guide dialog, sidebar collapse and toasts', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  const desktop = test.info().project.name === 'desktop';
  await page.goto('/#overview');
  await expect(page.getByRole('heading', { name: '네트워크 대시보드' })).toBeVisible();
  // 페이지 자체는 스크롤되지 않는다
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).overflow)).toBe('hidden');
  if (desktop) {
    // 데스크톱 대시보드는 한 화면에 들어간다: 본문(main)도 스크롤되지 않고, 탐지 이벤트 표만 패널 안에서 스크롤된다
    expect(await page.evaluate(() => { const main = document.querySelector('main')!; return main.scrollHeight - main.clientHeight; })).toBeLessThanOrEqual(1);
    await expect(page.locator('.page > footer')).toBeInViewport();
    await expect(page.locator('.events-panel .pagination')).toBeInViewport();
    expect(await page.evaluate(() => { const wrap = document.querySelector('.events-panel .table-wrap')!; return wrap.scrollHeight > wrap.clientHeight; })).toBeTruthy();
    // 긴 화면(탐지 이벤트 기록)에서는 본문만 안쪽에서 스크롤된다
    await page.goto('/#events');
    await expect(page.locator('.events-workspace')).toBeVisible();
  }
  expect(await page.evaluate(() => { const main = document.querySelector('main')!; return main.scrollHeight > main.clientHeight; })).toBeTruthy();
  await page.evaluate(() => { document.querySelector('main')!.scrollTop = 400; });
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
  expect(await page.evaluate(() => document.querySelector('main')!.scrollTop)).toBeGreaterThan(0);
  await expect(page.locator('.topbar')).toBeInViewport();
  if (desktop) await page.goto('/#overview');
  // 알림 센터: 첫 접속 알림이 드로어에 쌓이고, 열면 읽음 처리된다
  const bell = page.getByRole('button', { name: /알림 센터 열기/ });
  await expect(bell.locator('.notify-count')).toHaveText(/\d+/);
  await bell.click();
  const drawer = page.locator('.notify-drawer');
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText('서버와 실시간으로 연결됐어요');
  await drawer.getByRole('button', { name: '시스템' }).click();
  await expect(drawer.locator('.notify-item.level-ok')).toContainText('서버와 실시간으로 연결됐어요');
  await drawer.getByRole('button', { name: '탐지' }).click();
  await expect(drawer).toContainText('새 탐지 이벤트가 실시간으로 들어오면');
  await page.screenshot({ path: `test-results/notify-drawer-${test.info().project.name}.png` });
  await drawer.getByRole('button', { name: '알림 센터 닫기' }).click();
  await expect(drawer).toHaveCount(0);
  await expect(bell.locator('.notify-count')).toHaveCount(0);
  // 사용 안내: ? 키로 열고 단계를 누르면 해당 화면으로 이동
  await page.keyboard.press('?');
  const guide = page.getByRole('dialog');
  await expect(guide).toContainText('다섯 단계로 따라가는 eBPF Trace');
  await page.screenshot({ path: `test-results/guide-${test.info().project.name}.png` });
  await guide.getByRole('link', { name: /탐지 시나리오를 실행해요/ }).click();
  await expect(page.getByRole('heading', { name: '탐지 시나리오', exact: true })).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.locator('.breadcrumb')).toContainText('실습·분석');
  await page.goto('/#overview');
  if (desktop) {
    // 사이드바 접기: 아이콘만 남고 브라우저에 기억된다
    await expect(page.locator('.flow-rail a[aria-current="step"]')).toHaveText(/관찰/);
    await page.getByRole('button', { name: '메뉴 접기' }).click();
    await expect(page.locator('.sidebar')).toHaveClass(/collapsed/);
    expect(await page.evaluate(() => localStorage.getItem('ebpf.sidebar.collapsed'))).toBe('1');
    await expect(page.locator('nav[aria-label="주 메뉴"] .nav-label').first()).toBeHidden();
    await page.reload();
    await expect(page.locator('.sidebar')).toHaveClass(/collapsed/);
    await page.screenshot({ path: `test-results/sidebar-collapsed-${test.info().project.name}.png` });
    await page.getByRole('button', { name: '메뉴 펼치기' }).click();
    await expect(page.locator('.sidebar')).not.toHaveClass(/collapsed/);
  } else {
    // 모바일: 메뉴 버튼으로 사이드바 서랍을 열고 배경을 눌러 닫는다
    await expect(page.locator('.sidebar')).toBeHidden();
    await page.getByRole('button', { name: '메뉴 열기' }).click();
    await expect(page.locator('.sidebar')).toHaveClass(/open/);
    await expect(page.locator('.sidebar')).toBeVisible();
    await page.waitForTimeout(350);
    await page.screenshot({ path: `test-results/sidebar-drawer-${test.info().project.name}.png` });
    await page.locator('.sidebar-backdrop').click({ position: { x: 380, y: 400 } });
    await expect(page.locator('.sidebar')).not.toHaveClass(/open/);
  }
  // 토스트: 실시간 연결이 끊기면 알리고, 복구되면 다시 알린다
  await page.context().setOffline(true);
  await expect(page.locator('.toast-host')).toContainText('실시간 연결이 끊겼어요', { timeout: 15000 });
  await page.context().setOffline(false);
  await expect(page.locator('.toast-host')).toContainText('실시간 연결이 복구됐어요', { timeout: 15000 });
  await expect(page.getByText('실시간 연결됨', { exact: true })).toBeVisible({ timeout: 15000 });
  // 페이지가 고정된 뒤에는 본문(main) 안쪽의 가로 넘침을 직접 재야 한다
  for (const hash of ['#overview', '#events', '#scenarios', '#capture', '#settings', '#incidents']) {
    await page.goto('/' + hash);
    await expect(page.locator('main, .ops-signin').first()).toBeVisible();
    await page.waitForTimeout(150);
    const overflow = await page.evaluate(() => { const main = document.querySelector('main')!; return main.scrollWidth - main.clientWidth; });
    expect(overflow, `${hash} main overflow`).toBeLessThanOrEqual(0);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);
});

test('live inspection: token unlocks host interfaces, a counter run flows through rules → AI → response, and the defense check reports every line', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('/#live');
  await expect(page.getByRole('heading', { name: '내 네트워크 검사' })).toBeVisible();
  await expect(page.locator('.breadcrumb')).toContainText('모니터링');
  await expect(page.locator('.live-steps > div')).toHaveCount(4);
  // 잘못된 토큰은 번역된 오류로, 맞는 토큰은 이 호스트의 인터페이스 목록으로
  await page.getByLabel('관리자 토큰').fill('wrong-token');
  await page.getByRole('button', { name: '인터페이스 불러오기' }).click();
  await expect(page.locator('.error-banner')).toContainText('관리자');
  await page.getByLabel('관리자 토큰').fill('browser-admin');
  await page.getByRole('button', { name: '인터페이스 불러오기' }).click();
  const loopback = page.locator('.iface.kind-loopback').first();
  await expect(loopback).toBeVisible();
  await expect(page.locator('.live-steps')).toHaveCount(0);
  await loopback.click();
  await expect(loopback).toHaveAttribute('aria-checked', 'true');
  await page.getByLabel('검사 방식').selectOption('counters');
  await expect(page.locator('.live-cap')).toContainText('카운터 검사');
  await page.getByLabel('검사 시간').selectOption('5');
  await page.getByRole('button', { name: '검사 시작' }).click();
  await expect(page.locator('.live-run-head .run-status')).toHaveText('검사 중');
  await expect(page.locator('.stage.capture')).toContainText('진행 중');
  await expect(page.locator('.stage.rules')).toContainText('1차 방어선');
  await expect(page.locator('.live-run-head .run-status')).toHaveText('완료', { timeout: 15000 });
  // 네 단계가 서버 계산값으로 채워진다: 규칙 5건 판정, AI는 모델이 없어 건너뜀, 대응 단계는 탐지 수를 보여 준다
  await expect(page.locator('.stage.rules')).toContainText('5건');
  await expect(page.locator('.stage.model')).toContainText('건너뜀');
  await expect(page.locator('.stage.model')).toContainText('규칙만');
  await expect(page.locator('.stage.response .stage-value')).toContainText(/\d/);
  await expect(page.locator('.live-summary')).toContainText('5초를 관측');
  await expect(page.locator('.toast-host .toast').first()).toContainText('검사가 끝났어요');
  await page.screenshot({ path: `test-results/live-run-${test.info().project.name}.png` });
  // 방어선 점검: 1차 규칙 정상 · 2차 AI 건너뜀(모델 없음) · 대응 게이트 정상
  await page.getByRole('button', { name: '방어선 점검 실행' }).click();
  const items = page.locator('.check-item');
  await expect(items).toHaveCount(4);
  await expect(items.nth(1)).toContainText('1차 방어선');
  await expect(items.nth(1).locator('.check-pill')).toHaveText('정상');
  await expect(items.nth(2).locator('.check-pill')).toHaveText('건너뜀');
  await expect(items.nth(3).locator('.check-pill')).toHaveText('정상');
  await items.nth(1).locator('summary').click();
  await expect(items.nth(1).locator('tbody tr')).toHaveCount(5);
  await expect(items.nth(1)).toContainText('일치');
  await items.nth(3).locator('summary').click();
  await expect(items.nth(3)).toContainText('승인 경로');
  await expect(items.nth(3)).toContainText('자동 경로');
  await page.screenshot({ path: `test-results/live-check-${test.info().project.name}.png` });
  // 검사 관측은 실제(LIVE) 기록으로 저장되고 대시보드 그래프로도 흐른다(같은 세션의 실시간 버퍼)
  const runId = await page.locator('.live-run-head code').textContent();
  await page.goto('/#overview');
  await expect(page.locator('.traffic-panel .chart-empty')).toHaveCount(0);
  // 검사 기록은 서버 DB에 남는다: 새로고침 뒤 기록 목록에서 골라 같은 단계 값을 다시 본다
  await page.goto('/#live');
  await page.reload();
  await page.getByLabel('관리자 토큰').fill('browser-admin');
  await page.getByRole('button', { name: '인터페이스 불러오기' }).click();
  await expect(page.locator('.iface').first()).toBeVisible();
  await page.getByLabel('검사 기록').selectOption(runId!);
  await expect(page.locator('.live-run-head .run-status')).toHaveText('완료');
  await expect(page.locator('.stage.rules')).toContainText('5건');
  await expect(page.locator('.stage.capture')).toContainText('5초');
  expect(errors).toEqual([]);
});


test('supply demo page scrolls inside its own container while the document stays fixed', async ({ page }) => {
  await page.goto('/#supply');
  const app = page.locator('.trust-app');
  await expect(app).toBeVisible();
  await expect(page.getByRole('button', { name: '기능 둘러보기' })).toBeVisible();
  expect(await page.evaluate(() => { const app = document.querySelector('.trust-app')!; return app.scrollHeight > app.clientHeight; })).toBeTruthy();
  await page.getByRole('button', { name: '기능 둘러보기' }).click();
  await page.waitForTimeout(700);
  // 넓은 화면에서는 랜딩이 뷰포트보다 조금만 길 수 있으므로, 끝까지 내려갔는지(최대 스크롤)로 판정한다
  const scrolled = await page.evaluate(() => { const app = document.querySelector('.trust-app')!; return { top: app.scrollTop, max: app.scrollHeight - app.clientHeight }; });
  expect(scrolled.max).toBeGreaterThan(0);
  expect(scrolled.top).toBeGreaterThan(0); // 앵커 이동이 일어났다(펼쳐지는 안내 문구 때문에 최대 스크롤은 이동 뒤에 더 늘어난다)
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
  await expect(page.locator('#demo-features')).toBeInViewport();
  await expect(page.locator('.trust-header')).toBeInViewport();
});
