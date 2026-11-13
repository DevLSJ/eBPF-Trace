import type { Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 11/06 사용자 결정 — 「연동」 페이지: 라벨 한 줄(supplyguard.watch)로 내 컨테이너 연동.
//   메뉴 = 대시보드 바로 아래(모두에게) · 흐름 그림 자동 재생 · 시나리오 3종(입력 → 설정 생성 → 자동 감지 → 내 컨테이너 시험 동작) · 환경 점검 + 수집 확인(관리자)
//   · 감시 목록(3초 갱신 — 들어온 행 강조, 나간 행 흐려짐) · 대시보드 위 「연동 시작하기」 띠(실제 수집인데 내 컨테이너 0개)
// 11/09 밤: 사이드바 「연동」 묶음(하위 연동 · 환경 점검 · 감시 중 컨테이너)으로 나눔 — 환경 점검 · 수집 확인은 /integration/env, 감시 목록은 /integration/watch
const NAV = '[data-part="sidebar"] nav';
const P = '[data-part="integration"]';
const ready = (page: Page) => expect(page.locator(`${P}[data-state="ready"]`)).toBeVisible();

test.describe('11/06 연동 페이지', () => {
  test('메뉴: 대시보드 아래 고정 줄 · 조회자에게도 보임 · 누르면 「연동」', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/');
    const home = page.locator(`${NAV} [data-nav-group="home"]`);
    await expect.poll(() => home.evaluate((g) => [...g.children].map((e) => e.getAttribute('href') ?? `sub:${e.getAttribute('data-nav-sub')}`))).toEqual(['/', 'sub:integration']);
    await page.locator(`${NAV} [data-nav-sub="integration"] [data-part="subnav-toggle"]`).click(); // 11/09 밤: 묶음은 처음엔 접힘
    await page.locator(`${NAV} a[href="/integration"]`).click();
    await expect(page).toHaveURL(/\/integration$/);
    await expect(page.getByTestId('page-title')).toHaveText('연동');
    await ready(page);
  });

  test('흐름 그림: 4단계 자동 재생 · 요점 한 줄이 단계마다 바뀜, 움직임 줄이기면 정지 그림', async ({ page, backend }) => {
    void backend;
    await page.goto('/integration');
    await ready(page);
    const flow = page.locator('[data-part="int-flow"]');
    await expect(flow.locator('[data-node]')).toHaveCount(4);
    expect(await flow.locator('.flow-title').allTextContents()).toEqual(['내 컨테이너', '커널 eBPF', 'SupplyGuard', '경고 · 격리']);
    await expect(flow).toHaveAttribute('data-playing', 'true');
    const first = await flow.getAttribute('data-step');
    await expect.poll(() => flow.getAttribute('data-step'), { timeout: 4000 }).not.toBe(first);
    await expect(flow.locator('[data-part="int-flow-point"]')).toContainText(/됨$/); // 개조식 명사형 종결
    await expect(page.locator('[data-part="int-key"] li')).toHaveCount(3);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.reload();
    await ready(page);
    await expect(flow).toHaveAttribute('data-playing', 'false');
    await expect(flow.locator('[data-state="on"]')).toHaveAttribute('data-node', 'act');
  });

  test('환경 점검(/integration/env): 확인 필요는 현상 → 조치, 모두 정상이면 요약 한 줄 + 항목 모두 정상', async ({ page, backend }) => {
    await page.goto('/integration/env');
    await ready(page);
    const env = page.getByTestId('int-env');
    await expect(env.locator('[data-check="source"]')).toHaveAttribute('data-tone', 'warn'); // mock — 모의 이벤트 확인 필요
    await expect(env.locator('[data-check="source"]')).toContainText('EVENT_SOURCE=gadget');
    await expect(env.locator('[data-part="env-verdict"]')).toContainText('확인 필요');
    // 실제 서버처럼 — 모두 정상이면 요약 한 줄 · 항목 6개 정상(11/09 밤: 페이지로 나눠 늘 펼침)
    backend.integration = { ...backend.integration, env: { ...backend.integration.env, source: 'gadget', kernel: '5.15.0-160-generic', os: 'Ubuntu 22.04.5 LTS' } };
    backend.info = { ...backend.info, source: 'gadget', discovery: 'fanotify', dnsResolve: 'ok', gadgets: ['exec', 'open', 'connect', 'dns'], enforceKill: true };
    await page.reload();
    await ready(page);
    await expect(env.locator('[data-part="env-verdict"]')).toHaveText('실제 수집 준비됨');
    await expect(env.locator('[data-check]')).toHaveCount(6);
    for (const id of ['source', 'kernel', 'os', 'gadgets', 'discovery', 'enforce']) await expect(env.locator(`[data-check="${id}"]`), id).toHaveAttribute('data-tone', 'ok');
    // 커널 7.0 · docker-events · 격리 꺼짐 → 각각 확인 필요 + 조치
    backend.integration = { ...backend.integration, env: { ...backend.integration.env, kernel: '7.0.0-10-generic', enforceKill: false } };
    backend.info = { ...backend.info, discovery: 'docker-events', discoveryNote: '컨테이너 시작 직후 약 0.1초 안의 동작은 놓칠 수 있습니다' };
    await page.reload();
    await ready(page);
    await expect(env.locator('[data-check="kernel"]')).toContainText('이벤트 유실');
    await expect(env.locator('[data-check="discovery"]')).toContainText('0.1초');
    await expect(env.locator('[data-check="enforce"]')).toContainText('ENFORCE_KILL=false');
    await expect(env.locator('[data-part="env-verdict"]')).toContainText('확인 필요 3건');
  });

  test('시나리오 ① 내 서비스 하나: 입력 검사 → 설정 생성(격리 체크 · container_name) → 적용 뒤 자동 감지 → 시험 동작 결과(격리 보류)', async ({ page, context, backend }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/integration');
    await ready(page);
    const w = page.locator('[data-part="wizard"]');
    await expect(w.locator('[data-scn]')).toHaveCount(3);
    await expect(w.locator('[data-part="wizard-pick"]')).toBeVisible();
    await w.locator('[data-scn="single"]').click();
    await expect(w).toHaveAttribute('data-step', '1');
    // 입력 검사
    await w.locator('input[name="name"]').fill('My App');
    await expect(w.locator('.int-field-err')).toContainText('소문자');
    await expect(w.locator('[data-part="wizard-next"]')).toBeDisabled();
    await w.locator('input[name="name"]').fill('shop-api');
    await w.locator('input[name="image"]').fill('shop-api:1.4');
    await w.locator('input[name="enforce"]').check();
    await w.locator('[data-part="wizard-next"]').click();
    // 2 적용 — 생성된 compose · 명령, 감지 대기
    await expect(w).toHaveAttribute('data-step', '2');
    const cfg = w.locator('[data-part="gen-config"]');
    await expect(cfg).toContainText('container_name: shop-api');
    await expect(cfg).toContainText('supplyguard.watch: "true"');
    await expect(cfg).toContainText('supplyguard.enforce: "true"');
    await expect(w.locator('[data-part="gen-apply"]')).toHaveText('docker compose up -d shop-api');
    await w.locator('[data-part="gen-config-copy"]').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('container_name: shop-api');
    await expect(w.locator('[data-detect="shop-api"]')).toHaveAttribute('data-found', 'false');
    // 서버에 컨테이너가 나타나면(3초 갱신) 자동 감지
    backend.integration = { ...backend.integration, containers: [...backend.integration.containers, { id: 'c-shop', name: 'shop-api', image: 'shop-api:1.4', ignored: false, watched: true, watchBy: 'label', enforce: true, enforceBy: 'label' }] };
    await expect(w.locator('[data-detect="shop-api"]')).toHaveAttribute('data-found', 'true', { timeout: 6000 });
    await expect(w.locator('[data-part="detect-done"]')).toBeVisible();
    await w.locator('[data-part="wizard-next"]').click();
    // 3 확인 — 격리 라벨 경고 · 시험 명령 · 결과 대기 → 판정 수신
    await expect(w).toHaveAttribute('data-step', '3');
    await expect(w.locator('[data-part="verify-kill-warn"]')).toContainText('실제로 종료됨');
    await expect(w.locator('[data-part="gen-test"]')).toHaveText('docker exec shop-api cat /etc/shadow');
    await expect(w.locator('[data-part="verify-result"]')).toHaveAttribute('data-outcome', 'idle');
    await w.locator('[data-part="gen-test-copy"]').click();
    await expect(w.locator('[data-part="verify-result"]')).toHaveAttribute('data-outcome', 'waiting');
    backend.send({ type: 'verdict', data: { ...killedVerdict('shop-api', '금지 경로 /etc/shadow'), ruleId: 'sensitive-files', enforced: false, dryRun: true, enforceSkip: 'label' } });
    await expect(w.locator('[data-part="verify-result"]')).toHaveAttribute('data-outcome', 'held');
    await expect(w.locator('[data-part="verify-result"]')).toContainText('[격리 보류] 감시 동작 확인됨');
    await expect(w.locator('[data-part="verify-result"]')).toContainText('sensitive-files');
    await page.screenshot({ path: `${SHOTS}/1106-integration-scenario-single.png` });
    // 새로고침해도 단계 · 입력 이어짐
    await page.reload();
    await ready(page);
    await expect(w).toHaveAttribute('data-step', '3');
    await expect(w.locator('[data-part="gen-test"]')).toHaveText('docker exec shop-api cat /etc/shadow');
  });

  test('시나리오 ① docker run: 한 줄 명령 · 라벨 없는 격리면 enforce 줄 없음', async ({ page, backend }) => {
    void backend;
    await page.goto('/integration');
    await ready(page);
    const w = page.locator('[data-part="wizard"]');
    await w.locator('[data-scn="single"]').click();
    await w.locator('[data-mode="run"]').click();
    await w.locator('[data-part="wizard-next"]').click();
    await expect(w.locator('[data-part="gen-config"]')).toContainText('--label supplyguard.watch=true');
    await expect(w.locator('[data-part="gen-config"]')).not.toContainText('supplyguard.enforce');
    await expect(w.locator('[data-part="gen-apply"]')).toHaveText('docker run -d --name my-app --label supplyguard.watch=true my-app:latest');
  });

  test('시나리오 ② 여러 컨테이너: 서비스 행 추가 · 감시 끄면 격리도 꺼짐 · compose 전체 생성 · 감지 n / m · 시험 대상 선택(격리됨)', async ({ page, backend }) => {
    await page.goto('/integration');
    await ready(page);
    const w = page.locator('[data-part="wizard"]');
    await w.locator('[data-scn="multi"]').click();
    const rows = w.locator('[data-part="svc-table"] tbody tr');
    await expect(rows).toHaveCount(3);
    await w.locator('[data-part="svc-add"]').click();
    await expect(rows).toHaveCount(4);
    await rows.nth(3).getByLabel('서비스 4 감시').uncheck();
    await expect(rows.nth(3).getByLabel('서비스 4 격리')).toBeDisabled();
    await rows.nth(3).getByLabel('빼기(서비스 4)').click();
    await expect(rows).toHaveCount(3);
    // 감시 0개면 다음 불가
    for (const k of [1, 2]) await rows.nth(k - 1).getByLabel(`서비스 ${k} 감시`).uncheck();
    await expect(w.locator('[data-part="multi-error"]')).toContainText('감시할 서비스 1개 이상');
    await expect(w.locator('[data-part="wizard-next"]')).toBeDisabled();
    for (const k of [1, 2]) await rows.nth(k - 1).getByLabel(`서비스 ${k} 감시`).check();
    await rows.nth(1).getByLabel('서비스 2 격리').check();
    await w.locator('[data-part="wizard-next"]').click();
    const cfg = w.locator('[data-part="gen-config"]');
    await expect(cfg).toContainText('name: shop');
    await expect(cfg).toContainText('container_name: shop-web');
    await expect(cfg).toContainText('container_name: shop-db');
    expect((await cfg.textContent())!.match(/supplyguard\.watch/g)).toHaveLength(2); // db 는 감시 안 함
    await expect(w.locator('[data-part="gen-apply"]')).toHaveText('docker compose up -d');
    await expect(w.locator('[data-part="detect-count"]')).toHaveText('0 / 2');
    backend.integration = { ...backend.integration, containers: [...backend.integration.containers, { id: 'c-w', name: 'shop-web', image: 'nginx:1.27-alpine', ignored: false, watched: true, watchBy: 'label', enforce: false }] };
    await expect(w.locator('[data-part="detect-count"]')).toHaveText('1 / 2', { timeout: 6000 });
    await w.locator('[data-part="wizard-next"]').click();
    await w.locator('[data-part="verify-target"]').selectOption('shop-api');
    await expect(w.locator('[data-part="verify-kill-warn"]')).toBeVisible();
    await expect(w.locator('[data-part="gen-test"]')).toHaveText('docker exec shop-api cat /etc/shadow');
    await w.locator('[data-part="gen-test-copy"]').click();
    backend.send({ type: 'verdict', data: { ...killedVerdict('shop-api'), ruleId: 'sensitive-files' } });
    await expect(w.locator('[data-part="verify-result"]')).toHaveAttribute('data-outcome', 'killed');
    await expect(w.locator('[data-part="verify-result"]')).toContainText('[격리] 연동 · 격리 모두 동작 확인됨');
  });

  test('시나리오 ③ 패키지 설치 검사: 명령 생성 → 새 설치 세션 자동 감지 → 결과 · 설치 상세 링크', async ({ page, backend }) => {
    await page.goto('/integration');
    await ready(page);
    const w = page.locator('[data-part="wizard"]');
    await w.locator('[data-scn="install"]').click();
    await w.locator('[data-manager="npm"]').click();
    await w.locator('input[name="pkg"]').fill('left-pad@1.3.0');
    await w.locator('[data-part="wizard-next"]').click();
    await expect(w.locator('[data-part="gen-install"]')).toHaveText('tools/sg-install npm left-pad@1.3.0');
    await expect(w.locator('[data-part="install-result"]')).toHaveAttribute('data-status', 'idle');
    await w.locator('[data-part="gen-install-copy"]').click();
    await expect(w.locator('[data-part="install-result"]')).toHaveAttribute('data-status', 'waiting');
    const now = new Date().toISOString();
    backend.installs.unshift({ ...backend.installs[0], id: 'ins-9001', manager: 'npm', packages: ['left-pad@1.3.0'], startedAt: now, finishedAt: now, status: 'passed', caseId: null, violations: [], isolation: null, scan: undefined, scanId: null });
    await expect(w.locator('[data-part="install-result"]')).toHaveAttribute('data-status', 'passed', { timeout: 6000 });
    await expect(w).toHaveAttribute('data-step', '3');
    await expect(w.locator('[data-part="install-result"]')).toContainText('위반 없이 설치 완료');
    await w.locator('[data-part="install-open"]').click();
    await expect(page).toHaveURL(/\/installs\?id=ins-9001/);
  });

  test('수집 확인(시험 컨테이너): 관리자 → 진행 → 통과(종류별 수), 진행 중엔 버튼 잠김', async ({ page, backend }) => {
    await page.goto('/integration/env');
    await ready(page);
    const step = page.locator('[data-part="test-step"]');
    await step.locator('[data-part="test-start"]').click();
    await expect(step).toHaveAttribute('data-state', 'running');
    await expect(step.locator('[data-part="test-start"]')).toBeDisabled();
    await expect(step.locator('[data-part="test-state"]')).toContainText('sg-probe-');
    await expect(step).toHaveAttribute('data-state', 'passed', { timeout: 5000 });
    await expect(step.locator('[data-part="test-state"]')).toHaveText('[통과] 이벤트 6건 수신, 연결 확인됨');
    await expect(step.locator('[data-kind="exec"] b')).toHaveText('5');
    await expect(step.locator('[data-kind="exec"]')).toHaveClass(/got/);
    await expect(step.locator('[data-kind="connect"]')).not.toHaveClass(/got/);
    expect(backend.requests.filter((r) => r.method === 'POST' && r.path === '/integration/test')).toHaveLength(1);
    await page.screenshot({ path: `${SHOTS}/1106-integration.png` });
  });

  test('수집 확인 — 조회자: 버튼 잠김 + 이유', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/integration/env');
    await ready(page);
    await expect(page.locator('[data-part="test-start"]')).toBeDisabled();
    await expect(page.locator('[data-part="test-step"]')).toContainText('연결 테스트를 실행할 권한이 없습니다');
  });

  test('감시 목록: 감시 · 격리 이유 배지, 새 컨테이너는 강조하며 들어오고 사라진 것은 흐려진 뒤 빠짐', async ({ page, backend }) => {
    await page.goto('/integration/watch');
    await ready(page);
    const list = page.locator('[data-part="watch-rows"]');
    await expect(list.locator('[data-container]')).toHaveCount(3);
    await expect(page.locator('[data-part="watch-sum"]')).toContainText('3 감시 · 1 격리 대상');
    await expect(list.locator('[data-container="pkg-reqeusts"] [data-tag="enforce"]')).toHaveText('격리 · 라벨');
    await expect(list.locator('[data-container="web-api"] [data-tag="enforce"]')).toHaveText('격리 보류');
    backend.integration = {
      ...backend.integration,
      containers: [
        ...backend.integration.containers.filter((c) => c.name !== 'worker'),
        { id: 'c-shop', name: 'shop-api', image: 'shop:1', ignored: false, watched: true, watchBy: 'label', enforce: false },
      ],
    };
    // 같은 갱신에서 worker 는 빠지고 shop-api 가 들어온다 — 사라진 행은 0.7초만 보이므로 먼저 확인
    await expect(list.locator('.int-row.gone')).toContainText('worker', { timeout: 6000 });
    const row = list.locator('[data-container="shop-api"]');
    await expect(row).toHaveClass(/\bin\b/);
    await expect(row.locator('[data-tag="watch"]')).toHaveText('라벨');
    await expect(list.locator('.int-row.gone')).toHaveCount(0, { timeout: 3000 });
  });
});

test.describe('11/06 연동 페이지 — 화면 틀', () => {
  // 11/09 밤: 세 페이지 — 연동(흐름 그림 + 시나리오) · 환경 점검 · 감시 중 컨테이너, 각각 화면 안에 들고 문서 넘침 0
  for (const [w, h] of [[1920, 1080], [1440, 900]] as const)
    test(`${w}×${h}: 흐름 그림 · 시나리오 / 환경 점검 / 감시 목록 · 문서 넘침 0`, async ({ page, backend }) => {
      void backend;
      await page.setViewportSize({ width: w, height: h });
      await page.goto('/integration');
      await ready(page);
      await page.locator('[data-scn="multi"]').click();
      await page.locator('[data-part="wizard-next"]').click();
      await noPageOverflow(page);
      const wiz = await page.locator('[data-part="wizard"]').boundingBox();
      expect(wiz!.y + wiz!.height).toBeLessThanOrEqual(h);
      await page.waitForTimeout(700);
      await page.screenshot({ path: `${SHOTS}/1106-integration-${w}.png` });
      for (const [path, id] of [['/integration/env', 'int-test'], ['/integration/watch', 'int-watch']] as const) {
        await page.goto(path);
        await ready(page);
        await noPageOverflow(page);
        const box = await page.getByTestId(id).boundingBox();
        expect(box!.y + box!.height, path).toBeLessThanOrEqual(h);
      }
    });
});

test.describe('11/06 대시보드 「연동 시작하기」 띠', () => {
  test('실제 수집인데 내 컨테이너 0개면 보임 → 누르면 연동, 닫으면 다시 안 보임 · mock 은 안 보임', async ({ page, backend }) => {
    await page.goto('/');
    await expect(page.locator('[data-part="dashboard"]')).toBeVisible();
    await expect(page.locator('[data-part="integrate-banner"]')).toHaveCount(0); // mock — web-api 등 감시 중
    backend.integration = {
      ...backend.integration,
      env: { ...backend.integration.env, source: 'gadget' },
      containers: [{ id: 'c-sg', name: 'sg-install-pip-1', image: 'python:3.12-slim', ignored: false, watched: true, watchBy: 'name', enforce: true, enforceBy: 'name' }],
    };
    await page.reload();
    const banner = page.locator('[data-part="integrate-banner"]');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('감시 중인 내 컨테이너 없음');
    await banner.locator('[data-part="integrate-go"]').click();
    await expect(page).toHaveURL(/\/integration$/);
    await page.goto('/');
    await page.locator('[data-part="integrate-close"]').click();
    await expect(banner).toHaveCount(0);
    await page.reload();
    await expect(page.locator('[data-part="dashboard"]')).toBeVisible();
    await expect(banner).toHaveCount(0);
  });
});
