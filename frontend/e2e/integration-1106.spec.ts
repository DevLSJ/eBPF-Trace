import type { Page } from '@playwright/test';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// 11/06 사용자 결정 — 「연동」 페이지: 라벨 한 줄(supplyguard.watch)로 내 컨테이너 연동.
//   메뉴 = 대시보드 바로 아래(모두에게) · 흐름 그림 자동 재생 · ① 환경 점검 ② 라벨 한 줄(격리 체크 · 복사) ③ 연결 테스트(관리자)
//   · 감시 목록(3초 갱신 — 들어온 행 강조, 나간 행 흐려짐) · 대시보드 위 「연동 시작하기」 띠(실제 수집인데 내 컨테이너 0개)
const NAV = '[data-part="sidebar"] nav';
const P = '[data-part="integration"]';
const ready = (page: Page) => expect(page.locator(`${P}[data-state="ready"]`)).toBeVisible();

test.describe('11/06 연동 페이지', () => {
  test('메뉴: 대시보드 아래 고정 줄 · 조회자에게도 보임 · 누르면 「연동」', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/');
    const home = page.locator(`${NAV} [data-nav-group="home"] > a`);
    expect(await home.evaluateAll((els) => els.map((e) => e.getAttribute('href')))).toEqual(['/', '/integration']);
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

  test('① 환경 점검: 현상 → 조치. mock 은 「모의 이벤트」 확인 필요, 실제 수집 · fanotify · 격리 켬은 준비됨', async ({ page, backend }) => {
    await page.goto('/integration');
    await ready(page);
    const env = page.locator('[data-part="step-env"]');
    await expect(env.locator('[data-check="source"]')).toHaveAttribute('data-tone', 'warn');
    await expect(env.locator('[data-check="source"]')).toContainText('EVENT_SOURCE=gadget');
    await expect(env.locator('[data-part="env-verdict"]')).toContainText('확인 필요');
    // 실제 서버처럼
    backend.integration = { ...backend.integration, env: { ...backend.integration.env, source: 'gadget', kernel: '5.15.0-160-generic', os: 'Ubuntu 22.04.5 LTS' } };
    backend.info = { ...backend.info, source: 'gadget', discovery: 'fanotify', dnsResolve: 'ok', gadgets: ['exec', 'open', 'connect', 'dns'], enforceKill: true };
    await page.reload();
    await ready(page);
    for (const id of ['source', 'kernel', 'os', 'gadgets', 'discovery', 'enforce']) await expect(env.locator(`[data-check="${id}"]`), id).toHaveAttribute('data-tone', 'ok');
    await expect(env.locator('[data-part="env-verdict"]')).toHaveText('실제 수집 준비됨');
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

  test('② 라벨 한 줄: compose · docker run, 「격리까지 맡기기」면 enforce 줄 추가 · 복사', async ({ page, context, backend }) => {
    void backend;
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/integration');
    await ready(page);
    const step = page.locator('[data-part="step-label"]');
    const code = step.locator('[data-part="label-code"]');
    await expect(code).toContainText('supplyguard.watch: "true"');
    await expect(code).not.toContainText('supplyguard.enforce');
    await expect(code.locator('.hl')).toHaveCount(1);
    await step.locator('[data-part="label-enforce"]').check();
    await expect(code).toContainText('supplyguard.enforce: "true"');
    await expect(code.locator('.hl')).toHaveCount(2);
    await expect(step.locator('[data-part="label-points"]')).toContainText('즉시 격리됨');
    await step.locator('[data-tab="run"]').click();
    await expect(code).toContainText('--label supplyguard.watch=true');
    await expect(code).toContainText('--label supplyguard.enforce=true');
    await step.locator('[data-part="label-copy"]').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('--label supplyguard.enforce=true');
  });

  test('③ 연결 테스트: 관리자 → 진행 → 통과(종류별 수), 진행 중엔 버튼 잠김 · 변경 이력 1줄', async ({ page, backend }) => {
    await page.goto('/integration');
    await ready(page);
    const step = page.locator('[data-part="test-step"]');
    await step.locator('[data-part="test-start"]').click();
    await expect(step).toHaveAttribute('data-state', 'running');
    await expect(step.locator('[data-part="test-start"]')).toBeDisabled();
    await expect(step.locator('[data-part="test-state"]')).toContainText('sg-probe-');
    await expect(step).toHaveAttribute('data-state', 'passed', { timeout: 5000 });
    await expect(step.locator('[data-part="test-state"]')).toHaveText('연결 확인됨 — 이벤트 6건 수신');
    await expect(step.locator('[data-kind="exec"] b')).toHaveText('5');
    await expect(step.locator('[data-kind="exec"]')).toHaveClass(/got/);
    await expect(step.locator('[data-kind="connect"]')).not.toHaveClass(/got/);
    expect(backend.requests.filter((r) => r.method === 'POST' && r.path === '/integration/test')).toHaveLength(1);
    await page.screenshot({ path: `${SHOTS}/1106-integration.png` });
  });

  test('③ 조회자 · 실행 불가 서버: 버튼 잠김 + 이유', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/integration');
    await ready(page);
    await expect(page.locator('[data-part="test-start"]')).toBeDisabled();
    await expect(page.locator('[data-part="step-test"]')).toContainText('관리자만 실행 가능');
  });

  test('감시 목록: 감시 · 격리 이유 배지, 새 컨테이너는 강조하며 들어오고 사라진 것은 흐려진 뒤 빠짐', async ({ page, backend }) => {
    await page.goto('/integration');
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
    const row = list.locator('[data-container="shop-api"]');
    await expect(row).toBeVisible({ timeout: 6000 });
    await expect(row).toHaveClass(/\bin\b/);
    await expect(row.locator('[data-tag="watch"]')).toHaveText('라벨');
    await expect(list.locator('.int-row.gone')).toContainText('worker');
    await expect(list.locator('.int-row.gone')).toHaveCount(0, { timeout: 3000 });
  });
});

test.describe('11/06 연동 페이지 — 화면 틀', () => {
  for (const [w, h] of [[1920, 1080], [1440, 900]] as const)
    test(`${w}×${h}: 단계 3칸 가로 · 감시 목록 아래 · 문서 넘침 0 · 단계 카드 잘림 없음`, async ({ page, backend }) => {
      void backend;
      await page.setViewportSize({ width: w, height: h });
      await page.goto('/integration');
      await ready(page);
      await noPageOverflow(page);
      // 단계 카드 등장 애니메이션(차례로 10px 올라옴)이 끝난 뒤에 잰다
      await page.evaluate(() => Promise.all(document.getAnimations().filter((a) => ((a.effect as KeyframeEffect | null)?.target as Element | null)?.closest('.int-steps')).map((a) => a.finished)));
      const boxes = await page.locator('.int-step').evaluateAll((els) => els.map((e) => { const r = e.getBoundingClientRect(); return [Math.round(r.top), Math.round(r.bottom), e.scrollHeight <= e.clientHeight + 1]; }));
      expect(boxes).toHaveLength(3);
      expect(new Set(boxes.map((b) => b[0])).size).toBe(1); // 한 줄
      expect(boxes.every((b) => b[2])).toBe(true); // 안쪽 넘침 없음
      const watch = await page.getByTestId('int-watch').boundingBox();
      expect(watch!.y).toBeGreaterThan(boxes[0][1] as number);
      expect(watch!.y + watch!.height).toBeLessThanOrEqual(h);
      await page.screenshot({ path: `${SHOTS}/1106-integration-${w}.png` });
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
