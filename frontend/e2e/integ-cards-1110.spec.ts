import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 11/10 사용자 결정(「입력란만 있는 게 아니라 보다 직관적이고 쉽게」 · 추천안 「흐름 그림 + 2단 미리보기」):
//   시나리오를 고르면 1단계 위에 3컷 흐름 그림(무엇을 → 어떻게 → 결과)
//   내 서비스 하나 · 여러 컨테이너 = 왼쪽 입력(칸마다 한 줄 도움말 · 예시로 채우기) + 오른쪽 실시간 미리보기(추가되는 라벨 줄 강조 · 「추가되는 줄 N개」)
//   패키지 설치 검사 = 터미널 순서 3단계(① 토큰 준비 ② 명령 ③ 나오는 결과 · 종료 코드) · 단계별 복사 · 악성 흉내 패키지로 시연
//   토큰 값은 화면에 내지 않는다(명령은 파일에서 읽는 모양만)
const OUT = process.env.IC_SHOTS ?? SHOTS;
const W = '[data-part="wizard"]';
const ready = (page: Page) => expect(page.locator('[data-part="integration"][data-state="ready"]')).toBeVisible();
const TOKEN_CMD = `export SUPPLYGUARD_SANDBOX_TOKEN="$(grep '^SANDBOX_TOKEN=' .env.local | cut -d= -f2-)"`;
const SECRET = 'tok-SECRET-7f3a9c';

async function pick(page: Page, id: 'single' | 'multi' | 'install') {
  await page.goto('/integration');
  await ready(page);
  await page.locator(`${W} [data-scn="${id}"]`).click();
  await expect(page.locator(W)).toHaveAttribute('data-step', '1');
}

// 움직임이 끝날 때까지(끝없는 움직임은 빼고)
const settle = (page: Page) =>
  page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((a) => Number.isFinite(Number(a.effect?.getComputedTiming().endTime)))
        .map((a) => a.finished.catch(() => undefined)),
    ),
  );

// 움직임이 끝난 뒤 찍는다(흐린 사진 방지)
async function shoot(page: Page, name: string) {
  await settle(page);
  // 마법사 안 스크롤까지 한 장에 — 잠시 창을 늘려 찍고 되돌린다
  const vp = page.viewportSize()!;
  const extra = await page.locator(W).evaluate((e) => e.scrollHeight - e.clientHeight);
  if (extra > 0) await page.setViewportSize({ width: vp.width, height: vp.height + extra });
  await page.screenshot({ path: `${OUT}/integ-cards-${name}.png`, fullPage: true });
  await page.setViewportSize(vp);
}

// 화면 글자(코드 창 포함)에 「—」가 없다
async function noDash(page: Page) {
  const t = await page.locator('main').innerText();
  const attrs = await page.locator('main [title], main [placeholder], main [aria-label]').evaluateAll((els) => els.map((e) => `${e.getAttribute('title') ?? ''}${e.getAttribute('placeholder') ?? ''}${e.getAttribute('aria-label') ?? ''}`).join('\n'));
  expect(t.includes('—'), t.split('\n').filter((l) => l.includes('—')).join(' | ')).toBe(false);
  expect(attrs.includes('—'), attrs).toBe(false);
}

const FLOWS = {
  single: ['내 컨테이너', '라벨 2줄 추가 후 다시 실행', 'SupplyGuard 가 감시'],
  multi: ['compose 프로젝트', '서비스마다 라벨', '한 번에 감시'],
  install: ['터미널에서 sg-install', '격리 컨테이너 안에서 설치', '통과 또는 설치 전 격리'],
} as const;

test.describe('11/10 연동 시나리오 — 흐름 그림 3컷', () => {
  for (const [id, titles] of Object.entries(FLOWS) as [keyof typeof FLOWS, readonly string[]][])
    test(`${id}: 고르면 3컷(아이콘 + 짧은 라벨 + 한 줄 설명), 카드는 그대로`, async ({ page, backend }) => {
      void backend;
      await pick(page, id);
      const flow = page.locator(`${W} [data-part="int-scn-notes"]`);
      await expect(flow).toHaveAttribute('data-flow', id);
      const cuts = flow.locator('[data-cut]');
      await expect(cuts).toHaveCount(3);
      expect(await cuts.locator('[data-part="cut-title"]').allTextContents()).toEqual([...titles]);
      for (let i = 0; i < 3; i++) {
        await expect(cuts.nth(i).locator('svg').first()).toBeVisible();
        expect((await cuts.nth(i).locator('[data-part="cut-desc"]').innerText()).trim().length).toBeGreaterThan(8);
      }
      // 컷 사이 화살표 2개(직접 그린 그림)
      await expect(flow.locator('[data-part="cut-arrow"]')).toHaveCount(2);
      // 카드 자체는 제목 + 한 줄 설명 + 예 하나(11/09 밤 결정 유지)
      await expect(page.locator(`[data-scn="${id}"] ul, [data-scn="${id}"] li`)).toHaveCount(0);
    });

  test('패키지 설치 검사 결과 컷: 통과 · 격리 두 갈래', async ({ page, backend }) => {
    void backend;
    await pick(page, 'install');
    const last = page.locator('[data-part="int-scn-notes"] [data-cut]').nth(2);
    await expect(last.locator('[data-outcome="pass"]')).toHaveText('통과');
    await expect(last.locator('[data-outcome="kill"]')).toHaveText('격리');
  });
});

test.describe('11/10 연동 시나리오 — 입력 2단 + 실시간 미리보기', () => {
  test('내 서비스 하나: 왼쪽 입력 · 오른쪽 미리보기, 입력하는 대로 갱신 · 라벨 줄 강조 · 추가되는 줄 수', async ({ page, backend }) => {
    void backend;
    await pick(page, 'single');
    const input = page.locator(`${W} [data-part="scn-input"]`);
    const pv = page.locator(`${W} [data-part="scn-preview"]`);
    await expect(input).toBeVisible();
    await expect(pv).toBeVisible();
    const [a, b] = [await input.boundingBox(), await pv.boundingBox()];
    expect(b!.x, '1440 은 좌우 2단').toBeGreaterThanOrEqual(a!.x + a!.width - 1);
    // 칸마다 한 줄 도움말
    await expect(input.locator('[data-part="field-help"]')).toHaveCount(2);
    const cfg = pv.locator('[data-part="preview-config"]');
    await expect(cfg).toContainText('container_name: my-app');
    await input.locator('input[name="name"]').fill('shop-api');
    await expect(cfg).toContainText('container_name: shop-api');
    await expect(pv.locator('[data-part="preview-apply"]')).toHaveText('docker compose up -d shop-api');
    const added = cfg.locator('[data-added="true"]');
    await expect(added).toHaveCount(1);
    await expect(added.first()).toHaveClass(/\bhl\b/);
    await expect(added.first()).toContainText('supplyguard.watch: "true"');
    await expect(pv.locator('[data-part="preview-added"]')).toHaveText('추가되는 줄 1개');
    await input.locator('input[name="enforce"]').check();
    await expect(added).toHaveCount(2);
    await expect(pv.locator('[data-part="preview-added"]')).toHaveText('추가되는 줄 2개');
    await expect(added.nth(1)).toContainText('supplyguard.enforce: "true"');
    // docker run 으로 바꾸면 미리보기도 명령으로
    await input.locator('[data-mode="run"]').click();
    await expect(cfg).toContainText('--label supplyguard.watch=true');
    await expect(cfg).toContainText('--label supplyguard.enforce=true');
    await expect(pv.locator('[data-part="preview-added"]')).toHaveText('추가되는 줄 2개');
    await input.locator('[data-mode="compose"]').click();
    // 예시로 채우기
    await input.locator('input[name="name"]').fill('');
    await expect(input.locator('.int-field-err')).toBeVisible();
    await input.locator('[data-part="fill-example"]').click();
    await expect(input.locator('input[name="name"]')).not.toHaveValue('');
    await expect(input.locator('.int-field-err')).toHaveCount(0);
    const name = await input.locator('input[name="name"]').inputValue();
    await expect(cfg).toContainText(`container_name: ${name}`);
    await noDash(page);
    await shoot(page, '1440-single');
  });

  test('여러 컨테이너: 예시로 채우기 · 프로젝트 이름 · 감시 끄면 추가되는 줄이 줄어듦', async ({ page, backend }) => {
    void backend;
    await pick(page, 'multi');
    const input = page.locator(`${W} [data-part="scn-input"]`);
    const pv = page.locator(`${W} [data-part="scn-preview"]`);
    await input.locator('input[name="project"]').fill('store');
    const cfg = pv.locator('[data-part="preview-config"]');
    await expect(cfg).toContainText('name: store');
    await expect(cfg).toContainText('container_name: store-web');
    await expect(input.locator('[data-part="field-help"]').first()).toBeVisible();
    const count = () => cfg.locator('[data-added="true"]').count();
    const before = await count();
    expect(before).toBeGreaterThan(0);
    await expect(pv.locator('[data-part="preview-added"]')).toHaveText(`추가되는 줄 ${before}개`);
    await input.getByLabel('서비스 1 감시').uncheck();
    await expect.poll(count).toBeLessThan(before);
    await expect(pv.locator('[data-part="preview-added"]')).toHaveText(`추가되는 줄 ${await count()}개`);
    await expect(pv.locator('[data-part="preview-apply"]')).toHaveText('docker compose up -d');
    await input.locator('[data-part="fill-example"]').click();
    await expect(input.locator('input[name="project"]')).toHaveValue('shop');
    await expect(cfg).toContainText('container_name: shop-api');
    await noDash(page);
    await shoot(page, '1440-multi');
  });
});

test.describe('11/10 연동 시나리오 — 패키지 설치 검사(터미널 순서)', () => {
  test('3단계 ① 토큰 준비(값 없음) ② 명령(입력 따라 갱신) ③ 결과 예시 · 종료 코드 · 단계별 복사', async ({ page, context, backend }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    backend.sgSetup = { ...backend.sgSetup, tokenRequired: true, token: SECRET };
    await pick(page, 'install');
    const term = page.locator(`${W} [data-part="term-steps"]`);
    const steps = term.locator('[data-term-step]');
    await expect(steps).toHaveCount(3);
    expect(await steps.locator('[data-part="term-n"]').allTextContents()).toEqual(['1', '2', '3']);
    // ① 토큰 — 파일에서 읽는 명령만, 값은 어디에도 없음
    await expect(term.locator('[data-part="pre-token"]')).toHaveText(TOKEN_CMD);
    await expect(steps.nth(0)).toContainText('make dev');
    await expect(steps.nth(0)).toContainText('서버');
    // ② 명령 — 입력하는 대로
    const cmd = term.locator('[data-part="pre-install"]');
    await expect(cmd).toHaveText('tools/sg-install pip requests');
    await page.locator(`${W} [data-manager="npm"]`).click();
    await page.locator(`${W} input[name="pkg"]`).fill('left-pad@1.3.0');
    await expect(cmd).toHaveText('tools/sg-install npm left-pad@1.3.0');
    await expect(page.locator(`${W} [data-part="scn-input"] [data-part="field-help"]`).first()).toBeVisible();
    // ③ 결과 예시 · 종료 코드 표
    await expect(term.locator('[data-part="result-pass"]')).toContainText('[OK] 위반 없음');
    await expect(term.locator('[data-part="result-kill"]')).toContainText('[격리됨]');
    const codes = term.locator('[data-part="exit-codes"] tbody tr');
    expect(await codes.locator('td:first-child').allTextContents()).toEqual(['0', '2', '3', '77']);
    await expect(codes.nth(3)).toContainText('토큰');
    // 단계별 복사
    await term.locator('[data-part="pre-token-copy"]').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(TOKEN_CMD);
    await term.locator('[data-part="pre-install-copy"]').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('tools/sg-install npm left-pad@1.3.0');
    // 토큰 값은 화면 어디에도 없음 · 토큰을 주는 API 를 부르지 않음
    expect(await page.content()).not.toContain(SECRET);
    expect(backend.requests.filter((r) => r.path === '/sginstall/setup')).toHaveLength(0);
    await noDash(page);
  });

  test('「악성 흉내 패키지로 시연」 → pip ./deploy/demo/reqeusts, 다음 단계에서 설치 세션 자동 감지(그대로)', async ({ page, backend }) => {
    await pick(page, 'install');
    const w = page.locator(W);
    await w.locator('[data-part="fill-demo"]').click();
    await expect(w.locator('input[name="pkg"]')).toHaveValue('./deploy/demo/reqeusts');
    await expect(w.locator('[data-manager="pip"]')).toHaveAttribute('aria-selected', 'true');
    await expect(w.locator('[data-part="pre-install"]')).toHaveText('tools/sg-install pip ./deploy/demo/reqeusts');
    await expect(w.locator('.int-field-err')).toHaveCount(0);
    await w.locator('[data-part="fill-example"]').click();
    await expect(w.locator('input[name="pkg"]')).not.toHaveValue('./deploy/demo/reqeusts');
    await w.locator('[data-part="fill-demo"]').click();
    await shoot(page, '1440-install');
    await w.locator('[data-part="wizard-next"]').click();
    await expect(w).toHaveAttribute('data-step', '2');
    await expect(w.locator('[data-part="gen-install"]')).toHaveText('tools/sg-install pip ./deploy/demo/reqeusts');
    await w.locator('[data-part="gen-install-copy"]').click();
    await expect(w.locator('[data-part="install-result"]')).toHaveAttribute('data-status', 'waiting');
    const now = new Date().toISOString();
    backend.installs.unshift({ ...backend.installs[0], id: 'ins-9101', manager: 'pip', packages: ['./deploy/demo/reqeusts'], startedAt: now, finishedAt: now, status: 'passed', caseId: null, violations: [], isolation: null, scan: undefined, scanId: null });
    await expect(w.locator('[data-part="install-result"]')).toHaveAttribute('data-status', 'passed', { timeout: 6000 });
    await expect(w).toHaveAttribute('data-step', '3');
  });
});

test.describe('11/10 연동 시나리오 — 어두운 화면 · 390', () => {
  test('1440 어두운: 패키지 설치 검사 · 내 서비스 하나', async ({ page, backend }) => {
    void backend;
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await pick(page, 'install');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await noDash(page);
    await shoot(page, '1440-install-dark');
    await page.locator(`${W} [data-scn="single"]`).click();
    await expect(page.locator(`${W} [data-part="scn-preview"]`)).toBeVisible();
    await shoot(page, '1440-single-dark');
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    for (const id of ['single', 'multi', 'install'] as const)
      test(`390 ${id}: 위아래로 쌓임 · 가로 넘침 0`, async ({ page, backend }) => {
        void backend;
        await pick(page, id);
        const input = page.locator(`${W} [data-part="scn-input"]`);
        const pv = page.locator(`${W} ${id === 'install' ? '[data-part="term-steps"]' : '[data-part="scn-preview"]'}`);
        const [a, b] = [await input.boundingBox(), await pv.boundingBox()];
        expect(b!.y, '1024 미만은 위아래').toBeGreaterThanOrEqual(a!.y + a!.height - 1);
        await settle(page); // 행 들어오기 움직임(옆에서 밀려 들어옴)이 끝난 뒤 잰다
        const over = await page.evaluate(() => {
          const d = document.documentElement;
          const main = document.querySelector('main')!;
          const wiz = document.querySelector('[data-part="wizard"]')!;
          const right = wiz.getBoundingClientRect().right;
          const wide = [...wiz.querySelectorAll('*')].filter((e) => e.getBoundingClientRect().right > right + 0.5).map((e) => `${e.tagName}.${String(e.className).slice(0, 30)}:${Math.round(e.getBoundingClientRect().width)}`);
          return { doc: d.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth, wiz: wiz.scrollWidth - wiz.clientWidth, wide: wide.slice(0, 40) };
        });
        expect(over).toEqual({ doc: 0, main: 0, wiz: 0, wide: [] });
        await noDash(page);
        await shoot(page, `390-${id}`);
      });
  });
});
