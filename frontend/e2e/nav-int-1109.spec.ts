import type { Page } from '@playwright/test';
import { checkScreenCopy, SCREEN_COPY } from '../src/lib/screenCopy';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 11/09 밤 사용자 결정 ① ② — 「연동」을 사이드바 그룹 + 하위 메뉴 3개(연동 · 환경 점검 · 감시 중 컨테이너) 페이지로 나눈다.
//   연동 = 시나리오 고르기 → 설정 만들기 → 확인(마법사)만 · 환경 점검 = 수집 준비 상태 + 연결 테스트 · 감시 중 컨테이너 = 목록
//   시나리오 카드 = 한 줄 설명 + 예 하나(세부는 고른 뒤 단계 안에서만)
//   하위 메뉴가 있는 사이드바 그룹(연동 · 정책)은 머리를 눌러 접고 편다 — 지금 화면 그룹은 늘 펼침, 다른 그룹은 이 브라우저가 기억(처음엔 접힘)
const SHOT = process.env.NAV_SHOTS || `${SHOTS}/nav-int-1109`;
const NAV = 'nav[aria-label="화면"]';
const OPEN_KEY = 'supplyguard.nav.open.v1';
const PAGES = [
  { path: '/integration', page: 'setup', title: '연동', key: 'integration', parent: false },
  { path: '/integration/env', page: 'env', title: '환경 점검', key: 'integration/env', parent: true },
  { path: '/integration/watch', page: 'watch', title: '감시 중 컨테이너', key: 'integration/watch', parent: true },
] as const;
const ready = (page: Page, p: string) => expect(page.locator(`[data-part="integration"][data-page="${p}"][data-state="ready"]`)).toBeVisible();
const sub = (page: Page, id: string) => page.locator(`${NAV} [data-nav-sub="${id}"]`);
const toggle = (page: Page, id: string) => sub(page, id).locator('[data-part="subnav-toggle"]');
const stored = (page: Page) => page.evaluate((k) => localStorage.getItem(k), OPEN_KEY);

// 보이는 글자 · 툴팁에서 「—」(코드 창 제외)
async function dashes(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    const skip = (el: Element) => !!el.closest('[data-part="code"], pre, code, script, style');
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (w.nextNode()) {
      const n = w.currentNode as Text;
      const el = n.parentElement;
      if (!n.data.includes('—') || !el || skip(el) || !el.checkVisibility({ checkVisibilityCSS: true })) continue;
      out.push(n.data.trim().slice(0, 80));
    }
    for (const el of Array.from(document.querySelectorAll('[title], [placeholder]')))
      for (const a of ['title', 'placeholder']) if (!skip(el) && el.getAttribute(a)?.includes('—')) out.push(`@${a} ${el.getAttribute(a)}`);
    return out;
  });
}

test.describe('① 연동 3페이지', () => {
  test('경로 · 제목(하위는 「연동 ›」) · 설명 한 줄(lib/screenCopy) · 상위 링크 · 통합 검색', async ({ page, backend }) => {
    void backend;
    const title = page.getByTestId('page-title');
    const up = page.locator('[data-part="title-parent"]');
    for (const p of PAGES) {
      await page.goto(p.path);
      await ready(page, p.page);
      await expect(title, p.path).toHaveText(p.title);
      if (p.parent) {
        await expect(up, p.path).toHaveText('연동');
        await expect(page.locator('[data-part="title-sep"]')).toHaveText('›');
      } else await expect(up, p.path).toHaveCount(0);
      const d = page.locator('[data-part="screen-copy"]');
      await expect(d, p.path).toHaveCount(1);
      await expect(d, p.path).toHaveAttribute('data-screen', p.key);
      await expect(d, p.path).toHaveText(SCREEN_COPY[p.key]);
      expect(checkScreenCopy(SCREEN_COPY[p.key]), p.key).toEqual([]);
    }
    await up.click();
    await expect(page).toHaveURL(/\/integration$/);
    await expect(title).toHaveText('연동');
    // 통합 검색 「화면」: 새 화면 두 개 · 보조 줄은 상위(연동)
    const box = page.getByRole('combobox', { name: /통합 검색/ });
    const results = page.locator('[data-part="search-results"]');
    await box.fill('환경 점검');
    await expect(results.locator('[data-type="screen"]')).toHaveText([/^환경 점검.*연동/]);
    await box.fill('감시 중');
    await expect(results.locator('[data-type="screen"]').first()).toContainText('감시 중 컨테이너');
    await results.locator('[data-type="screen"]').first().click();
    await expect(page).toHaveURL(/\/integration\/watch$/);
  });

  test('페이지마다 맡은 부분만 — 연동 = 마법사 · 환경 점검 = 수집 준비 상태 + 연결 테스트 · 감시 중 컨테이너 = 목록', async ({ page, backend }) => {
    void backend;
    await page.goto('/integration');
    await ready(page, 'setup');
    await expect(page.locator('[data-part="wizard"]')).toBeVisible();
    for (const s of ['[data-part="env-checks"]', '[data-part="env-verdict"]', '[data-part="test-step"]', '[data-part="watch-rows"]', '[data-testid="int-watch"]', '[data-testid="int-env"]'])
      await expect(page.locator(s), `/integration ${s}`).toHaveCount(0);

    await page.goto('/integration/env');
    await ready(page, 'env');
    await expect(page.getByTestId('int-env').locator('[data-part="env-checks"] [data-check]')).toHaveCount(6);
    await expect(page.getByTestId('int-test').locator('[data-part="test-step"]')).toBeVisible();
    for (const s of ['[data-part="wizard"]', '[data-part="watch-rows"]', '[data-testid="int-watch"]']) await expect(page.locator(s), `/integration/env ${s}`).toHaveCount(0);
    // 페이지 사이 이동 — 감시 중 컨테이너 보기
    await page.locator('[data-part="to-watch"]').click();
    await expect(page).toHaveURL(/\/integration\/watch$/);

    await ready(page, 'watch');
    await expect(page.getByTestId('int-watch').locator('[data-part="watch-rows"] [data-container]')).toHaveCount(3);
    await expect(page.locator('[data-part="watch-sum"]')).toContainText('3 감시 · 1 격리 대상');
    for (const s of ['[data-part="wizard"]', '[data-part="env-checks"]', '[data-part="test-step"]']) await expect(page.locator(s), `/integration/watch ${s}`).toHaveCount(0);
  });

  test('시나리오 카드 3개 = 제목 + 한 줄 설명 + 예 하나(요점 목록 없음) · 세부는 고른 뒤 1단계 안에', async ({ page, backend }) => {
    void backend;
    await page.goto('/integration');
    await ready(page, 'setup');
    const cards = page.locator('[data-part="wizard"] [data-scn]');
    await expect(cards).toHaveCount(3);
    const want = [
      ['single', '내 서비스 하나', '컨테이너 하나를 감시합니다.', '예) docker run my-app'],
      ['multi', '여러 컨테이너 한 번에', 'compose 프로젝트를 한 번에 감시합니다.', '예) web · api · db'],
      ['install', '패키지 설치 검사', '설치 전에 격리 환경에서 검사합니다.', '예) pip install requests'],
    ] as const;
    for (const [id, t, desc, ex] of want) {
      const c = page.locator(`[data-scn="${id}"]`);
      await expect(c.locator('.int-scn-title')).toHaveText(t);
      await expect(c.locator('[data-part="int-scn-desc"]')).toHaveText(desc);
      await expect(c.locator('[data-part="int-scn-example"]')).toHaveText(ex);
      await expect(c.locator('ul, li'), `${id} 요점 목록 없음`).toHaveCount(0);
      await expect(c).not.toContainText('라벨 2줄');
      await expect(c).not.toContainText('n / m');
    }
    // 고른 뒤 1단계 안 설명(카드에서 옮긴 세부)
    const notes = page.locator('[data-part="int-scn-notes"]');
    await expect(notes).toHaveCount(0);
    await page.locator('[data-scn="single"]').click();
    await expect(notes).toContainText('라벨 2줄');
    await expect(notes).toContainText('자동 감지');
    await page.locator('[data-scn="multi"]').click();
    await expect(notes).toContainText('서비스별 감시 · 격리');
    await expect(notes).toContainText('감지 진행');
    await page.locator('[data-scn="install"]').click();
    await expect(notes).toContainText('정적 검사');
    await expect(notes).toContainText('설치 완료 전에 격리');
  });

  test('마법사 끝까지(내 서비스 하나) — 입력 → 설정 만들기 → 적용 뒤 자동 감지 → 확인(판정) · 감시 목록 · 환경 점검 링크', async ({ page, context, backend }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/integration');
    await ready(page, 'setup');
    const w = page.locator('[data-part="wizard"]');
    await w.locator('[data-scn="single"]').click();
    await w.locator('input[name="name"]').fill('shop-api');
    await w.locator('input[name="image"]').fill('shop-api:1.4');
    await w.locator('input[name="enforce"]').check();
    await w.locator('[data-part="wizard-next"]').click();
    await expect(w).toHaveAttribute('data-step', '2');
    await expect(w.locator('[data-part="gen-config"]')).toContainText('supplyguard.enforce: "true"');
    await expect(w.locator('[data-detect="shop-api"]')).toHaveAttribute('data-found', 'false');
    await expect(w.locator('[data-part="detect-watch-link"]')).toHaveAttribute('href', '/integration/watch');
    await expect(w.locator('[data-part="detect-env-link"]')).toHaveAttribute('href', '/integration/env');
    backend.integration = { ...backend.integration, containers: [...backend.integration.containers, { id: 'c-shop', name: 'shop-api', image: 'shop-api:1.4', ignored: false, watched: true, watchBy: 'label', enforce: true, enforceBy: 'label' }] };
    await expect(w.locator('[data-detect="shop-api"]')).toHaveAttribute('data-found', 'true', { timeout: 6000 });
    await expect(w.locator('[data-part="detect-done"]')).toBeVisible();
    await w.locator('[data-part="wizard-next"]').click();
    await expect(w).toHaveAttribute('data-step', '3');
    await w.locator('[data-part="gen-test-copy"]').click();
    await expect(w.locator('[data-part="verify-result"]')).toHaveAttribute('data-outcome', 'waiting');
    backend.send({ type: 'verdict', data: { ...killedVerdict('shop-api'), ruleId: 'sensitive-files' } });
    await expect(w.locator('[data-part="verify-result"]')).toHaveAttribute('data-outcome', 'killed');
    // 감시 목록 페이지에도 같은 데이터(같은 GET /api/integration)
    await page.goto('/integration/watch');
    await ready(page, 'watch');
    await expect(page.locator('[data-part="watch-rows"] [data-container="shop-api"] [data-tag="enforce"]')).toHaveText('격리 · 라벨');
    expect(backend.requests.filter((r) => r.method === 'GET' && /^\/integration\//.test(r.path))).toHaveLength(0); // 새 API 없음
  });

  test('연결 테스트(관리자) — 환경 점검 페이지에서 진행 → 통과 · 조회자는 잠김 + 사유', async ({ page, backend }) => {
    await page.goto('/integration/env');
    await ready(page, 'env');
    const step = page.locator('[data-part="test-step"]');
    await step.locator('[data-part="test-start"]').click();
    await expect(step).toHaveAttribute('data-state', 'running');
    await expect(step).toHaveAttribute('data-state', 'passed', { timeout: 5000 });
    await expect(step.locator('[data-part="test-state"]')).toHaveText('[통과] 이벤트 6건 수신, 연결 확인됨');
    expect(backend.requests.filter((r) => r.method === 'POST' && r.path === '/integration/test')).toHaveLength(1);
    backend.auth.asViewer();
    await page.reload();
    await ready(page, 'env');
    await expect(page.locator('[data-part="test-start"]')).toHaveAttribute('aria-disabled', 'true');
    await expect(page.locator('[data-part="test-step"]')).toContainText('연결 테스트를 실행할 권한이 없습니다');
  });

  test('환경 점검은 늘 펼친 채(접기 단추 없음) — 모두 정상이어도 항목 6개 · 연결 테스트', async ({ page, backend }) => {
    backend.integration = { ...backend.integration, env: { ...backend.integration.env, source: 'gadget', kernel: '5.15.0-160-generic', os: 'Ubuntu 22.04.5 LTS' } };
    backend.info = { ...backend.info, source: 'gadget', discovery: 'fanotify', dnsResolve: 'ok', gadgets: ['exec', 'open', 'connect', 'dns'], enforceKill: true };
    await page.goto('/integration/env');
    await ready(page, 'env');
    await expect(page.locator('[data-part="env-verdict"]')).toHaveText('실제 수집 준비됨');
    await expect(page.locator('[data-part="env-toggle"]')).toHaveCount(0);
    for (const id of ['source', 'kernel', 'os', 'gadgets', 'discovery', 'enforce']) await expect(page.locator(`[data-check="${id}"]`), id).toHaveAttribute('data-tone', 'ok');
    await expect(page.locator('[data-part="test-step"]')).toBeVisible();
  });

  test('「—」 없음 · 1440×900 문서 넘침 0 — 세 페이지(연동은 여러 컨테이너 2단계까지)', async ({ page, backend }) => {
    void backend;
    for (const p of PAGES) {
      await page.goto(p.path);
      await ready(page, p.page);
      if (p.page === 'setup') {
        await page.locator('[data-scn="multi"]').click();
        await page.locator('[data-part="wizard-next"]').click();
        await expect(page.locator('[data-part="apply"]')).toBeVisible();
      }
      await page.waitForTimeout(400);
      expect(await dashes(page), p.path).toEqual([]);
      await noPageOverflow(page);
    }
  });
});

test.describe('② 사이드바 그룹 접고 펴기', () => {
  test('「연동」 그룹 = 대시보드 바로 아래 · 하위 3개 · 정책 그룹과 같은 모양(시연은 그 아래)', async ({ page, backend }) => {
    backend.enableDemo();
    await page.goto('/');
    const home = page.locator(`${NAV} [data-nav-group="home"]`);
    expect(await home.evaluate((g) => [...g.children].map((e) => e.getAttribute('href') ?? `sub:${e.getAttribute('data-nav-sub')}`))).toEqual(['/', 'sub:integration', '/demo']);
    const links = sub(page, 'integration').locator('[data-part="subnav"] a');
    await expect(links).toHaveText(['연동', '환경 점검', '감시 중 컨테이너']);
    expect(await links.evaluateAll((els) => els.map((e) => e.getAttribute('href')))).toEqual(['/integration', '/integration/env', '/integration/watch']);
    await expect(toggle(page, 'integration')).toContainText('연동');
    await expect(toggle(page, 'policies')).toContainText('정책');
  });

  test('처음엔 접힘 · 머리를 누르면 펼침/접힘(aria-expanded · 화살표) · 새로고침 뒤 기억 · 그룹마다 따로', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    for (const id of ['integration', 'policies']) {
      await expect(toggle(page, id), id).toHaveAttribute('aria-expanded', 'false');
      await expect(sub(page, id), id).toHaveAttribute('data-open', 'false');
      await expect(sub(page, id).locator('[data-part="subnav"] a').first(), id).toBeHidden();
      await expect(toggle(page, id).locator('svg[data-part="subnav-chevron"]'), id).toHaveCount(1);
    }
    expect(await stored(page)).toBeNull();
    // 연동 펼침
    await toggle(page, 'integration').click();
    await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'true');
    await expect(sub(page, 'integration').getByRole('link', { name: '환경 점검' })).toBeVisible();
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'false');
    expect(JSON.parse((await stored(page))!)).toEqual({ integration: true });
    await page.reload();
    await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'true');
    await expect(sub(page, 'integration').getByRole('link', { name: '감시 중 컨테이너' })).toBeVisible();
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'false');
    // 정책도 펼침 → 연동 접음 → 새로고침
    await toggle(page, 'policies').click();
    await toggle(page, 'integration').click();
    await expect(sub(page, 'integration').locator('[data-part="subnav"] a').first()).toBeHidden();
    expect(JSON.parse((await stored(page))!)).toEqual({ integration: false, policies: true });
    await page.reload();
    await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'false');
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'true');
    await expect(sub(page, 'policies').getByRole('link', { name: '차단 목록' })).toBeVisible();
    // 펼친 하위 메뉴로 이동
    await sub(page, 'policies').getByRole('link', { name: '변경 이력' }).click();
    await expect(page).toHaveURL(/\/policies\/changes$/);
    // 깨진 저장값 → 처음처럼 접힘
    await page.evaluate((k) => localStorage.setItem(k, '{broken'), OPEN_KEY);
    await page.goto('/');
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'false');
    await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'false');
  });

  test('지금 화면이 속한 그룹은 늘 펼침 — 눌러도 접히지 않음(사유) · 다른 그룹은 저장 상태 그대로', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await page.evaluate((k) => localStorage.setItem(k, JSON.stringify({ integration: false, policies: false })), OPEN_KEY);
    await page.goto('/policies/blocklist');
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'true');
    await expect(sub(page, 'policies').getByRole('link', { name: '차단 목록' })).toBeVisible();
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-disabled', 'true');
    await expect(toggle(page, 'policies')).toHaveAttribute('title', '지금 화면이 속한 메뉴는 접을 수 없습니다');
    await toggle(page, 'policies').click();
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'true');
    await expect(sub(page, 'policies').getByRole('link', { name: '변경 이력' })).toBeVisible();
    await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'false');
    // 연동 하위 화면으로 — 연동은 펼치고 정책은 저장 상태(접힘)로
    await page.goto('/integration/env');
    await ready(page, 'env');
    await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'true');
    await expect(sub(page, 'integration').getByRole('link', { name: '환경 점검' })).toHaveAttribute('aria-current', 'page');
    await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'false');
    await expect(toggle(page, 'policies')).not.toHaveAttribute('aria-disabled', 'true');
    expect(JSON.parse((await stored(page))!)).toEqual({ integration: false, policies: false }); // 강제 펼침은 저장하지 않는다
    await page.screenshot({ path: `${SHOT}/nav-fold-1440.png` });
  });

  test('움직임 — 펼침 전환 --dur-base(180ms) · 동작 줄이기면 전환 없음', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    const fold = sub(page, 'integration').locator('[data-part="subnav-fold"]');
    const tr = () => fold.evaluate((e) => ({ p: getComputedStyle(e).transitionProperty, d: getComputedStyle(e).transitionDuration }));
    const t = await tr();
    expect(t.p).toContain('grid-template-rows');
    expect(t.d.split(',')[0].trim()).toBe('0.18s');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.reload();
    expect((await tr()).p).toBe('none');
  });

  test('접힌 사이드바(아이콘만) — 연동 하위 메뉴 팝오버 그대로 · 고르면 이동 · 키보드 초점으로도 뜸', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await page.getByRole('button', { name: '사이드바 접기' }).click();
    await expect(page.locator('[data-part="sidebar"]')).toHaveAttribute('data-collapsed', 'true');
    const pop = page.locator('[data-part="subnav-pop"]');
    await expect(toggle(page, 'integration')).toHaveCount(0); // 아이콘만 — 접기 단추 없음
    await sub(page, 'integration').hover();
    await expect(pop).toBeVisible();
    await expect(pop.locator('a')).toHaveText(['연동', '환경 점검', '감시 중 컨테이너']);
    await pop.getByRole('link', { name: '환경 점검' }).click();
    await expect(page).toHaveURL(/\/integration\/env$/);
    await expect(page.getByTestId('page-title')).toHaveText('환경 점검');
    await page.mouse.move(900, 500);
    await expect(pop).toHaveCount(0);
    await sub(page, 'integration').focus();
    await expect(pop).toBeVisible();
    await expect(pop.locator('a[href="/integration/env"]')).toHaveAttribute('aria-current', 'page');
    await page.screenshot({ path: `${SHOT}/nav-collapsed-pop.png` });
  });

  test.describe('390 서랍', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('연동 그룹 펴고 하위 메뉴 고르면 이동 · 서랍 닫힘 · 다시 열면 지금 그룹 펼침', async ({ page, backend }) => {
      void backend;
      await page.goto('/');
      const menu = page.getByRole('button', { name: '메뉴', exact: true });
      await menu.click();
      await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'false');
      await toggle(page, 'integration').click();
      await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'true');
      await page.waitForTimeout(300);
      await page.screenshot({ path: `${SHOT}/nav-drawer-390.png` });
      await sub(page, 'integration').getByRole('link', { name: '감시 중 컨테이너' }).click();
      await expect(page).toHaveURL(/\/integration\/watch$/);
      await expect(page.locator('[data-part="sidebar"]')).toHaveCount(0);
      await ready(page, 'watch');
      await expect(page.getByTestId('page-title')).toHaveText('감시 중 컨테이너');
      await menu.click();
      await expect(toggle(page, 'integration')).toHaveAttribute('aria-expanded', 'true');
      await expect(toggle(page, 'policies')).toHaveAttribute('aria-expanded', 'false');
    });
  });
});

test.describe('③ 화면 사진', () => {
  for (const theme of ['light', 'dark'] as const)
    test(`1440×900 ${theme} — 연동 · 환경 점검 · 감시 중 컨테이너`, async ({ page, backend }) => {
      void backend;
      if (theme === 'dark') await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
      for (const p of PAGES) {
        await page.goto(p.path);
        await ready(page, p.page);
        if (p.page === 'setup') await page.locator('[data-scn="single"]').click();
        await page.waitForTimeout(900);
        await page.screenshot({ path: `${SHOT}/${p.page}-1440-${theme}.png` });
      }
    });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390 — 세 페이지', async ({ page, backend }) => {
      void backend;
      for (const p of PAGES) {
        await page.goto(p.path);
        await ready(page, p.page);
        await page.waitForTimeout(900);
        expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth), `${p.path} 가로 넘침`).toBe(0);
        await page.screenshot({ path: `${SHOT}/${p.page}-390.png`, fullPage: true });
      }
    });
  });
});
