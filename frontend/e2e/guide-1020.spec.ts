import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 10/20 도우미 — 목업 회귀 mock/tests/guide-1020.cjs 를 React 로 옮긴 것 + 토스트 왼쪽 아래 + 도메인 판단 꺼짐 배너.
// 이번 이식은 「대응 가이드」 탭만(「AI 도우미」 탭은 /api/chat 이 생길 때 함께 옮긴다).
// 목업 8번(AI 도우미 탭 대화)은 → 「종결 건은 드롭다운에 남고 배지에서 빠진다 · 건이 있으면 구축 순서 없음」(사용자 10/20 확정)으로 바꿨다.

const FAB = '[data-part="assistant-fab"]';
const PANEL = '[data-part="assistant"]';
const G = '[data-part="guide"]';

const fab = (p: Page) => p.locator(FAB);
const panel = (p: Page) => p.locator(PANEL);
const guide = (p: Page) => p.locator(G);
const step = (p: Page, n: number) => p.locator(`${G} [data-step="${n}"]`);
const badge = (p: Page) => p.locator(`${FAB} [data-part="assistant-badge"]`);
const progress = (p: Page) => p.locator(`${G} [data-part="guide-progress"]`);

// 셸 · 건 목록 · 실시간 연결이 준비될 때까지 — WS 로 새 건을 보내기 전에
async function ready(page: Page, path = '/') {
  await page.goto(path);
  await expect(page.getByText('실시간 연결됨')).toBeVisible();
  await expect(fab(page)).toHaveAttribute('data-ready', 'true');
}
async function openPanel(page: Page) {
  if (await panel(page).isHidden()) await fab(page).click();
  await expect(panel(page)).toBeVisible();
}
const caseShown = (page: Page, id: string) => expect(guide(page)).toHaveAttribute('data-guide-case', id);

test.describe('도우미 · 대응 가이드 (10/20)', () => {
  test('1 오른쪽 아래 버튼 하나(도우미) · 탭은 「대응 가이드」 하나 · Esc 로 닫히고 포커스는 버튼으로', async ({ page, backend }) => {
    void backend;
    await ready(page);
    await expect(fab(page)).toHaveCount(1);
    await expect(fab(page)).toHaveAttribute('aria-label', /도우미/);
    await expect(panel(page)).toBeHidden();
    await fab(page).click();
    await expect(panel(page)).toBeVisible();
    await expect(panel(page)).toHaveAttribute('role', 'dialog');
    const tabs = panel(page).getByRole('tab');
    await expect(tabs).toHaveCount(1);
    await expect(tabs.first()).toHaveText(/대응 가이드/);
    await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
    await expect(panel(page).getByRole('tab', { name: /AI 도우미/ })).toHaveCount(0);
    await page.keyboard.press('Escape');
    await expect(panel(page)).toBeHidden();
    await expect(fab(page)).toBeFocused();
  });

  test('2 건이 없을 때: 구축 순서 3단계 · 명령 복사 · 정책 화면을 열면 ② 완료 · 그만 보기는 새로고침 뒤에도', async ({ page, backend }) => {
    backend.empty();
    await ready(page);
    await fab(page).click();
    const S = page.locator(`${G} [data-part="setup-steps"]`);
    await expect(S).toBeVisible();
    await expect(S.locator('[data-setup]')).toHaveCount(3);
    await expect(S.locator('[data-setup="install"]')).toHaveAttribute('data-done', 'false');
    await expect(S.locator('[data-setup="policies"]')).toHaveAttribute('data-done', 'false');
    // 런타임 컨테이너는 데이터로(토폴로지에 컨테이너가 보이면) 완료
    await expect(S.locator('[data-setup="runtime"]')).toHaveAttribute('data-done', 'true');
    await S.getByRole('button', { name: 'sg-install 명령 복사' }).click();
    await expect(page.locator('[data-toast="copy"]')).toContainText('sg-install pip requests');
    // 가이드 안의 링크 → 이동하고 패널은 닫힌다
    await S.getByRole('link', { name: /정책/ }).click();
    await expect(page.getByTestId('page-title')).toHaveText('정책');
    await expect(panel(page)).toBeHidden();
    await openPanel(page);
    await expect(S.locator('[data-setup="policies"]')).toHaveAttribute('data-done', 'true');
    await S.getByRole('button', { name: '구축 순서 그만 보기' }).click();
    await expect(S).toHaveCount(0);
    await expect(page.locator(`${G} [data-part="setup-off"]`)).toBeVisible();
    await page.reload();
    await expect(fab(page)).toHaveAttribute('data-ready', 'true');
    await openPanel(page);
    await expect(page.locator(`${G} [data-part="setup-off"]`)).toBeVisible();
    await expect(S).toHaveCount(0);
  });

  test('3 새 건(격리) → 대시보드에서 가이드 자동 열림 · 그 건 선택 · 1 · 2 자동 완료 · 2/5 · 배지 1', async ({ page, backend }) => {
    backend.empty();
    await ready(page);
    await expect(panel(page)).toBeHidden();
    const c = backend.openCase();
    await expect(panel(page)).toBeVisible();
    await expect(panel(page).getByRole('tab', { name: /대응 가이드/ })).toHaveAttribute('aria-selected', 'true');
    await caseShown(page, c.id);
    await expect(step(page, 1)).toHaveAttribute('data-done', 'true');
    await expect(step(page, 2)).toHaveAttribute('data-done', 'true');
    for (const r of c.ruleIds) await expect(step(page, 1)).toContainText(r);
    await expect(step(page, 1)).toContainText(/\d{2}:\d{2}/);
    await expect(step(page, 2)).toContainText('격리됨');
    for (const n of [3, 4, 5]) await expect(step(page, n)).toHaveAttribute('data-done', 'false');
    await expect(progress(page)).toHaveAttribute('data-value', '2/5');
    await expect(badge(page)).toHaveText('1');
  });

  test('4 체인 링크 → 완료 · 시트로 이동(패널 닫힘) / 판정 뒤 4 완료 / 후속 조치 체크 → 5/5 · 배지 0 · 새로고침 뒤 유지', async ({ page, backend }) => {
    backend.empty();
    await ready(page);
    const c = backend.openCase();
    await caseShown(page, c.id);
    await step(page, 3).locator('a[data-part="chain-link"]').click();
    await expect(page).toHaveURL(new RegExp(`/installs\\?.*id=${c.installId}`));
    await expect(page.locator('[data-sheet="install"]')).toBeVisible();
    await expect(panel(page)).toBeHidden();
    await openPanel(page);
    await expect(step(page, 3)).toHaveAttribute('data-done', 'true');
    // Esc 는 패널만 닫는다(시트는 그대로)
    await page.keyboard.press('Escape');
    await expect(panel(page)).toBeHidden();
    await expect(page.locator('[data-sheet="install"]')).toBeVisible();
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await openPanel(page);
    await expect(step(page, 4)).toHaveAttribute('data-done', 'true');
    await expect(step(page, 4)).toContainText('악성');
    const boxes = step(page, 5).locator('input[type="checkbox"]');
    const n = await boxes.count();
    expect(n).toBeGreaterThanOrEqual(2);
    for (let i = 0; i < n; i++) await boxes.nth(i).check();
    await expect(step(page, 5)).toHaveAttribute('data-done', 'true');
    await expect(progress(page)).toHaveAttribute('data-value', '5/5');
    await expect(badge(page)).toBeHidden();
    const saved = await page.evaluate((id) => JSON.parse(localStorage.getItem(`supplyguard.guide.${id}`) || 'null'), c.id);
    expect(saved?.chain).toBe(true);
    expect(Object.values(saved?.follow ?? {}).filter(Boolean)).toHaveLength(n);
    await page.reload();
    await expect(fab(page)).toHaveAttribute('data-ready', 'true');
    await openPanel(page);
    await caseShown(page, c.id);
    await expect(progress(page)).toHaveAttribute('data-value', '5/5');
    await expect(badge(page)).toBeHidden();
  });

  test('5 dry-run(격리 모드 끔)이면 2 격리 확인에 「격리 대상」 — 컨테이너는 살아 있음', async ({ page, backend }) => {
    backend.empty();
    backend.info.enforceKill = false;
    await ready(page);
    const c = backend.openCase();
    expect(c.level).toBe('held');
    await caseShown(page, c.id);
    await expect(step(page, 2)).toContainText('격리 대상');
    await expect(step(page, 2)).toContainText('dry-run');
    await expect(step(page, 2)).toHaveAttribute('data-done', 'true');
  });

  test('6 후속 조치 문구는 규칙별 + 알림 상태(발송됨 · 미설정 · 실패)는 /api/info notify 로', async ({ page, backend }) => {
    backend.empty();
    await ready(page);
    const c = backend.openCase();
    await caseShown(page, c.id);
    const follow = step(page, 5);
    await expect(follow.locator('[data-group="secrets"]')).toContainText(/키 · 토큰 교체/);
    await expect(follow.locator('[data-group="secrets"]')).toHaveAttribute('data-follow', /sensitive-files/);
    await expect(follow.locator('[data-group="egress"]')).toContainText('차단 목록');
    await expect(follow.locator('[data-group="egress"]')).toHaveAttribute('data-follow', /sandbox-egress/);
    await expect(follow.locator('[data-group="download"]')).toContainText(/출처|고정/);
    await expect(follow.locator('[data-group="download"]')).toHaveAttribute('data-follow', /no-shell-download/);
    // 같은 묶음 규칙은 한 줄로
    await expect(follow.locator('[data-follow]')).toHaveCount(3);
    const notify = follow.locator('[data-part="notify"]');
    await expect(notify).toHaveAttribute('data-notify', 'sent');
    await expect(notify).toContainText('알림 발송됨');

    backend.info.notify = { enabled: false, channels: [], sent: 0, failed: 0, dropped: 0, suppressed: 0 };
    await page.reload();
    await expect(fab(page)).toHaveAttribute('data-ready', 'true');
    await openPanel(page);
    await expect(notify).toHaveAttribute('data-notify', 'off');
    await expect(notify).toContainText('미설정');
    await expect(notify).toContainText('NOTIFY_WEBHOOK_URL');

    backend.info.notify = { enabled: true, channels: [{ name: 'webhook', host: 'hooks.example.test', sent: 0, failed: 2, dropped: 0, queued: 0, lastError: 'connection refused' }], sent: 0, failed: 2, dropped: 0, suppressed: 0, lastError: 'webhook: connection refused' };
    await page.reload();
    await expect(fab(page)).toHaveAttribute('data-ready', 'true');
    await openPanel(page);
    await expect(notify).toHaveAttribute('data-notify', 'failed');
    await expect(notify).toContainText('실패');
    await expect(notify).toContainText('connection refused');

    delete backend.info.notify;
    await page.reload();
    await expect(fab(page)).toHaveAttribute('data-ready', 'true');
    await openPanel(page);
    await expect(notify).toHaveAttribute('data-notify', 'unknown');
    await expect(notify).toContainText('미확인');
  });

  test('7 건이 여러 개면 드롭다운(최근 5건, 맨 위가 최근) — 고르면 그 건의 가이드', async ({ page, backend }) => {
    backend.empty();
    await ready(page);
    const made: ReturnType<typeof backend.openCase>[] = [];
    for (let i = 0; i < 6; i++) {
      made.push(backend.openCase(i === 5 ? { level: 'alert', ruleIds: ['egress-allowlist'] } : {}));
      await page.waitForTimeout(30);
    }
    const sel = page.locator(`${G} select[data-part="guide-case"]`);
    await expect(sel).toBeVisible();
    const opts = await sel.locator('option').evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value));
    expect(opts).toHaveLength(5);
    expect(opts[0]).toBe(made[5].id);
    expect(opts).not.toContain(made[0].id);
    await caseShown(page, made[5].id);
    await expect(step(page, 2)).toContainText('경고');
    await sel.selectOption(made[2].id);
    await caseShown(page, made[2].id);
    await expect(step(page, 2)).toContainText('격리됨');
  });

  test('8 종결 건은 드롭다운에 남고 배지에서 빠진다 · 건이 있으면 구축 순서는 없다', async ({ page, backend }) => {
    void backend;
    await ready(page);
    // 시드: 열린 건 3(case-0005 · 0004 · 0003) + 종결 건 1(case-0002)
    await expect(badge(page)).toHaveText('3');
    await fab(page).click();
    await expect(page.locator(`${G} [data-part="setup-steps"]`)).toHaveCount(0);
    const sel = page.locator(`${G} select[data-part="guide-case"]`);
    const opts = await sel.locator('option').evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value));
    expect(opts).toContain('case-0002');
    // 기본 선택은 종결되지 않은 최근 건
    await caseShown(page, 'case-0005');
    await sel.selectOption('case-0002');
    await expect(step(page, 4)).toHaveAttribute('data-done', 'true');
    await expect(step(page, 4)).toContainText('종결');
    // 시드 건은 처음부터 있던 것이라 자동으로 열지 않았다 — 패널은 버튼으로 연 것
    await expect(badge(page)).toHaveText('3');
  });

  test('9 토스트는 왼쪽 아래(사이드바 바로 오른쪽) — 도우미 버튼 · 시트와 겹치지 않음', async ({ page, backend }) => {
    await ready(page, '/events');
    backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    const t = page.locator('[data-toast="kill:api-gw"]');
    await expect(t).toBeVisible();
    const [r, f, side, vh] = await Promise.all([
      t.boundingBox(),
      fab(page).boundingBox(),
      page.locator('aside').first().boundingBox(),
      page.evaluate(() => window.innerHeight),
    ]);
    expect(r && f && side).toBeTruthy();
    expect(r!.x).toBeGreaterThanOrEqual(side!.x + side!.width);
    expect(r!.x).toBeLessThan(side!.x + side!.width + 40);
    expect(r!.x + r!.width).toBeLessThan(f!.x);
    expect(vh - (r!.y + r!.height)).toBeLessThan(40);
  });

  test('9b 사이드바를 접으면 토스트도 사이드바 옆으로 따라 붙는다(10/20 결정)', async ({ page, backend }) => {
    await ready(page, '/events');
    await page.keyboard.press('[');
    await expect(page.locator('aside').first()).toHaveAttribute('data-collapsed', 'true');
    backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    const t = page.locator('[data-toast="kill:api-gw"]');
    await expect(t).toBeVisible();
    const [r, side] = await Promise.all([t.boundingBox(), page.locator('aside').first().boundingBox()]);
    expect(r!.x).toBeGreaterThanOrEqual(side!.x + side!.width);
    expect(r!.x).toBeLessThan(side!.x + side!.width + 40);
  });

  test('10 dnsResolve=off 면 상단 「도메인 판단 꺼짐」 배너(trace_dns 안내) · 닫으면 세션 동안 숨김 · ok 면 없음', async ({ page, backend }) => {
    await ready(page);
    const banner = page.locator('[data-banner="dns"]');
    await expect(banner).toHaveCount(0);
    backend.info.dnsResolve = 'off';
    await page.reload();
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('도메인 판단 꺼짐');
    await expect(banner).toContainText('trace_dns');
    await banner.getByRole('button', { name: '닫기' }).click();
    await expect(banner).toHaveCount(0);
    await page.reload();
    await expect(fab(page)).toHaveAttribute('data-ready', 'true');
    await expect(banner).toHaveCount(0);
  });

  test('11 대시보드 밖에서는 자동으로 열지 않고 배지 + 토스트 「가이드 열기」 · 화면을 옮기면 닫힘', async ({ page, backend }) => {
    backend.empty();
    await ready(page, '/installs');
    const c = backend.openCase();
    const t = page.locator(`[data-toast="guide:${c.id}"]`);
    await expect(t).toContainText('대응 가이드');
    await expect(t).toContainText('pip ./reqeusts');
    await expect(panel(page)).toBeHidden();
    await expect(badge(page)).toHaveText('1');
    await t.getByRole('button', { name: '가이드 열기' }).click();
    await expect(panel(page)).toBeVisible();
    await caseShown(page, c.id);
    await page.getByRole('navigation', { name: '화면' }).getByRole('link', { name: '이벤트' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('이벤트');
    await expect(panel(page)).toBeHidden();
    await expect(badge(page)).toHaveText('1');
  });

  for (const vp of [
    { width: 1440, height: 900 },
    { width: 1280, height: 800 },
  ]) {
    test(`12 패널을 연 채 ${vp.width} 넘침 0`, async ({ page, backend }) => {
      await page.setViewportSize(vp);
      backend.empty();
      await ready(page, '/installs');
      backend.openCase();
      await openPanel(page);
      const o = await page.evaluate(() => {
        const d = document.documentElement;
        const m = document.querySelector('main')!;
        const p = document.querySelector('[data-part="assistant"]')!.getBoundingClientRect();
        return [d.scrollHeight - innerHeight, d.scrollWidth - innerWidth, m.scrollHeight - m.clientHeight, m.scrollWidth - m.clientWidth, p.bottom - innerHeight, p.right - innerWidth, -p.top];
      });
      expect(o.every((x) => x <= 0), `넘침 ${JSON.stringify(o)}`).toBe(true);
    });
  }
});

