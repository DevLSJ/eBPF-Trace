import type { Page } from '@playwright/test';
import type { Verdict } from '../src/lib/types';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// W20(10/20) — 이벤트 화면 정리 · connect 의 dnsTraced false 명시 · 768px 폭

// ── dnsTraced 3가지(필드 없음 = 옛 기록) ──
test.describe('W20 도메인 조회 줄 — dnsTraced false · 없음 · true', () => {
  const at = () => new Date().toISOString();
  const connect = (ip: string, extra: Partial<Verdict['event']>): Verdict => ({
    event: { kind: 'connect', timestamp: at(), containerId: 'c0ffee', containerName: 'dns-ctr', imageName: 'demo/x:1', comm: 'curl', pid: 7, dstIp: ip, dstPort: 443, ...extra },
    matched: true,
    ruleId: 'egress-allowlist',
    action: 'alert',
    reason: '허용 목적지 외 통신',
  });

  test('false → 판단 불가(trace_dns 꺼짐) · 없음 → 기록 없음(옛 기록) · true → 지금처럼', async ({ page, backend }) => {
    backend.recent.unshift(
      connect('198.51.100.21', { dnsTraced: false }),
      connect('198.51.100.22', {}),
      connect('198.51.100.23', { dnsTraced: true, dstHost: 'files.example.test' }),
    );
    await page.goto('/events');
    const dd = page.locator('[data-sheet="event"] [data-dns]');

    await page.locator('li[data-key]', { hasText: '198.51.100.21' }).click();
    await expect(dd).toHaveAttribute('data-dns', 'off');
    await expect(dd).toHaveText('판단 불가 — trace_dns 꺼짐(도메인 기준 규칙은 통과 처리)');

    await page.locator('li[data-key]', { hasText: '198.51.100.22' }).click();
    await expect(dd).toHaveAttribute('data-dns', 'unknown');
    await expect(dd).toHaveText('기록 없음(옛 기록)');

    await page.locator('li[data-key]', { hasText: '198.51.100.23' }).click();
    await expect(dd).toHaveAttribute('data-dns', 'traced');
    await expect(dd).toHaveText('trace_dns 로 확인 — files.example.test');
  });

  test('가짜 백엔드의 connect 이벤트도 dnsTraced 를 명시한다(백엔드 계약)', async ({ page, backend }) => {
    void page;
    const conns = backend.recent.filter((v) => v.event.kind === 'connect');
    expect(conns.length).toBeGreaterThan(0);
    for (const v of conns) expect(typeof v.event.dnsTraced, JSON.stringify(v.event)).toBe('boolean');
    for (const v of backend.recent.filter((x) => x.event.kind !== 'connect')) expect(v.event.dnsTraced, JSON.stringify(v.event)).toBeUndefined();
  });
});

// ── 768px — 대시보드 · 이벤트 본문 넘침 0 ──
async function settle(page: Page, url: string, testId: string) {
  await page.goto(url);
  await expect(page.getByTestId(testId)).toBeVisible();
  await page.waitForTimeout(300);
}

test.describe('W20 768px 넘침 0', () => {
  for (const h of [700, 600]) {
    test.describe(`768×${h}`, () => {
      test.use({ viewport: { width: 768, height: h } });
      test(`대시보드 ${h}`, async ({ page, backend }) => {
        void backend;
        await settle(page, '/', 'pending');
        await expect(page.locator('[data-kpi="collected"]')).toBeVisible();
        await noPageOverflow(page);
        // 판정 대기 목록이 너무 눌리지 않는다(최소 7rem)
        expect((await page.getByTestId('pending').boundingBox())!.height).toBeGreaterThanOrEqual(112);
        await page.screenshot({ path: `${SHOTS}/w20-768x${h}-dashboard.png` });
      });
      test(`이벤트 ${h}`, async ({ page, backend }) => {
        void backend;
        await settle(page, '/events', 'events');
        await expect(page.locator('li[data-key]').first()).toBeVisible();
        await noPageOverflow(page);
        // 행이 패널 안에 들어온다 — 탐지 결과 열이 잘리지 않음
        const panel = (await page.getByTestId('events').boundingBox())!;
        const badge = (await page.locator('li[data-key]').first().locator('span').last().boundingBox())!;
        expect(badge.x + badge.width).toBeLessThanOrEqual(panel.x + panel.width);
        // 머리의 「일시정지」가 한 글자씩 세로로 꺾이지 않는다
        expect((await page.getByRole('button', { name: '일시정지' }).boundingBox())!.height).toBeLessThanOrEqual(32);
        expect(await page.locator('header').first().evaluate((e) => e.scrollWidth - e.clientWidth)).toBe(0);
        await page.screenshot({ path: `${SHOTS}/w20-768x${h}-events.png` });
      });
      test(`이벤트 + 상세 시트 ${h}`, async ({ page, backend }) => {
        void backend;
        await settle(page, '/events', 'events');
        await page.locator('li[data-key]').first().click();
        await expect(page.locator('[data-sheet="event"]')).toBeVisible();
        await page.waitForTimeout(200);
        await noPageOverflow(page);
        // 좁아진 목록: 필터 이름이 글자 단위로 꺾이지 않고, 행의 탐지 결과가 패널 안에 보인다
        const lbl = page.getByTestId('events').locator('label', { hasText: '컨테이너' });
        expect((await lbl.boundingBox())!.height).toBeLessThanOrEqual(36);
        const panel = (await page.getByTestId('events').boundingBox())!;
        const badge = (await page.locator('li[data-key]').first().locator('span').last().boundingBox())!;
        expect(badge.width).toBeGreaterThan(0);
        expect(badge.x + badge.width).toBeLessThanOrEqual(panel.x + panel.width);
        // 일시정지는 목록 필터 줄에 하나만 보인다 — 눌러서 동작
        await page.getByRole('button', { name: '일시정지' }).click();
        await expect(page.getByRole('button', { name: '재개' })).toBeVisible();
        await page.screenshot({ path: `${SHOTS}/w20-768x${h}-events-sheet.png` });
      });
    });
  }

  test.describe('넓은 폭에서는 이미지 · 규칙 열이 그대로', () => {
    test.use({ viewport: { width: 1440, height: 900 } });
    test('1440 이벤트 표 이미지 · 규칙 열', async ({ page, backend }) => {
      void backend;
      await settle(page, '/events', 'events');
      await expect(page.getByText('이미지', { exact: true })).toBeVisible();
      await expect(page.getByText('규칙', { exact: true })).toBeVisible();
    });
  });
});

// ── 이벤트 첫 로드 — 셸 스트림 값(recentLoading · recentError · retryLoad)만 쓴다(W20 후속) ──
const RECENT = /\/api\/events\/recent/;
async function countRecent(page: Page, path: string) {
  let n = 0;
  const on = (r: { url: () => string }) => {
    if (RECENT.test(r.url())) n++;
  };
  page.on('request', on);
  await page.goto(path);
  await expect(page.getByText('실시간 연결됨')).toBeVisible();
  await page.waitForTimeout(600);
  page.off('request', on);
  return n;
}

test.describe('W20 이벤트 첫 로드 — 중복 호출 · 오류 1곳 · 다시 시도', () => {
  test('/events 는 recent 를 셸 스트림 외에 더 부르지 않는다', async ({ page, backend }) => {
    void backend;
    const shell = await countRecent(page, '/'); // 대시보드 = 셸 스트림의 호출만
    const events = await countRecent(page, '/events');
    expect(shell).toBeGreaterThan(0);
    expect(events).toBe(shell);
  });

  test('첫 로드 실패 → 오류는 목록 칸 한 곳 · 다시 시도는 셸의 retryLoad(다른 화면 배너도 풀린다)', async ({ page, backend, allowConsole }) => {
    allowConsole(/Failed to load resource: the server responded with a status of 503/);
    backend.failing.set('/events/recent', 503);
    await page.goto('/events');
    const err = page.locator('[data-part="error"]');
    await expect(err).toBeVisible();
    await expect(err).toContainText('503');
    await page.waitForTimeout(300);
    await expect(page.locator('[data-banner="load"]')).toHaveCount(0);
    await expect(page.locator('[role="alert"]')).toHaveCount(1);
    backend.failing.clear();
    await err.locator('[data-action="retry"]').click();
    await expect(page.locator('li[data-key]').first()).toBeVisible();
    await expect(err).toHaveCount(0);
    // 같은 앱 안에서 대시보드로 — 셸의 오류 상태도 풀렸다(페이지만 따로 다시 부른 것이 아님)
    await page.locator('aside a[href="/"]').first().click();
    await expect(page.getByTestId('pending')).toBeVisible();
    await page.waitForTimeout(300);
    await expect(page.locator('[data-banner="load"]')).toHaveCount(0);
  });

  test('다른 화면에서는 같은 실패가 셸 배너로 보인다', async ({ page, backend, allowConsole }) => {
    allowConsole(/Failed to load resource: the server responded with a status of 503/);
    backend.failing.set('/events/recent', 503);
    await page.goto('/');
    await expect(page.locator('[data-banner="load"]')).toBeVisible();
  });
});
