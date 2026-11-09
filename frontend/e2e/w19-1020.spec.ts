import type { Page } from '@playwright/test';
import type { Scan, Verdict } from '../src/lib/types';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// W19(10/20 2차 시안 C · D · E) — 셸: 알림 센터 · 통합 검색 · 사이드바 접기 · ? 도움말 · 실시간 끊김 배너 + 끊긴 구간 채우기 · 최초 로드 실패 표시.
// 기준: 목업 shared/shell-plus.js · app.js(끊김 배너 · liveBackfill · helpDialog), 스크린샷 w10-notify · w10-sidebar-collapsed.

const BELL = '[data-part="bell"]';
const NOTICES = '[data-part="notices"]';
const notice = (p: Page, id: string) => p.locator(`${NOTICES} [data-notice="${id}"]`);
const bellBadge = (p: Page) => p.locator(`${BELL} [data-part="bell-badge"]`);
const search = (p: Page) => p.getByRole('combobox', { name: /통합 검색/ });
const results = (p: Page) => p.locator('[data-part="search-results"]');
const aside = (p: Page) => p.locator('aside[data-part="sidebar"]');

async function ready(page: Page, path = '/') {
  await page.goto(path);
  await expect(page.getByText('실시간 연결됨')).toBeVisible();
}
async function openBell(page: Page) {
  if (await page.locator(NOTICES).isHidden()) await page.locator(BELL).click();
  await expect(page.locator(NOTICES)).toBeVisible();
}
const width = async (p: Page) => Math.round((await aside(p).boundingBox())!.width);

// mock-backend 에는 /api/scans 가 없다 — 검색 시나리오에서만 가로챈다
const scan: Scan = {
  id: 'scan-0007', target: { kind: 'package', manager: 'pip', name: 'colourama', version: '0.1.0', label: 'pip colourama 0.1.0' },
  status: 'done', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), verdict: 'malicious', risk: { score: 9, label: 'high' },
  engines: null, caseId: null, threats: 2, capabilities: 0, vulnCount: 0, vulnMax: null,
};
async function scansApi(page: Page) {
  await page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const detail = /\/api\/scans\/[^/?]+/.test(route.request().url());
    const body = detail ? { ...scan, findings: [], vulns: [], packages: [], files: {} } : [scan];
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
}

// 검색 칸에 들어오면 목록 API(설치 검사 · 공급망 검사 · 정책 · 차단 목록)를 읽는다 — /api/scans 는 이 파일에서 가로챈다
// (backend 를 먼저 붙여야 뒤에 등록한 이 route 가 먼저 맞는다)
test.beforeEach(async ({ page, backend }) => {
  void backend;
  await scansApi(page);
});

test.describe('W19 알림 센터 (C)', () => {
  test('1 알림 7종을 데이터로 계산 — 판정 대기 · 제안 · 연결 끊김 · 도메인 판단 꺼짐 · dry-run · 웹훅 실패 · 라이선스 30일 이하', async ({ page, backend }) => {
    backend.info.dnsResolve = 'off';
    backend.info.enforceKill = false;
    backend.stats.enforceKill = false;
    backend.info.notify = { ...backend.info.notify!, failed: 3, lastError: 'HTTP 502 Bad Gateway' };
    backend.auth.setLicenseDays(10);
    backend.proposals.push({ id: 'prop-0101', caseId: 'case-0003', decision: 'false_positive', state: 'draft', createdAt: new Date().toISOString(), createdBy: 'x', appliedAt: null, appliedBy: null, changes: [], notes: [] });
    await ready(page, '/events');
    await openBell(page);
    await expect(notice(page, 'pending')).toContainText('판정 대기 3건');
    await expect(notice(page, 'proposals')).toContainText('적용하지 않은 제안 1건');
    await expect(notice(page, 'dns')).toContainText('도메인 판단 꺼짐');
    await expect(notice(page, 'dryrun')).toContainText('dry-run');
    await expect(notice(page, 'webhook')).toContainText('알림 발송 실패 3건');
    await expect(notice(page, 'webhook')).toContainText('HTTP 502');
    await expect(notice(page, 'license')).toContainText(/라이선스 \d+일 남음/);
    await expect(notice(page, 'conn')).toHaveCount(0);
    // 실시간 연결이 끊기면 그 항목이 생긴다
    backend.wsRefuse = true;
    backend.dropWs();
    await expect(notice(page, 'conn')).toContainText('실시간 연결 끊김');
    await page.screenshot({ path: `${SHOTS}/w19-notify.png` });
  });

  test('2 라이선스 만료 · 이상 없음이면 「새 알림 없음」', async ({ page, backend }) => {
    backend.empty();
    backend.auth.setLicenseDays(-1);
    await ready(page);
    // 만료 라이선스는 로그인 게이트가 막을 수 있다 — 막히지 않는 경우(앱이 떴을 때)만 확인
    await openBell(page);
    await expect(notice(page, 'license')).toContainText('라이선스 만료');
    backend.auth.setLicenseDays(200);
    await page.reload();
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await openBell(page);
    await expect(page.locator(`${NOTICES} [data-notice]`)).toHaveCount(0);
    await expect(page.locator(NOTICES)).toContainText('새 알림 없음');
    await expect(bellBadge(page)).toBeHidden();
  });

  test('3 읽음 · 모두 읽음(localStorage) · 건이 늘면 다시 안 읽음', async ({ page, backend }) => {
    backend.info.dnsResolve = 'off';
    await ready(page);
    await expect(bellBadge(page)).toHaveText('2'); // 판정 대기 · 도메인 판단 꺼짐
    await openBell(page);
    await expect(notice(page, 'pending')).toHaveAttribute('data-unread', 'true');
    await page.locator(NOTICES).getByRole('button', { name: '모두 읽음' }).click();
    await expect(bellBadge(page)).toBeHidden();
    await expect(notice(page, 'pending')).toHaveAttribute('data-unread', 'false');
    await page.reload();
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await expect(bellBadge(page)).toBeHidden();
    // 새 건 → 판정 대기 서명이 바뀌어 다시 안 읽음
    backend.openCase();
    await expect(bellBadge(page)).toHaveText('1');
    await openBell(page);
    await expect(notice(page, 'pending')).toContainText('판정 대기 4건');
    await expect(notice(page, 'pending')).toHaveAttribute('data-unread', 'true');
    await expect(notice(page, 'dns')).toHaveAttribute('data-unread', 'false');
  });

  test('4 항목을 누르면 그 화면 + 읽음 — 판정 대기 → 대시보드, 서버 상태 → /settings, 제안 → 정책, 라이선스 → 설정 라이선스 탭', async ({ page, backend }) => {
    backend.info.dnsResolve = 'off';
    backend.auth.setLicenseDays(5);
    backend.proposals.push({ id: 'prop-0102', caseId: 'case-0003', decision: 'false_positive', state: 'draft', createdAt: new Date().toISOString(), createdBy: 'x', appliedAt: null, appliedBy: null, changes: [], notes: [] });
    await ready(page, '/events');
    await openBell(page);
    await notice(page, 'pending').click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.locator(NOTICES)).toBeHidden();
    await openBell(page);
    await expect(notice(page, 'pending')).toHaveAttribute('data-unread', 'false');
    await notice(page, 'dns').click();
    await expect(page).toHaveURL(/\/settings$/);
    await openBell(page);
    await notice(page, 'proposals').click();
    await expect(page).toHaveURL(/\/policies\?proposal=prop-0102/);
    await openBell(page);
    await notice(page, 'license').click();
    await expect(page).toHaveURL(/\/settings\?tab=license/);
    await expect(bellBadge(page)).toBeHidden();
    // Esc 로 닫힘
    await openBell(page);
    await page.keyboard.press('Escape');
    await expect(page.locator(NOTICES)).toBeHidden();
  });
});

test.describe('W19 통합 검색 (E)', () => {
  test('5 / 로 포커스 · 패키지 · 컨테이너 · 규칙 · 도메인 · 검사 · ↑↓ Enter 이동 · Esc 닫기', async ({ page, backend }) => {
    void backend;
    await ready(page);
    await page.keyboard.press('/');
    await expect(search(page)).toBeFocused();
    await search(page).fill('reqeusts');
    await expect(results(page)).toBeVisible();
    await expect(results(page).locator('[data-type="package"]').first()).toContainText('reqeusts');
    await expect(results(page).locator('[data-type="container"]').first()).toContainText('pkg-reqeusts');
    await expect(results(page).locator('[data-type="domain"]').first()).toContainText('cdn.reqeusts-update.test');
    await search(page).fill('sensitive');
    await expect(results(page).locator('[data-type="rule"]')).toContainText(['sensitive-files']);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/policies\?id=sensitive-files/);
    await expect(results(page)).toBeHidden();
    // 검사(목록 API) · 도메인(정책 allowHosts)
    await page.keyboard.press('/');
    await search(page).fill('colourama');
    await expect(results(page).locator('[data-type="scan"]')).toContainText(['scan-0007']);
    await expect(results(page).locator('[data-type="domain"]').first()).toContainText('cdn.colourama.test');
    await search(page).fill('pypi.org');
    await expect(results(page).locator('[data-type="domain"]').first()).toContainText('pypi.org');
    await search(page).fill('colourama');
    const all = results(page).locator('[data-result]');
    const scanIdx = await all.evaluateAll((els) => els.findIndex((e) => e.getAttribute('data-type') === 'scan'));
    for (let i = 0; i < scanIdx; i++) await page.keyboard.press('ArrowDown');
    await expect(all.nth(scanIdx)).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/scans\?id=scan-0007/);
    // Esc 로 닫기 · 입력 칸에서 / 는 글자
    await page.keyboard.press('/');
    await search(page).fill('zzz-nothing');
    await expect(results(page)).toContainText('찾는 것이 없습니다');
    await page.keyboard.press('Escape');
    await expect(results(page)).toBeHidden();
    await search(page).focus();
    await page.keyboard.type('a/b');
    await expect(search(page)).toHaveValue('a/b');
  });
});

test.describe('W19 사이드바 접기 (E)', () => {
  test('6 넓은 화면: 누르면 56px · [ 로 토글 · 이 브라우저에 기억', async ({ page, backend }) => {
    void backend;
    await ready(page);
    expect(await width(page)).toBeGreaterThan(150);
    await page.getByRole('button', { name: '사이드바 접기' }).click();
    expect(await width(page)).toBe(56);
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'true');
    // 접혀도 메뉴 이름(접근성 이름)은 남는다 · 판정 대기 배지
    await expect(page.getByRole('navigation', { name: '화면' }).getByRole('link', { name: /이벤트/ })).toBeVisible();
    await page.reload();
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'true');
    expect(await width(page)).toBe(56);
    await page.screenshot({ path: `${SHOTS}/w19-sidebar-collapsed.png` });
    await page.keyboard.press('[');
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'false');
    expect(await width(page)).toBeGreaterThan(150);
    // 접힌 상태에서도 / 검색은 열린다
    await page.keyboard.press('[');
    await page.keyboard.press('/');
    await expect(search(page)).toBeFocused();
    await expect(search(page)).toBeVisible();
  });

  test('7 1100px 이하: 자동 접힘 · 펼침은 그 화면 동안만(저장 안 함) · 넓은 화면 설정은 그대로', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 1000, height: 800 });
    await ready(page);
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'true');
    expect(await width(page)).toBe(56);
    await page.getByRole('button', { name: '사이드바 펼치기' }).click();
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'false');
    const stored = await page.evaluate(() => localStorage.getItem('supplyguard.sidebar'));
    expect(stored).toBeNull();
    // 펼친 사이드바가 본문을 밀지 않는다(겹쳐 뜸) — 넘침 없음
    await noPageOverflow(page);
    // 화면을 옮기면 다시 접힘
    await page.getByRole('navigation', { name: '화면' }).getByRole('link', { name: /이벤트/ }).click();
    await expect(page).toHaveURL(/\/events/);
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'true');
    await page.keyboard.press('[');
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'false');
    await page.reload();
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'true');
    // 넓게 돌아오면 넓은 화면 설정(기본 펼침)
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(aside(page)).toHaveAttribute('data-collapsed', 'false');
  });
});

test.describe('W19 도움말 (E)', () => {
  test('8 ? → 사용 흐름 6단계 + 단축키 표 · Esc 닫기 · 입력 중에는 열리지 않음', async ({ page, backend }) => {
    void backend;
    await ready(page);
    await page.keyboard.press('?');
    const help = page.locator('dialog[data-part="help"]');
    await expect(help).toBeVisible();
    await expect(help.locator('[data-part="flow"] li')).toHaveCount(6);
    const keys = help.locator('[data-part="shortcuts"] kbd');
    await expect(keys).toHaveText(['/', '?', 'Esc', 'Enter', '↑ ↓', '[']);
    await page.keyboard.press('Escape');
    await expect(help).toBeHidden();
    // 버튼으로도 열고, 단계의 「이동」은 그 화면
    await page.getByRole('button', { name: /사용 안내/ }).click();
    await help.locator('[data-part="flow"] li').nth(1).getByRole('link', { name: '이동' }).click();
    await expect(page).toHaveURL(/\/installs/);
    await expect(help).toBeHidden();
    await search(page).focus();
    await page.keyboard.type('?');
    await expect(help).toBeHidden();
  });
});

test.describe('W19 실시간 끊김 · 채우기 (D)', () => {
  test('9 끊기면 붉은 배너 · 다시 붙으면 recent 로 끊긴 구간을 채우고 「끊긴 동안 N건」 토스트(중복 제거)', async ({ page, backend }) => {
    await ready(page, '/events');
    const dup = killedVerdict('dup-ctr');
    backend.send({ type: 'verdict', data: dup });
    await expect(page.locator('li[data-key]', { hasText: 'dup-ctr' })).toHaveCount(1);
    backend.wsRefuse = true;
    backend.dropWs();
    const banner = page.locator('[data-banner="conn"]');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('실시간 연결이 끊겼습니다');
    // 끊긴 동안 서버가 받은 이벤트 2건 + 이미 받은 1건(같은 시각 · 컨테이너 · 종류)
    const gapA: Verdict = killedVerdict('gap-a');
    const gapB: Verdict = killedVerdict('gap-b');
    backend.recent.unshift(gapB, gapA, JSON.parse(JSON.stringify(dup)) as Verdict);
    backend.wsRefuse = false;
    await expect(banner).toBeHidden({ timeout: 15_000 });
    await expect(page.getByText('끊긴 동안 2건을 채웠습니다')).toBeVisible();
    await expect(page.locator('li[data-key]', { hasText: 'gap-a' })).toHaveCount(1);
    await expect(page.locator('li[data-key]', { hasText: 'gap-b' })).toHaveCount(1);
    await expect(page.locator('li[data-key]', { hasText: 'dup-ctr' })).toHaveCount(1);
  });

  test('10 최초 recent · stats 로드 실패를 삼키지 않는다 — 오류 배너 · 다시 시도', async ({ page, backend, allowConsole }) => {
    allowConsole(/Failed to load resource: the server responded with a status of 503/);
    backend.failing.set('/events/recent', 503);
    backend.failing.set('/stats', 503);
    // W20: /events 는 같은 실패를 목록 오류 칸 한 곳에만 보인다 — 배너는 다른 화면(대시보드)에서 확인
    await page.goto('/');
    const banner = page.locator('[data-banner="load"]');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('이벤트를 불러오지 못했습니다');
    await expect(banner).toContainText('모의 오류(서버가 응답하지 않습니다)'); // 11/09 G14: 상태 코드 없이 서버 문장만
    backend.failing.clear();
    await banner.getByRole('button', { name: '다시 시도' }).click();
    await expect(banner).toBeHidden();
    await page.locator('aside a[href="/events"]').first().click(); // 같은 앱 안 이동 — 다시 불러온 판정이 목록에
    await expect(page.locator('li[data-key]', { hasText: 'pkg-reqeusts' }).first()).toBeVisible();
  });
});

test.describe('W19 좁은 화면 넘침 0', () => {
  const SCREENS: [string, string, string][] = [
    ['01-dashboard', '/', 'pending'],
    ['02-installs', '/installs?id=ins-0012', 'installs'],
    ['03-events', '/events', 'events'],
    ['04-topology', '/topology?container=pkg-reqeusts', 'topology'],
    ['05-policies', '/policies?id=egress-allowlist', 'rules'],
    ['06-audit', '/audit', 'audit'],
  ];
  test.use({ viewport: { width: 960, height: 760 } });
  for (const [name, url, testId] of SCREENS) {
    test(`11 960px ${name}`, async ({ page, backend }) => {
      void backend;
      await page.goto(url);
      await expect(page.getByTestId(testId)).toBeVisible();
      await page.waitForTimeout(300);
      await noPageOverflow(page);
      // 상단 줄도 잘리지 않는다 — 종 · 계정 메뉴가 화면 안
      const hdr = await page.locator('header').first().evaluate((e) => e.scrollWidth - e.clientWidth);
      expect(hdr).toBe(0);
      const bell = (await page.locator(BELL).boundingBox())!;
      expect(bell.x + bell.width).toBeLessThanOrEqual(960);
      await page.screenshot({ path: `${SHOTS}/960-${name}.png` });
    });
  }
});
