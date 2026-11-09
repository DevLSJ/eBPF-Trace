import type { Page } from '@playwright/test';
import type { Scan } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';
import { killedVerdict } from './mock-backend';

// 11/09 저녁 묶음 B — 피드백 · 오류 · 상태(참고 제품 UI 문서 대조 항목)
//   G14 연결 실패 = 고정 문장(「Failed to fetch」 없음) · 화면에 상태 코드(「500 ·」) 없음 — 서버 문장만, 없을 때만 상태별 고정 문장
//   G20 토스트 = 단추 있으면 9초 · 없으면 5초 · 위험은 role=alert(그 밖 status) · 들어올 때 120ms(동작 줄이기면 없음) · G24 닫기 아이콘 title
//   G04 없는 주소 = 「화면을 찾을 수 없습니다」 + 「대시보드로」(주소 그대로) · 시연 꺼짐 = 권한 없음 양식, 설정 이름은 툴팁만
//   G40 필터 해제 단추 = 「조건 지우기」 하나(모든 목록 화면) · G37 목록 오류 제목 조사(「을(를)」 대신 josa)
// 화면 사진은 UI_SHOTS(없으면 SHOTS)에

const OUT = process.env.UI_SHOTS ?? SHOTS;
const NET = '서버에 연결하지 못했습니다. 네트워크를 확인한 뒤 다시 시도하세요.';
const RECENT = /\/api\/events\/recent/;
const listError = (page: Page) => page.locator('[data-part="error"]');

test.describe('G14 오류 문구', () => {
  test('연결 실패(요청 자체가 끊김) → 고정 문장 · 「Failed to fetch」 없음', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/Failed to load resource|ERR_FAILED/);
    await page.route(RECENT, (r) => r.abort('failed'));
    await page.goto('/events');
    const err = listError(page);
    await expect(err).toContainText('불러오지 못했습니다');
    await expect(err).toContainText(NET);
    await expect(page.locator('body')).not.toContainText(/Failed to fetch|TypeError|NetworkError/);
    await page.screenshot({ path: `${OUT}/ui-b-net-error-1440.png` });
  });

  test('500 + 서버 문장 → 서버 문장만(상태 코드 글자 없음)', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 500/);
    backend.failing.set('/events/recent', 500);
    await page.goto('/events');
    const err = listError(page);
    await expect(err).toContainText('모의 오류(서버가 응답하지 않습니다)');
    await expect(err).not.toContainText('500');
    await expect(err).not.toContainText(' · 모의');
  });

  test('500 + 서버 문장 없음(텍스트 본문) → 상태별 고정 문장 · 영어 상태 글 없음', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/status of 500/);
    await page.route(RECENT, (r) => r.fulfill({ status: 500, contentType: 'text/plain', body: 'Internal Server Error' }));
    await page.goto('/events');
    const err = listError(page);
    await expect(err).toContainText('서버에서 오류가 났습니다. 잠시 뒤 다시 시도하세요.');
    await expect(err).not.toContainText('500');
    await expect(err).not.toContainText('Internal Server Error');
  });

  test('다른 화면의 셸 띠도 상태 코드 없이 서버 문장만', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 503/);
    backend.failing.set('/events/recent', 503);
    await page.goto('/');
    const banner = page.locator('[data-banner="load"]');
    await expect(banner).toContainText('모의 오류(서버가 응답하지 않습니다)');
    await expect(banner).not.toContainText('503');
  });
});

test.describe('G37 목록 오류 제목 조사', () => {
  test('「[무엇]을(를)」 대신 받침에 맞는 조사', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 500/);
    backend.failing.set('/events/recent', 500);
    await page.goto('/events');
    const err = listError(page);
    await expect(err).toContainText('최근 이벤트를 불러오지 못했습니다');
    await expect(err).not.toContainText('을(를)');
  });
});

// 토스트 시간: 띄운 뒤 시계를 멈추고(pauseAt) 손으로만 앞당긴다 — 실제 시간이 흘러 경계가 흔들리지 않게
async function pauseNow(page: Page) {
  const now = await page.evaluate(() => Date.now());
  await page.clock.pauseAt(new Date(now + 20));
}

test.describe('G20 · G24 토스트', () => {
  test('단추 없는 토스트 5초 · 단추 있는 토스트 9초(시계 조작)', async ({ page, backend }) => {
    await page.clock.install();
    await page.goto('/settings');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    // 단추 없음(설정 「화면 배치 기본 순서로」)
    await page.locator('[data-action="layout-reset"]').click();
    const plain = page.locator('[data-toast="layout-reset"]');
    await expect(plain).toBeVisible();
    await expect(plain.getByRole('button')).toHaveCount(1); // 닫기만
    await pauseNow(page);
    await page.clock.fastForward(4_500);
    await expect(plain).toBeVisible();
    await page.clock.fastForward(1_000);
    await expect(plain).toHaveCount(0);
    // 단추 있음(격리 → 「이벤트 보기」)
    await page.clock.resume();
    backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    const act = page.locator('[data-toast="kill:api-gw"]');
    await expect(act).toBeVisible();
    await expect(act.getByRole('button', { name: '이벤트 보기' })).toBeVisible();
    await pauseNow(page);
    await page.clock.fastForward(8_500);
    await expect(act).toBeVisible();
    await page.clock.fastForward(1_000);
    await expect(act).toHaveCount(0);
  });

  test('위험(격리) 토스트는 role=alert · 그 밖은 role=status · 닫기 아이콘 title = aria-label', async ({ page, backend }) => {
    await page.goto('/settings');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await page.locator('[data-action="layout-reset"]').click();
    const plain = page.locator('[data-toast="layout-reset"]');
    await expect(plain).toHaveAttribute('role', 'status');
    backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    const kill = page.locator('[data-toast="kill:api-gw"]');
    await expect(kill).toHaveAttribute('role', 'alert');
    await expect(page.getByRole('alert').filter({ hasText: 'api-gw 격리됨' })).toHaveCount(1);
    for (const t of [plain, kill]) {
      const x = t.getByRole('button', { name: '알림 닫기' });
      await expect(x).toHaveAttribute('title', '알림 닫기');
    }
    await page.screenshot({ path: `${OUT}/ui-b-toast-1440.png` });
    await kill.getByRole('button', { name: '알림 닫기' }).click();
    await expect(kill).toHaveCount(0);
  });

  test('들어올 때 120ms(--dur-fast · --ease-enter) · 동작 줄이기면 효과 없음', async ({ page, backend }) => {
    void backend;
    await page.goto('/settings');
    await page.locator('[data-action="layout-reset"]').click();
    const t = page.locator('[data-toast="layout-reset"]');
    await expect(t).toBeVisible();
    const anim = () => t.evaluate((e) => ({ name: getComputedStyle(e).animationName, dur: getComputedStyle(e).animationDuration, ease: getComputedStyle(e).animationTimingFunction }));
    const a = await anim();
    expect(a.name).not.toBe('none');
    expect(a.dur).toBe('0.12s');
    expect(a.ease).toBe('cubic-bezier(0.16, 1, 0.3, 1)');
    await page.locator('[data-toast="layout-reset"]').getByRole('button', { name: '알림 닫기' }).click();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.locator('[data-action="layout-reset"]').click();
    await expect(t).toBeVisible();
    expect((await anim()).name).toBe('none');
  });
});

test.describe('G04 없는 주소 · 시연 꺼짐', () => {
  test('없는 주소 → 「화면을 찾을 수 없습니다」 + 한 줄 설명 + 「대시보드로」(주소는 그대로)', async ({ page, backend }) => {
    void backend;
    await page.goto('/no-such-screen');
    const nf = page.locator('[data-part="not-found"]');
    await expect(nf.getByRole('heading', { name: '화면을 찾을 수 없습니다' })).toBeVisible();
    await expect(nf).toContainText('주소를 확인하거나 왼쪽 메뉴에서 화면을 고르세요.');
    await expect(page).toHaveURL(/\/no-such-screen$/);
    await nf.getByRole('link', { name: '대시보드로' }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    await expect(nf).toHaveCount(0);
  });

  test('시연 꺼짐(관리자) = 권한 없음 양식 · 화면 글에 대문자 설정 이름 없음(툴팁에만)', async ({ page, backend }) => {
    void backend;
    await page.goto('/demo');
    const d = page.locator('[data-part="demo-denied"]');
    await expect(d.locator('[data-part="denied"]')).toBeVisible();
    await expect(d).toHaveAttribute('data-reason', 'off');
    await expect(d).toContainText('시연을 쓸 수 없습니다.');
    await expect(d).toContainText('서버에서 시연이 꺼져 있습니다.');
    expect(await d.innerText()).not.toMatch(/[A-Z][A-Z0-9]*_[A-Z0-9_]+/);
    await expect(d.locator('[title*="DEMO_ENABLED"]')).toHaveCount(1);
    await expect(d.locator('svg')).toHaveCount(0); // 권한 없음 양식 — 아이콘 없음
  });
});

// 공급망 검사 목록은 가짜 백엔드에 없어 이 파일에서 가로챈다(lists-copy-1109 와 같은 방식)
const SCAN: Scan = {
  id: 'scan-0001',
  target: { kind: 'package', manager: 'pip', name: 'reqeusts', label: 'pip reqeusts' },
  status: 'done', startedAt: '2026-11-09T03:04:05Z', finishedAt: '2026-11-09T03:04:35Z', verdict: 'malicious', risk: { score: 8.2, label: 'high_risk' },
  engines: [], findings: [], vulns: [], packages: [], files: {}, caseId: null, threats: 3, capabilities: 0, vulnCount: 0, vulnMax: null,
};

test.describe('G40 필터 해제 단추 이름', () => {
  async function onlyClearConditions(page: Page, where: string) {
    const btns = page.locator('[data-action="clear-filters"], [data-action="clear-conditions"], [data-part="no-results"] button');
    await expect(btns.first(), where).toBeVisible();
    for (const t of await btns.allInnerTexts()) expect(t.trim(), where).toBe('조건 지우기');
    await expect(page.getByRole('button', { name: /^(모두 해제|필터 모두 해제)$/ }), where).toHaveCount(0);
  }
  const search = async (page: Page, bar: string, q: string) => {
    const box = page.locator(`[data-filter-bar="${bar}"] [role="searchbox"]`);
    await box.fill(q);
    await box.press('Enter');
  };

  test('이벤트 · 감사 로그 · 설치 검사 · 공급망 검사 · 정책 · 차단 목록 · 변경 이력 · 인증 감사 = 「조건 지우기」', async ({ page, backend }) => {
    void backend;
    await page.route(/\/api\/scans(\/|$|\?)/, (route) => {
      const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
      const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
      return path === '/scans' ? json([SCAN]) : json({ error: '검사 없음' }, 404);
    });
    await page.goto('/events?kind=exec');
    await onlyClearConditions(page, '이벤트');
    await page.goto('/audit?kind=connect');
    await onlyClearConditions(page, '감사 로그');
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await page.locator('[data-chip="npm"]').click();
    await onlyClearConditions(page, '설치 검사');
    await page.goto('/scans');
    await page.locator('[data-chip="malicious"]').click();
    await onlyClearConditions(page, '공급망 검사');
    await page.goto('/policies');
    await search(page, 'policies', 'zzz-없는-정책');
    await expect(page.locator('[data-part="no-results"]')).toBeVisible();
    await onlyClearConditions(page, '정책');
    await page.goto('/policies/blocklist');
    await search(page, 'blocklist', 'zzz-없는-도메인');
    await onlyClearConditions(page, '차단 목록');
    await page.goto('/policies/changes');
    await search(page, 'changes', 'zzz-없는-변경');
    await onlyClearConditions(page, '변경 이력');
    await page.goto('/settings?tab=auth-audit');
    await page.locator('[data-field="failed"]').check();
    await onlyClearConditions(page, '인증 감사');
  });
});

test.describe('화면 사진(1440 밝은 · 어두운 · 390)', () => {
  for (const v of [
    { name: '1440-light', w: 1440, h: 900, dark: false },
    { name: '1440-dark', w: 1440, h: 900, dark: true },
    { name: '390', w: 390, h: 844, dark: false },
  ]) {
    test(`없는 주소 · 시연 꺼짐 · 목록 오류 ${v.name}`, async ({ page, backend, allowConsole }) => {
      allowConsole(/status of 500/);
      await page.setViewportSize({ width: v.w, height: v.h });
      if (v.dark) await page.emulateMedia({ colorScheme: 'dark' });
      await page.goto('/no-such-screen');
      await expect(page.locator('[data-part="not-found"]')).toBeVisible();
      await expect(page.locator('body')).not.toContainText('—');
      await page.screenshot({ path: `${OUT}/ui-b-not-found-${v.name}.png` });
      await page.goto('/demo');
      await expect(page.locator('[data-part="demo-denied"]')).toBeVisible();
      await expect(page.locator('body')).not.toContainText('—');
      await page.screenshot({ path: `${OUT}/ui-b-demo-off-${v.name}.png` });
      backend.failing.set('/events/recent', 500);
      await page.goto('/events');
      await expect(listError(page)).toBeVisible();
      await expect(page.locator('body')).not.toContainText('—');
      await page.screenshot({ path: `${OUT}/ui-b-list-error-${v.name}.png` });
    });
  }
});
