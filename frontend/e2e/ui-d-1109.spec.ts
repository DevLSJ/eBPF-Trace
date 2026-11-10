import type { Page, Route } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';
import { ADMIN_PW, MSG, OTP_OK, OTP_SECRET } from './mock-auth';

// 11/09 저녁 묶음 D(로그인 · 대시보드) — 참고 제품 UI 문서 대조 항목(G02 · G03 · G25 · G26 · G27 · G29 · G30 · G31~G34 · G36 · G38).
// 로그인 쪽은 화면 표시 · 입력 편의만 바꾼다 — 보내는 요청 · 순서 · 값은 그대로(auth-1020 이 그대로 통과하는 것이 증거).
// 화면 사진은 UI_D_SHOTS(메인 임시 폴더)가 있으면 그곳, 없으면 기본 SHOTS
const SHOT = process.env.UI_D_SHOTS || SHOTS;
const AUTH = '[data-part="auth"]';
const ERR = '[data-part="auth-error"]';
const step = (page: Page) => page.locator(AUTH);
const sent = (backend: { requests: { method: string; path: string; body?: string }[] }, path: string) =>
  backend.requests.filter((r) => r.method === 'POST' && r.path === path).map((r) => JSON.parse(r.body ?? '{}'));

// 일부러 실패시키는 로그인 · OTP(401/400)는 브라우저가 네트워크 로그를 콘솔에 남긴다 — 그 줄만 허용
test.beforeEach(({ allowConsole }) => allowConsole(/^Failed to load resource: the server responded with a status of (400|401|403|409|500) /));

test.describe('로그인 — 입력 · 진행 · 실패(G25 · G26 · G27)', () => {
  test('G25 빈 값이면 로그인 요청을 보내지 않고 칸 아래 문구 · aria-invalid', async ({ page, backend }) => {
    backend.auth.loggedOut();
    await page.goto('/');
    const id = step(page).getByLabel('아이디');
    const pw = step(page).getByLabel('비밀번호', { exact: true });
    const go = step(page).getByRole('button', { name: '로그인' });
    await go.click();
    await expect(step(page).locator('[data-part="field-error"][data-for="username"]')).toHaveText('아이디를 입력하세요.');
    await expect(step(page).locator('[data-part="field-error"][data-for="password"]')).toHaveText('비밀번호를 입력하세요.');
    await expect(id).toHaveAttribute('aria-invalid', 'true');
    await expect(pw).toHaveAttribute('aria-invalid', 'true');
    await expect(id).toBeFocused(); // 첫 빈 칸으로
    await id.fill('admin');
    await expect(id).not.toHaveAttribute('aria-invalid', 'true'); // 고치면 바로 지운다
    await go.click();
    await expect(step(page).locator('[data-part="field-error"][data-for="username"]')).toHaveCount(0);
    await expect(step(page).locator('[data-part="field-error"][data-for="password"]')).toHaveText('비밀번호를 입력하세요.');
    await expect(pw).toBeFocused();
    await page.waitForTimeout(200);
    expect(sent(backend, '/auth/login')).toEqual([]);
    await pw.fill(ADMIN_PW);
    await go.click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    expect(sent(backend, '/auth/login')).toEqual([{ username: 'admin', password: ADMIN_PW }]);
  });

  test('G27 진행 중 「로그인 중…」 · 실패 뒤 비밀번호 칸 비우고 초점', async ({ page, backend }) => {
    backend.auth.loggedOut();
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let hold = true;
    await page.route(/\/api\/auth\/login$/, async (route) => {
      if (hold) await held;
      await route.fallback();
    });
    await page.goto('/');
    await step(page).getByLabel('아이디').fill('admin');
    await step(page).getByLabel('비밀번호', { exact: true }).fill('wrong-password');
    await step(page).getByRole('button', { name: '로그인' }).click();
    const busy = step(page).locator('button[type="submit"]');
    await expect(busy).toHaveText('로그인 중…');
    await expect(busy).toBeDisabled();
    release();
    await expect(page.locator(ERR)).toHaveText(MSG.badCreds);
    await expect(busy).toHaveText('로그인');
    const pw = step(page).getByLabel('비밀번호', { exact: true });
    await expect(pw).toHaveValue('');
    await expect(pw).toBeFocused();
    hold = false;
    await pw.fill(ADMIN_PW);
    await pw.press('Enter');
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
  });

  // 11/09 메인 통합 실측: 실패 응답이 늦게 오면 그 사이 새로 입력한 비밀번호까지 지워져, 다음 「로그인」이 빈 값 검사(G25)에 걸려 서버로 가지 않았다
  // (auth-1020 「5번 틀리면 잠김」에서 5번째 시도가 사라짐). 실패하면 보낸 값이 칸에 그대로 있을 때만 비운다
  test('G27 늦게 온 실패 응답은 그 사이 새로 입력한 비밀번호를 지우지 않는다', async ({ page, backend }) => {
    backend.auth.loggedOut();
    await page.route('**/api/auth/login', async (r: Route) => {
      await new Promise((ok) => setTimeout(ok, 400));
      await r.fallback();
    });
    await page.goto('/');
    const pw = step(page).getByLabel('비밀번호', { exact: true });
    await step(page).getByLabel('아이디').fill('admin');
    await pw.fill('wrong-0');
    const answered = page.waitForResponse('**/api/auth/login');
    await step(page).getByRole('button', { name: '로그인' }).click();
    await pw.fill('wrong-1'); // 첫 요청이 아직 응답 전
    await answered;
    await expect(step(page).locator(ERR)).toBeVisible();
    await expect(pw).toHaveValue('wrong-1');
    await step(page).getByRole('button', { name: '로그인' }).click();
    await expect.poll(() => sent(backend, '/auth/login').map((b) => b.password)).toEqual(['wrong-0', 'wrong-1']);
  });

  // 11/09 사용자 「상단 해/달 단추 하나(로그인 화면 포함)」 — 단추 부품은 묶음 A(ThemeToggle), 로그인 화면 배치는 메인 통합
  test('G01 로그인 화면 오른쪽 위 해/달 단추 — 누르면 테마가 바뀌고 기억', async ({ page, backend }) => {
    backend.auth.loggedOut();
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/');
    const toggle = step(page).getByRole('button', { name: '어두운 화면으로' });
    await expect(toggle).toBeVisible();
    await expect(toggle).toHaveAttribute('title', '어두운 화면으로');
    const box = await toggle.boundingBox();
    const vw = page.viewportSize()!.width;
    expect(box!.x + box!.width).toBeGreaterThan(vw - 80); // 오른쪽 위
    expect(box!.y).toBeLessThan(80);
    await toggle.click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(step(page).getByRole('button', { name: '밝은 화면으로' })).toBeVisible();
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  });

  test('G26 비밀번호 보기(눈) · Caps Lock 켜짐 안내', async ({ page, backend }) => {
    backend.auth.loggedOut();
    await page.goto('/');
    const pw = step(page).getByLabel('비밀번호', { exact: true });
    await pw.fill('secret-1');
    await expect(pw).toHaveAttribute('type', 'password');
    const eye = step(page).getByRole('button', { name: '보기(비밀번호)' });
    await expect(eye).toHaveAttribute('title', '보기(비밀번호)');
    await expect(eye).toHaveAttribute('aria-pressed', 'false');
    await eye.click();
    await expect(pw).toHaveAttribute('type', 'text');
    const hide = step(page).getByRole('button', { name: '숨기기(비밀번호)' });
    await expect(hide).toHaveAttribute('aria-pressed', 'true');
    await expect(hide).toHaveAttribute('title', '숨기기(비밀번호)');
    await hide.click();
    await expect(pw).toHaveAttribute('type', 'password');
    // 보기 단추는 Tab 순서에서 비밀번호 칸 다음(로그인 단추 앞)
    const caps = step(page).locator('[data-part="caps-lock"]');
    await expect(caps).toHaveCount(0);
    const key = (type: string, on: boolean) =>
      pw.evaluate((el, [t, c]) => el.dispatchEvent(new KeyboardEvent(t as string, { key: 'a', bubbles: true, modifierCapsLock: c as boolean } as KeyboardEventInit)), [type, on] as const);
    await key('keydown', true);
    await expect(caps).toHaveText('Caps Lock이 켜져 있습니다.');
    await expect(pw).toHaveAttribute('aria-describedby', /caps/);
    await key('keyup', false);
    await expect(caps).toHaveCount(0);
  });
});

test.describe('OTP 등록 · 입력(G29 · G30)', () => {
  test('G29 등록 3단계(앱 설치 → QR 읽기 → 코드 입력) · 키는 접어 두고 「키 보기」 · 복사하면 「복사했습니다.」', async ({ page, backend, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    backend.auth.otpRequired = true;
    backend.auth.loggedOut();
    await page.goto('/');
    await step(page).getByLabel('아이디').fill('admin');
    await step(page).getByLabel('비밀번호', { exact: true }).fill(ADMIN_PW);
    await step(page).getByRole('button', { name: '로그인' }).click();
    await expect(step(page)).toHaveAttribute('data-step', 'otp-enroll');
    const steps = step(page).locator('[data-part="otp-steps"] > li');
    await expect(steps).toHaveCount(3);
    await expect(steps.nth(0)).toContainText('인증 앱 설치');
    await expect(steps.nth(1)).toContainText('QR 읽기');
    await expect(steps.nth(2)).toContainText('코드 입력');
    await expect(step(page).locator('[data-part="qr"] img')).toBeVisible();
    const secret = step(page).locator('[data-part="otp-secret"]');
    await expect(secret).toBeHidden(); // 접혀 있음
    const show = step(page).getByRole('button', { name: '키 보기' });
    await expect(show).toHaveAttribute('aria-expanded', 'false');
    await show.click();
    await expect(secret).toBeVisible();
    await expect(secret).toHaveText(OTP_SECRET.replace(/(.{4})/g, '$1 ').trim());
    await expect(step(page).getByRole('button', { name: '키 숨기기' })).toHaveAttribute('aria-expanded', 'true');
    await step(page).getByRole('button', { name: '복사(키)' }).click();
    await expect(page.locator('[data-toast]').filter({ hasText: '복사했습니다.' })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(OTP_SECRET);
    await page.screenshot({ path: `${SHOT}/ui-d-otp-enroll.png` });
  });

  test('G30 OTP 6자리가 차면 자동 확인 1번 — 틀리면 칸 비우고 초점, 자동 재시도 없음 · 확인 단추는 그대로', async ({ page, backend }) => {
    backend.auth.otpRequired = true;
    backend.auth.user('admin').otpEnabled = true;
    backend.auth.loggedOut();
    await page.goto('/');
    await step(page).getByLabel('아이디').fill('admin');
    await step(page).getByLabel('비밀번호', { exact: true }).fill(ADMIN_PW);
    await step(page).getByRole('button', { name: '로그인' }).click();
    await expect(step(page)).toHaveAttribute('data-step', 'otp');
    const code = step(page).getByLabel('OTP 6자리');
    await code.pressSequentially('00000');
    await page.waitForTimeout(700);
    expect(sent(backend, '/auth/otp')).toEqual([]); // 5자리는 기다린다
    await code.pressSequentially('0');
    await expect.poll(() => sent(backend, '/auth/otp')).toEqual([{ code: '000000' }]);
    await expect(page.locator(ERR)).toHaveText(MSG.badOTP);
    await expect(code).toHaveValue('');
    await expect(code).toBeFocused();
    // 두 번째 6자리는 자동으로 보내지 않는다(한 번만) — 확인 단추 · Enter 로
    await code.pressSequentially(OTP_OK);
    await page.waitForTimeout(900);
    expect(sent(backend, '/auth/otp')).toEqual([{ code: '000000' }]);
    await step(page).getByRole('button', { name: '확인' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    expect(sent(backend, '/auth/otp')).toEqual([{ code: '000000' }, { code: OTP_OK }]);
  });

  test('G30 등록 단계도 6자리면 자동 확인 → 복구 코드(요청 1번)', async ({ page, backend }) => {
    backend.auth.otpRequired = true;
    backend.auth.loggedOut();
    await page.goto('/');
    await step(page).getByLabel('아이디').fill('admin');
    await step(page).getByLabel('비밀번호', { exact: true }).fill(ADMIN_PW);
    await step(page).getByRole('button', { name: '로그인' }).click();
    await expect(step(page)).toHaveAttribute('data-step', 'otp-enroll');
    await expect(step(page).locator('[data-part="qr"] img')).toBeVisible();
    await step(page).getByLabel('앱에 나온 6자리').pressSequentially(OTP_OK);
    await expect(step(page)).toHaveAttribute('data-step', 'recovery-codes');
    await page.waitForTimeout(300);
    expect(sent(backend, '/auth/otp/enroll/confirm')).toEqual([{ code: OTP_OK }]);
  });

  test('G30 6자리를 채우자마자 Enter 를 눌러도 요청은 한 번(자동 확인과 겹치지 않음)', async ({ page, backend }) => {
    backend.auth.otpRequired = true;
    backend.auth.user('admin').otpEnabled = true;
    backend.auth.loggedOut();
    await page.goto('/');
    await step(page).getByLabel('아이디').fill('admin');
    await step(page).getByLabel('비밀번호', { exact: true }).fill(ADMIN_PW);
    await step(page).getByRole('button', { name: '로그인' }).click();
    await expect(step(page)).toHaveAttribute('data-step', 'otp');
    const code = step(page).getByLabel('OTP 6자리');
    await code.pressSequentially('000000');
    await code.press('Enter');
    await expect(page.locator(ERR)).toHaveText(MSG.badOTP);
    await page.waitForTimeout(900);
    expect(sent(backend, '/auth/otp')).toEqual([{ code: '000000' }]);
  });
});

test.describe('세션 확인(G02 · G03)', () => {
  test('G02 확인 중에는 스켈레톤 + 「로그인 정보를 확인하는 중입니다.」', async ({ page, backend }) => {
    void backend;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    await page.route(/\/api\/auth\/me$/, async (route) => {
      await held;
      await route.fallback();
    });
    await page.goto('/');
    const loading = page.locator('[data-part="auth-loading"]');
    await expect(loading).toBeVisible();
    await expect(loading).toHaveAttribute('aria-busy', 'true');
    await expect(loading.locator('.sg-skeleton').first()).toBeVisible();
    await expect(loading.getByRole('status')).toHaveText('로그인 정보를 확인하는 중입니다.');
    await expect(page.getByText('불러오는 중…')).toHaveCount(0);
    await page.screenshot({ path: `${SHOT}/ui-d-auth-loading.png` });
    release();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    await expect(loading).toHaveCount(0);
  });

  test('G03 연결 실패면 오류 + 「다시 시도」 → 같은 확인 요청을 다시 불러 성공', async ({ page, backend, allowConsole }) => {
    allowConsole(/net::ERR_FAILED|Failed to load resource/);
    // 개발 모드 StrictMode 는 첫 확인을 두 번 부른다 — 「다시 시도」 전까지는 모두 실패
    let down = true;
    let n = 0;
    await page.route(/\/api\/auth\/me$/, async (route: Route) => {
      n++;
      if (down) return route.abort('failed');
      return route.fallback();
    });
    await page.goto('/');
    const box = page.locator('[data-part="auth-check-error"]');
    await expect(box).toBeVisible();
    await expect(box.getByRole('heading')).toHaveText('로그인 정보를 확인하지 못했습니다.');
    await expect(box).toContainText('서버에 연결하지 못했습니다. 네트워크를 확인한 뒤 다시 시도하세요.');
    await expect(box).not.toContainText('Failed to fetch');
    await expect(page.locator(AUTH)).toHaveCount(0); // 로그인 카드로 넘기지 않는다
    await page.screenshot({ path: `${SHOT}/ui-d-auth-check-error.png` });
    const tried = n;
    down = false;
    await box.getByRole('button', { name: '다시 시도' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    expect(n).toBeGreaterThan(tried); // 같은 GET /api/auth/me 를 다시 불렀다
    expect(backend.requests.filter((r) => r.path === '/auth/me').length).toBeGreaterThanOrEqual(1);
  });

  test('G03 서버가 문장을 주면(500 JSON) 상태 코드 없이 그 문장만', async ({ page, backend }) => {
    void backend;
    let down = true;
    await page.route(/\/api\/auth\/me$/, async (route: Route) => {
      if (down) return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: '세션 저장소에 연결하지 못했습니다' }) });
      return route.fallback();
    });
    await page.goto('/');
    const box = page.locator('[data-part="auth-check-error"]');
    await expect(box).toContainText('세션 저장소에 연결하지 못했습니다');
    await expect(box).not.toContainText('500');
    down = false;
    await box.getByRole('button', { name: '다시 시도' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
  });
});

test.describe('로그인 화면 사진', () => {
  for (const [name, theme, w, h] of [
    ['1440', 'light', 1440, 900],
    ['1440-dark', 'dark', 1440, 900],
    ['390', 'light', 390, 844],
  ] as const) {
    test(`${name}: 빈 값 문구 · 보기 단추 · 「—」 없음`, async ({ page, backend }) => {
      await page.setViewportSize({ width: w, height: h });
      await page.addInitScript((t) => localStorage.setItem('supplyguard.theme', t), theme);
      backend.auth.loggedOut();
      await page.goto('/');
      await step(page).getByRole('button', { name: '로그인' }).click();
      await expect(step(page).locator('[data-part="field-error"]')).toHaveCount(2);
      const text = await step(page).innerText();
      expect(text).not.toContain('—');
      expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBe(0);
      await page.screenshot({ path: `${SHOT}/ui-d-login-${name}.png` });
    });
  }
});

// ── 대시보드(G31 · G32 · G33 · G34 · G36 · G38) ──
const DASH = '[data-part="dashboard"]';
async function ready(page: Page) {
  await expect(page.getByTestId('pending')).toBeVisible();
  await expect(page.locator(`${DASH} [data-kpi]`)).toHaveCount(6);
}
const summaryCalls = (backend: { requests: { path: string }[] }) => backend.requests.filter((r) => r.path.startsWith('/summary')).length;
// 탭 가림 흉내 — visibilityState · hidden 을 바꾸고 visibilitychange 를 보낸다
const setVisibility = (page: Page, v: 'hidden' | 'visible') =>
  page.evaluate((v) => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => v });
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => v === 'hidden' });
    document.dispatchEvent(new Event('visibilitychange'));
  }, v);
// 큰 수 · 긴 보조 줄(발표 서버 하루치 규모) — 카드 글자 잘림을 재는 데이터
async function bigSummary(page: Page, backend: { summary: (r: string) => import('../src/lib/types').Summary }) {
  await page.route(/\/api\/summary(\?|$)/, (route) => {
    const range = new URL(route.request().url()).searchParams.get('range') || '24h';
    const s = backend.summary(range);
    const big = {
      ...s,
      collected: { total: 12_345_678, byKind: { exec: 2_345_678, open: 7_654_321, connect: 2_345_679 - 1_234, dns: 1_234 } },
      violations: { total: 12_480, killed: 1_234, alert: 11_000, held: 246 },
      isolatedContainers: 1_234,
      installs: { ...s.installs, total: 12_345, passed: 11_000, isolated: 1_000, refused: 345 },
      decisions: { malicious: 1_234, falsePositive: 5_678, pending: 90 },
      isolation: { count: 1_480, medianMs: 1_234, p95Ms: 12_345, maxMs: 123_456 },
      previous: { collected: 9_876_543, violations: 10_000, isolatedContainers: 1_000, installs: 10_000, decided: 6_000, isolationMedianMs: 999 },
    };
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(big) });
  });
}
// KPI 카드 안에서 잘린 글자(scrollWidth > clientWidth) — 카드 · 이름 · 값 · 증감 · 보조 줄
const clipped = (page: Page) =>
  page.locator(`${DASH} [data-kpi]`).evaluateAll((cards) =>
    cards.flatMap((c) =>
      [c, ...c.querySelectorAll('.kpi-name, .kpi-num, .kpi-delta, .kpi-sub')]
        .filter((e) => e.scrollWidth > e.clientWidth + 0.5)
        .map((e) => `${(c as HTMLElement).dataset.kpi}:${e === c ? 'card' : e.className.split(' ')[0]} ${e.scrollWidth}>${e.clientWidth} 「${(e as HTMLElement).innerText.replace(/\s+/g, ' ')}」`),
    ),
  );

test.describe('대시보드 — 최종 갱신 · 새로고침 · 가려진 탭(G31 · G32)', () => {
  test('G31 머리 줄 「최종 갱신 HH:mm:ss」(툴팁 30초마다 자동 갱신) + 새로고침 단추 → 다시 불러 시각 갱신', async ({ page, backend }) => {
    await page.clock.install({ time: new Date('2026-11-09T14:03:20+09:00') });
    await page.goto('/');
    await ready(page);
    const upd = page.locator(`${DASH} [data-part="dash-updated"]`);
    await expect(upd).toHaveText(/^최종 갱신 14:03:2\d$/);
    await expect(upd).toHaveAttribute('title', '30초마다 자동 갱신');
    const btn = page.locator(`${DASH} [data-part="dash-top"]`).getByRole('button', { name: '새로고침(대시보드)' });
    await expect(btn).toHaveAttribute('title', '새로고침(대시보드)');
    await page.waitForTimeout(300);
    const n0 = summaryCalls(backend);
    await page.clock.fastForward(12_000);
    await btn.click();
    await expect.poll(() => summaryCalls(backend)).toBe(n0 + 1);
    await expect(upd).toHaveText(/^최종 갱신 14:03:3\d$/);
  });

  test('G32 탭이 가려져 있으면 30초 갱신을 건너뛰고, 다시 보이면 바로 한 번', async ({ page, backend }) => {
    await page.clock.install();
    await page.goto('/');
    await ready(page);
    await page.waitForTimeout(300);
    const n0 = summaryCalls(backend);
    await page.clock.fastForward(30_500); // 보이는 탭: 30초마다 한 번
    await expect.poll(() => summaryCalls(backend)).toBe(n0 + 1);
    await setVisibility(page, 'hidden');
    await page.clock.fastForward(30_500);
    await page.clock.fastForward(30_500);
    await page.waitForTimeout(400);
    expect(summaryCalls(backend)).toBe(n0 + 1); // 가려진 동안 0번
    await setVisibility(page, 'visible');
    await expect.poll(() => summaryCalls(backend)).toBe(n0 + 2); // 돌아오면 바로 한 번
    // 건너뛴 갱신이 없으면(잠깐 가렸다 보임) 더 부르지 않는다
    await setVisibility(page, 'hidden');
    await setVisibility(page, 'visible');
    await page.waitForTimeout(400);
    expect(summaryCalls(backend)).toBe(n0 + 2);
  });
});

test.describe('대시보드 — KPI 정의 · 큰 수 · 낮은 창(G33 · G34 · G36)', () => {
  test('G33 KPI 카드마다 「무엇을 세는지」 한 줄 툴팁', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await ready(page);
    const title = (k: string) => page.locator(`${DASH} [data-kpi="${k}"]`).getAttribute('title');
    expect(await title('collected')).toBe('이 기간에 커널에서 수집한 실행 · 파일 · 통신 · 조회 이벤트 수(같은 1분 안 같은 동작 반복은 1건)');
    expect(await title('violations')).toBe('이 기간에 정책에 걸린 이벤트 수(격리 · 경고)');
    expect(await title('isolated')).toBe('이 기간에 격리한 컨테이너 수(설치 검사 컨테이너 포함)');
    expect(await title('installs')).toBe('이 기간에 시작한 설치 검사 수');
    expect(await title('decided')).toBe('이 기간에 악성 · 오탐 판정을 마친 건 수');
    expect(await title('isolation')).toBe('탐지부터 격리까지 걸린 시간의 중앙값');
  });

  test('G36 1천만 이상은 「1,235만」 + 툴팁(정확한 값), 그 밑은 그대로', async ({ page, backend }) => {
    await bigSummary(page, backend);
    await page.goto('/');
    await ready(page);
    const val = (k: string) => page.locator(`${DASH} [data-kpi="${k}"] .kpi-val`);
    await expect(val('collected')).toHaveText('1,235만');
    await expect(val('collected')).toHaveAttribute('title', '12,345,678');
    await expect(val('violations')).toHaveText('12,480');
    expect(await val('violations').getAttribute('title')).toBeNull();
  });

  for (const [w, h] of [
    [1920, 1080],
    [1366, 768],
    [1280, 720],
  ] as const) {
    test(`G34 ${w}×${h}: KPI 카드 글자 잘림 0(보통 · 큰 수) · 머리 줄 한 줄 · 대시보드 스크롤 0`, async ({ page, backend }) => {
      await page.setViewportSize({ width: w, height: h });
      await page.goto('/');
      await ready(page);
      await page.waitForTimeout(900); // 카운트업이 끝난 뒤
      expect(await clipped(page), '보통 데이터').toEqual([]);
      await bigSummary(page, backend);
      await page.reload();
      await ready(page);
      await expect(page.locator(`${DASH} [data-kpi="collected"] .kpi-val`)).toHaveText('1,235만');
      await page.waitForTimeout(900);
      expect(await clipped(page), '큰 수').toEqual([]);
      const top = page.locator(`${DASH} [data-part="dash-top"]`);
      expect((await top.boundingBox())!.height, '머리 줄 한 줄').toBeLessThan(48);
      expect(await page.locator(DASH).evaluate((d) => d.scrollHeight - d.clientHeight), '대시보드 스크롤').toBe(0);
      await page.screenshot({ path: `${SHOT}/ui-d-dash-${w}.png` });
    });
  }
});

test.describe('대시보드 — 쉬운 말 · 사진(G38)', () => {
  test('G38 「evt」 · 대문자 설정 이름은 보이는 글자에 없음 — 「초당 N건」, 설정 이름은 툴팁 괄호 안에만', async ({ page, backend }) => {
    backend.info.enforceKill = false;
    backend.stats.enforceKill = false;
    backend.info.notify = { enabled: false, channels: [], sent: 0, failed: 0, dropped: 0, suppressed: 0 };
    await page.goto('/');
    await ready(page);
    await expect(page.locator(`${DASH} [data-part="dash-live"]`)).toHaveText('eBPF 감시 중 · 초당 9.6건');
    const text = await page.locator(DASH).innerText();
    expect(text).not.toMatch(/\bevt\b/);
    expect(text.match(/\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b/g)).toBeNull();
    expect(text).not.toContain('MOCK');
    // 툴팁은 쉬운 문장이 먼저, 설정 이름은 괄호 안 보조로
    const pill = (k: string) => page.locator(`[data-testid="signal-pills"] [data-pill="${k}"]`);
    await expect(pill('notify')).toHaveAttribute('title', '알림 채널이 없습니다. 서버 설정에 웹훅 · Slack 주소를 넣습니다(NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL)');
    await expect(pill('kill')).toHaveAttribute('title', '「즉시 격리」 정책도 격리하지 않고 경고만 남깁니다(ENFORCE_KILL=false)');
    await expect(pill('gadget')).toHaveAttribute('title', '모의 이벤트로 동작하고 있습니다(mock 소스)');
  });

  for (const [name, theme, w, h] of [
    ['1440', 'light', 1440, 900],
    ['1440-dark', 'dark', 1440, 900],
    ['390', 'light', 390, 844],
  ] as const) {
    test(`사진 ${name}: 「—」 없음 · 가로 넘침 0`, async ({ page, backend }) => {
      void backend;
      await page.setViewportSize({ width: w, height: h });
      await page.addInitScript((t) => localStorage.setItem('supplyguard.theme', t), theme);
      await page.goto('/');
      await ready(page);
      await expect(page.locator(`${DASH} [data-part="dash-updated"]`)).toHaveText(/^최종 갱신 \d{2}:\d{2}:\d{2}$/);
      expect(await page.locator(DASH).innerText()).not.toContain('—');
      expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBe(0);
      await page.waitForTimeout(900);
      await page.screenshot({ path: `${SHOT}/ui-d-dash-${name}.png` });
    });
  }
});
