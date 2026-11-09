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
