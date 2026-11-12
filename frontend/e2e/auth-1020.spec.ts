import QRCode from 'qrcode';
import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { ADMIN_PW, MSG, OTP_OK, OTP_SECRET, OTP_URI, RECOVERY } from './mock-auth';

// W16 (10/20): 로그인 · 비밀번호 · 라이선스 · OTP — 목업 shared/auth.js 와 같은 흐름 · 문구, 서버 계약은 backend/internal/api/auth.go
const AUTH = '[data-part="auth"]';

// 일부러 실패시키는 요청(틀린 비밀번호 400/401 · 로그인 전 401 · 조회자 403 · 단계 409)은 브라우저가 네트워크 로그를 콘솔에 남긴다 — 그 줄만 허용(스크립트 오류는 그대로 0)
test.beforeEach(({ allowConsole }) => allowConsole(/^Failed to load resource: the server responded with a status of (400|401|403|409) /));

const ERR = '[data-part="auth-error"]';

async function login(page: Page, username: string, password: string) {
  await page.locator(AUTH).getByLabel('아이디').fill(username);
  await page.locator(AUTH).getByLabel('비밀번호', { exact: true }).fill(password);
  await page.locator(AUTH).getByRole('button', { name: '로그인' }).click();
}
const step = (page: Page) => page.locator(AUTH);

test.describe('인증 — 로그인 단계', () => {
  test('로그인 실패 문구는 아이디가 있든 없든 같고, 쿠키 세션이라 Authorization 헤더를 보내지 않는다', async ({ page, backend }) => {
    backend.auth.loggedOut();
    await page.goto('/');
    await expect(step(page)).toHaveAttribute('data-step', 'login');
    await expect(page.getByTestId('page-title')).toHaveCount(0); // 셸은 그리지 않는다
    await login(page, 'admin', 'wrong-password');
    await expect(page.locator(ERR)).toHaveText(MSG.badCreds);
    await expect(step(page).getByLabel('비밀번호', { exact: true })).toHaveValue('');
    await login(page, 'nobody', 'wrong-password');
    await expect(page.locator(ERR)).toHaveText(MSG.badCreds);
    await login(page, 'admin', ADMIN_PW);
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    expect(backend.requests.filter((r) => r.auth !== null)).toEqual([]);
  });

  test('5번 틀리면 잠겨 맞는 비밀번호도 같은 문구로 거절', async ({ page, backend }) => {
    backend.auth.loggedOut();
    await page.goto('/');
    for (let i = 0; i < 5; i++) await login(page, 'admin', `wrong-${i}`);
    await login(page, 'admin', ADMIN_PW);
    await expect(page.locator(ERR)).toHaveText(MSG.badCreds);
    await expect(page.locator(ERR)).toContainText('5분 동안 로그인할 수 없습니다');
    await expect(step(page)).toHaveAttribute('data-step', 'login');
  });

  test('첫 로그인: 비밀번호 정책 → 라이선스 4칸 붙여넣기 → (OTP 꺼짐) 대시보드', async ({ page, backend }) => {
    backend.auth.fresh();
    await page.goto('/');
    await login(page, 'admin', ADMIN_PW);
    await expect(step(page)).toHaveAttribute('data-step', 'password');
    const cur = step(page).getByLabel('지금 비밀번호');
    const nx = step(page).getByLabel('새 비밀번호', { exact: true });
    const cf = step(page).getByLabel('새 비밀번호 확인');
    const go = step(page).getByRole('button', { name: '바꾸고 계속' });
    await cur.fill(ADMIN_PW);
    await nx.fill('abcd');
    await cf.fill('abcd');
    await go.click();
    await expect(page.locator(ERR)).toHaveText('비밀번호는 5자 이상이어야 합니다');
    await nx.fill('Admin');
    await cf.fill('Admin');
    await go.click();
    await expect(page.locator(ERR)).toHaveText('비밀번호는 아이디와 달라야 합니다');
    await nx.fill('new-password-2026');
    await cf.fill('new-password-2027');
    await go.click();
    await expect(page.locator(ERR)).toHaveText('새 비밀번호가 일치하지 않습니다');
    await cur.fill('not-the-current');
    await cf.fill('new-password-2026');
    await go.click();
    await expect(page.locator(ERR)).toHaveText(MSG.badCurrent); // 서버 문구
    await cur.fill(ADMIN_PW);
    await go.click();

    await expect(step(page)).toHaveAttribute('data-step', 'license');
    const boxes = step(page).locator('[data-part="key-boxes"] input');
    await expect(boxes).toHaveCount(4);
    await boxes.first().focus();
    await page.evaluate(() => {
      const dt = new DataTransfer();
      dt.setData('text/plain', ' 1234-5678-9012-3456 ');
      document.activeElement!.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    });
    await expect(boxes.nth(0)).toHaveValue('1234');
    await expect(boxes.nth(1)).toHaveValue('5678');
    await expect(boxes.nth(2)).toHaveValue('9012');
    await expect(boxes.nth(3)).toHaveValue('3456');
    await boxes.nth(3).fill('34');
    await step(page).getByRole('button', { name: '등록하고 계속' }).click();
    await expect(page.locator(ERR)).toHaveText(MSG.badKey);
    await boxes.nth(3).fill('3456');
    await step(page).getByRole('button', { name: '등록하고 계속' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    const lic = backend.requests.filter((r) => r.path === '/auth/license').map((r) => JSON.parse(r.body!).key);
    expect(lic).toEqual(['1234-5678-9012-34', '1234-5678-9012-3456']);
    await expect(page.locator('[data-part="license-chip"]')).toHaveText('평가판 · 365일 남음');
  });

  // W-B (10/21): 처리 중 Enter 를 또 눌러도 라이선스 등록 요청은 한 번만(KeyBoxes onEnter 는 keyup, 처리 중이면 무시)
  test('라이선스 단계: 응답이 늦을 때 Enter 두 번 → POST 1건', async ({ page, backend }) => {
    backend.auth.fresh();
    backend.auth.user('admin').mustChangePassword = false;
    let posts = 0;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    // 나중에 건 route 가 먼저 받는다 — 세고, 풀어 줄 때까지 붙잡았다가 가짜 백엔드로 넘긴다
    await page.route(/\/api\/auth\/license$/, async (route) => {
      if (route.request().method() === 'POST') posts++;
      await held;
      await route.fallback();
    });
    await page.goto('/');
    await login(page, 'admin', ADMIN_PW);
    await expect(step(page)).toHaveAttribute('data-step', 'license');
    const boxes = step(page).locator('[data-part="key-boxes"] input');
    for (const [i, v] of ['1234', '5678', '9012', '3456'].entries()) await boxes.nth(i).fill(v);
    await boxes.nth(3).press('Enter');
    await expect.poll(() => posts).toBe(1);
    await expect(step(page).getByRole('button', { name: '등록하고 계속' })).toBeDisabled();
    await boxes.nth(3).press('Enter');
    await page.waitForTimeout(300);
    release();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    expect(posts).toBe(1);
  });

  test('OTP 등록: 실제 QR(외부 요청 없음) · 수동 키 → 6자리 확인 → 복구 코드 10개(체크 뒤 시작)', async ({ page, backend }) => {
    backend.auth.otpRequired = true;
    backend.auth.loggedOut();
    const outside: string[] = [];
    page.on('request', (r) => {
      const u = new URL(r.url());
      if (!['127.0.0.1', 'localhost'].includes(u.hostname) && u.protocol !== 'data:') outside.push(r.url());
    });
    await page.goto('/');
    await login(page, 'admin', ADMIN_PW);
    await expect(step(page)).toHaveAttribute('data-step', 'otp-enroll');
    const qr = step(page).locator('[data-part="qr"] img');
    await expect(qr).toBeVisible();
    // QR 은 그림이 아니라 uri 를 담은 실제 부호 — 같은 라이브러리 · 옵션으로 만든 SVG 와 같아야 한다
    const src = await qr.getAttribute('src');
    const expected = await QRCode.toString(OTP_URI, { type: 'svg', errorCorrectionLevel: 'M', margin: 2 });
    expect(decodeURIComponent(src!.replace(/^data:image\/svg\+xml;charset=utf-8,/, ''))).toBe(expected);
    await expect(step(page).locator('[data-part="otp-secret"]')).toHaveText(OTP_SECRET.replace(/(.{4})/g, '$1 ').trim());

    await step(page).getByLabel('앱에 나온 6자리').fill('000000');
    await step(page).getByRole('button', { name: '확인' }).click();
    await expect(page.locator(ERR)).toHaveText(MSG.badOTP);
    await step(page).getByLabel('앱에 나온 6자리').fill(OTP_OK);
    await step(page).getByRole('button', { name: '확인' }).click();

    await expect(step(page)).toHaveAttribute('data-step', 'recovery-codes');
    await expect(step(page).locator('[data-part="recovery-codes"] li')).toHaveText(RECOVERY);
    await expect(step(page).getByRole('button', { name: '시작하기' })).toHaveCount(0);
    await step(page).getByLabel('복구 코드를 안전한 곳에 저장했습니다').check();
    await step(page).getByRole('button', { name: '시작하기' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    expect(outside).toEqual([]);
  });

  test('OTP 입력 → 틀림 문구, 맞으면 대시보드 / 복구 코드로 전환하면 {recovery} 로 보낸다', async ({ page, backend }) => {
    backend.auth.otpRequired = true;
    backend.auth.user('admin').otpEnabled = true;
    backend.auth.loggedOut();
    await page.goto('/');
    await login(page, 'admin', ADMIN_PW);
    await expect(step(page)).toHaveAttribute('data-step', 'otp');
    await step(page).getByLabel('OTP 6자리').fill('000000');
    await step(page).getByRole('button', { name: '확인' }).click();
    await expect(page.locator(ERR)).toHaveText(MSG.badOTP);

    await step(page).getByRole('button', { name: '복구 코드로 로그인' }).click();
    await expect(step(page).getByRole('heading')).toHaveText('복구 코드로 로그인');
    await step(page).getByLabel('복구 코드').fill('ZZZZ-ZZZZ');
    await step(page).getByRole('button', { name: '확인' }).click();
    await expect(page.locator(ERR)).toHaveText(MSG.badRecovery);
    await step(page).getByLabel('복구 코드').fill(RECOVERY[3].toLowerCase());
    await step(page).getByRole('button', { name: '확인' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    const sent = backend.requests.filter((r) => r.path === '/auth/otp').map((r) => JSON.parse(r.body!));
    expect(sent).toEqual([{ code: '000000' }, { recovery: 'ZZZZ-ZZZZ' }, { recovery: RECOVERY[3].toLowerCase() }]);

    // 다시 로그인하면 OTP 코드 입력으로
    await page.locator('[data-part="account"]').click();
    await page.getByRole('menuitem', { name: '로그아웃' }).click();
    await login(page, 'admin', ADMIN_PW);
    await step(page).getByLabel('OTP 6자리').fill(OTP_OK);
    await step(page).getByRole('button', { name: '확인' }).click();
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
  });

  test('조회자는 라이선스가 없으면 로그인 단계에서 403 문구', async ({ page, backend }) => {
    backend.auth.license = null;
    backend.auth.loggedOut();
    await page.goto('/');
    await login(page, 'viewer', 'e2e-viewer-pass-1');
    await expect(page.locator(ERR)).toHaveText(MSG.viewerNoLic);
    await expect(step(page)).toHaveAttribute('data-step', 'login');
  });
});

test.describe('인증 — 앱 안에서', () => {
  test('401 + state 면 그 단계 화면, state 가 없으면 로그인(문구 표시)', async ({ page, backend }) => {
    await page.goto('/');
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    // 실시간 연결이 선 뒤에 상태를 바꾼다 — 연결되는 순간 /api/cases · /api/info 를 다시 읽으므로, 느린 CI 에서는 그 요청이 클릭보다 먼저 401 을 받아 대시보드에서 라이선스 화면으로 갔다(11/05 CI trace)
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await page.waitForLoadState('networkidle'); // 연결 직후 다시 읽기까지 끝난 뒤
    backend.auth.session!.state = 'need_license';
    // R2 11/04: 대시보드 아래 칸 「감사 로그 ›」(더 보기)와 겹치지 않게 사이드바에서 누른다
    await page.getByRole('navigation', { name: '화면' }).getByRole('link', { name: '감사 로그' }).click();
    await expect(step(page)).toHaveAttribute('data-step', 'license');

    backend.auth.session!.state = 'active';
    await step(page).getByRole('button', { name: '다른 계정으로 로그인' }).click();
    await login(page, 'admin', ADMIN_PW);
    await expect(page.getByTestId('page-title')).toHaveText('감사 로그'); // 다시 로그인하면 보던 화면으로
    backend.auth.session = null; // 세션 만료
    // 화면의 주기 요청(5초 갱신 등)이 클릭보다 먼저 401 을 받아 로그인 화면으로 갈 수 있다 — 어느 쪽이 먼저든 결과는 같아야 한다(10/20 간헐 실패 원인)
    // 11/09 밤: 「정책」은 접힌 묶음 안(지금 화면이 아니면 처음엔 접힘)이라 늘 보이는 사이드바 링크를 누른다
    await page.getByRole('navigation', { name: '화면' }).getByRole('link', { name: '설치 검사', exact: true }).click({ timeout: 2000 }).catch(() => {});
    await expect(step(page)).toHaveAttribute('data-step', 'login');
    await expect(page.locator(ERR)).toHaveText(MSG.login);
  });

  test('실시간 연결이 열리기 전에 닫히면 로그인 여부를 다시 확인한다', async ({ page, backend }) => {
    await page.goto('/');
    await expect(page.getByTestId('page-title')).toHaveText('대시보드');
    await expect.poll(() => backend.ws !== null).toBe(true);
    // 연결 상태가 바뀌면 다시 읽는 /api/info · /api/cases 는 그대로 200 을 주게 해서, 재확인(/api/auth/me)만으로 로그인 화면이 되는지 본다
    await page.route(/\/api\/(info|cases)(\?|$)/, (r) =>
      r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(r.request().url().includes('/info') ? backend.info : backend.cases) }),
    );
    backend.auth.session = null;
    await backend.ws!.close();
    await expect(step(page)).toHaveAttribute('data-step', 'login', { timeout: 10_000 });
    expect(backend.requests.filter((r) => r.path === '/auth/me').length).toBeGreaterThanOrEqual(2);
  });

  test('403 은 「관리자만」 안내만 — 로그아웃하지 않는다', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0012');
    await expect(page.getByTestId('decision').getByRole('button', { name: '악성 확정' })).toBeVisible();
    backend.auth.user('admin').role = 'viewer'; // 다른 관리자가 이 계정을 조회자로 내렸다
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(page.locator('[data-toast]').filter({ hasText: '관리자만' }).first()).toBeVisible();
    await expect(page.locator(AUTH)).toHaveCount(0);
    await expect(page.getByTestId('page-title')).toHaveText('설치 검사');
  });

  test('조회자: 쓰기 버튼을 그리지 않는다(판정 · 적용 · 버림 · 해제 · 새 정책 · 검사 시작 · 차단 · 관리자 토큰 칸)', async ({ page, backend }) => {
    backend.auth.asViewer();
    backend.scanCase({ decided: true });
    await page.goto('/installs?id=ins-0012');
    const box = page.getByTestId('decision');
    await expect(box).toContainText('판정은 관리자가 합니다');
    await expect(box.getByRole('button')).toHaveCount(0);
    await expect(page.locator('[data-part="account"]')).toContainText('조회 담당자 · 조회자');

    const draft = backend.proposals.find((p) => p.state === 'draft')!;
    await page.goto(`/policies?proposal=${draft.id}`);
    await expect(page.getByTestId('proposal').getByRole('button', { name: '미리보기' })).toBeVisible(); // 바꾸지 않는 POST 는 조회자도
    await expect(page.getByTestId('proposal').getByRole('button', { name: /^(적용|버림)$/ })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '정책 생성' })).toHaveCount(0); // 11/09 「새 정책」 → 「정책 생성」
    await expect(page.getByLabel('관리자 토큰')).toHaveCount(0);
    await page.goto('/policies/blocklist'); // 11/09: 차단 목록 페이지
    await expect(page.getByTestId('blocklist').locator('[data-block]').first()).toBeVisible();
    await expect(page.getByTestId('blocklist').getByRole('button', { name: '해제' })).toHaveCount(0);
    await page.goto('/policies?id=egress-allowlist');
    await expect(page.locator('[data-view="rule-editor"]').getByRole('button', { name: '삭제' })).toHaveCount(0);

    await page.route(/\/api\/scans$/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
    await page.goto('/scans');
    await expect(page.getByRole('button', { name: '검사 시작' })).toHaveCount(0);
    expect(backend.writes().filter((r) => !r.path.endsWith('/preview'))).toEqual([]);
  });

  test('계정 메뉴: 내 정보 · 비밀번호 변경 · 로그아웃', async ({ page, backend }) => {
    await page.goto('/');
    await page.locator('[data-part="account"]').click();
    await page.getByRole('menuitem', { name: '내 정보' }).click();
    const prof = page.locator('[data-part="profile"]');
    await expect(prof).toContainText('admin');
    await expect(prof).toContainText('관리자');
    await expect(prof).toContainText('서버 설정으로 꺼짐');
    await prof.getByRole('button', { name: '닫기' }).click();

    await page.locator('[data-part="account"]').click();
    await page.getByRole('menuitem', { name: '비밀번호 변경' }).click();
    const pw = page.locator('[data-part="password"]');
    await pw.getByLabel('지금 비밀번호').fill(ADMIN_PW);
    await pw.getByLabel(/^새 비밀번호 \(/).fill('changed-pass-2026');
    await pw.getByLabel('새 비밀번호 확인').fill('changed-pass-2026');
    await pw.getByRole('button', { name: '바꾸기' }).click();
    await expect(pw).toHaveCount(0);
    expect(backend.auth.user('admin').pw).toBe('changed-pass-2026');

    await page.locator('[data-part="account"]').click();
    await page.getByRole('menuitem', { name: '로그아웃' }).click();
    await expect(step(page)).toHaveAttribute('data-step', 'login');
    expect(backend.requests.some((r) => r.method === 'POST' && r.path === '/auth/logout')).toBe(true);
    expect(backend.auth.session).toBeNull();
  });
});
