import { expect, test } from './fixtures';
import { AUDIT_ACTIONS, MSG } from './mock-auth';

// W16 (10/20): 「설정」 화면 — 서버 설정(정책 화면에서 옮겨 옴) · 계정 · 라이선스 · 인증 감사. 조회자는 계정 · 인증 감사 탭이 없다
const TABS = '[data-part="settings-tabs"] [role="tab"]';

// 일부러 실패시키는 요청(틀린 비밀번호 400/401 · 로그인 전 401 · 조회자 403 · 단계 409)은 브라우저가 네트워크 로그를 콘솔에 남긴다 — 그 줄만 허용(스크립트 오류는 그대로 0)
test.beforeEach(({ allowConsole }) => allowConsole(/^Failed to load resource: the server responded with a status of (400|401|403|409) /));


test.describe('설정 화면', () => {
  test('사이드바 「설정 · 기록」 묶음 → 탭 4개, 서버 설정은 보기만(정책 화면에서는 없어짐)', async ({ page, backend }) => {
    backend.info.watchContainers = ['sg-install-*'];
    backend.info.ignoreContainers = ['supplyguard-*'];
    backend.info.discovery = 'docker-events';
    backend.info.discoveryNote = '컨테이너 시작 직후 약 0.1초는 관찰하지 못할 수 있습니다';
    await page.goto('/');
    await page.locator('[data-nav-group="설정 · 기록"]').getByRole('link', { name: '설정' }).click();
    await expect(page).toHaveURL(/\/settings/);
    await expect(page.getByTestId('page-title')).toHaveText('설정');
    await expect(page.locator(TABS)).toHaveText(['서버 설정', '계정', '라이선스', '인증 감사']);
    const sv = page.locator('[data-view="server"]');
    await expect(sv).toContainText('자동 격리');
    await expect(sv).toContainText('sg-install-*');
    await expect(sv).toContainText('supplyguard-*');
    await expect(sv).toContainText('WATCH_CONTAINERS');
    await expect(sv).toContainText('다시 시작');
    await expect(sv.locator('[data-part="notify"]')).toContainText('hooks.example.test');
    await expect(sv.locator('[data-part="discovery"]')).toContainText('docker-events');
    await expect(sv.locator('[data-part="discovery"]')).toContainText('약 0.1초');
    await expect(sv.locator('[data-part="dns"]')).toContainText('켜짐');
    await expect(sv.locator('input, select, textarea')).toHaveCount(0);

    await page.goto('/policies');
    await expect(page.locator('[data-server-settings]')).toHaveCount(0);
    await expect(page.getByTestId('page-actions')).not.toContainText('서버 설정');
  });

  test('알림 「테스트 발송」 → POST /api/notify/test → 보낸 수 다시 읽기 / 채널 없으면 안내', async ({ page, backend }) => {
    await page.goto('/settings');
    const nt = page.locator('[data-part="notify"]');
    await expect(nt.locator('[data-channel="webhook"] [data-sent]')).toHaveText('3');
    await nt.getByRole('button', { name: '테스트 발송' }).click();
    await expect(nt.locator('[data-channel="webhook"] [data-sent]')).toHaveText('4', { timeout: 5000 });
    expect(backend.notifyTests).toBe(1);

    backend.info.notify = { enabled: false, channels: [], sent: 0, failed: 0 };
    await page.reload();
    await expect(nt).toContainText('NOTIFY_WEBHOOK_URL');
    await expect(nt.getByRole('button', { name: '테스트 발송' })).toHaveCount(0);
  });

  test('계정 추가 → 임시 비밀번호는 한 번만 보이고, 목록에 「첫 로그인 대기」', async ({ page, backend }) => {
    await page.goto('/settings?tab=accounts');
    const v = page.locator('[data-view="accounts"]');
    await expect(v.locator('tr[data-user]')).toHaveCount(2);
    await v.getByRole('button', { name: '계정 추가' }).click();
    const add = page.locator('[data-part="user-add"]');
    await add.getByLabel('아이디').fill('a');
    await add.getByRole('button', { name: '만들기' }).click();
    await expect(add.locator('[role="alert"]')).toContainText('3~32자');
    await add.getByLabel('아이디').fill('analyst1');
    await add.getByLabel('이름').fill('분석 담당');
    await add.getByLabel('역할').selectOption('viewer');
    await add.getByRole('button', { name: '만들기' }).click();
    const temp = page.locator('[data-part="temp-password"]');
    const shown = await temp.locator('[data-temp-password]').textContent();
    expect(shown).toBe(backend.auth.user('analyst1').pw);
    await temp.getByRole('button', { name: '닫기' }).click();
    await expect(temp).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText(shown!);
    await expect(v.locator('tr[data-user="analyst1"]')).toContainText('첫 로그인 대기');
    await expect(v.locator('tr[data-user="analyst1"]')).toContainText('조회자');

    // 비밀번호 초기화도 확인 대화상자 → 임시 비밀번호 1회
    await v.locator('tr[data-user="viewer"]').getByRole('button', { name: '비밀번호 초기화' }).click();
    await page.locator('[data-part="confirm"]').getByRole('button', { name: '초기화' }).click();
    await expect(page.locator('[data-part="temp-password"] [data-temp-password]')).toHaveText(backend.auth.user('viewer').pw);
  });

  test('마지막 관리자: 강등 · 비활성 버튼 없이 안내, 다른 계정을 올리면 생긴다', async ({ page, backend }) => {
    await page.goto('/settings?tab=accounts');
    const v = page.locator('[data-view="accounts"]');
    const me = v.locator('tr[data-user="admin"]');
    await expect(me).toContainText('(나)');
    await expect(me).toContainText('마지막 관리자');
    await expect(me.getByRole('button', { name: /조회자로|비활성/ })).toHaveCount(0);
    await expect(v.locator('[data-part="last-admin"]')).toContainText(MSG.lastAdmin);

    await v.locator('tr[data-user="viewer"]').getByRole('button', { name: '관리자로' }).click();
    await page.locator('[data-part="confirm"]').getByRole('button', { name: '바꾸기' }).click();
    await expect(v.locator('tr[data-user="viewer"]')).toContainText('관리자');
    await expect(me.getByRole('button', { name: '조회자로' })).toBeVisible();
    await expect(me.getByRole('button', { name: '비활성' })).toHaveCount(0); // 자기 자신은 비활성 불가
    expect(backend.writes().find((r) => r.method === 'PATCH')?.body).toBe(JSON.stringify({ role: 'admin' }));
  });

  test('조회자: 계정 · 인증 감사 탭이 없고 테스트 발송 버튼도 없다', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/settings?tab=accounts');
    await expect(page.locator(TABS)).toHaveText(['서버 설정', '라이선스']);
    await expect(page.locator('[data-view="server"]')).toBeVisible();
    await expect(page.getByRole('button', { name: '테스트 발송' })).toHaveCount(0);
    await page.goto('/settings?tab=license');
    await expect(page.locator('[data-view="license"]')).toContainText('****-****-****-2026');
    expect(backend.requests.some((r) => r.path.startsWith('/users') || r.path.startsWith('/auth/audit'))).toBe(false);
  });

  test('라이선스 · 인증 감사 탭', async ({ page, backend }) => {
    await page.goto('/settings?tab=license');
    const lic = page.locator('[data-view="license"]');
    await expect(lic).toContainText('평가판');
    await expect(lic).toContainText('****-****-****-2026');
    await expect(lic).toContainText('200일 남음');
    await page.locator(TABS).filter({ hasText: '인증 감사' }).click();
    await expect(page).toHaveURL(/tab=auth-audit/);
    const au = page.locator('[data-view="auth-audit"]');
    await expect(au.locator('tr[data-audit]')).toHaveCount(backend.auth.audit.length);
    await expect(au).toContainText('로그인');
  });

  // 10/20: 서버(auth/service.go)가 실제로 남기는 동작 이름은 모두 한글 이름표로 보인다 — 영문 원문이 새지 않게
  test('인증 감사: 서버 동작 이름 전부 한글 이름표', async ({ page, backend }) => {
    const server = ['license_register', 'license_renew', 'login_lock', 'login', 'logout', 'otp_enroll', 'otp_recovery', 'otp_verify',
      'password_change', 'user_create', 'user_reset_otp', 'user_reset_password', 'user_update'];
    backend.auth.audit = server.map((action, i) => ({ id: i + 1, at: new Date().toISOString(), actor: 'admin', action, target: 'admin', ip: '10.0.0.1', ok: true, detail: '' }));
    await page.goto('/settings?tab=auth-audit');
    const au = page.locator('[data-view="auth-audit"]');
    await expect(au.locator('tr[data-audit]')).toHaveCount(server.length);
    for (const a of server) await expect(au).not.toContainText(a);
  });

  // W-B (10/21): 서버가 거르는 필터 — 한 일(action) · 실패만(failed=1) · 켜진 필터 칩 · 「더 보기」(before=<마지막 id>)
  test('인증 감사 필터: 실패만 · 한 일 · 칩 해제 · 더 보기', async ({ page, backend }) => {
    const at = new Date().toISOString();
    // id 250 → 1(최신순). 3의 배수는 실패, 짝수는 로그인 · 홀수는 로그아웃
    backend.auth.audit = Array.from({ length: 250 }, (_, i) => {
      const id = 250 - i;
      return { id, at, actor: 'admin', action: id % 2 ? 'logout' : 'login', target: '', ip: '10.0.0.1', ok: id % 3 !== 0, detail: '' };
    });
    const auditReqs = () => backend.requests.filter((r) => r.method === 'GET' && r.path.startsWith('/auth/audit')).map((r) => new URL(r.path, 'http://x').searchParams);
    await page.goto('/settings?tab=auth-audit');
    const au = page.locator('[data-view="auth-audit"]');
    const rows = au.locator('tr[data-audit]');
    await expect(rows).toHaveCount(200);
    await expect(au.locator('[data-part="filter-chips"]')).toHaveCount(0);
    // 「한 일」은 서버가 받는 13개 + 전체(system 은 처리자 값이라 없다)
    await expect(au.getByLabel('한 일').locator('option')).toHaveCount(AUDIT_ACTIONS.length + 1);
    expect(await au.getByLabel('한 일').locator('option').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value).slice(1))).toEqual(AUDIT_ACTIONS);

    // 「더 보기」 — 마지막 행 id(51)를 before 로, 받은 수(50) < limit 이면 버튼이 사라진다
    await au.getByRole('button', { name: '더 보기' }).click();
    await expect(rows).toHaveCount(250);
    expect(auditReqs().at(-1)!.get('before')).toBe('51');
    await expect(au.getByRole('button', { name: '더 보기' })).toHaveCount(0);

    // 「실패만」 → failed=1, 실패 행만
    await au.getByLabel('실패만').check();
    await expect.poll(() => auditReqs().at(-1)!.get('failed')).toBe('1');
    await expect(rows).toHaveCount(83);
    await expect(rows.filter({ hasText: '성공' })).toHaveCount(0);
    await expect(au.locator('[data-part="filter-chips"] [data-chip="failed"]')).toContainText('실패만');
    await expect(au.getByRole('button', { name: '더 보기' })).toHaveCount(0);

    // 한 일 고르기 → action= 이 붙는다(실패만과 함께)
    await au.getByLabel('한 일').selectOption({ label: '로그인' });
    await expect.poll(() => auditReqs().at(-1)!.get('action')).toBe('login');
    expect(auditReqs().at(-1)!.get('failed')).toBe('1');
    await expect(rows).toHaveCount(41);
    await expect(rows.filter({ hasText: '로그아웃' })).toHaveCount(0);
    await expect(au.locator('[data-chip="action"]')).toContainText('한 일: 로그인');

    // 칩을 눌러 해제 — 실패만 해제 → failed 없이 다시 부른다
    await au.locator('[data-chip="failed"]').getByRole('button').click();
    await expect(au.getByLabel('실패만')).not.toBeChecked();
    await expect.poll(() => [...auditReqs().at(-1)!.entries()]).toEqual([['limit', '200'], ['action', 'login']]);
    await expect(rows).toHaveCount(125);
    await au.locator('[data-chip="action"]').getByRole('button').click();
    await expect(rows).toHaveCount(200);
    await expect(au.locator('[data-part="filter-chips"]')).toHaveCount(0);
  });

  test('상단 라이선스 칩: 30일 넘으면 기본, 30일 이하 노랑, 만료 빨강', async ({ page, backend }) => {
    const chip = page.locator('[data-part="license-chip"]');
    await page.goto('/');
    await expect(chip).toHaveText('평가판 · 200일 남음');
    await expect(chip).toHaveAttribute('data-tone', 'ok');
    backend.auth.setLicenseDays(30);
    await page.reload();
    await expect(chip).toHaveText('평가판 · 30일 남음');
    await expect(chip).toHaveAttribute('data-tone', 'warn');
    backend.auth.setLicenseDays(-1);
    await page.reload();
    await expect(chip).toHaveText('라이선스 만료');
    await expect(chip).toHaveAttribute('data-tone', 'danger');
  });
});
