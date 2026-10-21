import { expect, test } from './fixtures';
import { MSG } from './mock-auth';

// W21 (10/20): 설정 › 라이선스 「새 키 등록」 — PUT /api/license. 관리자만 버튼이 보이고(조회자는 버튼 없음),
// 로그인 라이선스 단계와 같은 4칸 입력(붙여넣기 분배) → 확인 대화상자 → 저장 → 탭 · 상단 칩 갱신(/api/auth/me 다시 읽기)

// 형식 오류 400 은 브라우저가 네트워크 로그를 콘솔에 남긴다 — 그 줄만 허용(스크립트 오류는 그대로 0)
test.beforeEach(({ allowConsole }) => allowConsole(/^Failed to load resource: the server responded with a status of 400 /));

// 클립보드 붙여넣기(포커스된 칸에) — 로그인 단계 e2e 와 같은 방법
const pasteText = (t: string) => {
  const dt = new DataTransfer();
  dt.setData('text/plain', t);
  document.activeElement!.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
};

test.describe('W21 라이선스 갱신', () => {
  test('관리자: 새 키 등록 → 붙여넣기 4칸 → 확인 대화상자 → 저장 → 탭 · 칩 갱신', async ({ page, backend }) => {
    backend.auth.setLicenseDays(20); // 30일 이하 — 노랑 칩
    await page.goto('/settings?tab=license');
    const chip = page.locator('[data-part="license-chip"]');
    await expect(chip).toHaveText('평가판 · 20일 남음');
    await expect(chip).toHaveAttribute('data-tone', 'warn');
    const view = page.locator('[data-view="license"]');
    await expect(view).toContainText('****-****-****-2026');

    await view.getByRole('button', { name: '새 키 등록' }).click();
    const dlg = page.locator('[data-part="license-renew"]');
    const boxes = dlg.locator('[data-part="key-boxes"] input');
    await expect(boxes).toHaveCount(4);
    await boxes.first().focus();
    await page.evaluate(pasteText, ' 9876-5432-1098-7654 ');
    await expect(boxes.nth(0)).toHaveValue('9876');
    await expect(boxes.nth(1)).toHaveValue('5432');
    await expect(boxes.nth(2)).toHaveValue('1098');
    await expect(boxes.nth(3)).toHaveValue('7654');
    await dlg.getByRole('button', { name: '등록' }).click();

    // 확인 대화상자 — 아직 서버에 보내지 않았다
    const cf = page.locator('[data-part="confirm"]');
    await expect(cf).toContainText('지금 라이선스를 바꿉니다');
    await expect(cf).toContainText('만료일');
    await expect(cf.locator('[data-part="confirm-target"]')).toContainText('7654');
    expect(backend.requests.some((r) => r.method === 'PUT' && r.path === '/license')).toBe(false);
    // 취소하면 입력 칸으로 돌아오고 값은 그대로
    await cf.getByRole('button', { name: '취소' }).click();
    await expect(boxes.nth(3)).toHaveValue('7654');
    await dlg.getByRole('button', { name: '등록' }).click();
    await page.locator('[data-part="confirm"]').getByRole('button', { name: '바꾸기' }).click();

    await expect(page.locator('[data-part="license-renew"]')).toHaveCount(0);
    await expect(view).toContainText('****-****-****-7654');
    await expect(view).toContainText('365일 남음');
    await expect(chip).toHaveText('평가판 · 365일 남음');
    await expect(chip).toHaveAttribute('data-tone', 'ok');
    const puts = backend.requests.filter((r) => r.method === 'PUT' && r.path === '/license').map((r) => JSON.parse(r.body!).key);
    expect(puts).toEqual(['9876-5432-1098-7654']);
    expect(backend.requests.filter((r) => r.path === '/auth/me').length).toBeGreaterThanOrEqual(2); // 칩 갱신용 다시 읽기

    // 인증 감사에 「라이선스 갱신」 — 키는 가린 값만
    await page.goto('/settings?tab=auth-audit');
    const au = page.locator('[data-view="auth-audit"]');
    await expect(au.locator('tr[data-audit]').first()).toContainText('라이선스 갱신');
    await expect(au).not.toContainText('9876-5432-1098-7654');
  });

  test('만료된 라이선스도 설정에서 바로 갱신', async ({ page, backend }) => {
    backend.auth.setLicenseDays(-1);
    await page.goto('/settings?tab=license');
    const chip = page.locator('[data-part="license-chip"]');
    await expect(chip).toHaveText('라이선스 만료');
    await page.locator('[data-view="license"]').getByRole('button', { name: '새 키 등록' }).click();
    const boxes = page.locator('[data-part="license-renew"] [data-part="key-boxes"] input');
    for (const [i, v] of ['1111', '2222', '3333', '4444'].entries()) await boxes.nth(i).fill(v);
    await boxes.nth(3).press('Enter'); // Enter 도 「등록」과 같다 — 확인 대화상자를 건너뛰지 않는다
    const cf = page.locator('[data-part="confirm"]');
    await expect(cf).toBeVisible();
    await expect(chip).toHaveText('라이선스 만료');
    expect(backend.requests.some((r) => r.method === 'PUT' && r.path === '/license')).toBe(false);
    await cf.getByRole('button', { name: '바꾸기' }).click();
    await expect(chip).toHaveText('평가판 · 365일 남음');
    await expect(page.locator('[data-view="license"]')).toContainText('****-****-****-4444');
  });

  test('형식 오류: 로그인 단계와 같은 문구, 입력 칸이 그대로 남고 저장되지 않는다', async ({ page, backend }) => {
    await page.goto('/settings?tab=license');
    await page.locator('[data-view="license"]').getByRole('button', { name: '새 키 등록' }).click();
    const dlg = page.locator('[data-part="license-renew"]');
    const boxes = dlg.locator('[data-part="key-boxes"] input');
    for (const [i, v] of ['1234', '5678', '9012', '34'].entries()) await boxes.nth(i).fill(v);
    await dlg.getByRole('button', { name: '등록' }).click();
    await page.locator('[data-part="confirm"]').getByRole('button', { name: '바꾸기' }).click();
    await expect(dlg.locator('[role="alert"]')).toHaveText(MSG.badKey);
    await expect(boxes.nth(3)).toHaveValue('34');
    await expect(page.locator('[data-view="license"]')).toContainText('****-****-****-2026');
    expect(backend.auth.license!.keyMasked).toBe('****-****-****-2026');
  });

  test('조회자: 라이선스 탭은 보기만 — 「새 키 등록」 버튼 자체가 없다', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/settings?tab=license');
    const view = page.locator('[data-view="license"]');
    await expect(view).toContainText('****-****-****-2026');
    await expect(view.getByRole('button')).toHaveCount(0);
    await expect(page.getByRole('button', { name: '새 키 등록' })).toHaveCount(0);
  });
});
