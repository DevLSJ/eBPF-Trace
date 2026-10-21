import { expect, test } from './fixtures';

test.describe('설치 검사 — 이 패키지는 무엇을 하려 했고, 악성인가?', () => {
  test('① 기본 필터는 「판정 대기」, 칩으로 결과 · 매니저를 고른다', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs');
    await expect(page.locator('[data-chip="pending"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('tr[data-install]')).toHaveCount(2); // reqeusts · tiny-git-dep
    await page.locator('[data-chip="all"]').click();
    await expect(page).toHaveURL(/status=all/);
    await expect(page.locator('tr[data-install]')).toHaveCount(8);
    await page.locator('[data-chip="npm"]').click();
    await expect(page.locator('tr[data-install]')).toHaveCount(2);
    await page.locator('[data-chip=""]').click();
    await page.locator('[data-chip="isolated"]').click();
    await expect(page.locator('tr[data-install]')).toHaveCount(2); // reqeusts · colourama
    await page.locator('[data-chip="npm"]').click(); // npm 격리 0
    await expect(page.getByText('조건에 맞는 세션 없음')).toBeVisible();
  });

  test('② 상세: 결과 · 명령 · 공격 체인 3단계 · 활동 요약 · 정적 분석 비교(버전 무관)', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0012');
    const sheet = page.locator('[data-sheet="install"]');
    await expect(sheet.locator('[data-status="isolated"]').first()).toBeVisible();
    await expect(sheet.getByTestId('install-command')).toHaveText('sg-install pip ./reqeusts');
    const chain = sheet.getByTestId('attack-chain');
    await expect(chain.locator('[data-step]')).toHaveCount(6);
    const steps = await chain.locator('[data-step]').allTextContents();
    expect([...new Set(steps)]).toEqual(['1 실행', '2 파일', '3 통신']);
    await expect(sheet.getByTestId('osv-result')).toContainText('버전 무관');
    await expect(sheet.getByTestId('osv-result').locator('[data-osv="0"]')).toContainText('0건');
    await expect(sheet.getByTestId('kernel-result')).toContainText('6건');
    await expect(sheet.getByTestId('activity')).toContainText('cdn.reqeusts-update.test:4444');
    // 이름 정규화: ./reqeusts → reqeusts, 생태계 PyPI
    expect(backend.requests.some((r) => r.path === '/osv?ecosystem=PyPI&name=reqeusts')).toBe(true);
  });

  test('OSV 조회가 실패해도 화면은 깨지지 않고 「조회 실패」', async ({ page, backend }) => {
    backend.osvFail = true;
    await page.goto('/installs?id=ins-0012');
    await expect(page.getByTestId('osv-result').locator('[data-osv="failed"]')).toHaveText('조회 실패');
    await expect(page.getByTestId('attack-chain')).toBeVisible();
  });

  test('③ 판정 버튼 2개, 판정 뒤 결과 · 처리자 · 시각', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0011');
    const box = page.getByTestId('decision');
    await expect(box.getByRole('button', { name: '악성 확정' })).toBeEnabled();
    await expect(box.getByRole('button', { name: '오탐' })).toBeEnabled();
    await box.getByRole('button', { name: '오탐' }).click();
    await page.locator('dialog[data-part="confirm"] textarea[name="reason"]').fill('git:// 의존성'); // W18: 메모 칸 → 대화상자의 사유
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(box.locator('[data-decision="false_positive"]')).toBeVisible();
    await expect(box.getByTestId('decided-by')).toHaveText('보안 담당자');
    await expect(box).toContainText('git:// 의존성');
    await expect(box.getByRole('link', { name: /정책에서 미리보기/ })).toHaveAttribute('href', /\/policies\?proposal=prop-/);
    expect(JSON.parse(backend.writes().find((r) => r.path === '/cases/case-0003/decide')!.body!)).toEqual({ decision: 'false_positive', note: 'git:// 의존성' });
    // 목록의 판정 열도 바뀐다
    await page.locator('[data-chip="all"]').click();
    await expect(page.locator('tr[data-install="ins-0011"] [data-decision="false_positive"]')).toBeVisible();
  });

  test('④ 차단된 패키지 재설치는 「설치 전 거부」 세션', async ({ page, backend }) => {
    backend.installs.unshift({
      id: 'ins-0014',
      manager: 'pip',
      packages: ['reqeusts'],
      container: '',
      image: 'python:3.12-slim',
      startedAt: new Date().toISOString(),
      status: 'refused',
      refusedBy: { list: 'packages', value: 'pip:colourama' },
      caseId: null,
    });
    await page.goto('/installs?status=refused');
    await expect(page.locator('tr[data-install="ins-0014"] [data-status="refused"]')).toHaveText('설치 전 거부');
    await page.locator('tr[data-install="ins-0014"]').click();
    await expect(page.getByTestId('refused-by')).toContainText('pip:colourama');
    await expect(page.getByTestId('refused-by')).toContainText('컨테이너를 띄우기 전에 거부');
  });

  test('URL 이 상태: 새로고침해도 시트 유지, Esc 로 닫고, 키보드로 연다', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?status=all&manager=pip&id=ins-0012');
    await page.reload();
    await expect(page.locator('[data-sheet="install"]')).toBeVisible();
    await expect(page.locator('[data-chip="pip"]')).toHaveAttribute('aria-pressed', 'true');
    await page.keyboard.press('Escape');
    await expect(page.locator('[data-sheet]')).toHaveCount(0);
    await expect(page).not.toHaveURL(/id=/);
    await page.locator('tr[data-install="ins-0010"]').focus();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/id=ins-0010/);
    await expect(page.getByTestId('decision-area')).toContainText('판정할 건이 없습니다');
  });

  test('빈 서버: 명령 복사 안내', async ({ page, backend, context }) => {
    backend.empty();
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/installs?status=all');
    await expect(page.getByTestId('installs-empty')).toContainText('tools/sg-install pip requests');
    await page.getByTestId('page-actions').getByRole('button', { name: '명령 복사' }).click();
    await expect(page.locator('[data-toast="copy"]')).toContainText('명령을 복사했습니다');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('tools/sg-install pip requests');
  });
});
