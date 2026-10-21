import { expect, test } from './fixtures';

test.describe('정책 — 이 변경을 적용하면 무엇이 달라지나?', () => {
  test('제안이 없으면 첫 정책을 자동 선택, 적용 범위 칩 · 시스템 규칙 잠금', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies');
    await expect(page).toHaveURL(/\?id=sensitive-files/);
    await expect(page.getByTestId('editor')).toContainText('정책 편집 · sensitive-files');
    await expect(page.locator('[data-rule="sandbox-egress"] [data-scope="sandbox"]')).toHaveText('설치 검사 전용');
    await expect(page.locator('[data-rule="sensitive-files"] [data-scope]')).toHaveCount(0); // 전체(기본)는 칩 없음
    await expect(page.locator('[data-rule="blocklist-hosts"] [data-system]')).toBeVisible();
    await page.locator('[data-rule="blocklist-hosts"]').click();
    await expect(page.getByTestId('system-rule')).toContainText('직접 편집할 수 없습니다');
    await expect(page.getByRole('button', { name: '저장 전 확인' })).toBeDisabled(); // 10/16: 저장은 「저장 전 확인」을 거친다
  });

  test('① 「제안된 변경」이 맨 위 ② 미리보기: 결과가 바뀌는 건수와 목록', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0011');
    await page.getByTestId('decision').getByRole('button', { name: '오탐' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await page.getByRole('button', { name: '제안 보기' }).click();
    await expect(page).toHaveURL(/\/policies\?proposal=prop-/);
    const proposals = page.getByTestId('proposals');
    // 왼쪽 열 맨 위
    const [pBox, rBox] = await Promise.all([proposals.boundingBox(), page.getByTestId('rules').boundingBox()]);
    expect(pBox!.y).toBeLessThan(rBox!.y);
    await expect(proposals.locator('[data-proposal]')).toHaveCount(1);
    const detail = page.getByTestId('proposal');
    await expect(detail.getByTestId('proposal-changes')).toContainText('egress-allowlist 허용 대역 += 140.82.112.3/32'); // allowHosts 없던 규칙 → IP/32 (3차 결정 3)
    await expect(detail.getByTestId('preview-summary')).toBeVisible(); // 열면 자동 미리보기(10/15 3차) — 버튼은 다시 계산
    await detail.getByRole('button', { name: '미리보기' }).click();
    await expect(detail.getByTestId('preview-summary')).toContainText(`감사 로그 ${backend.audit.length}건 재평가`);
    await expect(detail.locator('[data-to-normal="2"]')).toBeVisible(); // 「과거 2건이 통과로 바뀜」
    await expect(detail.getByTestId('preview').locator('tbody tr')).toHaveCount(2);
    expect(backend.writes().filter((r) => r.path.endsWith('/apply'))).toHaveLength(0); // 미리보기는 쓰기 없음
  });

  test('③ 적용하면 변경 이력(누가 · 언제 · 어느 판정에서) ④ 차단 목록', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await page.getByRole('button', { name: '제안 보기' }).click();
    const detail = page.getByTestId('proposal');
    await expect(detail.getByTestId('proposal-changes').locator('li')).toHaveText([/패키지 차단 pip:reqeusts/, /도메인 차단 cdn.reqeusts-update.test/]);
    await detail.getByRole('button', { name: '미리보기' }).click();
    await expect(detail.getByTestId('next-only')).toContainText('다음 설치 · 기동부터');
    await detail.getByRole('button', { name: '적용' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(detail.getByTestId('proposal-state')).toContainText('적용됨 · 보안 담당자');
    await expect(page.getByTestId('proposals').locator('[data-proposal]')).toHaveCount(0);
    const changes = page.getByTestId('changes');
    await expect(changes.locator('[data-change]').first()).toContainText('제안 적용');
    await expect(changes.locator('[data-change]').first()).toContainText('pip:reqeusts');
    await expect(changes.locator('[data-change]').first()).toContainText('보안 담당자');
    await expect(page.getByTestId('blocklist').locator('[data-block="packages:pip:reqeusts"]')).toBeVisible();
    await expect(page.getByTestId('blocklist').locator('[data-block="hosts:cdn.reqeusts-update.test"]')).toBeVisible();
    expect(backend.case('case-0004').state).toBe('closed');
  });

  test('버림은 확인 대화상자로 확정, 건은 변경 없이 종결', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0011');
    await page.getByTestId('decision').getByRole('button', { name: '오탐' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await page.getByRole('button', { name: '제안 보기' }).click();
    await page.getByRole('button', { name: '버림', exact: true }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(page.getByTestId('proposal-state')).toContainText('버림');
    expect(backend.case('case-0003').state).toBe('closed');
    expect(backend.changes).toHaveLength(2); // W18: 버림도 변경 이력(proposal_discarded)에 남는다
    expect(backend.changes[0].kind).toBe('proposal_discarded');
  });

  test('정책 저장은 쿠키 세션 — 관리자 토큰 칸 없이, Authorization 헤더 없이 (W16)', async ({ page, backend }) => {
    await page.goto('/policies?id=egress-allowlist');
    await expect(page.getByLabel('관리자 토큰')).toHaveCount(0);
    // 10/16: 쉬운 설정 ⑤ 설명 → 저장 전 확인 → 저장 후 적용
    await page.locator('[data-view="rule-editor"] input[data-field="description"]').fill('허용 목적지 외 통신 (수정)');
    await page.getByRole('button', { name: '저장 전 확인' }).click();
    const save = page.locator('[data-part="save-check"]').getByRole('button', { name: '저장 후 적용' });
    await save.click();
    await expect(page.getByText('저장 후 엔진에 적용됨')).toBeVisible();
    const w = backend.writes().find((r) => r.path === '/policies' && r.method === 'POST')!;
    expect(w.auth).toBeNull();
    expect(JSON.parse(w.body!).description).toBe('허용 목적지 외 통신 (수정)');
    await expect(page.getByTestId('changes').locator('[data-change]').first()).toContainText('정책 편집');
  });

  test('조회자에게는 판정 버튼이 없고 안내 한 줄만 (W16)', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/installs?id=ins-0012');
    await expect(page.getByTestId('decision').getByRole('button', { name: '악성 확정' })).toHaveCount(0);
    await expect(page.getByTestId('decision')).toContainText('판정은 관리자가 합니다');
  });
});
