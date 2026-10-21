import { expect, test } from './fixtures';

// 10/16 sg-vm 실측에서 찾은 화면 문제 2건

test('차단 이미지 재기동(blocked-image)은 토폴로지 공격 체인 단계에 섞이지 않는다', async ({ page, backend }) => {
  await page.goto('/topology?container=pkg-reqeusts&node=c%3Apkg-reqeusts');
  await page.getByTestId('topology-decision').getByRole('button', { name: '악성 확정' }).click();
  await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
  await page.getByRole('button', { name: '제안 보기' }).click();
  await page.getByTestId('proposal').getByRole('button', { name: '적용' }).click();
  await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
  await expect(page.getByTestId('proposal-state')).toContainText('적용됨');
  backend.runtimeKill('pkg-reqeusts', 'demo/reqeusts:1.0.2');
  await page.goto('/topology?container=pkg-reqeusts');
  const chains = page.getByTestId('chains');
  await expect(chains).toContainText('/etc/shadow');
  await expect(chains).not.toContainText('blocked-image');
});

test('조회자면 판정 칸은 안내 한 줄만 — 긴 설명으로 시트 본문을 가리지 않는다 (W16: 토큰 → 역할)', async ({ page, backend }) => {
  backend.auth.asViewer();
  await page.goto('/installs?id=ins-0012');
  const box = page.getByTestId('decision');
  await expect(box).toContainText('판정은 관리자가 합니다');
  await expect(box).not.toContainText('걸린 규칙에 예외 제안');
});
