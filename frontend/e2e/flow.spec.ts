import { expect, SHOTS, test } from './fixtures';

// 판정 흐름 한 바퀴: 설치 격리 건 → 악성 확정 → 정책 미리보기 → 적용 → 판정 대기 감소 · 변경 이력 1건
test('판정 흐름 한 바퀴 (설치 격리 → 악성 확정 → 미리보기 → 적용)', async ({ page, backend }) => {
  // 0) 대시보드: 판정 대기 3
  await page.goto('/');
  await expect(page.getByTestId('pending-count')).toHaveText('3');
  const changesBefore = backend.changes.length;

  // 1) 설치 격리 건을 연다
  await page.locator('[data-case="case-0004"]').click();
  const sheet = page.locator('[data-sheet="install"]');
  await expect(sheet.getByTestId('attack-chain')).toBeVisible();
  await expect(sheet.getByTestId('osv-result')).toContainText('0건');
  await page.screenshot({ path: `${SHOTS}/flow-1-install-sheet.png` });

  // 2) 악성 확정 → 토스트 「제안 보기」
  await sheet.getByRole('button', { name: '악성 확정' }).click();
  await expect(sheet.getByTestId('decision').locator('[data-decision="malicious"]')).toBeVisible();
  // 판정 대기 목록에서 빠진다(필터 「판정 대기」)
  await expect(page.locator('tr[data-install="ins-0012"]')).toHaveCount(0);
  await page.locator('[data-toast^="decide:"]').getByRole('button', { name: '제안 보기' }).click();

  // 3) 정책: 제안 미리보기 → 적용
  await expect(page).toHaveURL(/\/policies\?proposal=/);
  const detail = page.getByTestId('proposal');
  await detail.getByRole('button', { name: '미리보기' }).click();
  await expect(detail.getByTestId('preview-summary')).toBeVisible();
  await page.screenshot({ path: `${SHOTS}/flow-2-proposal-preview.png` });
  await detail.getByRole('button', { name: '적용' }).click();
  await expect(detail.getByTestId('proposal-state')).toContainText('적용됨');

  // 4) 변경 이력 1건 · 차단 목록에 패키지
  await expect(page.getByTestId('changes').locator('[data-change]')).toHaveCount(changesBefore + 1);
  await expect(page.getByTestId('blocklist').locator('[data-block="packages:pip:reqeusts"]')).toBeVisible();
  await page.screenshot({ path: `${SHOTS}/flow-3-applied.png` });

  // 5) 대시보드: 판정 대기 2 (3 → 2)
  await page.getByRole('navigation', { name: '화면' }).getByRole('link', { name: /대시보드/ }).click();
  await expect(page.getByTestId('pending-count')).toHaveText('2');
  await expect(page.locator('[data-case="case-0004"]')).toHaveCount(0);

  // 6) 감사 로그: 판정 결과가 「악성」, 이력에 판정 + 제안 적용
  await page.goto('/audit');
  await expect(page.locator('tr[data-audit]', { hasText: 'pip ./reqeusts' }).first().locator('[data-decision="malicious"]')).toBeVisible();
  await page.getByRole('button', { name: '판정 · 변경 이력' }).click();
  await expect(page.getByTestId('history').locator('[data-history="case:case-0004"]')).toContainText('악성');

  // 7) 같은 패키지 재설치 → CLI 가 차단 확인 후 「설치 전 거부」 세션을 보고(계약 POST /api/installs/refused)
  backend.installs.unshift({ id: 'ins-0099', manager: 'pip', packages: ['./reqeusts'], container: '', image: 'python:3.12-slim', startedAt: new Date().toISOString(), status: 'refused', refusedBy: { list: 'packages', value: 'pip:reqeusts' }, caseId: null });
  await page.goto('/installs?status=refused&id=ins-0099');
  await expect(page.getByTestId('refused-by')).toContainText('pip:reqeusts');
});
