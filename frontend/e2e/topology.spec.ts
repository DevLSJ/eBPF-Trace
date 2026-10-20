import { expect, test } from './fixtures';

test.describe('토폴로지 — 이 컨테이너는 어디까지 손댔나?', () => {
  test('① 설치 검사 컨테이너(sg-install-*)는 빼고 런타임만', async ({ page, backend }) => {
    void backend;
    await page.goto('/topology');
    await expect(page.locator('.react-flow__node')).not.toHaveCount(0);
    await expect(page.getByLabel('컨테이너').locator('option')).toHaveText(['모든 런타임 컨테이너', 'pkg-reqeusts', 'web-api', 'worker']);
    await expect(page.locator('.react-flow__node', { hasText: 'sg-install' })).toHaveCount(0);
  });

  test('② 공격 체인은 설치 검사와 같은 부품', async ({ page, backend }) => {
    void backend;
    await page.goto('/topology');
    const chain = page.locator('[data-chain="pkg-reqeusts"] [data-testid="attack-chain"]');
    await expect(chain).toBeVisible();
    const steps = await chain.locator('[data-step]').allTextContents();
    expect([...new Set(steps)]).toEqual(['1 실행', '2 파일', '3 통신']);
    await page.goto('/installs?id=ins-0012');
    await expect(page.locator('[data-sheet="install"] [data-testid="attack-chain"]')).toBeVisible();
  });

  test('③ 격리 컨테이너를 고르면 판정 버튼 → 악성 확정은 이미지 · 도메인 차단 제안', async ({ page, backend }) => {
    await page.goto('/topology?container=pkg-reqeusts&node=c%3Apkg-reqeusts');
    const box = page.getByTestId('topology-decision');
    await expect(box.getByRole('button', { name: '악성 확정' })).toBeVisible();
    await expect(box.getByRole('button', { name: '오탐' })).toBeVisible();
    await expect(box).toContainText('이미지 · 도메인 차단 제안');
    await box.getByRole('button', { name: '악성 확정' }).click();
    await expect(box.locator('[data-decision="malicious"]')).toBeVisible();
    const p = backend.proposals[0];
    expect(p.caseId).toBe('case-0005');
    expect(p.changes).toEqual([
      { op: 'block', list: 'images', value: 'demo/reqeusts:1.0.2' },
      { op: 'block', list: 'hosts', value: 'cdn.reqeusts-update.test' },
    ]);
    // 체인 머리에도 판정 배지
    await expect(page.locator('[data-chain="pkg-reqeusts"] [data-decision="malicious"]')).toBeVisible();
  });

  test('정상 컨테이너는 판정 버튼이 없다', async ({ page, backend }) => {
    void backend;
    await page.goto('/topology?node=c%3Aweb-api');
    await expect(page.getByTestId('node-detail')).toContainText('web-api');
    await expect(page.getByTestId('topology-decision')).toHaveCount(0);
  });
});
