import { expect, test } from './fixtures';

test.describe('대시보드 — 지금 처리할 일이 있나?', () => {
  test('① 첫 줄에 판정 대기 N 과 목록(설치 검사 · 런타임 함께)', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await expect(page.getByTestId('pending-count')).toHaveText('3');
    const list = page.getByTestId('pending-list');
    await expect(list.locator('[data-case]')).toHaveCount(3);
    await expect(list.getByText('설치 검사')).toHaveCount(2);
    await expect(list.getByText('런타임')).toHaveCount(1);
    await expect(list.getByText('pip ./reqeusts')).toBeVisible(); // 입력 그대로(정규화 이름은 차단 목록 · 제안 변경 내용만)
    await expect(list.getByText('pkg-reqeusts')).toBeVisible();
    // 사이드바 배지도 같은 숫자
    await expect(page.getByLabel('판정 대기 3건')).toBeVisible();
  });

  test('판정 대기 항목을 누르면 판정하러 간다', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await page.locator('[data-case="case-0004"]').click();
    await expect(page).toHaveURL(/\/installs\?status=pending&id=ins-0012/);
    await expect(page.locator('[data-sheet="install"]')).toBeVisible();
    await page.goto('/');
    await page.locator('[data-case="case-0005"]').click();
    await expect(page).toHaveURL(/\/topology\?container=pkg-reqeusts&node=c%3Apkg-reqeusts/);
  });

  test('② 0건이면 「처리할 일 없음」', async ({ page, backend }) => {
    backend.cases = backend.cases.filter((c) => c.state === 'closed');
    await page.goto('/');
    await expect(page.getByTestId('pending-count')).toHaveText('0');
    await expect(page.getByTestId('nothing-to-do')).toContainText('처리할 일 없음');
  });

  // 10/16: 오늘 요약 · 감시 중 분당 막대 → 「eBPF 수집 종합」(overview-1016.spec.ts)
  test('③ 판정 대기 아래 eBPF 수집 종합 — 감시 중 · 위반 추이', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    const ov = page.locator('[data-section="overview"]');
    await expect(ov).toContainText('감시 중');
    expect(await ov.locator('[data-chart="violations"] [data-bucket]').count()).toBeGreaterThanOrEqual(5);
    // 위험 점수 · 실시간 피드 · 최근 설치 전체 목록은 없다(다른 탭과 중복)
    await expect(page.getByText('위험 점수')).toHaveCount(0);
    await expect(page.getByText('실시간 이벤트 피드')).toHaveCount(0);
  });
});
