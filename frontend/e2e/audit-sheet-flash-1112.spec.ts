import { expect, test } from './fixtures';

// 11/12 CI 실패(sequence-1104 ⑦)의 원인 — 주소(/audit?id=)로 연 감사 시트가 한 건 조회로 먼저 그려진 뒤,
// 늦게 온 목록이 행 캐시를 채우면 불러오기 함수가 바뀌어 내용이 잠깐 「불러오는 중…」으로 깜박였다.
// 목록 응답만 늦춰 그 순서를 강제하고, 시트 내용이 한 번 나타난 뒤 사라지지 않는지 본다.
test('주소로 연 감사 시트: 목록이 늦게 와도 내용이 깜박이지 않음', async ({ page, backend }) => {
  const row = backend.audit[0];
  // 목록(한 건 조회 before=… 가 아닌 것)만 1.2초 늦춘다 — 나머지는 가짜 백엔드 그대로
  await page.route(/\/api\/audit(\?|$)/, async (route) => {
    if (!new URL(route.request().url()).searchParams.has('before')) await new Promise((r) => setTimeout(r, 1200));
    await route.fallback();
  });
  // 사유 칸이 나타난 뒤 문서에서 빠지는 횟수를 센다
  await page.addInitScript(() => {
    const w = window as unknown as { __reasonGone: number; __reasonSeen: boolean };
    w.__reasonGone = 0;
    w.__reasonSeen = false;
    new MutationObserver(() => {
      const on = !!document.querySelector('[data-sheet="audit"] [data-testid="audit-reason"]');
      if (on) w.__reasonSeen = true;
      else if (w.__reasonSeen) {
        w.__reasonGone += 1;
        w.__reasonSeen = false;
      }
    }).observe(document, { childList: true, subtree: true });
  });
  const listDone = page.waitForResponse((r) => /\/api\/audit(\?|$)/.test(r.url()) && !new URL(r.url()).searchParams.has('before'));
  await page.goto(`/audit?id=${row.id}`);
  await expect(page.locator('[data-sheet="audit"] [data-testid="audit-reason"]')).toBeVisible();
  await listDone;
  await page.waitForTimeout(300); // 목록 반영 뒤 다시 그리기까지
  await expect(page.locator('[data-sheet="audit"] [data-testid="audit-reason"]')).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { __reasonGone: number }).__reasonGone)).toBe(0);
});
