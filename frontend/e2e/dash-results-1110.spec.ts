import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";

// 11/10 사용자: 대시보드 「설치 검사 결과」 카드 오른쪽 내용(범례 5줄 · 판정 · 차단 목록)이 위로 삐져나옴 → 카드 몸통 안에 들어가게.
// 원인: .sg-res 높이를 차트 높이(--chart-h, 낮은 화면 120px)로 고정하고 가운데 정렬 → 내용이 더 길면 위아래로 넘침.
const CARD = '[data-card="results"]';

async function overflow(page: Page) {
  return page.locator(CARD).evaluate((card) => {
    const body = card.querySelector(".sg-dash-chart-body")!.getBoundingClientRect();
    const out: string[] = [];
    for (const el of card.querySelectorAll("[data-results] *")) {
      const b = el.getBoundingClientRect();
      if (!b.width || !b.height) continue;
      if (b.top < body.top - 0.5 || b.bottom > body.bottom + 0.5 || b.left < body.left - 0.5 || b.right > body.right + 0.5)
        out.push(`${el.tagName.toLowerCase()} "${(el.textContent || "").trim().slice(0, 16)}" ${Math.round(b.top - body.top)}..${Math.round(body.bottom - b.bottom)}`);
    }
    // 글이 잘려 「…」로 숨는 줄(판정 · 차단 목록)
    for (const el of card.querySelectorAll<HTMLElement>(".sg-res-line")) {
      if (el.scrollWidth > el.clientWidth + 1) out.push(`잘림 "${(el.textContent || "").trim().slice(0, 16)}"`);
    }
    return out;
  });
}

for (const [w, h] of [
  [1280, 720],
  [1366, 768],
  [1440, 900],
  [1920, 1080],
]) {
  test(`${w}×${h}: 설치 검사 결과 내용이 카드 몸통 안에 있고 판정 줄이 잘리지 않는다 · 페이지 스크롤 0`, async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: w, height: h });
    await page.goto("/");
    await expect(page.locator(`${CARD} [data-results]`)).toBeVisible();
    expect(await overflow(page)).toEqual([]);
    const doc = await page.evaluate(() => document.scrollingElement!.scrollHeight - innerHeight);
    expect(doc).toBeLessThanOrEqual(0);
  });
}

test("1280×720: 판정 · 차단 목록 줄이 범례 아래에 겹치지 않고 차례로 놓인다", async ({ page, backend }) => {
  void backend;
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/");
  const legend = (await page.locator(`${CARD} .sg-res-legend`).boundingBox())!;
  const dec = (await page.locator(`${CARD} [data-part="res-decisions"]`).boundingBox())!;
  const head = (await page.locator(`${CARD} .sg-dash-chart-body`).boundingBox())!;
  expect(legend.y).toBeGreaterThanOrEqual(head.y - 0.5);
  expect(dec.y).toBeGreaterThanOrEqual(legend.y + legend.height - 0.5);
});
