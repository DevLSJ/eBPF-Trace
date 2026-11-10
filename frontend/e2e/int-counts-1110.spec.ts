import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";

// 11/10 사용자: 연결 테스트 아래 실행 · 파일 · 통신 · 조회 칸 색이 너무 짙어 글씨가 안 보임.
// 원인: 차트 범례용 전역 .k-<종류> { background: 진한 종류색 } 이 칸(.int-count.k-<종류>)에도 걸리고, 받은 수 글자도 같은 진한 색.
// 기대: 칸 바탕은 옅게(연한 종류색 또는 면 색), 라벨 · 숫자 모두 바탕 대비 4.5:1 이상 — 밝은 · 어두운 모두
const lum = (rgb: string) => {
  const [r, g, b] = rgb.match(/[\d.]+/g)!.slice(0, 3).map(Number).map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

async function measure(page: Page) {
  return page.locator('[data-part="test-counts"] [data-kind]').evaluateAll((els) =>
    els.map((e) => {
      // 바탕: 칸 자신이 투명이면 위로 올라가며 첫 불투명 바탕
      let n: Element | null = e;
      let bg = "rgba(0, 0, 0, 0)";
      while (n && /rgba\(.*, 0\)|transparent/.test(bg)) {
        bg = getComputedStyle(n).backgroundColor;
        n = n.parentElement;
      }
      return {
        kind: (e as HTMLElement).dataset.kind!,
        got: e.classList.contains("got"),
        bg,
        label: getComputedStyle(e).color,
        num: getComputedStyle(e.querySelector("b")!).color,
      };
    }),
  );
}

for (const theme of ["light", "dark"] as const) {
  test(`연결 테스트 종류별 칸(${theme}): 바탕이 옅고 라벨 · 숫자 대비 4.5:1 이상(받은 칸 · 못 받은 칸 모두)`, async ({ page, backend }) => {
    void backend;
    await page.emulateMedia({ colorScheme: theme });
    await page.goto("/integration/env");
    const step = page.locator('[data-part="test-step"]');
    await step.locator('[data-part="test-start"]').click();
    await expect(step).toHaveAttribute("data-state", "passed", { timeout: 5000 });
    await page.waitForTimeout(400);
    const cells = await measure(page);
    expect(cells.map((c) => c.kind)).toEqual(["exec", "open", "connect", "dns"]);
    expect(cells.some((c) => c.got)).toBe(true);
    const bad = cells.flatMap((c) => {
      const out: string[] = [];
      if (ratio(c.label, c.bg) < 4.5) out.push(`${c.kind} 라벨 ${ratio(c.label, c.bg).toFixed(2)}`);
      if (ratio(c.num, c.bg) < 4.5) out.push(`${c.kind} 숫자 ${ratio(c.num, c.bg).toFixed(2)}`);
      return out;
    });
    expect(bad).toEqual([]);
  });
}
