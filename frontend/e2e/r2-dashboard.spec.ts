import type { Page } from "@playwright/test";
import { expect, SHOTS, test } from "./fixtures";
import { killedVerdict } from "./mock-backend";

// R2 11/04 — React 이식 2단계(대시보드). 목업 11/04e A(mock/README.md 「대시보드 재배치」, 회귀 ui-1104 3 · 4 · 5 · 6 · 12 · 13)와
// 사용자 결정(시연 카드는 대시보드에서 뺌 · KPI 증감은 GET /api/summary 의 previous · 위반 · 격리 증가만 빨강, 그 외 중립)을 본다.
//   A 배치(머리 한 줄 → KPI 6칸 → 차트 3칸 1.8 : 1 : 1.2 → 아래 3칸, 아래 줄이 남은 높이 · 몸통만 스크롤)  B 시연 카드 없음
//   C KPI 증감 줄  D previous null · 옛 백엔드  E 길게 눌러 옮기기(dashboardKpi)  F 1280×720 · 1440×900 · 1920×1080 스크롤 0  G 다크  H 390

const SCRATCH = process.env.R2_SHOTS || SHOTS;
const DASH = '[data-part="dashboard"]';
const KPI_IDS = [
  "collected",
  "violations",
  "isolated",
  "installs",
  "decided",
  "isolation",
];
const kpiIds = (page: Page) =>
  page
    .locator(`${DASH} [data-part="kpis"] > [data-kpi]`)
    .evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.kpi));
const box = async (page: Page, sel: string) =>
  (await page.locator(sel).boundingBox())!;
const delta = (page: Page, k: string) =>
  page.locator(`${DASH} [data-kpi="${k}"] [data-delta]`).evaluate((e) => ({
    dir: (e as HTMLElement).dataset.delta,
    tone: (e as HTMLElement).dataset.deltaTone,
    text: [...e.children].map((c) => c.textContent?.trim()).join(" "),
  }));
const rgb = (hex: string) => {
  const n = parseInt(hex.slice(1), 16);
  return `rgb(${n >> 16}, ${(n >> 8) & 255}, ${n & 255})`;
};
async function ready(page: Page) {
  await expect(page.getByTestId("pending")).toBeVisible();
  await expect(page.locator(`${DASH} [data-kpi]`)).toHaveCount(6);
}
// 768 이상: 문서 · main 스크롤 0, 넘쳐서 스크롤하는 요소는 채움 칸 안에만, 대시보드 틀 자체도 잘리지 않음
async function scrollAudit(page: Page) {
  return page.evaluate(() => {
    const main = document.querySelector("main")!;
    const se = document.scrollingElement!;
    const allowed = (e: Element) =>
      !!e.closest('[data-fill], [data-sheet], dialog, [data-part="assistant"]');
    const bad = [...main.querySelectorAll("*")]
      .filter((e) => {
        const cs = getComputedStyle(e);
        return (
          /(auto|scroll)/.test(cs.overflowY) &&
          e.scrollHeight > e.clientHeight + 1 &&
          !allowed(e)
        );
      })
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[${e.getAttribute("data-part") ?? e.getAttribute("data-testid") ?? String(e.className).split(" ").slice(0, 3).join(".")}]+${e.scrollHeight - e.clientHeight}`,
      );
    const d = document.querySelector('[data-part="dashboard"]')!;
    return {
      doc: se.scrollHeight - innerHeight,
      docW: se.scrollWidth - innerWidth,
      main: main.scrollHeight - main.clientHeight,
      dash: d.scrollHeight - d.clientHeight,
      bad,
    };
  });
}

test.describe("A 배치(1440×900)", () => {
  test("머리 한 줄(신호등 · 「eBPF 감시 중」 · 기간) → KPI 6칸 → 차트 줄 → 아래 3칸, 순서 · 한 줄", async ({
    page,
    backend,
  }) => {
    void backend;
    await page.goto("/");
    await ready(page);
    await expect(page.locator(DASH)).toHaveAttribute(
      "data-section",
      "overview",
    );
    const [top, k, c, b] = await Promise.all(
      ["dash-top", "kpis", "charts", "bottom"].map((p) =>
        box(page, `${DASH} [data-part="${p}"]`),
      ),
    );
    expect(top.y + top.height).toBeLessThanOrEqual(k.y);
    expect(k.y + k.height).toBeLessThanOrEqual(c.y);
    expect(c.y + c.height).toBeLessThanOrEqual(b.y);
    // 머리 한 줄: 신호등 · 감시 중 · 기간 칩이 같은 줄
    const head = page.locator(`${DASH} [data-part="dash-top"]`);
    await expect(head.getByTestId("signal-pills")).toBeVisible();
    await expect(head.locator('[data-part="dash-live"]')).toContainText(
      "eBPF 감시 중",
    );
    expect(
      await head
        .locator("[data-range]")
        .evaluateAll((els) =>
          els.map((e) => [
            (e as HTMLElement).dataset.range,
            e.getAttribute("aria-pressed"),
          ]),
        ),
    ).toEqual([
      ["1h", "false"],
      ["24h", "true"],
      ["7d", "false"],
    ]);
    expect(top.height).toBeLessThan(48);
    // KPI 6칸 — 직계 자식, 기본 순서, 한 줄
    expect(await kpiIds(page)).toEqual(KPI_IDS);
    const tops = await page
      .locator(`${DASH} [data-part="kpis"] > [data-kpi]`)
      .evaluateAll((els) =>
        els.map((e) => Math.round(e.getBoundingClientRect().top)),
      );
    expect(new Set(tops).size).toBe(1);
    // KPI 는 종합 카드 밖 독립 줄 — 패널 안에 있지 않다
    expect(
      await page
        .locator(`${DASH} [data-part="kpis"]`)
        .evaluate((e) => !!e.closest(".sg-panel")),
    ).toBe(false);
  });

  test("차트 줄 3칸 1.8 : 1 : 1.2 — 수집량 추이(선) · 위반 추이(막대) · 설치 검사 결과(도넛 + 판정 · 차단 목록 두 줄)", async ({
    page,
    backend,
  }) => {
    await page.goto("/");
    await ready(page);
    const cards = page.locator(`${DASH} [data-part="charts"] > *`);
    expect(
      await cards.evaluateAll((els) =>
        els.map((e) => [
          (e as HTMLElement).dataset.card,
          e.querySelector("[data-chart]")?.getAttribute("data-chart"),
        ]),
      ),
    ).toEqual([
      ["collected", "collected"],
      ["violations", "violations"],
      ["results", "results"],
    ]);
    const w = await cards.evaluateAll((els) =>
      els.map((e) => e.getBoundingClientRect().width),
    );
    expect(w[0] / w[1]).toBeCloseTo(1.8, 1);
    expect(w[2] / w[1]).toBeCloseTo(1.2, 1);
    // 같은 높이(한 줄) · 패널 제목
    await expect(cards.nth(0).locator("h2")).toHaveText("수집량 추이");
    await expect(cards.nth(1).locator("h2")).toHaveText("위반 추이");
    await expect(cards.nth(2).locator("h2")).toHaveText("설치 검사 결과");
    await expectLineDrawn(page);
    await expect(
      page.locator(
        `${DASH} [data-chart="violations"].stack-bars [data-bucket]`,
      ),
    ).toHaveCount(24);
    // 차트 상자 높이 = --chart-h(900 높이면 240)
    const ch = await page.evaluate(() => {
      const e = document.createElement("i");
      e.style.cssText = "display:block;height:var(--chart-h)";
      document.body.append(e);
      const v = e.getBoundingClientRect().height;
      e.remove();
      return v;
    });
    for (const n of ["collected", "violations"])
      expect(
        (await box(page, `${DASH} [data-chart="${n}"] .chart-box`)).height,
        n,
      ).toBeCloseTo(ch, 0);
    // 결과: 도넛 가운데 = 설치 검사 합, 범례 5줄, 아래 두 줄(판정 · 차단 목록 — 종류별 수는 툴팁)
    const s = backend.summary("24h");
    const res = page.locator(`${DASH} [data-results]`);
    await expect(res.locator('[data-part="donut-center"]')).toHaveText(
      String(
        s.installs.passed +
          s.installs.isolated +
          s.installs.warned +
          s.installs.refused +
          s.installs.failed,
      ),
    );
    expect(
      await res
        .locator("[data-res]")
        .evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.res)),
    ).toEqual(["passed", "isolated", "warned", "refused", "failed"]);
    await expect(res.locator('[data-part="res-decisions"]')).toContainText(
      `악성 ${s.decisions.malicious} · 오탐 ${s.decisions.falsePositive} · 대기 ${s.decisions.pending}`,
    );
    const bl = res.locator('[data-part="res-blocklist"]');
    await expect(bl.locator("[data-blocklist-total]")).toHaveText(
      String(s.blocklist.packages + s.blocklist.images + s.blocklist.hosts),
    );
    await expect(bl).toHaveAttribute(
      "title",
      `패키지 ${s.blocklist.packages} · 이미지 ${s.blocklist.images} · 도메인 ${s.blocklist.hosts}`,
    );
  });

  test("아래 3칸(판정 대기 · 많이 걸린 정책 · 위반 많은 컨테이너) — 남은 높이 채움 · 몸통만 [data-fill] · 「더 보기 ›」", async ({
    page,
    backend,
  }) => {
    void backend;
    await page.goto("/");
    await ready(page);
    const cards = page.locator(`${DASH} [data-part="bottom"] > *`);
    expect(
      await cards.evaluateAll((els) =>
        els.map((e) => (e as HTMLElement).dataset.card),
      ),
    ).toEqual(["pending", "top-rules", "top-containers"]);
    for (let i = 0; i < 3; i++)
      await expect(cards.nth(i).locator("[data-fill]")).toHaveCount(1);
    const more = await page
      .locator(`${DASH} [data-part="bottom"] [data-more]`)
      .evaluateAll((els) =>
        els.map((e) => [e.textContent?.trim(), e.getAttribute("href")]),
      );
    expect(more).toEqual([
      ["설치 검사 ›", "/installs"],
      ["정책 ›", "/policies"],
      ["감사 로그 ›", "/audit"],
    ]);
    // 아래 줄 끝 = 대시보드 끝(남은 높이를 채운다)
    const [b, d] = await Promise.all([
      box(page, `${DASH} [data-part="bottom"]`),
      box(page, DASH),
    ]);
    expect(Math.abs(b.y + b.height - (d.y + d.height))).toBeLessThan(2);
    // 판정 대기 행은 두 단(대상 · 탐지 결과 / 걸린 규칙 · 위반 수 · 시각) + 보고서
    const row = page
      .getByTestId("pending-list")
      .locator('[data-case="case-0004"]');
    await expect(row).toContainText("pip ./reqeusts");
    await expect(row.locator('[data-part="pend-meta"]')).toContainText("위반");
    await expect(
      page
        .getByTestId("pending-list")
        .locator('[data-action="report"]')
        .first(),
    ).toHaveAttribute("href", /\/report\?case=/);
  });
});

test.describe("B 시연 카드 없음", () => {
  test("관리자 + 시연 켜짐이어도 대시보드에 시연 카드가 없다(시연 페이지로 옮김)", async ({
    page,
    backend,
  }) => {
    backend.enableDemo();
    await page.goto("/");
    await ready(page);
    await expect(page.locator('[data-testid="demo"]')).toHaveCount(0);
    await expect(page.getByText("▶ 시연 시작")).toHaveCount(0);
  });
});

test.describe("C KPI 증감 줄(previous)", () => {
  test("수집 감소 · 격리 지연 증가는 경고색(사용자 결정 11/04 — 목업과 같게)", async ({ page, backend }) => {
    const s = backend.summary("24h");
    const iso = s.isolation?.medianMs ?? null;
    backend.summaryPrevious = {
      collected: s.collected.total + 10,
      violations: s.violations.total,
      isolatedContainers: s.isolatedContainers,
      installs: s.installs.total,
      decided: s.decisions.malicious + s.decisions.falsePositive,
      isolationMedianMs: iso != null ? Math.max(0, iso - 50) : null,
    };
    await page.goto("/");
    await ready(page);
    expect(await delta(page, "collected")).toMatchObject({ dir: "down", tone: "warn" });
    if (iso != null && iso > 0) expect(await delta(page, "isolation")).toMatchObject({ dir: "up", tone: "warn" });
  });

  test("위반 · 격리 증가만 빨강 ▲, 그 외 중립 · 「지난 24시간 대비」 · 기간 바꾸면 문구도", async ({
    page,
    backend,
  }) => {
    const s = backend.summary("24h");
    const decided = s.decisions.malicious + s.decisions.falsePositive;
    const prev = {
      collected: s.collected.total - 10,
      violations: Math.max(0, s.violations.total - 2),
      isolatedContainers: s.isolatedContainers + 1,
      installs: s.installs.total,
      decided: decided + 3,
      isolationMedianMs: null,
    };
    backend.summaryPrevious = prev;
    await page.goto("/");
    await ready(page);
    expect(s.violations.total).toBeGreaterThanOrEqual(2);
    expect(await delta(page, "violations")).toEqual({
      dir: "up",
      tone: "danger",
      text: "▲ 2 지난 24시간 대비",
    });
    expect(await delta(page, "collected")).toEqual({
      dir: "up",
      tone: "neutral",
      text: "▲ 10 지난 24시간 대비",
    });
    expect(await delta(page, "isolated")).toEqual({
      dir: "down",
      tone: "neutral",
      text: "▼ 1 지난 24시간 대비",
    });
    expect(await delta(page, "installs")).toEqual({
      dir: "flat",
      tone: "neutral",
      text: "변화 없음 지난 24시간 대비",
    });
    expect(await delta(page, "decided")).toEqual({
      dir: "down",
      tone: "neutral",
      text: "▼ 3 지난 24시간 대비",
    });
    // 빨강은 위험에만: 위반 증감 글자 = --danger, 수집 증감 글자는 아님
    const color = (k: string) =>
      page
        .locator(`${DASH} [data-kpi="${k}"] [data-delta] b`)
        .evaluate((e) => getComputedStyle(e).color);
    const danger = await page.evaluate(() => {
      const e = document.createElement("i");
      e.style.color = "var(--danger)";
      document.body.append(e);
      const v = getComputedStyle(e).color;
      e.remove();
      return v;
    });
    expect(await color("violations")).toBe(danger);
    expect(await color("collected")).not.toBe(danger);
    // 격리한 컨테이너가 늘면 빨강
    backend.summaryPrevious = {
      ...prev,
      isolatedContainers: Math.max(0, s.isolatedContainers - 1),
    };
    await page.reload();
    await ready(page);
    expect(s.isolatedContainers).toBeGreaterThanOrEqual(1);
    expect(await delta(page, "isolated")).toMatchObject({
      dir: "up",
      tone: "danger",
    });
    // 1시간 → 「지난 1시간 대비」
    await page.locator(`${DASH} [data-range="1h"]`).click();
    await expect(
      page.locator(`${DASH} [data-kpi="collected"] [data-delta]`),
    ).toContainText("지난 1시간 대비");
  });

  test("격리 지연: 이전 중앙값과 ms 차이(증가 = 경고색), 이 기간 격리가 없으면 「비교할 격리 없음」", async ({
    page,
    backend,
  }) => {
    const s0 = backend.summary("24h");
    backend.summaryPrevious = {
      collected: 0,
      violations: 0,
      isolatedContainers: 0,
      installs: 0,
      decided: 0,
      isolationMedianMs: 300,
    };
    await page.goto("/");
    await ready(page);
    expect(s0.isolation?.count).toBe(0);
    expect(await delta(page, "isolation")).toEqual({
      dir: "none",
      tone: "neutral",
      text: "비교할 격리 없음",
    });
    backend.enableIsolation();
    await page.reload();
    await ready(page);
    await expect(
      page.locator(`${DASH} [data-kpi="isolation"] [data-value] .kpi-val`),
    ).toHaveText("380");
    await expect(
      page.locator(`${DASH} [data-kpi="isolation"] .kpi-unit`),
    ).toHaveText("ms"); // 단위 분리(13/500)
    expect(await delta(page, "isolation")).toEqual({
      dir: "up",
      tone: "warn", // 11/04 사용자 결정: 격리 지연 증가 = 경고색(목업과 같게)
      text: "▲ 80 ms 지난 24시간 대비",
    });
  });

  test("기본(계산된 previous): 가짜 백엔드도 백엔드와 같은 규칙 — 직전 기간 기록이 있으면 숫자", async ({
    page,
    backend,
  }) => {
    const p = backend.summary("24h").previous;
    expect(p).not.toBeNull();
    await page.goto("/");
    await ready(page);
    expect((await delta(page, "collected")).dir).not.toBe("none");
  });
});

test.describe("D previous 없음", () => {
  test("previous null → 6칸 모두 「이전 기간 정보 없음」(색 없음)", async ({
    page,
    backend,
  }) => {
    backend.enableIsolation();
    backend.summaryPrevious = null;
    await page.goto("/");
    await ready(page);
    for (const k of KPI_IDS)
      expect(await delta(page, k), k).toEqual({
        dir: "none",
        tone: "neutral",
        text: "이전 기간 정보 없음",
      });
  });

  test("옛 백엔드(previous 키 없음)도 같은 문구", async ({ page, backend }) => {
    backend.summaryPrevious = "omit";
    await page.goto("/");
    await ready(page);
    for (const k of KPI_IDS.slice(0, 5))
      expect((await delta(page, k)).text, k).toBe("이전 기간 정보 없음");
  });
});

// ── E 길게 눌러 옮기기 ──
const layout = (page: Page) =>
  page.evaluate(() => localStorage.getItem("supplyguard.layout"));
async function longPressDrag(
  page: Page,
  from: string,
  to: string,
  xFrac = 0.2,
) {
  const a = await box(page, from);
  const b = await box(page, to);
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
  await page.mouse.down();
  await page.waitForTimeout(520);
  await page.mouse.move(b.x + b.width * xFrac, b.y + 4, { steps: 10 });
  await page.mouse.up();
}

test.describe("E KPI 길게 눌러 옮기기(dashboardKpi)", () => {
  test("0.4초 누르면 집힘 → 끌어 놓으면 자리 바뀜 · 이동 없음 · 저장 · 새로고침 유지 · 값 갱신 뒤에도", async ({
    page,
    backend,
  }) => {
    await page.goto("/");
    await ready(page);
    // 짧게 누르면 그냥 이동(링크)
    await page.locator(`${DASH} [data-kpi="violations"]`).click();
    await expect(page).toHaveURL(/\/audit$/);
    await page.goto("/");
    await ready(page);
    await expect(
      page.locator(`${DASH} [data-kpi="collected"]`),
    ).toHaveAttribute("data-sort-scope", "dashboardKpi");
    await longPressDrag(
      page,
      `${DASH} [data-kpi="isolation"]`,
      `${DASH} [data-kpi="collected"]`,
    );
    await expect
      .poll(() => kpiIds(page))
      .toEqual(["isolation", ...KPI_IDS.slice(0, 5)]);
    await expect(page).toHaveURL(/\/$/);
    expect(JSON.parse((await layout(page))!)).toEqual({
      v: 1,
      dashboardKpi: ["isolation", ...KPI_IDS.slice(0, 5)],
    });
    await expect(page.locator("#sg-sort-live")).toHaveText(
      "격리 지연 중앙값을 1번째로 옮김",
    );
    // 키보드 Alt+→ — 포커스 유지
    await page.locator(`${DASH} [data-kpi="isolation"]`).focus();
    await page.keyboard.press("Alt+ArrowRight");
    expect(await kpiIds(page)).toEqual([
      "collected",
      "isolation",
      ...KPI_IDS.slice(1, 5),
    ]);
    await expect(page.locator(`${DASH} [data-kpi="isolation"]`)).toBeFocused();
    // 새로고침 유지
    await page.reload();
    await ready(page);
    expect(await kpiIds(page)).toEqual([
      "collected",
      "isolation",
      ...KPI_IDS.slice(1, 5),
    ]);
    // 새 위반(WS) → 다시 계산돼도 순서 그대로
    const before = backend.summary("24h").violations.total;
    const kv = killedVerdict("api-gw");
    backend.audit.unshift({ ...kv, id: 9999, caseId: null, install: null });
    backend.send({ type: "verdict", data: kv });
    await expect(
      page.locator(`${DASH} [data-kpi="violations"] [data-value]`),
    ).toHaveText(String(before + 1));
    expect(await kpiIds(page)).toEqual([
      "collected",
      "isolation",
      ...KPI_IDS.slice(1, 5),
    ]);
  });
});

test.describe("F 스크롤 없는 대시보드", () => {
  for (const [w, hh] of [
    [1280, 720],
    [1440, 900],
    [1920, 1080],
  ]) {
    test.describe(`${w}×${hh}`, () => {
      test.use({ viewport: { width: w, height: hh } });
      test("문서 · main · 대시보드 틀 스크롤 0, 넘치는 것은 아래 3칸 몸통 안에서만 · 아래 줄 ≥ 120px", async ({
        page,
        backend,
      }) => {
        // 판정 대기가 넘치도록 건을 늘린다
        const base = backend.cases.find((c) => c.state === "open")!;
        for (let i = 0; i < 30; i++)
          backend.cases.push({
            ...base,
            id: `case-9${String(i).padStart(3, "0")}`,
            openedAt: new Date(Date.now() - i * 60000).toISOString(),
          });
        await page.goto("/");
        await ready(page);
        await page.waitForTimeout(300);
        expect(await scrollAudit(page)).toEqual({
          doc: 0,
          docW: 0,
          main: 0,
          dash: 0,
          bad: [],
        });
        const fill = page.getByTestId("pending").locator("[data-fill]");
        expect(
          await fill.evaluate((e) => e.scrollHeight > e.clientHeight),
        ).toBe(true);
        expect(
          (await box(page, `${DASH} [data-part="bottom"]`)).height,
        ).toBeGreaterThanOrEqual(120);
        if (hh <= 800)
          expect(
            (await box(page, `${DASH} [data-chart="collected"] .chart-box`))
              .height,
          ).toBe(120);
        await page.waitForTimeout(900); // 첫 그리기 애니메이션이 끝난 뒤
        await page.screenshot({ path: `${SCRATCH}/r2-dashboard-${w}.png` });
      });
    });
  }
});

test.describe("G 다크", () => {
  test("카드 · 패널 바탕 = 다크 surface, 스크롤 0", async ({
    page,
    backend,
  }) => {
    void backend;
    await page.addInitScript(() =>
      localStorage.setItem("supplyguard.theme", "dark"),
    );
    await page.goto("/");
    await ready(page);
    const bg = (sel: string) =>
      page
        .locator(sel)
        .first()
        .evaluate((e) => getComputedStyle(e).backgroundColor);
    for (const sel of [
      `${DASH} [data-kpi]`,
      `${DASH} [data-card="collected"] > .sg-panel`,
      `${DASH} [data-card="results"] > .sg-panel`,
      `${DASH} [data-card="top-rules"] > .sg-panel`,
      `${DASH} [data-card="pending"] > .sg-panel`,
    ])
      expect(await bg(sel), sel).toBe(rgb("#15202B")); // 11/09 밤 남색: 카드 = 바탕 하나
    expect(await scrollAudit(page)).toMatchObject({
      doc: 0,
      main: 0,
      dash: 0,
      bad: [],
    });
    await page.waitForTimeout(900);
    await page.screenshot({ path: `${SCRATCH}/r2-dashboard-dark.png` });
  });
});

test.describe("H 390", () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test("가로 넘침 0 · KPI 2열 · 차트 · 아래 칸 1열 · 시연 카드 없음", async ({
    page,
    backend,
  }) => {
    backend.enableDemo();
    await page.goto("/");
    await ready(page);
    const r = await scrollAudit(page);
    expect(r.docW).toBe(0);
    expect(
      await page
        .locator(`${DASH} [data-part="kpis"]`)
        .evaluate(
          (e) => getComputedStyle(e).gridTemplateColumns.split(" ").length,
        ),
    ).toBe(2);
    for (const p of ["charts", "bottom"]) {
      const xs = await page
        .locator(`${DASH} [data-part="${p}"] > *`)
        .evaluateAll((els) =>
          els.map((e) => Math.round(e.getBoundingClientRect().left)),
        );
      expect(new Set(xs).size, p).toBe(1);
    }
    await expect(page.locator('[data-testid="demo"]')).toHaveCount(0);
    // 아래 칸까지 닿는다(화면 안 칸 스크롤 · 문서 스크롤)
    await page
      .locator(`${DASH} [data-card="top-containers"]`)
      .scrollIntoViewIfNeeded();
    await expect(
      page.locator(`${DASH} [data-card="top-containers"]`),
    ).toBeInViewport();
    await page.locator(DASH).evaluate((e) => e.scrollTo(0, 0));
    await page.screenshot({ path: `${SCRATCH}/r2-dashboard-390.png` });
  });
});

// 11/06 CI(PR #4, 23:59 UTC)에서 수집량 선이 「hidden」 — 가짜 exec 는 시간당 180 고정이라 매시 59분엔 모든 칸이 같아
// 선 높이가 0 이 되고 Playwright 가 보이지 않는다고 본다. 지금 시간 칸도 180 으로 채워 그 순간을 매번 만든다
test.describe("C 수집량 선 — 모든 칸이 같은 값이어도 그려진다(11/06)", () => {
  test("exec 가 24칸 모두 같을 때도 선 path 가 있고 점 24개", async ({ page, backend }) => {
    const H = 60;
    const m0 = Math.max(...backend.collected.map((c) => c.minute));
    const hourStart = Math.floor(m0 / H) * H;
    const sum = backend.collected.filter((c) => c.minute >= hourStart).reduce((n, c) => n + c.exec, 0);
    backend.collected.push({ minute: m0, exec: 180 - sum, open: 0, connect: 0 });
    await page.goto("/");
    await ready(page);
    await expectLineDrawn(page);
  });
});
// 선이 그려졌는지 — 「보임」은 모든 점이 같은 높이면(높이 0 상자) 실패하므로 차트 SVG 가 보이고 path 의 점이 24개인지 본다
async function expectLineDrawn(page: Page) {
  await expect(page.locator(`${DASH} [data-chart="collected"].line-chart`)).toBeVisible();
  const line = page.locator(`${DASH} [data-chart="collected"].line-chart path[data-kind]`).first();
  await expect(line).toBeAttached();
  expect(((await line.getAttribute("d")) ?? "").match(/[ML]/g)?.length).toBe(24);
}
