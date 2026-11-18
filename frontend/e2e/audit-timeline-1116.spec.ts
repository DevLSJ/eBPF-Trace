import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 11/16 감사 기록 상세 「상세」 탭의 격리 타임라인 — 설치 시트 · 건 보고서와 같은 부품(components/TimelineBar).
// 격리 단계 시각(정지 · 증거 · 격리)이 있는 기록만 「격리 타임라인」 칸이 생기고, 없으면 칸 자체가 없다(빈 자리 · 「—」 없음).
// 이미 끝난 컨테이너(pause 「not running」)는 증거 시각만 있는 막대 + 격리 오류 사유(격리 아님).
// 가짜 백엔드 시각(탐지 기준 ms): 설치 쪽 탐지 0 · 판정 12 · 정지 20 · 증거 15~310 · 격리 420(알림 없음), 런타임 쪽 격리 380 · 알림 390

const ROOT = '[data-sheet="audit"]';
const SEGS = (page: Page) =>
  page.locator(`${ROOT} [data-testid="audit-timeline"] [data-seg]`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.seg));

test.describe('감사 상세 격리 타임라인(11/16)', () => {
  test('격리된 기록: 정지가 있으면 「정지」 구간 + 정지까지, 옛 기록은 구간 4개 · 격리까지 합계', async ({ page, backend }) => {
    backend.enableIsolation({ pauseMs: 20 });
    const paused = backend.audit.find((a) => a.timeline?.pausedAt)!;
    const old = backend.audit.find((a) => a.caseId === 'case-0005' && a.timeline)!;

    await page.goto(`/audit?id=${paused.id}`);
    const sec = page.locator(`${ROOT} [data-testid="audit-timeline"]`);
    await expect(sec).toBeVisible();
    await expect(sec.locator('h3')).toHaveText('격리 타임라인');
    expect(await SEGS(page)).toEqual(['detect', 'pause', 'evidence', 'kill', 'notify']);
    await expect(sec.locator('[data-seg="pause"]')).toHaveText('정지 8 ms');
    await expect(sec.locator('[data-seg="kill"]')).toContainText('110 ms');
    await expect(sec.locator('[data-part="timeline-pause-total"]')).toHaveText('정지까지 0.02초');
    await expect(sec.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    // 위반 칸 다음, 정책 시작점 앞
    const order = await page.locator(`${ROOT} section h3`).allTextContents();
    expect(order.indexOf('격리 타임라인')).toBe(order.indexOf('위반') + 1);
    await expect(page.locator(ROOT)).not.toContainText('—');
    await page.screenshot({ path: `${SHOTS}/1116-audit-timeline.png` });

    await page.goto(`/audit?id=${old.id}`);
    await expect(sec).toBeVisible();
    expect(await SEGS(page)).toEqual(['detect', 'evidence', 'kill', 'notify']);
    await expect(sec.locator('[data-part="timeline-pause-total"]')).toHaveCount(0);
    await expect(sec.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.38초');
  });

  test('이미 끝난 컨테이너: 증거 시각만 있는 막대 + 격리 오류 사유, 정지 · 격리 구간 값 없음', async ({ page, backend }) => {
    const id = backend.exitedBeforeKill();
    await page.goto(`/audit?id=${id}`);
    const sec = page.locator(`${ROOT} [data-testid="audit-timeline"]`);
    await expect(sec).toBeVisible();
    expect(await SEGS(page)).toEqual(['detect', 'evidence', 'kill', 'notify']);
    await expect(sec.locator('[data-seg="evidence"]')).toHaveText('증거 82 ms'); // 14 → 96
    await expect(sec.locator('[data-seg="kill"]')).toHaveText(/^격리\s*$/);
    await expect(sec.locator('[data-seg-bar]')).toHaveCount(2); // 탐지 · 증거만 막대
    await expect(sec.locator('[data-part="timeline-pause-total"]')).toHaveCount(0);
    await expect(sec.locator('[data-part="timeline-total"]')).toHaveCount(0); // 값 없는 「격리까지」 글자를 남기지 않는다
    await expect(page.locator(ROOT).getByText('container is not running')).toBeVisible();
    await expect(page.locator(ROOT)).not.toContainText('—');
    await page.screenshot({ path: `${SHOTS}/1116-audit-timeline-exited.png` });
  });

  test('타임라인 없는 기록: 옛 격리 기록 · 탐지 시각만 있는 경고는 칸 자체가 없음', async ({ page, backend }) => {
    const killed = backend.audit.find((a) => a.action === 'kill' && a.enforced && !a.timeline)!;
    const warned = backend.audit.find((a) => a.action === 'alert')!;
    // 실제 백엔드는 경고 판정에도 탐지 · 판정 시각을 붙인다 — 격리 단계가 없으면 막대를 그리지 않는다
    warned.timeline = { detectedAt: warned.event.timestamp, matchedAt: new Date(Date.parse(warned.event.timestamp) + 12).toISOString() };
    for (const a of [killed, warned]) {
      await page.goto(`/audit?id=${a.id}`);
      await expect(page.locator(`${ROOT} [data-testid="audit-reason"]`)).toBeVisible();
      await expect(page.locator(`${ROOT} [data-testid="audit-timeline"]`)).toHaveCount(0);
      await expect(page.locator(`${ROOT} [data-testid="timeline-bar"]`)).toHaveCount(0);
      await expect(page.locator(ROOT)).not.toContainText('격리 타임라인');
      await expect(page.locator(ROOT)).not.toContainText('—');
    }
  });
});
