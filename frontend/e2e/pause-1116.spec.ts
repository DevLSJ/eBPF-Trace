import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 11/16 격리 순서 「정지(Docker pause) → 증거 수집 → 격리(kill)」(사용자 결정 「먼저 멈추고 증거 수집」).
// 타임라인에 pausedAt 이 있으면 막대 · 시연 단계에 「정지」가 보이고, 없으면(옛 기록 · pause 실패) 예전 모양 그대로.
// 격리 지연(탐지 → 격리)의 정의 · 문구는 그대로, 탐지 → 정지는 보조로 작게만.
// 가짜 백엔드 시각(탐지 기준 ms): 탐지 0 · 판정 12 · 정지 20 · 증거 15~310 · 격리 420 · 알림 431(설치 쪽은 알림 없음)

const SEGS = (page: Page, root: string) =>
  page.locator(`${root} [data-testid="timeline-bar"] [data-seg]`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.seg));

test.describe('격리 타임라인 정지 단계(11/16)', () => {
  test('설치 시트 · 건 보고서: pausedAt 이 있으면 「정지」 구간 + 「정지까지」 보조 표기, 격리까지 합계는 그대로', async ({ page, backend }) => {
    backend.enableIsolation({ pauseMs: 20 });
    await page.goto('/installs?id=ins-0012');
    const root = '[data-sheet="install"]';
    const bar = page.locator(`${root} [data-testid="timeline-bar"]`);
    await expect(bar).toBeVisible();
    expect(await SEGS(page, root)).toEqual(['detect', 'pause', 'evidence', 'kill', 'notify']);
    await expect(bar.locator('[data-seg="pause"]')).toHaveText('정지 8 ms'); // 판정(12) → 정지(20)
    await expect(bar.locator('[data-seg="evidence"]')).toContainText('295 ms');
    await expect(bar.locator('[data-seg="kill"]')).toContainText('110 ms'); // 증거 끝(310) → 격리(420)
    await expect(bar.locator('[data-seg-bar="pause"]')).toHaveCount(1);
    await expect(bar.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    await expect(bar.locator('[data-part="timeline-pause-total"]')).toHaveText('정지까지 0.02초');
    await page.screenshot({ path: `${SHOTS}/1116-timeline-pause.png` });

    // 건 보고서도 같은 부품
    await page.goto('/report?install=ins-0012');
    const rep = page.getByTestId('report');
    await expect(rep.locator('[data-section="timeline"] [data-part="timeline-total"]')).toHaveText('격리까지 0.42초');
    expect(await SEGS(page, '[data-testid="report"] [data-section="timeline"]')).toEqual(['detect', 'pause', 'evidence', 'kill', 'notify']);
    await expect(rep.locator('[data-section="timeline"] [data-part="timeline-pause-total"]')).toHaveText('정지까지 0.02초');
  });

  test('pausedAt 이 없는 옛 기록: 구간 4개 · 정지 표기 없음(토폴로지 판정 카드 · 런타임 건 보고서)', async ({ page, backend }) => {
    backend.enableIsolation({ pauseMs: 20 }); // 설치 쪽만 정지 시각, 런타임 건(case-0005)은 옛 모양
    await page.goto('/topology?node=c%3Apkg-reqeusts');
    const root = '[data-testid="topology-decision"]';
    await expect(page.locator(`${root} [data-testid="timeline-bar"]`)).toBeVisible();
    expect(await SEGS(page, root)).toEqual(['detect', 'evidence', 'kill', 'notify']);
    await expect(page.locator(`${root} [data-part="timeline-pause-total"]`)).toHaveCount(0);
    await expect(page.locator(`${root} [data-part="timeline-total"]`)).toHaveText('격리까지 0.38초');
    await page.goto('/report?case=case-0005');
    const tl = page.getByTestId('report').locator('[data-section="timeline"]');
    await expect(tl.locator('[data-part="timeline-total"]')).toHaveText('격리까지 0.38초');
    await expect(tl.locator('[data-seg]')).toHaveCount(4);
    await expect(tl.locator('[data-part="timeline-pause-total"]')).toHaveCount(0);
  });

  test('시연 실시간 단계: 정책 탐지 다음에 「정지」 단계, 증거는 정지 상태에서 · 흐름 그림 노드는 5개 그대로', async ({ page, backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 300;
    backend.demoPauseMs = 20;
    await page.goto('/demo');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await page.locator('[data-part="demo-page"]').getByRole('button', { name: '시연 시작' }).click();
    const out = page.locator('[data-part="demo-outcome"]');
    await expect(out).toHaveAttribute('data-outcome', 'isolated', { timeout: 10_000 });
    const steps = page.locator('[data-part="demo-steps"] > li[data-step]');
    expect(await steps.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.step))).toEqual(['start', 'events', 'match', 'pause', 'evidence', 'outcome']);
    const pause = page.locator('[data-part="demo-steps"] [data-step="pause"]');
    await expect(pause).toHaveAttribute('data-state', 'done');
    await expect(pause.locator('.flow-head b')).toHaveText('정지');
    await expect(pause.locator('.flow-body')).toHaveText('[정지] 증거 수집 전 실행 멈춤 · 탐지→정지 20 ms');
    await expect(page.locator('[data-part="demo-steps"] [data-step="evidence"] .flow-body')).toHaveText('정지 상태에서 로그 · 파일 변경 · 프로세스 보존됨(295 ms)');
    await expect(out).toContainText('[격리] pipe-to-shell 위반 · 탐지→kill 420 ms'); // 격리 지연 문구 그대로
    await page.screenshot({ path: `${SHOTS}/1116-demo-pause.png` });
    // 흐름 그림: 노드는 그대로 5개, 증거 노드 문구만 정지 뒤 수집으로
    await page.locator('[data-part="why-tabs"] [role="tab"][data-tab="flow"]').click();
    const flow = page.locator('[data-part="demo-flow"]');
    expect(await flow.locator('[data-node]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.node))).toEqual(['start', 'events', 'match', 'evidence', 'outcome']);
    await expect(flow.locator('[data-node="evidence"] .flow-sub')).toHaveText('정지 후 295 ms');
    await expect(flow.locator('[data-node="evidence"]')).toHaveAttribute('data-state', 'done');
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-state', 'on');
  });

  test('시연 1920×1080: 정지 단계가 더해져도 한 화면(문서 · 안쪽 스크롤 없음)', async ({ page, backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 200;
    backend.demoPauseMs = 20;
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto('/demo');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await page.locator('[data-part="demo-page"]').getByRole('button', { name: '시연 시작' }).click();
    await expect(page.locator('[data-part="demo-outcome"]')).toHaveAttribute('data-outcome', 'isolated', { timeout: 10_000 });
    await expect(page.locator('[data-part="demo-steps"] [data-step="pause"]')).toHaveAttribute('data-state', 'done');
    await expect(page.locator('[data-part="why"] [data-ev]')).toHaveCount(3);
    const r = await page.evaluate(() => ({
      doc: document.scrollingElement!.scrollHeight - innerHeight,
      inner: [...document.querySelectorAll('[data-part="demo-page"] *')]
        .filter((e) => /(auto|scroll)/.test(getComputedStyle(e).overflowY) && e.scrollHeight > e.clientHeight + 1)
        .map((e) => String(e.className)),
    }));
    expect(r).toEqual({ doc: 0, inner: [] });
    await page.screenshot({ path: `${SHOTS}/1116-demo-pause-1920.png` });
  });

  test('시연(정지 시각 없음): 단계 5개 그대로', async ({ page, backend }) => {
    backend.enableDemo();
    backend.demoStepMs = 300;
    await page.goto('/demo');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    await page.locator('[data-part="demo-page"]').getByRole('button', { name: '시연 시작' }).click();
    await expect(page.locator('[data-part="demo-outcome"]')).toHaveAttribute('data-outcome', 'isolated', { timeout: 10_000 });
    const steps = page.locator('[data-part="demo-steps"] > li[data-step]');
    expect(await steps.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.step))).toEqual(['start', 'events', 'match', 'evidence', 'outcome']);
    await expect(page.locator('[data-part="demo-steps"] [data-step="evidence"] .flow-body')).toHaveText('로그 · 파일 변경 · 프로세스 보존됨(295 ms)');
  });
});
