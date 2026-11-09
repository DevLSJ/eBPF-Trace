import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 11/09 시연 화면(사용자 11/06 결정): 「한눈에 3줄 + 묶음 접기 + 상세 탭(흐름 그림 자동 재생, 실행 중엔 실제 단계에 맞춰 켜짐)」
//   한눈에 3줄 = 무엇을 · 잡는 규칙 · 예상 결과(격리 / 통과), 시나리오 열 위쪽(data-part="scenario-desc")
//   묶음 = 공격 재현(all · shell · revshell) · 네트워크 · DNS(direct-ip · domain · dns-exfil) · 대조군 · 연쇄(benign · chain), 접힘은 localStorage supplyguard.demo.folded,
//          고른 시나리오가 든 묶음은 늘 펼침
//   상세 탭 = 「판정 근거」(기본 — 기존 「왜」 카드 그대로) · 「흐름 그림」(FlowHero 세로 — 대기 중 자동 재생, 실행 중 실제 단계, 끝나면 결과 톤에서 멈춤, 움직임 줄이기면 정지)
// 기존 시연 회귀(r3-demo-page · demo-1030)는 그대로 둔다 — 기본 탭이 「판정 근거」라 그 선택자는 바뀌지 않는다.

const SHOT = `${SHOTS}/demo-1109`;
const PAGE = '[data-part="demo-page"]';
const BRIEF = '[data-part="scenario-desc"]';
const FLOW = '[data-part="demo-flow"]';
const FLOW_TAB = '[data-part="demo-flow-tab"]';
const FOLD_KEY = 'supplyguard.demo.folded';
const NODES = ['start', 'events', 'match', 'evidence', 'outcome'];
// 실시간 단계(data-state) → 흐름 그림 노드(data-state)
const MAP: Record<string, string> = { done: 'done', active: 'on', todo: 'off', skip: 'skip' };

async function goDemo(page: Page) {
  await page.goto('/demo');
  await expect(page.locator(PAGE)).toBeVisible();
  if ((page.viewportSize()?.width ?? 1440) >= 768) await expect(page.getByText('실시간 연결됨')).toBeVisible();
  else await page.waitForTimeout(400);
}
const tab = (page: Page, k: 'why' | 'flow') => page.locator(`[data-part="why-tabs"] [role="tab"][data-tab="${k}"]`);
const outcome = (page: Page) => page.locator('[data-part="demo-outcome"]');
const waitDone = (page: Page) => expect(outcome(page)).toHaveAttribute('data-outcome', /^(?!running$).+/, { timeout: 10_000 });
const group = (page: Page, g: string) => page.locator(`[data-group="${g}"]`);
const foldBtn = (page: Page, g: string) => group(page, g).locator('[data-action="fold-group"]');
// 실시간 단계와 흐름 그림 노드 상태를 한 번에 읽는다(사이에 다시 그려지지 않게)
const bothStates = (page: Page) =>
  page.evaluate(() => ({
    steps: [...document.querySelectorAll('[data-part="demo-steps"] > li[data-step]')].map((e) => (e as HTMLElement).dataset.state ?? ''),
    nodes: [...document.querySelectorAll('[data-part="demo-flow"] [data-node]')].map((e) => (e as HTMLElement).dataset.state ?? ''),
    mode: (document.querySelector('[data-part="demo-flow-tab"]') as HTMLElement | null)?.dataset.mode ?? '',
  }));
const probe = (page: Page, v: string) =>
  page.evaluate((name) => {
    const e = document.createElement('i');
    e.style.borderColor = `var(${name})`;
    e.style.borderStyle = 'solid';
    document.body.append(e);
    const out = getComputedStyle(e).borderTopColor;
    e.remove();
    return out;
  }, v);

test.describe('11/09 시연 — 한눈에 3줄', () => {
  test.beforeEach(({ backend }) => {
    backend.enableDemo();
  });

  test('고른 시나리오의 무엇을 · 잡는 규칙 · 예상 결과 3줄 — 시나리오 열 맨 위, 고르면 바뀜, 개조식 명사형 종결', async ({ page }) => {
    await goDemo(page);
    const brief = page.locator(BRIEF);
    await expect(brief).toBeVisible();
    const rows = brief.locator('[data-brief]');
    await expect(rows).toHaveCount(3);
    expect(await rows.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.brief))).toEqual(['what', 'rule', 'result']);
    expect(await brief.locator('dt').allTextContents()).toEqual(['무엇을', '잡는 규칙', '예상 결과']);
    // 열 맨 위 — 묶음 목록보다 위
    const [b, g] = await Promise.all([brief.boundingBox(), page.locator('[data-part="scn-groups"]').boundingBox()]);
    expect(b!.y).toBeLessThan(g!.y);
    // 기본 shell
    await expect(brief.locator('[data-brief="what"]')).toContainText('/etc/shadow');
    await expect(brief.locator('[data-brief="rule"]')).toContainText('pipe-to-shell');
    const exp = brief.locator('[data-part="brief-expect"]');
    await expect(exp).toHaveAttribute('data-expect', 'isolated');
    await expect(exp).toHaveText('격리');
    // 대조군 → 통과
    await page.locator('[data-scenario="benign"]').click();
    await expect(exp).toHaveAttribute('data-expect', 'passed');
    await expect(exp).toHaveText('통과');
    await expect(brief.locator('[data-brief="rule"]')).toContainText('걸리는 규칙 없음');
    // 연쇄 → 1단계 no-shell-download · dryRun
    await page.locator('[data-scenario="chain"]').click();
    await expect(brief.locator('[data-brief="rule"]')).toContainText('no-shell-download');
    await expect(brief.locator('[data-brief="rule"]')).toContainText('dryRun');
    await expect(brief.locator('[data-brief="result"]')).toContainText('1/3');
    // 8개 모두: 「무엇을」 줄은 「~함 / ~됨」으로 끝나고, 예상 결과 배지는 시나리오 단추의 예상과 같다
    for (const k of ['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil', 'benign', 'chain']) {
      await page.locator(`[data-scenario="${k}"]`).click();
      await expect(brief.locator('[data-brief="what"] dd')).toHaveText(/[함됨]$/);
      const want = await page.locator(`[data-scenario="${k}"] [data-part="expect"]`).getAttribute('data-expect');
      await expect(exp).toHaveAttribute('data-expect', want!);
    }
  });
});

test.describe('11/09 시연 — 묶음 접기', () => {
  test.beforeEach(({ backend }) => {
    backend.enableDemo();
  });

  test('묶음 3개(성격별) · 기본 모두 펼침 · 접으면 숨김 + 저장 · 새로 고침 뒤 유지 · 다시 펼침', async ({ page }) => {
    await goDemo(page);
    const groups = page.locator('[data-part="scn-groups"] [data-group]');
    expect(await groups.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.group))).toEqual(['attack', 'network', 'control']);
    expect(await page.locator('[data-part="scn-groups"] .scn-group-name').allTextContents()).toEqual(['공격 재현', '네트워크 · DNS', '대조군 · 연쇄']);
    const keysOf = (g: string) => group(page, g).locator('[data-scenario]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.scenario));
    expect(await keysOf('attack')).toEqual(['all', 'shell', 'revshell']);
    expect(await keysOf('network')).toEqual(['direct-ip', 'domain', 'dns-exfil']);
    expect(await keysOf('control')).toEqual(['benign', 'chain']);
    for (const g of ['attack', 'network', 'control']) await expect(foldBtn(page, g)).toHaveAttribute('aria-expanded', 'true');
    // 접기
    await foldBtn(page, 'network').click();
    await expect(foldBtn(page, 'network')).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('[data-scenario="direct-ip"]')).toBeHidden();
    await expect(page.locator('[data-scenario="dns-exfil"]')).toBeHidden();
    await expect(group(page, 'network')).toContainText('펼치기');
    // 접혀도 단추 순서(백엔드 순서)는 DOM 에 그대로 8개
    expect(await page.locator('[data-scenario]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.scenario))).toEqual([
      'all',
      'shell',
      'revshell',
      'direct-ip',
      'domain',
      'dns-exfil',
      'benign',
      'chain',
    ]);
    expect(JSON.parse((await page.evaluate((k) => localStorage.getItem(k), FOLD_KEY))!)).toEqual(['network']);
    await foldBtn(page, 'control').click();
    await expect(page.locator('[data-scenario="benign"]')).toBeHidden();
    expect(JSON.parse((await page.evaluate((k) => localStorage.getItem(k), FOLD_KEY))!).sort()).toEqual(['control', 'network']);
    // 새로 고침 뒤에도 접힘 유지
    await page.reload();
    await expect(page.locator(PAGE)).toBeVisible();
    await expect(foldBtn(page, 'network')).toHaveAttribute('aria-expanded', 'false');
    await expect(foldBtn(page, 'control')).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('[data-scenario="domain"]')).toBeHidden();
    await expect(page.locator('[data-scenario="shell"]')).toBeVisible();
    // 다시 펼침
    await foldBtn(page, 'network').click();
    await expect(foldBtn(page, 'network')).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('[data-scenario="domain"]')).toBeVisible();
    expect(JSON.parse((await page.evaluate((k) => localStorage.getItem(k), FOLD_KEY))!)).toEqual(['control']);
  });

  test('고른 시나리오가 든 묶음은 늘 펼침 — 저장값이 접힘이어도 펼치고, 접기 단추는 「선택 중」으로 잠김', async ({ page }) => {
    await page.addInitScript((k) => {
      if (!sessionStorage.getItem('seeded')) {
        localStorage.setItem(k, JSON.stringify(['attack']));
        sessionStorage.setItem('seeded', '1');
      }
    }, FOLD_KEY);
    await goDemo(page);
    // 기본 선택 shell 이 든 공격 재현 — 저장은 접힘이지만 펼쳐 보인다
    await expect(page.locator('[data-scenario="shell"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(foldBtn(page, 'attack')).toHaveAttribute('aria-expanded', 'true');
    await expect(foldBtn(page, 'attack')).toHaveAttribute('aria-disabled', 'true');
    await expect(group(page, 'attack')).toContainText('선택 중');
    await expect(page.locator('[data-scenario="revshell"]')).toBeVisible();
    // 눌러도 접히지 않는다(aria-disabled — 강제로 눌러 본다)
    await foldBtn(page, 'attack').click({ force: true });
    await expect(foldBtn(page, 'attack')).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('[data-scenario="shell"]')).toBeVisible();
    // 다른 묶음에서 고르면 저장값(접힘)대로 돌아간다 · 새 묶음은 펼침 + 잠김
    await page.locator('[data-scenario="benign"]').click();
    await expect(foldBtn(page, 'attack')).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('[data-scenario="shell"]')).toBeHidden();
    await expect(foldBtn(page, 'control')).toHaveAttribute('aria-disabled', 'true');
    await foldBtn(page, 'control').click({ force: true });
    await expect(page.locator('[data-scenario="benign"]')).toBeVisible();
    // 저장값이 깨져 있으면 기본(모두 펼침) — 콘솔 오류 없음(fixtures 가 확인)
    await page.evaluate((k) => localStorage.setItem(k, '{깨짐'), FOLD_KEY);
    await page.reload();
    await expect(page.locator(PAGE)).toBeVisible();
    for (const g of ['attack', 'network', 'control']) await expect(foldBtn(page, g)).toHaveAttribute('aria-expanded', 'true');
  });
});

test.describe('11/09 시연 — 상세 탭 · 흐름 그림', () => {
  test.beforeEach(({ backend }) => {
    backend.enableDemo();
  });

  test('탭: 「판정 근거」(기본 — 기존 「왜」 카드) · 「흐름 그림」 전환, 패널 제목 그대로, 화살표 키로도 전환', async ({ page }) => {
    await goDemo(page);
    const tabs = page.locator('[data-part="why-tabs"] [role="tab"]');
    expect(await tabs.allTextContents()).toEqual(['판정 근거', '흐름 그림']);
    await expect(tab(page, 'why')).toHaveAttribute('aria-selected', 'true');
    await expect(tab(page, 'flow')).toHaveAttribute('aria-selected', 'false');
    await expect(page.locator('[data-part="why"]')).toBeVisible();
    await expect(page.locator('[data-part="why"] [data-why="what"]')).toBeVisible();
    await expect(page.locator(FLOW)).toHaveCount(0);
    await tab(page, 'flow').click();
    await expect(tab(page, 'flow')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator(FLOW)).toBeVisible();
    await expect(page.locator('[data-part="why"]')).toBeHidden();
    await expect(page.locator('[data-col="why"] h2')).toHaveText('왜');
    // 화살표 키
    await tab(page, 'flow').focus();
    await page.keyboard.press('ArrowLeft');
    await expect(tab(page, 'why')).toHaveAttribute('aria-selected', 'true');
    await expect(tab(page, 'why')).toBeFocused();
    await expect(page.locator('[data-part="why"]')).toBeVisible();
    await page.keyboard.press('ArrowRight');
    await expect(tab(page, 'flow')).toHaveAttribute('aria-selected', 'true');
    // 다른 화면에 다녀와도 고른 탭 유지
    await page.locator('aside[data-part="sidebar"] nav a[href="/"]').click();
    await page.locator('aside[data-part="sidebar"] nav a[href="/demo"]').click();
    await expect(tab(page, 'flow')).toHaveAttribute('aria-selected', 'true');
  });

  test('대기 중: 5단계 세로 흐름 자동 재생(켜지는 단계가 바뀜) · 고른 시나리오의 예상 경로 · 대조군은 증거 건너뜀 + 통과 정상 톤', async ({ page }) => {
    await goDemo(page);
    await tab(page, 'flow').click();
    const flow = page.locator(FLOW);
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-mode', 'idle');
    await expect(flow).toHaveAttribute('data-playing', 'true');
    expect(await flow.locator('[data-node]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.node))).toEqual(NODES);
    expect(await flow.locator('.flow-title').allTextContents()).toEqual(['설치 시작', '커널 이벤트', '규칙 판정', '증거 수집', '격리']);
    await expect(flow.locator('[data-node="match"] .flow-sub')).toContainText('pipe-to-shell');
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-tone', 'danger');
    // 세로 배치
    const ys = await flow.locator('[data-node]').evaluateAll((els) => els.map((e) => Math.round(e.getBoundingClientRect().top)));
    for (let i = 1; i < ys.length; i++) expect(ys[i]).toBeGreaterThan(ys[i - 1]);
    // 자동 재생 — 켜진 단계가 바뀐다
    const seen = new Set<string>();
    await expect
      .poll(
        async () => {
          seen.add((await flow.getAttribute('data-step'))!);
          return seen.size;
        },
        { timeout: 8000, intervals: [300] },
      )
      .toBeGreaterThanOrEqual(3);
    await expect(flow.locator('[data-state="on"]')).toHaveCount(1);
    await expect(page.locator('[data-part="demo-flow-point"]')).toHaveText(/됨$/);
    // 대조군: 증거 수집 건너뜀 · 결과 「통과」 정상 톤
    await page.locator('[data-scenario="benign"]').click();
    await expect(flow.locator('[data-node="outcome"] .flow-title')).toHaveText('통과');
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-tone', 'ok');
    await expect(flow.locator('[data-node="evidence"] .flow-sub')).toContainText('건너뜀');
    await expect(flow).toHaveAttribute('data-playing', 'true');
  });

  test('실행 중: 자동 재생 멈춤 · 실시간 단계와 같은 단계가 켜짐 → 끝나면 결과(격리 = 위험 톤)에서 멈춤 · 시나리오를 고르면 다시 대기', async ({ page, backend }) => {
    backend.demoStepMs = 900;
    await goDemo(page);
    await tab(page, 'flow').click();
    await page.locator('[data-scenario="shell"]').click();
    await page.locator('[data-action="demo-run"]').click();
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-mode', 'live');
    await expect(page.locator(FLOW)).toHaveAttribute('data-playing', 'false');
    // 실행 중 표본 — 노드 상태 = 실시간 단계 상태(같은 순간)
    let live = 0;
    for (let i = 0; i < 12; i++) {
      const s = await bothStates(page);
      if (s.mode !== 'live') break;
      expect(s.nodes, `표본 ${i}`).toEqual(s.steps.map((x) => MAP[x]));
      live++;
      await page.waitForTimeout(250);
    }
    expect(live).toBeGreaterThanOrEqual(2);
    await waitDone(page);
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-mode', 'done');
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-outcome', 'isolated');
    const flow = page.locator(FLOW);
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-state', 'on');
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-tone', 'danger');
    await expect(flow.locator('[data-node="outcome"] .flow-title')).toHaveText('격리');
    for (const k of ['start', 'events', 'match', 'evidence']) await expect(flow.locator(`[data-node="${k}"]`)).toHaveAttribute('data-state', 'done');
    await expect(flow.locator('[data-node="match"] .flow-sub')).toContainText('pipe-to-shell');
    await expect(flow).toHaveAttribute('data-playing', 'false');
    // 결과 톤 = 위험 토큰
    const danger = await probe(page, '--danger');
    expect(await flow.locator('[data-node="outcome"]').evaluate((e) => getComputedStyle(e).borderTopColor)).toBe(danger);
    // 멈춤 — 시간이 지나도 그대로
    await page.waitForTimeout(1800);
    await expect(flow).toHaveAttribute('data-step', '4');
    // 판정 근거로 바로 가기
    await page.locator('[data-action="show-why"]').click();
    await expect(tab(page, 'why')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('[data-part="why-rule"]')).toHaveText('pipe-to-shell');
    // 시나리오를 다시 고르면 대기(자동 재생)로
    await tab(page, 'flow').click();
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-mode', 'done');
    await page.locator('[data-scenario="revshell"]').click();
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-mode', 'idle');
    await expect(page.locator(FLOW)).toHaveAttribute('data-playing', 'true');
  });

  test('대조군 실행: 증거 단계 건너뜀(skip) · 끝나면 「통과」 정상 톤에서 멈춤', async ({ page, backend }) => {
    backend.demoStepMs = 300;
    await goDemo(page);
    await tab(page, 'flow').click();
    await page.locator('[data-scenario="benign"]').click();
    await page.locator('[data-action="demo-run"]').click();
    await waitDone(page);
    const flow = page.locator(FLOW);
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-outcome', 'passed');
    await expect(flow.locator('[data-node="evidence"]')).toHaveAttribute('data-state', 'skip');
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-state', 'on');
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-tone', 'ok');
    await expect(flow.locator('[data-node="outcome"] .flow-title')).toHaveText('통과');
    const ok = await probe(page, '--ok');
    expect(await flow.locator('[data-node="outcome"]').evaluate((e) => getComputedStyle(e).borderTopColor)).toBe(ok);
  });

  test('움직임 줄이기: 자동 재생 · 흐르는 점 없이 정지 그림, 실행하면 실제 단계만 정적으로 켬', async ({ page, backend }) => {
    backend.demoStepMs = 600;
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await goDemo(page);
    await tab(page, 'flow').click();
    const flow = page.locator(FLOW);
    await expect(flow).toHaveAttribute('data-playing', 'false');
    await expect(flow).toHaveClass(/still/);
    const step0 = await flow.getAttribute('data-step');
    expect(await flow.locator('[data-node]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.state))).not.toContain('off');
    await page.waitForTimeout(2200);
    await expect(flow).toHaveAttribute('data-step', step0!);
    await expect(flow.locator('.flow-particle')).toHaveCount(0);
    expect(await flow.locator('[data-node]').evaluateAll((els) => els.map((e) => getComputedStyle(e).animationName))).toEqual(NODES.map(() => 'none'));
    // 실행: 실제 단계 그대로(정적)
    await page.locator('[data-action="demo-run"]').click();
    await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-mode', 'live');
    const s = await bothStates(page);
    if (s.mode === 'live') expect(s.nodes).toEqual(s.steps.map((x) => MAP[x]));
    await waitDone(page);
    await expect(flow.locator('[data-node="outcome"]')).toHaveAttribute('data-state', 'on');
    await expect(flow.locator('.flow-particle')).toHaveCount(0);
  });

  test('1920×1080 흐름 그림 탭도 한 화면(안쪽 스크롤 없음 · 글자 12px 이상) · 1440×900 문서 스크롤 0 + 3줄 · 시작 단추는 화면 안(묶음 목록만 스크롤)', async ({
    page,
    backend,
  }) => {
    backend.demoStepMs = 200;
    await page.setViewportSize({ width: 1920, height: 1080 });
    await goDemo(page);
    await tab(page, 'flow').click();
    await page.locator('[data-action="demo-run"]').click();
    await waitDone(page);
    const r = await page.evaluate(() => {
      const small = [...document.querySelectorAll('[data-part="demo-page"] *')]
        .filter(
          (e) =>
            e.getClientRects().length &&
            [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent!.trim()) &&
            parseFloat(getComputedStyle(e).fontSize) < (e.closest('.badge, [data-kind-badge], .sg-pill') ? 11.5 : 12),
        )
        .map((e) => `${e.tagName}.${e.className}:${getComputedStyle(e).fontSize}`);
      const inner = [...document.querySelectorAll('[data-part="demo-page"] *')]
        .filter((e) => /(auto|scroll)/.test(getComputedStyle(e).overflowY) && e.scrollHeight > e.clientHeight + 1)
        .map((e) => String(e.className));
      return { doc: document.scrollingElement!.scrollHeight - innerHeight, small: small.slice(0, 5), inner };
    });
    expect(r).toEqual({ doc: 0, small: [], inner: [] });
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.waitForTimeout(300);
    expect(
      await page.evaluate(() => [document.scrollingElement!.scrollHeight - innerHeight, document.querySelector('main')!.scrollHeight - document.querySelector('main')!.clientHeight]),
    ).toEqual([0, 0]);
    await expect(page.locator(BRIEF)).toBeInViewport({ ratio: 1 });
    await expect(page.locator('[data-action="demo-run"]')).toBeInViewport({ ratio: 1 });
    const scenarioScroll = await page.evaluate(() => {
      const body = document.querySelector('[data-col="scenarios"] .demo-col-body')!;
      const groups = document.querySelector('[data-part="scn-groups"]')!;
      return { body: body.scrollHeight - body.clientHeight, groupsScrolls: getComputedStyle(groups).overflowY };
    });
    expect(scenarioScroll).toEqual({ body: 0, groupsScrolls: 'auto' });
  });
});

test.describe('11/09 시연 — 화면 사진', () => {
  test.beforeEach(({ backend }) => {
    backend.enableDemo();
  });

  for (const theme of ['light', 'dark'] as const) {
    test(`1440×900 ${theme}: 대기 · 실행 중 · 격리 끝(흐름 그림 · 판정 근거)`, async ({ page, backend }) => {
      backend.demoStepMs = 900;
      if (theme === 'dark') await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
      await page.setViewportSize({ width: 1440, height: 900 });
      await goDemo(page);
      await tab(page, 'flow').click();
      await page.waitForTimeout(700);
      await page.screenshot({ path: `${SHOT}/1440-${theme}-idle.png` });
      await page.locator('[data-action="demo-run"]').click();
      await expect(page.locator('[data-step="match"]')).toHaveAttribute('data-state', /active|done/, { timeout: 8000 });
      await page.screenshot({ path: `${SHOT}/1440-${theme}-running.png` });
      await waitDone(page);
      await expect(page.locator(FLOW_TAB)).toHaveAttribute('data-mode', 'done');
      await page.waitForTimeout(400);
      await page.screenshot({ path: `${SHOT}/1440-${theme}-isolated.png` });
      await tab(page, 'why').click();
      await expect(page.locator('[data-part="why"] [data-ev]')).toHaveCount(3);
      await page.screenshot({ path: `${SHOT}/1440-${theme}-isolated-why.png` });
    });
  }

  test('390 light: 1열 — 3줄 · 묶음 · 흐름 그림, 가로 넘침 없음', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await goDemo(page);
    await foldBtn(page, 'network').click();
    await expect(page.locator('[data-scenario="domain"]')).toBeHidden();
    await tab(page, 'flow').click();
    await expect(page.locator(FLOW)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    const w = await page.locator(FLOW).evaluate((e) => e.getBoundingClientRect().right);
    expect(w).toBeLessThanOrEqual(390);
    await page.locator('[data-col="scenarios"]').scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOT}/390-light-top.png` });
    await page.locator(FLOW).scrollIntoViewIfNeeded();
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${SHOT}/390-light-flow.png` });
  });
});
