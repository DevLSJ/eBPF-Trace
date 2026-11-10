import type { Locator, Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 11/10 사용자 결정 — 화면 용어 세 낱말의 뜻을 고정한다(「정책 자체가 격리 판정이 된 것처럼 오해받지 않게」)
//   판정 = 사람이 건을 악성 · 오탐으로 내리는 결론(판정 대기 · 판정 완료 · 판정 · 변경 이력 · 판정 제안). 정책 목록 · 상세의 「판정」 칸 이름은 그대로
//   탐지 = 시스템이 정책에 걸린 것을 자동으로 잡은 것(시연 흐름 · 연동 · 정책 카드 · 보고서 위반 표 · 감시 시트 · 타임라인)
//   경고 = 정책 action alert 의 이름. 「알림」은 밖으로 보내는 것(웹훅 · Slack · 알림 센터 · 알림 설정)에만
//   kill = 「격리」, dryRun = 「시험 운영」
//   고급 · 폼 칸 이름도 한글(정책 ID · 종류 · 판정, 선택지는 값 + 한글)
const SHOT = process.env.TERMS_SHOTS || `${SHOTS}/terms-1110`;
const ED = '[data-view="rule-editor"]';
const DEMO = '[data-part="demo-page"]';

// 보이는 글자 + 툴팁
const allText = (l: Locator) =>
  l.evaluate((root) => {
    const titles = Array.from(root.querySelectorAll('[title], [aria-label], [placeholder]')).flatMap((e) =>
      ['title', 'aria-label', 'placeholder'].map((a) => e.getAttribute(a) ?? ''),
    );
    return `${(root as HTMLElement).innerText}\n${titles.join('\n')}`;
  });

async function goDemo(page: Page) {
  await page.goto('/demo');
  await expect(page.locator(DEMO)).toBeVisible();
  await expect(page.getByText('실시간 연결됨')).toBeVisible();
}

test.describe('11/10 용어 — 탐지 · 판정 · 경고', () => {
  test('시연: 흐름 단계 「정책 탐지」 · 탭 「탐지 근거」, 실행 전 · 끝 · 흐름 그림 어디에도 「판정」 없음', async ({ page, backend }) => {
    backend.enableDemo();
    await goDemo(page);
    const demo = page.locator(DEMO);
    await expect(page.locator('[data-part="why-tabs"] [role="tab"]')).toHaveText(['탐지 근거', '흐름 그림']);
    await expect(page.locator('[data-part="demo-steps"] > li[data-step="match"]')).toContainText('정책 탐지');
    expect(await allText(demo)).not.toContain('판정');
    // directIp 시나리오 설명
    await page.locator('[data-scenario="direct-ip"]').click();
    expect(await allText(demo)).not.toContain('판정');
    await page.locator('[data-scenario="shell"]').click();
    await page.locator('[data-action="demo-run"]').click();
    await expect(page.locator('[data-part="demo-outcome"]')).toHaveAttribute('data-outcome', /^(?!running$).+/, { timeout: 10_000 });
    expect(await allText(demo)).not.toContain('판정');
    await page.locator('[data-part="why-tabs"] [role="tab"][data-tab="flow"]').click();
    const flow = page.locator('[data-part="demo-flow"]');
    await expect(flow.locator('.flow-title')).toHaveText(['설치 시작', '커널 이벤트', '정책 탐지', '증거 수집', '격리']);
    await expect(flow.locator('[data-node="match"]')).toContainText('에 걸려 격리됨');
    expect(await allText(demo)).not.toContain('판정');
    await page.screenshot({ path: `${SHOT}/1440-demo-flow.png` });
  });

  test('연동: 흐름 「정책으로 탐지」 · 환경 점검(도메인 조회 꺼짐 · 격리 꺼짐)에 「판정」 · 「알림만」 없음', async ({ page, backend }) => {
    await page.goto('/integration');
    const integ = page.locator('[data-part="integration"][data-state="ready"]');
    await expect(integ).toBeVisible();
    await expect(integ).toContainText('정책으로 탐지');
    const t = await allText(integ);
    expect(t).not.toContain('판정');
    expect(t).not.toContain('알림만');
    await page.screenshot({ path: `${SHOT}/1440-integration-flow.png` });
    backend.info.dnsResolve = 'off';
    backend.integration = { ...backend.integration, env: { ...backend.integration.env, enforceKill: false } };
    await page.goto('/integration/env');
    const env = page.locator('[data-part="integration"][data-state="ready"]');
    await expect(env).toBeVisible();
    await expect(env).toContainText('도메인 기준 탐지');
    await expect(env).toContainText('경고만');
    const e = await allText(env);
    expect(e).not.toContain('판정');
    expect(e).not.toContain('알림만');
  });

  test('감시 시트: 위반 이력 빈 상태 「탐지된 기록」 · 격리 보류 안내 「경고만」', async ({ page, backend }) => {
    void backend;
    await page.goto('/integration/watch?id=c-web');
    const sheet = page.locator('[data-sheet="watch"]');
    await expect(sheet.getByTestId('watch-info').locator('[data-field="enforce"] dd')).toContainText('경고만 남깁니다');
    await expect(sheet.getByTestId('watch-info')).not.toContainText('알림');
    await sheet.getByRole('tab', { name: /^위반 이력/ }).click();
    await expect(sheet).toContainText('이 컨테이너에서 위반으로 탐지된 기록이 없습니다.');
    expect(await allText(sheet)).not.toContain('판정');
  });

  test('정책 목록: 「판정」 칸 이름은 그대로, 화면 설명은 「탐지하는 정책」', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies');
    await expect(page.locator('table[data-table="policies"] thead th')).toHaveText(['상태', '정책', '종류', '판정', '적용 컨테이너', '마지막 위반', '마지막 수정']);
    await expect(page.locator('[data-part="screen-copy"]')).toHaveText('컨테이너 행동을 탐지하는 정책을 만들고 적용 범위를 관리합니다.');
  });

  test('정책 쉬운 편집: ③ 걸리면 = 경고만 · 즉시 격리 · 시험 운영, 「알림」 없음 · 적용 컨테이너 카드 「탐지할 컨테이너」 · 저장 전 확인 「경고로」', async ({ page, backend }) => {
    backend.info.enforceKill = false;
    await page.goto('/policies?id=sensitive-files');
    const act = page.locator(`${ED} [data-step="action"]`);
    await expect(act).toBeVisible();
    await expect(act).toContainText('경고만');
    await expect(act).toContainText('경고로 남깁니다');
    await expect(act).toContainText('시험 운영');
    expect(await allText(act)).not.toContain('알림');
    const card = page.locator('[data-part="containers-card"]').first();
    await expect(card).toContainText('이 정책으로 탐지할 컨테이너');
    expect(await allText(card)).not.toContain('판정');
    expect(await allText(card)).not.toContain('알림');
    await page.screenshot({ path: `${SHOT}/1440-policy-easy.png` });
    await page.locator(`${ED} [data-step="action"] input[value="alert"]`).check();
    await page.locator(ED).getByRole('button', { name: '저장 전 확인' }).click();
    const chk = page.locator(`${ED} [data-part="save-check"]`);
    await expect(chk.locator('[data-preview-count]')).toBeVisible();
    await expect(chk).toContainText('격리에서 경고로 바뀜');
    await expect(chk.locator('[data-summary]')).toContainText('경고로 남깁니다');
    expect(await allText(chk)).not.toContain('알림');
  });

  test('정책 고급 · 폼: 칸 이름 정책 ID · 종류 · 판정, 선택지 값 + 한글, 시험 운영 스위치, 「알림」 없음', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=egress-allowlist');
    await page.locator(`${ED} [data-mode="form"]`).click();
    const ed = page.locator(ED);
    const labels = await ed.locator('label.grid > span:first-child').evaluateAll((els) => els.map((e) => (e.firstChild?.textContent ?? '').trim()));
    expect(labels.slice(0, 4)).toEqual(['정책 ID', '설명', '종류', '판정']);
    await expect(ed.getByText('소문자·숫자·하이픈')).toBeVisible();
    const kind = ed.locator('select[data-field="kind"] option');
    await expect(kind).toHaveText(['exec(실행)', 'open(파일)', 'connect(통신)', 'dns(조회)']);
    expect(await kind.evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value))).toEqual(['exec', 'open', 'connect', 'dns']);
    const action = ed.locator('select[data-field="action"] option');
    await expect(action).toHaveText(['alert(경고)', 'kill(격리)']);
    expect(await action.evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value))).toEqual(['alert', 'kill']);
    await expect(ed.locator('select[data-field="directIp"] option')).toHaveText(['(비움)', 'allow(통과)', 'alert(경고)', 'kill(격리)']);
    await expect(page.getByRole('switch').locator('xpath=..')).toContainText('시험 운영');
    expect(await allText(ed)).not.toContain('알림');
    expect(await allText(ed)).not.toContain('강제 종료');
  });

  test('정책 상세 차단 이력 빈 상태: 「이 정책이 탐지한 위반 기록」', async ({ page, backend }) => {
    backend.audit = [];
    await page.goto('/policies?id=sensitive-files&tab=blocks');
    const sheet = page.locator('[data-sheet]').filter({ has: page.getByRole('tab', { name: /^차단 이력/ }) });
    await expect(sheet).toContainText('이 정책이 탐지한 위반 기록이 아직 없습니다.');
  });

  test('보고서: 위반 표 칸 「탐지 결과」 · 타임라인 「수집→탐지」, 사람 판정 칸은 그대로', async ({ page, backend }) => {
    backend.enableIsolation();
    await page.goto('/report?install=ins-0012');
    const rep = page.getByTestId('report');
    await expect(rep.locator('[data-section="violations"] thead th')).toHaveText(['시각', '종류', '정책', '상세', '탐지 결과']);
    expect(await allText(rep.locator('[data-section="timeline"]'))).not.toContain('판정');
    await expect(rep.locator('[data-section="timeline"]')).toContainText('수집→탐지');
    await expect(rep.locator('[data-section="decision"]')).toContainText('판정');
  });

  test('대시보드: 자동 격리 꺼짐 = 「경고만」(알림 신호등은 그대로) · 판정 대기 그대로', async ({ page, backend }) => {
    backend.stats.enforceKill = false;
    backend.info.enforceKill = false;
    await page.goto('/');
    const pill = (k: string) => page.locator(`[data-testid="signal-pills"] [data-pill="${k}"]`);
    await expect(pill('kill')).toContainText('경고만');
    await expect(pill('kill')).toHaveAttribute('title', '「즉시 격리」 정책도 격리하지 않고 경고만 남깁니다(ENFORCE_KILL=false)');
    await expect(pill('notify')).toContainText('알림');
    await expect(page.getByText('판정 대기').first()).toBeVisible();
  });
});
