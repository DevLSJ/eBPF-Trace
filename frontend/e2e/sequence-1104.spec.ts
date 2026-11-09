import type { Page } from '@playwright/test';
import { expect, SHOTS, test, closeSheet } from './fixtures';
import { SEQ_PATHS, SEQ_RULE_ID, sequenceRule } from './mock-backend';

// 11/04 연쇄 규칙(kind: sequence) — 정책 화면 표시 · 편집 최소안(설계 2-4, 목업 mock/tests/sequence-1104.cjs 화면 항목을 React 에 맞게)
// ① 목록 배지 「연쇄」 ② YAML 전용 편집 ③ 저장 전 요약 · 미리보기 불가 안내 · dryRun 없는 kill 경고 ④ 검증(백엔드 422 문구) · 단일 규칙 YAML 의 kind: sequence 탭 전환 거절
// ⑤ 새 기본 규칙 추가 ⑥ 바뀐 기본 규칙 단계별 병합 ⑦ 감사 상세 「연쇄」 행 ⑧ 이벤트 상세 「연쇄」 행 / 없음 · 「이 행동 허용」 ⑨ 조회자 ⑩ 다크 ⑪ 375px

const ED = '[data-view="rule-editor"]';
const YAML_TA = `${ED} textarea[aria-label="정책 YAML"]`;
const NO_PREVIEW = '연쇄 규칙은 미리보기를 할 수 없습니다. 감사 로그에는 위반만 저장돼 연쇄의 앞 단계(정상 실행 · 연결)가 남아 있지 않습니다. 시험 운영(dryRun)으로 저장해 실제 판정을 지켜본 뒤 격리로 바꾸세요';
const KILL_WARN = '시험 운영(dryRun) 없이 격리(kill)로 저장합니다. 오탐이면 정상 컨테이너가 바로 종료됩니다. 먼저 dryRun: true 로 지켜보기를 권합니다';
const SEQ_LINE = `규칙 ${SEQ_RULE_ID}: exec wget(0.0초) → connect 203.0.113.7:80(+2.1초) → open /root/.netrc(+2.4초)`;
const SUMMARY_DRY = '연쇄 3단계 · 10초 안 · 시험(격리 대상)';

const openSeq = async (page: Page) => {
  await page.goto(`/policies?id=${SEQ_RULE_ID}`);
  await expect(page.locator(YAML_TA)).toBeVisible();
};
const checkNow = (page: Page) => page.locator(ED).getByRole('button', { name: '저장 전 확인' }).click();
const saveCheck = (page: Page) => page.locator('[data-part="save-check"]');
// dl 의 「연쇄」 dt 다음 dd 글자
const seqRows = (page: Page, sheet: string) =>
  page.locator(`[data-sheet="${sheet}"] dl dt`).evaluateAll((els) => els.filter((e) => e.textContent === '연쇄').map((e) => e.nextElementSibling?.textContent ?? ''));
const previewCalls = (b: { requests: { method: string; path: string }[] }) => b.requests.filter((r) => r.method === 'POST' && r.path === '/policies/preview').length;

test.describe('연쇄 규칙(kind: sequence) — 정책 · 감사 · 이벤트 화면', () => {
  test('① 정책 목록: 연쇄 규칙 배지 「연쇄」(badge-kind-sequence · accent 토큰) · 대응 「시험」 · 다른 배지 그대로', async ({ page, backend }) => {
    backend.enableDns().enableSequence();
    await page.goto('/policies?id=sensitive-files');
    const row = page.locator(`[data-rule="${SEQ_RULE_ID}"]`);
    const badge = row.locator('[data-kind-badge="sequence"]');
    await expect(badge).toHaveText('연쇄');
    await expect(badge).toHaveClass(/badge-kind-sequence/);
    await expect(badge).toHaveAttribute('title', '연쇄');
    await expect(row).toContainText('시험');
    await expect(page.locator('[data-rule="sandbox-dns"] [data-kind-badge="dns"]')).toHaveText('조회');
    await expect(page.locator('[data-rule="sensitive-files"] [data-kind-badge="open"]')).toHaveText('파일');
    // 라이트 토큰: --accent-soft #EEF2FF · --accent-text #3730A3
    expect(await badge.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color])).toEqual(['rgb(220, 233, 255)', 'rgb(13, 71, 184)']);
    await page.screenshot({ path: `${SHOTS}/1104-seq-list.png` });
  });

  test('② 편집: 탭은 「고급 · YAML」 하나(쉬운 설정 · 폼 없음) · 처음 YAML 에 kind: sequence · windowSeconds · steps(들여쓰기) · 적용 결과 문구', async ({ page, backend }) => {
    backend.enableSequence();
    await openSeq(page);
    const ed = page.locator(ED);
    const modes = await ed.locator('[data-mode]').evaluateAll((els) => els.map((e) => [(e as HTMLElement).dataset.mode, e.getAttribute('aria-pressed')]));
    expect(modes).toEqual([['yaml', 'true']]);
    await expect(ed.locator('[data-step]')).toHaveCount(0);
    const y = (await page.locator(YAML_TA).inputValue()).split('\n');
    for (const want of [`id: ${SEQ_RULE_ID}`, 'kind: sequence', 'action: kill', 'dryRun: true', 'windowSeconds: 10', 'steps:', '  - kind: exec', '    denyComms:', '      - curl', '  - kind: connect', '    allowCidrs:', '  - kind: open', '      - /root/.kube/config'])
      expect(y, want).toContain(want);
    expect(y.some((l) => /^(denyComms|allowCidrs|denyPaths):/.test(l)), '조건이 최상위에 나옴').toBe(false);
    await expect(ed).toContainText('kill → 알림만 (dry-run)');
    await page.screenshot({ path: `${SHOTS}/1104-seq-yaml.png` });
  });

  test('③ 저장 전 확인: 요약 · 미리보기 불가 안내(미리보기 API 안 부름) · dryRun 이면 경고 없음 → dryRun 지우면 「격리」 + 경고 한 줄 → 저장 뒤 단계 그대로', async ({ page, backend }) => {
    backend.enableSequence();
    await openSeq(page);
    await checkNow(page);
    await expect(saveCheck(page).locator('[data-summary]')).toHaveText(SUMMARY_DRY);
    await expect(page.locator('[data-part="seq-no-preview"]')).toHaveText(NO_PREVIEW);
    await expect(page.locator('[data-preview-count]')).toHaveCount(0);
    await expect(saveCheck(page)).not.toContainText('계산하는 중');
    await expect(page.locator('[data-part="seq-kill-warn"]')).toHaveCount(0);
    expect(previewCalls(backend)).toBe(0);
    await page.screenshot({ path: `${SHOTS}/1104-seq-check.png` });
    await saveCheck(page).getByRole('button', { name: '고치기' }).click();
    const ta = page.locator(YAML_TA);
    await ta.fill((await ta.inputValue()).split('\n').filter((l) => l !== 'dryRun: true').join('\n'));
    await checkNow(page);
    await expect(saveCheck(page).locator('[data-summary]')).toHaveText('연쇄 3단계 · 10초 안 · 격리');
    await expect(page.locator('[data-part="seq-kill-warn"]')).toHaveText(KILL_WARN);
    await page.screenshot({ path: `${SHOTS}/1104-seq-check-kill.png` });
    // 경고는 저장을 막지 않는다
    await saveCheck(page).getByRole('button', { name: '저장 후 적용' }).click();
    await expect(page.getByText('저장 후 엔진에 적용됨')).toBeVisible();
    expect(previewCalls(backend)).toBe(0);
    const s = backend.rules.find((r) => r.id === SEQ_RULE_ID)!;
    expect(s.dryRun).toBeFalsy();
    expect(s.windowSeconds).toBe(10);
    expect(s.steps?.map((x) => x.kind)).toEqual(['exec', 'connect', 'open']);
    expect(s.steps?.[2].denyPaths).toEqual(SEQ_PATHS);
    expect(s.steps?.[1].allowCidrs).toContain('::1');
    // 저장 뒤에도 YAML 하나
    await expect(page.locator(`${ED} [data-mode]`)).toHaveCount(1);
    await page.goto('/policies/changes'); // 11/09: 변경 이력 페이지 · 태그는 끝말(정책 수정)
    await expect(page.getByTestId('changes').locator('[data-change]').first()).toContainText('정책 수정');
  });

  test('④ 검증: 백엔드 422 문구를 그대로 보인다(단계 1개 · 창 0 · 단계에 action · 최상위 조건 · 중첩 sequence · 빈 단계) / 단일 규칙 YAML 에 kind: sequence → 다른 탭 거절', async ({ page, backend, allowConsole }) => {
    backend.enableSequence();
    allowConsole(/status of 422/); // 일부러 내는 저장 거절
    await openSeq(page);
    const ta = page.locator(YAML_TA);
    const orig = await ta.inputValue();
    // 11/09 G14: 화면에는 상태 코드(「422 ·」) 없이 서버 문장만
    const cases: [string, (y: string) => string, string][] = [
      ['단계 1개', (y) => y.split('  - kind: connect')[0].trimEnd(), 'steps: 단계 2~5개 (지금 1개)'],
      ['창 0', (y) => y.replace('windowSeconds: 10', 'windowSeconds: 0'), 'windowSeconds 0: 1~60'],
      ['단계에 action', (y) => y.replace('  - kind: exec', '  - kind: exec\n    action: kill'), 'steps[0]: 단계에는 kind 와 조건만'],
      ['최상위 조건', (y) => y.replace('windowSeconds: 10', 'windowSeconds: 10\ndenyComms:\n  - nc'), 'sequence 규칙 최상위에는 조건을 쓸 수 없음(조건은 steps 에)'],
      ['중첩 sequence', (y) => y.replace('  - kind: open', '  - kind: sequence'), 'steps[2]: kind "sequence": exec | open | connect | dns'],
      ['빈 단계', (y) => y.replace(/ {2}- kind: connect\n {4}allowCidrs:\n( {6}- .*\n)+/, '  - kind: connect\n'), 'steps[1]: connect 규칙에 조건이 없음'],
    ];
    for (const [name, fn, want] of cases) {
      const y = fn(orig);
      expect(y, name).not.toBe(orig);
      await ta.fill(y);
      await checkNow(page);
      await saveCheck(page).getByRole('button', { name: '저장 후 적용' }).click();
      await expect(page.locator(`${ED} span.text-red-600`), name).toContainText(want);
      await expect(saveCheck(page)).toHaveCount(0);
    }
    expect(backend.rules.find((r) => r.id === SEQ_RULE_ID)).toEqual(sequenceRule());
    // 단일 규칙: YAML 에서 kind: sequence 로 바꾸고 쉬운 설정으로 가면 거절(단계를 잃지 않게) — YAML 탭에 남는다
    await page.goto('/policies?id=sensitive-files'); // 11/09: 목록은 시트 뒤 — 주소로 연다
    const ed = page.locator(ED);
    await ed.locator('[data-mode="yaml"]').click();
    await ta.fill(orig.replace(`id: ${SEQ_RULE_ID}`, 'id: sensitive-files'));
    await ed.locator('[data-mode="easy"]').click();
    await expect(ed.locator('[data-mode="yaml"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(ed.locator('span.text-red-600')).toContainText('연쇄 규칙(sequence)은 「고급 · YAML」로만 편집합니다');
  });

  test('⑤ 새 기본 규칙: 연쇄 규칙이 없으면 안내 띠 → 「미리보기 후 추가」 → 연쇄 저장 전 확인(미리보기 없음) → 저장하면 단계 3개 그대로', async ({ page, backend }) => {
    backend.policyDefaults = { missing: [sequenceRule()], differs: [] };
    await page.goto('/policies'); // 11/09: 띠는 목록 위(시트가 열려 있으면 가림)
    await page.locator('[data-action="defaults-toggle"]').click();
    const item = page.locator(`[data-default="${SEQ_RULE_ID}"]`);
    await expect(item).toContainText('새 규칙');
    await item.locator('[data-action="default-preview"]').click();
    await expect(page.getByTestId('editor')).toContainText(`새 기본 규칙 · ${SEQ_RULE_ID}`);
    await expect(saveCheck(page).locator('[data-summary]')).toHaveText(SUMMARY_DRY);
    await expect(page.locator('[data-part="seq-no-preview"]')).toHaveText(NO_PREVIEW);
    expect(previewCalls(backend)).toBe(0);
    await saveCheck(page).getByRole('button', { name: '저장 후 적용' }).click();
    await expect.poll(() => backend.rules.some((r) => r.id === SEQ_RULE_ID)).toBe(true);
    expect(backend.rules.find((r) => r.id === SEQ_RULE_ID)).toEqual(sequenceRule());
  });

  test('⑥ 바뀐 기본 규칙: 3단계 경로 하나 · 창 20초 → 안내 「steps[2].denyPaths +/root/.kube/config」 · 병합은 그 단계에만(steps 중복 없음) · 창 20 유지 / 단계 모양이 다르면 지금 단계 유지', async ({ page, backend }) => {
    backend.enableSequence();
    const cur = backend.rules.find((r) => r.id === SEQ_RULE_ID)!;
    cur.windowSeconds = 20;
    cur.steps![2].denyPaths = SEQ_PATHS.filter((p) => p !== '/root/.kube/config');
    backend.policyDefaults = { missing: [], differs: [{ id: SEQ_RULE_ID, default: sequenceRule(), current: structuredClone(cur) }] };
    await page.goto('/policies'); // 11/09: 띠는 목록 위
    await page.locator('[data-action="defaults-toggle"]').click();
    const item = page.locator(`[data-default="${SEQ_RULE_ID}"]`);
    await expect(item).toContainText('steps[2].denyPaths +/root/.kube/config');
    await expect(item).toContainText('windowSeconds: 20 (지금 값 유지, 기본은 10)');
    await expect(item).not.toContainText('[object Object]');
    await item.locator('[data-action="default-preview"]').click();
    await expect(saveCheck(page).locator('[data-summary]')).toHaveText('연쇄 3단계 · 20초 안 · 시험(격리 대상)');
    await saveCheck(page).getByRole('button', { name: '저장 후 적용' }).click();
    await expect.poll(() => backend.rules.find((r) => r.id === SEQ_RULE_ID)!.steps![2].denyPaths!.length).toBe(10);
    const s = backend.rules.find((r) => r.id === SEQ_RULE_ID)!;
    expect(s.steps).toHaveLength(3);
    expect(s.windowSeconds).toBe(20);
    expect(s.steps![2].denyPaths!.filter((p) => p === '/etc/shadow')).toHaveLength(1);
    expect(s.steps![0].denyComms).toEqual(['curl', 'wget']);

    // 단계 수가 다르면 단계를 붙이지 않는다(지금 단계 유지)
    const two = backend.rules.find((r) => r.id === SEQ_RULE_ID)!;
    two.steps = two.steps!.slice(0, 2);
    backend.policyDefaults = { missing: [], differs: [{ id: SEQ_RULE_ID, default: sequenceRule(), current: structuredClone(two) }] };
    await page.goto('/policies'); // 11/09: 띠는 목록 위
    await page.locator('[data-action="defaults-toggle"]').click();
    await expect(page.locator(`[data-default="${SEQ_RULE_ID}"]`)).toContainText('steps: 지금 단계 유지 (기본은 exec → connect → open)');
    await page.locator(`[data-default="${SEQ_RULE_ID}"] [data-action="default-preview"]`).click();
    await expect(saveCheck(page).locator('[data-summary]')).toHaveText('연쇄 2단계 · 20초 안 · 시험(격리 대상)');
  });

  test('⑦ 감사 상세: 연쇄가 이긴 행에 「연쇄」 한 줄 · 「이 행동 허용」 없음 / 다른 행에는 연쇄 행 없음', async ({ page, backend }) => {
    backend.enableSequence();
    const row = backend.audit.find((a) => a.sequence)!;
    await page.goto(`/audit?id=${row.id}`);
    const sheet = page.locator('[data-sheet="audit"]');
    await expect(sheet.getByTestId('audit-reason')).toHaveText('연쇄 3단계(10초 안): exec wget → connect 203.0.113.7:80 → open /root/.netrc · 2.4초');
    expect(await seqRows(page, 'audit')).toEqual([SEQ_LINE]);
    await expect(sheet.locator('[data-action="block-this"]')).toBeVisible(); // 막기 링크는 그대로(그 행동 = open 경로)
    await expect(sheet.locator('[data-action="allow-this"]')).toHaveCount(0);
    await page.screenshot({ path: `${SHOTS}/1104-seq-audit.png` });
    const other = backend.audit.find((a) => !a.sequence && a.event.kind === 'open')!;
    await page.goto(`/audit?id=${other.id}`);
    await expect(sheet.getByTestId('audit-reason')).toHaveText(other.reason!);
    expect(await seqRows(page, 'audit')).toEqual([]);
  });

  test('⑧ 이벤트 상세: 단일 규칙이 이긴 판정의 연쇄 주석 「 · 판정은 sensitive-files」(허용 링크는 단일 규칙에) · 연쇄가 이긴 판정은 허용 링크 없음 · 일반 판정에는 연쇄 행 없음', async ({ page, backend }) => {
    backend.enableSequence();
    await page.goto('/events?container=web-api');
    const sheet = page.locator('[data-sheet="event"]');
    await page.locator('li[data-key]', { hasText: '/root/.ssh/id_rsa' }).first().click();
    await expect(sheet).toBeVisible();
    expect(await seqRows(page, 'event')).toEqual([
      `규칙 ${SEQ_RULE_ID}: exec wget(0.0초) → connect 203.0.113.7:80(+2.1초) → open /root/.ssh/id_rsa(+2.4초) · 판정은 sensitive-files`,
    ]);
    await expect(sheet.locator('[data-action="allow-this"]')).toContainText('sensitive-files');
    await closeSheet(page); // 11/05 슬라이드 패널: 열린 동안 뒤 화면은 어두운 배경에 가려 눌리지 않는다 — 먼저 닫는다
    await page.locator('li[data-key]', { hasText: '/root/.netrc' }).first().click();
    await expect(sheet.locator('[data-part="detail"]')).toHaveText('/root/.netrc');
    expect(await seqRows(page, 'event')).toEqual([SEQ_LINE]);
    await expect(sheet.locator('[data-action="allow-this"]')).toHaveCount(0);
    await page.goto('/events?container=pkg-reqeusts');
    await page.locator('li[data-key]', { hasText: '/etc/shadow' }).first().click();
    await expect(sheet.locator('[data-part="detail"]')).toHaveText('/etc/shadow');
    expect(await seqRows(page, 'event')).toEqual([]);
  });

  test('⑨ 조회자: 연쇄 규칙도 YAML 하나 · 저장 전 확인 요약 · 안내(저장 버튼 없음)', async ({ page, backend }) => {
    backend.enableSequence();
    backend.auth.asViewer();
    await openSeq(page);
    await expect(page.locator(`${ED} [data-mode]`)).toHaveCount(1);
    expect(await page.locator(YAML_TA).inputValue()).toContain('  - kind: open');
    await checkNow(page);
    await expect(saveCheck(page).locator('[data-summary]')).toHaveText(SUMMARY_DRY);
    await expect(page.locator('[data-part="seq-no-preview"]')).toHaveText(NO_PREVIEW);
    await expect(saveCheck(page).getByRole('button', { name: '저장 후 적용' })).toHaveCount(0);
    await expect(saveCheck(page)).toContainText('저장은 관리자만 할 수 있습니다');
  });

  test('⑩ 다크: 목록 배지가 다크 토큰(--accent-soft #1A2D4E · --accent-text #DCE9FF) · 저장 전 확인 안내', async ({ page, backend }) => {
    backend.enableSequence();
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await openSeq(page);
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    const badge = page.locator(`[data-rule="${SEQ_RULE_ID}"] [data-kind-badge="sequence"]`);
    expect(await badge.evaluate((e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color])).toEqual(['rgb(26, 45, 78)', 'rgb(220, 233, 255)']);
    await checkNow(page);
    await expect(page.locator('[data-part="seq-no-preview"]')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/1104-seq-dark.png` });
  });

  test('⑪ 375px: 연쇄 규칙 편집 · 저장 전 확인 안내가 화면 폭 안(가로 스크롤 없음)', async ({ page, backend }) => {
    backend.enableSequence();
    await page.setViewportSize({ width: 375, height: 812 });
    await openSeq(page);
    const noHScroll = () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
    expect(await noHScroll()).toBe(true);
    await checkNow(page);
    const box = page.locator('[data-part="seq-no-preview"]');
    await box.scrollIntoViewIfNeeded();
    await expect(box).toBeVisible();
    expect(await noHScroll()).toBe(true);
    const b = (await box.boundingBox())!;
    expect(b.x).toBeGreaterThanOrEqual(0);
    expect(b.x + b.width).toBeLessThanOrEqual(375);
    await page.screenshot({ path: `${SHOTS}/1104-seq-375.png` });
  });
});
