import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 10/16 정책 설정 개편(목업 mock/tests/policy-1016.cjs 확정 → 이식): 처음 쓰는 사람도 정책을 세부적으로
const ED = '[data-view="rule-editor"]';
const chips = (page: Page, group: string) =>
  page.locator(`${ED} [data-chips="${group}"] [data-chip]`).evaluateAll((els) => els.map((e) => `${(e as HTMLElement).dataset.type}:${(e as HTMLElement).dataset.value}`));
const addChip = async (page: Page, group: string, value: string) => {
  const i = page.locator(`${ED} [data-chips="${group}"] input`);
  await i.fill(value);
  await i.press('Enter');
};

test.describe('정책 쉬운 설정', () => {
  test('정책을 열면 쉬운 설정: 단계 5개 + 요약, 고급(폼 · YAML)은 탭, 목록은 쉬운 말', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=sensitive-files');
    const ed = page.locator(ED);
    await expect(ed.locator('[data-mode="easy"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(ed.locator('[data-step]')).toHaveCount(5);
    expect(await ed.locator('[data-step]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.step))).toEqual(['what', 'values', 'action', 'scope', 'name']);
    await expect(ed.locator('[data-step="what"] input[value="open"]')).toBeChecked();
    // 11/09 밤 사용자: 편집 탭 아래 요약 띠는 화면을 가려 삭제 — 같은 요약은 「저장 전 확인」 창에서 본다
    await expect(ed.locator('[data-summary]')).toHaveCount(0);
    expect(await ed.locator('[data-mode]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.mode))).toEqual(['easy', 'form', 'yaml']);
    const row = page.locator('[data-rule="sensitive-files"]');
    await expect(row).toContainText('자격 증명·계정 파일 접근');
    await expect(row).toContainText('격리');
    await expect(row).toContainText('파일');
    await page.screenshot({ path: `${SHOTS}/1440-10-policy-easy.png` });
    // 요약은 「저장 전 확인」 창에서(편집기가 확인 화면으로 바뀌므로 맨 끝에)
    await ed.getByRole('button', { name: '저장 전 확인' }).click();
    await expect(page.locator('[data-part="save-check"] [data-summary]')).toContainText('/etc/shadow');
    await expect(page.locator('[data-part="save-check"] [data-summary]')).toContainText('즉시 격리');
  });

  test('통신 정책: 칩이 포트 · 대역 · 도메인을 나누고, 틀린 값은 이유와 함께 거부, 고급 폼과 같은 값', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=egress-allowlist');
    await addChip(page, 'block', '4444');
    await addChip(page, 'block', 'evil.example');
    await addChip(page, 'allow', '10.1.0.0/16');
    await addChip(page, 'allow', 'pypi.org');
    await addChip(page, 'allow', '99999');
    const b = await chips(page, 'block');
    const a = await chips(page, 'allow');
    expect(b).toEqual(expect.arrayContaining(['port:4444', 'host:evil.example']));
    expect(a).toEqual(expect.arrayContaining(['cidr:10.1.0.0/16', 'host:pypi.org', 'port:443']));
    expect(a.some((x) => x.endsWith(':99999'))).toBe(false);
    await expect(page.locator(`${ED} [data-chips="allow"] [data-chip-error]`)).toContainText('1~65535');
    await expect(page.locator(`${ED} [data-summary]`)).toHaveCount(0); // 편집 탭 요약 띠 삭제(11/09 밤) — 값은 아래 고급 폼으로 확인
    await page.locator(`${ED} [data-mode="form"]`).click();
    await expect(page.locator(`${ED} textarea[data-field="denyPorts"]`)).toHaveValue(/4444/);
  });

  test('저장 전 확인: 요약 + 미리보기 → 저장 후 적용 → 정책 · 변경 이력', async ({ page, backend }) => {
    await page.goto('/policies?id=sensitive-files');
    await page.locator(`${ED} [data-step="action"] input[value="alert"]`).check();
    await page.locator(ED).getByRole('button', { name: '저장 전 확인' }).click();
    const chk = page.locator(`${ED} [data-part="save-check"]`);
    await expect(chk.locator('[data-preview-count]')).toBeVisible();
    await expect(chk).toContainText('격리에서 경고로 바뀜');
    expect(backend.writes().filter((r) => r.path === '/policies')).toHaveLength(0);
    await page.screenshot({ path: `${SHOTS}/1440-11-policy-save-check.png` });
    await chk.getByRole('button', { name: '저장 후 적용' }).click();
    await expect(page.getByText('저장 후 엔진에 적용됨')).toBeVisible();
    const w = backend.writes().find((r) => r.path === '/policies' && r.method === 'POST')!;
    expect(JSON.parse(w.body!).action).toBe('alert');
    expect(w.auth).toBeNull(); // W16: 쿠키 세션
    await page.goto('/policies/changes'); // 11/09: 변경 이력은 「정책」 아래 페이지 · 태그는 끝말(정책 수정)
    await expect(page.getByTestId('changes').locator('[data-change]').first()).toContainText('정책 수정');
  });

  test('새 정책: 목적별 템플릿 → 값이 채워진 쉬운 설정 → 저장', async ({ page, backend }) => {
    await page.goto('/policies');
    await page.getByRole('button', { name: '정책 생성' }).click(); // 11/09: 큰 2단 창
    const tpl = page.locator('[data-view="templates"] [data-template]');
    // 10/20: count() 는 기다리지 않아 부하 때 그려지기 전 0 개로 잡혔다(전체 실행 간헐 실패 3회) — 6번째가 보일 때까지 기다린다
    await expect(tpl.nth(5)).toBeVisible();
    await page.locator('[data-view="templates"] [data-template="reverse-shell"]').click();
    await expect(page.locator(`${ED} [data-step="what"] input[value="connect"]`)).toBeChecked();
    expect(await chips(page, 'block')).toContain('port:4444');
    const id = await page.locator(`${ED} [data-step="name"] input[data-field="id"]`).inputValue();
    expect(id).toMatch(/^[a-z0-9-]{4,}$/);
    // 11/09: 생성 창은 바닥 줄(취소 · 저장 전 확인)
    await page.locator('dialog[data-part="policy-create"] [data-part="modal-foot"]').getByRole('button', { name: '저장 전 확인' }).click();
    await page.locator(`${ED} [data-part="save-check"]`).getByRole('button', { name: '저장 후 적용' }).click();
    await expect(page).toHaveURL(new RegExp(`id=${id}`));
    const saved = backend.rules.find((r) => r.id === id)!;
    expect(saved.denyPorts).toContain(4444);
  });

  test('감사 행 「이 행동 막기」 → 값이 채워진 새 정책, 「이 행동 허용」 → 걸린 정책에 예외 칩', async ({ page, backend }) => {
    const a = backend.audit.find((x) => x.ruleId === 'sensitive-files' && x.event.path === '/etc/shadow')!;
    await page.goto(`/audit?id=${a.id}`);
    await page.locator('[data-sheet="audit"] [data-action="block-this"]').click();
    await expect(page.locator(`${ED} [data-step="what"] input[value="open"]`)).toBeChecked();
    expect(await chips(page, 'block')).toContain('path:/etc/shadow');
    await page.goto(`/audit?id=${a.id}`);
    await page.locator('[data-sheet="audit"] [data-action="allow-this"]').click();
    await expect(page).toHaveURL(/id=sensitive-files/);
    await expect(page.locator(`${ED} [data-chips="allow"] [data-chip][data-new]`)).toHaveCount(1);
    expect(await chips(page, 'allow')).toContain('path:/etc/shadow');
  });
  // 서버 설정 보기는 W16 에서 「설정」 화면으로 옮겼다 — settings-1020.spec
});
