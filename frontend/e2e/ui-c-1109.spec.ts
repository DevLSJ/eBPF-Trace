import { readFileSync } from 'node:fs';
import type { Locator, Page, Route } from '@playwright/test';
import type { Scan } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';

// 11/09 저녁 묶음 C(정책 · 판정 문구 · 표기) — 참고 제품 문서와 대조해 찾은 항목:
//   G41 시각 YYYY-MM-DD HH:mm:ss(표 칸 TimeText 와 같은 모양) · G44 칸 이름 통일(통일표 lib/fieldNames.ts 한 곳)
//   G16 꺼진 단추는 초점을 받고 사유를 읽어 줌(aria-disabled + title) · G19 확인 창 제목 「~할까요?」 + 영향 범위 줄
//   G20 실패 알림 「~하지 못했습니다(…).」 + 할 일 · G24 아이콘 단추 title = aria-label · G37 한글 뒤 조사
// 화면 사진은 UI_C_SHOTS(없으면 test-results/screens/ui-c-1109)
const LOG = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/;
const LOG_IN = '\\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d';
const OUT = process.env.UI_C_SHOTS || `${SHOTS}/ui-c-1109`;
const DIALOG = 'dialog[data-part="confirm"]';
const ED = '[data-view="rule-editor"]';
const src = (f: string) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
const fail500 = (route: Route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: '모의 오류' }) });

// 꺼진 단추(G16): 진짜 disabled 가 아니라 aria-disabled — 초점은 가고 화면 읽기가 사유(title → 설명)를 읽는다. 누름은 막힘
async function offWithReason(el: Locator, reason: string) {
  await expect(el).toHaveAttribute('aria-disabled', 'true');
  await expect(el).toHaveAttribute('title', reason);
  await expect(el).not.toHaveAttribute('disabled');
  expect(reason, '사유는 마침표 없이').not.toMatch(/\.$/);
  await el.focus();
  await expect(el).toBeFocused();
  await expect(el).toHaveAccessibleDescription(reason);
}

test.describe('G41 시각 표기 — YYYY-MM-DD HH:mm:ss', () => {
  test('설치 시트(시작 · 판정 시각) · 보고서(판정 · 작성) · 제안 상세(적용됨)', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0006');
    const sheet = page.locator('[data-sheet="install"]');
    await expect(sheet.locator('dt', { hasText: /^시작$/ }).locator('xpath=following-sibling::dd[1]')).toHaveText(LOG);
    await expect(page.getByTestId('decision').locator('dd.num')).toHaveText(LOG);

    await page.goto('/report?case=case-0002');
    const rep = page.getByTestId('report');
    await expect(rep.locator('[data-section="decision"]')).toContainText(new RegExp(`· ${LOG_IN}`));
    await expect(rep.locator('[data-section="meta"]')).toContainText(new RegExp(`작성 ${LOG_IN}`));

    await page.goto('/policies?proposal=prop-0001');
    await expect(page.getByTestId('proposal-state')).toHaveText(new RegExp(`^적용됨 · .+ · ${LOG_IN}$`));
  });
});

test.describe('G44 칸 이름 통일 — 감사 「정책」 · 정책 「처리자」 · 설치 「패키지 관리자」', () => {
  test('감사 로그: 정책 ID 칸 · 검색 · 적용된 필터 · 상세 시트 모두 「정책」', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await expect(page.locator('table[data-table="audit"] th[data-col="rule"]')).toHaveText('정책');
    const box = page.getByRole('searchbox', { name: '정책 검색' });
    await expect(box).toHaveAttribute('placeholder', '정책 ID');
    await box.fill('sensitive-files');
    await box.press('Enter');
    await expect(page.locator('[data-part="filter-chips"]')).toContainText('정책: sensitive-files');
    await page.locator('table[data-table="audit"] tbody tr').first().click();
    await expect(page.locator('[data-sheet] dt', { hasText: /^정책$/ })).toBeVisible();
    await expect(page.locator('[data-sheet] dt', { hasText: /^규칙$/ })).toHaveCount(0);
  });

  test('정책 목록: 숨김 칸 「처리자」(옛 「수정자」)', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies');
    await page.locator('[data-table-tools="policies"] [data-action="table-columns"]').click();
    const picker = page.locator('[data-part="column-picker"]');
    await expect(picker.getByRole('checkbox', { name: '수정자' })).toHaveCount(0);
    await picker.getByRole('checkbox', { name: '처리자' }).check();
    await page.keyboard.press('Escape');
    await expect(page.locator('table[data-table="policies"] th[data-col="by"]')).toHaveText('처리자');
  });

  test('설치 검사: 칸 · 거르기 · 적용된 필터 「패키지 관리자」(옛 「매니저」)', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await expect(page.locator('table[data-table="installs"] th[data-col="manager"]')).toHaveText('패키지 관리자');
    const group = page.getByRole('group', { name: '패키지 관리자' });
    await expect(group).toBeVisible();
    await group.locator('[data-chip="pip"]').click();
    await expect(page.locator('[data-part="filter-chips"]')).toContainText('패키지 관리자: pip');
    await expect(page.locator('main')).not.toContainText('매니저');
  });

  test('통일표는 lib/fieldNames.ts 한 곳 — 세 화면이 거기서 읽고 옛 이름 글자를 직접 쓰지 않는다', () => {
    const table = src('lib/fieldNames.ts');
    for (const name of ['정책', '처리자', '패키지 관리자', '조건 지우기']) expect(table).toContain(`'${name}'`);
    for (const [file, old] of [
      ['features/audit/AuditPage.tsx', /label: '규칙'|>규칙</],
      ['features/policies/PoliciesPage.tsx', /'수정자'/],
      ['features/installs/InstallsPage.tsx', /'매니저'|"매니저"|`매니저/],
    ] as const) {
      const s = src(file);
      expect(s, file).toMatch(/from '\.\.\/\.\.\/lib\/fieldNames'/);
      expect(s, file).not.toMatch(old);
    }
  });
});

test.describe('G16 꺼진 단추 — 초점을 받고 사유를 읽어 준다(aria-disabled + 사유)', () => {
  test('시스템 규칙: 삭제 · 저장 전 확인 · 적용 범위 단추', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=blocklist-hosts');
    const ed = page.locator(ED);
    await offWithReason(ed.getByRole('button', { name: '삭제' }), '시스템 규칙은 지울 수 없습니다');
    await offWithReason(ed.getByRole('button', { name: '저장 전 확인' }), '시스템 규칙은 직접 편집할 수 없습니다');
    const pickSome = page.locator('[data-part="containers-card"] [data-scope-pick="some"]');
    await offWithReason(pickSome, '시스템 규칙은 직접 편집할 수 없습니다');
    await pickSome.click({ force: true });
    await expect(page.locator('[data-part="containers-card"] [data-scope-pick="some"]')).toHaveAttribute('aria-pressed', 'false');
    await ed.getByRole('button', { name: '삭제' }).click({ force: true });
    await expect(page.locator(DIALOG)).toHaveCount(0);
  });

  test('정책 생성 고급 · YAML: 오른쪽 적용 범위 단추는 YAML 의 containers 칸 안내가 사유', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies');
    await page.getByRole('button', { name: '정책 생성' }).click();
    const m = page.locator('dialog[data-part="policy-create"]');
    await m.locator('[data-template="install-registry"]').click();
    await m.locator('[data-mode="yaml"]').click();
    await offWithReason(m.locator('[data-part="containers-card"] [data-scope-pick="all"]'), '고급 · YAML 에서는 YAML 의 containers 칸으로 정합니다');
  });

  test('제안 적용: 미리보기가 없으면 사유 「미리보기를 계산한 뒤 쓸 수 있습니다」', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/500/);
    await page.route(/\/api\/proposals\/[^/]+\/preview$/, fail500);
    await page.goto('/installs?id=ins-0011');
    await page.getByTestId('decision').getByRole('button', { name: '오탐' }).click();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    await page.getByRole('button', { name: '제안 보기' }).click();
    const detail = page.getByTestId('proposal');
    await expect(detail.getByTestId('preview')).toContainText('모의 오류');
    await offWithReason(detail.getByRole('button', { name: '적용', exact: true }), '미리보기를 계산한 뒤 쓸 수 있습니다');
  });

  test('공급망 검사 패키지: 고를 것이 없으면 「모두 고르기」가 사유와 함께 꺼짐', async ({ page, backend }) => {
    void backend;
    const iso = new Date().toISOString();
    const scan: Scan = {
      id: 'scan-0009', status: 'done', startedAt: iso, finishedAt: iso, verdict: 'clean', risk: { score: 0, label: 'no_risks_detected' },
      engines: [{ name: 'GuardDog', version: '3.2.0' }], findings: [], vulns: [], files: {}, caseId: null, threats: 0, capabilities: 0, vulnCount: 0, vulnMax: null,
      target: { kind: 'repo', name: 'app', url: 'https://github.com/o/app', label: 'github.com/o/app' },
      packages: [
        { manager: 'pip', name: 'colourama', version: '0.1', ecosystem: 'PyPI', source: 'requirements.txt', direct: true, vulns: 0 },
        { manager: '', name: 'golang.org/x/text', version: '0.3.0', ecosystem: 'Go', source: 'go.mod', direct: true, vulns: 0 },
      ],
    };
    await page.route(/\/api\/scans(\/|$|\?)/, (route: Route) => {
      const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
      const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
      if (path === '/scans') return json([{ ...scan, packages: null }]);
      return path === `/scans/${scan.id}` ? json(scan) : json({ error: '검사 없음' }, 404);
    });
    await page.goto(`/scans?id=${scan.id}`);
    const sec = page.locator('[data-sheet="scan"] [data-part="packages"]');
    await expect(sec.locator('tr[data-pkg="pip:colourama@0.1"]')).toContainText('차단됨');
    const all = sec.getByLabel('모두 고르기');
    await offWithReason(all, '고를 수 있는 패키지가 없습니다');
    await all.click({ force: true });
    await expect(all).not.toBeChecked();
  });

  test('YAML 일괄 적용: 불러오는 동안 입력 칸은 사유와 함께 꺼짐(초점은 감)', async ({ page, backend }) => {
    void backend;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    await page.route(/\/api\/policies\/export$/, async (route) => {
      await gate;
      await route.fallback();
    });
    await page.goto('/policies?id=__yaml__');
    const area = page.locator('dialog[data-part="bulk-yaml"] textarea[aria-label="전체 정책 YAML"]');
    await offWithReason(area, 'YAML 을 불러온 뒤 쓸 수 있습니다');
    await expect(area).toHaveValue('불러오는 중…');
    release();
    await expect(area).not.toHaveAttribute('aria-disabled', 'true');
    await expect(area).not.toHaveValue('불러오는 중…');
  });
});

test.describe('G19 확인 창 — 제목 「~할까요?」 + 영향 범위 줄', () => {
  test('정책 삭제', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=egress-allowlist');
    await page.locator(ED).getByRole('button', { name: '삭제' }).click();
    const d = page.locator(DIALOG);
    await expect(d.locator('h3')).toHaveText('egress-allowlist 정책을 삭제할까요?');
    await expect(d).toHaveAttribute('aria-label', 'egress-allowlist 정책을 삭제할까요?');
    await expect(d.locator('[data-part="confirm-body"]')).toHaveText(/니다\.$/);
    await expect(d.locator('[data-part="confirm-impact"] li').first()).toBeVisible();
    await expect(d.locator('[data-part="confirm-impact"]')).toContainText('변경 이력에 「정책 삭제」로 남습니다.');
    await expect(d.locator('[data-part="confirm-undo"]')).toContainText('변경 이력');
    await expect(d.locator('[data-part="confirm-effects"]')).toHaveCount(0);
    await expect(d.locator('[data-confirm="ok"]')).toHaveText('삭제');
  });

  test('악성 확정 · 오탐 — 서버 판정 미리보기가 영향 범위 줄', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0012');
    const box = page.getByTestId('decision');
    await box.getByRole('button', { name: '악성 확정' }).click();
    const d = page.locator(DIALOG);
    await expect(d.locator('h3')).toHaveText('pip ./reqeusts 건을 악성으로 확정할까요?');
    await expect(d.locator('[data-part="confirm-body"]')).toContainText('case-0004');
    const fx = d.locator('[data-part="confirm-impact"] li');
    await expect(fx.first()).toHaveText('차단 목록 +2 (패키지 1 · 도메인 1)');
    await expect(fx.first()).toHaveAttribute('data-kind', 'blocklist');
    await expect(d.locator('[data-part="confirm-effects"]')).toHaveCount(0);
    await expect(d.locator('textarea[name="reason"]')).toBeVisible();
    await expect(d.locator('[data-confirm="ok"]')).toHaveText('악성 확정');
    await d.locator('[data-confirm="cancel"]').click();
    await box.getByRole('button', { name: '오탐' }).click();
    await expect(d.locator('h3')).toHaveText('pip ./reqeusts 건을 오탐으로 판정할까요?');
    await expect(d.locator('[data-part="confirm-impact"] li').first()).toBeVisible();
  });

  test('제안 적용 · 버림', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    await page.getByRole('button', { name: '제안 보기' }).click();
    const detail = page.getByTestId('proposal');
    await expect(detail.getByTestId('preview-summary')).toBeVisible();
    await detail.getByRole('button', { name: '적용', exact: true }).click();
    const d = page.locator(DIALOG);
    await expect(d.locator('h3')).toHaveText('pip ./reqeusts 차단 제안을 적용할까요?');
    await expect(d.locator('[data-part="confirm-body"]')).toHaveText(/니다\.$/);
    await expect(d.locator('[data-part="confirm-impact"]')).toContainText('차단 목록 +2 (패키지 1 · 도메인 1)');
    await expect(d.locator('[data-part="confirm-impact"]')).toContainText('과거 위반');
    await d.locator('[data-confirm="cancel"]').click();
    await detail.getByRole('button', { name: '버림', exact: true }).click();
    await expect(d.locator('h3')).toHaveText('pip ./reqeusts 차단 제안을 버릴까요?');
    await expect(d.locator('[data-part="confirm-impact"]')).toContainText('정책 · 차단 목록은 바뀌지 않습니다');
  });
});

test.describe('G20 실패 알림 — 「~하지 못했습니다(…).」 + 할 일', () => {
  test('판정 실패(500)', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/500/);
    await page.route(/\/api\/cases\/[^/]+\/decide$/, fail500);
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    const t = page.locator('[data-toast="decide:case-0004"]');
    await expect(t).toContainText('판정하지 못했습니다(');
    await expect(t).toContainText('모의 오류).');
    await expect(t).toContainText('잠시 뒤 다시 시도하세요.');
    await expect(t).not.toContainText('판정 실패');
  });

  test('제안 적용 실패(500)', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/500/);
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    await page.getByRole('button', { name: '제안 보기' }).click();
    const detail = page.getByTestId('proposal');
    await expect(detail.getByTestId('preview-summary')).toBeVisible();
    await page.route(/\/api\/proposals\/[^/]+\/apply$/, fail500);
    await detail.getByRole('button', { name: '적용', exact: true }).click();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    const t = page.locator('[data-toast^="proposal:"]');
    await expect(t).toContainText('제안을 적용하지 못했습니다(');
    await expect(t).toContainText('모의 오류).');
    await expect(t).toContainText('다시 시도하세요.');
    await expect(t).not.toContainText('적용 실패');
  });
});

test.describe('G24 · G37 아이콘 단추 이름 · 조사', () => {
  test('큰 창 닫기 · 쉬운 설정 값 빼기: title = aria-label(「동작(대상)」)', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=egress-allowlist');
    const chipX = page.locator(`${ED} [data-chip] button`).first();
    const name = await chipX.getAttribute('aria-label');
    expect(name).toMatch(/^빼기\(.+\)$/);
    await expect(chipX).toHaveAttribute('title', name!);

    await page.goto('/policies');
    await page.getByRole('button', { name: '정책 생성' }).click();
    const close = page.locator('dialog[data-part="policy-create"] header').getByRole('button', { name: '닫기' });
    await expect(close).toHaveAttribute('title', '닫기');
  });

  test('「사용 방법」 복사 알림: 한글 뒤 조사(을 · 를)', async ({ page, backend, context }) => {
    void backend;
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/installs');
    await page.getByTestId('page-actions').getByRole('button', { name: '사용 방법' }).click();
    const g = page.locator('[data-part="sginstall-guide"]');
    await g.getByRole('button', { name: '환경 변수 복사' }).click();
    await expect(page.locator('[data-toast="copy"]')).toContainText('환경 변수를 복사했습니다.');
    await g.getByRole('button', { name: '실행 명령 복사' }).click();
    await expect(page.locator('[data-toast="copy"]')).toContainText('실행 명령을 복사했습니다.');
    await expect(page.locator('[data-toast="copy"]')).not.toContainText('(를)');
  });
});

test.describe('화면 사진(1440 밝은 · 어두운, 390 밝은) — 정책 상세 · 확인 창', () => {
  async function shots(page: Page, tag: string) {
    await page.goto('/policies?id=egress-allowlist');
    await expect(page.locator('[data-sheet="policy"]')).toBeVisible();
    await page.waitForTimeout(450);
    await page.screenshot({ path: `${OUT}/${tag}-policy-sheet.png` });
    await page.locator(ED).getByRole('button', { name: '삭제' }).click();
    await expect(page.locator(DIALOG)).toBeVisible();
    await page.screenshot({ path: `${OUT}/${tag}-confirm-delete.png` });
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await expect(page.locator(`${DIALOG} [data-part="confirm-impact"] li`).first()).toHaveAttribute('data-kind', 'blocklist');
    await page.screenshot({ path: `${OUT}/${tag}-confirm-decide.png` });
    await page.keyboard.press('Escape');
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await expect(page.locator('table[data-table="installs"] tbody tr').first()).toBeVisible();
    await page.screenshot({ path: `${OUT}/${tag}-installs.png` });
    await page.goto('/audit');
    await expect(page.locator('table[data-table="audit"] tbody tr').first()).toBeVisible();
    await page.screenshot({ path: `${OUT}/${tag}-audit.png` });
  }
  test('1440 밝은 · 어두운 · 390 밝은', async ({ page, backend }) => {
    test.setTimeout(120_000);
    void backend;
    for (const theme of ['light', 'dark'] as const) {
      await page.addInitScript((t) => localStorage.setItem('supplyguard.theme', t), theme);
      await shots(page, `1440-${theme}`);
    }
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'light'));
    await page.setViewportSize({ width: 390, height: 844 });
    await shots(page, '390-light');
  });
});
