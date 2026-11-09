import type { Page } from '@playwright/test';
import { checkScreenCopy } from '../src/lib/screenCopy';
import type { Proposal } from '../src/lib/types';
import { ACTOR } from './mock-backend';
import { expect, SHOTS, test } from './fixtures';

// 11/09 정책 화면 분리(사용자 결정 — 사이드바 하위 메뉴 · 정책별 적용 컨테이너 카드 · 범위 전부):
//   「정책」 아래 정책(/policies) · 차단 목록(/policies/blocklist) · 변경 이력(/policies/changes)
//   정책 목록 = 표(상태 맨 앞) + 거르기 · 행 → 시트 탭 [편집 | 차단 이력 | 변경 이력](?id= · ?tab=) · 「정책 생성」 = 큰 2단 창(오른쪽 적용 컨테이너)
//   주소에는 링크용 값(id · proposal · tab)만 — 필터 · 검색 · 쪽 · 정렬은 화면 상태(10/21 결정 유지)
const NAV = 'nav[aria-label="화면"]';
const T = 'table[data-table="policies"]';
const SHEET = '[data-sheet="policy"]';
const OUT = `${SHOTS}/policies-1109`;
const row = (page: Page, id: string) => page.locator(`${T} tbody tr[data-rule="${id}"]`);
const cell = (page: Page, id: string, col: string) => row(page, id).locator(`td[data-col="${col}"]`);
const cols = (page: Page, table: string) => page.locator(`${table} thead th`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.col));
async function pick(page: Page, filter: string, label: string, option: string) {
  await page.locator(`[data-filter="${filter}"]`).click();
  await page.getByRole('listbox', { name: label }).getByRole('option', { name: option, exact: true }).click();
}
const draft = (id: string): Proposal => ({
  id,
  caseId: 'case-0003',
  decision: 'false_positive',
  state: 'draft',
  createdAt: new Date().toISOString(),
  createdBy: ACTOR,
  appliedAt: null,
  appliedBy: null,
  changes: [{ op: 'except', ruleId: 'egress-allowlist', field: 'allowCidrs', value: '140.82.112.3/32' }],
  notes: [],
});

test.describe('① 사이드바 하위 메뉴', () => {
  test('「정책」 아래 정책 · 차단 목록 · 변경 이력 — 지금 화면 표시 · 화면 이름 · 묶음 안 순서 칸은 그대로 3개', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies');
    const sub = page.locator(`${NAV} [data-nav-sub="policies"]`);
    await expect(sub.locator('a')).toHaveText(['정책', '차단 목록', '변경 이력']);
    expect(await sub.locator('a').evaluateAll((els) => els.map((e) => e.getAttribute('href')))).toEqual(['/policies', '/policies/blocklist', '/policies/changes']);
    await expect(sub.locator('a[href="/policies"]')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('page-title')).toHaveText('정책');
    // 묶음 「설정 · 기록」의 옮길 수 있는 칸 = 정책 묶음 · 감사 로그 · 설정(하위 메뉴는 묶음째 옮긴다)
    await expect(page.locator(`${NAV} [data-nav-group="설정 · 기록"] > [data-sort-id]`)).toHaveCount(3);
    await expect(page.locator(`${NAV} [data-nav-group="설정 · 기록"] > [data-sort-id="policies"]`)).toHaveAttribute('data-nav-sub', 'policies');

    await sub.getByRole('link', { name: '차단 목록' }).click();
    await expect(page).toHaveURL(/\/policies\/blocklist$/);
    await expect(page.getByTestId('page-title')).toHaveText('차단 목록');
    await expect(sub.locator('a[href="/policies/blocklist"]')).toHaveAttribute('aria-current', 'page');
    await expect(sub.locator('a[href="/policies"]')).not.toHaveAttribute('aria-current', 'page');
    await sub.getByRole('link', { name: '변경 이력' }).click();
    await expect(page).toHaveURL(/\/policies\/changes$/);
    await expect(page.getByTestId('page-title')).toHaveText('변경 이력');
  });

  test('접힌 사이드바: 하위 메뉴만 겹쳐 뜸(잠깐 기다린 뒤) · 고르면 이동', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await page.getByRole('button', { name: '사이드바 접기' }).click();
    await expect(page.locator('[data-part="sidebar"]')).toHaveAttribute('data-collapsed', 'true');
    const sub = page.locator(`${NAV} [data-nav-sub="policies"]`);
    const pop = page.locator('[data-part="subnav-pop"]');
    await expect(pop).toHaveCount(0);
    await sub.hover();
    await expect(pop).toBeVisible();
    await expect(pop.locator('a')).toHaveText(['정책', '차단 목록', '변경 이력']);
    await pop.getByRole('link', { name: '변경 이력' }).click();
    await expect(page).toHaveURL(/\/policies\/changes$/);
    // 키보드: 묶음 칸에 초점 → 하위 메뉴가 뜨고 Tab 으로 닿는다
    await page.mouse.move(900, 500);
    await expect(pop).toHaveCount(0);
    await sub.focus();
    await expect(pop).toBeVisible();
  });

  test('768 미만: 서랍에 하위 메뉴 · 고르면 이동하고 서랍이 닫힘', async ({ page, backend }) => {
    void backend;
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await page.getByRole('button', { name: '메뉴', exact: true }).click();
    const sub = page.locator(`${NAV} [data-nav-sub="policies"]`);
    await expect(sub.locator('a')).toHaveText(['정책', '차단 목록', '변경 이력']);
    await sub.getByRole('link', { name: '차단 목록' }).click();
    await expect(page).toHaveURL(/\/policies\/blocklist$/);
    await expect(page.locator('[data-part="sidebar"]')).toHaveCount(0);
  });
});

test.describe('② 옛 주소 · 링크용 값만 주소에', () => {
  test('/policies 는 시트 없이 목록 · ?id= 는 정책 시트(편집 탭) · ?proposal= 는 제안 시트 · 제안 띠 → 제안 시트', async ({ page, backend }) => {
    backend.proposals.push(draft('prop-0901'));
    await page.goto('/policies');
    await expect(row(page, 'sensitive-files')).toBeVisible();
    await expect(page.locator('.sg-sheet-layer')).toHaveCount(0);
    await expect(page).toHaveURL(/\/policies$/);

    await page.goto('/policies?id=egress-allowlist');
    const sheet = page.locator(SHEET);
    await expect(sheet).toBeVisible();
    await expect(sheet.getByRole('tab', { name: '편집' })).toHaveAttribute('aria-selected', 'true');
    await expect(sheet.locator('[data-view="rule-editor"]')).toBeVisible();
    await expect(page).toHaveURL(/\/policies\?id=egress-allowlist$/);

    await page.goto('/policies?proposal=prop-0901');
    await expect(page.locator('[data-sheet="proposal"]')).toBeVisible();
    await expect(page.getByTestId('proposal').getByTestId('proposal-changes')).toContainText('egress-allowlist');
    await page.keyboard.press('Escape');
    await expect(page).toHaveURL(/\/policies$/);
    const band = page.getByTestId('proposals');
    await expect(band).toContainText('적용 대기 제안 1건');
    await band.locator('[data-proposal="prop-0901"]').click();
    await expect(page).toHaveURL(/\/policies\?proposal=prop-0901$/);
    await expect(page.locator('[data-sheet="proposal"]')).toBeVisible();
  });
});

test.describe('③ 정책 목록 표', () => {
  test('화면 설명 · 버튼 · 칸(상태 맨 앞 · 두 줄 정책 · 적용 컨테이너 · 마지막 위반 · 마지막 수정) · 숨김 칸 · 쪽 넘김 · 표 아래 안내', async ({ page, backend }) => {
    backend.seedPolicyHistory();
    backend.rules = backend.rules.map((r) => (r.id === 'no-shell-download' ? { ...r, dryRun: true } : r.id === 'pipe-to-shell' ? { ...r, disabled: true } : r));
    await page.goto('/policies');
    await expect(page.locator('[data-part="screen-copy"]')).toHaveText('컨테이너 행동을 판정하는 정책을 만들고 적용 범위를 관리합니다.');
    await expect(page.getByRole('button', { name: '정책 생성' })).toHaveClass(/sg-btn-primary/);
    await expect(page.getByRole('button', { name: 'YAML 일괄 적용' })).toHaveClass(/sg-btn-secondary/);
    await expect(row(page, 'sensitive-files')).toBeVisible();
    expect(await cols(page, T)).toEqual(['status', 'policy', 'kind', 'action', 'containers', 'lastHit', 'updated']);
    await expect(page.locator(`${T} thead th`)).toHaveText(['상태', '정책', '종류', '판정', '적용 컨테이너', '마지막 위반', '마지막 수정']);
    await expect(page.locator(`${T} tbody tr`)).toHaveCount(backend.rules.length);
    await expect(cell(page, 'sensitive-files', 'status')).toHaveText('사용 중');
    await expect(cell(page, 'no-shell-download', 'status')).toHaveText('시험 운영');
    await expect(cell(page, 'pipe-to-shell', 'status')).toHaveText('사용 안 함');
    await expect(cell(page, 'sensitive-files', 'policy').locator('.tk-2l-top')).toHaveText('자격 증명·계정 파일 접근');
    await expect(cell(page, 'sensitive-files', 'policy').locator('.tk-2l-sub')).toHaveText('sensitive-files');
    await expect(cell(page, 'sensitive-files', 'kind')).toHaveText('파일');
    await expect(cell(page, 'sensitive-files', 'action')).toHaveText('격리');
    await expect(cell(page, 'egress-allowlist', 'action')).toHaveText('경고');
    await expect(cell(page, 'sensitive-files', 'containers')).toHaveText('모든 컨테이너');
    await expect(cell(page, 'sandbox-egress', 'containers')).toHaveText('설치 검사');
    await expect(row(page, 'blocklist-hosts').locator('[data-system]')).toBeVisible();
    // 마지막 위반 = 감사 로그 기준(없으면 빈 칸) · 마지막 수정 = updatedAt(없으면 빈 칸), 현황 시각 MM-DD HH:mm
    const hit = new Set(backend.audit.map((a) => a.ruleId));
    const noHit = backend.rules.find((r) => !hit.has(r.id))!;
    expect(hit.has('sensitive-files')).toBe(true);
    await expect(cell(page, 'sensitive-files', 'lastHit')).toHaveText(/^\d{2}-\d{2} \d{2}:\d{2}$/);
    await expect(cell(page, noHit.id, 'lastHit')).toHaveText('');
    await expect(cell(page, 'sensitive-files', 'updated')).toHaveText(/^\d{2}-\d{2} \d{2}:\d{2}$/);
    await expect(cell(page, 'sandbox-secrets', 'updated')).toHaveText('');
    // 숨김 칸: 조건 요약 · 출처 · 수정자
    await page.locator('[data-table-tools="policies"] [data-action="table-columns"]').click();
    const picker = page.locator('[data-part="column-picker"]');
    for (const n of ['조건 요약', '출처', '수정자']) await expect(picker.getByRole('checkbox', { name: n })).not.toBeChecked();
    await picker.getByRole('checkbox', { name: '수정자' }).check();
    await page.keyboard.press('Escape');
    await expect(cell(page, 'sensitive-files', 'by')).toHaveText(ACTOR);
    await expect(page.locator('[data-table-tools="policies"] [data-part="total"]')).toHaveText(`총 ${backend.rules.length}건`);
    await expect(page.locator('[data-table-foot="policies"] [data-part="range"]')).toHaveText(`총 ${backend.rules.length}건 · 1/1 페이지`);
    await expect(page.locator('[data-part="screen-note"]')).toHaveText(/[^.…]\.$/);
  });

  test('거르기: 검색(정책 ID · 설명, Enter) · 종류 · 판정(사용 안 함 포함) · 적용 범위 · 「○○ 전체」 · 조건 지우기 — 주소에는 남기지 않음', async ({ page, backend }) => {
    backend.rules = backend.rules.map((r) => (r.id === 'pipe-to-shell' ? { ...r, disabled: true } : r));
    await page.goto('/policies');
    const ids = () => page.locator(`${T} tbody tr[data-rule]`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.rule));
    const search = page.getByRole('searchbox', { name: '정책 검색' });
    await expect(search).toHaveAttribute('placeholder', '정책 ID · 설명');
    await search.fill('자격');
    await search.press('Enter');
    expect(await ids()).toEqual(['sensitive-files']);
    await search.fill('');
    await search.press('Enter');
    await expect(page.locator('[data-filter="rkind"]')).toHaveText('종류 전체');
    await pick(page, 'rkind', '종류', '실행');
    expect(await ids()).toEqual(['no-shell-download', 'pipe-to-shell']);
    await pick(page, 'act', '판정', '사용 안 함');
    expect(await ids()).toEqual(['pipe-to-shell']);
    await page.locator('[data-action="clear-conditions"]').click();
    await pick(page, 'scope', '적용 범위', '설치 검사');
    expect(await ids()).toEqual(['sandbox-egress', 'sandbox-secrets']);
    await expect(page).toHaveURL(/\/policies$/);
    await page.locator('[data-action="clear-conditions"]').click();
    await expect(page.locator(`${T} tbody tr`)).toHaveCount(backend.rules.length);
    // 결과 없음
    await search.fill('없는-정책');
    await search.press('Enter');
    await expect(page.locator('[data-part="no-results"]')).toContainText('조건에 맞는 데이터가 없습니다');
  });
});

test.describe('④ 정책 상세 시트', () => {
  test('행 클릭 → 머리(ID · 판정 · 종류) · 탭 [편집 | 차단 이력 | 변경 이력] · 주소 ?id= · ?tab=', async ({ page, backend }) => {
    backend.seedPolicyHistory();
    await page.goto('/policies');
    await row(page, 'sensitive-files').click();
    const sheet = page.locator(SHEET);
    await expect(sheet).toBeVisible();
    await expect(page).toHaveURL(/\/policies\?id=sensitive-files$/);
    await expect(sheet.locator('h2')).toHaveText('sensitive-files');
    await expect(sheet.locator('[data-part="sheet-badges"]')).toContainText('격리');
    await expect(sheet.locator('[data-part="sheet-badges"]')).toContainText('파일');
    await expect(sheet.getByRole('tab')).toHaveText(['편집', '차단 이력', '변경 이력']);
    await expect(sheet.getByTestId('editor').locator('[data-view="rule-editor"]')).toBeVisible();
    await sheet.getByRole('tab', { name: /^차단 이력/ }).click();
    await expect(page).toHaveURL(/\/policies\?id=sensitive-files&tab=blocks$/);
    await sheet.getByRole('tab', { name: /^변경 이력/ }).click();
    await expect(page).toHaveURL(/\/policies\?id=sensitive-files&tab=changes$/);
    await page.reload();
    await expect(page.locator(SHEET).getByRole('tab', { name: /^변경 이력/ })).toHaveAttribute('aria-selected', 'true');
  });

  test('시스템 규칙은 편집 탭이 읽기 전용 안내 + 차단 목록으로 가는 링크', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies?id=blocklist-hosts');
    const sheet = page.locator(SHEET);
    await expect(sheet.getByTestId('system-rule')).toContainText('차단 목록');
    await sheet.getByTestId('system-rule').getByRole('link', { name: '차단 목록' }).click();
    await expect(page).toHaveURL(/\/policies\/blocklist$/);
  });

  test('차단 이력: GET /api/audit?rule= 완전 일치 · 시각(초까지) · 컨테이너 · 결과 · 요약 · 행 → 감사 로그', async ({ page, backend }) => {
    const base = backend.audit.find((a) => a.ruleId === 'sensitive-files')!;
    // 이름이 겹치는 다른 정책의 기록 — 섞이면 안 된다(백엔드는 rule_id 완전 일치)
    backend.audit.push({ ...base, id: 1, ruleId: 'sensitive-files-extra' });
    const mine = backend.audit.filter((a) => a.ruleId === 'sensitive-files');
    await page.goto('/policies?id=sensitive-files&tab=blocks');
    const hits = page.locator(`${SHEET} [data-testid="policy-hits"]`);
    await expect(hits.locator('tbody tr[data-audit]')).toHaveCount(mine.length);
    expect(await cols(page, `${SHEET} [data-testid="policy-hits"] table`)).toEqual(['at', 'container', 'result', 'detail']);
    await expect(hits.locator('tbody tr[data-audit="1"]')).toHaveCount(0);
    await expect(hits.locator('tbody tr td[data-col="at"]').first()).toHaveText(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    const r = backend.requests.find((x) => x.method === 'GET' && x.path.startsWith('/audit?') && x.path.includes('rule=sensitive-files'))!;
    expect(new URLSearchParams(r.path.split('?')[1]).get('rule')).toBe('sensitive-files');
    expect(new URLSearchParams(r.path.split('?')[1]).get('offset')).toBe('0');
    await expect(page.locator(`${SHEET} [role="tab"][aria-selected="true"]`)).toHaveText('차단 이력');
    await expect(page.locator(`${SHEET} [data-table-foot="policy-hits"] [data-part="range"]`)).toHaveText(`총 ${mine.length}건 · 1/1 페이지`);
    await hits.locator(`tbody tr[data-audit="${mine[0].id}"]`).click();
    await expect(page).toHaveURL(new RegExp(`/audit\\?id=${mine[0].id}$`));
  });

  test('변경 이력: 이 정책 것만(GET /api/changes?rule=) · 동작 태그 색 = 끝말 · 바뀐 값 「이전 → 새 값」 펼침 · 되돌리기는 변경 전 값이 있을 때만', async ({ page, backend }) => {
    backend.seedPolicyHistory();
    await page.goto('/policies?id=sensitive-files&tab=changes');
    const list = page.locator(`${SHEET} [data-testid="policy-changes"]`);
    await expect(list.locator('[data-change]')).toHaveCount(2);
    expect(await list.locator('[data-change]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.change))).toEqual(['chg-0012', 'chg-0011']);
    const r = backend.requests.find((x) => x.method === 'GET' && x.path.startsWith('/changes?') && x.path.includes('rule=sensitive-files'))!;
    expect(new URLSearchParams(r.path.split('?')[1]).get('offset')).toBe('0');
    const tag = (id: string) => list.locator(`[data-change="${id}"] [data-part="action-tag"]`);
    await expect(tag('chg-0012')).toHaveText('정책 수정');
    await expect(tag('chg-0012')).toHaveClass(/sg-pill-warn/);
    await expect(tag('chg-0011')).toHaveText('정책 생성');
    await expect(tag('chg-0011')).toHaveClass(/sg-pill-ok/);
    await expect(list.locator('[data-change="chg-0012"]')).toContainText('격리로 올림');
    await list.locator('[data-change="chg-0012"] [data-action="change-expand"]').click();
    const diff = list.locator('[data-change="chg-0012"] [data-part="change-diff"]');
    await expect(diff.locator('[data-field="action"]')).toContainText('경고 → 격리');
    await expect(diff.locator('[data-field="denyPaths"]')).toContainText('/etc/shadow → /etc/shadow · /root/.ssh/ · /home/*/.ssh/*');
    await expect(list.getByRole('button', { name: '되돌리기(chg-0012)' })).toBeVisible();
    await expect(list.getByRole('button', { name: '되돌리기(chg-0011)' })).toHaveCount(0); // 만든 기록 — 변경 전 값 없음
  });

  test('되돌리기: 확인 창(「~할까요?」 · 영향 · 사유 필수 · 확인 체크) → POST {changeId, reason} · 토스트 · 이력에 「정책 되돌림」 · 서버 오류 문장 그대로', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 404/); // 일부러 낸 404(되돌리기 거절)
    backend.seedPolicyHistory();
    await page.goto('/policies?id=sensitive-files&tab=changes');
    const list = page.locator(`${SHEET} [data-testid="policy-changes"]`);
    await list.getByRole('button', { name: '되돌리기(chg-0012)' }).click();
    const d = page.locator('dialog[data-part="confirm"]');
    await expect(d.locator('h3')).toHaveText('정책 sensitive-files 을(를) 되돌릴까요?');
    await expect(d.locator('[data-part="confirm-body"]')).toContainText('변경 이전 값으로');
    await expect(d.locator('[data-part="confirm-impact"]')).toContainText('판정: 격리 → 경고');
    const ok = d.locator('[data-confirm="ok"]');
    await expect(ok).toHaveText('되돌리기');
    await expect(ok).toHaveAttribute('aria-disabled', 'true');
    await expect(ok).toHaveAttribute('title', '사유를 입력하세요');
    await d.getByRole('textbox', { name: '사유' }).fill('  오탐 증가  ');
    await expect(ok).toHaveAttribute('title', '확인 칸을 먼저 고르세요');
    await ok.click({ force: true }); // 꺼진 단추(aria-disabled)는 눌러도 아무 일 없음
    expect(backend.requests.filter((x) => x.path.endsWith('/revert'))).toHaveLength(0);
    await d.getByRole('checkbox', { name: '되돌리면 엔진에 바로 적용됨을 확인했습니다' }).check();
    await expect(ok).not.toHaveAttribute('aria-disabled', 'true');
    await ok.click();
    await expect(page.locator('[data-toast]').filter({ hasText: '정책 sensitive-files 을(를) 되돌렸습니다.' })).toBeVisible();
    const w = backend.requests.find((x) => x.method === 'POST' && x.path === '/policies/sensitive-files/revert')!;
    expect(JSON.parse(w.body!)).toEqual({ changeId: 'chg-0012', reason: '오탐 증가' });
    expect(backend.rules.find((x) => x.id === 'sensitive-files')!.action).toBe('alert');
    await expect(list.locator('[data-change]').first().locator('[data-part="action-tag"]')).toHaveText('정책 되돌림');
    await expect(list.locator('[data-change]').first()).toContainText('오탐 증가');
    // 서버 거절(404) — 서버 문장 그대로
    await page.route(/\/api\/policies\/[^/]+\/revert$/, (r) => r.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: '변경 기록 없음' }) }));
    await list.getByRole('button', { name: /^되돌리기\(/ }).first().click();
    await d.getByRole('textbox', { name: '사유' }).fill('다시');
    await d.getByRole('checkbox').check();
    await ok.click();
    await expect(page.locator('[data-toast]').filter({ hasText: '되돌리지 못했습니다(변경 기록 없음).' })).toBeVisible();
  });

  test('조회자: 정책 생성 · YAML 일괄 적용 · 되돌리기 · 해제 단추를 그리지 않음', async ({ page, backend }) => {
    backend.seedPolicyHistory();
    backend.auth.asViewer();
    await page.goto('/policies?id=sensitive-files&tab=changes');
    await expect(page.locator(`${SHEET} [data-change]`).first()).toBeVisible();
    await expect(page.getByRole('button', { name: '정책 생성' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'YAML 일괄 적용' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^되돌리기/ })).toHaveCount(0);
    await page.goto('/policies/blocklist');
    await expect(page.locator('[data-testid="blocklist"] tbody tr[data-block]').first()).toBeVisible();
    await expect(page.getByRole('button', { name: /^해제/ })).toHaveCount(0);
  });
});

test.describe('⑤ 정책 생성 2단 창', () => {
  test('왼쪽 템플릿 → 정책 입력, 오른쪽 적용 컨테이너 카드(모든 · 설치 검사 · 지정) · 지정 0개면 저장 막음 · 실행 중 컨테이너 고르기 · 패턴 칩 · 일치 수 · 격리 보류', async ({ page, backend }) => {
    await page.goto('/policies');
    await page.getByRole('button', { name: '정책 생성' }).click();
    const m = page.locator('dialog[data-part="policy-create"]');
    await expect(m).toHaveAttribute('data-size', 'xl');
    await expect(m.locator('h3').first()).toHaveText('정책 생성');
    await m.locator('[data-template="protect-secrets"]').click();
    const main = m.locator('[data-part="modal-main"]');
    const side = m.locator('[data-part="modal-side"]');
    await expect(main.locator('[data-view="rule-editor"]')).toBeVisible();
    const card = side.locator('[data-part="containers-card"]');
    await expect(card).toBeVisible();
    const [mb, sb] = await Promise.all([main.boundingBox(), side.boundingBox()]);
    expect(mb!.x + mb!.width).toBeLessThanOrEqual(sb!.x + 1);
    expect(sb!.width).toBeGreaterThanOrEqual(340);
    expect(sb!.width).toBeLessThanOrEqual(460);
    // 쉬운 설정의 「어디에」는 오른쪽 카드로 옮김
    await expect(main.locator('[data-step="scope"]')).toHaveCount(0);
    await expect(main.locator('[data-step="name"] [data-required]')).toBeVisible();
    await expect(card.locator('[data-scope-pick="all"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(card.locator('[data-part="scope-summary"]')).toContainText(`지금 실행 중 ${backend.integration.containers.length}개`);

    await card.locator('[data-scope-pick="some"]').click();
    await expect(card.locator('[data-part="containers-error"]')).toHaveText('적용 컨테이너를 1개 이상 고르세요.');
    await expect(card.locator('[data-part="containers-error"]')).toHaveAttribute('role', 'alert');
    // 바닥 줄(취소 · 저장 전 확인)
    const save = m.locator('[data-part="modal-foot"]').getByRole('button', { name: '저장 전 확인' });
    await expect(m.locator('[data-part="modal-foot"] [data-action="form-cancel"]')).toHaveText('취소');
    await expect(save).toHaveAttribute('aria-disabled', 'true');
    await expect(save).toHaveAttribute('title', '적용 컨테이너를 1개 이상 고르세요');
    await save.click({ force: true });
    await expect(main.locator('[data-part="save-check"]')).toHaveCount(0);

    await card.locator('[data-part="running-list"]').getByRole('checkbox', { name: 'web-api' }).check();
    const web = card.locator('[data-entry="web-api"]');
    await expect(web.locator('[data-part="match-count"]')).toHaveText('지금 일치 1개');
    await expect(web.locator('[data-part="entry-status"]')).toContainText('감시 중');
    await expect(web.locator('[data-part="entry-status"]')).toContainText('격리 보류');
    const pat = card.getByRole('textbox', { name: '이름 패턴' });
    await expect(pat).toHaveAttribute('placeholder', /^예: /);
    await pat.fill('pkg-*');
    await pat.press('Enter');
    const pkg = card.locator('[data-entry="pkg-*"]');
    await expect(pkg.locator('[data-part="match-count"]')).toHaveText('지금 일치 1개');
    await expect(pkg.locator('[data-part="entry-status"]')).toContainText('격리 가능');
    await pat.fill('none-*');
    await pat.press('Enter');
    await expect(card.locator('[data-entry="none-*"] [data-part="match-count"]')).toHaveText('지금 일치 0개');
    await card.locator('[data-entry="none-*"]').getByRole('button', { name: '빼기(none-*)' }).click();
    await expect(card.locator('[data-part="containers-error"]')).toHaveCount(0);
    await expect(save).not.toHaveAttribute('aria-disabled', 'true');
    await page.screenshot({ path: `${OUT}/1440-create-light.png` });

    await save.click();
    await main.locator('[data-part="save-check"]').getByRole('button', { name: '저장 후 적용' }).click();
    const w = backend.writes().find((r) => r.method === 'POST' && r.path === '/policies')!;
    const body = JSON.parse(w.body!) as Record<string, unknown>;
    expect(body.containers).toEqual(['web-api', 'pkg-*']);
    expect(body).not.toHaveProperty('updatedAt');
    await expect(m).toHaveCount(0);
    await expect(page).toHaveURL(/\/policies\?id=protect-secrets$/);
    await expect(page.locator(SHEET)).toBeVisible();
  });

  test('바꾼 값이 있으면 닫을 때 확인(계속 편집 · 버리고 닫기) · YAML 일괄 적용은 큰 창', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies');
    await page.getByRole('button', { name: '정책 생성' }).click();
    const m = page.locator('dialog[data-part="policy-create"]');
    await m.locator('[data-template="no-downloader"]').click();
    await m.locator('[data-view="rule-editor"] input[data-field="description"]').fill('바꾼 설명');
    await page.keyboard.press('Escape');
    const ask = page.locator('dialog[data-part="unsaved"]');
    await expect(ask).toBeVisible();
    await ask.getByRole('button', { name: '버리고 닫기' }).click();
    await expect(m).toHaveCount(0);
    await page.getByRole('button', { name: 'YAML 일괄 적용' }).click();
    const y = page.locator('dialog[data-part="bulk-yaml"]');
    await expect(y).toBeVisible();
    await expect(y.locator('textarea[aria-label="전체 정책 YAML"]')).toBeVisible();
    await expect(page).toHaveURL(/\/policies\?id=__yaml__$/);
  });
});

test.describe('⑥ 차단 목록 · 변경 이력 페이지', () => {
  test('차단 목록: 표(종류 · 값 · 차단 시각 · 처리자 · 근거 건) · 종류 거르기 · 해제(확인 창 · 사유) · 토스트', async ({ page, backend }) => {
    await page.goto('/policies/blocklist');
    const t = page.getByTestId('blocklist');
    await expect(t.locator('tbody tr[data-block]')).toHaveCount(2);
    expect(await cols(page, '[data-testid="blocklist"] table')).toEqual(['list', 'value', 'at', 'by', 'case', 'act']);
    await expect(t.locator('tr[data-block="packages:pip:colourama"] td[data-col="list"]')).toHaveText('패키지');
    await expect(t.locator('tr[data-block="packages:pip:colourama"] td[data-col="at"]')).toHaveText(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    await pick(page, 'list', '종류', '도메인');
    await expect(t.locator('tbody tr[data-block]')).toHaveCount(1);
    await t.locator('tr[data-block="hosts:cdn.colourama.test"]').getByRole('button', { name: /^해제/ }).click();
    const d = page.locator('dialog[data-part="confirm"]');
    await expect(d.locator('h3')).toHaveText('cdn.colourama.test 차단을 해제할까요?');
    await expect(d.locator('[data-part="confirm-impact"]')).toContainText('blocklist-hosts');
    await d.getByRole('textbox', { name: /사유/ }).fill('오탐');
    await d.locator('[data-confirm="ok"]').click();
    await expect(page.locator('[data-toast]').filter({ hasText: 'cdn.colourama.test 차단을 해제했습니다.' })).toBeVisible();
    expect(backend.requests.some((r) => r.method === 'DELETE' && r.path.startsWith('/blocklist/hosts/'))).toBe(true);
    await expect(t.locator('tr[data-block="hosts:cdn.colourama.test"]')).toHaveCount(0);
  });

  test('변경 이력: 시각 먼저 · 동작 태그 색 · 대상 정책 → 그 정책의 변경 이력 탭 · 종류 거르기 · 줄 펼침 · 되돌리기 없음 + 안내', async ({ page, backend }) => {
    backend.seedPolicyHistory();
    await page.goto('/policies/changes');
    const t = page.getByTestId('changes');
    await expect(t.locator('tbody tr[data-change]')).toHaveCount(backend.changes.length);
    expect(await cols(page, '[data-testid="changes"] table')).toEqual(['at', 'action', 'target', 'by', 'summary']);
    const tag = (id: string) => t.locator(`tr[data-change="${id}"] [data-part="action-tag"]`);
    await expect(tag('chg-0013')).toHaveText('제안 적용');
    await expect(tag('chg-0013')).toHaveClass(/sg-pill-info/);
    await expect(tag('chg-0014')).toHaveText('시연 실행');
    await expect(tag('chg-0014')).toHaveClass(/sg-pill-neutral/);
    await expect(tag('chg-0011')).toHaveText('정책 생성');
    await expect(t.locator('tr[data-change="chg-0013"] td[data-col="at"]')).toHaveText(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    await t.locator('tr[data-change="chg-0013"] [data-action="change-expand"]').click();
    await expect(t.locator('[data-part="change-diff"][data-for="chg-0013"] [data-field="allowCidrs"]')).toContainText('10.0.0.0/8 → 10.0.0.0/8 · 140.82.112.3/32');
    await expect(page.getByRole('button', { name: /^되돌리기/ })).toHaveCount(0);
    await expect(page.locator('[data-part="screen-note"]')).toHaveText('되돌리기는 정책 상세의 변경 이력에서 합니다.');
    await pick(page, 'kind', '종류', '제안 적용');
    expect(await t.locator('tbody tr[data-change]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.change))).toEqual(['chg-0001', 'chg-0013']); // 시각 내림차순(chg-0001 이 더 최근)
    await t.locator('tr[data-change="chg-0013"] td[data-col="target"]').getByRole('link', { name: 'egress-allowlist' }).click();
    await expect(page).toHaveURL(/\/policies\?id=egress-allowlist&tab=changes$/);
    await expect(page.locator(SHEET).getByRole('tab', { name: /^변경 이력/ })).toHaveAttribute('aria-selected', 'true');
  });
});

test.describe('⑤-2 적용 컨테이너 패턴 = 백엔드 appliesTo(Go path.Match) 규칙', () => {
  test('* · ? 는 「/」를 넘지 않음 · [..] 묶음(^ 부정 · 범위) · \\ 그대로 · 틀린 패턴은 아무것도 안 맞음 · 이름 또는 이미지', async () => {
    const { globMatch, containerMatches } = await import('../src/features/policies/glob');
    // Go path.Match 문서 · 시험 벡터에서 고른 것(+ 이 제품에서 자주 쓰는 모양)
    const cases: [string, string, boolean][] = [
      ['abc', 'abc', true], ['*', 'abc', true], ['*c', 'abc', true], ['a*', 'a', true], ['a*', 'abc', true], ['a*', 'ab/c', false],
      ['a*/b', 'abc/b', true], ['a*/b', 'a/c/b', false], ['a*b*c*d*e*/f', 'axbxcxdxe/f', true], ['a*b?c*x', 'abxbbxdbxebxczzx', true], ['a*b?c*x', 'abxbbxdbxebxczzy', false],
      ['ab[c]', 'abc', true], ['ab[b-d]', 'abc', true], ['ab[e-g]', 'abc', false], ['ab[^c]', 'abc', false], ['ab[^b-d]', 'abc', false], ['ab[^e-g]', 'abc', true],
      ['a\\*b', 'a*b', true], ['a\\*b', 'ab', false], ['a?b', 'a☺b', true], ['a[^a]b', 'a☺b', true], ['a???b', 'a☺b', false], ['*x', 'xxx', true],
      ['[', 'a', false], ['a[', 'a', false], ['a\\', 'a', false],
      ['sg-install-*', 'sg-install-pip-1792040610-0012', true], ['python*', 'docker.io/library/python:3', false], ['python*', 'python:3.12-slim', true],
    ];
    for (const [pat, s, want] of cases) expect(globMatch(pat, s), `${pat} ~ ${s}`).toBe(want);
    expect(containerMatches('node:*', { name: 'web-api', image: 'node:22-alpine' })).toBe(true);
    expect(containerMatches('web-*', { name: 'web-api', image: 'node:22-alpine' })).toBe(true);
    expect(containerMatches('worker', { name: 'web-api', image: 'node:22-alpine' })).toBe(false);
  });
});

test.describe('⑦ 화면 문구', () => {
  test('세 화면 설명 한 줄은 「니다.」로 끝나는 20~50자 · 마침표 앞 기호 없음 · 표 아래 안내 한 줄', async ({ page, backend }) => {
    void backend;
    for (const path of ['/policies', '/policies/blocklist', '/policies/changes']) {
      await page.goto(path);
      const copy = (await page.locator('[data-part="screen-copy"]').textContent()) ?? '';
      expect(checkScreenCopy(copy), `${path}: ${copy}`).toEqual([]);
      await expect(page.locator('[data-part="screen-note"]'), path).toHaveText(/[^.…]\.$/);
    }
  });
});

test.describe('⑧ 화면 사진(1440 밝은 · 어두운, 390 밝은)', () => {
  test('목록 · 상세 각 탭 · 생성 창 · 차단 목록 · 변경 이력', async ({ page, backend }) => {
    test.setTimeout(180_000); // 사진 17장
    backend.seedPolicyHistory();
    for (const theme of ['light', 'dark'] as const) {
      await page.addInitScript((t) => localStorage.setItem('supplyguard.theme', t), theme);
      await page.goto('/policies');
      await expect(row(page, 'sensitive-files')).toBeVisible();
      await page.screenshot({ path: `${OUT}/1440-list-${theme}.png` });
      for (const tab of ['', 'blocks', 'changes']) {
        await page.goto(`/policies?id=sensitive-files${tab ? `&tab=${tab}` : ''}`);
        await expect(page.locator(SHEET)).toBeVisible();
        await page.waitForTimeout(400);
        await page.screenshot({ path: `${OUT}/1440-sheet-${tab || 'edit'}-${theme}.png` });
      }
      await page.goto('/policies');
      await page.getByRole('button', { name: '정책 생성' }).click();
      await page.locator('dialog[data-part="policy-create"] [data-template="install-registry"]').click();
      await expect(page.locator('[data-part="containers-card"]')).toBeVisible();
      await page.screenshot({ path: `${OUT}/1440-create-${theme}.png` });
      await page.goto('/policies/blocklist');
      await expect(page.getByTestId('blocklist').locator('tbody tr').first()).toBeVisible();
      await page.screenshot({ path: `${OUT}/1440-blocklist-${theme}.png` });
      await page.goto('/policies/changes');
      await expect(page.getByTestId('changes').locator('tbody tr').first()).toBeVisible();
      await page.screenshot({ path: `${OUT}/1440-changes-${theme}.png` });
    }
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'light'));
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/policies');
    await expect(row(page, 'sensitive-files')).toBeVisible();
    await page.screenshot({ path: `${OUT}/390-list-light.png` });
    await page.goto('/policies?id=sensitive-files');
    await expect(page.locator(SHEET)).toBeVisible();
    await page.screenshot({ path: `${OUT}/390-sheet-light.png` });
  });
});

test.describe('통합 검색 — 차단 목록 결과는 차단 목록 화면으로(11/09 메인)', () => {
  test('차단된 패키지 · 도메인 결과를 누르면 /policies/blocklist', async ({ page, backend }) => {
    void backend;
    // 검색 칸은 공급망 검사 목록도 읽는다 — mock-backend 에 /api/scans 가 없어 w19 처럼 여기서 빈 목록을 준다
    await page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
    await page.goto('/');
    const box = page.getByRole('combobox', { name: /통합 검색/ });
    for (const q of ['colourama', 'cdn.colourama.test']) {
      await box.fill(q);
      const hit = page.locator('[data-part="search-results"] [role="option"]').filter({ hasText: '차단 목록' }).first();
      await expect(hit).toBeVisible();
      await hit.click();
      await expect(page).toHaveURL(/\/policies\/blocklist(\?|$)/);
      await page.goto('/');
    }
  });
});
