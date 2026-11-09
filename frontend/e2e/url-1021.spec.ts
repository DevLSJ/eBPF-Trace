import type { Page } from '@playwright/test';
import type { Scan } from '../src/lib/types';
import { expect, test, closeSheet } from './fixtures';

// 10/21 목록 필터를 주소에서 뺀다(보안 — 사용자 결정). 주소에는 링크용 값(id · proposal · tab · view, 토폴로지 컨테이너 노드)만.
const FILTER_KEYS = ['status', 'manager', 'kind', 'level', 'normal', 'container', 'action', 'rule', 'since', 'until', 'verdict', 'range', 'tpl', 'intent', 'value', 'default'];
const filterKeysIn = (page: Page) => [...new URL(page.url()).searchParams.keys()].filter((k) => FILTER_KEYS.includes(k));

const now = new Date().toISOString();
const scan = (id: string, verdict: Scan['verdict']): Scan => ({
  id,
  target: { kind: 'package', manager: 'pip', name: `p-${id}`, label: `pip p-${id}` },
  status: 'done', startedAt: now, finishedAt: now, verdict, risk: { score: 0, label: 'no_risks_detected' },
  engines: [{ name: 'GuardDog', version: '3.2.0' }], findings: [], vulns: [], packages: [], files: {},
  caseId: null, threats: 0, capabilities: 0, vulnCount: 0, vulnMax: null,
});
async function scansApi(page: Page) {
  const list = [scan('scan-0001', 'malicious'), scan('scan-0002', 'clean')];
  await page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify(list) }));
}

test.describe('URL 1021 — 목록 필터는 화면 상태로만', () => {
  test('① 각 목록에서 필터를 바꿔도 주소에 필터 키가 없다', async ({ page, backend }) => {
    void backend;
    await scansApi(page);

    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await page.locator('[data-chip="npm"]').click();
    await expect(page.locator('tr[data-install]')).toHaveCount(2);
    await page.locator('tr[data-install]').first().click();
    await expect(page).toHaveURL(/\/installs\?id=/); // 열린 세션(id)은 링크로 남는다
    expect(filterKeysIn(page)).toEqual([]);

    await page.goto('/events');
    await page.locator('[data-filter="kind"]').click(); // 11/09 공통 Select · 검색칸(Enter 로 적용)
    await page.getByRole('option', { name: 'connect', exact: true }).click();
    await page.getByLabel('정상 포함').click();
    await page.getByPlaceholder('컨테이너 이름').fill('pkg');
    await page.getByPlaceholder('컨테이너 이름').press('Enter');
    await expect(page.locator('[data-part="filter-chips"] [data-chip]')).toHaveCount(3);
    expect(filterKeysIn(page)).toEqual([]);

    await page.goto('/audit');
    await page.locator('[data-filter="kind"]').click();
    await page.getByRole('option', { name: 'connect', exact: true }).click();
    await page.locator('[data-filter="action"]').click();
    await page.getByRole('option', { name: '격리 (kill)' }).click();
    await page.getByPlaceholder('정책 ID').fill('egress'); // 11/09 G44: 감사 로그 「규칙」 → 「정책」
    await page.getByPlaceholder('정책 ID').press('Enter');
    await page.getByLabel('기간 시작').fill('2020-01-01T00:00');
    await expect.poll(() => backend.requests.some((r) => r.path.startsWith('/audit?') && r.path.includes('rule=egress') && r.path.includes('action=kill'))).toBe(true);
    expect(filterKeysIn(page)).toEqual([]);

    await page.goto('/scans');
    await page.locator('[data-chip="malicious"]').click();
    await expect(page.locator('tr[data-scan]')).toHaveCount(1);
    expect(filterKeysIn(page)).toEqual([]);

    await page.goto('/topology');
    await page.getByRole('combobox', { name: /^컨테이너/ }).selectOption('pkg-reqeusts');
    await expect(page.getByRole('combobox', { name: /^컨테이너/ })).toHaveValue('pkg-reqeusts');
    expect(filterKeysIn(page)).toEqual([]);

    await page.goto('/');
    await page.locator('[data-section="overview"] [data-range="7d"]').click();
    await expect(page.locator('[data-section="overview"] [data-range="7d"]')).toHaveAttribute('aria-pressed', 'true');
    expect(filterKeysIn(page)).toEqual([]);
  });

  test('② 바깥 링크(알림 · AI 도우미)의 쿼리는 초기 필터로 적용하고 주소에서 지운다', async ({ page, backend }) => {
    // 웹훅 · Slack 알림의 /topology?container=
    await page.goto('/topology?container=pkg-reqeusts');
    await expect(page.getByRole('combobox', { name: /^컨테이너/ })).toHaveValue('pkg-reqeusts');
    await expect(page).toHaveURL(/\/topology$/);
    // AI 도우미 답의 /audit?rule= — 링크용 키(view · id · tab)는 남긴다
    await page.goto('/audit?rule=egress-allowlist&id=200');
    await expect(page.getByPlaceholder('정책 ID')).toHaveValue('egress-allowlist');
    await expect(page).toHaveURL(/\/audit\?id=200$/);
    await expect.poll(() => backend.requests.some((r) => r.path.startsWith('/audit?') && r.path.includes('rule=egress-allowlist'))).toBe(true);
    // 정책 마법사 미리 채우기(예전 북마크)도 한 번 읽고 지운다
    await page.goto('/policies?id=__new__&tpl=protect-secrets');
    await expect(page.getByTestId('editor')).toContainText('비밀 파일 보호');
    await expect(page).toHaveURL(/\/policies\?id=__new__$/);
  });

  test('③ 토폴로지 — 파일 · 도메인 노드 선택은 주소에 안 남고, 컨테이너 노드는 남는다', async ({ page, backend }) => {
    void backend;
    await page.goto('/topology');
    await page.locator('.react-flow__node', { hasText: '/etc/shadow' }).first().click();
    await expect(page.getByTestId('node-detail')).toContainText('/etc/shadow');
    expect(new URL(page.url()).searchParams.has('node')).toBe(false);
    await closeSheet(page); // 11/05 슬라이드 패널: 열린 동안 뒤 화면은 어두운 배경에 가려 눌리지 않는다 — 먼저 닫는다
    await page.locator('.react-flow__node', { hasText: 'cdn.reqeusts-update.test' }).first().click();
    await expect(page.getByTestId('node-detail')).toContainText('cdn.reqeusts-update.test');
    expect(new URL(page.url()).searchParams.has('node')).toBe(false);
    await closeSheet(page); // 11/05 슬라이드 패널: 열린 동안 뒤 화면은 가려진다 — 먼저 닫는다
    await page.locator('.react-flow__node', { hasText: /^pkg-reqeusts/ }).first().click();
    await expect(page).toHaveURL(/\/topology\?node=c%3Apkg-reqeusts$/);
    await expect(page.getByTestId('node-detail')).toContainText('pkg-reqeusts');
    // 예전 북마크의 파일 노드는 선택만 하고 주소에서 지운다
    await page.goto(`/topology?node=${encodeURIComponent('f:pkg-reqeusts:/etc/shadow')}`);
    await expect(page.getByTestId('node-detail')).toContainText('/etc/shadow');
    await expect(page).toHaveURL(/\/topology$/);
  });

  test('④ 화면 안 링크는 필터를 state 로 넘긴다 — 대시보드 카드 → 설치 「전체」 · 감사 「격리」', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    await page.locator('[data-kpi="installs"]').click();
    await expect(page).toHaveURL(/\/installs$/);
    await expect(page.locator('[data-chip="all"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('tr[data-install]')).toHaveCount(8);

    await page.goto('/');
    await page.locator('[data-kpi="isolated"]').click();
    await expect(page).toHaveURL(/\/audit$/);
    await expect(page.locator('[data-filter="action"]')).toHaveAttribute('data-value', 'kill'); // 11/09 공통 Select

    // 사이드바 메뉴는 화면을 처음 연 것처럼(기본 필터)
    await page.locator('nav[aria-label="화면"]').getByRole('link', { name: '감사 로그' }).click();
    await expect(page.locator('[data-filter="action"]')).toHaveAttribute('data-value', ''); // 11/09 공통 Select
  });

  test('⑤ 새로고침하면 기본값 — 직접 고른 필터도, 링크로 받은 필터도', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await page.reload();
    await expect(page.locator('[data-chip="pending"]')).toHaveAttribute('aria-pressed', 'true');

    await page.goto('/');
    await page.locator('[data-section="overview"] [data-range="1h"]').click();
    await expect(page.locator('[data-section="overview"] [data-range="1h"]')).toHaveAttribute('aria-pressed', 'true');
    await page.reload();
    await expect(page.locator('[data-section="overview"] [data-range="24h"]')).toHaveAttribute('aria-pressed', 'true');

    // state 로 받은 필터도 적용 뒤 비우므로 새로고침하면 기본값
    await page.locator('[data-kpi="installs"]').click();
    await expect(page.locator('[data-chip="all"]')).toHaveAttribute('aria-pressed', 'true');
    await page.reload();
    await expect(page.locator('[data-chip="pending"]')).toHaveAttribute('aria-pressed', 'true');

    await page.goto('/topology?container=pkg-reqeusts');
    await expect(page.getByRole('combobox', { name: /^컨테이너/ })).toHaveValue('pkg-reqeusts');
    await expect(page).toHaveURL(/\/topology$/);
    await page.reload();
    await expect(page.getByRole('combobox', { name: /^컨테이너/ })).toHaveValue('');
  });
});
