import { readFileSync } from 'node:fs';
import type { Page, Route } from '@playwright/test';
import { expect, test } from './fixtures';

// 11/09 사용자 결정: 화면에 보이는 글자에 「—」(U+2014)를 쓰지 않는다.
//   빈 값은 빈 칸 · 문장 안 「A — B」는 「[통과] 위반 사항 없음」 같은 양식으로 다듬는다.
//   공급망 검사 상세의 엔진 줄에서 「오픈소스 정적 분석(Apache-2.0)」 글씨를 뺀다.
// 검사 범위: 보이는 글자(본문 · 셸 · 시트 · 창 · 탭 내용) + title · placeholder 속성 + select 항목.
// 제외: 코드 창(사용자 데이터 · 패키지 소스) — [data-part="code"] · pre · code 안 글자.
const DASH = '—';

const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as unknown;
const EVAL = { static: load('static'), runtime: load('runtime'), model: load('model'), modelAll: load('model-all') };

const now = new Date().toISOString();
const scan = (id: string, verdict: 'clean' | 'malicious' | 'vulnerable') => ({
  id,
  target: { kind: 'package', manager: 'pip', name: 'requests', version: '2.31.0', label: 'pip:requests==2.31.0' },
  status: 'done', startedAt: now, finishedAt: now, verdict, risk: { score: verdict === 'malicious' ? 8 : 0, label: verdict === 'malicious' ? 'malicious' : 'no_risks_detected' },
  engines: [{ name: 'GuardDog', version: '3.2.0' }, { name: 'OSV-Scanner', version: '2.7.0' }],
  findings: verdict === 'malicious' ? [{ rule: 'threat-setup-download', severity: 'high', file: 'setup.py', line: 3, message: 'setup.py downloads code' }] : [],
  vulns: verdict === 'vulnerable' ? [{ id: 'GHSA-xxxx', package: 'urllib3', version: '1.26.0', severity: 'HIGH', score: 7.5, fixed: '1.26.18', summary: 'test' }] : [],
  packages: [{ manager: 'pip', name: 'urllib3', version: '2.2.1', ecosystem: 'PyPI', source: 'requirements.txt', direct: true, vulns: 0 }],
  files: {}, caseId: null, threats: verdict === 'malicious' ? 1 : 0, capabilities: 0, vulnCount: verdict === 'vulnerable' ? 1 : 0, vulnMax: null,
});

async function stubs(page: Page) {
  await page.route(/\/api\/evaluation$/, (r: Route) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(EVAL) }));
  const scans = [scan('scan-0003', 'malicious'), scan('scan-0002', 'vulnerable'), scan('scan-0001', 'clean')];
  await page.route(/\/api\/scans(\/|$|\?)/, (route: Route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (path === '/scans') return json(scans);
    const s = scans.find((x) => path === `/scans/${x.id}`);
    return s ? json(s) : json({ error: '검사 없음' }, 404);
  });
}

// 보이는 글자 · 툴팁 · 입력 안내 · 선택 항목에서 「—」가 든 것
async function dashes(page: Page): Promise<string[]> {
  return page.evaluate((d) => {
    const out: string[] = [];
    const skip = (el: Element) => !!el.closest('[data-part="code"], pre, code, script, style');
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const n = walker.currentNode as Text;
      if (!n.data.includes(d)) continue;
      const el = n.parentElement;
      if (!el || skip(el)) continue;
      if (el.tagName !== 'OPTION' && !el.checkVisibility({ checkVisibilityCSS: true })) continue;
      out.push(n.data.trim().slice(0, 90));
    }
    for (const el of Array.from(document.querySelectorAll('[title], [placeholder]'))) {
      if (skip(el)) continue;
      for (const a of ['title', 'placeholder']) {
        const v = el.getAttribute(a);
        if (v?.includes(d)) out.push(`@${a} ${v.slice(0, 90)}`);
      }
    }
    return [...new Set(out)];
  }, DASH);
}

const settle = (page: Page) => page.waitForTimeout(400);

// 보이는 탭(role=tab)을 차례로 눌러 각 탭 내용을 본다
async function eachTab(page: Page, scope: string, found: Set<string>, where: string) {
  const tabs = page.locator(`${scope} [role="tab"]`);
  const n = await tabs.count();
  for (let i = 0; i < n; i++) {
    const t = tabs.nth(i);
    if (!(await t.isVisible()) || (await t.getAttribute('aria-disabled')) === 'true' || (await t.isDisabled())) continue;
    const name = ((await t.textContent()) ?? '').trim();
    await t.click();
    await settle(page);
    for (const s of await dashes(page)) found.add(`${where} › 탭 「${name}」: ${s}`);
  }
}

// 표 첫 줄을 눌러 상세 시트를 열고 탭마다 본다
async function firstSheet(page: Page, found: Set<string>, where: string) {
  const row = page.locator('main tbody tr').first();
  if (!(await row.isVisible().catch(() => false))) return;
  await row.click();
  const sheet = page.locator('.sg-sheet-layer [role="dialog"]');
  if (!(await sheet.isVisible().catch(() => false))) return;
  await settle(page);
  for (const s of await dashes(page)) found.add(`${where} › 시트: ${s}`);
  await eachTab(page, '.sg-sheet-layer', found, `${where} › 시트`);
  await page.keyboard.press('Escape');
  await expect(page.locator('.sg-sheet-layer')).toHaveCount(0);
}

const PAGES: [string, string][] = [
  ['대시보드', '/'],
  ['설치 검사', '/installs'],
  ['공급망 검사', '/scans'],
  ['평가', '/evaluation'],
  ['이벤트', '/events'],
  ['토폴로지', '/topology'],
  ['정책', '/policies'],
  ['차단 목록', '/policies/blocklist'],
  ['변경 이력', '/policies/changes'],
  ['감사 로그', '/audit'],
  ['감사 로그 판정 · 변경', '/audit?view=changes'],
  ['설정', '/settings'],
  ['건 보고서(설치)', '/report?install=ins-0012'],
  ['건 보고서(건)', '/report?case=case-0005'],
  ['연동', '/integration'],
  ['환경 점검', '/integration/env'], // 11/10 연동 3페이지
  ['감시 중 컨테이너', '/integration/watch'],
  ['시연', '/demo'],
];

test.describe('11/09 「—」 없음 — 모든 페이지 · 탭 · 상세 시트', () => {
  for (const [name, path] of PAGES) {
    test(`${name} (${path})`, async ({ page, backend, allowConsole }) => {
      void backend;
      allowConsole(/404|Failed to load resource/);
      await stubs(page);
      await page.goto(path);
      await expect(page.locator('h1').first()).toBeVisible();
      await page.waitForTimeout(800);
      const found = new Set<string>();
      for (const s of await dashes(page)) found.add(`${name}: ${s}`);
      await eachTab(page, 'main', found, name);
      await firstSheet(page, found, name);
      expect([...found], `「—」가 보이는 곳 ${found.size}개`).toEqual([]);
    });
  }

  test('셸 — 계정 메뉴 · 알림 센터 · 사용 안내 · 도우미(탭마다) · 검색', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/404|Failed to load resource/);
    await stubs(page);
    await page.goto('/');
    await expect(page.locator('h1').first()).toBeVisible();
    const found = new Set<string>();
    const look = async (where: string) => {
      await settle(page);
      for (const s of await dashes(page)) found.add(`${where}: ${s}`);
    };
    await page.locator('[data-part="account"]').click();
    await look('계정 메뉴');
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: /^알림 \d+건 안 읽음$|^알림/ }).first().click();
    await look('알림 센터');
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: '사용 안내 (?)' }).click();
    await look('사용 안내');
    await page.keyboard.press('Escape');
    await page.locator('[data-part="assistant-fab"]').click();
    await look('도우미');
    await eachTab(page, '[data-part="assistant"]', found, '도우미');
    await page.keyboard.press('Escape');
    await page.locator('body').press('/');
    await page.keyboard.type('re');
    await look('검색');
    expect([...found], `「—」가 보이는 곳 ${found.size}개`).toEqual([]);
  });

  test('공급망 검사 상세 — 엔진 줄은 이름 · 판만(「오픈소스 정적 분석(Apache-2.0)」 없음)', async ({ page, backend }) => {
    void backend;
    await stubs(page);
    await page.goto('/scans');
    await page.locator('table[data-table="scans"] tbody tr').first().click();
    const sheet = page.locator('.sg-sheet-layer [role="dialog"]');
    await expect(sheet).toBeVisible();
    await expect(sheet.getByText('GuardDog 3.2.0 · OSV-Scanner 2.7.0', { exact: true })).toBeVisible();
    await expect(sheet.getByText(/오픈소스 정적 분석|Apache-2\.0/)).toHaveCount(0);
  });
});
