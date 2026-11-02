import type { Page } from '@playwright/test';
import type { Scan } from '../src/lib/types';
import { expect, test } from './fixtures';

// 11/02 공급망 검사 보완(목업 mock/tests/scan-1102.cjs 와 같은 기대값):
// 테스트 코드 탐지는 「테스트 코드 N — 위험 점수 · 판정에 넣지 않음」 묶음으로 따로, 위협 수에 들지 않는다 /
// 패키지 이름 검사는 자기 버전의 알려진 취약점 — 판정 문구 「이 버전에 …」 · 표 제목 「이 패키지 버전」

const now = new Date().toISOString();
const base = {
  status: 'done' as const, startedAt: now, finishedAt: now, engines: [{ name: 'GuardDog', version: '3.2.0' }, { name: 'OSV-Scanner', version: '2.7.0' }],
  files: {}, caseId: null,
};
const repoScan: Scan = {
  ...base, id: 'scan-0011',
  target: { kind: 'repo', name: 'requests', url: 'https://github.com/psf/requests', label: 'github.com/psf/requests' },
  verdict: 'clean', risk: { score: 1.2, label: 'low' }, vulns: [], packages: [],
  findings: [
    { rule: 'capability-process-spawn', category: 'capability', message: 'Detects process execution', file: 'src/requests/help.py', line: 73, match: 'system(' },
    { rule: 'threat-filesystem-read', category: 'threat', message: 'Detects access to sensitive files', file: 'tests/test_requests.py', line: 1827, match: '/etc/passwd', test: true },
  ],
  threats: 0, capabilities: 1, testFindings: 1, vulnCount: 0, vulnMax: null,
};
const djangoScan: Scan = {
  ...base, id: 'scan-0012',
  target: { kind: 'package', manager: 'pip', name: 'django', version: '2.2.0', label: 'pip django==2.2.0' },
  verdict: 'vulnerable', risk: { score: 4.9, label: 'low' }, findings: [], packages: [],
  vulns: [{ package: 'django', version: '2.2.0', ecosystem: 'PyPI', direct: true, count: 75, maxSeverity: '9.8', ids: ['PYSEC-2019-10', 'PYSEC-2019-11'] }],
  threats: 0, capabilities: 0, testFindings: 0, vulnCount: 75, vulnMax: 9.8,
};

// 11/02 sg-vm 실측: 최신 requests 2.34.2 는 자기 취약점 0, OSV-Scanner 가 푼 간접 의존성 certifi · idna 에 4건
const requestsScan: Scan = {
  ...base, id: 'scan-0013',
  target: { kind: 'package', manager: 'pip', name: 'requests', version: '2.34.2', label: 'pip requests' },
  verdict: 'vulnerable', risk: { score: 0, label: 'no_risks_detected' }, findings: [], packages: [],
  vulns: [
    { package: 'certifi', version: '2026.7.22', ecosystem: 'PyPI', direct: false, count: 2, maxSeverity: '9.1', ids: ['PYSEC-2026-4320'] },
    { package: 'idna', version: '3.9.0', ecosystem: 'PyPI', direct: false, count: 2, maxSeverity: '6.9', ids: ['PYSEC-2026-215'] },
  ],
  threats: 0, capabilities: 0, testFindings: 0, vulnCount: 4, vulnMax: 9.1,
};

async function scansApi(page: Page, scans: Scan[]) {
  await page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (path === '/scans') return json(scans.map(({ findings, vulns, packages, files, ...s }) => { void findings; void vulns; void packages; void files; return s; }));
    const m = path.match(/^\/scans\/([^/]+)$/);
    const s = m && scans.find((x) => x.id === m[1]);
    return s ? json(s) : json({ error: '검사 없음' }, 404);
  });
}

test.describe('공급망 검사 보완(11/02)', () => {
  test('테스트 코드는 따로 묶고 위협 수에서 뺀다', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [repoScan]);
    await page.goto('/scans?id=scan-0011');
    const tests = page.locator('[data-part="tests"]');
    await expect(tests.locator('summary')).toHaveText('테스트 코드 1 — 위험 점수 · 판정에 넣지 않음');
    await tests.locator('summary').click();
    const f = tests.locator('[data-finding]');
    await expect(f).toHaveCount(1);
    await expect(f).toHaveAttribute('data-loc', 'tests/test_requests.py:1827');
    await expect(f).toHaveAttribute('data-test', 'true');
    await expect(f).toContainText('테스트 코드');
    await expect(page.getByText('위협 0 — GuardDog, 누르면 코드에서 그 줄')).toBeVisible();
  });

  test('패키지 이름 검사는 자기 버전의 알려진 취약점을 「이 버전」으로 말한다', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [djangoScan]);
    await page.goto('/scans?id=scan-0012');
    await expect(page.locator('[data-part="verdict"]')).toContainText('이 버전에 알려진 취약점이 75건 있습니다');
    await expect(page.getByText('알려진 취약점 75 — OSV-Scanner, 이 패키지 버전 · 의존성 포함')).toBeVisible();
  });

  test('패키지 자신은 깨끗하고 의존성만 취약하면 「의존성에 …」로 말한다', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [requestsScan]);
    await page.goto('/scans?id=scan-0013');
    await expect(page.locator('[data-part="verdict"]')).toContainText('의존성에 알려진 취약점이 4건 있습니다');
    await expect(page.locator('[data-part="verdict"]')).not.toContainText('이 버전에');
  });
});
