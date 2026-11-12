import type { Page } from '@playwright/test';
import type { Scan } from '../src/lib/types';
import { expect, test, closeSheet } from './fixtures';

// 공급망 검사 — 저장소 주소 확장(W4): tree/<ref>/<폴더> · commit · releases/tag 를 받고, 라벨에 @ref/폴더가 보인다.
// mock-backend 에는 /api/scans 가 없어 이 파일에서만 가로챈다(뒤에 등록한 route 가 먼저 맞는다).

const now = new Date().toISOString();
const repoScan: Scan = {
  id: 'scan-0002',
  target: { kind: 'repo', name: 'requests', url: 'https://github.com/psf/requests/tree/v2.31.0/src/requests', ref: 'v2.31.0', subpath: 'src/requests', label: 'github.com/psf/requests@v2.31.0/src/requests' },
  status: 'done', startedAt: now, finishedAt: now, verdict: 'clean', risk: { score: 0, label: 'no_risks_detected' },
  engines: [{ name: 'GuardDog', version: '3.2.0' }, { name: 'OSV-Scanner', version: '2.7.0' }],
  findings: [], vulns: [], packages: [{ manager: 'pip', name: 'urllib3', version: '2.2.1', ecosystem: 'PyPI', source: 'requirements.txt', direct: true, vulns: 0 }], files: {},
  caseId: null, threats: 0, capabilities: 0, vulnCount: 0, vulnMax: null,
};
const headScan: Scan = { ...repoScan, id: 'scan-0001', target: { kind: 'repo', name: 'requests', url: 'https://github.com/psf/requests', label: 'github.com/psf/requests' } };

async function scansApi(page: Page, scans: Scan[], posts: string[]) {
  await page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace(/^\/api/, '');
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (req.method() === 'POST' && path === '/scans') {
      posts.push(req.postData() ?? '');
      return json({ id: 'scan-0003' }, 202);
    }
    if (path === '/scans') return json(scans.map(({ findings, vulns, packages, files, ...s }) => { void findings; void vulns; void packages; void files; return s; }));
    const m = path.match(/^\/scans\/([^/]+)$/);
    const s = m && scans.find((x) => x.id === m[1]);
    return s ? json(s) : json({ error: '검사 없음' }, 404);
  });
}

test.describe('공급망 검사 — 저장소 주소 확장(W4)', () => {
  test('받지 않는 주소는 이유를 보이고 시작하지 않는다', async ({ page, backend }) => {
    void backend;
    const posts: string[] = [];
    await scansApi(page, [], posts);
    await page.goto('/scans');
    await page.locator('[data-input="repo"]').click();
    await expect(page.locator('[data-part="repo-hint"]')).toContainText('tree/<브랜치>/<폴더>');
    const url = page.locator('[data-field="url"]');
    const start = page.getByRole('button', { name: '검사 시작' });
    for (const [bad, hint] of [
      ['https://github.com/psf/requests/pull/1', 'tree/<브랜치>/<폴더>'],
      ['https://gitlab.com/psf/requests', 'https://github.com/<소유자>/<저장소>'],
      ['https://github.com/psf/requests/blob/main/setup.py', '파일 올리기'],
      ['https://github.com/psf/requests/tree/main/../x', '하위 경로'],
      ['https://github.com/psf/requests/tree', 'tree/<브랜치>/<폴더>'],
    ] as const) {
      await url.fill(bad);
      await start.click();
      await expect(page.locator('[data-form-error]'), bad).toContainText(hint);
    }
    expect(posts).toEqual([]);
  });

  test('tree/<ref>/<폴더> · commit · releases/tag 주소를 받아 그대로 보낸다', async ({ page, backend }) => {
    void backend;
    const posts: string[] = [];
    await scansApi(page, [], posts);
    await page.goto('/scans');
    await page.locator('[data-input="repo"]').click();
    const url = page.locator('[data-field="url"]');
    const start = page.getByRole('button', { name: '검사 시작' });
    const good = [
      ' https://www.github.com/psf/requests/tree/v2.31.0/src/requests/?tab=readme-ov-file ',
      'https://github.com/psf/requests.git',
      'https://github.com/psf/requests/commit/0e322af87745eff34caffe4df68456ebc20d9068',
      'https://github.com/psf/requests/releases/tag/v2.31.0',
    ];
    for (const g of good) {
      await url.fill(g);
      await start.click();
      await expect(page.locator('[data-toast="scan"]')).toContainText('검사 scan-0003을(를) 시작했습니다.');
      await expect(page.locator('[data-form-error]')).toHaveCount(0);
    }
    expect(posts.map((b) => JSON.parse(b))).toEqual(good.map((g) => ({ kind: 'repo', url: g.trim() })));
  });

  test('목록 · 상세 라벨에 브랜치 · 폴더가 보인다', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [repoScan, headScan], []);
    await page.goto('/scans?id=scan-0002');
    await expect(page.locator('tr[data-scan="scan-0002"]')).toContainText('github.com/psf/requests@v2.31.0/src/requests');
    await expect(page.locator('tr[data-scan="scan-0001"]')).toContainText('github.com/psf/requests');
    const sheet = page.locator('[data-sheet="scan"]');
    await expect(sheet).toContainText('github.com/psf/requests@v2.31.0/src/requests');
    const ref = sheet.locator('[data-part="repo-ref"]');
    await expect(ref.locator('a')).toHaveAttribute('href', 'https://github.com/psf/requests/tree/v2.31.0/src/requests');
    await expect(ref.locator('[data-ref="v2.31.0"]')).toContainText('브랜치/태그 v2.31.0');
    await expect(ref.locator('[data-subpath="src/requests"]')).toContainText('폴더 src/requests');
    // 기본 브랜치 전체는 그렇게 표시
    await closeSheet(page); // 11/05 슬라이드 패널: 열린 동안 뒤 화면은 어두운 배경에 가려 눌리지 않는다 — 먼저 닫는다
    await page.locator('tr[data-scan="scan-0001"]').click();
    await expect(page.locator('[data-sheet="scan"] [data-part="repo-ref"] [data-ref=""]')).toContainText('기본 브랜치');
    await expect(page.locator('[data-sheet="scan"] [data-subpath]')).toHaveCount(0);
  });
});
