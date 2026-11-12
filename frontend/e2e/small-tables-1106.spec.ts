import { readFileSync } from 'node:fs';
import type { Locator, Page, Route } from '@playwright/test';
import type { Evidence, Scan } from '../src/lib/types';
import { expect, test } from './fixtures';

// 11/06 사용자 결정 — 상세 안 작은 표도 참고 대시보드 표 값(머리 42 · 12/600 · 좌우 16 · 행 48 · 본문 12.5)으로.
// 대상: 검사 상세(패키지 · 취약점) · 증거(파일 변경 · 프로세스) · 건 보고서(위반) · 제안 미리보기 · 정책 저장 전 확인 · 평가(정상 설치 위반).
// 평가 화면 혼동 행렬(2×2)은 차트라 제외

async function expectRefTable(t: Locator, name: string) {
  await expect(t, name).toBeVisible();
  const r = await t.evaluate((tb) => {
    const th = tb.querySelector('thead th');
    const td = tb.querySelector('tbody td')!;
    const cs = (e: Element) => getComputedStyle(e);
    return {
      th: th ? [cs(th).height, cs(th).fontSize, cs(th).fontWeight, cs(th).paddingLeft] : null,
      td: [cs(td).paddingLeft, cs(td).fontSize],
      row: Math.round(tb.querySelector('tbody tr')!.getBoundingClientRect().height),
    };
  });
  if (r.th) expect(r.th, `${name} 머리`).toEqual(['42px', '12px', '600', '16px']);
  expect(r.td, `${name} 칸`).toEqual(['16px', '13.5px']); // 11/09 SPEC 표 본문 13.5
  expect(r.row, `${name} 행 높이`).toBeGreaterThanOrEqual(48);
}

const iso = new Date().toISOString();
const scan: Scan = {
  id: 'scan-0002', verdict: 'vulnerable', status: 'done', startedAt: iso, finishedAt: iso, risk: { score: 3.2, label: 'medium_risk' }, engines: [{ name: 'GuardDog', version: '3.2.0' }],
  findings: [], files: {}, caseId: null, threats: 0, capabilities: 0, vulnCount: 2, vulnMax: 7.5,
  target: { kind: 'repo', name: 'app', url: 'https://github.com/o/app', label: 'github.com/o/app' },
  packages: [{ manager: 'pip', name: 'urllib3', version: '1.26.4', ecosystem: 'PyPI', source: 'requirements.txt', direct: true, vulns: 2 }],
  vulns: [{ package: 'urllib3', version: '1.26.4', ecosystem: 'PyPI', direct: true, count: 2, maxSeverity: '7.5', ids: ['PYSEC-2023-74'] }],
};

async function scansApi(page: Page) {
  await page.route(/\/api\/scans(\/|$|\?)/, (route: Route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (path === '/scans') return json([{ ...scan, packages: null }]);
    return path === `/scans/${scan.id}` ? json(scan) : json({ error: '검사 없음' }, 404);
  });
}

test.describe('11/06 상세 안 작은 표 = 참고 대시보드 표 값', () => {
  test('검사 상세: 패키지 · 취약점', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await page.goto(`/scans?id=${scan.id}`);
    await expectRefTable(page.locator('[data-sheet="scan"] [data-part="packages"] table'), '패키지');
    await expectRefTable(page.locator('[data-sheet="scan"] table[data-part="vulns"]'), '취약점');
  });

  test('증거: 파일 변경 · 프로세스', async ({ page, backend }) => {
    const ctr = backend.installs.find((s) => s.id === 'ins-0012')!.container;
    const row = backend.audit.find((a) => a.event.containerName === ctr && a.enforced)!;
    const list: Evidence[] = [
      { id: 'ev-1', containerId: row.event.containerId, containerName: ctr, image: 'python:3.12-slim', collectedAt: iso, logs: 'x', partial: false, durationMs: 120,
        changes: [{ kind: 'A', path: '/tmp/p.sh' }], processes: [{ pid: 1, user: 'root', cmd: 'pip install ./reqeusts' }] },
    ];
    backend.evidence = list;
    await page.goto(`/audit?id=${row.id}`);
    await page.locator('[data-sheet="audit"]').getByRole('tab', { name: '증거' }).click();
    await expectRefTable(page.locator('table[data-part="evidence-changes"]'), '파일 변경');
    await expectRefTable(page.locator('table[data-part="evidence-procs"]'), '프로세스');
  });

  test('건 보고서: 위반', async ({ page, backend }) => {
    void backend;
    await page.goto('/report?install=ins-0012');
    await expectRefTable(page.locator('[data-section="violations"] table'), '보고서 위반');
  });

  test('제안 미리보기 · 정책 저장 전 확인', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0011');
    await page.getByTestId('decision').getByRole('button', { name: '오탐' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click();
    await page.getByRole('button', { name: '제안 보기' }).click();
    await expectRefTable(page.getByTestId('proposal').locator('table'), '제안 미리보기');

    await page.goto('/policies?id=sensitive-files');
    const ED = '[data-view="rule-editor"]';
    await page.locator(`${ED} [data-step="action"] input[value="alert"]`).check();
    await page.locator(ED).getByRole('button', { name: '저장 전 확인' }).click();
    await expectRefTable(page.locator(`${ED} [data-part="save-check"] table`), '정책 저장 전 확인');
  });

  test('평가: 정상 설치 위반', async ({ page, backend }) => {
    void backend;
    const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as Record<string, unknown>;
    const runtime = load('runtime') as { benign: { items: Record<string, unknown>[] } };
    runtime.benign.items[0] = { ...runtime.benign.items[0], result: 'violation', rule: 'sandbox-dns' };
    const body = { static: load('static'), runtime, model: load('model'), modelAll: load('model-all') };
    await page.route(/\/api\/evaluation$/, (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) }));
    await page.goto('/evaluation');
    // 11/09 저녁: 평가는 접는 목록 — 「런타임 · 정상 설치 위반」 줄을 펼쳐야 표가 보인다
    await page.locator('[data-item="benign"] [data-action="toggle-row"]').click();
    await expectRefTable(page.locator('table[data-table="benign-violations"]'), '정상 설치 위반');
  });
});
