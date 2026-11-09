import { readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import type { InstallSession, Scan } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';

// R4 11/04 — React 이식 4단계(표 화면들). 목업 11/04e A(mock/README.md — 표 · 쪽 번호 · 타이포 · 평가 몸통)와
// 목업 회귀 ui-1104 7 · 8 · 9 · 10 · 14 번이 확인하는 동작을 설치 검사 · 공급망 검사 · 평가 · 이벤트 · 토폴로지 · 정책 · 감사 로그 · 설정 · 건 보고서에 옮겼는지 본다.
//   A 설치 검사 표   B 공급망 검사 표   C 감사 로그 쪽 번호(서버)   D 다른 표(변경 이력 · 설정 · 이벤트 행 40)
//   E 평가 머리 고정   F 9개 화면 스크롤 0   G 타이포 · 패널   H 다크   I 390

const SCRATCH = process.env.R4_SHOTS || SHOTS;
type Json = Record<string, unknown>;
const load = (f: string) => JSON.parse(readFileSync(new URL(`./evaluation/${f}.json`, import.meta.url), 'utf8')) as Json;
const EVAL = {
  static: load('static'),
  runtime: load('runtime'),
  model: load('model'),
  modelAll: load('model-all'),
};
const evalApi = (page: Page) => page.route(/\/api\/evaluation$/, (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(EVAL) }));

// 공급망 검사 25건(첫 건 악성) — 쪽 번호 · 정렬 · 막대
const t0 = Date.now();
const mkScan = (i: number): Scan => {
  const verdict = i === 0 ? 'malicious' : i % 4 === 1 ? 'vulnerable' : 'clean';
  const at = new Date(t0 - i * 600_000).toISOString();
  return {
    id: `scan-${String(900 + i)}`,
    target: {
      kind: 'package',
      manager: 'pip',
      name: `pkg${String(i).padStart(2, '0')}`,
      version: '1.0.0',
      label: `pip pkg${String(i).padStart(2, '0')}==1.0.0`,
    },
    status: 'done',
    startedAt: at,
    finishedAt: at,
    verdict,
    risk: {
      score: verdict === 'malicious' ? 8.2 : (i % 7) / 2,
      label: verdict === 'malicious' ? 'high_risk' : 'low_risk',
    },
    engines: [{ name: 'GuardDog', version: '3.2.0' }],
    findings: [],
    vulns: [],
    packages: [],
    files: {},
    caseId: null,
    threats: verdict === 'malicious' ? 2 : 0,
    capabilities: 0,
    vulnCount: verdict === 'vulnerable' ? i : 0,
    vulnMax: verdict === 'vulnerable' ? 'HIGH' : null,
    installThreats: verdict === 'malicious' ? 1 : 0,
  } as Scan;
};
const SCANS = Array.from({ length: 25 }, (_, i) => mkScan(i));
async function scansApi(page: Page, scans: Scan[] = SCANS) {
  await page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    const json = (d: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: 'application/json',
        body: JSON.stringify(d),
      });
    if (path === '/scans') return json(scans.map(({ findings, vulns, packages, files, ...s }) => (void findings, void vulns, void packages, void files, s)));
    const m = path.match(/^\/scans\/([^/]+)$/);
    const s = m && scans.find((x) => x.id === m[1]);
    return s ? json(s) : json({ error: '검사 없음' }, 404);
  });
}

// 설치 세션을 n 개 더(통과 · 오래된 순) — 쪽 번호 확인용
function seedInstalls(b: MockBackend, n: number) {
  const last = b.installs[b.installs.length - 1];
  const at = new Date(last.startedAt).getTime();
  for (let i = 1; i <= n; i++) {
    const s: InstallSession = {
      ...last,
      id: `ins-1${String(i).padStart(3, '0')}`,
      packages: [`bulk-${String(i).padStart(2, '0')}`],
      startedAt: new Date(at - i * 60_000).toISOString(),
      finishedAt: new Date(at - i * 60_000 + 5_000).toISOString(),
      status: 'passed',
      caseId: null,
      violations: [],
      isolation: null,
      scan: undefined,
      scanId: null,
    };
    b.installs.push(s);
  }
}

// ── 공통 측정 ──
const tokRgb = (page: Page, name: string) =>
  page.evaluate((n) => {
    const e = document.createElement('i');
    e.style.color = `var(${n})`;
    document.body.append(e);
    const v = getComputedStyle(e).color;
    e.remove();
    return v;
  }, name);
const headStyle = (page: Page, table: string) =>
  page
    .locator(`table[data-table="${table}"] thead th`)
    .first()
    .evaluate((e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight, getComputedStyle(e.closest('thead')!).position]);
const colText = (page: Page, table: string, col: string) => page.locator(`table[data-table="${table}"] tbody tr td[data-col="${col}"]`).allTextContents();
const ariaSort = (page: Page, table: string, col: string) => page.locator(`table[data-table="${table}"] th[data-col="${col}"]`).getAttribute('aria-sort');
const rowH = (page: Page, sel: string) =>
  page
    .locator(sel)
    .first()
    .evaluate((e) => e.getBoundingClientRect().height);
// 행 왼쪽 3px 막대(첫 칸 inset 그림자) 색 — 없으면 null
const barOf = (page: Page, sel: string) =>
  page.locator(sel).evaluateAll((els) =>
    els.map((tr) => {
      const sh = getComputedStyle((tr as HTMLTableRowElement).cells[0]).boxShadow;
      return sh.match(/(rgba?\([^)]*\)) 3px 0px 0px 0px inset/)?.[1] ?? null;
    }),
  );
const pillStyle = (page: Page, sel: string) =>
  page
    .locator(sel)
    .first()
    .evaluate((e) => {
      const cs = getComputedStyle(e);
      return {
        fs: cs.fontSize,
        fw: cs.fontWeight,
        line: cs.boxShadow !== 'none' || cs.borderTopWidth !== '0px',
        radius: parseFloat(cs.borderTopLeftRadius) >= 10,
      };
    });
async function scrollAudit(page: Page) {
  return page.evaluate(() => {
    const main = document.querySelector('main')!;
    const se = document.scrollingElement!;
    const allowed = (e: Element) => !!e.closest('[data-fill], [data-sheet], dialog, [data-part="assistant"]');
    const bad = [...main.querySelectorAll('*')]
      .filter((e) => {
        const cs = getComputedStyle(e);
        return /(auto|scroll)/.test(cs.overflowY) && e.scrollHeight > e.clientHeight + 1 && !allowed(e);
      })
      .map(
        (e) => `${e.tagName.toLowerCase()}[${e.getAttribute('data-part') ?? e.getAttribute('data-testid') ?? String(e.className).split(' ').slice(0, 3).join('.')}]+${e.scrollHeight - e.clientHeight}`,
      );
    return {
      doc: se.scrollHeight - innerHeight,
      docW: se.scrollWidth - innerWidth,
      main: main.scrollHeight - main.clientHeight,
      fills: document.querySelectorAll('main [data-page=""] [data-fill]').length,
      bad,
    };
  });
}
// 화면 안 글자 12px 미만(상태 배지 .sg-pill 은 11.5 까지) — 보이는 요소의 자기 글자만
const smallText = (page: Page) =>
  page.evaluate(() =>
    [...document.querySelectorAll('main *')]
      .filter((e) => {
        if (!e.getClientRects().length) return false;
        if (![...e.childNodes].some((n) => n.nodeType === 3 && n.textContent!.trim())) return false;
        const fs = parseFloat(getComputedStyle(e).fontSize);
        return fs < (e.closest('.sg-pill') ? 11.5 : 12) - 0.01;
      })
      .slice(0, 5)
      .map((e) => `${e.tagName.toLowerCase()}「${e.textContent!.trim().slice(0, 14)}」:${getComputedStyle(e).fontSize}`),
  );

const SCREENS: [string, string, (p: Page) => Promise<void>][] = [
  ['installs', '/installs', (p) => expect(p.locator('table[data-table="installs"]')).toBeVisible()],
  ['scans', '/scans', (p) => expect(p.locator('table[data-table="scans"]')).toBeVisible()],
  ['evaluation', '/evaluation', (p) => expect(p.locator('[data-part="evaluation"][data-state="ready"]')).toBeVisible()],
  ['events', '/events', (p) => expect(p.getByTestId('events')).toBeVisible()],
  ['topology', '/topology', (p) => expect(p.getByTestId('topology')).toBeVisible()],
  ['policies', '/policies?id=egress-allowlist', (p) => expect(p.getByTestId('editor')).toBeVisible()],
  ['audit', '/audit', (p) => expect(p.locator('table[data-table="audit"]')).toBeVisible()],
  ['settings', '/settings', (p) => expect(p.locator('[data-part="settings-tabs"]')).toBeVisible()],
  ['report', '/report?install=ins-0012', (p) => expect(p.getByTestId('report')).toBeVisible()],
];

// ── A 설치 검사 ──
test.describe('A 설치 검사 표', () => {
  test('머리 sticky 12/600 · 정렬 aria-sort(오름 → 내림 · 키보드) · 행 44~48 · 숫자 오른쪽 · 배지 12.5/700 + 글자색 테두리 · 막대는 판정 대기 · 격리만', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    const T = 'installs';
    expect(await headStyle(page, T)).toEqual(['12px', '600', 'sticky']);
    const sortable = await page.locator(`table[data-table="${T}"] th[aria-sort]`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.col));
    expect(sortable.length, `정렬 칸 ${sortable}`).toBeGreaterThanOrEqual(5);
    expect(await ariaSort(page, T, 'started')).toBe('descending'); // 기본: 시작 내림(목록 순서 그대로)
    await page.locator(`table[data-table="${T}"] th[data-col="package"] button`).click();
    const asc = await colText(page, T, 'package');
    expect(asc).toEqual([...asc].sort((a, b) => a.localeCompare(b, 'ko', { numeric: true })));
    expect(await ariaSort(page, T, 'package')).toBe('ascending');
    expect(await ariaSort(page, T, 'started')).toBe('none');
    await page.locator(`table[data-table="${T}"] th[data-col="package"] button`).click();
    expect(await colText(page, T, 'package')).toEqual([...asc].reverse());
    expect(await ariaSort(page, T, 'package')).toBe('descending');
    await page.locator(`table[data-table="${T}"] th[data-col="violations"] button`).focus();
    await page.keyboard.press('Enter');
    expect(await ariaSort(page, T, 'violations')).toBe('ascending');
    const h = await rowH(page, `table[data-table="${T}"] tbody tr`);
    expect(h).toBeGreaterThanOrEqual(44);
    expect(h).toBeLessThanOrEqual(48);
    expect(
      await page
        .locator(`table[data-table="${T}"] tbody td[data-col="violations"]`)
        .first()
        .evaluate((e) => getComputedStyle(e).textAlign),
    ).toBe('right');
    expect(await page.locator(`table[data-table="${T}"] th[data-col="violations"]`).evaluate((e) => getComputedStyle(e).textAlign)).toBe('right');
    expect(
      await page
        .locator(`table[data-table="${T}"] td[data-col="package"]`)
        .first()
        .evaluate((e) => e.classList.contains('tk-fill')),
    ).toBe(true);
    expect(await page.locator(`table[data-table="${T}"] th[data-col="started"]`).evaluate((e) => e.classList.contains('tk-short'))).toBe(true);
    expect(await pillStyle(page, `table[data-table="${T}"] tbody [data-status]`)).toEqual({ fs: '12.5px', fw: '700', line: true, radius: true });
    // 막대: 격리(위험) · 판정 대기 경고(경고)만, 통과 없음
    await page.locator(`table[data-table="${T}"] th[data-col="started"] button`).click();
    const danger = await tokRgb(page, '--danger');
    const warn = await tokRgb(page, '--warn');
    const rows = page.locator(`table[data-table="${T}"] tbody tr`);
    const ids = await rows.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.install));
    const bars = await barOf(page, `table[data-table="${T}"] tbody tr`);
    const by = Object.fromEntries(ids.map((id, i) => [id, bars[i]]));
    expect(by['ins-0012'], '격리 + 판정 대기').toBe(danger);
    expect(by['ins-0011'], '경고 + 판정 대기').toBe(warn);
    expect(by['ins-0010'], '통과').toBeNull();
    expect(by['ins-0009'], '통과').toBeNull();
    await page.screenshot({ path: `${SCRATCH}/r4-installs.png` });
  });

  test('쪽 번호 바닥줄(클라이언트): 총 N건 · 1/P 페이지 · 쪽 단추 · 페이지당 50 · 바닥줄은 채움 칸 밖 · 필터 바꾸면 첫 쪽 · ?id= 행이 있는 쪽', async ({ page, backend }) => {
    seedInstalls(backend, 37); // 8 + 37 = 45
    await page.goto('/installs?status=all');
    const foot = page.locator('[data-table-foot="installs"]');
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 1/3 페이지');
    await expect(page.locator('table[data-table="installs"] tbody tr')).toHaveCount(20);
    await expect(foot.locator('select[data-part="page-size"]')).toHaveValue('20');
    await foot.locator('[data-page="2"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 2/3 페이지');
    await expect(foot.locator('[data-page="2"]')).toHaveAttribute('aria-current', 'page');
    await foot.locator('[data-page="next"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 3/3 페이지');
    await expect(foot.locator('[data-page="next"]')).toBeDisabled();
    await foot.locator('select[data-part="page-size"]').selectOption('50');
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 1/1 페이지');
    await expect(page.locator('table[data-table="installs"] tbody tr')).toHaveCount(45);
    expect(
      await page.evaluate(() => {
        const f = document.querySelector('[data-table-foot="installs"]')!;
        const sc = document.querySelector('table[data-table="installs"]')!.closest('[data-fill]')!;
        return !sc.contains(f);
      }),
    ).toBe(true);
    // 필터를 바꾸면 첫 쪽부터
    await foot.locator('select[data-part="page-size"]').selectOption('20');
    await foot.locator('[data-page="3"]').click();
    await page.locator('[data-chip="pip"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText(/^총 \d+건 · 1\/\d+ 페이지$/);
    // 주소 ?id= 로 들어오면 그 행이 있는 쪽(38번째 행 = 2쪽)
    await page.goto('/installs?status=all&id=ins-1030');
    await expect(page.locator('[data-sheet="install"]')).toBeVisible();
    await expect(page.locator('tr[data-install="ins-1030"]')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('[data-table-foot="installs"] [data-page="2"]')).toHaveAttribute('aria-current', 'page');
  });

  test('재조회 동안 2px 진행 띠(이전 행 유지) · 첫 로딩 스켈레톤', async ({ page, backend }) => {
    void backend;
    let delay = 900;
    await page.route(/\/api\/installs\?/, async (route) => {
      await new Promise((r) => setTimeout(r, delay));
      await route.fallback();
    });
    await page.goto('/installs?status=all');
    await expect(page.locator('[data-part="skeleton"]')).toBeVisible();
    await expect(page.locator('table[data-table="installs"] tbody tr')).toHaveCount(8);
    const busy = page.locator('[data-testid="installs"] [data-part="busy"]');
    await expect(busy).toBeHidden();
    delay = 1500;
    // 5초 폴링 — 재조회 중에는 띠가 보이고 행은 그대로
    await expect(busy).toBeVisible({ timeout: 8000 });
    await expect(page.locator('table[data-table="installs"] tbody tr')).toHaveCount(8);
    expect(await busy.evaluate((e) => e.getBoundingClientRect().height)).toBe(2);
    await expect(busy).toBeHidden({ timeout: 4000 });
  });
});

// ── B 공급망 검사 ──
test.describe('B 공급망 검사 표', () => {
  test('정렬 aria-sort · 총 25건 · 1/2 페이지 · 악성 행만 위험 막대 · 배지 pill · 위험 점수 오른쪽', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await page.goto('/scans');
    const T = 'scans';
    await expect(page.locator(`table[data-table="${T}"] tbody tr`)).toHaveCount(20);
    expect(await headStyle(page, T)).toEqual(['12px', '600', 'sticky']);
    await expect(page.locator(`[data-table-foot="${T}"] [data-part="range"]`)).toHaveText('총 25건 · 1/2 페이지');
    expect(await ariaSort(page, T, 'started')).toBe('descending');
    await page.locator(`table[data-table="${T}"] th[data-col="risk"] button`).click();
    expect(await ariaSort(page, T, 'risk')).toBe('ascending');
    const risk = (await colText(page, T, 'risk')).map(Number);
    expect(risk).toEqual([...risk].sort((a, b) => a - b));
    await page.locator(`table[data-table="${T}"] th[data-col="risk"] button`).click();
    expect(await ariaSort(page, T, 'risk')).toBe('descending');
    expect((await colText(page, T, 'risk'))[0]).toBe('8.2');
    expect(
      await page
        .locator(`table[data-table="${T}"] td[data-col="risk"]`)
        .first()
        .evaluate((e) => getComputedStyle(e).textAlign),
    ).toBe('right');
    expect(await pillStyle(page, `table[data-table="${T}"] tbody td[data-col="verdict"] > span`)).toEqual({ fs: '12.5px', fw: '700', line: true, radius: true });
    const danger = await tokRgb(page, '--danger');
    const bars = await barOf(page, `table[data-table="${T}"] tbody tr`);
    expect(bars[0]).toBe(danger); // 악성(점수 8.2 — 내림 정렬 첫 행)
    expect(bars.slice(1).every((b) => b === null)).toBe(true);
    await page.locator(`[data-table-foot="${T}"] [data-page="2"]`).click();
    await expect(page.locator(`[data-table-foot="${T}"] [data-part="range"]`)).toHaveText('총 25건 · 2/2 페이지');
    await expect(page.locator(`table[data-table="${T}"] tbody tr`)).toHaveCount(5);
    // ?id= 로 들어오면 그 행이 있는 쪽
    await page.goto(`/scans?id=${SCANS[22].id}`);
    await expect(page.locator(`tr[data-scan="${SCANS[22].id}"]`)).toHaveAttribute('aria-selected', 'true');
    await page.screenshot({ path: `${SCRATCH}/r4-scans.png` });
  });
});

// ── C 감사 로그(서버 쪽 번호) ──
test.describe('C 감사 로그 쪽 번호', () => {
  test('offset · limit 요청 → 총 total건 · 2쪽 offset=20 · 페이지당 50 · 정렬은 받은 쪽 안에서 · 「더 보기」 없음 · 격리 행만 막대', async ({ page, backend }) => {
    backend.seedAudit(40);
    const total = backend.audit.length;
    await page.goto('/audit');
    const T = 'audit';
    const foot = page.locator(`[data-table-foot="${T}"]`);
    await expect(foot.locator('[data-part="range"]')).toHaveText(`총 ${total}건 · 1/${Math.ceil(total / 20)} 페이지`);
    await expect(page.locator(`table[data-table="${T}"] tbody tr`)).toHaveCount(20);
    const auditReqs = () => backend.requests.filter((r) => r.method === 'GET' && r.path.startsWith('/audit?')).map((r) => new URLSearchParams(r.path.split('?')[1]));
    expect(auditReqs().some((q) => q.get('offset') === '0' && q.get('limit') === '20')).toBe(true);
    expect(await headStyle(page, T)).toEqual(['12px', '600', 'sticky']);
    const page1 = await page.locator(`table[data-table="${T}"] tbody tr`).evaluateAll((els) => els.map((e) => Number((e as HTMLElement).dataset.audit)));
    await foot.locator('[data-page="2"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText(`총 ${total}건 · 2/${Math.ceil(total / 20)} 페이지`);
    expect(auditReqs().some((q) => q.get('offset') === '20' && q.get('limit') === '20')).toBe(true);
    const page2 = await page.locator(`table[data-table="${T}"] tbody tr`).evaluateAll((els) => els.map((e) => Number((e as HTMLElement).dataset.audit)));
    expect(page2.some((id) => page1.includes(id))).toBe(false);
    // 정렬: 받은 쪽 안에서만(#  오름) — 같은 행들, 순서만 바뀐다. 새로 부르지 않는다
    const n = auditReqs().length;
    await page.locator(`table[data-table="${T}"] th[data-col="id"] button`).click();
    expect(await ariaSort(page, T, 'id')).toBe('ascending');
    const sorted = await page.locator(`table[data-table="${T}"] tbody tr`).evaluateAll((els) => els.map((e) => Number((e as HTMLElement).dataset.audit)));
    expect(sorted).toEqual([...page2].sort((a, b) => a - b));
    expect(auditReqs().length).toBe(n);
    await foot.locator('select[data-part="page-size"]').selectOption('50');
    await expect(foot.locator('[data-part="range"]')).toHaveText(`총 ${total}건 · 1/${Math.ceil(total / 50)} 페이지`);
    expect(auditReqs().some((q) => q.get('offset') === '0' && q.get('limit') === '50')).toBe(true);
    await expect(page.locator(`table[data-table="${T}"] tbody tr`)).toHaveCount(50);
    await expect(page.getByRole('button', { name: '더 보기' })).toHaveCount(0);
    expect(
      await page.evaluate(() => {
        const f = document.querySelector('[data-table-foot="audit"]')!;
        const sc = document.querySelector('table[data-table="audit"]')!.closest('[data-fill]')!;
        return !sc.contains(f);
      }),
    ).toBe(true);
    // 막대: 격리(killed)만
    const danger = await tokRgb(page, '--danger');
    const lv = await page.locator(`table[data-table="${T}"] tbody tr`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.level));
    const bars = await barOf(page, `table[data-table="${T}"] tbody tr`);
    expect(lv.includes('killed') && lv.includes('alert')).toBe(true);
    lv.forEach((l, i) => expect(bars[i], `${l} 행 막대`).toBe(l === 'killed' ? danger : null));
    const h = await rowH(page, `table[data-table="${T}"] tbody tr`);
    expect(h).toBeGreaterThanOrEqual(44);
    expect(h).toBeLessThanOrEqual(48);
    expect(
      await page
        .locator(`table[data-table="${T}"] td[data-col="id"]`)
        .first()
        .evaluate((e) => getComputedStyle(e).textAlign),
    ).toBe('right');
    expect(await pillStyle(page, `table[data-table="${T}"] tbody td[data-col="level"] > span`)).toMatchObject({ fs: '12.5px', fw: '700', line: true });
    await page.screenshot({ path: `${SCRATCH}/r4-audit.png` });
  });

  test('옛 백엔드(배열 응답)면 total 없이 이전/다음만 — 다음은 before 커서, 이전은 앞 쪽 커서', async ({ page, backend }) => {
    backend.seedAudit(40);
    backend.auditLegacy = true;
    await page.goto('/audit');
    const foot = page.locator('[data-table-foot="audit"]');
    await expect(foot.locator('[data-part="range"]')).toHaveText('1–20 · 1 페이지');
    await expect(foot.locator('[data-page]')).toHaveCount(2);
    await expect(foot.locator('[data-page="prev"]')).toBeDisabled();
    await expect(foot.locator('[data-page="next"]')).toHaveAttribute('aria-label', '다음 쪽');
    const ids1 = await page.locator('table[data-table="audit"] tbody tr').evaluateAll((els) => els.map((e) => Number((e as HTMLElement).dataset.audit)));
    const cursor = Math.min(...ids1);
    await foot.locator('[data-page="next"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('21–40 · 2 페이지');
    expect(backend.requests.some((r) => r.path.startsWith('/audit?') && new URLSearchParams(r.path.split('?')[1]).get('before') === String(cursor))).toBe(true);
    const ids2 = await page.locator('table[data-table="audit"] tbody tr').evaluateAll((els) => els.map((e) => Number((e as HTMLElement).dataset.audit)));
    expect(Math.max(...ids2)).toBeLessThan(cursor);
    await foot.locator('[data-page="next"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText(/^41–\d+ · 3 페이지$/);
    await expect(foot.locator('[data-page="next"]')).toBeDisabled(); // 마지막 쪽(20개 미만)
    await foot.locator('[data-page="prev"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('21–40 · 2 페이지');
    expect(await page.locator('table[data-table="audit"] tbody tr').evaluateAll((els) => els.map((e) => Number((e as HTMLElement).dataset.audit)))).toEqual(ids2);
  });

  test('딥링크 ?id= 행이 지금 쪽에 없으면 그 행만 불러 시트를 연다', async ({ page, backend }) => {
    backend.seedAudit(40);
    const target = backend.audit[33].id;
    await page.goto(`/audit?id=${target}`);
    const sheet = page.locator('[data-sheet="audit"]');
    await expect(sheet).toBeVisible();
    await expect(sheet).toContainText(`감사 기록 #${target}`);
    await expect(page.locator(`tr[data-audit="${target}"]`)).toHaveCount(0); // 1쪽에는 없다
    expect(
      backend.requests.some(
        (r) =>
          r.path.startsWith('/audit?') &&
          /before=\d+/.test(r.path) &&
          new URLSearchParams(r.path.split('?')[1]).get('before') === String(target + 1) &&
          new URLSearchParams(r.path.split('?')[1]).get('limit') === '1',
      ),
    ).toBe(true);
    await expect(page.locator('[data-table-foot="audit"] [data-page="1"]')).toHaveAttribute('aria-current', 'page');
  });

  test('필터를 바꾸면 이전 행을 둔 채 2px 진행 띠 · 첫 로딩 스켈레톤 · 첫 쪽부터', async ({ page, backend }) => {
    backend.seedAudit(40);
    backend.auditDelayMs = 700;
    await page.goto('/audit');
    await expect(page.locator('[data-part="skeleton"]')).toBeVisible();
    await expect(page.locator('table[data-table="audit"] tbody tr')).toHaveCount(20);
    await page.locator('[data-table-foot="audit"] [data-page="2"]').click();
    await expect(page.locator('[data-table-foot="audit"] [data-part="range"]')).toHaveText(/ 2\/\d+ 페이지$/);
    const busy = page.locator('[data-testid="audit"] [data-part="busy"]');
    await expect(busy).toBeHidden();
    await page.locator('[data-filter="action"]').click(); // 11/09 공통 Select
    await page.getByRole('option', { name: '격리 (kill)' }).click();
    await expect(busy).toBeVisible();
    await expect(page.locator('table[data-table="audit"] tbody tr')).toHaveCount(20); // 이전 행 유지
    await expect(busy).toBeHidden({ timeout: 3000 });
    await expect(page.locator('[data-table-foot="audit"] [data-part="range"]')).toHaveText(/ 1\/\d+ 페이지$/);
    const q = backend.requests.filter((r) => r.path.startsWith('/audit?') && r.path.includes('action=kill')).map((r) => new URLSearchParams(r.path.split('?')[1]));
    expect(q.some((x) => x.get('offset') === '0')).toBe(true);
  });
});

// ── D 다른 표 ──
test.describe('D 다른 표 — 변경 이력 · 설정 · 이벤트', () => {
  test('판정 · 변경 이력: 머리 12/600 · 정렬 aria-sort(받은 목록 안)', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit?view=changes');
    const T = 'history';
    await expect(page.locator(`table[data-table="${T}"] tbody tr`).first()).toBeVisible();
    expect(await headStyle(page, T)).toEqual(['12px', '600', 'sticky']);
    expect(await ariaSort(page, T, 'at')).toBe('descending');
    await page.locator(`table[data-table="${T}"] th[data-col="at"] button`).click();
    expect(await ariaSort(page, T, 'at')).toBe('ascending');
    await page.locator(`table[data-table="${T}"] th[data-col="by"] button`).click();
    expect(await ariaSort(page, T, 'by')).toBe('ascending');
    expect(await ariaSort(page, T, 'at')).toBe('none');
  });

  test('설정 — 계정 · 인증 감사 표: 머리 12/600 · 정렬 aria-sort · 행 44~48', async ({ page, backend }) => {
    void backend;
    await page.goto('/settings?tab=accounts');
    const T = 'users';
    await expect(page.locator(`table[data-table="${T}"] tbody tr`)).toHaveCount(2);
    expect(await headStyle(page, T)).toEqual(['12px', '600', 'sticky']);
    await page.locator(`table[data-table="${T}"] th[data-col="username"] button`).click();
    expect(await ariaSort(page, T, 'username')).toBe('ascending');
    expect(await colText(page, T, 'username')).toEqual(['admin (나)', 'viewer']);
    await page.locator(`table[data-table="${T}"] th[data-col="username"] button`).click();
    expect(await colText(page, T, 'username')).toEqual(['viewer', 'admin (나)']);
    const h = await rowH(page, `table[data-table="${T}"] tbody tr`);
    expect(h).toBeGreaterThanOrEqual(44);
    expect(h).toBeLessThanOrEqual(48);
    await page.goto('/settings?tab=auth-audit');
    await expect(page.locator('table[data-table="auth-audit"] tbody tr').first()).toBeVisible();
    expect(await headStyle(page, 'auth-audit')).toEqual(['12px', '600', 'sticky']);
    await page.locator('table[data-table="auth-audit"] th[data-col="actor"] button').click();
    expect(await ariaSort(page, 'auth-audit', 'actor')).toBe('ascending');
  });

  test('이벤트 피드: 행 40 유지(가상 스크롤)', async ({ page, backend }) => {
    void backend;
    await page.goto('/events');
    await expect(page.locator('li[data-key]').first()).toBeVisible();
    expect(await rowH(page, 'li[data-key]')).toBe(40);
  });

  test('이벤트 피드: 머리줄 굵기 700(표 머리 규칙, 11/04 메인)', async ({ page, backend }) => {
    void backend;
    await page.goto('/events');
    await expect(page.locator('li[data-key]').first()).toBeVisible();
    const w = await page.locator('[data-part="feed-head"]').evaluate((e) => getComputedStyle(e).fontWeight);
    expect(w).toBe('700');
  });
});

// ── E 평가 ──
test.describe('E 평가 — 머리 · 지표 6칸 고정, 몸통만 스크롤', () => {
  test.use({ viewport: { width: 1280, height: 720 } });
  test('몸통(eval-body)만 data-fill 로 스크롤 · 스크롤해도 지표 제자리 · 길게 눌러 옮기기 그대로', async ({ page, backend }) => {
    void backend;
    await evalApi(page);
    await page.goto('/evaluation');
    await expect(page.locator('[data-part="evaluation"][data-state="ready"]')).toBeVisible();
    const body = page.locator('[data-part="eval-body"]');
    const r = await page.evaluate(() => {
      const b = document.querySelector('[data-part="eval-body"]')!;
      const k = document.querySelector('[data-part="kpis"]')!;
      const head = document.querySelector('[data-part="eval-head"]')!;
      return {
        fill: b.hasAttribute('data-fill'),
        scrolls: b.scrollHeight > b.clientHeight,
        kpiAbove: k.getBoundingClientRect().bottom <= b.getBoundingClientRect().top,
        headOut: !b.contains(head) && !b.contains(k),
      };
    });
    expect(r).toEqual({
      fill: true,
      scrolls: true,
      kpiAbove: true,
      headOut: true,
    });
    const top0 = await page.locator('[data-part="kpis"]').evaluate((e) => e.getBoundingClientRect().top);
    await body.evaluate((e) => (e.scrollTop = 400));
    await page.waitForTimeout(100);
    expect(await body.evaluate((e) => e.scrollTop)).toBeGreaterThan(0);
    expect(await page.locator('[data-part="kpis"]').evaluate((e) => e.getBoundingClientRect().top)).toBeCloseTo(top0, 0);
    expect(await page.locator('[data-part="kpis"] [data-sort-id]').count()).toBe(6);
    const sa = await scrollAudit(page);
    expect(sa).toMatchObject({ doc: 0, main: 0, bad: [] });
    await page.screenshot({ path: `${SCRATCH}/r4-evaluation.png` });
  });
});

// ── F 9개 화면 스크롤 0 ──
test.describe('F 9개 화면 — 문서 · main 스크롤 0, 스크롤은 채움 칸 안에서만', () => {
  for (const [w, hh] of [
    [1280, 720],
    [1440, 900],
    [1920, 1080],
  ]) {
    test.describe(`${w}×${hh}`, () => {
      test.use({ viewport: { width: w, height: hh } });
      test('설치 · 공급망 · 평가 · 이벤트 · 토폴로지 · 정책 · 감사 · 설정 · 보고서', async ({ page, backend }) => {
        seedInstalls(backend, 30);
        backend.seedAudit(40);
        await scansApi(page);
        await evalApi(page);
        for (const [name, url, ready] of SCREENS) {
          await page.goto(name === 'installs' ? '/installs?status=all' : url);
          await ready(page);
          await page.waitForTimeout(250);
          const r = await scrollAudit(page);
          expect(r, name).toMatchObject({ doc: 0, docW: 0, main: 0, bad: [] });
          expect(r.fills, `${name} 채움 칸`).toBeGreaterThan(0);
        }
      });
    });
  }
});

// ── G 타이포 · 패널 ──
test.describe('G 타이포 · 패널', () => {
  test('9개 화면: 글자 12px 이상(상태 배지 11.5) · 표 패널 제목 17.9/700 · 표는 패널(반경 8) 안', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await evalApi(page);
    const small: string[] = [];
    for (const [name, url, ready] of SCREENS) {
      await page.goto(url);
      await ready(page);
      await page.waitForTimeout(200);
      const r = await smallText(page);
      if (r.length) small.push(`${name} ${r.join(',')}`);
    }
    expect(small, small.join(' | ')).toEqual([]);
    for (const [url, T] of [
      ['/installs?status=all', 'installs'],
      ['/audit', 'audit'],
    ] as const) {
      await page.goto(url);
      await expect(page.locator(`table[data-table="${T}"]`)).toBeVisible();
      const p = await page.locator(`table[data-table="${T}"]`).evaluate((e) => {
        const panel = e.closest('.sg-panel')!;
        const h2 = panel.querySelector('h2')!;
        return [getComputedStyle(h2).fontSize, getComputedStyle(h2).fontWeight, getComputedStyle(panel).borderTopLeftRadius];
      });
      expect(p, T).toEqual(['17.92px', '700', '8px']);
    }
  });
});

// ── H 다크 ──
test.describe('H 다크', () => {
  test('표 머리 바탕 · 줄 선 · 배지 · 막대 · 바닥줄이 다크 토큰', async ({ page, backend }) => {
    void backend;
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await page.goto('/installs?status=all');
    await expect(page.locator('table[data-table="installs"] tbody tr').first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    const th = await page
      .locator('table[data-table="installs"] th')
      .first()
      .evaluate((e) => getComputedStyle(e).backgroundColor);
    expect(th).toBe('rgb(40, 45, 56)'); // --surface-2 다크(11/05 표 머리 회색 바탕)
    const line = await page
      .locator('table[data-table="installs"] tbody td')
      .first()
      .evaluate((e) => getComputedStyle(e).borderBottomColor);
    expect(line).toBe('rgb(48, 52, 66)'); // --line-soft 다크
    const bars = await barOf(page, 'table[data-table="installs"] tbody tr[data-install="ins-0012"]');
    expect(bars[0]).toBe('rgb(228, 81, 111)'); // --danger 다크
    const foot = await page.locator('[data-table-foot="installs"]').evaluate((e) => getComputedStyle(e).backgroundColor);
    expect(foot).toBe('rgb(27, 30, 40)');
    await page.screenshot({ path: `${SCRATCH}/r4-installs-dark.png` });
    await page.goto('/audit');
    await expect(page.locator('table[data-table="audit"] tbody tr').first()).toBeVisible();
    await page.screenshot({ path: `${SCRATCH}/r4-audit-dark.png` });
  });
});

// ── I 390 ──
test.describe('I 390', () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test('설치 검사 · 감사 로그 · 공급망 검사: 가로 넘침 없음 · 바닥줄 보임(768 미만은 기존 방식)', async ({ page, backend }) => {
    backend.seedAudit(40);
    await scansApi(page);
    for (const [url, T] of [
      ['/installs?status=all', 'installs'],
      ['/audit', 'audit'],
      ['/scans', 'scans'],
    ] as const) {
      await page.goto(url);
      await expect(page.locator(`table[data-table="${T}"] tbody tr`).first()).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth), T).toBe(0);
      await expect(page.locator(`[data-table-foot="${T}"]`)).toBeVisible();
      const foot = await page.locator(`[data-table-foot="${T}"]`).evaluate((e) => e.getBoundingClientRect().right);
      expect(foot, T).toBeLessThanOrEqual(390);
      if (T === 'audit') await page.screenshot({ path: `${SCRATCH}/r4-audit-390.png` });
    }
  });
});
