import type { Locator, Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { SCREEN_COPY } from '../src/lib/screenCopy';
import type { Scan } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';

// 11/09 P5 — 정책 밖 목록 화면 정리(SPEC-1109 §3 · §4 · §7)
//   2단계: 화면 설명 한 줄(lib/screenCopy.ts) · 표 아래 안내 · 표 도구(총 N건 · 새로고침 · 칸 고르기/폭/순서 · 내보내기 = 보이는 칸) · Select · SearchField · 두 줄 칸
//   1단계: 포커스 링 하나(화면 쪽 개별 규칙 제거) · 표 칸 순서(현황 = 상태 먼저, 기록류 = 시각 먼저) · 시각 3형식 · 빈 값 「—」 ·
//          화면 문구(빈 · 결과 없음 · 입력 검사 · 토스트 · 자리 표시 · 꺼진 단추 사유) · 행을 흐리게 하지 않음

const LOG = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/;
const STATUS = /^\d\d-\d\d \d\d:\d\d$/;
const RING = { 'outline-style': 'solid', 'outline-width': '2px', 'outline-offset': '2px', 'outline-color': 'rgb(23, 105, 232)' };
const RING_P = Object.keys(RING);

const cs = (loc: Locator, props: string[]) =>
  loc.evaluate((e, ps) => {
    const c = getComputedStyle(e);
    return Object.fromEntries(ps.map((p) => [p, c.getPropertyValue(p)]));
  }, props);
const ring = async (page: Page, loc: Locator, name: string) => {
  await page.keyboard.press('Shift'); // 마지막 입력을 키보드로 — 프로그램 포커스도 :focus-visible
  await loc.focus();
  await expect.poll(() => cs(loc, RING_P), { message: name }).toEqual(RING);
};
const heads = (page: Page, table: string) => page.locator(`table[data-table="${table}"] thead th`).evaluateAll((ths) => ths.map((t) => (t as HTMLElement).dataset.col));
const mono = (loc: Locator) => loc.evaluate((e) => /monospace|Menlo|SFMono|Consolas/.test(getComputedStyle(e).fontFamily));
// 가짜 백엔드에 /api/scans 가 없어 이 파일에서 가로챈다(scans.spec 과 같은 방식) — 목록 1건 · 시작은 scan-0003
const SCAN: Scan = {
  id: 'scan-0001',
  target: { kind: 'package', manager: 'pip', name: 'reqeusts', label: 'pip reqeusts' },
  status: 'done', startedAt: '2026-11-09T03:04:05Z', finishedAt: '2026-11-09T03:04:35Z', verdict: 'malicious', risk: { score: 8.2, label: 'high_risk' },
  engines: [], findings: [], vulns: [], packages: [], files: {}, caseId: null, threats: 3, capabilities: 0, vulnCount: 0, vulnMax: null,
};
const scansApi = (page: Page) =>
  page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace(/^\/api/, '');
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (req.method() === 'POST' && path === '/scans') return json({ id: 'scan-0003' }, 202);
    if (path === '/scans') return json([SCAN]);
    return path === '/scans/scan-0001' ? json(SCAN) : json({ error: '검사 없음' }, 404);
  });

test.describe('① 포커스 링 하나(화면 쪽 개별 규칙 없음)', () => {
  test('연동 입력 · 대시보드 판정 대기 줄 · 시연 시나리오 · 묶음 머리 · 탭 · 평가 용어 = 2px 주 색 · 바깥 2px, 연동 입력 글자 13.5', async ({ page, backend }) => {
    backend.enableDemo();
    await page.goto('/integration');
    await page.locator('[data-part="wizard"] [data-scn="single"]').click();
    const input = page.locator('[data-part="wizard"] input.int-input').first();
    await expect(input).toBeVisible();
    await ring(page, input, '연동 입력');
    expect(await cs(input, ['font-size', 'box-shadow'])).toEqual({ 'font-size': '13.5px', 'box-shadow': 'none' });

    await page.goto('/');
    const pend = page.locator('.sg-pend-link').first();
    await expect(pend).toBeVisible();
    await ring(page, pend, '대시보드 판정 대기 줄');

    await page.goto('/demo');
    await expect(page.locator('[data-part="demo-page"]')).toBeVisible();
    await ring(page, page.locator('.scn-item').first(), '시연 시나리오');
    await ring(page, page.locator('.scn-group-head').first(), '시연 묶음 머리');
    await ring(page, page.locator('.demo-tab').first(), '시연 상세 탭');
  });

  test('표 행 · 필터 입력도 같은 링(행은 안쪽) — 화면 쪽 focus 유틸리티를 지워도 그대로', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    const row = page.locator('table[data-table="audit"] tbody tr').first();
    await expect(row).toBeVisible();
    await page.keyboard.press('Shift');
    await row.focus();
    await expect.poll(() => cs(row, RING_P)).toEqual({ ...RING, 'outline-offset': '-2px' });
    await ring(page, page.locator('[data-testid="audit"] input[type="datetime-local"]').first(), '기간 입력');
  });
});

test.describe('② 표 칸 순서 · 시각 형식 · 빈 값', () => {
  test('현황 표는 상태가 맨 앞 · 시각은 MM-DD HH:mm + 전체 시각 툴팁(설치 검사 · 공급망 검사 · 계정)', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await expect(page.locator('tr[data-install]').first()).toBeVisible();
    expect((await heads(page, 'installs'))[0]).toBe('status');
    const started = page.locator('tr[data-install] td[data-col="started"]').first();
    await expect(started).toHaveText(STATUS);
    await expect(started.locator('time')).toHaveAttribute('title', LOG);
    // 판정이 없는 행의 판정 칸은 빈 칸
    await expect(page.locator('tr[data-install] td[data-col="decision"]').filter({ hasNotText: /\S/ }).first()).toBeVisible();

    await scansApi(page);
    await page.goto('/scans');
    await expect(page.locator('tr[data-scan]').first()).toBeVisible();
    expect((await heads(page, 'scans'))[0]).toBe('verdict');
    const sStart = page.locator('tr[data-scan] td[data-col="started"]').first();
    await expect(sStart).toHaveText(STATUS);
    await expect(sStart.locator('time')).toHaveAttribute('title', LOG);

    await page.goto('/settings?tab=accounts');
    await expect(page.locator('table[data-table="users"] tbody tr').first()).toBeVisible();
    expect((await heads(page, 'users'))[0]).toBe('status');
    const last = page.locator('table[data-table="users"] td[data-col="last"]');
    await expect(last.first()).toHaveText(new RegExp(`${STATUS.source}|^$`));
  });

  test('기록류는 시각이 맨 앞 · YYYY-MM-DD HH:mm:ss 고정폭(감사 위반 · 판정 변경 이력 · 인증 감사)', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await expect(page.locator('tr[data-audit]').first()).toBeVisible();
    expect((await heads(page, 'audit'))[0]).toBe('time');
    const t = page.locator('tr[data-audit] td[data-col="time"] time').first();
    await expect(t).toHaveText(LOG);
    expect(await mono(t)).toBe(true);

    await page.goto('/audit?view=changes');
    await expect(page.locator('tr[data-history]').first()).toBeVisible();
    expect((await heads(page, 'history'))[0]).toBe('at');
    await expect(page.locator('tr[data-history] td[data-col="at"] time').first()).toHaveText(LOG);

    await page.goto('/settings?tab=auth-audit');
    await expect(page.locator('table[data-table="auth-audit"] tbody tr').first()).toBeVisible();
    expect((await heads(page, 'auth-audit'))[0]).toBe('at');
    await expect(page.locator('table[data-table="auth-audit"] td[data-col="at"] time').first()).toHaveText(LOG);
  });

  test('알림 채널 표 — 상태(실패) 먼저 · 「마지막 성공」 MM-DD HH:mm + 툴팁, 상대 시각 없음', async ({ page, backend }) => {
    backend.info.notify!.channels[0].lastAt = new Date(Date.now() - 90_000).toISOString();
    await page.goto('/settings');
    const t = page.locator('table[data-table="notify"]');
    await expect(t).toBeVisible();
    expect(await t.locator('thead th').allTextContents()).toEqual(['채널', '호스트', '보냄', '실패', '마지막 성공', '마지막 오류']);
    const at = t.locator('tbody td[data-col="last"] time');
    await expect(at).toHaveText(STATUS);
    await expect(at).toHaveAttribute('title', LOG);
    await expect(page.locator('main')).not.toContainText(/\d+분 전|\d+시간 전|\d+일 전/);
  });
});

test.describe('③ 화면 문구', () => {
  test('검색 결과 없음 = 「조건에 맞는 데이터가 없습니다」 + 「검색 조건을 바꾸거나 해제해 보세요.」 + 조건 지우기(설치 검사 · 이벤트 · 감사 로그)', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await page.locator('[data-chip="isolated"]').click();
    await page.locator('[data-chip="npm"]').click(); // npm 격리 0
    const nr = page.locator('[data-testid="installs"] [data-part="no-results"]');
    await expect(nr).toContainText('조건에 맞는 데이터가 없습니다');
    await expect(nr).toContainText('검색 조건을 바꾸거나 해제해 보세요.');
    await nr.getByRole('button', { name: '조건 지우기' }).click();
    await expect(page.locator('tr[data-install]').first()).toBeVisible();

    await page.goto('/events');
    await page.getByPlaceholder('컨테이너 이름').fill('no-such-container');
    await page.getByPlaceholder('컨테이너 이름').press('Enter'); // 검색칸은 Enter · 칸 벗어날 때 적용(11/09)
    await expect(page.locator('[data-testid="events"] [data-part="no-results"]')).toContainText('조건에 맞는 데이터가 없습니다');

    await page.goto('/audit');
    await page.getByPlaceholder('규칙 ID').fill('no-such-rule');
    await page.getByPlaceholder('규칙 ID').press('Enter');
    await expect(page.locator('[data-testid="audit"] [data-part="no-results"]')).toContainText('검색 조건을 바꾸거나 해제해 보세요.');
    await expect(page.getByPlaceholder('컨테이너 이름')).toBeVisible();
  });

  test('빈 상태 = 「[무엇]이 없습니다.」 + 다음 할 일(설치 검사 · 공급망 검사 · 감사 로그 · 판정 변경 이력)', async ({ page, backend }) => {
    backend.empty();
    await page.route(/\/api\/scans(\/|$|\?)/, (route) => route.fulfill({ contentType: 'application/json', body: '[]' }));
    await page.route(/\/api\/audit(\?|$)/, (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [], total: 0 }) }));
    await page.goto('/installs');
    const e1 = page.getByTestId('installs-empty');
    await expect(e1.locator('> span').first()).toHaveText('설치 검사가 없습니다.');
    const copyBtn = e1.getByRole('button', { name: '명령 복사' });
    await expect(copyBtn).toHaveAttribute('title', '명령 복사');

    await page.goto('/scans');
    await expect(page.locator('[data-testid="scans"] [data-part="empty"] > span').first()).toHaveText('공급망 검사가 없습니다.');

    await page.goto('/audit');
    await expect(page.locator('[data-testid="audit"] [data-part="empty"] > span').first()).toHaveText('위반 기록이 없습니다.');
    await page.goto('/audit?view=changes');
    await expect(page.locator('[data-testid="history"] [data-part="empty"] > span').first()).toHaveText('판정 · 변경 기록이 없습니다.');
  });

  test('입력 검사(칸 밑 role=alert) · 시작 토스트 「~했습니다.」 — 공급망 검사', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    await page.goto('/scans');
    const form = page.locator('[data-part="scan-form"]');
    await form.locator('[data-input="file"]').click();
    await form.getByRole('button', { name: '검사 시작' }).click();
    await expect(form.getByRole('alert')).toHaveText('파일을 먼저 고르세요.');
    await form.locator('[data-input="repo"]').click();
    await form.locator('[data-field="url"]').fill('https://example.test/x');
    await form.getByRole('button', { name: '검사 시작' }).click();
    await expect(form.getByRole('alert')).toHaveText(/^저장소 주소는 https:\/\/github\.com\/<소유자>\/<저장소> 모양으로 입력하세요.+\.$/);
    await expect(form.locator('[data-field="url"]')).toHaveAttribute('placeholder', /^예: /);
    await form.locator('[data-input="package"]').click();
    await form.getByRole('button', { name: '검사 시작' }).click();
    await expect(form.getByRole('alert')).toHaveText('패키지 이름을 입력하세요.');
    await expect(form.locator('[data-field="version"]')).toHaveAttribute('placeholder', '비우면 최신 버전');
    await form.locator('[data-field="name"]').fill('requests');
    await form.getByRole('button', { name: '검사 시작' }).click();
    await expect(page.locator('[data-toast="scan"]')).toContainText(/^검사 scan-\d+을\(를\) 시작했습니다\./);
  });

  test('감사 로그 내보내기 — 먼저 할 일 「~를 먼저 고르세요.」(role=alert)', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await page.locator('[data-table-tools="audit"] [data-action="table-export"]').click(); // 11/09: 내보내기는 표 도구줄 하나
    await expect(page.locator('[data-part="export-error"]')).toHaveText('기간을 먼저 고르세요.');
  });

  test('꺼진 단추 = aria-disabled + 사유(마침표 없음) · 행을 흐리게 하지 않음 — 연동', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/integration');
    await expect(page.locator('[data-part="integration"]')).toHaveAttribute('data-state', 'ready');
    const env = page.locator('[data-part="step-env"]');
    if ((await env.getAttribute('data-open')) !== 'true') await env.locator('[data-part="env-toggle"]').click();
    const btn = page.locator('[data-part="test-start"]');
    await expect(btn).toHaveAttribute('aria-disabled', 'true');
    await expect(btn).toHaveAttribute('title', '연결 테스트를 실행할 권한이 없습니다');
    await expect(btn).not.toHaveAttribute('disabled'); // 진짜 disabled 아님 — 초점이 가고 사유가 읽힌다
    const out = page.locator('[data-part="watch-rows"] li[data-watched="false"]').first();
    if (await out.count()) expect(await cs(out, ['opacity'])).toEqual({ opacity: '1' });
  });

  test('토스트는 「~했습니다.」 — 설정 화면 배치 되돌리기', async ({ page, backend }) => {
    void backend;
    await page.goto('/settings');
    await page.locator('[data-action="layout-reset"]').click();
    await expect(page.locator('[data-toast="layout-reset"]')).toContainText('화면 배치를 기본 순서로 되돌렸습니다.');
  });

  test('입력 검사 — 연동 시나리오 칸 밑 role=alert 「[칸]을(를) 입력하세요.」 · 다음 단추는 aria-disabled + 사유', async ({ page, backend }) => {
    void backend;
    await page.goto('/integration');
    await page.locator('[data-part="wizard"] [data-scn="single"]').click();
    const w = page.locator('[data-part="wizard"]');
    await w.locator('input[name="name"]').fill('');
    await expect(w.getByRole('alert').first()).toHaveText('이름을 입력하세요.');
    const next = w.locator('[data-part="wizard-next"]');
    await expect(next).toHaveAttribute('aria-disabled', 'true');
    await expect(next).toHaveAttribute('title', '입력 칸의 오류를 먼저 고치세요');
  });
});

// ── 2단계: 화면 설명 한 줄(lib/screenCopy) · 표 도구(총 N건 · 새로고침 · 칸 고르기 · 폭/순서 · 내보내기 = 보이는 칸) · 필터 Select · 검색칸 · 두 줄 칸 · 표 아래 안내 ──
const DESC: [string, string][] = [
  ['/installs', 'installs'],
  ['/scans', 'scans'],
  ['/evaluation', 'evaluation'],
  ['/events', 'events'],
  ['/topology', 'topology'],
  ['/audit', 'audit'],
  ['/settings', 'settings'],
  ['/integration', 'integration'],
  ['/demo', 'demo'],
  ['/report?case=case-0004', 'report'],
];
const SYMBOLS = /[.=—·()「」:;/]/;

test.describe('④ 화면 설명 한 줄(lib/screenCopy.ts 한 곳)', () => {
  test('화면마다 제목 아래 「~합니다.」 20~50자 한 문장 · 마침표 앞 기호 없음 · 저장소 문장 그대로, 대시보드는 설명 없음', async ({ page, backend, allowConsole }) => {
    test.setTimeout(120_000); // 화면 11개를 차례로 연다
    backend.enableDemo();
    allowConsole(/status of 404/); // 가짜 백엔드에 평가 결과가 없다(평가 화면은 「평가 결과가 없습니다.」 — 설명 줄은 그대로)
    await scansApi(page);
    for (const [url, key] of DESC) {
      await page.goto(url);
      if (key === 'demo') await expect(page.locator('[data-part="demo-page"]')).toBeVisible({ timeout: 10_000 }); // /api/info 를 읽은 뒤 그린다
      const want = SCREEN_COPY[key] ?? '';
      const d = page.locator('[data-part="screen-copy"]');
      await expect(d, `${key} 설명`).toHaveCount(1, { timeout: 15_000 });
      const text = (await d.textContent())!.trim();
      const n = [...text].length;
      expect(text, key).toMatch(/니다\.$/);
      expect(n, `${key} 길이`).toBeGreaterThanOrEqual(20);
      expect(n, `${key} 길이`).toBeLessThanOrEqual(50);
      expect(SYMBOLS.test(text.slice(0, -1)), `${key} 기호`).toBe(false);
      expect(await d.getAttribute('data-screen'), key).toBe(key);
      expect(text, `${key} = lib/screenCopy.ts 문장`).toBe(want);
      expect(await d.evaluate((e) => getComputedStyle(e).fontSize)).toBe('13.5px');
    }
    await page.goto('/');
    await expect(page.locator('[data-part="screen-copy"]')).toHaveCount(0);
  });

  test('표 아래 안내 한 줄(ScreenNote) — 설치 검사 · 감사 로그 · 이벤트 · 공급망 검사', async ({ page, backend }) => {
    void backend;
    await scansApi(page);
    for (const url of ['/installs', '/audit', '/events', '/scans']) {
      await page.goto(url);
      const note = page.locator('[data-part="screen-note"]');
      await expect(note, url).toHaveCount(1);
      await expect(note, url).toHaveText(/[^.…]\.$/);
      await expect(note, url).toHaveAttribute('title', (await note.textContent())!);
    }
  });
});

test.describe('⑤ 표 도구 — 총 N건 · 새로고침 · 칸 고르기(저장 키 화면마다) · 내보내기 = 보이는 칸', () => {
  const TABLES: { url: string; table: string; grid: string; hide: string; hideName: string }[] = [
    { url: '/installs', table: 'installs', grid: 'installs', hide: 'manager', hideName: '매니저' },
    { url: '/scans', table: 'scans', grid: 'scans', hide: 'risk', hideName: '위험 점수' },
    { url: '/audit', table: 'audit', grid: 'audit', hide: 'rule', hideName: '규칙' },
    { url: '/audit?view=changes', table: 'history', grid: 'audit-history', hide: 'by', hideName: '처리자' },
    { url: '/settings?tab=accounts', table: 'users', grid: 'settings-users', hide: 'otp', hideName: 'OTP' },
    { url: '/settings?tab=auth-audit', table: 'auth-audit', grid: 'settings-auth-audit', hide: 'ip', hideName: 'IP' },
  ];
  for (const t of TABLES) {
    test(`${t.table}: 도구줄 · 칸 끄기 → 저장 supplyguard.grid.${t.grid}.v1 · 다시 열어도 유지 · CSV 머리 = 보이는 칸`, async ({ page, backend }) => {
      void backend;
      await scansApi(page);
      await page.goto(t.url);
      if (t.table === 'installs') await page.locator('[data-chip="all"]').click();
      const T = `table[data-table="${t.table}"]`;
      await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
      const tools = page.locator(`[data-table-tools="${t.table}"]`);
      await expect(tools.locator('[data-part="total"]')).toHaveText(/^총 [\d,]+건$/);
      await expect(tools.locator('[data-action="table-refresh"]')).toHaveAttribute('aria-label', '새로고침');
      await tools.locator('[data-action="table-columns"]').click();
      const pick = page.locator('[data-part="column-picker"]');
      await pick.getByRole('checkbox', { name: t.hideName, exact: true }).uncheck();
      await page.keyboard.press('Escape');
      await expect(page.locator(`${T} th[data-col="${t.hide}"]`)).toHaveCount(0);
      const saved = await page.evaluate((k) => localStorage.getItem(k), `supplyguard.grid.${t.grid}.v1`);
      expect(JSON.parse(saved!).vis[t.hide]).toBe(false);
      const heads = await page.locator(`${T} thead th`).evaluateAll((ths) => ths.map((e) => e.textContent!.trim()).filter(Boolean));
      if (t.table === 'audit') {
        // 감사 로그 내보내기는 기간 안 전체 — 기간이 먼저(브라우저 시간대로 만든 datetime-local)
        const [since, until] = await page.evaluate(() => {
          const local = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
          return [local(new Date(Date.now() - 86_400_000)), local(new Date(Date.now() + 3600_000))];
        });
        await page.getByLabel('기간 시작').fill(since);
        await page.getByLabel('기간 끝').fill(until);
      }
      const [dl] = await Promise.all([page.waitForEvent('download'), tools.locator('[data-action="table-export"]').click()]);
      const first = readFileSync((await dl.path())!, 'utf8').replace(/^\uFEFF/, '').split('\n')[0];
      expect(first.split(','), 'CSV 머리 = 보이는 칸').toEqual(heads);
      await page.reload();
      await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
      await expect(page.locator(`${T} th[data-col="${t.hide}"]`), '다시 열어도 숨김 유지').toHaveCount(0);
    });
  }

  test('칸 폭 — 기록류 시각 칸은 COL_W.log 192 · 초까지 잘리지 않음 · 감사 컨테이너는 두 줄 칸(이름 + 컨테이너 ID) · 행 48 유지', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    const T = 'table[data-table="audit"]';
    await expect(page.locator(`${T} tbody tr`).first()).toBeVisible();
    // 기록류 시각(YYYY-MM-DD HH:mm:ss 고정폭)은 COL_W.log 192(메인 11/09 — 160 은 잘림), 현황 시각은 COL_W.time 160
    expect(Math.round(await page.locator(`${T} th[data-col="time"]`).evaluate((e) => e.getBoundingClientRect().width))).toBe(192);
    expect(await page.locator(`${T} tbody td[data-col="time"]`).first().evaluate((e) => e.scrollWidth <= e.clientWidth)).toBe(true);
    const two = page.locator(`${T} tbody tr`).first().locator('td[data-col="container"] .tk-2line');
    await expect(two.locator('.tk-2l-top')).not.toBeEmpty();
    await expect(two.locator('.tk-2l-sub')).toHaveText(/^\S{1,12}$/); // 컨테이너 ID 앞 12자
    expect(await page.locator(`${T} tbody tr`).first().evaluate((e) => Math.round(e.getBoundingClientRect().height))).toBe(48);
    await page.goto('/settings?tab=auth-audit');
    expect(Math.round(await page.locator('table[data-table="auth-audit"] th[data-col="at"]').evaluate((e) => e.getBoundingClientRect().width))).toBe(192);
    expect(await page.locator('table[data-table="auth-audit"] tbody td[data-col="at"]').first().evaluate((e) => e.scrollWidth <= e.clientWidth)).toBe(true);
    expect(Math.round(await page.locator('table[data-table="auth-audit"] th[data-col="actor"]').evaluate((e) => e.getBoundingClientRect().width)), '사용자 칸 110').toBe(110);
    await page.goto('/audit?view=changes');
    expect(Math.round(await page.locator('table[data-table="history"] th[data-col="at"]').evaluate((e) => e.getBoundingClientRect().width))).toBe(192);
  });
});

test.describe('⑤-2 변경 동작 이름 — 정책 화면과 한 곳(features/policies/changeView changeName)', () => {
  test('감사 로그 판정 · 변경 이력: 정책 저장은 「정책 수정」 · 새로 만든 정책은 「정책 생성」(「정책 편집」 없음) · 태그 색은 끝말로', async ({ page, backend }) => {
    backend.seedPolicyHistory();
    await page.goto('/audit?view=changes');
    const kind = (id: string) => page.locator(`tr[data-history="chg:${id}"] td[data-col="kind"] [data-action-tone]`);
    await expect(kind('chg-0012')).toHaveText('정책 수정');
    await expect(kind('chg-0012')).toHaveAttribute('data-action-tone', 'warn');
    await expect(kind('chg-0011')).toHaveText('정책 생성');
    await expect(kind('chg-0011')).toHaveAttribute('data-action-tone', 'ok');
    await expect(kind('chg-0013')).toHaveText('제안 적용');
    await expect(page.locator('table[data-table="history"]')).not.toContainText('정책 편집');
  });
});

test.describe('⑥ 필터 Select · 검색칸(Enter · 칸 벗어날 때 적용, 검색 단추 없음)', () => {
  test('이벤트 · 감사 로그 · 인증 감사 — 선택 상자는 Select(「종류 전체」), 글 검색은 SearchField(자리 표시 = 찾는 칸 이름)', async ({ page, backend }) => {
    void backend;
    await page.goto('/events');
    const kind = page.locator('[data-filter="kind"]');
    await expect(kind).toHaveAttribute('role', 'combobox');
    await expect(kind).toHaveText('종류 전체');
    const box = page.getByRole('searchbox', { name: '컨테이너 검색' });
    await expect(box).toHaveAttribute('placeholder', '컨테이너 이름');
    await box.fill('no-such');
    await expect(page.locator('[data-testid="events"] [data-part="no-results"]'), '쓰는 동안은 적용하지 않음').toHaveCount(0);
    await box.press('Enter');
    await expect(page.locator('[data-testid="events"] [data-part="no-results"]')).toBeVisible();
    await page.locator('[data-part="filter-chips"] [data-action="clear-filters"]').click(); // 조건 지우기 = 「적용된 필터」 줄 하나
    await expect(box).toHaveValue('');

    await page.goto('/audit');
    await expect(page.locator('[data-filter="action"]')).toHaveText('대응 전체');
    await page.locator('[data-filter="action"]').click();
    await page.getByRole('option', { name: '격리 (kill)' }).click();
    await expect(page.locator('[data-filter="action"]')).toHaveText('격리 (kill)');
    await expect(page.getByRole('searchbox', { name: '규칙 검색' })).toHaveAttribute('placeholder', '규칙 ID');

    await page.goto('/settings?tab=auth-audit');
    await expect(page.locator('[data-filter="action"]')).toHaveText('한 일 전체');
  });
});

test.describe('⑦ 스크린샷 1440×900 밝은', () => {
  test('바꾼 화면 각 1장 → test-results/screens/lists-1109/', async ({ page, backend, allowConsole }) => {
    test.setTimeout(150_000);
    backend.enableDemo();
    allowConsole(/status of 404/);
    await scansApi(page);
    const shot = async (name: string) => {
      await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getComputedTiming().iterations === Infinity));
      await page.screenshot({ path: `${SHOTS}/lists-1109/${name}.png` });
    };
    const go = async (url: string, ready: string) => {
      await page.goto(url);
      await expect(page.locator(ready).first()).toBeVisible({ timeout: 10_000 });
    };
    await go('/', '[data-testid="pending"]');
    await shot('dashboard');
    await go('/installs', '[data-chip="all"]');
    await page.locator('[data-chip="all"]').click();
    await expect(page.locator('tr[data-install]').first()).toBeVisible();
    await shot('installs');
    await go('/scans', 'tr[data-scan]');
    await shot('scans');
    await go('/events', 'li[data-key]');
    await shot('events');
    await go('/audit', 'tr[data-audit]');
    await shot('audit');
    await go('/audit?view=changes', 'tr[data-history]');
    await shot('audit-history');
    await go('/settings', 'table[data-table="notify"]');
    await shot('settings-server');
    await go('/settings?tab=accounts', 'table[data-table="users"] tbody tr');
    await shot('settings-accounts');
    await go('/settings?tab=auth-audit', 'table[data-table="auth-audit"] tbody tr');
    await shot('settings-auth-audit');
    await go('/integration', '[data-part="integration"][data-state="ready"]');
    await shot('integration');
    await go('/demo', '[data-part="demo-page"]');
    await shot('demo');
    await go('/evaluation', '[data-part="screen-copy"]');
    await shot('evaluation');
    await go('/topology', '[data-testid="topology"]');
    await shot('topology');
    await go('/report?case=case-0004', '[data-testid="report"]');
    await shot('report');
  });
});
