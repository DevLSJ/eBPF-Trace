import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';

// 11/10 사용자 결정 — 연동 › 감시 중 컨테이너: 행을 누르면(또는 Enter) 오른쪽 상세 시트(공통 Sheet)
//   탭 [정보 | 위반 이력 | 최근 이벤트] — 주소 ?id=<컨테이너 id>&tab=violations|events(첫 탭은 쿼리 없음)
//   정보 = 이름 · ID(짧게 + 전체 툴팁 · 복사) · 이미지 · 상태 · 시작 시각 · 재시작 · 포트 · 감시 이유 · 격리 이유(또는 격리 보류) · 라벨
//         (상태 · 시작 시각 · 라벨은 읽기 전용 GET /api/integration/containers/{id}, 환경 변수는 받지도 보이지도 않는다)
//   위반 이력 = GET /api/audit?container=<이름> 중 이름이 완전히 같은 것만(백엔드 필터는 부분 일치) · 시각 먼저 · 행 → 감사 로그 그 기록
//   최근 이벤트 = 실시간 수집 흐름 중 이 컨테이너 것만 최근 순 최대 50건(시각 · 종류 · 프로세스 · 대상)
const SHOT = process.env.WATCH_SHOTS || `${SHOTS}/watch-detail-1110`;
const SHEET = '[data-sheet="watch"]';
const row = (page: Page, name: string) => page.locator(`[data-part="watch-rows"] li[data-container="${name}"]`);
// 시트가 다 밀려 들어온 뒤(사진 · 위치 확인)
const settled = (page: Page) => page.locator(SHEET).evaluate((e) => Promise.all(e.getAnimations({ subtree: true }).map((a) => a.finished)).then(() => undefined));
const ready = (page: Page) => expect(page.locator('[data-part="integration"][data-page="watch"][data-state="ready"]')).toBeVisible();

// 이름이 비슷한 다른 컨테이너(부분 일치에 걸림) — 위반 · 이벤트에 섞여 있어도 시트에는 안 나와야 한다
function seedLookalikes(b: MockBackend) {
  const a0 = b.audit.find((a) => a.event.containerName === 'pkg-reqeusts')!;
  const top = Math.max(...b.audit.map((a) => a.id));
  b.audit.unshift({ ...a0, id: top + 1, caseId: null, install: null, event: { ...a0.event, containerName: 'pkg-reqeusts-old', timestamp: new Date().toISOString() } });
  const v0 = b.recent.find((v) => v.event.containerName === 'pkg-reqeusts')!;
  b.recent.unshift({ ...v0, event: { ...v0.event, containerName: 'pkg-reqeusts-2', containerId: 'other0123', timestamp: new Date().toISOString() } });
  b.containerDetails['c-pkg'] = {
    state: 'running',
    startedAt: '2026-11-10T01:02:03Z',
    restartCount: 2,
    imageId: 'sha256:feedbeef',
    ports: [{ port: '8080/tcp', hostIp: '0.0.0.0', hostPort: '18080' }, { port: '443/tcp' }],
    labels: { 'supplyguard.enforce': 'true', 'com.docker.compose.service': 'pkg' },
  };
}

// 보이는 글자 · 툴팁에서 「—」
async function dashes(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (w.nextNode()) {
      const n = w.currentNode as Text;
      const el = n.parentElement;
      if (n.data.includes('—') && el?.checkVisibility({ checkVisibilityCSS: true })) out.push(n.data.trim().slice(0, 80));
    }
    for (const el of Array.from(document.querySelectorAll('[title], [placeholder], [aria-label]')))
      for (const a of ['title', 'placeholder', 'aria-label']) if (el.getAttribute(a)?.includes('—')) out.push(`@${a} ${el.getAttribute(a)}`);
    return out;
  });
}

test.describe('11/10 감시 중 컨테이너 상세 시트', () => {
  test('행 클릭 → 시트(정보 · 위반 이력 · 최근 이벤트), 이 컨테이너 것만 · 행 → 감사 로그 · 「—」 없음 · 1440 밝은', async ({ page, backend, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    seedLookalikes(backend);
    await page.goto('/integration/watch');
    await ready(page);
    // 행 모양은 그대로, 누를 수 있는 표시만(손가락 커서 · Tab 으로 닿음)
    const r = row(page, 'pkg-reqeusts');
    await expect(r).toHaveCSS('cursor', 'pointer');
    await expect(r).toHaveAttribute('tabindex', '0');
    await r.click();
    const sheet = page.locator(SHEET);
    await expect(sheet).toBeVisible();
    await expect(page).toHaveURL(/\/integration\/watch\?id=c-pkg$/);
    await expect(sheet.locator('h2')).toHaveText('pkg-reqeusts');
    await expect(sheet.locator('[data-part="sheet-subtitle"]')).toHaveText('demo/reqeusts:1.0.2');
    await expect(sheet.locator('[data-part="sheet-badges"] [data-tag="enforce"]')).toContainText('격리');
    await expect(sheet.locator('[role="tab"]')).toHaveText(['정보', '위반 이력', '최근 이벤트']);
    await expect(sheet.locator('[role="tab"][aria-selected="true"]')).toHaveText('정보');

    // 정보
    const info = sheet.getByTestId('watch-info');
    await expect(info.locator('[data-field="state"] dd')).toHaveText('실행 중');
    await expect(info.locator('[data-field="started"] dd')).toHaveText('2026-11-10 10:02:03'); // KST
    await expect(info.locator('[data-field="restarts"] dd')).toHaveText('2');
    await expect(info.locator('[data-field="image"] dd')).toContainText('demo/reqeusts:1.0.2');
    await expect(info.locator('[data-field="ports"] dd')).toContainText('8080/tcp → 0.0.0.0:18080');
    await expect(info.locator('[data-field="ports"] dd')).toContainText('443/tcp');
    await expect(info.locator('[data-field="watch"] dd')).toContainText('전체 감시');
    await expect(info.locator('[data-field="enforce"] dd')).toContainText('supplyguard.enforce=true');
    await expect(info.locator('[data-label]')).toHaveText(['com.docker.compose.service=pkg', 'supplyguard.enforce=true']);
    const idCell = info.locator('[data-field="id"] dd [data-part="id-short"]');
    await expect(idCell).toHaveText('c-pkg');
    await expect(idCell).toHaveAttribute('title', 'c-pkg');
    await info.locator('[data-action="copy-id"]').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('c-pkg');
    expect(backend.requests.some((q) => q.method === 'GET' && q.path === '/integration/containers/c-pkg')).toBe(true);
    await expect(sheet).not.toContainText(/env|환경 변수/i);
    await settled(page);
    await page.screenshot({ path: `${SHOT}/watch-sheet-info-1440-light.png` });

    // 위반 이력 — 이름이 같은 것만(pkg-reqeusts-old 제외), 시각 먼저 · 최근 순
    await sheet.locator('[role="tab"][data-tab="violations"]').click();
    await expect(page).toHaveURL(/tab=violations/);
    const vio = sheet.getByTestId('watch-violations');
    const want = backend.audit.filter((a) => a.event.containerName === 'pkg-reqeusts').sort((a, b) => b.event.timestamp.localeCompare(a.event.timestamp) || b.id - a.id);
    await expect(vio.locator('tbody tr')).toHaveCount(want.length);
    await expect(vio.locator('thead th').first()).toHaveText('시각');
    await expect(vio.locator('thead th')).toContainText(['시각', '정책', '결과']);
    for (const tr of await vio.locator('tbody tr').all()) await expect(tr).not.toContainText('pkg-reqeusts-old');
    expect(backend.requests.some((q) => q.path.startsWith('/audit?') && q.path.includes('container=pkg-reqeusts'))).toBe(true);
    await page.screenshot({ path: `${SHOT}/watch-sheet-violations-1440-light.png` });

    // 최근 이벤트 — 이 컨테이너 것만(pkg-reqeusts-2 제외)
    await sheet.locator('[role="tab"][data-tab="events"]').click();
    const evs = sheet.getByTestId('watch-events');
    const mine = backend.recent.filter((v) => v.event.containerName === 'pkg-reqeusts');
    await expect(evs.locator('tbody tr')).toHaveCount(mine.length);
    await expect(evs.locator('thead th')).toHaveText(['시각', '종류', '프로세스', '대상']);
    expect(await evs.locator('tbody tr').evaluateAll((trs) => trs.map((t) => t.getAttribute('data-container')))).toEqual(mine.map(() => 'pkg-reqeusts'));
    await expect(evs).toContainText('/etc/shadow');
    expect(await dashes(page)).toEqual([]);
    await page.screenshot({ path: `${SHOT}/watch-sheet-events-1440-light.png` });

    // 위반 행 → 감사 로그 그 기록(?id=)
    await sheet.locator('[role="tab"][data-tab="violations"]').click();
    await vio.locator('tbody tr').first().click();
    await expect(page).toHaveURL(new RegExp(`/audit\\?id=${want[0].id}$`));
    await expect(page.locator('[data-sheet="audit"]')).toBeVisible();
  });

  test('열린 채 ↑↓ → 내용만 교체 · 「n / m」 · Enter 로 열기 · Esc 닫기', async ({ page, backend }) => {
    seedLookalikes(backend);
    await page.goto('/integration/watch');
    await ready(page);
    await row(page, 'web-api').focus();
    await page.keyboard.press('Enter');
    const sheet = page.locator(SHEET);
    await expect(sheet.locator('h2')).toHaveText('web-api');
    await expect(sheet.locator('[data-part="sheet-pos"]')).toHaveText('2 / 3');
    await expect(sheet.getByTestId('watch-info').locator('[data-field="enforce"] dd')).toContainText('격리 보류');
    // 열린 채 다음 행(↓, 뒤는 어둡게 덮여 있다) — 시트는 하나, 내용만 바뀐다(탭 유지)
    await sheet.locator('[role="tab"][data-tab="events"]').click();
    await expect(page).toHaveURL(/id=c-web&tab=events$/);
    await page.keyboard.press('ArrowDown');
    await expect(page).toHaveURL(/id=c-worker&tab=events$/);
    await expect(page.locator(SHEET)).toHaveCount(1);
    await expect(sheet.locator('h2')).toHaveText('worker');
    await expect(sheet.locator('[role="tab"][aria-selected="true"]')).toHaveText('최근 이벤트');
    await expect(sheet.getByTestId('watch-events').locator('tbody tr')).toHaveCount(backend.recent.filter((v) => v.event.containerName === 'worker').length);
    await page.keyboard.press('ArrowUp');
    await expect(sheet.locator('h2')).toHaveText('web-api');
    await page.keyboard.press('Escape');
    await expect(page.locator('.sg-sheet-layer')).toHaveCount(0);
    await expect(page).toHaveURL(/\/integration\/watch$/);
  });

  test('빈 이력 · 상세를 못 읽으면 서버 문장(상태 코드 없음) · 조회자도 읽기', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 404/); // 브라우저가 남기는 네트워크 줄(상세 404) — 앱 오류가 아니다
    backend.auth.asViewer();
    backend.detailMissing.add('c-worker');
    await page.goto('/integration/watch?id=c-worker&tab=violations');
    await ready(page);
    const sheet = page.locator(SHEET);
    await expect(sheet.getByTestId('watch-violations').locator('[data-part="empty"]')).toContainText('위반');
    await sheet.locator('[role="tab"][data-tab="info"]').click();
    const info = sheet.getByTestId('watch-info');
    await expect(info.locator('[data-part="error"]')).toContainText('컨테이너를 찾을 수 없습니다');
    await expect(info).not.toContainText('404');
    expect(await dashes(page)).toEqual([]);
  });

  test('1440 어두운 · 390 폭(전체 화면 시트)', async ({ page, backend }) => {
    seedLookalikes(backend);
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/integration/watch');
    await ready(page);
    await row(page, 'pkg-reqeusts').click();
    await expect(page.locator(SHEET).getByTestId('watch-info').locator('[data-field="state"] dd')).toHaveText('실행 중');
    await settled(page);
    await page.screenshot({ path: `${SHOT}/watch-sheet-info-1440-dark.png` });
    await page.locator(SHEET).locator('[role="tab"][data-tab="violations"]').click();
    await expect(page.locator(SHEET).getByTestId('watch-violations').locator('tbody tr').first()).toBeVisible();
    await page.screenshot({ path: `${SHOT}/watch-sheet-violations-1440-dark.png` });
    expect(await dashes(page)).toEqual([]);

    await page.emulateMedia({ colorScheme: 'light' });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/integration/watch?id=c-pkg');
    await ready(page);
    await settled(page);
    const box = await page.locator(SHEET).boundingBox();
    expect(box && [Math.round(box.x), Math.round(box.width)]).toEqual([0, 390]);
    await expect(page.locator(SHEET).getByTestId('watch-info').locator('[data-field="started"] dd')).toHaveText('2026-11-10 10:02:03');
    const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(over).toBe(0);
    await page.screenshot({ path: `${SHOT}/watch-sheet-info-390.png` });
    expect(await dashes(page)).toEqual([]);
  });
});
