import type { Page } from '@playwright/test';
import type { Scan } from '../src/lib/types';
import { expect, noPageOverflow, SHOTS, test } from './fixtures';

// 11/04 종합 판정(라운드 계획 2단계 — 2026-11-03 설계 승인, 목업 main 617b658 확정 뒤 React).
// sg-install 세션 시작 때 서버가 같은 패키지의 정적 검사(GuardDog + OSV)를 자동으로 시작하고, 설치 화면 한 건에 런타임 + 정적 결과를 나란히 보인다.
// 가짜 백엔드 고정 데이터: ins-0013 검사 중 · ins-0012 로컬 건너뜀 · ins-0011 경고 + 정상 · ins-0010 통과 + 정상(재사용) · ins-0009 cargo 건너뜀
//   · ins-0008 검사 실패 · ins-0007 취약 · ins-0006 옛 세션(scan 없음). 정적 악성 · 정적만 실행 중은 도우미(staticMalicious · scanRunning)로 넣는다

const NOTE_RUNTIME = '정적 검사로는 악성 코드를 찾지 못했지만, 설치 중 행동을 커널에서 보고 잡았습니다.';
const NOTE_STATIC = '설치 중 정책 위반은 없었지만, 정적 검사에서 설치 단계의 위험한 코드가 나왔습니다 — 공급망 검사에서 코드를 확인하세요.';
const SKIP_LOCAL = '로컬 패키지라 정적 검사 건너뜀';
const SKIP_CARGO = 'cargo 는 정적 검사 미지원';

const sheet = (page: Page) => page.locator('[data-sheet="install"]');
const row = (page: Page, id: string) => page.locator(`tr[data-install="${id}"]`);
const allRows = async (page: Page) => {
  await page.goto('/installs');
  await page.locator('[data-chip="all"]').click();
  await expect(page.locator('tr[data-install]').first()).toBeVisible();
};
// var(--danger) 로 칠한 글자인가(라이트 · 다크 모두 토큰 값으로 비교)
const isDanger = (page: Page, sel: string) =>
  page.locator(sel).evaluate((el) => {
    const probe = document.createElement('span');
    probe.style.color = 'var(--danger)';
    document.body.append(probe);
    const want = getComputedStyle(probe).color;
    probe.remove();
    return getComputedStyle(el).color === want;
  });
const visibleHeads = (page: Page) =>
  page.locator('[data-testid="installs"] thead th').evaluateAll((els) => els.filter((e) => (e as HTMLElement).offsetParent !== null).map((e) => e.textContent!.trim()));

// /scans?id= 링크를 눌렀을 때 공급망 검사 화면이 그 검사를 연다 — mock-backend 에는 /api/scans 가 없어 여기서만 가로챈다
const now = new Date().toISOString();
const requestsScan: Scan = {
  id: 'scan-0101',
  target: { kind: 'package', manager: 'pip', name: 'requests', version: '2.32.3', label: 'pip requests' },
  status: 'done', startedAt: now, finishedAt: now, verdict: 'clean', risk: { score: 0, label: 'no_risks_detected' },
  engines: [{ name: 'GuardDog', version: '3.2.0' }, { name: 'OSV-Scanner', version: '2.7.0' }],
  findings: [], vulns: [], packages: [], files: {}, caseId: null, threats: 0, capabilities: 0, vulnCount: 0, vulnMax: null,
};
const stubScans = (page: Page) =>
  page.route(/\/api\/scans(\/|$|\?)/, (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    const body = path === '/scans' ? [requestsScan] : path === `/scans/${requestsScan.id}` ? requestsScan : null;
    return body ? route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) }) : route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"검사 없음"}' });
  });

test.describe('11/04 종합 판정 — 설치 한 건에 런타임 + 정적 결과', () => {
  test('① 목록: 설치 결과 다음 「정적 검사」 열 · 배지(악성 의심 · 취약점 있음 · 위협 없음 · 검사 중… · 실패 · —) · 건너뜀 title', async ({ page, backend }) => {
    backend.staticMalicious();
    await allRows(page);
    const heads = await visibleHeads(page);
    expect(heads.indexOf('정적 검사'), `열 ${JSON.stringify(heads)}`).toBe(heads.indexOf('설치 결과') + 1);
    expect(heads.indexOf('설치 결과')).toBeGreaterThan(0);
    const badge = (id: string) => row(page, id).locator('[data-static]');
    await expect(badge('ins-0014')).toHaveText('악성 의심');
    await expect(badge('ins-0014')).toHaveAttribute('data-static', 'malicious');
    await expect(badge('ins-0007')).toHaveText('취약점 있음');
    await expect(badge('ins-0010')).toHaveText('위협 없음');
    await expect(badge('ins-0013')).toHaveText('검사 중…');
    await expect(badge('ins-0013')).toHaveAttribute('data-static', 'running');
    await expect(badge('ins-0008')).toHaveText('실패');
    await expect(badge('ins-0008')).toHaveAttribute('title', 'GuardDog 시간 초과(120초)'); // 실패: title 에 오류
    // 건너뜀: 회색 「—」 + title 에 이유 · 옛 세션(scan 없음): 「—」 title 없음
    await expect(badge('ins-0012')).toHaveText('—');
    await expect(badge('ins-0012')).toHaveAttribute('data-static', 'skipped');
    await expect(badge('ins-0012')).toHaveAttribute('title', SKIP_LOCAL);
    await expect(badge('ins-0009')).toHaveAttribute('title', SKIP_CARGO);
    await expect(badge('ins-0006')).toHaveText('—');
    await expect(badge('ins-0006')).toHaveAttribute('data-static', 'none');
    expect(await badge('ins-0006').getAttribute('title')).toBeNull();
    // 공급망 검사 화면의 판정 배지 그대로 — 악성 의심은 빨강 계열 배경(위험에만)
    await page.screenshot({ path: `${SHOTS}/1104-list.png` });
  });

  test('② 상세 정적 칸: 「정적 검사 · GuardDog + OSV」 · 배지 · 위험 점수 N / 10 · 라벨 + 받은 버전 · 재사용 · /scans?id= 링크', async ({ page, backend }) => {
    await stubScans(page);
    await page.goto('/installs?id=ins-0010');
    const cell = sheet(page).getByTestId('static-result');
    await expect(cell).toBeVisible();
    await expect(cell.locator('[data-part="static-head"]')).toHaveText('정적 검사 · GuardDog + OSV');
    await expect(cell.locator('[data-static="clean"]')).toHaveText('위협 없음');
    await expect(cell.locator('[data-part="risk"]')).toHaveText('위험 점수 0.0 / 10');
    expect(await isDanger(page, '[data-testid="static-result"] [data-part="risk"]')).toBe(false); // 악성일 때만 빨강
    await expect(cell.locator('[data-part="static-target"]')).toHaveText('pip requests · 2.32.3 · 24시간 안 검사 결과 재사용');
    const link = cell.getByRole('link', { name: '공급망 검사에서 보기 →' });
    await expect(link).toHaveAttribute('href', '/scans?id=scan-0101');
    // 정적 검사가 있으면 OSV 이름 조회 칸 · 조회 요청이 없다. 오른쪽 커널 칸은 그대로
    await expect(sheet(page).getByTestId('osv-result')).toHaveCount(0);
    await expect(sheet(page).getByTestId('kernel-result')).toContainText('0건');
    expect(backend.requests.some((r) => r.path.startsWith('/osv'))).toBe(false);
    await page.screenshot({ path: `${SHOTS}/1104-detail.png` });
    // 재사용이 아니면 문구 없음 · 악성이면 점수 빨강
    await page.goto('/installs?id=ins-0011');
    await expect(sheet(page).locator('[data-part="static-target"]')).toHaveText('npm tiny-git-dep · 1.0.0');
    backend.staticMalicious();
    await page.goto('/installs?id=ins-0014');
    await expect(sheet(page).locator('[data-part="risk"]')).toHaveText('위험 점수 8.6 / 10');
    expect(await isDanger(page, '[data-testid="static-result"] [data-part="risk"]')).toBe(true);
    // 실패: 회색 「실패」(title 에 오류) · 점수 없음
    await page.goto('/installs?id=ins-0008');
    await expect(sheet(page).locator('[data-testid="static-result"] [data-static="failed"]')).toHaveAttribute('title', 'GuardDog 시간 초과(120초)');
    await expect(sheet(page).locator('[data-testid="static-result"] [data-part="risk"]')).toHaveCount(0);
    // 링크 → 공급망 검사 화면에서 그 검사가 열린다
    await page.goto('/installs?id=ins-0010');
    await sheet(page).getByRole('link', { name: '공급망 검사에서 보기 →' }).click();
    await expect(page).toHaveURL(/\/scans\?id=scan-0101$/);
    await expect(page.locator('[data-sheet="scan"]')).toBeVisible();
  });

  test('③ 엇갈릴 때만 빨간 한 줄 — 런타임 격리 · 경고 + 정적 정상/건너뜀 · 런타임 통과 + 정적 악성', async ({ page, backend }) => {
    backend.staticMalicious();
    const note = () => sheet(page).locator('[data-part="cmp-note"]');
    await page.goto('/installs?id=ins-0011'); // 경고 + 정상
    await expect(note()).toHaveText(NOTE_RUNTIME);
    expect(await isDanger(page, '[data-part="cmp-note"]')).toBe(true);
    await page.screenshot({ path: `${SHOTS}/1104-mismatch-runtime.png` });
    await page.goto('/installs?id=ins-0014'); // 통과 + 악성
    await expect(note()).toHaveText(NOTE_STATIC);
    expect(await isDanger(page, '[data-part="cmp-note"]')).toBe(true);
    await page.screenshot({ path: `${SHOTS}/1104-mismatch.png` });
    await page.goto('/installs?id=ins-0012'); // 격리 + 건너뜀(로컬)
    await expect(sheet(page).getByTestId('osv-result')).toBeVisible();
    await expect(note()).toHaveText(NOTE_RUNTIME);
    // 엇갈리지 않으면 문장 없음: 통과 + 정상 · 설치 실패 + 취약
    for (const id of ['ins-0010', 'ins-0007']) {
      await page.goto(`/installs?id=${id}`);
      await expect(sheet(page).getByTestId('static-result')).toBeVisible();
      await expect(note()).toHaveCount(0);
    }
  });

  test('④ 정적 검사만 실행 중이면 상세가 2초마다 다시 불러 done 으로 바뀌고, 끝나면 멈춘다', async ({ page, backend }) => {
    backend.scanRunning();
    await page.goto('/installs?id=ins-0015');
    const cell = sheet(page).getByTestId('static-result');
    await expect(cell.locator('[data-static="running"]')).toHaveText('검사 중…');
    await expect(cell.locator('[data-part="risk"]')).toHaveCount(0); // 실행 중이면 점수 숨김
    const gets = () => backend.requests.filter((r) => r.method === 'GET' && r.path === '/installs/ins-0015').length;
    const before = gets();
    backend.finishScan('ins-0015', { verdict: 'clean', riskScore: 0.4 });
    await expect(cell.locator('[data-static="clean"]')).toHaveText('위협 없음', { timeout: 4500 });
    await expect(cell.locator('[data-part="risk"]')).toHaveText('위험 점수 0.4 / 10');
    expect(gets()).toBeGreaterThan(before);
    const after = gets();
    await page.waitForTimeout(2600);
    expect(gets(), '끝난 뒤에도 상세를 계속 부름').toBe(after);
  });

  test('⑤ 옛 백엔드(scan 없음): 목록 「—」 + 상세는 지금의 OSV 칸 그대로(하위 호환) · 건너뜀은 OSV 부제에 이유', async ({ page, backend }) => {
    // 건너뜀(로컬): OSV 칸 그대로 + 부제 끝에 이유
    await page.goto('/installs?id=ins-0012');
    await expect(sheet(page).getByTestId('osv-result').locator('[data-osv="0"]')).toContainText('0건');
    await expect(sheet(page).getByTestId('osv-result')).toContainText(`PyPI · reqeusts · ${SKIP_LOCAL}`);
    await expect(sheet(page).getByTestId('static-result')).toHaveCount(0);
    // 옛 백엔드: 어떤 세션에도 scan · scanId · scanSkip 이 없다
    for (const s of backend.installs) {
      delete s.scan;
      delete s.scanId;
      delete s.scanSkip;
    }
    await allRows(page);
    const marks = await page.locator('tr[data-install] [data-static]').evaluateAll((els) => els.map((e) => [e.getAttribute('data-static'), e.textContent, e.getAttribute('title')]));
    expect(marks.length).toBe(8);
    expect(marks.every(([k, t, ti]) => k === 'none' && t === '—' && ti === null), JSON.stringify(marks)).toBe(true);
    await page.goto('/installs?id=ins-0012');
    const osv = sheet(page).getByTestId('osv-result');
    await expect(osv).toContainText('버전 무관');
    await expect(osv.locator('[data-osv="0"]')).toContainText('0건');
    await expect(osv).not.toContainText('건너뜀');
    await expect(sheet(page).getByTestId('kernel-result')).toContainText('6건');
    await expect(sheet(page).locator('[data-part="cmp-note"]')).toHaveCount(0);
  });

  test('⑥ 시트가 열리면 「걸린 시간」 열을 숨기고(상세에 같은 값), 닫으면 다시 보인다 — 1440 에서 표가 가로로 넘치지 않는다', async ({ page, backend }) => {
    void backend;
    await allRows(page);
    expect(await visibleHeads(page)).toContain('걸린 시간');
    await row(page, 'ins-0010').click();
    await expect(sheet(page)).toBeVisible();
    await expect.poll(() => visibleHeads(page)).not.toContain('걸린 시간');
    const cells = await row(page, 'ins-0010').locator('td').evaluateAll((els) => els.filter((e) => (e as HTMLElement).offsetParent !== null).length);
    expect(cells).toBe(7);
    await expect(sheet(page).locator('dl')).toContainText('걸린 시간'); // 상세에는 그대로
    const over = await page.locator('[data-testid="installs"] table').evaluate((t) => t.parentElement!.scrollWidth - t.parentElement!.clientWidth);
    expect(over, `표 가로 넘침 ${over}px`).toBeLessThanOrEqual(0);
    await page.keyboard.press('Escape');
    await expect(sheet(page)).toHaveCount(0);
    await expect.poll(() => visibleHeads(page)).toContain('걸린 시간');
  });

  test('⑦ 빨간 행 = 런타임 격리 · 경고 또는 정적 악성', async ({ page, backend }) => {
    backend.staticMalicious();
    await allRows(page);
    const danger = await page.locator('tr[data-install]').evaluateAll((els) =>
      Object.fromEntries(els.map((e) => [e.getAttribute('data-install'), e.getAttribute('data-danger') === 'true' && getComputedStyle(e).boxShadow.includes('inset')])),
    );
    expect(danger).toEqual({
      'ins-0014': true, // 통과 + 정적 악성
      'ins-0013': false,
      'ins-0012': true, // 격리
      'ins-0011': true, // 경고
      'ins-0010': false,
      'ins-0009': false,
      'ins-0008': false,
      'ins-0007': false, // 설치 실패 + 취약 — 빨강 아님
      'ins-0006': true, // 격리(옛 세션)
    });
    // 정적만 악성이면 건을 열지 않는다 — 판정 열 「—」, 기본 「판정 대기」 보기에는 없다
    await expect(row(page, 'ins-0014').locator('td').nth(5)).toHaveText('—');
  });

  for (const [name, vp, theme] of [
    ['375', { width: 375, height: 812 }, 'light'],
    ['dark', { width: 1440, height: 900 }, 'dark'],
  ] as const) {
    test(`⑧ ${name}: 정적 칸 · 엇갈림 한 줄이 넘치지 않는다${name === '375' ? '(두 칸은 한 열)' : ''}`, async ({ page, backend }) => {
      backend.staticMalicious();
      await page.setViewportSize(vp);
      if (theme === 'dark') await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
      await page.goto('/installs?id=ins-0014');
      const cell = sheet(page).getByTestId('static-result');
      await expect(cell).toBeVisible();
      await expect(sheet(page).locator('[data-part="cmp-note"]')).toHaveText(NOTE_STATIC);
      await page.waitForTimeout(350); // 시트 애니메이션
      await noPageOverflow(page);
      const sw = await sheet(page).evaluate((e) => {
        const body = e.querySelector(':scope > div')!;
        return body.scrollWidth - body.clientWidth;
      });
      expect(sw, '시트 가로 넘침').toBeLessThanOrEqual(0);
      const boxes = await sheet(page)
        .getByTestId('osv')
        .locator('[data-cell]')
        .evaluateAll((els) => els.map((e) => e.getBoundingClientRect()).map((r) => ({ l: Math.round(r.left), t: Math.round(r.top), r: Math.round(r.right), b: Math.round(r.bottom) })));
      expect(boxes.length).toBe(2);
      for (const b of boxes) expect(b.r).toBeLessThanOrEqual(vp.width);
      if (name === '375') expect(boxes[1].t, `한 열 아님 ${JSON.stringify(boxes)}`).toBeGreaterThanOrEqual(boxes[0].b - 1);
      else {
        expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
        const bg = await cell.locator('[data-static]').evaluate((e) => getComputedStyle(e).backgroundColor);
        expect(bg).not.toBe('rgba(0, 0, 0, 0)');
        expect(await isDanger(page, '[data-part="cmp-note"]')).toBe(true);
      }
      await page.screenshot({ path: `${SHOTS}/1104-${name}.png` });
      if (name === '375') {
        // 목록(시트 닫힘)도 넘치지 않는다 — 표는 가로 스크롤 컨테이너 안
        await page.keyboard.press('Escape');
        await page.locator('[data-chip="all"]').click();
        await expect(row(page, 'ins-0014').locator('[data-static="malicious"]')).toBeVisible();
        await noPageOverflow(page);
      }
    });
  }
});
