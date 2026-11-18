import { test as base, expect, type Page } from '@playwright/test';
import { MockBackend } from './mock-backend';

export const SHOTS = 'test-results/screens';

interface Fixtures {
  backend: MockBackend;
  // 이 시나리오에서 일부러 내는 콘솔 오류(예: 「백엔드 미지원」 404) 허용 패턴
  allowConsole: (re: RegExp) => void;
}

// 느린 응답 흉내(기본 꺼짐): E2E_API_DELAY_MS=800 이면 page.route 로 가로챈 모든 요청을 그만큼 늦게 처리한다.
// CI 에서 API 응답이 늦을 때 「한 번만 읽는 비교」가 깨지는지 로컬에서 재현하는 용도. 요청마다 한 번만 늦춘다(fallback 이어받기 포함).
const API_DELAY_MS = Number(process.env.E2E_API_DELAY_MS) || 0;

function delayRoutes(page: Page) {
  const delayed = new WeakSet<object>();
  const route = page.route.bind(page);
  page.route = ((url, handler, options) =>
    route(
      url,
      async (r, req) => {
        if (!delayed.has(req)) {
          delayed.add(req);
          await new Promise((res) => setTimeout(res, API_DELAY_MS));
        }
        return handler(r, req);
      },
      options,
    )) as Page['route'];
}

// 모든 시나리오: 계약 모양의 가짜 백엔드를 붙이고, 끝날 때 콘솔 오류 0 을 확인한다.
export const test = base.extend<Fixtures & { _console: string[]; _allowed: RegExp[] }>({
  page: async ({ page }, use) => {
    if (API_DELAY_MS > 0) delayRoutes(page);
    await use(page);
  },
  _allowed: async ({}, use) => {
    await use([]);
  },
  _console: async ({ page }, use) => {
    const errors: string[] = [];
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
    page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
    await use(errors);
  },
  backend: async ({ page, _console, _allowed }, use) => {
    const b = new MockBackend();
    await b.attach(page);
    await use(b);
    const unexpected = _console.filter((t) => !_allowed.some((re) => re.test(t)));
    expect(unexpected, '콘솔 오류 0').toEqual([]);
  },
  allowConsole: async ({ _allowed }, use) => {
    await use((re) => _allowed.push(re));
  },
});

export { expect };

// 11/05 슬라이드 패널 닫기 — Esc 뒤 미끄러져 나갈 때까지
export async function closeSheet(page: Page) {
  await page.keyboard.press('Escape');
  await expect(page.locator('.sg-sheet-layer')).toHaveCount(0);
}

// 페이지 넘침 검사: 문서 · main 모두 스크롤이 생기지 않아야 한다(표 · 피드 · 시트만 스크롤)
export async function noPageOverflow(page: Page) {
  const r = await page.evaluate(() => {
    const d = document.documentElement;
    const main = document.querySelector('main')!;
    return {
      docH: d.scrollHeight - window.innerHeight,
      docW: d.scrollWidth - window.innerWidth,
      mainH: main.scrollHeight - main.clientHeight,
      mainW: main.scrollWidth - main.clientWidth,
    };
  });
  expect(r, `페이지 넘침 ${JSON.stringify(r)}`).toEqual({ docH: 0, docW: 0, mainH: 0, mainW: 0 });
}
