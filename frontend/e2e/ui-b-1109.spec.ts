import type { Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 11/09 저녁 묶음 B — 피드백 · 오류 · 상태(참고 제품 UI 문서 대조 항목)
//   G14 연결 실패 = 고정 문장(「Failed to fetch」 없음) · 화면에 상태 코드(「500 ·」) 없음 — 서버 문장만, 없을 때만 상태별 고정 문장
// 화면 사진은 UI_SHOTS(없으면 SHOTS)에

const OUT = process.env.UI_SHOTS ?? SHOTS;
const NET = '서버에 연결하지 못했습니다. 네트워크를 확인한 뒤 다시 시도하세요.';
const RECENT = /\/api\/events\/recent/;
const listError = (page: Page) => page.locator('[data-part="error"]');

test.describe('G14 오류 문구', () => {
  test('연결 실패(요청 자체가 끊김) → 고정 문장 · 「Failed to fetch」 없음', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/Failed to load resource|ERR_FAILED/);
    await page.route(RECENT, (r) => r.abort('failed'));
    await page.goto('/events');
    const err = listError(page);
    await expect(err).toContainText('불러오지 못했습니다');
    await expect(err).toContainText(NET);
    await expect(page.locator('body')).not.toContainText(/Failed to fetch|TypeError|NetworkError/);
    await page.screenshot({ path: `${OUT}/ui-b-net-error-1440.png` });
  });

  test('500 + 서버 문장 → 서버 문장만(상태 코드 글자 없음)', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 500/);
    backend.failing.set('/events/recent', 500);
    await page.goto('/events');
    const err = listError(page);
    await expect(err).toContainText('모의 오류(서버가 응답하지 않습니다)');
    await expect(err).not.toContainText('500');
    await expect(err).not.toContainText(' · 모의');
  });

  test('500 + 서버 문장 없음(텍스트 본문) → 상태별 고정 문장 · 영어 상태 글 없음', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/status of 500/);
    await page.route(RECENT, (r) => r.fulfill({ status: 500, contentType: 'text/plain', body: 'Internal Server Error' }));
    await page.goto('/events');
    const err = listError(page);
    await expect(err).toContainText('서버에서 오류가 났습니다. 잠시 뒤 다시 시도하세요.');
    await expect(err).not.toContainText('500');
    await expect(err).not.toContainText('Internal Server Error');
  });

  test('다른 화면의 셸 띠도 상태 코드 없이 서버 문장만', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 503/);
    backend.failing.set('/events/recent', 503);
    await page.goto('/');
    const banner = page.locator('[data-banner="load"]');
    await expect(banner).toContainText('모의 오류(서버가 응답하지 않습니다)');
    await expect(banner).not.toContainText('503');
  });
});
