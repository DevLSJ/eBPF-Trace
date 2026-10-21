import { expect, test } from './fixtures';
import { killedVerdict, normalVerdict } from './mock-backend';

test.describe('이벤트 — 지금 무엇이 걸리고 있나?', () => {
  test('① 실시간만(기간 조회 없음) ② 기본 위반만, 「정상 포함」 토글', async ({ page, backend }) => {
    void backend;
    await page.goto('/events');
    await expect(page.getByRole('group', { name: '기간' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '1h' })).toHaveCount(0);
    const rows = page.locator('li[data-key]');
    await expect(rows).toHaveCount(7); // 런타임 5 + 설치 검사 2, 정상 4 는 숨김
    await expect(page.locator('li[data-level="normal"]')).toHaveCount(0);
    // 필터는 화면 상태로만(10/21) — 주소에 normal 이 남지 않는다
    await page.getByLabel('정상 포함').click();
    await expect(page.getByLabel('정상 포함')).toBeChecked();
    expect(new URL(page.url()).search).toBe('');
    await expect(rows).toHaveCount(11);
    await page.getByLabel('정상 포함').click();
    await expect(page.getByLabel('정상 포함')).not.toBeChecked();
    await page.getByLabel('탐지 결과').selectOption('alert');
    await expect(rows).toHaveCount(1);
  });

  test('WS 로 들어온 위반이 바로 맨 위에 보인다(기존 피드 동작)', async ({ page, backend }) => {
    await page.goto('/events');
    await expect(page.locator('li[data-key]')).toHaveCount(7);
    backend.send({ type: 'verdict', data: killedVerdict('api-gw') });
    backend.send({ type: 'verdict', data: normalVerdict('api-gw', '/tmp/x') });
    await expect(page.locator('li[data-key]')).toHaveCount(8);
    await expect(page.locator('li[data-key]').first()).toContainText('api-gw');
    await page.getByRole('button', { name: '일시정지' }).click();
    backend.send({ type: 'verdict', data: killedVerdict('api-gw2') });
    await page.waitForTimeout(600);
    await expect(page.locator('li[data-key]')).toHaveCount(8);
    await page.getByRole('button', { name: '재개' }).click();
  });

  test('③ 행 상세 시트에 「토폴로지에서 보기」', async ({ page, backend }) => {
    void backend;
    // 바깥 링크 · 예전 북마크의 ?container= 는 한 번 적용하고 주소에서 지운다(10/21)
    await page.goto('/events?container=pkg-reqeusts');
    await expect(page.getByPlaceholder('이름 검색')).toHaveValue('pkg-reqeusts');
    await expect(page).toHaveURL(/\/events$/);
    const row = page.locator('li[data-key]').first();
    await row.focus();
    await page.keyboard.press('Enter');
    const sheet = page.locator('[data-sheet="event"]');
    await expect(sheet).toBeVisible();
    await expect(page).toHaveURL(/id=\d+/);
    await expect(sheet).toContainText('탐지 결과');
    await sheet.getByRole('link', { name: '토폴로지에서 보기' }).click();
    await expect(page).toHaveURL(/\/topology\?node=c%3Apkg-reqeusts$/);
    await expect(page.getByRole('combobox', { name: /^컨테이너/ })).toHaveValue('pkg-reqeusts');
    await expect(page.getByTestId('node-detail')).toContainText('pkg-reqeusts');
  });

  test('설치 검사 컨테이너 이벤트는 설치 검사로 안내', async ({ page, backend }) => {
    void backend;
    await page.goto('/events?container=sg-install');
    await page.locator('li[data-key]').first().click();
    await expect(page.locator('[data-sheet="event"]').getByRole('link', { name: /설치 검사에서 보기/ })).toBeVisible();
  });
});
