import { expect, noPageOverflow, SHOTS, test } from './fixtures';

const SCREENS: [string, string, string][] = [
  ['01-dashboard', '/', 'pending'],
  ['02-installs', '/installs?id=ins-0012', 'installs'],
  ['03-events', '/events?id=7', 'events'],
  ['04-topology', '/topology?container=pkg-reqeusts&node=c%3Apkg-reqeusts', 'topology'],
  ['05-policies', '/policies?id=egress-allowlist', 'rules'],
  ['06-audit', '/audit', 'audit'],
];

for (const [w, h] of [
  [1440, 900],
  [1280, 800],
]) {
  test.describe(`${w}x${h} 페이지 넘침 0`, () => {
    test.use({ viewport: { width: w, height: h } });
    for (const [name, url, testId] of SCREENS) {
      test(`${name}`, async ({ page, backend }) => {
        void backend;
        await page.goto(url);
        await expect(page.getByTestId(testId)).toBeVisible();
        if (name === '04-topology') await expect(page.locator('.react-flow__node').first()).toBeVisible();
        await page.waitForTimeout(400);
        await noPageOverflow(page);
        await page.screenshot({ path: `${SHOTS}/${w}-${name}.png` });
      });
    }
    test('07-policies-proposal', async ({ page, backend }) => {
      void backend;
      await page.goto('/installs?id=ins-0011');
      await page.getByTestId('decision').getByRole('button', { name: '오탐' }).click();
      await page.getByRole('button', { name: '제안 보기' }).click();
      await page.getByRole('button', { name: '미리보기' }).click();
      await expect(page.getByTestId('preview-summary')).toBeVisible();
      await noPageOverflow(page);
      await page.screenshot({ path: `${SHOTS}/${w}-07-policies-proposal.png` });
    });
    test('08-audit-history', async ({ page, backend }) => {
      void backend;
      await page.goto('/audit?view=changes');
      await expect(page.getByTestId('history')).toBeVisible();
      await noPageOverflow(page);
      await page.screenshot({ path: `${SHOTS}/${w}-08-audit-history.png` });
    });
  });
}
