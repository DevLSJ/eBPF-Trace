// Read-only screenshots of the deployed application; no fixture data or API writes.
import { chromium } from '../../frontend/node_modules/playwright/index.mjs';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const baseURL = process.env.CAPTURE_URL || 'http://52.62.165.10';
const directory = fileURLToPath(new URL('../screenshots/', import.meta.url));
await mkdir(directory, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROME || undefined });
const errors = [];
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, locale: 'ko-KR', timezoneId: 'Asia/Seoul', deviceScaleFactor: 1 });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(baseURL, { waitUntil: 'networkidle' });
  await page.locator('.pagination').waitFor();
  await page.waitForFunction(() => !document.querySelector('.table-empty')?.textContent?.includes('불러오는'));
  await page.evaluate(() => document.fonts.ready);
  // Let real WebSocket samples accumulate; never seed a chart for the screenshot.
  await page.waitForTimeout(20000);
  await page.setViewportSize({ width: 1440, height: 1120 });
  await page.screenshot({ path: `${directory}dashboard-desktop.png` });
  await page.goto(`${baseURL}/#capture`);
  await page.locator('.evaluation-metrics').waitFor();
  await page.getByLabel('캡처 파일').selectOption('Thursday-WorkingHours.pcap');
  await page.screenshot({ path: `${directory}analysis-desktop.png`, fullPage: true });
  await page.locator('.model-panel').screenshot({ path: `${directory}model-evaluation.png` });
  const health = await (await page.request.get(`${baseURL}/health`)).json();
  const model = await (await page.request.get(`${baseURL}/api/analysis/model`)).json();
  const reports = await (await page.request.get(`${baseURL}/api/analysis/pcap`)).json();
  const desktopOverflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${baseURL}/#capture`);
  await page.locator('.evaluation-metrics').waitFor();
  await page.evaluate(() => scrollTo(0, 0));
  await page.screenshot({ path: `${directory}analysis-mobile.png` });
  const mobileOverflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  if (errors.length || desktopOverflow || mobileOverflow) throw new Error(JSON.stringify({ errors, desktopOverflow, mobileOverflow }));
  await writeFile(`${directory}capture-manifest.json`, JSON.stringify({ captured_at: new Date().toISOString(), base_url: baseURL, source: 'live production API; no seeded or injected traffic', health, evaluation: model.evaluation.performance, captures: reports.items.map(item => ({ source: item.source, matched: item.labels.counts.matched, coverage: item.labels.coverage })), page_errors: errors, desktop_overflow: desktopOverflow, mobile_overflow: mobileOverflow }, null, 2) + '\n');
  console.log('Saved four production screenshots and capture-manifest.json');
} finally {
  await browser.close();
}
