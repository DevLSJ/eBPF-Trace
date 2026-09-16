import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  use: {
    baseURL: 'http://127.0.0.1:15173',
    trace: 'retain-on-failure',
    launchOptions: process.env.PLAYWRIGHT_CHROME ? { executablePath: process.env.PLAYWRIGHT_CHROME } : {},
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 1000 } } },
    { name: 'mobile', use: { ...devices['Desktop Chrome'], viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
  webServer: [
    { command: '../.venv/bin/python -m uvicorn infra.e2e_app:app --app-dir .. --host 127.0.0.1 --port 18001', url: 'http://127.0.0.1:18001/health', reuseExistingServer: false },
    { command: `${process.execPath} node_modules/vite/bin/vite.js --host 127.0.0.1 --port 15173 --strictPort`, url: 'http://127.0.0.1:15173', env: { E2E_API_TARGET: 'http://127.0.0.1:18001' }, reuseExistingServer: false },
  ],
});
