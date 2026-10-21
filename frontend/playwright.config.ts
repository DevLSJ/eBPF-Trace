import { defineConfig, devices } from '@playwright/test';

// React E2E — 백엔드 없이 계약(Claude Docs 「API 계약」) 모양의 고정 응답을 page.route 로 준다.
// Vite 는 5174 (사용자 5173 과 겹치지 않게). 프록시 대상은 닫힌 포트로 돌려 실제 백엔드(:8000)에 닿지 않게 한다.
const PORT = Number(process.env.PW_PORT) || 5174;

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results/pw',
  fullyParallel: true,
  workers: process.env.CI ? 2 : 4,
  retries: 0,
  reporter: [['list']],
  timeout: 30_000,
  expect: { timeout: 5_000 },
  use: {
    ...devices['Desktop Chrome'],
    baseURL: `http://127.0.0.1:${PORT}`,
    viewport: { width: 1440, height: 900 },
    locale: 'ko-KR',
    timezoneId: 'Asia/Seoul',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `npx vite --port ${PORT} --strictPort --host 127.0.0.1`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: { API_TARGET: 'http://127.0.0.1:9' },
  },
});
