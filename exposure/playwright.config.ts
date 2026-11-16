import { defineConfig } from '@playwright/test'

// The built page (npm run build first) in headless Chromium, served by vite preview, under its own
// Content Security Policy. The lookups of live Sepolia Safes run with EXPOSURE_LIVE=1.
const port = Number(process.env.E2E_PORT ?? 4317)

export default defineConfig({
  testDir: 'e2e',
  timeout: 120_000,
  workers: 1,
  reporter: 'list',
  outputDir: process.env.E2E_DIR ? `${process.env.E2E_DIR}/test-results` : 'test-results',
  use: { baseURL: `http://localhost:${port}`, trace: 'off', video: 'off', screenshot: 'off' },
  webServer: {
    command: `npx vite preview --port ${port} --strictPort`,
    url: `http://localhost:${port}`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
})
