import { defineConfig } from '@playwright/test'

// End-to-end tests in headless Chromium against the dev server. The live run (e2e/live.spec.ts)
// needs E2E_DIR (a scratch directory for its state, browser profiles and screenshots) and
// WINTERLOCK_ENV_FILE (the git-ignored .env with the test keys); see README.md. No traces or
// videos: they would record what is typed, RPC keys included.
const port = Number(process.env.E2E_PORT ?? 5190)

export default defineConfig({
  testDir: 'e2e',
  timeout: 15 * 60_000,
  workers: 1,
  fullyParallel: false,
  reporter: 'list',
  outputDir: process.env.E2E_DIR ? `${process.env.E2E_DIR}/test-results` : 'test-results',
  use: {
    baseURL: `http://localhost:${port}`,
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },
  webServer: {
    command: `npx vite --port ${port} --strictPort`,
    url: `http://localhost:${port}`,
    reuseExistingServer: true,
    timeout: 60_000,
  },
})
