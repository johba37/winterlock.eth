import { defineConfig } from '@playwright/test'
import { projectId } from './e2e/env'

// End-to-end tests in headless Chromium against the dev server. The live run (e2e/live.spec.ts)
// needs E2E_DIR (a scratch directory for its state, browser profiles and screenshots) and
// WINTERLOCK_ENV_FILE (the git-ignored .env with the test keys); see README.md. No traces or
// videos: they would record what is typed, RPC keys included.
const port = Number(process.env.E2E_PORT ?? 5190)
// WalletConnect's project ID from WINTERLOCK_ENV_FILE, for the dev server (never printed). With
// E2E_PREVIEW=1 the runs use the production build (its Content Security Policy included), built
// outside dist/ and the repository's tracked files.
const pid = projectId()
const out = process.env.E2E_DIR ? `${process.env.E2E_DIR}/preview-dist` : 'node_modules/.cache/preview-dist'

export default defineConfig({
  testDir: 'e2e',
  timeout: 15 * 60_000,
  workers: 1,
  fullyParallel: false,
  reporter: 'list',
  // scrubs the run's own files of the .env's values, whatever wrote them
  globalTeardown: './e2e/scrub.ts',
  outputDir: process.env.E2E_DIR ? `${process.env.E2E_DIR}/test-results` : 'test-results',
  use: {
    baseURL: `http://localhost:${port}`,
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },
  webServer: {
    command: process.env.E2E_PREVIEW ? `npx vite build --outDir ${out} --emptyOutDir && npx vite preview --outDir ${out} --port ${port} --strictPort` : `npx vite --port ${port} --strictPort`,
    env: pid ? { VITE_WALLETCONNECT_PROJECT_ID: pid } : {},
    url: `http://localhost:${port}`,
    reuseExistingServer: true,
    timeout: 180_000,
  },
})
