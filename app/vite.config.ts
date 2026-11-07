import preact from '@preact/preset-vite'
import { defineConfig, loadEnv, type Plugin } from 'vite'

// The production page's Content Security Policy: scripts only from the app itself (and its
// WebAssembly), no third-party code at run time. connect-src stays open to any https endpoint
// because the RPC URL is the member's choice; localhost is for a local chain.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "worker-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ')

function csp(): Plugin {
  return {
    name: 'winterlock-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace('<meta charset="utf-8">', `<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="${CSP}">`)
    },
  }
}

export default defineConfig(({ mode }) => {
  // Development only: SAFE_API_KEY from the environment, added by the dev server's proxy for
  // writes to Safe's service when VITE_SERVICE_PROXY=/safe-service is set. Never bundled: the
  // key stays in this Node process and only the dev server's proxy sees it.
  const env = loadEnv(mode, process.cwd(), '')
  const key = process.env.SAFE_API_KEY ?? env.SAFE_API_KEY
  return {
    base: './',
    plugins: [preact(), csp()],
    worker: { format: 'es' },
    build: { target: 'es2022', sourcemap: true, assetsInlineLimit: 0 },
    server: {
      fs: { allow: ['..'] },
      proxy: key
        ? {
            '/safe-service': {
              target: 'https://api.safe.global',
              changeOrigin: true,
              rewrite: (p) => p.replace(/^\/safe-service/, ''),
              headers: { Authorization: `Bearer ${key}` },
            },
          }
        : undefined,
    },
    test: {
      environment: 'node',
      setupFiles: ['test/setup.ts'],
      include: ['test/**/*.test.ts'],
      testTimeout: 60_000,
    },
  }
})
