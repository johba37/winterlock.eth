import { fileURLToPath } from 'node:url'
import preact from '@preact/preset-vite'
import { defineConfig, loadEnv, type Plugin } from 'vite'

// The production page's Content Security Policy: scripts only from the app itself (and its
// WebAssembly), no third-party code at run time. connect-src stays open to any https endpoint
// because the RPC URL is the member's choice; localhost is for a local chain. WalletConnect adds
// one WebSocket origin, Reown's relay. Frames stay at 'self' (default-src): WalletConnect's Verify
// API would load an iframe from verify.walletconnect.org, and the app switches it off
// (src/lib/walletconnect.ts).
const RELAY = 'wss://relay.walletconnect.org'
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "worker-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self' https: http://localhost:* http://127.0.0.1:* ${RELAY}`,
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

export default defineConfig(({ command, mode }) => {
  // Development only: SAFE_API_KEY from the environment, added by the dev server's proxy for
  // writes to Safe's service when VITE_SERVICE_PROXY=/safe-service is set. Never bundled: the
  // key stays in this Node process and only the dev server's proxy sees it.
  const env = loadEnv(mode, process.cwd(), '')
  const key = process.env.SAFE_API_KEY ?? env.SAFE_API_KEY
  return {
    base: './',
    plugins: [preact(), csp()],
    // the virtual board: the dev server and the tests only, unless VIRTUAL_BOARD=1 (src/board/dev.d.ts)
    define: { __VIRTUAL_BOARD__: JSON.stringify(command === 'serve' || mode === 'test' || process.env.VIRTUAL_BOARD === '1') },
    resolve: {
      // WalletKit's payments client (api.pay.walletconnect.com, with its own WebAssembly) stays out
      alias: { '@walletconnect/pay': fileURLToPath(new URL('src/lib/wc-pay-stub.ts', import.meta.url)) },
    },
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
