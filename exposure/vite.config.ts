/// <reference types="vitest/config" />
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { defineConfig, type Plugin } from 'vite'

// The page's Content Security Policy: scripts, styles and fonts from the page itself only, no
// inline script or style, nothing framed, no forms posted. connect-src is open to https because
// the RPC endpoint is the reader's choice (as in the signer app); the page itself only ever calls
// that endpoint and Safe's Transaction Service. localhost is for a local node.
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  'connect-src https: http://localhost:* http://127.0.0.1:*',
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ')

function csp(): Plugin {
  return {
    name: 'exposure-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace('<meta charset="utf-8">', `<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="${CSP}">`)
    },
  }
}

// The landing page's fonts (../fonts) come in through the stylesheet; their licence texts go
// alongside them, as the SIL Open Font License asks.
function fontLicences(): Plugin {
  return {
    name: 'exposure-font-licences',
    apply: 'build',
    generateBundle() {
      for (const name of ['OFL-atkinson-next.txt', 'OFL-atkinson-mono.txt']) {
        this.emitFile({ type: 'asset', fileName: `fonts/${name}`, source: readFileSync(fileURLToPath(new URL(`../fonts/${name}`, import.meta.url))) })
      }
    },
  }
}

export default defineConfig({
  base: './',
  plugins: [csp(), fontLicences()],
  build: {
    target: 'es2022',
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  server: { fs: { allow: ['..'] } },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 120_000,
  },
})
