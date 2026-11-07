// Renders the app's PNG icons from the brand mark (docs/brand/mark.svg) with Playwright's
// Chromium: the icons for the manifest and the iOS home screen. Run after changing the mark.
import { readFileSync } from 'node:fs'
import { chromium } from '@playwright/test'

const mark = readFileSync(new URL('../../docs/brand/mark.svg', import.meta.url), 'utf8')
  // fixed light colours: an icon doesn't follow the viewer's theme
  .replace(/@media \(prefers-color-scheme:dark\)\{.*?\}\}/, '')
const out = new URL('../public/icons/', import.meta.url)

const sizes = [
  { file: 'icon-192.png', size: 192, pad: 0.12 },
  { file: 'icon-512.png', size: 512, pad: 0.12 },
  { file: 'maskable-512.png', size: 512, pad: 0.24 },
  { file: 'apple-touch-icon.png', size: 180, pad: 0.14 },
]

const browser = await chromium.launch()
const page = await browser.newPage()
for (const { file, size, pad } of sizes) {
  const inner = Math.round(size * (1 - 2 * pad))
  const svg = mark.replace(/width="\d+" height="\d+"/, `width="${inner}" height="${inner}"`)
  await page.setViewportSize({ width: size, height: size })
  await page.setContent(
    `<html><body style="margin:0;width:${size}px;height:${size}px;background:#E3E5E4;display:grid;place-items:center">${svg}</body></html>`,
  )
  await page.screenshot({ path: new URL(file, out).pathname, omitBackground: false })
  console.log(`wrote public/icons/${file}`)
}
await browser.close()
