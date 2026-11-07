// The core's timings in Chromium, in the app's own device worker (bench.html): the member key, a
// height-10 key tree, a stateless signature, a one-time signature. No chain needed.

import { test } from '@playwright/test'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'

test('timings in the device worker', async ({ page }) => {
  await page.goto('/bench.html?runs=3')
  await page.waitForFunction(() => (window as any).benchDone, null, { timeout: 300_000 })
  const r = await page.evaluate(() => (window as any).benchDone)
  const line = (k: string) => r.results.map((x: any) => Math.round(x[k])).join(', ')
  console.log(`${r.userAgent}\n${r.cores} hardware threads, ${r.results[0].backend}`)
  console.log(`member key (b = 10), ms: ${line('memberKeyMs')}`)
  console.log(`key tree, height 10, ms: ${line('tree10Ms')}`)
  console.log(`stateless signature, median of 5, ms: ${line('statelessMs')}`)
  console.log(`one-time signature through the key log, median of 5, ms: ${r.results.map((x: any) => x.wotsMs.toFixed(1)).join(', ')}`)
  if (process.env.E2E_DIR) writeFileSync(join(process.env.E2E_DIR, 'bench.json'), JSON.stringify(r, null, 1))
})
