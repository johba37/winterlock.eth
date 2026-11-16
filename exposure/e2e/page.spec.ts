// The built page under its Content Security Policy: it loads with nothing from other servers and
// no console errors, and (EXPOSURE_LIVE=1) looks up live Sepolia Safes, talking only to the RPC
// endpoint and Safe's Transaction Service.

import { type Page, expect, test } from '@playwright/test'

const LIVE = process.env.EXPOSURE_LIVE === '1'

function watch(page: Page) {
  const errors: string[] = []
  const origins = new Set<string>()
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') errors.push(`${m.type()}: ${m.text()}`)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))
  page.on('request', (r) => origins.add(new URL(r.url()).origin))
  return { errors, origins }
}

test('loads under its CSP with nothing from other servers', async ({ page, baseURL }) => {
  const w = watch(page)
  await page.goto('/')
  const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content')
  expect(csp).toContain("script-src 'self'")
  expect(csp).toContain("default-src 'none'")
  await expect(page.locator('h1')).toHaveText('Who could sign for your Safe if elliptic curves broke?')
  await expect(page.locator('#background')).toContainText('exists today, and nobody knows when one will')
  await expect(page.locator('#peers')).toContainText('https://ethereum-rpc.publicnode.com')
  await expect(page.locator('#peers')).toContainText('https://api.safe.global')
  // the fonts are the page's own
  await page.evaluate(() => document.fonts.ready)
  expect(await page.evaluate(() => document.fonts.check('16px "Atkinson Next"'))).toBe(true)
  // a bad address is refused before anything is sent
  await page.fill('#safe', '0x1234')
  await page.click('#go')
  await expect(page.locator('#form-error')).toContainText('0x followed by 40 hexadecimal digits')
  expect([...w.origins]).toEqual([baseURL])
  expect(w.errors).toEqual([])
})

test.describe('live lookups on Sepolia', () => {
  test.skip(!LIVE, 'EXPOSURE_LIVE=1 runs these')

  test('a 2-of-2 Safe of Winterlock owners, from the hash route: protected', async ({ page, baseURL }) => {
    const w = watch(page)
    await page.goto('/#/sep:0xA5dA2Ab05Cb7EE8D3FBbB486Dee542dcCb5197E6')
    await expect(page.locator('#verdict')).toHaveText('Protected by hash-based owners', { timeout: 60_000 })
    await expect(page.locator('.owners .badge')).toHaveText(['Hash-based', 'Hash-based'])
    await expect(page.locator('#result')).toContainText('No module is enabled.')
    expect(new Set(w.origins)).toEqual(new Set([baseURL, 'https://ethereum-sepolia-rpc.publicnode.com']))
    expect(w.errors).toEqual([])
  })

  test("the landing page's 2-of-2 Safe of Winterlock owners v1: protected", async ({ page, baseURL }) => {
    const w = watch(page)
    await page.goto('/#/sep:0x68f64486FC720D1dB14507bC7Fa64896bE6Bef07')
    await expect(page.locator('#verdict')).toHaveText('Protected by hash-based owners', { timeout: 60_000 })
    await expect(page.locator('.owners td.evidence')).toHaveText([/Winterlock owner v1/, /Winterlock owner v1/])
    expect(new Set(w.origins)).toEqual(new Set([baseURL, 'https://ethereum-sepolia-rpc.publicnode.com']))
    expect(w.errors).toEqual([])
  })

  test('typed into the form: a Safe with an exposed ECDSA owner at threshold 1: exposed', async ({ page, baseURL }) => {
    const w = watch(page)
    await page.goto('/')
    await page.selectOption('#chain', 'sep')
    await page.fill('#safe', 'https://app.safe.global/home?safe=sep:0xb0ad7064b7fa1FFF27611DC800CF85D70C861075')
    await page.click('#go')
    await expect(page).toHaveURL(/#\/sep:0xb0ad7064b7fa1FFF27611DC800CF85D70C861075$/)
    await expect(page.locator('#verdict')).toHaveText('Exposed', { timeout: 60_000 })
    await expect(page.locator('#result')).toContainText('Has sent')
    expect(new Set(w.origins)).toEqual(new Set([baseURL, 'https://ethereum-sepolia-rpc.publicnode.com']))
    expect(w.errors).toEqual([])
  })

  test("a Safe whose ECDSA owner only signed at Safe's service: protected, and the service was asked", async ({ page, baseURL }) => {
    const w = watch(page)
    await page.goto('/#/sep:0xA8B1581F7DDF0DE335828Ba68aEBb4C0D53A1Cc5')
    await expect(page.locator('#verdict')).toHaveText('Protected by hash-based owners', { timeout: 90_000 })
    await expect(page.locator('#result')).toContainText('Safe’s Transaction Service holds')
    expect(new Set(w.origins)).toEqual(new Set([baseURL, 'https://ethereum-sepolia-rpc.publicnode.com', 'https://api.safe.global']))
    expect(w.errors).toEqual([])
  })
})
