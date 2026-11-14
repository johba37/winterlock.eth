// The keys follow ERC-8499 (decisions.md, D15), end to end on a local chain (anvil with Sepolia's
// chain id; local.ts):
// - pairing the ERC's own test phrase, which no owner uses: the app asks first, and once told to go
//   on it creates the owner that the Python reference names for that phrase (erc8499.py, through
//   core/tests/vectors/erc8499.json), from the gas account the reference names;
// - a device that a build before ERC-8499 set up: the app shows what it was and only forgets it.
//
// Needs anvil and the Python signer's virtualenv (local.ts). With E2E_PREVIEW=1 the app is the
// production build. Spends nothing.

import { type Browser, type BrowserContext, type Page, expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { type Address, getAddress } from 'viem'
import { EARLIER_BUILD } from '../src/lib/db'
import { LocalChain, boardRecord, haveChainTools, tid as t, useLocalRpc, waitDone } from './local'

const BASE = `http://localhost:${process.env.E2E_PORT ?? 5190}`
const VECTORS = JSON.parse(readFileSync(new URL('../../core/tests/vectors/erc8499.json', import.meta.url), 'utf8'))
// seed 0: the all-zero entropy, the ERC's first test phrase
const ZERO = VECTORS.keys[0]
const ABANDON = `${'abandon '.repeat(23)}art`

const chain = new LocalChain()
let ctx: BrowserContext
let page: Page

test.describe.serial('ERC-8499 keys on a local chain', () => {
  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    test.skip(!haveChainTools(), 'needs anvil and the Python signer’s virtualenv (WINTERLOCK_PYTHON)')
    await chain.start()
    ctx = await browser.newContext({ baseURL: BASE })
    page = await ctx.newPage()
  })

  test.afterAll(async () => {
    await ctx?.close()
    chain.stop()
  })

  test('pairing a phrase no owner uses asks first, then makes the reference’s owner', async () => {
    test.setTimeout(5 * 60_000)
    expect(ZERO.seed).toBe(`0x${'00'.repeat(32)}`)
    await useLocalRpc(page, BASE, chain.url)
    await chain.setBalance(getAddress(ZERO.gas_address), 10n ** 19n)

    await page.goto('/#/pair')
    await t(page, 'phrase-input').fill(ABANDON)
    await t(page, 'pair-submit').click()
    await expect(t(page, 'no-account')).toBeVisible({ timeout: 120_000 })
    await t(page, 'pair-stop').click()
    await expect(t(page, 'error')).toContainText('Nothing was paired')
    expect(await boardRecord(page)).toBeUndefined()

    await t(page, 'phrase-input').fill(ABANDON)
    await t(page, 'pair-submit').click()
    await expect(t(page, 'no-account')).toBeVisible({ timeout: 120_000 })
    await t(page, 'pair-anyway').click()
    await waitDone(page, t(page, 'pair-done'))
    await expect(t(page, 'pair-report')).toContainText('owner created')
    const rec = await boardRecord(page)
    expect(rec.keys).toBe('erc-8499')
    expect(getAddress(rec.owner)).toBe(ZERO.owner)
    expect(rec.memberKey).toBe(ZERO.member_key)
    expect(getAddress(rec.gasAddress)).toBe(ZERO.gas_address)
    expect(rec.device).toBe(1)
    const code = await chain.client().getCode({ address: ZERO.owner as Address })
    expect(code && code.length > 2).toBe(true)
    await t(page, 'done-home').click()
    await expect(t(page, 'earlier-keys')).toHaveCount(0)

    // a second browser: now an owner uses the phrase, so no question
    const other = await ctx.browser()!.newContext({ baseURL: BASE })
    const p2 = await other.newPage()
    await useLocalRpc(p2, BASE, chain.url)
    await p2.goto('/#/pair')
    await t(p2, 'phrase-input').fill(ABANDON)
    await t(p2, 'pair-submit').click()
    await waitDone(p2, t(p2, 'pair-done'))
    await expect(t(p2, 'no-account')).toHaveCount(0)
    expect((await boardRecord(p2)).device).toBe(2)
    await other.close()
  })

  test('a device from an earlier build is shown, linked to that build, and only forgotten', async () => {
    const rec = await boardRecord(page)
    // what an earlier build stored: the same fields, no `keys`
    const { keys: _, ...earlier } = rec
    await page.evaluate(
      (r) =>
        new Promise<void>((res, rej) => {
          const o = indexedDB.open('winterlock')
          o.onsuccess = () => {
            const tx = o.result.transaction('device', 'readwrite')
            tx.objectStore('device').put(r)
            tx.oncomplete = () => {
              o.result.close()
              res()
            }
            tx.onerror = () => rej(tx.error)
          }
        }),
      earlier,
    )
    await page.goto('/#/')
    await page.reload()
    await expect(t(page, 'earlier-keys')).toBeVisible()
    await expect(t(page, 'earlier-owner')).toHaveAttribute('data-value', rec.owner)
    await expect(t(page, 'earlier-link')).toHaveAttribute('href', EARLIER_BUILD.url)
    // every route leads here, and no dapp bar
    await page.goto('/#/settings')
    await expect(t(page, 'earlier-keys')).toBeVisible()
    await expect(t(page, 'wc-bar')).toHaveCount(0)

    await t(page, 'earlier-forget').click()
    await t(page, 'earlier-forget-confirm').click()
    await expect(t(page, 'welcome')).toBeVisible()
    expect(await boardRecord(page)).toBeUndefined()
  })
})
