// The app without a board, on the local chain (local.ts, fake-service.ts): the development path and
// the fallback, checked after the screens it shares with the board's: create (the phrase, three
// words back), the device's certificate (the owner created on the way), join, enrol, a transfer
// proposed and executed. Spends nothing.

import { expect, test } from '@playwright/test'
import { type Address, getAddress } from 'viem'
import { FakeService } from './fake-service'
import { BOB, LocalChain, haveChainTools, joinSafe, tid as t, useLocalRpc, waitDone } from './local'

const chain = new LocalChain()

test.beforeAll(async () => {
  test.skip(!haveChainTools(), 'needs anvil and the Python signer’s virtualenv (WINTERLOCK_PYTHON)')
  await chain.start()
})

test.afterAll(() => chain.stop())

test('the app without a board, on a local chain', async ({ page, baseURL }) => {
  test.setTimeout(5 * 60_000)
  const svc = new FakeService(chain.client() as any)
  await svc.install(page)
  await useLocalRpc(page, baseURL!, chain.url)

  await page.goto(`${baseURL}/#/`)
  await t(page, 'go-create').click()
  await t(page, 'show-phrase').click()
  await t(page, 'phrase-words').waitFor()
  const words = await t(page, 'phrase-words').locator('li').allTextContents()
  await t(page, 'written-down').click()
  const labels = await page.locator('form label').allTextContents()
  for (let i = 0; i < 3; i++) await t(page, `check-word-${i}`).fill(words[Number(labels[i].match(/Word (\d+)/)![1]) - 1])
  await t(page, 'check-submit').click()
  await t(page, 'create-done').waitFor({ timeout: 120_000 })
  const owner = getAddress((await t(page, 'owner-address').getAttribute('data-value'))!) as Address
  await t(page, 'done-home').click()
  await expect(t(page, 'home')).toBeVisible()
  // no board: no board bar
  await expect(t(page, 'board-dock')).toHaveCount(0)

  await page.goto(`${baseURL}/#/settings`)
  const gas = (await t(page, 'gas-address').getAttribute('data-value')) as Address
  await chain.setBalance(gas, 10n ** 19n)
  await page.goto(`${baseURL}/#/`)
  await t(page, 'send-certificate').click()
  await waitDone(page, t(page, 'certificate-report'))
  await expect(t(page, 'chain-11155111').getByTestId('device-state')).toHaveAttribute('data-kind', 'active', { timeout: 60_000 })

  const safe = await chain.createSafe([owner], 11n)
  await joinSafe(page, baseURL!, safe)
  await t(page, 'enrol').click()
  await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '512', { timeout: 180_000 })

  await page.goto(`${baseURL}/#/safe/11155111/${safe}/send`)
  await t(page, 'to-input').fill(BOB)
  await t(page, 'amount-input').fill('0.0625')
  await t(page, 'review').click()
  await t(page, 'sign-propose').click()
  await waitDone(page, t(page, 'done'))
  const hash = (await t(page, 'done').getAttribute('data-hash'))!
  await page.goto(`${baseURL}/#/safe/11155111/${safe}/tx/${hash}`)
  const before = await chain.client().getBalance({ address: BOB })
  await t(page, 'execute').click()
  await waitDone(page, page.locator('[data-testid="done"][data-tx^="0x"]'))
  expect((await chain.client().getBalance({ address: BOB })) - before).toBe(625n * 10n ** 14n)
  // the device's signature: device 1, not the member key
  const sig = svc.txs.get(hash.toLowerCase())!.confirmations[0].signature
  expect(Number.parseInt(sig.slice(2 + 2 * 98, 2 + 2 * 99), 16)).toBe(1)
})
