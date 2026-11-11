// The app with the virtual board, in Chromium, end to end on a local chain: anvil with Sepolia's
// chain id, owner v2's contracts at their pinned addresses, Safe v1.4.1, and a stand-in for Safe's
// Transaction Service (fake-service.ts). The member uses the app's screens and the virtual board's
// drawn screen and buttons, as on the page:
//
//   onboarding with a board, set up on it; a restart (locked: the PIN on the board); joining a Safe;
//   enrolment (deployAndEnroll: the first enrolment creates the owner); a transfer proposed and
//   executed; an approveHash of a parent Safe's transfer, then the parent executes it; a delegate
//   call the board refuses; a cancel from the app; a reload.
//
// Needs Foundry's anvil (~/.foundry/bin), the Python signer's virtualenv (WINTERLOCK_PYTHON) and
// Safe v1.4.1's build (SAFE_141_BUILD). Spends nothing: a local chain.

import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { type Page, expect, test } from '@playwright/test'
import { type Address, type Hex, encodeFunctionData, getAddress, zeroAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { FakeService } from './fake-service'
import { BOB, LocalChain, OWNER_FACTORY, SAFE_ABI, boardRecord, haveChainTools, joinSafe, shot as shotIn, tid as t, useLocalRpc, waitDone } from './local'
import { VBoard } from './vboard'

const here = dirname(fileURLToPath(import.meta.url))
const SHOTS = join(process.env.E2E_DIR ?? join(here, '..', 'test-results'), 'board-screens')
const shot = (p: Page, name: string) => shotIn(p, SHOTS, name)
const chain = new LocalChain()

test.beforeAll(async () => {
  test.skip(!haveChainTools(), 'needs anvil and the Python signer’s virtualenv (WINTERLOCK_PYTHON)')
  await chain.start()
})

test.afterAll(() => chain.stop())

const client = () => chain.client()

test('the app with the virtual board, on a local chain', async ({ page, baseURL }) => {
  test.setTimeout(10 * 60_000)
  const log = (...a: unknown[]) => console.log('  ', ...a)
  page.on('pageerror', (e) => log(`page error: ${e.message}`))
  const svc = new FakeService(client() as any)
  await svc.install(page)
  const vb = new VBoard(page)
  const t0 = Date.now()

  await test.step('the local chain as the RPC', () => useLocalRpc(page, baseURL!, chain.url))

  let owner: Address = zeroAddress
  let words: string[] = []
  await test.step('onboarding: a board, set up on the virtual board', async () => {
    await page.goto(`${baseURL}/#/`)
    await t(page, 'go-board').click()
    await shot(page, '01-use-a-board')
    await t(page, 'connect-virtual').click()
    await expect(t(page, 'board-state')).toContainText('A new or erased board')
    await expect(t(page, 'virtual-board')).toContainText('Its keys live in this browser')
    await shot(page, '02-virtual-board-blank')
    await t(page, 'board-setup').click()
    words = await vb.setup()
    await expect(t(page, 'board-done')).toBeVisible({ timeout: 60_000 })
    owner = getAddress((await t(page, 'owner-address').getAttribute('data-value'))!)
    // the board shows the same address, in full
    await vb.until('Owner address')
    expect((await vb.lines()).slice(1, 4).join('').replace(/ /g, '')).toBe(owner)
    await shot(page, '03-board-ready')
    await vb.press('RR')
    await t(page, 'done-home').click()
    await expect(t(page, 'home')).toBeVisible()
    await expect(t(page, 'owner-state')).toHaveAttribute('data-deployed', 'false', { timeout: 30_000 })
    expect(words).toHaveLength(24)
    log(`set up on the virtual board: owner ${owner}`)
  })

  await test.step('the owner the factory predicts for the board’s member key; the gas key the board gave', async () => {
    const st = await boardRecord(page)
    expect(st.kind).toBe('board')
    expect(Object.keys(st).sort()).toEqual(['createdAt', 'gasAddress', 'gasKey', 'how', 'id', 'kind', 'link', 'memberKey', 'owner'])
    expect(await client().readContract({ address: chain.deployed.factory, abi: OWNER_FACTORY, functionName: 'predict', args: [st.memberKey] })).toBe(owner)
    expect(privateKeyToAccount(st.gasKey).address).toBe(getAddress(st.gasAddress))
    await chain.setBalance(st.gasAddress, 10n ** 19n)
  })

  await test.step('a restart: locked until the PIN is entered on the board', async () => {
    await t(page, 'vb-restart').click()
    await expect(t(page, 'link-state')).toHaveAttribute('data-state', 'locked', { timeout: 30_000 })
    await expect(t(page, 'enter-pin')).toBeVisible()
    await shot(page, '04-locked')
    await vb.unlock()
    await expect(t(page, 'link-state')).toHaveAttribute('data-state', 'unlocked', { timeout: 30_000 })
  })

  let child: Address = zeroAddress
  let parent: Address = zeroAddress
  await test.step('a Safe owned by the board’s owner alone, and a parent Safe owned by that Safe', async () => {
    child = await chain.createSafe([owner], 1n)
    parent = await chain.createSafe([child], 2n)
    log(`Safe ${child}, parent Safe ${parent}`)
  })

  await test.step('join, then enrol: the first enrolment creates the owner contract', async () => {
    await joinSafe(page, baseURL!, child)
    await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '0', { timeout: 60_000 })
    await shot(page, '05-safe-no-tree')
    await t(page, 'enrol').click()
    const pages = await vb.confirm()
    expect(pages[0]).toMatch(/^Enrol key tree/)
    await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '512', { timeout: 180_000 })
    await expect(t(page, 'enrolled')).toContainText('created your owner contract')
    log(await t(page, 'enrolled').textContent())
    await vb.dismiss('Enrolled')
    await shot(page, '06-safe-enrolled')
  })

  await test.step('a transfer: proposed, confirmed on the board, executed by the gas account', async () => {
    await page.goto(`${baseURL}/#/safe/11155111/${child}/send`)
    await t(page, 'to-input').fill(BOB)
    await t(page, 'amount-input').fill('0.25')
    await t(page, 'review').click()
    await t(page, 'sign-propose').click()
    const pages = await vb.confirm()
    expect(pages[0]).toMatch(/^Send/)
    await waitDone(page, t(page, 'done'))
    await vb.dismiss('Signed')
    const hash = (await t(page, 'done').getAttribute('data-hash')) as Hex
    expect(svc.posts.at(-1)!.body.contractTransactionHash).toBe(hash)
    await page.goto(`${baseURL}/#/safe/11155111/${child}/tx/${hash}`)
    await expect(t(page, 'sig-count')).toHaveAttribute('data-valid', '1', { timeout: 60_000 })
    await shot(page, '07-tx-ready')
    const before = await client().getBalance({ address: BOB })
    await t(page, 'execute').click()
    await waitDone(page, page.locator('[data-testid="done"][data-tx^="0x"]'))
    expect((await client().getBalance({ address: BOB })) - before).toBe(25n * 10n ** 16n)
    log(`transfer: ${await page.locator('[data-testid="done"][data-tx^="0x"]').textContent()}`)
  })

  await test.step('approveHash of the parent Safe’s transfer: the board shows the parent’s transaction', async () => {
    const pn = await chain.nonceOf(parent)
    const ph = await chain.hashOf(parent, BOB, 10n ** 17n, '0x', 0, pn)
    svc.add(parent, { to: BOB, value: String(10n ** 17n), data: null, operation: 0, safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: zeroAddress, refundReceiver: zeroAddress, nonce: pn }, ph)
    const cn = await chain.nonceOf(child)
    const data = encodeFunctionData({ abi: SAFE_ABI, functionName: 'approveHash', args: [ph] })
    const ch = await chain.hashOf(child, parent, 0n, data, 0, cn)
    svc.add(child, { to: parent, value: '0', data, operation: 0, safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: zeroAddress, refundReceiver: zeroAddress, nonce: cn }, ch)
    await page.goto(`${baseURL}/#/safe/11155111/${child}/tx/${ch}`)
    await expect(t(page, 'tx-summary')).toContainText('Approves transaction')
    await t(page, 'confirm').click()
    const pages = await vb.confirm()
    expect(pages[0]).toMatch(/^Approve/)
    expect(pages.some((x) => x.startsWith('Parent: Send'))).toBe(true)
    await waitDone(page, t(page, 'done'))
    await vb.dismiss('Signed')
    await expect(t(page, 'execute')).toBeVisible({ timeout: 60_000 })
    await t(page, 'execute').click()
    await waitDone(page, page.locator('[data-testid="done"][data-tx^="0x"]'))
    expect(await client().readContract({ address: parent, abi: SAFE_ABI, functionName: 'approvedHashes', args: [child, ph] })).toBe(1n)
    // the parent executes on the approval: r = the approving owner, s = 0, v = 1
    const approval = `0x${child.slice(2).toLowerCase().padStart(64, '0')}${'0'.repeat(64)}01` as Hex
    const before = await client().getBalance({ address: BOB })
    await chain.send(parent, encodeFunctionData({ abi: SAFE_ABI, functionName: 'execTransaction', args: [BOB, 10n ** 17n, '0x', 0, 0n, 0n, 0n, zeroAddress, zeroAddress, approval] }))
    expect((await client().getBalance({ address: BOB })) - before).toBe(10n ** 17n)
    log(`approveHash executed, then the parent Safe's transfer on it (pages: ${pages.join(' / ')})`)
  })

  await test.step('a delegate call: the board refuses it', async () => {
    const cn = await chain.nonceOf(child)
    const h = await chain.hashOf(child, BOB, 0n, '0x12345678', 1, cn)
    svc.add(child, { to: BOB, value: '0', data: '0x12345678', operation: 1, safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: zeroAddress, refundReceiver: zeroAddress, nonce: cn }, h)
    await page.goto(`${baseURL}/#/safe/11155111/${child}/tx/${h}`)
    await t(page, 'confirm').click()
    await expect(t(page, 'error')).toContainText('delegate calls are refused', { timeout: 60_000 })
    await shot(page, '08-delegate-refused')
    await vb.dismiss('Refused')
  })

  await test.step('cancel from the app while the board shows the transaction', async () => {
    const cn = await chain.nonceOf(child)
    const h = await chain.hashOf(child, BOB, 1n, '0x', 0, cn)
    svc.add(child, { to: BOB, value: '1', data: null, operation: 0, safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: zeroAddress, refundReceiver: zeroAddress, nonce: cn }, h)
    await page.goto(`${baseURL}/#/safe/11155111/${child}/tx/${h}`)
    await t(page, 'confirm').click()
    await vb.until('Send')
    await shot(page, '09-confirm-on-board')
    await t(page, 'cancel').click()
    await expect(t(page, 'error')).toContainText('Cancelled', { timeout: 30_000 })
    await vb.until('Winterlock')
  })

  await test.step('a reload: the virtual board starts again, locked, and unlocks', async () => {
    await page.goto(`${baseURL}/#/`)
    await page.reload()
    await expect(t(page, 'link-state')).toHaveAttribute('data-state', 'locked', { timeout: 30_000 })
    await vb.unlock()
    await expect(t(page, 'owner-state')).toHaveAttribute('data-deployed', 'true', { timeout: 30_000 })
    await page.goto(`${baseURL}/#/board`)
    await expect(t(page, 'board-status')).toContainText('unlocked')
    await shot(page, '10-board-info')
  })
  log(`done in ${Math.round((Date.now() - t0) / 1000)} s`)
})
