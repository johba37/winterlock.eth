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

import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import { createServer } from 'node:net'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { type Page, expect, test } from '@playwright/test'
import { type Address, type Hex, createPublicClient, createWalletClient, encodeFunctionData, getAddress, http, keccak256, parseAbi, toHex, zeroAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { FakeService } from './fake-service'
import { VBoard } from './vboard'

const here = dirname(fileURLToPath(import.meta.url))
const repo = resolve(here, '../..')
const PYTHON = process.env.WINTERLOCK_PYTHON ?? resolve(repo, 'signer/.venv/bin/python')
const ANVIL = process.env.ANVIL ?? join(homedir(), '.foundry/bin/anvil')
// anvil's first default account: a public test key, local chains only
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const BOB = getAddress(keccak256(toHex('board run: recipient')).slice(0, 42))
const SHOTS = join(process.env.E2E_DIR ?? join(here, '..', 'test-results'), 'board-screens')

const SAFE_ABI = parseAbi([
  'function setup(address[] owners, uint256 threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)',
  'function nonce() view returns (uint256)',
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)',
  'function approvedHashes(address owner, bytes32 hash) view returns (uint256)',
  'function approveHash(bytes32 hashToApprove)',
])
const FACTORY_ABI = parseAbi(['function createProxyWithNonce(address singleton, bytes initializer, uint256 saltNonce) returns (address proxy)'])
const OWNER_FACTORY = parseAbi(['function predict(bytes32 key) view returns (address)'])

function freePort(): Promise<number> {
  return new Promise((res) => {
    const s = createServer()
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as any).port
      s.close(() => res(p))
    })
  })
}

let anvil: ChildProcess | undefined
let rpcUrl = ''
let deployed: { factory: Address; safe: { singleton: Address; factory: Address; fallback_handler: Address } }

test.beforeAll(async () => {
  test.skip(!existsSync(ANVIL) || !existsSync(PYTHON), 'needs anvil and the Python signer’s virtualenv (WINTERLOCK_PYTHON)')
  const port = await freePort()
  rpcUrl = `http://127.0.0.1:${port}`
  anvil = spawn(ANVIL, ['--port', String(port), '--chain-id', '11155111', '--silent', '--disable-code-size-limit', '--disable-block-gas-limit'], { stdio: 'ignore' })
  const c = createPublicClient({ transport: http(rpcUrl) })
  for (let i = 0; ; i++) {
    try {
      await c.getChainId()
      break
    } catch {
      if (i > 100) throw new Error('anvil didn’t start')
      await new Promise((r) => setTimeout(r, 100))
    }
  }
  const r = spawnSync(PYTHON, ['-I', join(here, 'local_chain.py'), rpcUrl], { encoding: 'utf8' })
  if (r.status !== 0) throw new Error(`local_chain.py: ${r.stderr}`)
  deployed = JSON.parse(r.stdout)
})

test.afterAll(() => {
  anvil?.kill()
})

const client = () => createPublicClient({ transport: http(rpcUrl) })
const wallet = () => createWalletClient({ account: privateKeyToAccount(ANVIL_KEY), transport: http(rpcUrl), chain: { id: 11155111, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [rpcUrl] } } } })

async function sendTx(to: Address, data: Hex, value = 0n) {
  const hash = await wallet().sendTransaction({ to, data, value })
  const r = await client().waitForTransactionReceipt({ hash })
  if (r.status !== 'success') throw new Error(`reverted: ${hash}`)
  return r
}

async function createSafe(owners: Address[], salt: bigint): Promise<Address> {
  const init = encodeFunctionData({ abi: SAFE_ABI, functionName: 'setup', args: [owners, 1n, zeroAddress, '0x', deployed.safe.fallback_handler, zeroAddress, 0n, zeroAddress] })
  const args = [deployed.safe.singleton, init, salt] as const
  const { result } = await client().simulateContract({ account: privateKeyToAccount(ANVIL_KEY), address: deployed.safe.factory, abi: FACTORY_ABI, functionName: 'createProxyWithNonce', args })
  await sendTx(deployed.safe.factory, encodeFunctionData({ abi: FACTORY_ABI, functionName: 'createProxyWithNonce', args }))
  await client().request({ method: 'anvil_setBalance' as any, params: [result, toHex(10n ** 18n)] as any })
  return getAddress(result)
}

const nonceOf = async (safe: Address) => Number(await client().readContract({ address: safe, abi: SAFE_ABI, functionName: 'nonce' }))
const hashOf = (safe: Address, to: Address, value: bigint, data: Hex, operation: number, nonce: number) =>
  client().readContract({ address: safe, abi: SAFE_ABI, functionName: 'getTransactionHash', args: [to, value, data, operation, 0n, 0n, 0n, zeroAddress, zeroAddress, BigInt(nonce)] })

const t = (p: Page, id: string) => p.getByTestId(id)

async function shot(p: Page, name: string) {
  mkdirSync(SHOTS, { recursive: true })
  await p.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: true })
}

/** Waits for the action's result line, or fails with the app's error. */
async function waitDone(p: Page, ok: ReturnType<Page['locator']>, timeout = 180_000) {
  await expect(ok.or(t(p, 'error')).first()).toBeVisible({ timeout })
  if (await t(p, 'error').isVisible()) throw new Error(`the app says: ${await t(p, 'error').textContent()}`)
}

test('the app with the virtual board, on a local chain', async ({ page, baseURL }) => {
  test.setTimeout(10 * 60_000)
  const log = (...a: unknown[]) => console.log('  ', ...a)
  page.on('pageerror', (e) => log(`page error: ${e.message}`))
  const svc = new FakeService(client() as any)
  await svc.install(page)
  const vb = new VBoard(page)
  const t0 = Date.now()

  await test.step('the local chain as the RPC', async () => {
    await page.goto(`${baseURL}/#/settings`)
    await t(page, 'rpc-edit-11155111').click()
    await t(page, 'rpc-input-11155111').fill(rpcUrl)
    await t(page, 'rpc-save-11155111').click()
    await expect(t(page, 'rpc-host-11155111')).toHaveText(new URL(rpcUrl).origin)
  })

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
    const st = await page.evaluate(() =>
      new Promise<any>((res, rej) => {
        const r = indexedDB.open('winterlock')
        r.onsuccess = () => {
          const q = r.result.transaction('device').objectStore('device').get('this')
          q.onsuccess = () => res(q.result)
          q.onerror = () => rej(q.error)
        }
      }),
    )
    expect(st.kind).toBe('board')
    expect(Object.keys(st).sort()).toEqual(['createdAt', 'gasAddress', 'gasKey', 'how', 'id', 'kind', 'link', 'memberKey', 'owner'])
    expect(await client().readContract({ address: deployed.factory, abi: OWNER_FACTORY, functionName: 'predict', args: [st.memberKey] })).toBe(owner)
    expect(privateKeyToAccount(st.gasKey).address).toBe(getAddress(st.gasAddress))
    await client().request({ method: 'anvil_setBalance' as any, params: [st.gasAddress, toHex(10n ** 19n)] as any })
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
    child = await createSafe([owner], 1n)
    parent = await createSafe([child], 2n)
    log(`Safe ${child}, parent Safe ${parent}`)
  })

  await test.step('join, then enrol: the first enrolment creates the owner contract', async () => {
    await page.goto(`${baseURL}/#/join`)
    await t(page, 'safe-input').fill(`sep:${child}`)
    await t(page, 'join-submit').click()
    await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '0', { timeout: 60_000 })
    await shot(page, '05-safe-no-tree')
    await t(page, 'enrol').click()
    const pages = await vb.confirm()
    expect(pages[0]).toMatch(/^Enrol key tree/)
    await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '512', { timeout: 180_000 })
    await expect(page.locator('.okline').first()).toContainText('created your owner contract')
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
    log(`transfer executed: ${await page.locator('[data-testid="done"]').getAttribute('data-tx')}`)
  })

  await test.step('approveHash of the parent Safe’s transfer: the board shows the parent’s transaction', async () => {
    const pn = await nonceOf(parent)
    const ph = await hashOf(parent, BOB, 10n ** 17n, '0x', 0, pn)
    svc.add(parent, { to: BOB, value: String(10n ** 17n), data: null, operation: 0, safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: zeroAddress, refundReceiver: zeroAddress, nonce: pn }, ph)
    const cn = await nonceOf(child)
    const data = encodeFunctionData({ abi: SAFE_ABI, functionName: 'approveHash', args: [ph] })
    const ch = await hashOf(child, parent, 0n, data, 0, cn)
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
    await sendTx(parent, encodeFunctionData({ abi: SAFE_ABI, functionName: 'execTransaction', args: [BOB, 10n ** 17n, '0x', 0, 0n, 0n, 0n, zeroAddress, zeroAddress, approval] }))
    expect((await client().getBalance({ address: BOB })) - before).toBe(10n ** 17n)
    log(`approveHash executed, then the parent Safe's transfer on it (pages: ${pages.join(' / ')})`)
  })

  await test.step('a delegate call: the board refuses it', async () => {
    const cn = await nonceOf(child)
    const h = await hashOf(child, BOB, 0n, '0x12345678', 1, cn)
    svc.add(child, { to: BOB, value: '0', data: '0x12345678', operation: 1, safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: zeroAddress, refundReceiver: zeroAddress, nonce: cn }, h)
    await page.goto(`${baseURL}/#/safe/11155111/${child}/tx/${h}`)
    await t(page, 'confirm').click()
    await expect(t(page, 'error')).toContainText('delegate calls are refused', { timeout: 60_000 })
    await shot(page, '08-delegate-refused')
    await vb.dismiss('Refused')
  })

  await test.step('cancel from the app while the board shows the transaction', async () => {
    const cn = await nonceOf(child)
    const h = await hashOf(child, BOB, 1n, '0x', 0, cn)
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
