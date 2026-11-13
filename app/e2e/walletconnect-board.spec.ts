// WalletConnect with the virtual board as the member's only device, on the local chain (local.ts,
// fake-service.ts), and a dapp on the official SDK in this test process, paired through Reown's
// live relay. A dapp's transaction goes to the board's SIGN, which shows it and signs on confirm;
// a batch is refused before it reaches the board, which refuses delegate calls.
//
// Needs anvil and the Python signer's virtualenv (local.ts), and WINTERLOCK_ENV_FILE with
// WALLETCONNECT_PROJECT_ID (never printed). Spends nothing.

import { type Browser, type BrowserContext, type Page, expect, test } from '@playwright/test'
import { SignClient } from '@walletconnect/sign-client'
import { type Address, type Hex, createWalletClient, encodeFunctionData, getAddress, http, parseAbi, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { ERC20_ABI } from '../src/lib/safe'
import { log, projectId, redact } from './env'
import { FakeService } from './fake-service'
import { BOB, LocalChain, boardRecord, haveChainTools, joinSafe, tid as t, useLocalRpc } from './local'
import { TEST_TOKEN_CODE } from './test-token'
import { VBoard } from './vboard'

const CHAIN = 11155111
const CAIP = `eip155:${CHAIN}`
const BASE = `http://localhost:${process.env.E2E_PORT ?? 5190}`
// anvil's first default account: a public test key, local chains only
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const TOKEN_ABI = parseAbi(['function balanceOf(address) view returns (uint256)'])

const chain = new LocalChain()
let ctx: BrowserContext
let page: Page
let vb: VBoard
let dapp: Awaited<ReturnType<typeof SignClient.init>>
let topic = ''
let safe: Address
let token: Address

async function sendAnvil(to: Address | undefined, data: Hex) {
  const w = createWalletClient({
    account: privateKeyToAccount(ANVIL_KEY),
    transport: http(chain.url),
    chain: { id: CHAIN, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [chain.url] } } },
  })
  const hash = await w.sendTransaction({ to: to ?? null, data } as any)
  const r = await chain.client().waitForTransactionReceipt({ hash })
  if (r.status !== 'success') throw new Error(`reverted: ${hash}`)
  return r
}

const ask = <T = any>(method: string, params: unknown[]) => {
  const p = dapp.request<T>({ topic, chainId: CAIP, request: { method, params } })
  p.catch(() => {})
  return p
}

async function refusal(p: Promise<unknown>): Promise<{ code: number; message: string }> {
  try {
    await p
  } catch (e: any) {
    return { code: e?.code, message: String(e?.message ?? e) }
  }
  throw new Error('the request was answered, not refused')
}

/** The request's card, confirmed in the app and on the board; the dapp's answer and the card's hash.
 * The Safe's threshold is 1, so the app executes at once after the board signs. */
async function confirmOnBoard<T>(pending: Promise<T>, check: (card: ReturnType<typeof t>) => Promise<void>) {
  const card = t(page, 'wc-request').first()
  await expect(card).toBeVisible({ timeout: 60_000 })
  await check(card)
  await expect(card.getByTestId('wc-confirm')).toHaveText('Sign on the board and execute')
  const before = await t(page, 'wc-done').count()
  await card.getByTestId('wc-confirm').click()
  const pages = await vb.confirm()
  const answer = await pending
  await vb.dismiss('Signed')
  await expect(t(page, 'wc-done')).toHaveCount(before + 1, { timeout: 60_000 })
  const done = t(page, 'wc-done').first()
  return { pages, answer, hash: (await done.getByTestId('wc-done-text').getAttribute('data-hash')) as Hex, done }
}

test.describe.serial('WalletConnect with the virtual board', () => {
  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    test.skip(!haveChainTools(), 'needs anvil and the Python signer’s virtualenv (WINTERLOCK_PYTHON)')
    test.skip(!projectId(), 'needs WINTERLOCK_ENV_FILE with WALLETCONNECT_PROJECT_ID')
    await chain.start()
    dapp = await SignClient.init({
      projectId: projectId()!,
      telemetryEnabled: false,
      logger: 'silent',
      // its own core: specs in one worker would otherwise share the SDK's global one
      customStoragePrefix: 'e2e-board',
      storageOptions: { database: ':memory:' },
      metadata: { name: 'Winterlock e2e dapp', description: 'a scripted dapp', url: 'https://dapp.example.org', icons: [] },
    })
    ctx = await browser.newContext({ baseURL: BASE })
    page = await ctx.newPage()
    page.on('pageerror', (e) => log(`  page error: ${redact(e.message)}`))
    await new FakeService(chain.client() as any).install(page)
    vb = new VBoard(page)
  })

  test.afterAll(async () => {
    await ctx?.close()
    await (dapp?.core.relayer as any)?.transportClose?.().catch(() => {})
    chain.stop()
  })

  test('a board, a Safe and a key tree', async () => {
    test.setTimeout(6 * 60_000)
    await useLocalRpc(page, BASE, chain.url)
    await page.goto('/#/')
    await t(page, 'go-board').click()
    await t(page, 'connect-virtual').click()
    await t(page, 'board-setup').click()
    await vb.setup()
    await expect(t(page, 'board-done')).toBeVisible({ timeout: 60_000 })
    const owner = getAddress((await t(page, 'owner-address').getAttribute('data-value'))!)
    await vb.until('Owner address')
    await vb.press('RR')
    await t(page, 'done-home').click()
    await chain.setBalance((await boardRecord(page)).gasAddress, 10n ** 19n)
    safe = await chain.createSafe([owner], 31n)
    await joinSafe(page, BASE, safe)
    await t(page, 'enrol').click()
    await vb.confirm()
    await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '512', { timeout: 180_000 })
    await vb.dismiss('Enrolled')
    const r = await sendAnvil(undefined, TEST_TOKEN_CODE)
    token = getAddress(r.contractAddress!)
    await sendAnvil(token, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [safe, 10n ** 12n] }))
  })

  test('pairing by a pasted link; the capabilities say no batches', async () => {
    const { uri, approval } = await dapp.connect({
      optionalNamespaces: { eip155: { chains: [CAIP], methods: ['eth_sendTransaction', 'personal_sign', 'wallet_sendCalls', 'wallet_getCallsStatus', 'wallet_getCapabilities', 'eth_getTransactionReceipt', 'eth_chainId'], events: ['chainChanged', 'accountsChanged'] } },
    })
    await page.goto(`/#/safe/${CHAIN}/${safe}/dapps`)
    await t(page, 'wc-uri').fill(uri!)
    await t(page, 'wc-pair').click()
    await t(page, 'wc-proposal').getByTestId('wc-approve').click()
    const s = await approval()
    topic = s.topic
    expect(s.namespaces.eip155.accounts).toEqual([`${CAIP}:${safe}`])
    expect(JSON.parse(s.sessionProperties!.atomic)).toEqual({ status: 'unsupported' })
    expect(await ask('wallet_getCapabilities', [safe])).toEqual({ '0xaa36a7': { atomicBatch: { supported: false }, atomic: { status: 'unsupported' } } })
  })

  test('eth_sendTransaction: the board shows the transfer and signs; executed at once; the dapp gets the transaction hash', async () => {
    const value = 10n ** 17n
    const before = await chain.client().getBalance({ address: BOB })
    const pending = ask<Hex>('eth_sendTransaction', [{ from: safe, to: BOB, value: toHex(value) }])
    const { pages, answer, hash, done } = await confirmOnBoard(pending, async (card) => {
      await expect(card.getByTestId('tx-summary')).toContainText(`Send 0.1 ETH to ${BOB}`)
      await expect(card).toContainText('The board shows this transaction itself')
    })
    expect(pages[0]).toMatch(/^Send/)
    await expect(done.getByTestId('wc-executed')).toBeVisible({ timeout: 120_000 })
    const tx = (await done.getByTestId('wc-executed').getAttribute('data-tx')) as Hex
    expect(answer).toBe(tx)
    expect(hash).toBe((await chain.hashOf(safe, BOB, value, '0x', 0, (await chain.nonceOf(safe)) - 1)).toLowerCase())
    expect((await chain.client().getBalance({ address: BOB })) - before).toBe(value)
    expect(await ask('eth_getTransactionReceipt', [tx])).toMatchObject({ transactionHash: tx, status: '0x1' })
    expect(await ask('eth_getTransactionReceipt', [hash])).toMatchObject({ transactionHash: tx, status: '0x1' })
    log(`  board pages: ${pages.join(' | ')}`)
  })

  test('a batch is refused with the reason; one call through wallet_sendCalls works', async () => {
    const e = await refusal(ask('wallet_sendCalls', [{ version: '2.0.0', from: safe, chainId: '0xaa36a7', calls: [{ to: BOB, value: '0x1' }, { to: BOB, value: '0x2' }] }]))
    expect(e.code).toBe(4001)
    expect(e.message).toMatch(/board, which refuses delegate calls/)
    await expect(t(page, 'wc-log')).toContainText('Refused wallet_sendCalls (4001)')
    await expect(t(page, 'wc-request')).toHaveCount(0)
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [BOB, 2_000_000n] })
    const pending = ask<{ id: Hex }>('wallet_sendCalls', [{ version: '2.0.0', from: safe, chainId: '0xaa36a7', calls: [{ to: token, data }] }])
    const { pages, answer, hash, done } = await confirmOnBoard(pending, async (card) => {
      await expect(card.getByTestId('tx-summary')).toContainText(`Send 2 TST to ${BOB}`)
    })
    // the test token isn't in the board's list: a call it doesn't decode, confirmed twice
    log(`  board pages: ${pages.join(' | ')}`)
    expect(pages).toContain('Not decoded')
    expect(answer).toEqual({ id: hash })
    await expect(done.getByTestId('wc-executed')).toBeVisible({ timeout: 120_000 })
    expect(await ask('wallet_getCallsStatus', [hash])).toMatchObject({ status: 200 })
    expect(await chain.client().readContract({ address: token, abi: TOKEN_ABI, functionName: 'balanceOf', args: [BOB] })).toBe(2_000_000n)
  })

  test('a message is refused; the member disconnects', async () => {
    expect(await refusal(ask('personal_sign', [toHex('hello'), safe]))).toEqual({ code: 4001, message: "messages aren't supported yet" })
    const deleted = new Promise<string>((res) => dapp.on('session_delete', (e) => res(e.topic)))
    await t(page, 'wc-session').getByTestId('wc-disconnect').click()
    expect(await deleted).toBe(topic)
    await expect(t(page, 'wc-session')).toHaveCount(0)
  })
})
