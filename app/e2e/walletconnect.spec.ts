// WalletConnect end to end: the app on the local chain (anvil with Sepolia's chain id, the stand-in
// for Safe's service; local.ts, fake-service.ts) and a dapp on the official SDK
// (@walletconnect/sign-client) in this test process, paired through Reown's live relay.
//
// Needs anvil and the Python signer's virtualenv (local.ts), and WINTERLOCK_ENV_FILE with
// WALLETCONNECT_PROJECT_ID (never printed). With E2E_PREVIEW=1 the app is the production build,
// under its Content Security Policy. Spends nothing.

import { type Browser, type BrowserContext, type Page, expect, test } from '@playwright/test'
import { SignClient } from '@walletconnect/sign-client'
import { readFileSync } from 'node:fs'
import { type Address, type Hex, createWalletClient, encodeFunctionData, getAddress, http, keccak256, parseAbi, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { ERC20_ABI, MAX_UINT256, execCalldata, fromService, pack, parseSignature } from '../src/lib/safe'
import { log, projectId, redact } from './env'
import { FakeService } from './fake-service'
import { BOB, LocalChain, haveChainTools, joinSafe, tid as t, useLocalRpc, waitDone } from './local'
import { TEST_TOKEN_CODE } from './test-token'

const CHAIN = 11155111
const BASE = `http://localhost:${process.env.E2E_PORT ?? 5190}`
const CAIP = `eip155:${CHAIN}`
// anvil's first default account: a public test key, local chains only
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const SPENDER = getAddress(keccak256(toHex('walletconnect run: spender')).slice(0, 42))
const SAFE_141 = process.env.SAFE_141_BUILD ?? '/home/johba/winterlock.eth/contracts/lib/safe-smart-account-v1.4.1/build/forge-out'
const MULTISEND = getAddress('0x9641d764fc13c8B624c04430C7356C1C7C8102e2')
const TOKEN_ABI = parseAbi(['function allowance(address owner, address spender) view returns (uint256)', 'function balanceOf(address) view returns (uint256)'])
// what the dapp asks for: the methods a dapp on wagmi lists, and a read
const METHODS = ['eth_sendTransaction', 'personal_sign', 'eth_signTypedData_v4', 'wallet_sendCalls', 'wallet_getCallsStatus', 'wallet_getCapabilities', 'wallet_switchEthereumChain', 'eth_chainId', 'eth_getTransactionReceipt', 'eth_getTransactionByHash', 'eth_getBalance']

const chain = new LocalChain()
let ctx: BrowserContext
let page: Page
let svc: FakeService
let dapp: Awaited<ReturnType<typeof SignClient.init>>
let topic = ''
let safe: Address
let token: Address
const hosts = new Set<string>()
const times: Record<string, number> = {}

function anvilWallet() {
  return createWalletClient({
    account: privateKeyToAccount(ANVIL_KEY),
    transport: http(chain.url),
    chain: { id: CHAIN, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [chain.url] } } },
  })
}

async function sendAnvil(to: Address | undefined, data: Hex) {
  const hash = await anvilWallet().sendTransaction({ to: to ?? null, data } as any)
  const r = await chain.client().waitForTransactionReceipt({ hash })
  if (r.status !== 'success') throw new Error(`reverted: ${hash}`)
  return r
}

const ask = <T = any>(method: string, params: unknown[], chainId = CAIP) => dapp.request<T>({ topic, chainId, request: { method, params } })

/** The dapp's error for a request: its code and message. */
async function refusal(p: Promise<unknown>): Promise<{ code: number; message: string }> {
  try {
    await p
  } catch (e: any) {
    return { code: e?.code, message: String(e?.message ?? e) }
  }
  throw new Error('the request was answered, not refused')
}

async function connect(): Promise<string> {
  const t0 = Date.now()
  const { uri, approval } = await dapp.connect({ optionalNamespaces: { eip155: { chains: [CAIP], methods: METHODS, events: ['chainChanged', 'accountsChanged'] } } })
  await page.goto(`/#/safe/${CHAIN}/${safe}/dapps`)
  await t(page, 'wc-uri').fill(uri!)
  await t(page, 'wc-pair').click()
  const card = t(page, 'wc-proposal')
  await expect(card).toBeVisible({ timeout: 60_000 })
  await expect(card.getByTestId('dapp-claim')).toContainText('Winterlock e2e dapp')
  await expect(card.getByTestId('dapp-claim')).toContainText('not verified')
  await expect(card).toContainText(safe)
  await card.getByTestId('wc-approve').click()
  const s = await approval()
  times.pairing = Date.now() - t0
  expect(s.namespaces.eip155.accounts).toEqual([`${CAIP}:${safe}`])
  await expect(t(page, 'wc-session').filter({ hasText: 'Winterlock e2e dapp' })).toHaveCount(1 + (topic ? 1 : 0), { timeout: 30_000 })
  return s.topic
}

/** Waits for the request's card, confirms it, and returns the dapp's answer and the card's hash. */
async function confirmNext<T>(pending: Promise<T>, check: (card: ReturnType<typeof t>) => Promise<void>) {
  const t0 = Date.now()
  const card = t(page, 'wc-request').first()
  await expect(card).toBeVisible({ timeout: 60_000 })
  times.requestShown = Date.now() - t0
  await check(card)
  const before = await t(page, 'wc-done').count()
  const t1 = Date.now()
  await card.getByTestId('wc-confirm').click()
  // the dapp's answer, or the app's error on the card
  const failed = card
    .getByTestId('error')
    .waitFor({ timeout: 300_000 })
    .then(async () => {
      throw new Error(`the app says: ${await card.getByTestId('error').textContent()}`)
    })
  failed.catch(() => {})
  const answer = await Promise.race([pending, failed])
  times.confirmToAnswer = Date.now() - t1
  // the newest result comes first
  await expect(t(page, 'wc-done')).toHaveCount(before + 1, { timeout: 60_000 })
  const done = t(page, 'wc-done').first()
  return { answer, hash: (await done.getByTestId('wc-done-text').getAttribute('data-hash')) as Hex, done }
}

test.describe.serial('WalletConnect on a local chain', () => {
  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    test.skip(!haveChainTools(), 'needs anvil and the Python signer’s virtualenv (WINTERLOCK_PYTHON)')
    test.skip(!projectId(), 'needs WINTERLOCK_ENV_FILE with WALLETCONNECT_PROJECT_ID')
    await chain.start()
    // Safe v1.4.1's MultiSendCallOnly at its canonical address, from the release build
    const code = JSON.parse(readFileSync(`${SAFE_141}/MultiSendCallOnly.sol/MultiSendCallOnly.json`, 'utf8')).deployedBytecode.object as Hex
    await chain.client().request({ method: 'anvil_setCode' as any, params: [MULTISEND, code] as any })
    dapp = await SignClient.init({
      projectId: projectId()!,
      telemetryEnabled: false,
      logger: 'silent',
      storageOptions: { database: ':memory:' },
      metadata: { name: 'Winterlock e2e dapp', description: 'a scripted dapp', url: 'https://dapp.example.org', icons: [] },
    })
    ctx = await browser.newContext({ baseURL: BASE })
    page = await ctx.newPage()
    page.on('request', (r) => hosts.add(new URL(r.url()).host))
    page.on('websocket', (w) => hosts.add(new URL(w.url()).host))
    page.on('pageerror', (e) => log(`  page error: ${redact(e.message)}`))
    page.on('console', (m) => {
      if (m.type() === 'error') log(`  console: ${redact(m.text()).slice(0, 300)}`)
    })
    svc = new FakeService(chain.client() as any)
    await svc.install(page)
  })

  test.afterAll(async () => {
    log(`  hosts the page reached: ${[...hosts].sort().join(', ')}`)
    log(`  times (ms): ${JSON.stringify(times)}`)
    await ctx?.close()
    await (dapp?.core.relayer as any)?.transportClose?.().catch(() => {})
    chain.stop()
  })

  test('a member with a Safe and a key tree', async () => {
    test.setTimeout(5 * 60_000)
    await useLocalRpc(page, BASE, chain.url)
    await page.goto('/#/')
    await t(page, 'go-create').click()
    await t(page, 'show-phrase').click()
    await t(page, 'phrase-words').waitFor()
    const words = await t(page, 'phrase-words').locator('li').allTextContents()
    await t(page, 'written-down').click()
    const labels = await page.locator('form label').allTextContents()
    for (let i = 0; i < 3; i++) await t(page, `check-word-${i}`).fill(words[Number(labels[i].match(/Word (\d+)/)![1]) - 1])
    await t(page, 'check-submit').click()
    await t(page, 'create-done').waitFor({ timeout: 120_000 })
    const owner = getAddress((await t(page, 'owner-address').getAttribute('data-value'))!)
    await t(page, 'done-home').click()
    await page.goto('/#/settings')
    await chain.setBalance((await t(page, 'gas-address').getAttribute('data-value')) as Address, 10n ** 19n)
    await page.goto('/#/')
    await t(page, 'send-certificate').click()
    await waitDone(page, t(page, 'certificate-report'))
    safe = await chain.createSafe([owner], 21n)
    await joinSafe(page, BASE, safe)
    await t(page, 'enrol').click()
    await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '512', { timeout: 180_000 })
    // a token, and some of it in the Safe
    const r = await sendAnvil(undefined, TEST_TOKEN_CODE)
    token = getAddress(r.contractAddress!)
    await sendAnvil(token, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [safe, 10n ** 12n] }))
  })

  test('pairing by a pasted link', async () => {
    // no WalletConnect before the member opens a Safe's dapps
    expect([...hosts].some((h) => h.includes('walletconnect'))).toBe(false)
    topic = await connect()
    log(`  paired in ${times.pairing} ms`)
    expect(await ask('eth_chainId', [])).toBe('0xaa36a7')
  })

  test('eth_sendTransaction: an ETH transfer, executed here, its receipt through the SafeTx hash', async () => {
    const value = 625n * 10n ** 14n
    const before = await chain.client().getBalance({ address: BOB })
    // the bar on another screen leads to the request
    await page.goto(`/#/safe/${CHAIN}/${safe}`)
    const pending = ask<Hex>('eth_sendTransaction', [{ from: safe, to: BOB, value: toHex(value), gas: '0x5208' }])
    await expect(t(page, 'wc-bar')).toBeVisible({ timeout: 60_000 })
    await t(page, 'wc-bar').click()
    const { answer, hash, done } = await confirmNext(pending, async (card) => {
      await expect(card.getByTestId('tx-summary')).toContainText(`Send 0.0625 ETH to ${BOB}`)
    })
    expect(answer).toBe(hash)
    const nonce = await chain.nonceOf(safe)
    expect(hash).toBe((await chain.hashOf(safe, BOB, value, '0x', 0, nonce)).toLowerCase())
    expect(svc.txs.get(hash)?.confirmations).toHaveLength(1)
    log(`  answered ${times.confirmToAnswer} ms after the confirm (shown ${times.requestShown} ms after asking)`)
    // before execution: no receipt, a pending placeholder
    expect(await ask('eth_getTransactionReceipt', [hash])).toBeNull()
    expect(await ask('eth_getTransactionByHash', [hash])).toMatchObject({ hash, blockNumber: null })
    await done.getByTestId('wc-execute').click()
    await expect(done.getByTestId('wc-executed')).toBeVisible({ timeout: 120_000 })
    const tx = (await done.getByTestId('wc-executed').getAttribute('data-tx')) as Hex
    expect((await chain.client().getBalance({ address: BOB })) - before).toBe(value)
    const receipt = await ask('eth_getTransactionReceipt', [hash])
    expect(receipt).toMatchObject({ transactionHash: tx, status: '0x1' })
    expect(await ask('eth_getTransactionByHash', [hash])).toMatchObject({ hash: tx })
  })

  test('eth_sendTransaction: an ERC-20 transfer', async () => {
    const amount = 1_500_000n
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [BOB, amount] })
    const pending = ask<Hex>('eth_sendTransaction', [{ from: safe, to: token, data }])
    const { answer, hash, done } = await confirmNext(pending, async (card) => {
      await expect(card.getByTestId('tx-summary')).toContainText(`Send 1.5 TST to ${BOB}`)
    })
    expect(answer).toBe(hash)
    await done.getByTestId('wc-execute').click()
    await expect(done.getByTestId('wc-executed')).toBeVisible({ timeout: 120_000 })
    expect(await chain.client().readContract({ address: token, abi: TOKEN_ABI, functionName: 'balanceOf', args: [BOB] })).toBe(amount)
  })

  test('wallet_sendCalls with a batch, then wallet_getCallsStatus through an execution elsewhere', async () => {
    expect(await ask('wallet_getCapabilities', [safe, ['0xaa36a7']])).toEqual({ '0xaa36a7': { atomicBatch: { supported: true }, atomic: { status: 'supported' } } })
    const calls = [
      { to: BOB, value: toHex(10n ** 16n) },
      { to: token, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [BOB, 2_500_000n] }) },
      { to: token, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, MAX_UINT256] }) },
    ]
    const ethBefore = await chain.client().getBalance({ address: BOB })
    const pending = ask<{ id: Hex }>('wallet_sendCalls', [{ version: '2.0.0', from: safe, chainId: '0xaa36a7', atomicRequired: true, calls }])
    const { answer, hash } = await confirmNext(pending, async (card) => {
      await expect(card.getByTestId('batch-call')).toHaveCount(3)
      await expect(card.getByTestId('batch-call').nth(0)).toContainText(`Send 0.01 ETH to ${BOB}`)
      await expect(card.getByTestId('batch-call').nth(1)).toContainText(`Send 2.5 TST to ${BOB}`)
      await expect(card.getByTestId('batch-call').nth(2)).toContainText(`Allow ${SPENDER} to take any amount of TST`)
      await expect(card).toContainText('Call 3: Unlimited allowance')
    })
    expect(answer).toEqual({ id: hash })
    const rec = svc.txs.get(hash)!
    expect(rec.operation).toBe(1)
    expect(getAddress(rec.to)).toBe(MULTISEND)
    // proposed, not executed: 100
    expect(await ask('wallet_getCallsStatus', [hash])).toMatchObject({ id: hash, status: 100, atomic: true })
    // anyone executes it (as in Safe's app): here anvil's account, with the member's confirmation
    const sig = parseSignature(rec.confirmations[0].signature)
    const exec = execCalldata(fromService(rec), pack([{ owner: sig.owner!, data: sig.data, contract: true }]))
    const r = await sendAnvil(safe, exec)
    // the service indexes the execution
    rec.transactionHash = r.transactionHash
    const status = await ask<any>('wallet_getCallsStatus', [hash])
    expect(status).toMatchObject({ version: '2.0.0', id: hash, chainId: '0xaa36a7', atomic: true, status: 200 })
    expect(status.receipts[0]).toMatchObject({ transactionHash: r.transactionHash, status: '0x1' })
    expect((await chain.client().getBalance({ address: BOB })) - ethBefore).toBe(10n ** 16n)
    expect(await chain.client().readContract({ address: token, abi: TOKEN_ABI, functionName: 'allowance', args: [safe, SPENDER] })).toBe(MAX_UINT256)
    expect(await ask('eth_getTransactionReceipt', [hash])).toMatchObject({ transactionHash: r.transactionHash })
    log(`  batch of 3: ${r.gasUsed} gas`)
  })

  test('a message request is refused', async () => {
    const e = await refusal(ask('personal_sign', [toHex('Sign in to dapp.example.org'), safe]))
    expect(e).toEqual({ code: 4001, message: "messages aren't supported yet" })
    const e2 = await refusal(ask('eth_signTypedData_v4', [safe, JSON.stringify({ domain: {}, types: {}, message: {} })]))
    expect(e2.code).toBe(4001)
    await expect(t(page, 'wc-log')).toContainText('Refused personal_sign (4001)')
  })

  test('requests for another chain are refused', async () => {
    const e = await refusal(ask('eth_sendTransaction', [{ from: safe, to: BOB, value: '0x1', chainId: '0x1' }]))
    expect(e.code).toBe(5100)
    const e2 = await refusal(ask('wallet_switchEthereumChain', [{ chainId: '0x1' }]))
    expect(e2.code).toBe(4902)
    // a request on a chain the session doesn't hold: the dapp's own SDK refuses it
    const e3 = await refusal(ask('eth_chainId', [], 'eip155:1'))
    log(`  on eip155:1 the dapp's SDK says: ${e3.message.slice(0, 120)}`)
    await expect(t(page, 'wc-request')).toHaveCount(0)
  })

  test('a reload with a live session and a pending request', async () => {
    const pending = ask('eth_sendTransaction', [{ from: safe, to: BOB, value: '0x2' }])
    await expect(t(page, 'wc-request')).toHaveCount(1, { timeout: 60_000 })
    const t0 = Date.now()
    await page.reload()
    await expect(t(page, 'wc-session')).toHaveCount(1, { timeout: 60_000 })
    await expect(t(page, 'wc-request')).toHaveCount(1, { timeout: 60_000 })
    times.reloadToRequest = Date.now() - t0
    await t(page, 'wc-request').getByTestId('wc-refuse').click()
    expect(await refusal(pending)).toEqual({ code: 4001, message: 'the member rejected the transaction' })
    expect(await ask('eth_chainId', [])).toBe('0xaa36a7')
    // and from another screen, after a reload there: the app reconnects by itself
    await page.goto('/#/')
    await page.reload()
    await expect(t(page, 'home')).toBeVisible()
    const p2 = ask('eth_sendTransaction', [{ from: safe, to: BOB, value: '0x3' }])
    await expect(t(page, 'wc-bar')).toBeVisible({ timeout: 60_000 })
    await t(page, 'wc-bar').click()
    await t(page, 'wc-request').getByTestId('wc-refuse').click()
    expect((await refusal(p2)).code).toBe(4001)
  })

  test('the dapp disconnects', async () => {
    await dapp.disconnect({ topic, reason: { code: 6000, message: 'User disconnected.' } })
    await expect(t(page, 'wc-session')).toHaveCount(0, { timeout: 60_000 })
    await expect(t(page, 'wc-log')).toContainText('The dapp disconnected.')
  })

  test('the member disconnects', async () => {
    topic = ''
    topic = await connect()
    const deleted = new Promise<string>((res) => dapp.on('session_delete', (e) => res(e.topic)))
    await t(page, 'wc-session').getByTestId('wc-disconnect').click()
    expect(await deleted).toBe(topic)
    await expect(t(page, 'wc-session')).toHaveCount(0)
    expect(dapp.session.getAll().some((s) => s.topic === topic)).toBe(false)
  })

  test('the page reached no third party', async () => {
    const allowed = new Set(['relay.walletconnect.org', 'api.safe.global', new URL(chain.url).host, new URL(page.url()).host])
    expect([...hosts].filter((h) => !allowed.has(h))).toEqual([])
    const refused = await page.evaluate(() => (globalThis as any).__winterlockRefused ?? [])
    log(`  fetches the guard refused: ${JSON.stringify(refused)}`)
    expect(refused).toEqual([])
  })
})
