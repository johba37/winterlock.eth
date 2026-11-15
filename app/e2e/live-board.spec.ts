// The app with the virtual board, live on Sepolia, with Safe's hosted Transaction Service and no
// API key in the app (as live.spec.ts, with a board instead of device keys). One Chromium profile,
// "board", holds the app and the virtual board's flash. A fresh test Safe, made by script, starts
// with an ECDSA owner alone; it adds the board's owner with threshold 2, so each transfer needs
// both: the board proposes and the ECDSA owner confirms, then the other way round.
//
// Each step runs once; a finished step is skipped on a re-run (state in E2E_DIR/state.json).
// Spending stops past MAX_SPEND.
//
//   E2E_DIR=... WINTERLOCK_ENV_FILE=.../contracts/bench/bundlers/.env npx playwright test e2e/live-board.spec.ts

import { expect, test } from '@playwright/test'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Address, type Hex, getAddress, parseAbi } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import * as app from './app'
import * as chain from './chain'
import { log, redact } from './env'
import { boardRecord } from './local'
import { VBoard } from './vboard'

const MAX_SPEND = 3n * 10n ** 16n // 0.03 ETH from the funding account, value moved included
const GAS_FUNDING = 10n ** 15n // the board's gas account
const SAFE_FUNDING = 10n ** 14n
const TRANSFER = '0.00001'
const SERVICE = 'https://api.safe.global/tx-service/sep/api'

interface State {
  done: string[]
  startBalance?: string
  ecdsaKey?: Hex
  ecdsa?: Address
  owner?: Address
  gas?: Address
  safe?: Address
  hashes: Record<string, string>
  txs: { step: string; what: string; hash: string; gasUsed?: string }[]
  notes: Record<string, unknown>
}

const file = () => join(app.dir(), 'state.json')
const load = (): State => (existsSync(file()) ? JSON.parse(readFileSync(file(), 'utf8')) : { done: [], hashes: {}, txs: [], notes: {} })
const save = (st: State) => writeFileSync(file(), JSON.stringify(st, null, 1))

async function record(st: State, step: string, what: string, hash: string) {
  const r = await chain.receipt(hash as Hex)
  st.txs.push({ step, what, hash, gasUsed: r.gasUsed.toString() })
  log(`  ${what}: ${hash} (${r.gasUsed} gas)`)
}

async function spent(st: State) {
  const s = BigInt(st.startBalance!) - (await chain.balance(chain.funder().address))
  if (s > MAX_SPEND) throw new Error(`spent ${s} wei, over this run's ${MAX_SPEND}: stopping`)
  return s
}

function step(name: string, f: (st: State, baseURL: string) => Promise<void>) {
  test(name, async ({ baseURL }) => {
    const st = load()
    if (st.done.includes(name)) {
      log(`${name}: done before, skipped`)
      return
    }
    log(`${name}:`)
    try {
      await f(st, baseURL!)
    } catch (e) {
      throw new Error(redact(String((e as Error)?.stack ?? e)))
    }
    st.done.push(name)
    st.notes.spentWei = (await spent(st)).toString()
    save(st)
  })
}

/** The board's profile, its virtual board started by the app and unlocked. */
async function openBoard(base: string) {
  const d = await app.open('board', base)
  const vb = new VBoard(d.page)
  await expect(d.page.getByTestId('link-state')).toHaveAttribute('data-phase', 'connected', { timeout: 60_000 })
  if ((await d.page.getByTestId('link-state').getAttribute('data-state')) === 'locked') await vb.unlock()
  await expect(d.page.getByTestId('link-state')).toHaveAttribute('data-state', 'unlocked', { timeout: 30_000 })
  return { d, vb }
}

/** The ECDSA owner's signature of a SafeTx hash (v = 27 or 28), as Safe's service takes it. */
async function ecdsaSign(st: State, hash: Hex): Promise<Hex> {
  return privateKeyToAccount(st.ecdsaKey!).sign({ hash })
}

async function post(path: string, body: unknown) {
  const r = await fetch(`${SERVICE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  if (r.status !== 200 && r.status !== 201) throw new Error(`the service answered ${r.status}: ${(await r.text()).slice(0, 300)}`)
}

const SAFE = parseAbi([
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
])

/** A proposal by the ECDSA owner, with its signature. */
async function ecdsaPropose(st: State, tx: { to: Address; value: bigint; data: Hex; operation: 0 | 1; nonce: number }): Promise<Hex> {
  const c = chain.client()
  const zero = '0x0000000000000000000000000000000000000000'
  const hash = await c.readContract({ address: st.safe!, abi: SAFE, functionName: 'getTransactionHash', args: [tx.to, tx.value, tx.data, tx.operation, 0n, 0n, 0n, zero, zero, BigInt(tx.nonce)] })
  await post(`/v2/safes/${st.safe}/multisig-transactions/`, {
    to: tx.to,
    value: tx.value.toString(),
    data: tx.data === '0x' ? null : tx.data,
    operation: tx.operation,
    safeTxGas: '0',
    baseGas: '0',
    gasPrice: '0',
    gasToken: zero,
    refundReceiver: zero,
    nonce: tx.nonce,
    contractTransactionHash: hash,
    sender: st.ecdsa,
    signature: await ecdsaSign(st, hash),
    origin: null,
  })
  return hash
}

async function nextNonce(st: State): Promise<number> {
  const o = await chain.owners(st.safe!)
  const r = await fetch(`${SERVICE}/v2/safes/${st.safe}/multisig-transactions/?executed=false&nonce__gte=${o.nonce}`)
  const pending = r.status === 200 ? ((await r.json()).results as { nonce: number }[]) : []
  return Math.max(o.nonce, ...pending.map((p) => Number(p.nonce) + 1))
}

test.describe.serial('live on Sepolia with the virtual board', () => {
  test.skip(!process.env.E2E_DIR || !process.env.WINTERLOCK_ENV_FILE, 'needs E2E_DIR and WINTERLOCK_ENV_FILE')

  step('00 setup', async (st) => {
    const b = await chain.balance(chain.funder().address)
    log(`  funding account ${chain.funder().address}: ${b} wei`)
    if (b < GAS_FUNDING + SAFE_FUNDING + 10n ** 15n) throw new Error('the funding account holds too little for this run')
    st.startBalance = b.toString()
    st.ecdsaKey ??= generatePrivateKey() // a throwaway testnet key, kept in the scratch directory only
    st.ecdsa = privateKeyToAccount(st.ecdsaKey).address
    save(st)
  })

  step('01 a member with the virtual board: set up on it', async (st, base) => {
    const d = await app.open('board', base)
    const p = d.page
    await app.setRpc(d)
    await p.goto('/#/')
    await app.screens(d, 'b01-welcome')
    await p.getByTestId('go-board').click()
    await app.screens(d, 'b02-use-a-board')
    await p.getByTestId('connect-virtual').click()
    await expect(p.getByTestId('board-state')).toContainText('A new or erased board', { timeout: 30_000 })
    await app.screens(d, 'b03-board-blank')
    await p.getByTestId('board-setup').click()
    const vb = new VBoard(p)
    await vb.setup()
    await expect(p.getByTestId('board-done')).toBeVisible({ timeout: 60_000 })
    await app.screens(d, 'b04-board-ready')
    await vb.press('RR')
    const rec = await boardRecord(p)
    st.owner = getAddress(rec.owner)
    st.gas = getAddress(rec.gasAddress)
    save(st)
    await p.getByTestId('done-home').click()
    await expect(p.getByTestId('home')).toBeVisible()
    await expect(p.getByTestId('owner-state')).toHaveAttribute('data-deployed', 'false', { timeout: 60_000 })
    await app.screens(d, 'b05-home')
    log(`  owner ${st.owner}, gas account ${st.gas}`)
    await app.close(d)
  })

  step('02 fund the gas account', async (st) => {
    const r = await chain.fund(st.gas!, GAS_FUNDING)
    st.txs.push({ step: '02', what: 'fund the board’s gas account', hash: r.hash, gasUsed: r.gasUsed.toString() })
  })

  step('03 a fresh Safe, owned by an ECDSA test key', async (st) => {
    const r = await chain.createSafe(st.ecdsa!, BigInt(Date.now()))
    st.safe = r.safe
    st.txs.push({ step: '03', what: 'create the Safe (v1.4.1 SafeL2), owner: ECDSA test key, 1 of 1', hash: r.hash, gasUsed: r.gasUsed.toString() })
    save(st)
    const f = await chain.fund(r.safe, SAFE_FUNDING)
    st.txs.push({ step: '03', what: 'fund the Safe', hash: f.hash, gasUsed: f.gasUsed.toString() })
    log(`  Safe ${r.safe}`)
  })

  step('04 join: not an owner yet; the ECDSA owner adds the board’s owner (threshold 2); enrol on the board', async (st, base) => {
    const { d, vb } = await openBoard(base)
    const p = d.page
    await app.join(d, st.safe!)
    const o0 = await chain.owners(st.safe!)
    if (!o0.owners.includes(st.owner!)) {
      await expect(p.getByTestId('not-owner')).toBeVisible()
      await app.screens(d, 'b06-safe-not-owner')
      const r = await chain.addOwner(st.safe!, st.ecdsaKey!, st.owner!, 2n)
      st.txs.push({ step: '04', what: 'addOwnerWithThreshold(board’s owner, 2), signed by the ECDSA owner', hash: r.hash, gasUsed: r.gasUsed.toString() })
      save(st)
      await p.getByTestId('check-again').click()
    }
    await expect(p.getByTestId('not-owner')).toBeHidden({ timeout: 60_000 })
    await expect(p.getByTestId('enrol')).toBeEnabled({ timeout: 60_000 })
    await app.screens(d, 'b07-safe-enrol')
    await p.getByTestId('enrol').click()
    const pages = await vb.confirm()
    expect(pages[0]).toMatch(/^Enrol key tree/)
    await app.screens(d, 'b08-enrolling')
    await expect(p.getByTestId('enrolled').or(p.getByTestId('error')).first()).toBeVisible({ timeout: 10 * 60_000 })
    if (await p.getByTestId('error').isVisible()) throw new Error(`the app says: ${await p.getByTestId('error').textContent()}`)
    await expect(p.getByTestId('tree-state')).toHaveAttribute('data-left', /^[1-9]/, { timeout: 60_000 })
    await vb.dismiss('Enrolled')
    await app.screens(d, 'b09-safe-enrolled')
    const tx = (await p.getByTestId('enrolled').getAttribute('data-tx'))!
    await record(st, '04', 'deployAndEnroll: the board’s owner created with its first key tree (height 10), certificate by the board', tx)
    await app.close(d)
  })

  step('05 Safe’s service indexes the Safe and its owners', async (st) => {
    const r = await chain.waitIndexed(st.safe!, [st.ecdsa!, st.owner!])
    st.notes.indexedAfterPolls = r.polls
    log(`  indexed after ${r.polls} poll(s): threshold ${r.info.threshold}, nonce ${r.info.nonce}`)
  })

  step('06 the board proposes a transfer, the ECDSA owner confirms, the app executes', async (st, base) => {
    const { d, vb } = await openBoard(base)
    const p = d.page
    let h = st.hashes.boardProposed as Hex | undefined
    if (!h) {
      await p.goto(`/#/safe/11155111/${st.safe}/send`)
      await p.getByTestId('to-input').fill(chain.funder().address)
      await p.getByTestId('amount-input').fill(TRANSFER)
      await p.getByTestId('review').click()
      await app.screens(d, 'b10-send-review')
      await p.getByTestId('sign-propose').click()
      const pages = await vb.confirm()
      log(`  the board showed: ${pages.join(' / ')}`)
      await expect(p.getByTestId('done').or(p.getByTestId('error')).first()).toBeVisible({ timeout: 5 * 60_000 })
      if (await p.getByTestId('error').isVisible()) throw new Error(`the app says: ${await p.getByTestId('error').textContent()}`)
      await vb.dismiss('Signed')
      await app.screens(d, 'b11-send-done')
      h = (await p.getByTestId('done').getAttribute('data-hash')) as Hex
      st.hashes.boardProposed = h
      save(st)
      log(`  proposed ${h} (no API key in the app)`)
    }
    await post(`/v1/multisig-transactions/${h}/confirmations/`, { signature: await ecdsaSign(st, h) }).catch((e) => log(`  ECDSA confirmation: ${e.message}`))
    const tx = await app.executeTx(d, st.safe!, h)
    await record(st, '06', 'execTransaction: the board proposed, the ECDSA owner confirmed, the gas account executed', tx)
    await app.close(d)
  })

  step('07 the ECDSA owner proposes, the board confirms, the app executes', async (st, base) => {
    let h = st.hashes.ecdsaProposed as Hex | undefined
    if (!h) {
      h = await ecdsaPropose(st, { to: chain.funder().address, value: 10n ** 13n, data: '0x', operation: 0, nonce: await nextNonce(st) })
      st.hashes.ecdsaProposed = h
      save(st)
    }
    const { d, vb } = await openBoard(base)
    const p = d.page
    await app.openTx(d, st.safe!, h)
    await app.screens(d, 'b12-tx-to-confirm')
    if (await p.getByTestId('confirm').isVisible()) {
      await p.getByTestId('confirm').click()
      const pages = await vb.confirm()
      log(`  the board showed: ${pages.join(' / ')}`)
      await expect(p.getByTestId('done').or(p.getByTestId('error')).first()).toBeVisible({ timeout: 5 * 60_000 })
      if (await p.getByTestId('error').isVisible()) throw new Error(`the app says: ${await p.getByTestId('error').textContent()}`)
      await vb.dismiss('Signed')
      log(`  ${await p.getByTestId('done').textContent()}`)
    }
    const tx = await app.executeTx(d, st.safe!, h)
    await record(st, '07', 'execTransaction: the ECDSA owner proposed, the board confirmed, the gas account executed', tx)
    await app.close(d)
  })

  step('08 a delegate call proposed by the ECDSA owner: the board refuses it', async (st, base) => {
    let h = st.hashes.delegate as Hex | undefined
    if (!h) {
      try {
        h = await ecdsaPropose(st, { to: st.ecdsa!, value: 0n, data: '0x12345678', operation: 1, nonce: await nextNonce(st) })
      } catch (e) {
        st.notes.delegateProposal = `the service didn't take it: ${(e as Error).message}`
        log(`  ${st.notes.delegateProposal}`)
        return
      }
      st.hashes.delegate = h
      save(st)
    }
    const { d, vb } = await openBoard(base)
    const p = d.page
    await app.openTx(d, st.safe!, h)
    await p.getByTestId('confirm').click()
    await expect(p.getByTestId('error')).toContainText('delegate calls are refused', { timeout: 120_000 })
    st.notes.delegateRefused = await p.getByTestId('error').textContent()
    await app.screens(d, 'b13-delegate-refused')
    await vb.dismiss('Refused')
    await app.close(d)
  })

  step('09 the remaining screens', async (st, base) => {
    const { d } = await openBoard(base)
    const p = d.page
    await p.goto('/#/')
    await expect(p.getByTestId('owner-state')).toHaveAttribute('data-deployed', 'true', { timeout: 60_000 })
    await app.screens(d, 'b14-home-with-safe')
    await p.goto('/#/board')
    await expect(p.getByTestId('board-status')).toBeVisible({ timeout: 30_000 })
    await app.screens(d, 'b15-board-info')
    await p.goto(`/#/safe/11155111/${st.safe}`)
    await expect(p.getByTestId('tree-state')).toBeVisible({ timeout: 60_000 })
    await app.screens(d, 'b16-safe')
    await app.close(d)
    const o = await chain.owners(st.safe!)
    st.notes.final = { ...o, safeBalance: (await chain.balance(st.safe!)).toString(), gasBalance: (await chain.balance(st.gas!)).toString() }
    log(`  final: ${JSON.stringify(st.notes.final)}`)
  })
})
