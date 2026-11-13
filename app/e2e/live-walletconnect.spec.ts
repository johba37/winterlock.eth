// WalletConnect live on Sepolia: the app as member A's wallet, a dapp on the official SDK in this
// test process, Reown's relay, Safe's hosted Transaction Service, and the Python signer as member P.
// A fresh 2-of-2 Safe of A's and P's owners. The dapp asks; A confirms in the app; P confirms with
// the Python signer; A executes in the app, or P with the Python signer; the dapp gets its answers.
//
// Each step runs once; a finished step is skipped on a re-run (state in E2E_DIR/state-wc.json).
// Spending stops past MAX_SPEND. Needs E2E_DIR and WINTERLOCK_ENV_FILE with ALCHEMY_API_KEY,
// FRESH_EYES_GAS_KEY, SAFE_API_KEY (for the Python signer) and WALLETCONNECT_PROJECT_ID.

import { expect, test } from '@playwright/test'
import { SignClient } from '@walletconnect/sign-client'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Address, type Hex, toHex } from 'viem'
import * as app from './app'
import * as chain from './chain'
import { log, projectId, redact } from './env'
import { chainArgs, signer } from './python'

const MAX_SPEND = 10n ** 16n // 0.01 ETH from the funding account, value moved included
const GAS_FUNDING = 10n ** 15n
const SAFE_FUNDING = 10n ** 14n
const CAIP = 'eip155:11155111'

interface State {
  done: string[]
  startBalance?: string
  aOwner?: Address
  aGas?: Address
  pOwner?: Address
  safe?: Address
  txs: { step: string; what: string; hash: string; gasUsed?: string }[]
  notes: Record<string, unknown>
}

const file = () => join(app.dir(), 'state-wc.json')
const load = (): State => (existsSync(file()) ? JSON.parse(readFileSync(file(), 'utf8')) : { done: [], txs: [], notes: {} })
const save = (st: State) => writeFileSync(file(), JSON.stringify(st, null, 1))
const pyHome = () => join(app.dir(), 'python-member-wc')

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

async function refusal(p: Promise<unknown>): Promise<{ code: number; message: string }> {
  try {
    await p
  } catch (e: any) {
    return { code: e?.code, message: String(e?.message ?? e) }
  }
  throw new Error('the request was answered, not refused')
}

const until = async <T>(f: () => Promise<T | undefined>, ms: number, every = 5000): Promise<T> => {
  const end = Date.now() + ms
  for (;;) {
    const v = await f()
    if (v !== undefined) return v
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, every))
  }
}

test.describe.serial('WalletConnect live on Sepolia', () => {
  test.skip(!process.env.E2E_DIR || !process.env.WINTERLOCK_ENV_FILE || !projectId(), 'needs E2E_DIR and WINTERLOCK_ENV_FILE with WALLETCONNECT_PROJECT_ID')

  step('00 setup: funding account, member P (Python)', async (st) => {
    const b = await chain.balance(chain.funder().address)
    log(`  funding account ${chain.funder().address}: ${b} wei`)
    if (b < GAS_FUNDING + SAFE_FUNDING + 10n ** 15n) throw new Error('the funding account holds too little for this run')
    st.startBalance = b.toString()
    if (!existsSync(join(pyHome(), 'keylog.jsonl'))) signer(pyHome(), ['init', '--insecure-plaintext-seed'])
    st.pOwner = signer(pyHome(), ['address']).out.match(/owner address\s+(0x[0-9a-fA-F]{40})/)![1] as Address
    save(st)
  })

  step('01 member A in the app: create, fund, certificate', async (st, base) => {
    const a = await app.open('wc-a', base)
    if ((await app.idb(a, 'device')).length === 0) {
      const { owner } = await app.createMember(a)
      st.aOwner = owner as Address
    } else st.aOwner = (await app.idb(a, 'device'))[0].owner
    await app.setRpc(a)
    st.aGas = await app.gasAddress(a)
    save(st)
    const r = await chain.fund(st.aGas, GAS_FUNDING)
    st.txs.push({ step: '01', what: 'fund member A’s gas account', hash: r.hash, gasUsed: r.gasUsed.toString() })
    const lines = await app.sendCertificate(a)
    log(`  ${lines.join(' | ')}`)
    for (const h of lines.flatMap((l) => l.match(/0x[0-9a-fA-F]{64}/g) ?? [])) await record(st, '01', 'A’s owner and certificate', h)
    await app.close(a)
  })

  step('02 a fresh 2-of-2 Safe of A and P; both enrol', async (st, base) => {
    const r = await chain.createSafeOf([st.aOwner!, st.pOwner!], 2n, BigInt(Date.now()))
    st.safe = r.safe
    st.txs.push({ step: '02', what: 'create the Safe (v1.4.1 SafeL2), owners A and P, 2 of 2', hash: r.hash, gasUsed: r.gasUsed.toString() })
    save(st)
    const f = await chain.fund(r.safe, SAFE_FUNDING)
    st.txs.push({ step: '02', what: 'fund the Safe', hash: f.hash, gasUsed: f.gasUsed.toString() })
    log(`  Safe ${r.safe}`)
    const out = signer(pyHome(), ['enroll', '--safe', st.safe!, '--height', '6', ...chainArgs()]).out
    await record(st, '02', 'deployAndEnroll, member P (Python), height 6', out.match(/tx (0x[0-9a-fA-F]{64})/)![1])
    const a = await app.open('wc-a', base)
    await app.join(a, st.safe!)
    await app.enrol(a)
    const [tree] = await app.idb(a, 'trees')
    await record(st, '02', 'enroll, A (device 1), height 10', tree.enrolTx)
    await app.close(a)
    const ix = await chain.waitIndexed(st.safe!, [st.aOwner!, st.pOwner!])
    log(`  Safe's service indexed the Safe after ${ix.polls} poll(s)`)
  })

  step('03 a dapp pairs, a transfer and a batch, a message refused, the dapp disconnects', async (st, base) => {
    const safe = st.safe!
    const funder = chain.funder().address
    const a = await app.open('wc-a', base)
    const dapp = await SignClient.init({
      projectId: projectId()!,
      telemetryEnabled: false,
      logger: 'silent',
      storageOptions: { database: ':memory:' },
      metadata: { name: 'Winterlock live dapp', description: 'a scripted dapp', url: 'https://dapp.example.org', icons: [] },
    })
    const p = a.page
    const t = (id: string) => p.getByTestId(id)
    try {
      // pairing
      let t0 = Date.now()
      const { uri, approval } = await dapp.connect({
        optionalNamespaces: { eip155: { chains: [CAIP], methods: ['eth_sendTransaction', 'personal_sign', 'wallet_sendCalls', 'wallet_getCallsStatus', 'wallet_getCapabilities', 'eth_getTransactionReceipt', 'eth_getTransactionByHash', 'eth_chainId'], events: ['chainChanged', 'accountsChanged'] } },
      })
      await p.goto(`/#/safe/11155111/${safe}/dapps`)
      await t('wc-uri').fill(uri!)
      await app.screens(a, 'wc-01-paste')
      await t('wc-pair').click()
      await expect(t('wc-proposal')).toBeVisible({ timeout: 60_000 })
      await app.screens(a, 'wc-02-proposal')
      await t('wc-approve').click()
      const session = await approval()
      st.notes.pairingMs = Date.now() - t0
      log(`  paired in ${st.notes.pairingMs} ms; accounts ${session.namespaces.eip155.accounts.join(', ')}`)
      expect(session.namespaces.eip155.accounts).toEqual([`${CAIP}:${safe}`])
      const ask = <T = any>(method: string, params: unknown[]) => {
        const q = dapp.request<T>({ topic: session.topic, chainId: CAIP, request: { method, params } })
        q.catch(() => {})
        return q
      }

      // a transfer: A proposes in the app, P confirms (Python), A executes in the app
      t0 = Date.now()
      const pending = ask<Hex>('eth_sendTransaction', [{ from: safe, to: funder, value: toHex(10n ** 13n) }])
      const card = t('wc-request').first()
      await expect(card).toBeVisible({ timeout: 60_000 })
      st.notes.requestShownMs = Date.now() - t0
      await app.screens(a, 'wc-03-request')
      t0 = Date.now()
      await card.getByTestId('wc-confirm').click()
      const hash = await pending
      st.notes.confirmToAnswerMs = Date.now() - t0
      log(`  eth_sendTransaction answered ${st.notes.confirmToAnswerMs} ms after the confirm: ${hash}`)
      await expect(t('wc-done')).toHaveCount(1, { timeout: 60_000 })
      await app.screens(a, 'wc-04-proposed')
      expect(await ask('eth_getTransactionReceipt', [hash])).toBeNull()
      signer(pyHome(), ['confirm', hash, ...chainArgs()])
      const tx = await app.executeTx(a, safe, hash)
      await record(st, '03', 'execTransaction: the dapp’s transfer, A proposed in the app, P confirmed, A executed', tx)
      const receipt = await ask('eth_getTransactionReceipt', [hash])
      expect(receipt).toMatchObject({ transactionHash: tx, status: '0x1' })
      log('  the dapp got the execution’s receipt for the SafeTx hash')

      // a batch: A proposes in the app, P confirms and executes (Python); the status through Safe's service
      await p.goto(`/#/safe/11155111/${safe}/dapps`)
      const calls = [
        { to: funder, value: toHex(10n ** 13n) },
        { to: funder, value: toHex(2n * 10n ** 13n) },
      ]
      expect(await ask('wallet_getCapabilities', [safe, ['0xaa36a7']])).toMatchObject({ '0xaa36a7': { atomic: { status: 'supported' } } })
      const pb = ask<{ id: Hex }>('wallet_sendCalls', [{ version: '2.0.0', from: safe, chainId: '0xaa36a7', atomicRequired: true, calls }])
      await expect(t('wc-request').first()).toBeVisible({ timeout: 60_000 })
      await expect(t('wc-request').first().getByTestId('batch-call')).toHaveCount(2)
      await app.screens(a, 'wc-05-batch')
      await t('wc-request').first().getByTestId('wc-confirm').click()
      const { id } = await pb
      log(`  wallet_sendCalls answered: id ${id}`)
      expect(await ask('wallet_getCallsStatus', [id])).toMatchObject({ status: 100 })
      signer(pyHome(), ['confirm', id, ...chainArgs()])
      const ex = signer(pyHome(), ['execute', id, ...chainArgs()]).out
      const exTx = ex.match(/Executed nonce \d+: .* tx (0x[0-9a-fA-F]{64})/)![1] as Hex
      await record(st, '03', 'execTransaction: the dapp’s batch (MultiSendCallOnly), A proposed in the app, P confirmed and executed', exTx)
      t0 = Date.now()
      const status = await until(async () => {
        const s = await ask<any>('wallet_getCallsStatus', [id])
        return s.status === 100 ? undefined : s
      }, 300_000)
      st.notes.statusAfterExecutionMs = Date.now() - t0
      log(`  wallet_getCallsStatus ${status.status} ${st.notes.statusAfterExecutionMs} ms after the execution was mined (through Safe's service)`)
      expect(status).toMatchObject({ status: 200, receipts: [{ transactionHash: exTx, status: '0x1' }] })

      // a message, refused
      expect(await refusal(ask('personal_sign', [toHex('Sign in to dapp.example.org'), safe]))).toEqual({ code: 4001, message: "messages aren't supported yet" })
      await p.goto(`/#/safe/11155111/${safe}/dapps`)
      await expect(t('wc-log')).toContainText('Refused personal_sign')
      await app.screens(a, 'wc-06-after')
      await dapp.disconnect({ topic: session.topic, reason: { code: 6000, message: 'User disconnected.' } })
      await expect(t('wc-session')).toHaveCount(0, { timeout: 60_000 })
    } finally {
      await (dapp.core.relayer as any).transportClose?.().catch(() => {})
      await app.close(a)
    }
  })
})
