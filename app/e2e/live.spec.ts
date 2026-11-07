// The app live on Sepolia, end to end, with Safe's hosted Transaction Service and no API key in
// the app. Several Chromium profiles play separate devices:
//   a1      member A's first device (create)
//   a2      member A's second device (pair, from the phrase)
//   a1copy  a copy of a1's profile, as a restored or synced browser
// Member P is the Python signer (the reference). A fresh test Safe, made by script, starts with an
// ECDSA owner alone; the script adds A's and P's owners with addOwnerWithThreshold, threshold 2.
//
// Each step runs once; a finished step is skipped on a re-run (state in E2E_DIR/state.json).
// Spending stops past MAX_SPEND.

import { expect, test } from '@playwright/test'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Address, Hex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import * as app from './app'
import * as chain from './chain'
import { log, redact } from './env'
import { chainArgs, signer } from './python'

const MAX_SPEND = 25n * 10n ** 15n // 0.025 ETH from the funding account, value moved included
const GAS_FUNDING = 2n * 10n ** 15n // member A's gas account
const SAFE_FUNDING = 5n * 10n ** 14n
const TRANSFER = '0.00001'

interface Tx {
  step: string
  what: string
  hash: string
  gasUsed?: string
}

interface State {
  done: string[]
  startBalance?: string
  ecdsaKey?: Hex
  ecdsa?: Address
  words?: string[]
  aOwner?: Address
  aGas?: Address
  pOwner?: Address
  safe?: Address
  hashes: Record<string, string>
  txs: Tx[]
  notes: Record<string, unknown>
}

const file = () => join(app.dir(), 'state.json')
function load(): State {
  return existsSync(file()) ? JSON.parse(readFileSync(file(), 'utf8')) : { done: [], hashes: {}, txs: [], notes: {} }
}
function save(st: State) {
  writeFileSync(file(), JSON.stringify(st, null, 1))
}
const pyHome = () => join(app.dir(), 'python-member')

async function record(st: State, step: string, what: string, hash: string) {
  const r = await chain.receipt(hash as Hex)
  st.txs.push({ step, what, hash, gasUsed: r.gasUsed.toString() })
  log(`  ${what}: ${hash} (${r.gasUsed} gas)`)
}

function hashesIn(lines: string[]): string[] {
  return lines.flatMap((l) => l.match(/0x[0-9a-fA-F]{64}/g) ?? [])
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
      // viem's errors name the RPC URL, which holds the key: rethrow redacted, without the cause
      throw new Error(redact(String((e as Error)?.stack ?? e)))
    }
    st.done.push(name)
    st.notes.spentWei = (await spent(st)).toString()
    save(st)
  })
}

test.describe.serial('live on Sepolia', () => {
  test.skip(!process.env.E2E_DIR || !process.env.WINTERLOCK_ENV_FILE, 'needs E2E_DIR and WINTERLOCK_ENV_FILE')

  step('00 setup', async (st) => {
    const b = await chain.balance(chain.funder().address)
    log(`  funding account ${chain.funder().address}: ${b} wei`)
    if (b < 2n * MAX_SPEND / 3n) throw new Error('the funding account holds too little for this run')
    st.startBalance = b.toString()
    st.ecdsaKey ??= generatePrivateKey() // a throwaway testnet key, kept in the scratch directory only
    st.ecdsa = privateKeyToAccount(st.ecdsaKey).address
    if (!existsSync(join(pyHome(), 'keylog.jsonl'))) signer(pyHome(), ['init', '--insecure-plaintext-seed'])
    const out = signer(pyHome(), ['address']).out
    st.pOwner = out.match(/owner address\s+(0x[0-9a-fA-F]{40})/)![1] as Address
    save(st)
  })

  step('01 create member A on a1', async (st, base) => {
    const a1 = await app.open('a1', base)
    const { words, owner } = await app.createMember(a1)
    st.words = words // a throwaway testnet phrase, kept in the scratch directory only
    st.aOwner = owner as Address
    save(st)
    await app.screens(a1, '07-home-new')
    await app.setRpc(a1)
    st.aGas = await app.gasAddress(a1)
    await app.screens(a1, '24-settings')
    await app.close(a1)
  })

  step('02 fund A’s gas account', async (st) => {
    const r = await chain.fund(st.aGas!, GAS_FUNDING)
    st.txs.push({ step: '02', what: 'fund member A’s gas account', hash: r.hash, gasUsed: r.gasUsed.toString() })
  })

  step('03 a1 sends its certificate', async (st, base) => {
    const a1 = await app.open('a1', base)
    const lines = await app.sendCertificate(a1)
    log(`  ${lines.join(' | ')}`)
    const [deploy, certify] = hashesIn(lines)
    await record(st, '03', 'owner created by the factory’s deploy (a1)', deploy)
    await record(st, '03', 'certifyDevice, device 1, generation 1 (a1)', certify)
    await app.close(a1)
  })

  step('04 pair a2 from the phrase', async (st, base) => {
    const a2 = await app.open('a2', base)
    await app.setRpc(a2)
    await a2.page.goto('/#/')
    if ((await app.idb(a2, 'device')).length === 0) {
      const lines = await app.pair(a2, st.words!)
      log(`  ${lines.join(' | ')}`)
      expect(lines.join(' ')).toMatch(/device 2 certified at generation 1/)
      await a2.page.getByTestId('done-home').click()
    } else log('  a2 was paired before (its run stopped after the certificate was sent)')
    await expect(a2.page.getByTestId('chain-11155111').getByTestId('device-state')).toHaveAttribute('data-kind', 'active', { timeout: 60_000 })
    const [cert] = await app.idb(a2, 'certs')
    expect(cert).toMatchObject({ device: 2, generation: 1, status: 'submitted' })
    await record(st, '04', 'certifyDevice, device 2, generation 1 (a2)', cert.tx)
    expect(await app.gasAddress(a2)).toBe(st.aGas)
    await app.close(a2)
  })

  step('05 a fresh Safe, owned by an ECDSA test key', async (st) => {
    const r = await chain.createSafe(st.ecdsa!, BigInt(Date.now()))
    st.safe = r.safe
    st.txs.push({ step: '05', what: 'create the Safe (v1.4.1 SafeL2), owner: ECDSA test key, 1 of 1', hash: r.hash, gasUsed: r.gasUsed.toString() })
    save(st)
    const f = await chain.fund(r.safe, SAFE_FUNDING)
    st.txs.push({ step: '05', what: 'fund the Safe', hash: f.hash, gasUsed: f.gasUsed.toString() })
    log(`  Safe ${r.safe}`)
  })

  step('06 a1 joins: not an owner yet; the team adds A and P; a1 enrols', async (st, base) => {
    const a1 = await app.open('a1', base)
    await app.join(a1, st.safe!)
    await expect(a1.page.getByTestId('not-owner')).toBeVisible()
    await app.screens(a1, '12-safe-not-owner')
    let r = await chain.addOwner(st.safe!, st.ecdsaKey!, st.aOwner!, 1n)
    st.txs.push({ step: '06', what: 'addOwnerWithThreshold(A, 1), signed by the ECDSA owner', hash: r.hash, gasUsed: r.gasUsed.toString() })
    r = await chain.addOwner(st.safe!, st.ecdsaKey!, st.pOwner!, 2n)
    st.txs.push({ step: '06', what: 'addOwnerWithThreshold(P, 2), signed by the ECDSA owner', hash: r.hash, gasUsed: r.gasUsed.toString() })
    const o = await chain.owners(st.safe!)
    log(`  owners ${o.owners.join(', ')}, threshold ${o.threshold}, nonce ${o.nonce}`)
    save(st)
    await a1.page.getByTestId('check-again').click()
    await expect(a1.page.getByTestId('not-owner')).toBeHidden({ timeout: 60_000 })
    await expect(a1.page.getByTestId('enrol')).toBeVisible()
    await app.screens(a1, '12b-safe-enrol')
    const text = await app.enrol(a1)
    log(`  ${text}`)
    const tree = await app.idb(a1, 'trees')
    await record(st, '06', `enroll, a1 (device 1), height ${tree[0].height}, from nonce ${tree[0].start}`, tree[0].enrolTx)
    await app.close(a1)
  })

  step('07 P enrols (Python); a2 joins and enrols', async (st, base) => {
    const out = signer(pyHome(), ['enroll', '--safe', st.safe!, '--height', '6', ...chainArgs()]).out
    await record(st, '07', 'deployAndEnroll, member P (Python), height 6', out.match(/tx (0x[0-9a-fA-F]{64})/)![1])
    const a2 = await app.open('a2', base)
    await app.join(a2, st.safe!)
    await app.enrol(a2)
    const [tree] = await app.idb(a2, 'trees')
    await record(st, '07', 'enroll, a2 (device 2), height 10', tree.enrolTx)
    await app.close(a2)
  })

  step('08 Safe’s service indexes the Safe and its owners', async (st) => {
    const r = await chain.waitIndexed(st.safe!, [st.aOwner!, st.pOwner!])
    st.notes.indexedAfterPolls = r.polls
    log(`  indexed after ${r.polls} poll(s): threshold ${r.info.threshold}, nonce ${r.info.nonce}`)
  })

  step('09 a1 proposes an ETH transfer, P confirms, a1 executes', async (st, base) => {
    const a1 = await app.open('a1', base)
    const h = await app.proposeEth(a1, st.safe!, chain.funder().address, TRANSFER)
    st.hashes.transfer1 = h
    save(st)
    log(`  proposed ${h} (no API key in the app)`)
    signer(pyHome(), ['confirm', h, ...chainArgs()])
    const tx = await app.executeTx(a1, st.safe!, h)
    await record(st, '09', 'execTransaction: a1 proposed, P confirmed, a1 executed', tx)
    await app.close(a1)
  })

  step('10 P proposes, a2 confirms and executes', async (st, base) => {
    let h = st.hashes.transfer2
    if (!h) {
      const out = signer(pyHome(), ['propose', '--safe', st.safe!, '--to', chain.funder().address, '--value', TRANSFER, ...chainArgs()]).out
      h = out.match(/Proposed (0x[0-9a-fA-F]{64})/)![1]
      st.hashes.transfer2 = h
      save(st)
    }
    const a2 = await app.open('a2', base)
    await a2.page.goto(`/#/safe/11155111/${st.safe}`)
    await expect(a2.page.getByTestId('queue-item').first()).toBeVisible({ timeout: 60_000 })
    await app.screens(a2, '13b-safe-queue')
    log(`  ${await app.confirmTx(a2, st.safe!, h)}`)
    const tx = await app.executeTx(a2, st.safe!, h)
    await record(st, '10', 'execTransaction: P proposed, a2 confirmed and executed', tx)
    await app.close(a2)
  })

  step('11 revoke a2 while its confirmation is pending; a1 confirms again and executes', async (st, base) => {
    let h = st.hashes.pending as Hex | undefined
    if (!h) {
      const out = signer(pyHome(), ['propose', '--safe', st.safe!, '--to', chain.funder().address, '--value', TRANSFER, ...chainArgs()]).out
      h = out.match(/Proposed (0x[0-9a-fA-F]{64})/)![1] as Hex
      st.hashes.pending = h
      save(st)
    }
    const a2 = await app.open('a2', base)
    log(`  a2: ${await app.confirmTx(a2, st.safe!, h)}`)
    await app.close(a2)
    // a2's confirmation as the service holds it (a moment after it was posted)
    let mine: any
    for (let i = 0; i < 10 && !mine; i++) {
      const r = await fetch(`https://api.safe.global/tx-service/sep/api/v2/multisig-transactions/${h}/`)
      const svc = r.status === 200 ? await r.json() : {}
      mine = (svc.confirmations ?? []).find((c: any) => c.owner.toLowerCase() === st.aOwner!.toLowerCase())
      if (!mine) await new Promise((res) => setTimeout(res, 3000))
    }
    const data = ('0x' + mine.signature.slice(2 + 2 * 97)) as Hex
    const before = await chain.ownerAccepts(st.aOwner!, h, data)
    const a1 = await app.open('a1', base)
    const lines = await app.revoke(a1, 2, st.words!)
    log(`  ${lines.join(' | ')}`)
    await record(st, '11', 'revokeDevice, device 2, generation 1 (from a1, with the phrase)', hashesIn(lines)[0])
    const after = await chain.ownerAccepts(st.aOwner!, h, data)
    st.notes.a2SignatureBeforeRevoke = before
    st.notes.a2SignatureAfterRevoke = after
    log(`  isValidSignature of a2's confirmation by eth_call: before ${before}, after ${after}`)
    expect(before).toBe('0x1626ba7e')
    expect(after).not.toBe('0x1626ba7e')
    // the app on a2 refuses to sign
    const a2b = await app.open('a2', base)
    await expect(a2b.page.getByTestId('chain-11155111').getByTestId('device-state')).toHaveAttribute('data-kind', 'revoked', { timeout: 60_000 })
    await app.screens(a2b, '23-home-revoked')
    const refused = await app.confirmRefused(a2b, st.safe!, h)
    st.notes.a2Refused = refused
    log(`  a2 refuses: ${refused}`)
    expect(refused).toMatch(/REVOKED/)
    await app.close(a2b)
    // a1 confirms again: the service keeps a2's stale confirmation, a1 keeps its own and executes
    await a1.page.goto(`/#/safe/11155111/${st.safe}/tx/${h}`)
    await a1.page.getByTestId('sig-count').waitFor({ timeout: 120_000 })
    await app.screens(a1, '20-tx-stale-confirmation')
    const note = await app.confirmTx(a1, st.safe!, h)
    st.notes.a1Reconfirm = note
    log(`  a1: ${note}`)
    const tx = await app.executeTx(a1, st.safe!, h)
    await record(st, '11', 'execTransaction: P and a1 (a2’s confirmation revoked)', tx)
    await app.close(a1)
  })

  step('12 a copied browser refuses once the original has signed again', async (st, base) => {
    app.copyProfile('a1', 'a1copy')
    const a1 = await app.open('a1', base)
    const h = await app.proposeEth(a1, st.safe!, chain.funder().address, TRANSFER)
    st.hashes.afterCopy = h
    save(st)
    await app.close(a1)
    const copy = await app.open('a1copy', base)
    await copy.page.goto(`/#/safe/11155111/${st.safe}/send`)
    await copy.page.getByTestId('to-input').fill(chain.funder().address)
    await copy.page.getByTestId('amount-input').fill(TRANSFER)
    await copy.page.getByTestId('review').click()
    await copy.page.getByTestId('sign-propose').click()
    await expect(copy.page.getByTestId('error')).toBeVisible({ timeout: 5 * 60_000 })
    const msg = (await copy.page.getByTestId('error').textContent()) ?? ''
    st.notes.copyRefused = msg
    log(`  the copy refuses: ${msg}`)
    expect(msg).toMatch(/out of date/)
    await app.screens(copy, '25-copy-refused')
    await app.close(copy)
    // and the original carries on
    signer(pyHome(), ['confirm', h, ...chainArgs()])
    const a1b = await app.open('a1', base)
    const tx = await app.executeTx(a1b, st.safe!, h)
    await record(st, '12', 'execTransaction: a1 (the original) proposed after the copy, P confirmed', tx)
    await app.close(a1b)
  })

  step('13 the remaining screens', async (st, base) => {
    const a1 = await app.open('a1', base)
    await a1.page.goto('/#/devices')
    await expect(a1.page.getByTestId('device-row-2')).toHaveAttribute('data-active', 'false', { timeout: 60_000 })
    await app.screens(a1, '26-devices')
    await a1.page.goto('/#/')
    await expect(a1.page.getByTestId('safe-link')).toBeVisible()
    await app.screens(a1, '27-home-with-safe')
    await a1.page.goto(`/#/safe/11155111/${st.safe}`)
    await expect(a1.page.getByTestId('tree-state')).toBeVisible({ timeout: 60_000 })
    await app.screens(a1, '28-safe-done')
    await a1.page.goto('/#/install')
    await app.screens(a1, '29-install')
    await app.close(a1)
    const o = await chain.owners(st.safe!)
    st.notes.final = { ...o, safeBalance: (await chain.balance(st.safe!)).toString(), aGasBalance: (await chain.balance(st.aGas!)).toString() }
    log(`  final: ${JSON.stringify(st.notes.final)}`)
  })

  step('14 the revoked a2 forgets its key and pairs again: device 2, generation 2', async (st, base) => {
    const a2 = await app.open('a2', base)
    await a2.page.goto('/#/devices')
    await a2.page.getByTestId('forget').click()
    await app.screens(a2, '30-forget')
    await a2.page.getByTestId('forget-confirm').click()
    await a2.page.getByTestId('welcome').waitFor()
    expect(await app.idb(a2, 'uses')).toHaveLength(0)
    const lines = await app.pair(a2, st.words!)
    log(`  ${lines.join(' | ')}`)
    expect(lines.join(' ')).toMatch(/device 2 certified at generation 2/)
    await record(st, '14', 'certifyDevice, device 2, generation 2 (a2 paired again after its revocation)', hashesIn(lines)[0])
    await a2.page.getByTestId('done-home').click()
    await expect(a2.page.getByTestId('chain-11155111').getByTestId('device-state')).toHaveAttribute('data-kind', 'active', { timeout: 60_000 })
    await app.close(a2)
  })
})
