// Safe's nested transaction envelope (src/lib/nested.ts): the fields Safe's app sends after an
// approveHash, checked against the approved hash with the core, taken off the call, and proposed
// to Safe's service after the approval is executed. The sample is the call Safe{Wallet} v1.105.0
// sent on Sepolia on 2026-11-16 for a transfer of 0.0001 ETH from a test Safe. No network.

import { type Address, concat, encodeAbiParameters, getAddress, parseAbiParameters, size } from 'viem'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { CODE, RpcFail, approvedOf } from '../src/lib/dapp'
import { type DappTxRecord, type Hex, writeStrict } from '../src/lib/db'
import { listApproved, safeTxHash } from '../src/lib/flows'
import { APPROVE_HASH, NESTED_MAGIC, approveCall, approvedHashSignature, envelopes, splitApprove } from '../src/lib/nested'
import { type SafeTx, safeTx, toService } from '../src/lib/safe'
import { directCore, freshDb } from './helpers'

const CHAIN = 11155111
// the Safe that approves, and the Safe whose transaction it approves (the sample's)
const SAFE = getAddress('0x6c315c5c9aDbFE50217B976a70BA54Cd11EC04EA')
const TEAM = getAddress('0x590F45fc1F05f832De93425d789a95fdd8EfFE3E')
const HASH = '0xedea4d55863dd6cf81e98f36d12cc5d1594a0ddfdd732fd2c6f99aaa6c6cb004' as Hex
const TRANSFER = safeTx({ to: getAddress('0x1fD721fE2c564FfCf6ef60Ac7514FCA1FEa056A2'), value: 10n ** 14n, nonce: 0n })
const SAMPLE = ('0x' +
  'd4d9bdcdedea4d55863dd6cf81e98f36d12cc5d1594a0ddfdd732fd2c6f99aaa6c6cb004fb4e87b00000000000000000' +
  '000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000' +
  '000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000' +
  '000000000000000000000000000000000000000000aa36a7000000000000000000000000590f45fc1f05f832de93425d' +
  '789a95fdd8effe3e00000000000000000000000000000000000000000000000000000000000000000000000000000000' +
  '000000001fd721fe2c564ffcf6ef60ac7514fca1fea056a2000000000000000000000000000000000000000000000000' +
  '00005af3107a400000000000000000000000000000000000000000000000000000000000000001800000000000000000' +
  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' +
  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' +
  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' +
  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' +
  '000000000000000000000000000000000000000000000000') as Hex

const core = directCore()
const hashOf = (chain: number) => (safe: Address, tx: SafeTx) => safeTxHash(core, chain, safe, tx)
const call = (data: Hex, to: Address = TEAM, value = 0n) => ({ to, value, data })

const ENVELOPES = parseAbiParameters(
  '(uint256 chainId, address safe, uint256 nonce, address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver)[]',
)
const envelope = (tx: SafeTx, safe: Address = TEAM, chainId = BigInt(CHAIN)) => ({ chainId, safe, ...tx })
/** approveHash(hash) followed by Safe's payload for these envelopes. */
const withEnvelopes = (hash: Hex, list: ReturnType<typeof envelope>[]): Hex => concat([APPROVE_HASH, hash, NESTED_MAGIC, encodeAbiParameters(ENVELOPES, [list])])

async function refusal(p: Promise<unknown>): Promise<string> {
  try {
    await p
  } catch (e) {
    expect(e).toBeInstanceOf(RpcFail)
    expect((e as RpcFail).code).toBe(CODE.params)
    return (e as RpcFail).message
  }
  throw new Error('not refused')
}

describe('the envelope after approveHash', () => {
  it('splits Safe’s call into the hash and the fields that follow', () => {
    expect(size(SAMPLE)).toBe(552)
    const s = splitApprove(SAMPLE)!
    expect(s.hash).toBe(HASH)
    expect(size(s.rest)).toBe(516)
    expect(envelopes(s.rest)).toEqual([{ chainId: BigInt(CHAIN), safe: TEAM, tx: TRANSFER }])
    expect(splitApprove(approveCall(HASH))).toEqual({ hash: HASH, rest: '0x' })
    expect(splitApprove('0xa9059cbb')).toBeNull()
    expect(splitApprove(`${APPROVE_HASH}00`)).toBeNull()
  })

  it('encodes the way Safe’s app does', () => {
    expect(withEnvelopes(HASH, [envelope(TRANSFER)])).toBe(SAMPLE)
  })

  it('reads nothing from other bytes after the hash', () => {
    expect(envelopes('0x')).toBeNull()
    expect(envelopes('0x00')).toBeNull()
    expect(envelopes(NESTED_MAGIC)).toBeNull()
    expect(envelopes(`${NESTED_MAGIC}00ff`)).toBeNull()
    // an empty list, and an operation that is neither a call nor a delegate call
    expect(envelopes(concat([NESTED_MAGIC, encodeAbiParameters(ENVELOPES, [[]])]))).toBeNull()
    expect(envelopes(concat([NESTED_MAGIC, encodeAbiParameters(ENVELOPES, [[{ ...envelope(TRANSFER), operation: 2 }]])]))).toBeNull()
  })

  it('the approved-hash signature is r = the owner, s = 0, v = 1', () => {
    expect(approvedHashSignature(SAFE)).toBe(`0x${'00'.repeat(12)}${SAFE.slice(2).toLowerCase()}${'00'.repeat(32)}01`)
  })
})

describe('a request’s approveHash with the fields', () => {
  it('the sample’s fields hash to the approved hash: the approval and what it approves', async () => {
    expect(await approvedOf([call(SAMPLE)], CHAIN, SAFE, hashOf(CHAIN))).toEqual({ safe: TEAM, hash: HASH, tx: TRANSFER, plain: approveCall(HASH) })
  })

  it('refuses fields for another chain, for another Safe, or that don’t hash to the approved hash', async () => {
    expect(await refusal(approvedOf([call(SAMPLE)], 1, SAFE, hashOf(1)))).toMatch(/is for chain 11155111, not 1: refused/)
    expect(await refusal(approvedOf([call(SAMPLE, SAFE)], CHAIN, TEAM, hashOf(CHAIN)))).toMatch(/is for the Safe 0x590F.*, not the one called/)
    const more = withEnvelopes(HASH, [envelope({ ...TRANSFER, value: 10n ** 18n })])
    expect(await refusal(approvedOf([call(more)], CHAIN, SAFE, hashOf(CHAIN)))).toMatch(/doesn’t hash to the approved hash: refused/)
    const delegate = withEnvelopes(HASH, [envelope({ ...TRANSFER, operation: 1 })])
    expect(await refusal(approvedOf([call(delegate)], CHAIN, SAFE, hashOf(CHAIN)))).toMatch(/doesn’t hash/)
  })

  it('leaves everything else as the dapp sent it', async () => {
    const none = (calls: ReturnType<typeof call>[]) => approvedOf(calls, CHAIN, SAFE, hashOf(CHAIN))
    // no fields, bytes that aren't Safe's payload, a value, a batch, the Safe itself
    expect(await none([call(approveCall(HASH))])).toBeUndefined()
    expect(await none([call(`${approveCall(HASH)}00`)])).toBeUndefined()
    expect(await none([call(concat([approveCall(HASH), NESTED_MAGIC, '0x1234']))])).toBeUndefined()
    expect(await none([call(SAMPLE, TEAM, 1n)])).toBeUndefined()
    expect(await none([call(SAMPLE), call(SAMPLE)])).toBeUndefined()
    expect(await approvedOf([call(SAMPLE)], CHAIN, TEAM, hashOf(CHAIN))).toBeUndefined()
  })

  it('takes the first envelope: the transaction whose hash is approved', async () => {
    const inner = safeTx({ to: SAFE, value: 5n, nonce: 9n })
    const two = withEnvelopes(HASH, [envelope(TRANSFER), envelope(inner, SAFE)])
    expect((await approvedOf([call(two)], CHAIN, SAFE, hashOf(CHAIN)))?.tx).toEqual(TRANSFER)
  })
})

describe('after the approval is executed', () => {
  const BASE = 'https://api.safe.global/tx-service/sep/api'
  afterEach(() => vi.unstubAllGlobals())

  /** Safe's service: whether it holds the transaction, and what it answers a proposal. */
  function service(holds: boolean, post = 201) {
    const posts: { url: string; body: any }[] = []
    const gets: string[] = []
    vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posts.push({ url, body: JSON.parse(init.body as string) })
        return new Response(post === 201 ? '{}' : JSON.stringify({ nonFieldErrors: ['no'] }), { status: post })
      }
      gets.push(url)
      return holds ? new Response(JSON.stringify({ safeTxHash: HASH }), { status: 200 }) : new Response('{"detail":"Not found."}', { status: 404 })
    })
    return { posts, gets }
  }

  const steps: string[] = []
  const step = (s: string) => void steps.push(s)
  const approval = (data: Hex) => safeTx({ to: TEAM, data, nonce: 3n })

  async function env(kept?: SafeTx) {
    const { db } = await freshDb()
    const tx = approval(approveCall(HASH))
    const hash = await safeTxHash(core, CHAIN, SAFE, tx)
    if (kept) {
      const rec: DappTxRecord = {
        safeTxHash: hash,
        chain: CHAIN,
        safe: SAFE,
        nonce: 3,
        calls: 1,
        method: 'eth_sendTransaction',
        requestId: 1,
        topic: 't',
        dapp: { name: 'Safe{Wallet}', url: 'https://app.safe.global' },
        at: 0,
        answered: true,
        approved: { safe: TEAM, hash: HASH, tx: toService(kept) },
      }
      await writeStrict(db, 'dapp', [rec])
    }
    return { env: { db, core }, tx, hash }
  }

  const proposal = { ...toService(TRANSFER), contractTransactionHash: HASH, sender: SAFE, signature: approvedHashSignature(SAFE), origin: null }

  it('proposes the transaction the service lacks, with the Safe’s approval as the signature', async () => {
    const s = service(false)
    const e = await env(TRANSFER)
    expect(await listApproved(e.env, CHAIN, SAFE, e.hash, e.tx, step)).toMatch(/the app proposed it there with this Safe’s approval/)
    expect(s.gets).toEqual([`${BASE}/v2/multisig-transactions/${HASH}/`])
    expect(s.posts).toEqual([{ url: `${BASE}/v2/safes/${TEAM}/multisig-transactions/`, body: proposal }])
    expect(steps).toContain('Proposing the approved transaction to Safe’s service')
  })

  it('takes the fields from the call when they were left in it', async () => {
    const s = service(false)
    const { db } = await freshDb()
    const tx = approval(SAMPLE)
    expect(await listApproved({ db, core }, CHAIN, SAFE, await safeTxHash(core, CHAIN, SAFE, tx), tx, step)).toMatch(/proposed it there/)
    expect(s.posts.map((p) => p.body)).toEqual([proposal])
  })

  it('does nothing when the service holds it, without the fields, or for another call', async () => {
    let s = service(true)
    let e = await env(TRANSFER)
    expect(await listApproved(e.env, CHAIN, SAFE, e.hash, e.tx, step)).toBeUndefined()
    expect(s.posts).toEqual([])
    s = service(false)
    e = await env()
    expect(await listApproved(e.env, CHAIN, SAFE, e.hash, e.tx, step)).toBeUndefined()
    // kept fields that don't hash to the approved hash are not proposed
    e = await env({ ...TRANSFER, value: 1n })
    expect(await listApproved(e.env, CHAIN, SAFE, e.hash, e.tx, step)).toBeUndefined()
    const other = safeTx({ to: TEAM, value: 1n, nonce: 3n })
    expect(await listApproved(e.env, CHAIN, SAFE, await safeTxHash(core, CHAIN, SAFE, other), other, step)).toBeUndefined()
    expect(s.posts).toEqual([])
  })

  it('says so when the service doesn’t take the proposal', async () => {
    const s = service(false, 500)
    const e = await env(TRANSFER)
    expect(await listApproved(e.env, CHAIN, SAFE, e.hash, e.tx, step)).toMatch(/The approval is on-chain, but Safe’s service didn’t take the approved transaction \(.*HTTP 500/)
    expect(s.posts.length).toBe(1)
  })
})
