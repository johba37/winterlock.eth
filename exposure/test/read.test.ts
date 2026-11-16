// The whole check on a fake chain and a fake service: every owner class, every verdict, nesting,
// cycles, the caps and the service's failures.

import { readFileSync } from 'node:fs'
import { type Address, type Hex, encodeErrorResult, pad, parseAbi } from 'viem'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PASSKEY_FACTORIES } from '../src/lib/known'
import { allLimits } from '../src/lib/model'
import { CheckError, type CheckOptions, checkSafe } from '../src/lib/read'
import type { OwnerFacts, SafeReport } from '../src/lib/types'
import { FakeChain, FakeService, Revert, SERVICE_URL, SOME_CODE, addr } from './fake'

const vectors = JSON.parse(readFileSync(new URL('../../core/tests/vectors/owner.json', import.meta.url), 'utf8'))
const KEYS: Hex[] = (vectors.addresses as { key: Hex }[]).map((a) => a.key)

let chain: FakeChain
let service: FakeService
const SAFE = addr('safe')

beforeEach(() => {
  chain = new FakeChain()
  service = new FakeService()
})

function run(address: Address = SAFE, o: Partial<CheckOptions> = {}): Promise<SafeReport> {
  return checkSafe(address, {
    client: chain.client(),
    chainId: chain.chainId,
    service: { url: SERVICE_URL, fetch: service.fetch, interval: 0 },
    ...o,
  })
}

const kinds = (r: SafeReport) => r.owners.map((o) => o.facts.kind)
const classes = (r: SafeReport) => r.owners.map((o) => o.class)
const facts = <K extends OwnerFacts['kind']>(r: SafeReport, i: number, kind: K) => {
  const f = r.owners[i].facts
  if (f.kind !== kind) throw new Error(`owner ${i} is ${f.kind}, not ${kind}`)
  return f as Extract<OwnerFacts, { kind: K }>
}

describe('owners and verdicts', () => {
  it('2 of 2 Winterlock owners: protected, without asking the service', async () => {
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0]), chain.winterlock(KEYS[1])], threshold: 2 })
    const r = await run()
    expect(kinds(r)).toEqual(['winterlock', 'winterlock'])
    expect(facts(r, 0, 'winterlock').memberKey).toBe(KEYS[0].toLowerCase())
    expect(r.verdict.kind).toBe('protected')
    expect(r.official).toEqual({ proxy: true, singleton: true })
    expect(r.version).toBe('1.4.1')
    expect(r.l2).toBe(true)
    expect(r.service).toBeNull()
    expect(service.urls).toEqual([])
  })

  it('Winterlock owners v1: hash-based too, with their version', async () => {
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0], 1), chain.winterlock(KEYS[1], 1), chain.key(addr('alice'), 2)], threshold: 2 })
    const r = await run()
    expect(r.owners.map((o) => [o.facts.kind, o.facts.kind === 'winterlock' ? o.facts.version : null, o.class])).toEqual([
      ['winterlock', 1, 'hash-based'],
      ['winterlock', 1, 'hash-based'],
      ['key', null, 'exposed'],
    ])
    expect(r.verdict.kind).toBe('protected')
  })

  it("a key that sent transactions: exposed, and the service isn't needed", async () => {
    chain.safe(SAFE, { owners: [chain.key(addr('alice'), 5), chain.winterlock(KEYS[0])], threshold: 1 })
    const r = await run()
    expect(classes(r)).toEqual(['exposed', 'hash-based'])
    expect(r.verdict.kind).toBe('exposed')
    expect(service.urls).toEqual([])
  })

  it('a key that only signed at the service: exposed, with the signature as evidence', async () => {
    const alice = chain.key(addr('alice'))
    chain.safe(SAFE, { owners: [alice, chain.winterlock(KEYS[0])], threshold: 1 })
    service.add(SAFE, {
      transactions: [
        { safeTxHash: pad('0x1'), nonce: 0, isExecuted: true, confirmations: [{ owner: chain.winterlock(KEYS[0]), signatureType: 'CONTRACT_SIGNATURE' }] },
        { safeTxHash: pad('0x2'), nonce: 1, isExecuted: false, confirmations: [{ owner: alice, signatureType: 'EOA' }] },
      ],
    })
    const r = await run()
    const f = facts(r, 0, 'key')
    expect(f.signatures).toEqual({ byType: { EOA: 1 }, example: { source: 'transaction', signatureType: 'EOA', hash: pad('0x2'), nonce: 1, executed: false } })
    expect(r.verdict.kind).toBe('exposed')
    expect(r.service).toMatchObject({ transactions: { read: 2, total: 2 }, messages: { read: 0, total: 0 }, requests: 3 })
  })

  it('a message signature counts too', async () => {
    const alice = chain.key(addr('alice'))
    chain.safe(SAFE, { owners: [alice], threshold: 1 })
    service.add(SAFE, { messages: [{ messageHash: pad('0x3'), confirmations: [{ owner: alice, signatureType: 'ETH_SIGN' }] }] })
    const r = await run()
    expect(facts(r, 0, 'key').signatures?.example?.source).toBe('message')
    expect(r.verdict.kind).toBe('exposed')
  })

  it('keys with no signature found: not known to be exposed, and the Safe is exposed as owners sign', async () => {
    chain.safe(SAFE, { owners: [chain.key(addr('a')), chain.key(addr('b')), chain.winterlock(KEYS[0])], threshold: 2 })
    service.add(SAFE, {})
    const r = await run()
    expect(classes(r)).toEqual(['not-known', 'not-known', 'hash-based'])
    expect(facts(r, 0, 'key').signatures).toEqual({ byType: {} })
    expect(r.verdict.kind).toBe('exposed-as-owners-sign')
    expect(r.changes[0]).toEqual({ type: 'more-exposed', exposed: 0, more: 2 })
  })

  it('an EIP-7702 delegated key is still an ECDSA key: exposed', async () => {
    const k = chain.set(addr('delegated'), { code: `0xef0100${addr('delegate').slice(2)}` as Hex, nonce: 1 })
    chain.safe(SAFE, { owners: [k], threshold: 1 })
    const r = await run()
    expect(facts(r, 0, 'delegated-key').delegate).toBe(addr('delegate'))
    expect(r.verdict.kind).toBe('exposed')
  })

  it("a passkey signer: exposed; look-alike code the factory doesn't vouch for: unknown", async () => {
    const pk = chain.passkey(addr('passkey'), 7n, 8n)
    const fake = chain.set(addr('lookalike'), { ...chain.get(pk) })
    chain.safe(SAFE, { owners: [pk, fake, chain.winterlock(KEYS[0])], threshold: 2 })
    const r = await run()
    expect(facts(r, 0, 'passkey')).toEqual({ kind: 'passkey', factoryVersion: PASSKEY_FACTORIES[1].version, x: 7n, y: 8n })
    expect(kinds(r)).toEqual(['passkey', 'contract', 'winterlock'])
    expect(classes(r)).toEqual(['exposed', 'unknown', 'hash-based'])
    expect(r.verdict).toMatchObject({ kind: 'cannot-tell', reasons: ['unknown-owners'] })
  })

  it('the shared passkey signer: exposed when set up for this Safe, unknown when not', async () => {
    const shared = chain.sharedSigner([SAFE])
    chain.safe(SAFE, { owners: [shared], threshold: 1 })
    expect((await run()).owners[0]).toMatchObject({ class: 'exposed', facts: { kind: 'passkey-shared', configured: true } })
    const other = addr('other safe')
    chain.safe(other, { owners: [shared, chain.winterlock(KEYS[0])], threshold: 1 })
    const r = await run(other)
    expect(r.owners[0]).toMatchObject({ class: 'unknown', facts: { kind: 'passkey-shared', configured: false } })
    expect(r.verdict.kind).toBe('cannot-tell')
  })

  it("an unknown contract: can't tell when it could make up the threshold", async () => {
    chain.safe(SAFE, { owners: [chain.set(addr('contract'), { code: SOME_CODE }), chain.key(addr('a'), 1)], threshold: 2 })
    const r = await run()
    expect(facts(r, 0, 'contract').size).toBe((SOME_CODE.length - 2) / 2)
    expect(r.verdict).toMatchObject({ kind: 'cannot-tell', reasons: ['unknown-owners'] })
    expect(r.changes).toEqual([{ type: 'replace-owners', count: 1, of: 2 }])
  })

  it("an owner the endpoint doesn't answer for: unknown", async () => {
    const k = chain.key(addr('flaky'), 1)
    chain.failing.add(k.toLowerCase())
    chain.safe(SAFE, { owners: [k, chain.winterlock(KEYS[0])], threshold: 1 })
    const r = await run()
    expect(r.owners[0]).toMatchObject({ class: 'unknown', facts: { kind: 'unread' } })
  })
})

describe('modules, guard, fallback handler, singletons', () => {
  it("a module: can't tell, and it's listed", async () => {
    const m = addr('module')
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, modules: [m] })
    const r = await run()
    expect(r.modules).toEqual([m])
    expect(r.verdict).toMatchObject({ kind: 'cannot-tell', reasons: ['modules'], modules: 1 })
    expect(r.changes).toEqual([{ type: 'modules', count: 1 }])
  })

  it('exposed stands with modules', async () => {
    chain.safe(SAFE, { owners: [chain.key(addr('a'), 3)], threshold: 1, modules: [addr('m')] })
    expect((await run()).verdict).toMatchObject({ kind: 'exposed', modules: 1 })
  })

  it('more modules than one page: the limit is reported', async () => {
    const modules = Array.from({ length: 12 }, (_, i) => addr(`m${i}`))
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, modules })
    const r = await run()
    expect(r.modules).toHaveLength(10)
    expect(r.modulesComplete).toBe(false)
    expect(r.limits).toContainEqual({ type: 'modules-page', safe: SAFE, shown: 10 })
    expect(r.verdict.kind).toBe('cannot-tell')
  })

  it('reads the guard and the fallback handler as information', async () => {
    const guard = addr('guard')
    const fallbackHandler = '0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99'
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, guard, fallbackHandler })
    const r = await run()
    expect(r.guard).toBe(guard)
    expect(r.fallbackHandler).toBe(fallbackHandler)
    expect(r.moduleGuard).toBeNull()
    expect(r.verdict.kind).toBe('protected')
  })

  it('a Safe 1.0.0 lists its modules with getModules()', async () => {
    chain.chainId = 1
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, v100: true, modules: [addr('m')] })
    const r = await run()
    expect(r.version).toBe('1.0.0')
    expect(r.modules).toEqual([addr('m')])
  })

  it("a singleton that isn't official on this chain: can't tell", async () => {
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, singleton: addr('my singleton') })
    const r = await run()
    expect(r.official).toEqual({ proxy: true, singleton: false })
    expect(r.verdict).toMatchObject({ kind: 'cannot-tell', reasons: ['unofficial-safe'] })
    expect(r.version).toBeNull()
  })

  it("Safe 1.0.0's singleton on Sepolia, where safe-deployments doesn't list it: not official", async () => {
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, singleton: '0xb6029EA3B2c51D09a50B53CA8012FeEB05bDa35A' })
    expect((await run()).official.singleton).toBe(false)
  })

  it("a proxy that isn't official: can't tell", async () => {
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, code: SOME_CODE })
    const r = await run()
    expect(r.official).toEqual({ proxy: false, singleton: true })
    expect(r.verdict.reasons).toEqual(['unofficial-safe'])
  })
})

describe('nested Safes', () => {
  it('a protected Safe owner counts as hash-based; an exposed one as exposed', async () => {
    const inner = chain.safe(addr('inner'), { owners: [chain.winterlock(KEYS[0]), chain.winterlock(KEYS[1])], threshold: 2 })
    const exposed = chain.safe(addr('exposed inner'), { owners: [chain.key(addr('x'), 9)], threshold: 1 })
    chain.safe(SAFE, { owners: [inner, exposed, chain.winterlock(KEYS[2])], threshold: 2 })
    const r = await run()
    expect(kinds(r)).toEqual(['safe', 'safe', 'winterlock'])
    expect(classes(r)).toEqual(['hash-based', 'exposed', 'hash-based'])
    expect(facts(r, 0, 'safe').report.depth).toBe(1)
    expect(r.verdict.kind).toBe('protected')
  })

  it('a Safe exposed as owners sign counts as quantum-vulnerable, not exposed', async () => {
    const inner = chain.safe(addr('inner'), { owners: [chain.key(addr('a')), chain.key(addr('b'))], threshold: 1 })
    service.add(inner, {})
    chain.safe(SAFE, { owners: [inner], threshold: 1 })
    const r = await run()
    expect(facts(r, 0, 'safe').report.verdict.kind).toBe('exposed-as-owners-sign')
    expect(r.owners[0].class).toBe('not-known')
    expect(r.verdict.kind).toBe('exposed-as-owners-sign')
  })

  it("Safes that own each other: the cycle stops, and counts as can't tell", async () => {
    const a = addr('A')
    const b = addr('B')
    chain.safe(a, { owners: [b, chain.winterlock(KEYS[0])], threshold: 1 })
    chain.safe(b, { owners: [a, chain.winterlock(KEYS[1])], threshold: 1 })
    const r = await run(a)
    const inner = facts(r, 0, 'safe').report
    expect(inner.owners[0].facts).toEqual({ kind: 'cycle' })
    expect(inner.verdict.kind).toBe('cannot-tell')
    expect(r.verdict.kind).toBe('cannot-tell')
    expect(allLimits(r)).toContainEqual({ type: 'cycle', safe: b, owner: a })
  })

  it("an owner not read doesn't stop a verdict the others settle", async () => {
    const a = addr('A')
    const b = addr('B')
    chain.safe(a, { owners: [b, chain.winterlock(KEYS[0])], threshold: 1 })
    // B needs both: A (the cycle, unknown) and a hash-based owner, so B can't be signed for by
    // quantum-vulnerable keys alone
    chain.safe(b, { owners: [a, chain.winterlock(KEYS[1])], threshold: 2 })
    const r = await run(a)
    expect(facts(r, 0, 'safe').report.verdict.kind).toBe('protected')
    expect(r.verdict.kind).toBe('protected')
  })

  it("two Safes owning each other from both sides of a diamond don't wait on each other", async () => {
    const b = addr('B')
    const c = addr('C')
    chain.safe(b, { owners: [c, chain.winterlock(KEYS[0])], threshold: 1 })
    chain.safe(c, { owners: [b, chain.winterlock(KEYS[1])], threshold: 1 })
    chain.safe(SAFE, { owners: [b, c], threshold: 1 })
    const r = await run()
    expect(kinds(r)).toEqual(['safe', 'safe'])
  })

  it('the depth limit', async () => {
    let owner = chain.winterlock(KEYS[0])
    for (let i = 4; i >= 1; i--) owner = chain.safe(addr(`level ${i}`), { owners: [owner], threshold: 1 })
    chain.safe(SAFE, { owners: [owner], threshold: 1 })
    const deep = await run(SAFE, { maxDepth: 3 })
    const limits = allLimits(deep)
    expect(limits).toContainEqual({ type: 'depth', safe: addr('level 3'), owner: addr('level 4'), maxDepth: 3 })
    expect(deep.verdict.kind).toBe('cannot-tell')
    const all = await run(SAFE, { maxDepth: 4 })
    expect(all.verdict.kind).toBe('protected')
  })

  it('the cap on Safes read', async () => {
    const inner = [1, 2, 3].map((i) => chain.safe(addr(`inner ${i}`), { owners: [chain.winterlock(KEYS[i])], threshold: 1 }))
    chain.safe(SAFE, { owners: inner, threshold: 1 })
    const r = await run(SAFE, { maxSafes: 3 })
    expect(r.owners.filter((o) => o.facts.kind === 'not-read')).toHaveLength(1)
    expect(r.limits.filter((l) => l.type === 'safes-cap')).toHaveLength(1)
    expect(r.verdict.kind).toBe('cannot-tell')
  })
})

describe("Safe's Transaction Service", () => {
  it('the page cap: reads at most maxPages pages per list and reports the rest', async () => {
    const alice = chain.key(addr('alice'))
    chain.safe(SAFE, { owners: [alice], threshold: 1 })
    service.add(SAFE, {
      transactions: [0, 1, 2, 3, 4].map((nonce) => ({ nonce, isExecuted: true, confirmations: [] })),
      messages: [{ confirmations: [] }],
    })
    const r = await run(SAFE, { service: { url: SERVICE_URL, fetch: service.fetch, interval: 0, maxPages: 2, pageSize: 2 } })
    expect(r.limits).toContainEqual({ type: 'service-cap', safe: SAFE, list: 'transactions', read: 4, total: 5, pages: 2, pageSize: 2 })
    expect(r.service).toMatchObject({ transactions: { read: 4, total: 5 }, messages: { read: 1, total: 1 }, requests: 4 })
    expect(service.urls).toEqual([
      `/api/v1/safes/${SAFE}/`,
      `/api/v2/safes/${SAFE}/multisig-transactions/?limit=2&offset=0`,
      `/api/v2/safes/${SAFE}/multisig-transactions/?limit=2&offset=2`,
      `/api/v1/safes/${SAFE}/messages/?limit=2&offset=0`,
    ])
  })

  it("a Safe the service doesn't know: its signatures there are unknown, and said so", async () => {
    chain.safe(SAFE, { owners: [chain.key(addr('alice'))], threshold: 1 })
    const r = await run()
    expect(facts(r, 0, 'key').signatures).toBeNull()
    expect(r.limits).toContainEqual({ type: 'service-unavailable', safe: SAFE, reason: 'not-indexed', detail: 'HTTP 404' })
    expect(r.verdict.kind).toBe('exposed-as-owners-sign')
  })

  it('rate limited part-way: what was read still counts', async () => {
    const alice = chain.key(addr('alice'))
    const bob = chain.key(addr('bob'))
    chain.safe(SAFE, { owners: [alice, bob], threshold: 2 })
    service.add(SAFE, {
      transactions: [
        { nonce: 0, isExecuted: true, confirmations: [{ owner: alice, signatureType: 'EOA' }] },
        { nonce: 1, isExecuted: true, confirmations: [{ owner: bob, signatureType: 'EOA' }] },
      ],
    })
    service.rateLimitFrom = 2
    const r = await run(SAFE, { service: { url: SERVICE_URL, fetch: service.fetch, interval: 0, pageSize: 1 } })
    expect(classes(r)).toEqual(['exposed', 'not-known'])
    expect(r.limits).toContainEqual({ type: 'service-unavailable', safe: SAFE, reason: 'rate-limited', detail: 'HTTP 429' })
  })

  it('no service at all: said so', async () => {
    chain.safe(SAFE, { owners: [chain.key(addr('alice'))], threshold: 1 })
    const r = await run(SAFE, { service: null })
    expect(facts(r, 0, 'key').signatures).toBeNull()
    expect(r.limits).toContainEqual({ type: 'service-unavailable', safe: SAFE, reason: 'failed', detail: 'not asked' })
  })

  it('spaces its requests', async () => {
    chain.safe(SAFE, { owners: [chain.key(addr('alice'))], threshold: 1 })
    service.add(SAFE, {})
    const t0 = Date.now()
    await run(SAFE, { service: { url: SERVICE_URL, fetch: service.fetch, interval: 50 } })
    expect(service.urls).toHaveLength(3)
    expect(Date.now() - t0).toBeGreaterThanOrEqual(100)
  })
})

describe('reading', () => {
  it('reads every chain value at one block, a little behind the latest', async () => {
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1 })
    const r = await run()
    expect(r.block).toBe(998n)
    const tagged = chain.requests.filter((q) => !['eth_chainId', 'eth_blockNumber'].includes(q.method))
    expect(tagged.length).toBeGreaterThan(5)
    for (const q of tagged) expect(q.params[q.params.length - 1]).toBe('0x3e6')
  })

  it('balances of the native currency and the tokens asked for', async () => {
    const usdc = chain.token(addr('usdc'), { [SAFE.toLowerCase()]: 1_500_000n })
    chain.safe(SAFE, { owners: [chain.winterlock(KEYS[0])], threshold: 1, balance: 10n ** 18n })
    const r = await run(SAFE, { tokens: [{ address: usdc, symbol: 'USDC', decimals: 6 }] })
    expect(r.balances).toEqual({ native: 10n ** 18n, tokens: [{ token: { address: usdc, symbol: 'USDC', decimals: 6 }, balance: 1_500_000n }] })
  })

  it('refuses an endpoint for another chain', async () => {
    chain.safe(SAFE, { owners: [], threshold: 1 })
    await expect(run(SAFE, { chainId: 1 })).rejects.toMatchObject({ code: 'wrong-chain' })
  })

  it('no contract, or not a Safe', async () => {
    await expect(run()).rejects.toBeInstanceOf(CheckError)
    await expect(run()).rejects.toMatchObject({ code: 'no-contract' })
    chain.set(SAFE, { code: SOME_CODE })
    await expect(run()).rejects.toMatchObject({ code: 'not-a-safe' })
  })

  it("never follows CCIP-Read: a contract can't make the check fetch a URL of its choosing", async () => {
    const lookup = encodeErrorResult({
      abi: parseAbi(['error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData)']),
      errorName: 'OffchainLookup',
      args: [SAFE, ['https://attacker.test/{sender}/{data}'], '0x', '0x12345678', '0x'],
    })
    chain.set(SAFE, {
      code: SOME_CODE,
      call: () => {
        throw new Revert(lookup)
      },
    })
    const spy = vi.spyOn(globalThis, 'fetch')
    try {
      await expect(run()).rejects.toMatchObject({ code: 'not-a-safe' })
      expect(spy).not.toHaveBeenCalled()
    } finally {
      spy.mockRestore()
    }
  })

  it("a Safe that was never set up: can't tell", async () => {
    chain.safe(SAFE, { owners: [], threshold: 0 })
    expect((await run()).verdict.reasons).toEqual(['no-threshold'])
  })
})
