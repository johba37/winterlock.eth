import { describe, expect, it } from 'vitest'
import { changesFor, classify, nestedClass, verdictOf } from '../src/lib/model'
import type { OwnerClass, OwnerFacts, SafeReport, Verdict } from '../src/lib/types'

const nested = (kind: Verdict['kind']) => ({ kind: 'safe', report: { verdict: { kind } } as SafeReport }) as OwnerFacts

describe('owner classes', () => {
  const cases: [string, OwnerFacts, OwnerClass][] = [
    ['a key that sent a transaction', { kind: 'key', nonce: 3 }, 'exposed'],
    ['a key with an ECDSA confirmation at the service', { kind: 'key', nonce: 0, signatures: { byType: { EOA: 1 } } }, 'exposed'],
    ['a key with an eth_sign confirmation', { kind: 'key', nonce: 0, signatures: { byType: { ETH_SIGN: 2 } } }, 'exposed'],
    ['a key with a secp256r1 confirmation', { kind: 'key', nonce: 0, signatures: { byType: { SECP256R1: 1 } } }, 'exposed'],
    ['a key with only an approved hash', { kind: 'key', nonce: 0, signatures: { byType: { APPROVED_HASH: 1 } } }, 'not-known'],
    ['a key with only contract signatures listed', { kind: 'key', nonce: 0, signatures: { byType: { CONTRACT_SIGNATURE: 4 } } }, 'not-known'],
    ['a key with no signature found', { kind: 'key', nonce: 0, signatures: { byType: {} } }, 'not-known'],
    ['a key whose service read failed', { kind: 'key', nonce: 0, signatures: null }, 'not-known'],
    ['a key, service not read', { kind: 'key', nonce: 0 }, 'not-known'],
    ['an EIP-7702 delegated key', { kind: 'delegated-key', nonce: 1, delegate: '0x0000000000000000000000000000000000000001' }, 'exposed'],
    ['a Winterlock owner v2', { kind: 'winterlock', version: 2, memberKey: '0x01' }, 'hash-based'],
    ['a Winterlock owner v1', { kind: 'winterlock', version: 1, memberKey: '0x01' }, 'hash-based'],
    ['a passkey signer', { kind: 'passkey', factoryVersion: '0.2.1', x: 1n, y: 2n }, 'exposed'],
    ['the shared passkey signer, set up', { kind: 'passkey-shared', configured: true, x: 1n, y: 2n }, 'exposed'],
    ['the shared passkey signer, not set up', { kind: 'passkey-shared', configured: false, x: 0n, y: 0n }, 'unknown'],
    ['an exposed Safe', nested('exposed'), 'exposed'],
    ['a Safe exposed as owners sign', nested('exposed-as-owners-sign'), 'not-known'],
    ['a protected Safe', nested('protected'), 'hash-based'],
    ["a Safe that can't be told", nested('cannot-tell'), 'unknown'],
    ['a cycle', { kind: 'cycle' }, 'unknown'],
    ['a Safe too deep', { kind: 'not-read', why: 'depth' }, 'unknown'],
    ['a Safe past the cap', { kind: 'not-read', why: 'safes-cap' }, 'unknown'],
    ['an unknown contract', { kind: 'contract', size: 100, codeHash: '0x00' }, 'unknown'],
    ["an owner the RPC didn't answer for", { kind: 'unread', error: 'timeout' }, 'unknown'],
  ]
  for (const [name, facts, cls] of cases) it(name, () => expect(classify(facts)).toBe(cls))

  it('maps every nested verdict', () => {
    expect(['exposed', 'exposed-as-owners-sign', 'protected', 'cannot-tell'].map((k) => nestedClass(k as Verdict['kind']))).toEqual(['exposed', 'not-known', 'hash-based', 'unknown'])
  })
})

const v = (threshold: number, classes: OwnerClass[], modules = 0, official = true) => verdictOf({ threshold, classes, modules, official })

describe('verdicts', () => {
  it('exposed: at least t owners exposed', () => {
    expect(v(2, ['exposed', 'exposed', 'hash-based']).kind).toBe('exposed')
    expect(v(1, ['exposed', 'hash-based', 'hash-based']).kind).toBe('exposed')
  })
  it('exposed stands with modules', () => {
    const r = v(1, ['exposed'], 2)
    expect(r.kind).toBe('exposed')
    expect(r.modules).toBe(2)
    expect(r.reasons).toEqual([])
  })
  it('exposed as owners sign: enough quantum-vulnerable owners, too few exposed', () => {
    expect(v(2, ['exposed', 'not-known', 'hash-based']).kind).toBe('exposed-as-owners-sign')
    expect(v(2, ['not-known', 'not-known']).kind).toBe('exposed-as-owners-sign')
    // with modules too: the owners alone already reach the threshold
    expect(v(2, ['not-known', 'not-known'], 1).kind).toBe('exposed-as-owners-sign')
  })
  it('protected: vulnerable plus unknown below the threshold, no module', () => {
    const r = v(2, ['exposed', 'hash-based', 'hash-based'])
    expect(r).toMatchObject({ kind: 'protected', exposed: 1, vulnerable: 1, unknown: 0, hashBased: 2 })
    expect(v(3, ['exposed', 'unknown', 'hash-based', 'hash-based']).kind).toBe('protected')
    expect(v(1, ['hash-based']).kind).toBe('protected')
  })
  it("can't tell: unknown owners could make up the threshold", () => {
    const r = v(2, ['exposed', 'unknown', 'hash-based'])
    expect(r.kind).toBe('cannot-tell')
    expect(r.reasons).toEqual(['unknown-owners'])
  })
  it("can't tell: a module, where the owners alone wouldn't reach the threshold", () => {
    const r = v(2, ['exposed', 'hash-based', 'hash-based'], 1)
    expect(r.kind).toBe('cannot-tell')
    expect(r.reasons).toEqual(['modules'])
  })
  it("can't tell: both reasons at once", () => {
    expect(v(2, ['exposed', 'unknown'], 1).reasons).toEqual(['unknown-owners', 'modules'])
  })
  it("can't tell: not an official Safe, whatever the owners", () => {
    const r = v(1, ['exposed'], 0, false)
    expect(r.kind).toBe('cannot-tell')
    expect(r.reasons).toEqual(['unofficial-safe'])
  })
  it("can't tell: threshold 0", () => {
    expect(v(0, []).reasons).toEqual(['no-threshold'])
  })
})

describe('what would change the verdict', () => {
  it("the user's example: 2 of 3 ECDSA owners, with 2 of them hash-based it holds", () => {
    const r = v(2, ['exposed', 'exposed', 'not-known'])
    expect(changesFor(r)).toEqual([
      { type: 'replace-owners', count: 2, of: 3 },
    ])
  })
  it('a hash-based owner already there: the threshold could be raised instead', () => {
    const r = v(1, ['exposed', 'not-known', 'hash-based'])
    expect(changesFor(r)).toEqual([
      { type: 'replace-owners', count: 2, of: 2 },
      { type: 'raise-threshold', to: 3, owners: 3 },
    ])
  })
  it('exposed as owners sign: how many more exposures make it exposed', () => {
    const r = v(2, ['exposed', 'not-known', 'not-known'])
    expect(changesFor(r)[0]).toEqual({ type: 'more-exposed', exposed: 1, more: 1 })
  })
  it('modules', () => {
    expect(changesFor(v(2, ['exposed', 'hash-based', 'hash-based'], 2))).toEqual([{ type: 'modules', count: 2 }])
  })
  it('protected: the margin', () => {
    expect(changesFor(v(2, ['exposed', 'hash-based', 'hash-based']))).toEqual([{ type: 'margin', addOwners: 1, threshold: 1 }])
    expect(changesFor(v(2, ['hash-based', 'hash-based']))).toEqual([{ type: 'margin', addOwners: 2, threshold: 0 }])
  })
  it('not official: only that', () => {
    expect(changesFor(v(1, ['exposed'], 0, false))).toEqual([{ type: 'official-safe' }])
  })
})
