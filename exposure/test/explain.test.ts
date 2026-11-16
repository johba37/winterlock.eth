// The wording: what each verdict says, and what it must never say.

import { describe, expect, it } from 'vitest'
import * as explain from '../src/lib/explain'
import { changesFor, verdictOf } from '../src/lib/model'
import type { Limit, OwnerClass, OwnerFacts, SafeReport, Verdict } from '../src/lib/types'

const SAFE = '0x1111111111111111111111111111111111111111'

function report(threshold: number, classes: OwnerClass[], modules = 0, official = true): SafeReport {
  const verdict = verdictOf({ threshold, classes, modules, official })
  return {
    verdict,
    changes: changesFor(verdict),
    official: { proxy: official, singleton: true },
    owners: [],
    threshold,
  } as unknown as SafeReport
}

const CASES: [string, SafeReport][] = [
  ['exposed', report(1, ['exposed', 'hash-based'])],
  ['exposed with a module', report(1, ['exposed'], 1)],
  ['exposed as owners sign', report(2, ['exposed', 'not-known', 'hash-based'])],
  ['protected', report(2, ['exposed', 'hash-based', 'hash-based'])],
  ['protected, no vulnerable owner', report(1, ['hash-based'])],
  ['unknown owners', report(2, ['exposed', 'unknown', 'hash-based'])],
  ['modules', report(1, ['hash-based'], 2)],
  ['unofficial', report(1, ['exposed'], 0, false)],
]

const FACTS: OwnerFacts[] = [
  { kind: 'key', nonce: 2 },
  { kind: 'key', nonce: 0, signatures: { byType: { EOA: 1 }, example: { source: 'transaction', signatureType: 'EOA', hash: '0x00', nonce: 4, executed: true } } },
  { kind: 'key', nonce: 0, signatures: { byType: {} } },
  { kind: 'key', nonce: 0, signatures: null },
  { kind: 'delegated-key', nonce: 1, delegate: SAFE },
  { kind: 'winterlock', version: 2, memberKey: '0x580a94021dfd586b2537f1002eea21bdb6a451466d33cb0171146eba471b8d42' },
  { kind: 'winterlock', version: 1, memberKey: '0x22f2b5a2a743366962fb60bf4a51ef5132a5318652cb3cf81966e12a13cdedc0' },
  { kind: 'passkey', factoryVersion: '0.2.1', x: 1n, y: 2n },
  { kind: 'passkey-shared', configured: true, x: 1n, y: 2n },
  { kind: 'passkey-shared', configured: false, x: 0n, y: 0n },
  { kind: 'cycle' },
  { kind: 'not-read', why: 'depth' },
  { kind: 'contract', size: 12, codeHash: '0x00' },
  { kind: 'unread', error: 'timeout' },
]

const LIMITS: Limit[] = [
  { type: 'service-cap', safe: SAFE, list: 'transactions', read: 1000, total: 2989, pages: 5, pageSize: 200 },
  { type: 'service-unavailable', safe: SAFE, reason: 'not-indexed', detail: 'HTTP 404' },
  { type: 'service-unavailable', safe: SAFE, reason: 'rate-limited', detail: 'HTTP 429' },
  { type: 'depth', safe: SAFE, owner: SAFE, maxDepth: 3 },
  { type: 'safes-cap', safe: SAFE, owner: SAFE, maxSafes: 10 },
  { type: 'cycle', safe: SAFE, owner: SAFE },
  { type: 'modules-page', safe: SAFE, shown: 10 },
]

function everything(): string[] {
  const out = [explain.BACKGROUND, ...explain.scopeNotes(1)]
  for (const [, r] of CASES) {
    out.push(explain.verdictTitle(r.verdict.kind), ...explain.verdictText(r), ...r.changes.map((c) => explain.changeText(c, r.verdict)))
  }
  for (const c of ['exposed', 'not-known', 'hash-based', 'unknown'] as OwnerClass[]) out.push(explain.classLabel(c), explain.classMeaning(c))
  for (const f of FACTS) out.push(explain.ownerKind(f), explain.ownerEvidence(f, 11155111))
  for (const l of LIMITS) out.push(explain.limitText(l))
  return out
}

describe('wording', () => {
  it('every case says something', () => {
    for (const s of everything()) expect(s.trim().length).toBeGreaterThan(0)
    for (const [, r] of CASES) expect(explain.verdictText(r).length).toBeGreaterThan(0)
  })

  it("never calls anything safe, except to say that not knowing isn't safe", () => {
    for (const s of everything()) {
      const lower = s.replace(/Safe’s|Safes?\b/g, '')
      expect(lower.replace('doesn’t make it safe', '')).not.toMatch(/\bsafe\b|\bsecure\b|\bquantum-proof\b|\bquantum-safe\b/i)
    }
    expect(explain.classMeaning('not-known')).toMatch(/That doesn’t make it safe/)
  })

  it('no score, no countdown', () => {
    for (const s of everything()) expect(s).not.toMatch(/\bscore\b|\d+\s*%|\byears?\b|\bdays? left\b|\bby 20\d\d\b/i)
  })

  it('states that no such computer exists today', () => {
    expect(explain.BACKGROUND).toMatch(/exists today, and nobody knows when one will/)
  })

  it("the user's example: with 2 of these 3 owners hash-based", () => {
    const r = report(2, ['exposed', 'exposed', 'not-known'])
    expect(explain.changeText(r.changes[0], r.verdict)).toBe(
      'With 2 of these 3 quantum-vulnerable owners hash-based instead, the threshold of 2 could no longer be reached without a hash-based owner.',
    )
  })

  it('one owner, or all of them', () => {
    const one = report(1, ['exposed', 'hash-based', 'hash-based'])
    expect(explain.changeText(one.changes[0], one.verdict)).toBe(
      'With this quantum-vulnerable owner hash-based instead, the threshold of 1 could no longer be reached without a hash-based owner.',
    )
    expect(explain.verdictText(one)[0]).toBe(
      'This Safe needs 1 of its 3 owners to sign. 1 owner is exposed: the public key behind it is already known. An attacker able to derive private keys from public keys could sign as that owner and move the Safe’s funds without any owner signing.',
    )
    const all = report(1, ['exposed', 'not-known'])
    expect(explain.changeText(all.changes[0], all.verdict)).toMatch(/^With all 2 of these quantum-vulnerable owners hash-based instead/)
  })

  it("an owner the check can't classify", () => {
    const r = report(1, ['unknown'], 2)
    expect(explain.verdictText(r)).toEqual([
      'This Safe needs its only owner to sign. No owner is known to be quantum-vulnerable, but this check can’t classify 1 owner. If it can be signed for with quantum-vulnerable keys, the threshold could be reached that way; if not, it couldn’t.',
      '2 modules are enabled. A module can move funds without the owners’ signatures, and this check doesn’t analyse modules.',
    ])
    expect(explain.changeText(r.changes[0], r.verdict)).toMatch(/^With this unclassified owner hash-based instead/)
  })

  it('the threshold in words', () => {
    expect(explain.verdictText(report(2, ['not-known', 'not-known']))[0]).toBe(
      'This Safe needs all 2 of its owners to sign. 2 owners are quantum-vulnerable, enough to reach that threshold. None of them is known to be exposed today. Each signature makes its key’s public key known, so as these owners sign, the Safe becomes open to an attacker able to derive private keys from public keys.',
    )
    expect(explain.verdictText(report(1, ['hash-based']))[0]).toBe('This Safe needs its only owner to sign. No owner is quantum-vulnerable, so every signature that counts comes from a hash-based owner. No module is enabled.')
    expect(explain.verdictText(report(2, ['exposed', 'hash-based', 'hash-based']))[0]).toBe(
      'This Safe needs 2 of its 3 owners to sign. Only 1 owner is quantum-vulnerable, fewer than 2, so every set of 2 signatures includes a hash-based owner. No module is enabled.',
    )
  })

  it('protected says it covers who can sign, nothing more', () => {
    expect(explain.verdictText(CASES[3][1]).join(' ')).toMatch(/This covers who can sign for the Safe, nothing more/)
  })

  it('a margin with no vulnerable owner leaves out the threshold', () => {
    const v = { threshold: 1 } as Verdict
    expect(explain.changeText({ type: 'margin', addOwners: 1, threshold: 0 }, v)).toBe('It would no longer be protected with 1 more quantum-vulnerable owner or an enabled module.')
    expect(explain.changeText({ type: 'margin', addOwners: 2, threshold: 1 }, v)).toBe(
      'It would no longer be protected with 2 more quantum-vulnerable owners, a threshold of 1 or lower or an enabled module.',
    )
  })

  it('amounts in token units', () => {
    expect(explain.amount(1_500_000n, 6)).toBe('1.5')
    expect(explain.amount(1_234_567_000_000n, 6)).toBe('1,234,567')
    expect(explain.amount(10n ** 18n + 1n, 18)).toBe('1')
    expect(explain.amount(1n, 18)).toBe('less than 0.000001')
    expect(explain.amount(0n, 18)).toBe('0')
  })
})
