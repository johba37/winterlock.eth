// The exposure model, as pure functions of what was read. An ECDSA (or P-256) key can only be
// attacked by someone able to derive private keys from public keys once its public key is
// known, which happens when it signs. Each owner gets a class; the Safe's threshold and the
// classes give the verdict.

import type { Change, OwnerClass, OwnerFacts, SafeReport, Verdict, VerdictKind } from './types'

/** Signature types at Safe's service that carry or reveal the signer's public key: an ECDSA
 * signature recovers it, and a secp256r1 (passkey) signature includes it. CONTRACT_SIGNATURE
 * is the owner contract's own business; APPROVED_HASH is an on-chain call by the owner, which
 * its transaction count already shows. */
export const EXPOSING_TYPES: readonly string[] = ['EOA', 'ETH_SIGN', 'SECP256R1']

export function exposingCount(byType: Record<string, number>): number {
  return EXPOSING_TYPES.reduce((n, t) => n + (byType[t] ?? 0), 0)
}

/** A nested Safe counts for its parent by its own verdict. */
export function nestedClass(kind: VerdictKind): OwnerClass {
  switch (kind) {
    case 'exposed':
      return 'exposed'
    case 'exposed-as-owners-sign':
      return 'not-known'
    case 'protected':
      return 'hash-based'
    case 'cannot-tell':
      return 'unknown'
  }
}

export function classify(facts: OwnerFacts): OwnerClass {
  switch (facts.kind) {
    case 'key':
      if (facts.nonce > 0) return 'exposed'
      if (facts.signatures && exposingCount(facts.signatures.byType) > 0) return 'exposed'
      return 'not-known'
    case 'delegated-key':
      return 'exposed'
    case 'winterlock':
      return 'hash-based'
    case 'passkey':
      return 'exposed'
    case 'passkey-shared':
      // unconfigured, it can't sign for this Safe until a Safe transaction configures a key
      return facts.configured ? 'exposed' : 'unknown'
    case 'safe':
      return nestedClass(facts.report.verdict.kind)
    case 'cycle':
    case 'not-read':
    case 'contract':
    case 'unread':
      return 'unknown'
  }
}

export interface VerdictInput {
  threshold: number
  classes: readonly OwnerClass[]
  modules: number
  /** Both the proxy and the singleton are Safe's official ones. */
  official: boolean
}

export function verdictOf({ threshold: t, classes, modules, official }: VerdictInput): Verdict {
  const count = (c: OwnerClass) => classes.filter((x) => x === c).length
  const exposed = count('exposed')
  const vulnerable = exposed + count('not-known')
  const unknown = count('unknown')
  const hashBased = count('hash-based')
  const base = { threshold: t, owners: classes.length, exposed, vulnerable, unknown, hashBased, modules }
  if (!official) return { ...base, kind: 'cannot-tell', reasons: ['unofficial-safe'] }
  if (t < 1) return { ...base, kind: 'cannot-tell', reasons: ['no-threshold'] }
  if (exposed >= t) return { ...base, kind: 'exposed', reasons: [] }
  if (vulnerable >= t) return { ...base, kind: 'exposed-as-owners-sign', reasons: [] }
  if (vulnerable + unknown < t && modules === 0) return { ...base, kind: 'protected', reasons: [] }
  const reasons: Verdict['reasons'] = []
  if (vulnerable + unknown >= t) reasons.push('unknown-owners')
  if (modules > 0) reasons.push('modules')
  return { ...base, kind: 'cannot-tell', reasons }
}

/** What would change the verdict. */
export function changesFor(v: Verdict): Change[] {
  if (v.reasons.includes('unofficial-safe') || v.reasons.includes('no-threshold')) {
    return v.reasons.includes('unofficial-safe') ? [{ type: 'official-safe' }] : []
  }
  const out: Change[] = []
  const reach = v.vulnerable + v.unknown
  if (v.kind === 'protected') {
    out.push({ type: 'margin', addOwners: v.threshold - reach, threshold: reach })
    return out
  }
  if (v.kind === 'exposed-as-owners-sign') out.push({ type: 'more-exposed', exposed: v.exposed, more: v.threshold - v.exposed })
  if (reach >= v.threshold) {
    out.push({ type: 'replace-owners', count: reach - v.threshold + 1, of: reach })
    if (reach + 1 <= v.owners) out.push({ type: 'raise-threshold', to: reach + 1, owners: v.owners })
  }
  if (v.modules > 0) out.push({ type: 'modules', count: v.modules })
  return out
}

/** Every limit hit while reading this Safe and the Safes nested in it. */
export function allLimits(r: SafeReport): SafeReport['limits'] {
  const out = [...r.limits]
  for (const o of r.owners) if (o.facts.kind === 'safe') out.push(...allLimits(o.facts.report))
  return out
}
