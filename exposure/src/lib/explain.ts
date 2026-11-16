// The check's sentences, separate from the page so that another checker can reuse them or write
// its own. Plain strings: no markup. The typographic apostrophe is deliberate.

import { type Address, formatUnits } from 'viem'
import { chainById } from './chains'
import { nameOf } from './known'
import { exposingCount, nestedClass } from './model'
import type { Change, Limit, OwnerClass, OwnerFacts, SafeReport, Verdict, VerdictKind } from './types'

export const BACKGROUND =
  'No computer able to derive a private key from its public key exists today, and nobody knows when one will. An ECDSA key, the kind almost every wallet uses, is open to such an attack only once its public key is known, and its public key becomes known when it signs.'

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`
const isAre = (n: number) => (n === 1 ? 'is' : 'are')

export function shortAddress(a: Address): string {
  return `${a.slice(0, 6)}…${a.slice(-4)}`
}

export function verdictTitle(kind: VerdictKind): string {
  switch (kind) {
    case 'exposed':
      return 'Exposed'
    case 'exposed-as-owners-sign':
      return 'Exposed as owners sign'
    case 'protected':
      return 'Protected by hash-based owners'
    case 'cannot-tell':
      return 'Can’t tell'
  }
}

export function classLabel(c: OwnerClass): string {
  switch (c) {
    case 'exposed':
      return 'Exposed'
    case 'not-known':
      return 'Not known to be exposed'
    case 'hash-based':
      return 'Hash-based'
    case 'unknown':
      return 'Can’t tell'
  }
}

export function classMeaning(c: OwnerClass): string {
  switch (c) {
    case 'exposed':
      return 'Quantum-vulnerable, and its public key is already known.'
    case 'not-known':
      return 'Quantum-vulnerable, and no signature by it was found here. That doesn’t make it safe: it may have signed on another network, for another Safe or off-chain, and its public key would then be known.'
    case 'hash-based':
      return 'Signs with hash-based keys only, which don’t rest on elliptic curves.'
    case 'unknown':
      return 'A contract this check doesn’t recognise or couldn’t read, so it can’t say how it signs.'
  }
}

function needs(v: Verdict): string {
  if (v.owners === 1) return 'This Safe needs its only owner to sign.'
  if (v.threshold === v.owners) return `This Safe needs all ${v.owners} of its owners to sign.`
  return `This Safe needs ${v.threshold} of its ${v.owners} owners to sign.`
}

/** The verdict in a few sentences. */
export function verdictText(r: SafeReport): string[] {
  const v = r.verdict
  const out: string[] = []
  const modules = v.modules > 0 ? `${plural(v.modules, 'module')} ${isAre(v.modules)} also enabled, which can act without the owners’ signatures; this check doesn’t analyse modules.` : ''
  const owners = (n: number) => `${plural(n, 'owner')} ${isAre(n)}`
  switch (v.kind) {
    case 'exposed': {
      const e = v.exposed
      out.push(
        `${needs(v)} ${owners(e)} exposed: ${e === 1 ? 'the public key behind it is' : 'the public keys behind them are'} already known. An attacker able to derive private keys from public keys could sign as ${e === 1 ? 'that owner' : e === v.threshold ? 'them' : `${v.threshold} of them`} and move the Safe’s funds without any owner signing.`,
      )
      if (modules) out.push(modules)
      break
    }
    case 'exposed-as-owners-sign': {
      const none = v.vulnerable === 1 ? 'It isn’t' : 'None of them is'
      out.push(
        `${needs(v)} ${owners(v.vulnerable)} quantum-vulnerable, enough to reach that threshold. ${v.exposed === 0 ? none : owners(v.exposed)} known to be exposed today. Each signature makes its key’s public key known, so as these owners sign, the Safe becomes open to an attacker able to derive private keys from public keys.`,
      )
      if (modules) out.push(modules)
      break
    }
    case 'protected': {
      const reach = v.vulnerable + v.unknown
      const who = v.unknown === 0 ? 'quantum-vulnerable' : 'quantum-vulnerable or unclassified'
      out.push(
        reach === 0
          ? `${needs(v)} No owner is ${who}, so every signature that counts comes from a hash-based owner. No module is enabled.`
          : `${needs(v)} Only ${owners(reach)} ${who}, fewer than ${v.threshold}, so every set of ${v.threshold} signatures includes a hash-based owner. No module is enabled.`,
        'An attacker able to derive private keys from public keys couldn’t reach the threshold with quantum-vulnerable keys alone. This covers who can sign for the Safe, nothing more: see what the check couldn’t see below.',
      )
      break
    }
    case 'cannot-tell':
      for (const reason of v.reasons) {
        if (reason === 'unofficial-safe') {
          const which = !r.official.proxy && !r.official.singleton ? 'its proxy and its singleton are' : !r.official.proxy ? 'its proxy is' : 'its singleton is'
          out.push(`This contract answers like a Safe, but ${which} not among Safe’s official contracts on this network, so its owners and threshold may not mean what they mean in a Safe. The check stops there.`)
        } else if (reason === 'no-threshold') {
          out.push('Its threshold is 0: the Safe was never set up.')
        } else if (reason === 'unknown-owners') {
          const vulnerable = v.vulnerable === 0 ? 'No owner is known to be quantum-vulnerable' : `${owners(v.vulnerable)} quantum-vulnerable, fewer than ${v.threshold}`
          out.push(
            `${needs(v)} ${vulnerable}, but this check can’t classify ${plural(v.unknown, 'owner')}. If ${v.unknown === 1 ? 'it' : 'they'} can be signed for with quantum-vulnerable keys, the threshold could be reached that way; if not, it couldn’t.`,
          )
        } else if (reason === 'modules') {
          out.push(`${plural(v.modules, 'module')} ${isAre(v.modules)} enabled. A module can move funds without the owners’ signatures, and this check doesn’t analyse modules.`)
        }
      }
      break
  }
  return out
}

export function ownerKind(f: OwnerFacts): string {
  switch (f.kind) {
    case 'key':
      return 'Key (ECDSA)'
    case 'delegated-key':
      return 'Key (ECDSA) with EIP-7702 delegation'
    case 'winterlock':
      return 'Winterlock owner'
    case 'passkey':
      return 'Passkey signer (P-256)'
    case 'passkey-shared':
      return 'Shared passkey signer (P-256)'
    case 'safe':
      return `Safe, ${f.report.threshold} of ${f.report.owners.length}`
    case 'cycle':
      return 'Safe'
    case 'not-read':
      return 'Safe'
    case 'contract':
      return 'Contract'
    case 'unread':
      return 'Not read'
  }
}

/** Why the owner has its class. */
export function ownerEvidence(f: OwnerFacts, chainId: number): string {
  const chain = chainById(chainId)?.name ?? `chain ${chainId}`
  switch (f.kind) {
    case 'key': {
      const parts: string[] = []
      if (f.nonce > 0) parts.push(`Has sent ${plural(f.nonce, 'transaction')} on ${chain}: its public key can be computed from any of them.`)
      const n = f.signatures ? exposingCount(f.signatures.byType) : 0
      const ex = f.signatures?.example
      if (n > 0 && ex) {
        const what = ex.source === 'transaction' ? `transaction${ex.nonce !== undefined ? ` at nonce ${ex.nonce}` : ''}${ex.executed ? ', executed' : ', queued'}` : 'message'
        const shows = ex.signatureType === 'SECP256R1' ? 'which includes its public key' : 'from which its public key can be computed'
        parts.push(`Safe’s Transaction Service holds ${plural(n, 'signature')} by it for this Safe (one on a ${what}), ${shows}.`)
      }
      if (f.nonce === 0 && n === 0) {
        parts.push(`Has sent no transaction on ${chain}.`)
        if (f.signatures === null) parts.push('Safe’s Transaction Service couldn’t be read, so its signatures there weren’t checked.')
        else if (f.signatures) parts.push('Safe’s Transaction Service holds no signature by it for this Safe.')
        parts.push('No code at this address: a plain key, or a contract not deployed yet.')
      }
      return parts.join(' ')
    }
    case 'delegated-key':
      return `A key with an EIP-7702 delegation to ${f.delegate}${nameOf(f.delegate) ? ` (${nameOf(f.delegate)})` : ''}. Signing the delegation made its public key known, and the key can still sign on its own.`
    case 'winterlock':
      return `Its code is a Winterlock owner (v2) of the pinned implementation, with member key ${f.memberKey.slice(0, 10)}…; it signs with hash-based keys only.`
    case 'passkey':
      return `Safe’s passkey signer (${f.factoryVersion}): its P-256 public key is stored on-chain, in the contract’s code. P-256 is an elliptic curve, as open to this attack as ECDSA’s.`
    case 'passkey-shared':
      return f.configured
        ? 'Safe’s shared passkey signer, set up for this Safe: its P-256 public key is stored on-chain, in the Safe’s storage. P-256 is an elliptic curve, as open to this attack as ECDSA’s.'
        : 'Safe’s shared passkey signer, with no key set up for this Safe: it can’t sign until a Safe transaction sets one.'
    case 'safe': {
      const r = f.report
      return `A Safe${r.version ? ` ${r.version}` : ''} that needs ${r.threshold} of its ${plural(r.owners.length, 'owner')}. Read in turn, its own verdict is “${verdictTitle(r.verdict.kind)}”, and it counts here as “${classLabel(nestedClass(r.verdict.kind))}”.`
    }
    case 'cycle':
      return 'A Safe already on the path being checked: Safes that own each other. Not read again, so it counts as “Can’t tell”.'
    case 'not-read':
      return f.why === 'depth' ? 'A Safe nested deeper than the check follows. Not read.' : 'A Safe past the number of Safes the check reads. Not read.'
    case 'contract':
      return `A contract this check doesn’t recognise (${f.size} bytes of code).`
    case 'unread':
      return `The RPC endpoint didn’t answer for this owner (${f.error}).`
  }
}

/** What would change the verdict, in sentences. */
export function changeText(c: Change, v: Verdict): string {
  switch (c.type) {
    case 'replace-owners': {
      const who = v.unknown === 0 ? 'quantum-vulnerable' : v.vulnerable === 0 ? 'unclassified' : 'quantum-vulnerable or unclassified'
      const which = c.of === 1 ? `this ${who} owner` : c.count === c.of ? `all ${c.of} of these ${who} owners` : `${c.count} of these ${c.of} ${who} owners`
      return `With ${which} hash-based instead, the threshold of ${v.threshold} could no longer be reached without a hash-based owner.`
    }
    case 'raise-threshold':
      return `Or, with the owners as they are, a threshold of ${c.to} of ${c.owners} would need a hash-based owner’s signature on every transaction.`
    case 'modules':
      return `The ${c.count === 1 ? 'module would need' : `${c.count} modules would need`} removing, or checking by other means: this check doesn’t analyse what a module can do.`
    case 'more-exposed':
      return `${c.exposed === 0 ? 'None' : c.exposed} of the ${v.threshold} keys needed ${c.exposed === 1 ? 'is' : 'are'} known to be exposed today; ${c.more} more would make this Safe Exposed.`
    case 'margin': {
      const parts = [`${plural(c.addOwners, 'more quantum-vulnerable owner', 'more quantum-vulnerable owners')}`]
      if (c.threshold >= 1) parts.push(`a threshold of ${c.threshold} or lower`)
      parts.push('or an enabled module')
      return `It would no longer be protected with ${parts.length === 3 ? `${parts[0]}, ${parts[1]} ${parts[2]}` : `${parts[0]} ${parts[1]}`}.`
    }
    case 'official-safe':
      return 'This check reads only Safes made of Safe’s official contracts.'
  }
}

export function limitText(l: Limit): string {
  switch (l.type) {
    case 'service-cap':
      return `Safe’s Transaction Service holds ${plural(l.total, l.list === 'transactions' ? 'transaction' : 'message')} for ${shortAddress(l.safe)}; the check read ${l.read} (${plural(l.pages, 'page')} of ${l.pageSize}). Signatures on the rest weren’t checked.`
    case 'service-unavailable':
      if (l.detail === 'not asked') return `Safe’s Transaction Service wasn’t asked about ${shortAddress(l.safe)}, so signatures there weren’t checked.`
      return l.reason === 'not-indexed'
        ? `Safe’s Transaction Service has no record of ${shortAddress(l.safe)}, so signatures there weren’t checked.`
        : l.reason === 'rate-limited'
          ? `Safe’s Transaction Service turned down further requests (too many) while reading ${shortAddress(l.safe)}, so its signatures there weren’t all checked. Try again in a minute.`
          : `Safe’s Transaction Service couldn’t be read for ${shortAddress(l.safe)} (${l.detail}), so signatures there weren’t checked.`
    case 'depth':
      return `${shortAddress(l.owner)}, a Safe that owns ${shortAddress(l.safe)}, is nested deeper than the ${l.maxDepth} levels the check follows. It wasn’t read.`
    case 'safes-cap':
      return `${shortAddress(l.owner)}, a Safe that owns ${shortAddress(l.safe)}, wasn’t read: the check reads at most ${l.maxSafes} Safes.`
    case 'cycle':
      return `${shortAddress(l.owner)} owns ${shortAddress(l.safe)} and is already on the path: Safes that own each other. It counts as “Can’t tell”.`
    case 'modules-page':
      return `${shortAddress(l.safe)} has more than ${l.shown} modules; the check listed the first ${l.shown}.`
  }
}

/** What the check never covers, whatever the Safe; without a chain, in general terms. */
export function scopeNotes(chainId?: number): string[] {
  const chain = chainId === undefined ? 'the Safe’s network' : (chainById(chainId)?.name ?? `chain ${chainId}`)
  return [
    'It covers who can sign for this Safe, and nothing else: not what its modules, guard or fallback handler can do, nor token approvals the Safe has given to other contracts.',
    `It looks for signatures in two places only: transactions sent on ${chain}, and this Safe’s transactions and messages at Safe’s Transaction Service. A key has the same address on every network, so a key that signed on another network, for another Safe or off-chain (a sign-in, a permit) is exposed even when nothing here shows it.`,
    'It takes Safe’s Transaction Service at its word: it doesn’t verify the signatures the service lists.',
  ]
}

/** A token amount in its own units, without trailing zeros. */
export function amount(value: bigint, decimals: number, max = 6): string {
  const [i, f = ''] = formatUnits(value, decimals).split('.')
  const int = i.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  const frac = f.slice(0, max).replace(/0+$/, '')
  if (!frac && f.length > 0 && /[1-9]/.test(f) && i === '0') return `less than 0.${'0'.repeat(max - 1)}1`
  return frac ? `${int}.${frac}` : int
}
