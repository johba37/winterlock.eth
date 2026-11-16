// The shapes the check reads into and reports. Plain data, no DOM: another checker can render
// them its own way, or use explain.ts for this check's sentences.

import type { Address, Hex } from 'viem'
import type { Token } from './chains'

/** A signature by an owner that Safe's Transaction Service holds for this Safe. */
export interface SignatureSeen {
  source: 'transaction' | 'message'
  /** The service's signatureType: EOA, ETH_SIGN, SECP256R1, CONTRACT_SIGNATURE or APPROVED_HASH. */
  signatureType: string
  /** The SafeTx hash or the message hash. */
  hash: Hex
  nonce?: number
  executed?: boolean
}

/** One owner's signatures at the service, by signature type. */
export interface OwnerSignatures {
  byType: Record<string, number>
  /** The first one found whose type shows the public key (see EXPOSING_TYPES). */
  example?: SignatureSeen
}

/** What the check found about an owner, before it is classified. */
export type OwnerFacts =
  /** No code: an ECDSA key (or a contract not deployed yet). `signatures` is undefined when the
   * service wasn't read, null when it couldn't be. */
  | { kind: 'key'; nonce: number; signatures?: OwnerSignatures | null }
  /** An EOA with an EIP-7702 delegation: still an ECDSA key, and it signed the delegation. */
  | { kind: 'delegated-key'; nonce: number; delegate: Address }
  /** A Winterlock owner: owner v2, or the earlier owner v1. */
  | { kind: 'winterlock'; version: 1 | 2; memberKey: Hex }
  /** Safe's passkey signer: a P-256 key whose public key (x, y) is in the contract's code. */
  | { kind: 'passkey'; factoryVersion: string; x: bigint; y: bigint }
  /** Safe's shared passkey signer: the P-256 public key is in the Safe's storage, if configured. */
  | { kind: 'passkey-shared'; configured: boolean; x: bigint; y: bigint }
  | { kind: 'safe'; report: SafeReport }
  /** A Safe already on the path from the looked-up Safe: not read again. */
  | { kind: 'cycle' }
  /** A Safe nested deeper than the depth limit, or past the cap on Safes read. */
  | { kind: 'not-read'; why: 'depth' | 'safes-cap' }
  | { kind: 'contract'; size: number; codeHash: Hex }
  /** The RPC didn't answer for this owner. */
  | { kind: 'unread'; error: string }

export type OwnerClass = 'exposed' | 'not-known' | 'hash-based' | 'unknown'

export interface OwnerReport {
  address: Address
  facts: OwnerFacts
  class: OwnerClass
}

export type VerdictKind = 'exposed' | 'exposed-as-owners-sign' | 'protected' | 'cannot-tell'

export type CannotTellReason =
  /** The proxy or the singleton isn't one of Safe's official contracts. */
  | 'unofficial-safe'
  /** The threshold is 0: the Safe was never set up. */
  | 'no-threshold'
  /** Quantum-vulnerable owners plus owners this check couldn't classify reach the threshold. */
  | 'unknown-owners'
  /** A module can act without the owners; this version doesn't analyse modules. */
  | 'modules'

export interface Verdict {
  kind: VerdictKind
  threshold: number
  owners: number
  exposed: number
  /** Quantum-vulnerable owners: exposed plus not known to be exposed. */
  vulnerable: number
  unknown: number
  hashBased: number
  /** Why the answer is "can't tell"; empty otherwise. */
  reasons: CannotTellReason[]
  /** Enabled modules, counted for every verdict (a verdict of exposed stands with them). */
  modules: number
}

/** What would change the verdict, as facts; explain.ts words them. */
export type Change =
  /** With `count` of these `of` quantum-vulnerable or unclassified owners hash-based, the
   * threshold could no longer be reached by them alone. */
  | { type: 'replace-owners'; count: number; of: number }
  /** The same with the owners as they are and a threshold of `to` of `owners`. */
  | { type: 'raise-threshold'; to: number; owners: number }
  /** The modules would need removing, or checking by other means. */
  | { type: 'modules'; count: number }
  /** Exposed as owners sign: `more` further exposed keys would reach the threshold. */
  | { type: 'more-exposed'; exposed: number; more: number }
  /** Protected: what would undo it. */
  | { type: 'margin'; addOwners: number; threshold: number }
  /** The check reads only Safes on Safe's official contracts. */
  | { type: 'official-safe' }

export type Limit =
  | { type: 'service-cap'; safe: Address; list: 'transactions' | 'messages'; read: number; total: number; pages: number; pageSize: number }
  | { type: 'service-unavailable'; safe: Address; reason: 'not-indexed' | 'rate-limited' | 'failed'; detail: string }
  | { type: 'depth'; safe: Address; owner: Address; maxDepth: number }
  | { type: 'safes-cap'; safe: Address; owner: Address; maxSafes: number }
  | { type: 'cycle'; safe: Address; owner: Address }
  | { type: 'modules-page'; safe: Address; shown: number }

export interface ServiceSummary {
  transactions: { read: number; total: number }
  messages: { read: number; total: number }
  requests: number
  pageSize: number
  maxPages: number
}

export interface Balances {
  native: bigint
  tokens: { token: Token; balance: bigint | null }[]
}

export interface SafeReport {
  chainId: number
  address: Address
  /** The block every chain read was made at. */
  block: bigint
  singleton: Address
  /** The official version, when both the proxy and the singleton are official. */
  version: string | null
  l2: boolean
  official: { proxy: boolean; singleton: boolean }
  threshold: number
  nonce: bigint | null
  owners: OwnerReport[]
  modules: Address[]
  /** False when more modules are enabled than were listed. */
  modulesComplete: boolean
  guard: Address | null
  moduleGuard: Address | null
  fallbackHandler: Address | null
  /** Read for the looked-up Safe only. */
  balances: Balances | null
  verdict: Verdict
  changes: Change[]
  /** This Safe's own limits; nested Safes carry theirs (allLimits collects them). */
  limits: Limit[]
  /** Null when no owner needed the service (every key already shown exposed by the chain). */
  service: ServiceSummary | null
  depth: number
}
