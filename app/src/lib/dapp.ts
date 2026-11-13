// What the app answers a dapp over WalletConnect, following the Python bridge
// (signer/winterlock_signer/bridge.py; docs/notes/walletconnect.md, "What the dapp gets"), without
// messages for now. Nothing here talks to the network: lib/walletconnect.ts runs what it decides
// against the relay, the chain and Safe's service.
//
//   eth_sendTransaction       a SafeTx (a call) the member confirms and proposes; the dapp gets the
//                             SafeTx hash after the proposal, as Safe's own app answers, or the
//                             execution's hash when the app executes at once (threshold 1)
//   wallet_sendCalls          EIP-5792: one call, or a batch as a delegatecall to MultiSendCallOnly
//                             v1.4.1; the dapp gets {id: SafeTx hash}
//   wallet_getCallsStatus     100 pending, 200 executed, 400 replaced at its nonce, 500 reverted
//   receipt and transaction   for a SafeTx hash the app gave out: the execution's, once there is one
//   lookups
//   messages                  refused for now (4001)
//   reads                     answered from the member's RPC, as the bridge does
//   anything else             4200

import { type Address, getAddress, isAddress, isHex, toHex } from 'viem'
import type { DappTxRecord, Hex } from './db'
import { type Call, type SafeTx, batchTx, controlsSafe, safeTx } from './safe'

export const SIGN_METHODS = [
  'eth_sendTransaction',
  'personal_sign',
  'eth_signTypedData',
  'eth_signTypedData_v4',
  'wallet_sendCalls',
  'wallet_getCallsStatus',
  'wallet_getCapabilities',
  'wallet_switchEthereumChain',
]
export const READ_METHODS = [
  'eth_accounts',
  'eth_requestAccounts',
  'eth_chainId',
  'net_version',
  'eth_blockNumber',
  'eth_getBalance',
  'eth_getCode',
  'eth_getTransactionCount',
  'eth_getStorageAt',
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getTransactionByHash',
  'eth_getTransactionReceipt',
  'eth_estimateGas',
  'eth_call',
  'eth_getLogs',
  'eth_gasPrice',
]
const SUPPORTED = new Set([...SIGN_METHODS, ...READ_METHODS])
const EVENTS = ['chainChanged', 'accountsChanged']
const MESSAGES = new Set(['personal_sign', 'eth_sign', 'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4'])

/** EIP-1193's codes (4001 rejected, 4200 unsupported, 4902 unknown chain), WalletConnect's (5100
 * unsupported chains, 5104 unsupported namespace), EIP-5792's (5700, 5730) and JSON-RPC's. */
export const CODE = {
  rejected: 4001,
  unsupported: 4200,
  unknownChain: 4902,
  chains: 5100,
  namespace: 5104,
  capability: 5700,
  unknownBundle: 5730,
  params: -32602,
  failed: -32000,
  internal: -32603,
}

export const MESSAGES_LATER = "messages aren't supported yet"
export const MEMBER_REFUSED = 'the member rejected the transaction'

/** An error for the dapp. */
export class RpcFail extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message)
  }
}

// --- the dapp's strings ---

// control characters, bidi overrides and isolates, zero-width characters: never shown raw
// (messages.py's printable). Code points, not escapes, so the source stays ASCII.
const HIDDEN: [number, number][] = [
  [0x00, 0x1f],
  [0x7f, 0x9f],
  [0x061c, 0x061c],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2069],
  [0xfeff, 0xfeff],
]

/** A dapp's string as the app shows it: hidden characters as a visible mark, cut at `limit`. */
export function printable(v: unknown, limit = 120): string {
  const s = typeof v === 'string' ? v : v == null ? '' : String(v)
  let out = ''
  for (const ch of s) {
    const c = ch.codePointAt(0)!
    out += HIDDEN.some(([a, b]) => c >= a && c <= b) ? '·' : ch
    if (out.length >= limit) return `${out.slice(0, limit)}…`
  }
  return out
}

export interface DappInfo {
  name: string
  url: string
  description: string
}

/** A dapp's metadata as it describes itself (WalletConnect doesn't verify it here). */
export function dappInfo(md: any): DappInfo {
  return { name: printable(md?.name, 80) || 'A dapp with no name', url: printable(md?.url, 200), description: printable(md?.description, 300) }
}

// --- the session ---

interface Ns {
  chains?: string[]
  methods?: string[]
  events?: string[]
}

export interface ProposalNamespaces {
  requiredNamespaces?: Record<string, Ns>
  optionalNamespaces?: Record<string, Ns>
}

export type SessionNamespaces = Record<'eip155', { chains: string[]; accounts: string[]; methods: string[]; events: string[] }> & Record<string, { chains?: string[]; accounts: string[]; methods: string[]; events: string[] }>

/** The namespaces to approve a proposal with, or RpcFail to reject it (bridge.py's
 * session_namespaces). As Safe's app does, chains the dapp requires are listed so its SDK accepts
 * the session, and requests on any chain but the Safe's are refused. */
export function sessionNamespaces(p: ProposalNamespaces, chain: number, safe: Address): { namespaces: SessionNamespaces; notes: string[] } {
  const ours = `eip155:${chain}`
  const chainsReq = new Set<string>()
  const methodsReq = new Set<string>()
  const eventsReq = new Set<string>()
  for (const [key, ns] of Object.entries(p.requiredNamespaces ?? {})) {
    if (key !== 'eip155' && !key.startsWith('eip155:')) throw new RpcFail(CODE.namespace, `only Ethereum (eip155) is supported, not ${printable(key, 40)}`)
    for (const c of ns.chains ?? (key.includes(':') ? [key] : [])) chainsReq.add(c)
    for (const m of ns.methods ?? []) methodsReq.add(m)
    for (const e of ns.events ?? []) eventsReq.add(e)
  }
  const chainsOpt = new Set<string>()
  const methodsOpt = new Set<string>()
  const eventsOpt = new Set<string>()
  for (const [key, ns] of Object.entries(p.optionalNamespaces ?? {})) {
    if (key !== 'eip155' && !key.startsWith('eip155:')) continue
    for (const c of ns.chains ?? (key.includes(':') ? [key] : [])) chainsOpt.add(c)
    for (const m of ns.methods ?? []) methodsOpt.add(m)
    for (const e of ns.events ?? []) eventsOpt.add(e)
  }
  if (!chainsReq.has(ours) && !chainsOpt.has(ours)) throw new RpcFail(CODE.chains, `the dapp doesn't offer chain ${chain}, where this Safe is`)
  const chains = [...new Set([...chainsReq, ours])].sort()
  const methods = [...new Set([...methodsReq, ...[...methodsOpt, ...SIGN_METHODS].filter((m) => SUPPORTED.has(m))])].sort()
  const events = [...new Set([...eventsReq, ...[...eventsOpt, ...EVENTS].filter((e) => EVENTS.includes(e))])].sort()
  const notes: string[] = []
  const others = [...chainsReq].filter((c) => c !== ours).sort()
  if (others.length) notes.push(`The dapp requires ${others.map((c) => printable(c, 40)).join(', ')} too: the app refuses requests there.`)
  const unsupported = [...methodsReq].filter((m) => !SUPPORTED.has(m)).sort()
  if (unsupported.length) notes.push(`The dapp requires ${unsupported.map((m) => printable(m, 60)).join(', ')}, which the app refuses.`)
  return { namespaces: { eip155: { chains, accounts: chains.map((c) => `${c}:${safe}`), methods, events } }, notes }
}

/** The session properties the app approves with (EIP-5792's capabilities, as the bridge sends). */
export function sessionProperties(chain: number, safe: Address, batches: boolean): Record<string, string> {
  return {
    capabilities: JSON.stringify({ [safe]: { [toHex(chain)]: { atomicBatch: { supported: batches } } } }),
    atomic: JSON.stringify({ status: batches ? 'supported' : 'unsupported' }),
  }
}

/** The Safe and chain a session serves: its first account on an enabled chain. */
export function sessionSafe(accounts: string[], enabled: (chain: number) => boolean): { chain: number; safe: Address } | undefined {
  for (const a of accounts) {
    const m = a.match(/^eip155:(\d+):(0x[0-9a-fA-F]{40})$/)
    if (m && enabled(Number(m[1]))) return { chain: Number(m[1]), safe: getAddress(m[2]) }
  }
  return undefined
}

// --- requests ---

export interface Ctx {
  chain: number
  safe: Address
  /** whether batches are allowed (not with a board) */
  batches: boolean
  /** why batches are refused, when they are */
  noBatches?: string
}

export type Plan =
  | { kind: 'answer'; result: unknown }
  | { kind: 'rpc'; method: string; params: unknown[] }
  | { kind: 'lookup'; method: 'eth_getTransactionByHash' | 'eth_getTransactionReceipt'; hash: Hex; params: unknown[] }
  | { kind: 'status'; id: Hex }
  | { kind: 'tx'; method: 'eth_sendTransaction' | 'wallet_sendCalls'; calls: Call[] }

function quantity(v: unknown, what: string): bigint {
  if (v === undefined || v === null) return 0n
  try {
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v)
    if (typeof v === 'string' && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(v)) return BigInt(v)
  } catch {
    /* below */
  }
  throw new RpcFail(CODE.params, `${what} is not a number`)
}

const same = (a: unknown, b: string) => typeof a === 'string' && a.toLowerCase() === b.toLowerCase()

/** One call a dapp asks for, after the checks that apply to every call (bridge.py's _call). */
export function parseCall(tx: unknown, where: string, ctx: Ctx, checkFrom = true): Call {
  if (!tx || typeof tx !== 'object' || Array.isArray(tx)) throw new RpcFail(CODE.params, `${where} is not an object`)
  const t = tx as Record<string, unknown>
  if (checkFrom && t.from && !same(t.from, ctx.safe)) throw new RpcFail(CODE.params, `${where} is from ${printable(t.from, 50)}, not this Safe ${ctx.safe}`)
  if (t.chainId !== undefined && t.chainId !== null && quantity(t.chainId, 'chainId') !== BigInt(ctx.chain)) {
    throw new RpcFail(CODE.chains, `${where} is for chain ${printable(t.chainId, 30)}, not ${ctx.chain}`)
  }
  if (!t.to) throw new RpcFail(CODE.unsupported, `${where} creates a contract, which the app doesn't do from a Safe`)
  if (typeof t.to !== 'string' || !isAddress(t.to, { strict: false })) throw new RpcFail(CODE.params, `${where}: \`to\` is not an address`)
  const raw = t.data ?? t.input ?? '0x'
  if (typeof raw !== 'string' || !(raw === '' || isHex(raw)) || raw.length % 2 !== 0) throw new RpcFail(CODE.params, `${where}: the data is not hex`)
  const call: Call = { to: getAddress(t.to), value: quantity(t.value, 'value'), data: (raw === '' ? '0x' : raw.toLowerCase()) as Hex }
  if (controlsSafe(call, ctx.safe)) {
    throw new RpcFail(CODE.rejected, 'a dapp asks the Safe to change its owners, threshold, modules, guard or fallback handler: refused over WalletConnect')
  }
  return call
}

const asHash = (v: unknown): Hex | undefined => (typeof v === 'string' && /^0x[0-9a-fA-F]{64}$/.test(v) ? (v.toLowerCase() as Hex) : undefined)

/** What to do with a request (bridge.py's handle), or RpcFail. `chainId` is the request's CAIP-2
 * chain. */
export function plan(method: string, params: unknown, chainId: string | undefined, ctx: Ctx): Plan {
  if (chainId && chainId !== `eip155:${ctx.chain}`) throw new RpcFail(CODE.chains, `this Safe is on eip155:${ctx.chain}, not ${printable(chainId, 40)}`)
  const ps: unknown[] = Array.isArray(params) ? params : params === undefined || params === null ? [] : [params]
  if (method === 'eth_accounts' || method === 'eth_requestAccounts') return { kind: 'answer', result: [ctx.safe] }
  if (method === 'eth_chainId') return { kind: 'answer', result: toHex(ctx.chain) }
  if (method === 'net_version') return { kind: 'answer', result: String(ctx.chain) }
  if (method === 'wallet_switchEthereumChain') {
    const p = ps[0] as Record<string, unknown> | undefined
    const want = quantity(p && typeof p === 'object' ? p.chainId : undefined, 'chainId')
    if (want === BigInt(ctx.chain)) return { kind: 'answer', result: null }
    throw new RpcFail(CODE.unknownChain, `the app serves this Safe on chain ${ctx.chain} only; connect again for chain ${want}`)
  }
  if (method === 'wallet_getCapabilities') {
    if (typeof ps[0] === 'string' && !same(ps[0], ctx.safe)) return { kind: 'answer', result: {} }
    const atomic = ctx.batches ? { atomicBatch: { supported: true }, atomic: { status: 'supported' } } : { atomicBatch: { supported: false }, atomic: { status: 'unsupported' } }
    return { kind: 'answer', result: { [toHex(ctx.chain)]: atomic } }
  }
  if (method === 'eth_sendTransaction') return { kind: 'tx', method, calls: [parseCall(ps[0], 'the transaction', ctx)] }
  if (method === 'wallet_sendCalls') return { kind: 'tx', method, calls: sendCalls(ps[0], ctx) }
  if (method === 'wallet_getCallsStatus') {
    const id = asHash(ps[0])
    if (!id) throw new RpcFail(CODE.unknownBundle, 'unknown bundle id')
    return { kind: 'status', id }
  }
  if (MESSAGES.has(method)) throw new RpcFail(CODE.rejected, MESSAGES_LATER)
  if (method === 'eth_getTransactionByHash' || method === 'eth_getTransactionReceipt') {
    const h = asHash(ps[0])
    if (h) return { kind: 'lookup', method, hash: h, params: ps }
  }
  if (READ_METHODS.includes(method)) return { kind: 'rpc', method, params: ps }
  if (method === 'eth_signTransaction' || method === 'eth_sendRawTransaction') {
    throw new RpcFail(CODE.unsupported, `${method}: a Safe has no key that signs raw transactions; use eth_sendTransaction`)
  }
  throw new RpcFail(CODE.unsupported, `${printable(method, 60)} is not supported by the app`)
}

/** wallet_sendCalls's bundle (EIP-5792), checked as the bridge's send_calls does. */
function sendCalls(bundle: unknown, ctx: Ctx): Call[] {
  if (!bundle || typeof bundle !== 'object' || !Array.isArray((bundle as any).calls) || (bundle as any).calls.length === 0) {
    throw new RpcFail(CODE.params, 'wallet_sendCalls needs a bundle with calls')
  }
  const b = bundle as Record<string, any>
  if (b.chainId !== undefined && b.chainId !== null && quantity(b.chainId, 'chainId') !== BigInt(ctx.chain)) {
    throw new RpcFail(CODE.chains, `the calls are for chain ${printable(b.chainId, 30)}, not ${ctx.chain}`)
  }
  if (b.from && !same(b.from, ctx.safe)) throw new RpcFail(CODE.params, `the calls are from ${printable(b.from, 50)}, not this Safe`)
  for (const [name, cap] of Object.entries(b.capabilities ?? {})) {
    if (cap && typeof cap === 'object' && (cap as any).optional === false) throw new RpcFail(CODE.capability, `capability ${printable(name, 40)} is not supported`)
  }
  const calls = (b.calls as unknown[]).map((c, i) => parseCall(c, `call ${i + 1}`, ctx, false))
  if (calls.length > 1 && !ctx.batches) throw new RpcFail(CODE.rejected, ctx.noBatches ?? 'batches are not supported')
  return calls
}

/** The Safe transaction for a request's calls: one call, or a batch through MultiSendCallOnly. The
 * app picks the nonce, and the gas fields are zero. */
export function txFor(calls: Call[], nonce: bigint): SafeTx {
  return calls.length === 1 ? safeTx({ ...calls[0], nonce }) : batchTx(calls, nonce)
}

/** The dapp's answer once the transaction is proposed. */
export function answerFor(method: string, safeTxHash: Hex): unknown {
  return method === 'wallet_sendCalls' ? { id: safeTxHash } : safeTxHash
}

// --- what happened to a SafeTx the app gave out ---

export type Execution = { state: 'pending' } | { state: 'replaced' } | { state: 'executed'; tx: Hex }

/** What finding an execution needs: the Safe's nonce on-chain, and Safe's service. No log scans:
 * free RPC tiers limit them (docs/notes/signer-app.md, "Arbitrum"). */
export interface ExecutionSource {
  safeNonce(): Promise<number>
  /** the service's record of this SafeTx, or null if it has none */
  serviceTx(hash: Hex): Promise<{ isExecuted: boolean; transactionHash?: Hex | null } | null>
  /** the SafeTx hashes the service lists as executed at this nonce */
  executedAt(nonce: number): Promise<Hex[]>
}

/**
 * Whether the Safe executed a SafeTx the app gave out:
 * - an execution this app made or found before (in the record)
 * - nothing while the Safe's nonce hasn't passed the transaction's
 * - then Safe's service: the SafeTx's own record, or another one executed at its nonce (replaced).
 *   A service that hasn't indexed the execution yet leaves it pending, to be asked again.
 */
export async function findExecution(rec: Pick<DappTxRecord, 'safeTxHash' | 'nonce' | 'execution'>, src: ExecutionSource): Promise<Execution> {
  if (rec.execution) return { state: 'executed', tx: rec.execution.tx }
  if ((await src.safeNonce()) <= rec.nonce) return { state: 'pending' }
  const t = await src.serviceTx(rec.safeTxHash)
  if (t?.isExecuted && t.transactionHash) return { state: 'executed', tx: t.transactionHash }
  const at = await src.executedAt(rec.nonce)
  if (at.some((h) => h.toLowerCase() !== rec.safeTxHash.toLowerCase())) return { state: 'replaced' }
  return { state: 'pending' }
}

export interface RawLog {
  address: string
  topics: Hex[]
  data: Hex
}

export interface RawReceipt {
  transactionHash: Hex
  blockHash: Hex
  blockNumber: Hex
  gasUsed: Hex
  status?: Hex
  logs: RawLog[]
}

// keccak256 of ExecutionSuccess(bytes32,uint256) and ExecutionFailure(bytes32,uint256)
export const EXECUTION_SUCCESS = '0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e'
export const EXECUTION_FAILURE = '0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23'

/** Whether a receipt holds the Safe's ExecutionSuccess or ExecutionFailure for this SafeTx. Safe
 * v1.4.1 indexes the hash (topic 1); v1.3.0 puts it in the data. */
export function outcome(logs: RawLog[], safe: Address, safeTxHash: Hex): 'success' | 'failure' | 'none' {
  for (const lg of logs) {
    if (lg.address.toLowerCase() !== safe.toLowerCase()) continue
    const kind = lg.topics[0]?.toLowerCase()
    if (kind !== EXECUTION_SUCCESS && kind !== EXECUTION_FAILURE) continue
    const got = lg.topics.length > 1 ? lg.topics[1] : `0x${lg.data.slice(2, 66)}`
    if (got.toLowerCase() !== safeTxHash.toLowerCase()) continue
    return kind === EXECUTION_SUCCESS ? 'success' : 'failure'
  }
  return 'none'
}

/** wallet_getCallsStatus's answer (EIP-5792, version 2.0.0). An execution whose receipt the node
 * doesn't have yet still counts as pending. */
export function callsStatus(rec: Pick<DappTxRecord, 'safeTxHash' | 'chain' | 'safe'>, exec: Execution, receipt: RawReceipt | null) {
  const out: Record<string, unknown> = { version: '2.0.0', id: rec.safeTxHash, chainId: toHex(rec.chain), atomic: true }
  if (exec.state === 'replaced') return { ...out, status: 400 }
  if (exec.state === 'pending' || !receipt) return { ...out, status: 100 }
  const ok = outcome(receipt.logs, getAddress(rec.safe), rec.safeTxHash) === 'success'
  return {
    ...out,
    status: ok ? 200 : 500,
    receipts: [
      {
        blockHash: receipt.blockHash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed,
        transactionHash: receipt.transactionHash,
        status: ok ? '0x1' : '0x0',
        logs: receipt.logs.map((l) => ({ address: l.address, data: l.data, topics: l.topics })),
      },
    ],
  }
}

/** eth_getTransactionByHash for a SafeTx hash not yet executed: a pending placeholder, as the
 * bridge answers (Safe's app answers likewise). */
export function pendingTransaction(hash: Hex, safe: Address) {
  return {
    hash,
    from: safe,
    to: null,
    blockHash: null,
    blockNumber: null,
    transactionIndex: null,
    nonce: '0x0',
    gas: '0x0',
    gasPrice: '0x0',
    value: '0x0',
    input: '0x',
  }
}
