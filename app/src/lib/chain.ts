// The chain: reads, the owner contract's views, and transactions from the gas account.
//
// The gas account is an ordinary account whose key comes from the phrase (core:
// derive::erc8499::gas_key, ERC-8499's application secret "winterlock.eth/gas"), so every paired
// device holds the same one. It pays for the owner's deployment, certificates,
// enrolments and executions. Fees follow the Python signer (ethtx.py's send): a gas limit of the
// node's estimate × 1.2 under EIP-7825's cap, a fee cap of twice the base fee plus the tip.
// No log scans: free RPC tiers limit them (10 blocks on Alchemy's, 2.5 s on Arbitrum).

import {
  type Address,
  BaseError,
  type PublicClient,
  type TransactionReceipt,
  createPublicClient,
  decodeEventLog,
  getAddress,
  hexToBytes,
  http,
  padHex,
  parseAbi,
  toHex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { type ChainConfig, chainById, safeUrl } from './chains'
import { type Hex, setting } from './db'
import type { Core } from './keylog'
import { SAFE_ABI } from './safe'

export const MAX_TX_GAS = 16_777_216n

export const OWNER_ABI = parseAbi([
  'function KEY() view returns (bytes32)',
  'function devices(uint8 device) view returns (bytes32 key, uint16 generation, bool active)',
  'function tree(address safe, uint8 device) view returns (bytes32 root, uint128 seed, uint8 height, uint64 start, uint16 generation)',
  'function certifyDevice(uint8 device, uint16 generation, bytes32 key, bytes signature)',
  'function revokeDevice(uint8 device, uint16 generation, bytes signature)',
  'function enroll(address safe, uint8 device, bytes32 root, uint8 height, uint64 start, bytes signature)',
  'function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)',
  'error InvalidCertificate()',
  'error InvalidRevocation()',
])

export const FACTORY_ABI = parseAbi([
  'function deploy(bytes32 key) returns (address owner)',
  'function deployAndEnroll(bytes32 key, address safe, bytes32 root, uint8 height, uint64 start, bytes signature) returns (address owner)',
  'function predict(bytes32 key) view returns (address)',
  'function IMPLEMENTATION() view returns (address)',
])

export const MAGIC = '0x1626ba7e'

export interface Ctx {
  chain: ChainConfig
  rpcUrl: string
  client: PublicClient
}

export async function rpcUrlFor(db: IDBDatabase, chainId: number): Promise<string> {
  return (await setting<string>(db, `rpc:${chainId}`)) || chainById(chainId).defaultRpc
}

const contexts = new Map<string, Ctx>()

/** A client for the chain at the member's RPC, checked to be that chain. */
export async function ctxFor(db: IDBDatabase, chainId: number): Promise<Ctx> {
  const rpcUrl = await rpcUrlFor(db, chainId)
  const id = `${chainId} ${rpcUrl}`
  const have = contexts.get(id)
  if (have) return have
  const client = createPublicClient({ transport: http(rpcUrl, { retryCount: 2, timeout: 30_000 }) }) as PublicClient
  const got = await client.getChainId().catch((e) => {
    throw new Error(`The RPC at ${safeUrl(rpcUrl)} doesn't answer (${short(e)}). Check it in Settings.`)
  })
  if (got !== chainId) throw new Error(`The RPC at ${safeUrl(rpcUrl)} is chain ${got}, not ${chainById(chainId).name}: change it in Settings.`)
  const ctx = { chain: chainById(chainId), rpcUrl, client }
  contexts.set(id, ctx)
  return ctx
}

const checked = new Set<string>()

/** ctxFor, after checking once that the pinned owner v2 contracts have code on the chain. */
export async function usableCtx(db: IDBDatabase, core: Core, chainId: number): Promise<Ctx> {
  const ctx = await ctxFor(db, chainId)
  const id = `${chainId} ${ctx.rpcUrl}`
  if (!checked.has(id)) {
    const missing = await missingContracts(ctx, core)
    if (missing.length) throw new Error(`Winterlock's contracts aren't on ${ctx.chain.name} yet (${missing.join(', ')}).`)
    checked.add(id)
  }
  return ctx
}

export function forgetContexts() {
  contexts.clear()
  checked.clear()
}

/** A URL's scheme and host only, wherever one appears in `text`. */
export function stripUrls(text: string): string {
  return text.replace(/\b(https?|wss?):\/\/([^/\s"'<>]+)[^\s"'<>]*/g, '$1://$2')
}

/** An error in one line, without URL paths (viem's messages name the RPC URL, which may hold a key). */
export function short(e: unknown): string {
  const m = (e as any)?.shortMessage ?? (e as Error)?.message ?? String(e)
  return stripUrls(String(m).split('\n')[0]).slice(0, 1000)
}

/** The pinned owner v2 contracts this chain lacks (by name). */
export async function missingContracts(ctx: Ctx, core: Core): Promise<string[]> {
  const pinned = await core.call<Uint8Array[]>('pinned')
  const names = ['stateless verifier', 'WOTS verifier', 'owner implementation', 'owner factory']
  const codes = await Promise.all(pinned.map((a) => ctx.client.getCode({ address: toHex(a) })))
  return names.filter((_, i) => !codes[i] || codes[i] === '0x')
}

export async function factoryAddress(core: Core): Promise<Address> {
  return getAddress(toHex((await core.call<Uint8Array[]>('pinned'))[3]))
}

// --- the owner contract ---

export interface DeviceState {
  key: Hex
  generation: number
  active: boolean
}

export async function readDevice(ctx: Ctx, owner: Address, device: number, blockNumber?: bigint): Promise<DeviceState> {
  const [key, generation, active] = await ctx.client.readContract({ address: owner, abi: OWNER_ABI, functionName: 'devices', args: [device], blockNumber })
  return { key, generation, active }
}

export interface OnchainTree {
  root: Hex | null
  height: number
  start: number
  generation: number
}

export async function readTree(ctx: Ctx, owner: Address, safe: Address, device: number, blockNumber?: bigint): Promise<OnchainTree> {
  const [root, , height, start, generation] = await ctx.client.readContract({ address: owner, abi: OWNER_ABI, functionName: 'tree', args: [safe, device], blockNumber })
  if (BigInt(root) === 0n) return { root: null, height: 0, start: 0, generation: 0 }
  return { root: toHex(hexToBytes(root).slice(0, 24)), height, start: Number(start), generation }
}

/** Whether the member's owner exists here: the code at its address must be the v2 proxy of the
 * pinned implementation with this member key (cli.py's owner_deployed). */
export async function ownerDeployed(ctx: Ctx, core: Core, owner: Address, memberKey: Hex, blockNumber?: bigint): Promise<boolean> {
  const code = await ctx.client.getCode({ address: owner, blockNumber })
  if (!code || code === '0x') return false
  const key = await core.call<Uint8Array | null>('memberKeyOf', { address: hexToBytes(owner), code: hexToBytes(code) })
  if (!key || toHex(key).toLowerCase() !== memberKey.toLowerCase()) {
    throw new Error(`The code at your owner address ${owner} isn't your owner contract: refusing.`)
  }
  return true
}

export async function isValidSignature(ctx: Ctx, owner: Address, hash: Hex, data: Uint8Array): Promise<boolean> {
  try {
    const r = await ctx.client.readContract({ address: owner, abi: OWNER_ABI, functionName: 'isValidSignature', args: [hash, toHex(data)] })
    return r.toLowerCase() === MAGIC
  } catch {
    return false
  }
}

// --- Safe reads ---

export interface SafeState {
  nonce: number
  threshold: number
  owners: Address[]
  version: string
}

export async function safeState(ctx: Ctx, safe: Address, blockNumber?: bigint): Promise<SafeState> {
  const code = await ctx.client.getCode({ address: safe, blockNumber })
  if (!code || code === '0x') throw new Error(`There is no Safe at ${safe} on ${ctx.chain.name}.`)
  const [nonce, threshold, owners, version] = await Promise.all([
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'nonce', blockNumber }),
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getThreshold', blockNumber }),
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getOwners', blockNumber }),
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'VERSION', blockNumber }).catch(() => '?'),
  ])
  return { nonce: Number(nonce), threshold: Number(threshold), owners: owners.map((o) => getAddress(o)), version }
}

// --- the gas account ---

export function gasAccount(gasKey: Hex) {
  return privateKeyToAccount(gasKey)
}

export interface Sent {
  hash: Hex
  receipt: TransactionReceipt
  gasLimit: bigint
}

/**
 * A read for the check after a transaction, at the block that mined it. A public endpoint can
 * spread requests over several nodes, and one that hasn't reached that block yet answers a read
 * of the latest state with the state from before the transaction (as on Sepolia's publicnode
 * endpoint on 2026-11-13: "enroll was mined, but the Safe's tree for this device differs", for an
 * enrolment that had worked). Asked for the block itself, such a node refuses, and the read is
 * tried again, for up to about 30 s.
 */
export async function afterTx<T>(receipt: { blockNumber: bigint }, read: (blockNumber: bigint) => Promise<T>, tries = 15, waitMs = 2000): Promise<T> {
  let last: unknown
  for (let i = 0; i < tries; i++) {
    try {
      return await read(receipt.blockNumber)
    } catch (e) {
      last = e
      if (i + 1 < tries) await new Promise((r) => setTimeout(r, waitMs))
    }
  }
  throw last
}

/** Per chain, the newest block that mined a transaction this app sent. */
const mined = new Map<number, bigint>()

/** Remembers that `block` mined one of this app's transactions: later views read no older state. */
export function sawMined(chainId: number, block: bigint) {
  if (block > (mined.get(chainId) ?? 0n)) mined.set(chainId, block)
}

/**
 * A view's reads: of the latest state, but never of a block older than one that mined a
 * transaction this app sent. A node behind the others answers "latest" with the state from before
 * that transaction: on the first wired board (2026-11-15) the Key tree panel, refreshed right after
 * an enrolment, saw no owner contract and offered to enrol again, and the second tree pushed the
 * start nonce past the Safe's. After such a transaction, `read` gets a block number (the newest
 * the node reports, or the mining block if that is newer) and is tried again while the node
 * refuses it, for up to about 30 s. An error that isn't the endpoint's (one of ours, thrown in
 * `read`) isn't tried again.
 */
export async function readFresh<T>(ctx: Ctx, read: (blockNumber?: bigint) => Promise<T>, tries = 15, waitMs = 2000): Promise<T> {
  const floor = mined.get(ctx.chain.id)
  if (floor === undefined) return read()
  const head = await ctx.client.getBlockNumber({ cacheTime: 0 })
  const at = head > floor ? head : floor
  for (let i = 0; ; i++) {
    try {
      return await read(at)
    } catch (e) {
      if (!(e instanceof BaseError) || i + 1 >= tries) throw e
      await new Promise((r) => setTimeout(r, waitMs))
    }
  }
}

/**
 * Signs and sends a transaction from the gas account and waits for its receipt; throws if it
 * reverts. The caller dry-runs it with eth_call first, as the Python signer does.
 */
export async function sendFromGas(
  ctx: Ctx,
  gasKey: Hex,
  to: Address,
  data: Hex,
  opts: { value?: bigint; onSent?: (hash: Hex) => void } = {},
): Promise<Sent> {
  const account = gasAccount(gasKey)
  const value = opts.value ?? 0n
  const est = await ctx.client.estimateGas({ account: account.address, to, data, value })
  if (est > MAX_TX_GAS) throw new Error(`The node estimates ${est.toLocaleString()} gas, over the ${MAX_TX_GAS.toLocaleString()} transaction cap.`)
  let gas = (est * 12n) / 10n
  if (gas > MAX_TX_GAS) gas = MAX_TX_GAS
  const block = await ctx.client.getBlock({ blockTag: 'latest' })
  const base = block.baseFeePerGas ?? 0n
  let tip: bigint
  try {
    tip = await ctx.client.estimateMaxPriorityFeePerGas()
  } catch {
    tip = 1_000_000_000n
  }
  const cap = base > 1_000_000n ? base : 1_000_000n
  if (tip > cap) tip = cap
  const maxFee = 2n * base + tip
  const balance = await ctx.client.getBalance({ address: account.address })
  if (balance < gas * maxFee + value) {
    throw new GasError(`The gas account ${account.address} holds too little ETH on ${ctx.chain.name} for this (it needs up to ${fmtEth(gas * maxFee + value)} ETH). Fund it from Settings.`)
  }
  const nonce = await ctx.client.getTransactionCount({ address: account.address, blockTag: 'pending' })
  const raw = await account.signTransaction({
    type: 'eip1559',
    chainId: ctx.chain.id,
    nonce,
    to,
    value,
    data,
    gas,
    maxFeePerGas: maxFee,
    maxPriorityFeePerGas: tip,
  })
  const hash = await ctx.client.sendRawTransaction({ serializedTransaction: raw })
  opts.onSent?.(hash)
  const receipt = await ctx.client.waitForTransactionReceipt({ hash, pollingInterval: ctx.chain.id === 42161 ? 1000 : 3000, timeout: 600_000 })
  sawMined(ctx.chain.id, receipt.blockNumber)
  if (receipt.status !== 'success') throw new Error(`The transaction reverted: ${hash}`)
  return { hash, receipt, gasLimit: gas }
}

export class GasError extends Error {}

export function fmtEth(wei: bigint): string {
  const whole = wei / 10n ** 18n
  const frac = (wei % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '')
  return `${whole}${frac ? '.' + frac : ''}`
}

/** Whether `receipt` holds the Safe's ExecutionSuccess for `safeTxHash` (cli.py's execute). */
export function executionResult(receipt: TransactionReceipt, safe: Address, safeTxHash: Hex): 'success' | 'failure' | 'none' {
  let out: 'success' | 'failure' | 'none' = 'none'
  for (const lg of receipt.logs) {
    if (lg.address.toLowerCase() !== safe.toLowerCase()) continue
    try {
      const ev = decodeEventLog({ abi: SAFE_ABI, data: lg.data, topics: lg.topics })
      if ((ev.args as any).txHash?.toLowerCase() !== safeTxHash.toLowerCase()) continue
      if (ev.eventName === 'ExecutionFailure') return 'failure'
      if (ev.eventName === 'ExecutionSuccess') out = 'success'
    } catch {
      /* another event */
    }
  }
  return out
}

export const word32 = (v: Hex) => padHex(v, { size: 32 })
