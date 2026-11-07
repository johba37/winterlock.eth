// The chain: reads, the owner contract's views, and transactions from the gas account.
//
// The gas account is an ordinary account whose key comes from the phrase (core: derive::gas_key),
// so every paired device holds the same one. It pays for the owner's deployment, certificates,
// enrolments and executions. Fees follow the Python signer (ethtx.py's send): a gas limit of the
// node's estimate × 1.2 under EIP-7825's cap, a fee cap of twice the base fee plus the tip.
// No log scans: free RPC tiers limit them (10 blocks on Alchemy's, 2.5 s on Arbitrum).

import {
  type Address,
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

export async function readDevice(ctx: Ctx, owner: Address, device: number): Promise<DeviceState> {
  const [key, generation, active] = await ctx.client.readContract({ address: owner, abi: OWNER_ABI, functionName: 'devices', args: [device] })
  return { key, generation, active }
}

export interface OnchainTree {
  root: Hex | null
  height: number
  start: number
  generation: number
}

export async function readTree(ctx: Ctx, owner: Address, safe: Address, device: number): Promise<OnchainTree> {
  const [root, , height, start, generation] = await ctx.client.readContract({ address: owner, abi: OWNER_ABI, functionName: 'tree', args: [safe, device] })
  if (BigInt(root) === 0n) return { root: null, height: 0, start: 0, generation: 0 }
  return { root: toHex(hexToBytes(root).slice(0, 24)), height, start: Number(start), generation }
}

/** Whether the member's owner exists here: the code at its address must be the v2 proxy of the
 * pinned implementation with this member key (cli.py's owner_deployed). */
export async function ownerDeployed(ctx: Ctx, core: Core, owner: Address, memberKey: Hex): Promise<boolean> {
  const code = await ctx.client.getCode({ address: owner })
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

export async function safeState(ctx: Ctx, safe: Address): Promise<SafeState> {
  const code = await ctx.client.getCode({ address: safe })
  if (!code || code === '0x') throw new Error(`There is no Safe at ${safe} on ${ctx.chain.name}.`)
  const [nonce, threshold, owners, version] = await Promise.all([
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'nonce' }),
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getThreshold' }),
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getOwners' }),
    ctx.client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'VERSION' }).catch(() => '?'),
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
