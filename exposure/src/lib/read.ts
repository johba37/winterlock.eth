// Reading a Safe and its owners: chain reads through a viem client (any transport, so tests run
// on a fake one), and owners' signatures from Safe's Transaction Service through SafeService
// (any fetch). Every chain read is made at one block. The service is read only for a Safe with
// a key owner that hasn't sent a transaction: for every other owner the chain already settles it.

import { type Address, type Hex, type PublicClient, createPublicClient, custom, getAddress, isAddressEqual, keccak256, parseAbi, sliceHex } from 'viem'
import type { Token } from './chains'
import { PASSKEY_FACTORIES, PASSKEY_SHARED_SIGNER, PROXY_CODE_HASHES, SENTINEL, SLOTS, officialSingleton } from './known'
import { changesFor, classify, verdictOf } from './model'
import { SafeService, type ServiceOptions } from './service'
import type { Balances, Limit, OwnerFacts, OwnerReport, SafeReport } from './types'
import { memberKeyOf } from './winterlock'

const SAFE_ABI = parseAbi([
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function getModulesPaginated(address start, uint256 pageSize) view returns (address[] array, address next)',
  'function getModules() view returns (address[])',
])
const ERC20_ABI = parseAbi(['function balanceOf(address owner) view returns (uint256)'])
const PASSKEY_SIGNER_ABI = parseAbi(['function getConfiguration() view returns (uint256 x, uint256 y, uint176 verifiers)'])
const PASSKEY_FACTORY_ABI = parseAbi(['function getSigner(uint256 x, uint256 y, uint176 verifiers) view returns (address)'])
const SHARED_SIGNER_ABI = parseAbi(['function getConfiguration(address account) view returns ((uint256 x, uint256 y, uint176 verifiers) signer)'])

const MODULES_PAGE = 10n

export interface CheckOptions {
  /** A viem public client for the Safe's chain; JSON-RPC batching keeps the requests few. Only
   * its endpoint is used: the check makes its own client on it, with CCIP-Read off. */
  client: PublicClient
  /** The chain the Safe is on; the client's endpoint must answer this chain ID. */
  chainId: number
  /** Safe's Transaction Service, or null to skip it (keys that haven't sent a transaction then
   * stay "not known to be exposed", with the service marked as not read). */
  service: ServiceOptions | SafeService | null
  /** Tokens whose balances to show for the looked-up Safe. */
  tokens?: readonly Token[]
  /** How deep to follow Safes that own Safes. Default 3. */
  maxDepth?: number
  /** How many Safes to read in all, the looked-up one included. Default 10. */
  maxSafes?: number
  /** Blocks behind the latest to read at, so that every node behind a load balancer has it. Default 2. */
  lag?: number
  onProgress?: (step: string) => void
}

export type CheckErrorCode = 'wrong-chain' | 'no-contract' | 'not-a-safe' | 'rpc'

export class CheckError extends Error {
  constructor(
    readonly code: CheckErrorCode,
    message: string,
  ) {
    super(message)
  }
}

interface Context {
  client: PublicClient
  chainId: number
  service: SafeService | null
  tokens: readonly Token[]
  maxDepth: number
  maxSafes: number
  blockNumber: bigint
  safesRead: number
  /** Safes read to the end; pending ones aren't shared, so that two Safes owning each other
   * can't wait on each other. */
  cache: Map<string, SafeReport>
  progress: (step: string) => void
}

/** Reads a Safe, its owners and (within the limits) the Safes among them, and gives the verdict. */
export async function checkSafe(address: Address, options: CheckOptions): Promise<SafeReport> {
  // the caller's endpoint (and its batching and retries), with CCIP-Read (EIP-3668) off: the
  // contracts read here may be anyone's, and a revert with OffchainLookup would otherwise make
  // the client fetch a URL of the contract's choosing
  const client = createPublicClient({ transport: custom({ request: options.client.request }, { retryCount: 0 }), ccipRead: false })
  const progress = options.onProgress ?? (() => {})
  progress('Checking the network')
  let chainId: number
  let latest: bigint
  try {
    ;[chainId, latest] = await Promise.all([client.getChainId(), client.getBlockNumber()])
  } catch (e) {
    throw new CheckError('rpc', `The RPC endpoint didn’t answer (${short(e)})`)
  }
  if (chainId !== options.chainId) throw new CheckError('wrong-chain', `The RPC endpoint is for chain ${chainId}, not ${options.chainId}`)
  const lag = BigInt(Math.max(0, options.lag ?? 2))
  const service = options.service == null ? null : options.service instanceof SafeService ? options.service : new SafeService(options.service)
  const ctx: Context = {
    client,
    chainId,
    service,
    tokens: options.tokens ?? [],
    maxDepth: options.maxDepth ?? 3,
    maxSafes: options.maxSafes ?? 10,
    blockNumber: latest > lag ? latest - lag : latest,
    safesRead: 0,
    cache: new Map(),
    progress,
  }
  return readSafe(ctx, getAddress(address), 0, [])
}

function short(e: unknown): string {
  const m = (e as { shortMessage?: string; message?: string })?.shortMessage ?? (e as Error)?.message ?? String(e)
  return m.split('\n')[0].slice(0, 200)
}

const settled = <T>(p: Promise<T>) => p.then((value) => ({ ok: true as const, value }), (error: unknown) => ({ ok: false as const, error }))

function slotAddress(word: Hex | undefined): Address | null {
  if (!word || /^0x0*$/.test(word)) return null
  return getAddress(sliceHex(word.padEnd(66, '0') as Hex, 12, 32))
}

async function readSafe(ctx: Context, address: Address, depth: number, path: readonly Address[]): Promise<SafeReport> {
  const cached = ctx.cache.get(address.toLowerCase())
  if (cached) return cached
  const report = await readSafeOnce(ctx, address, depth, path)
  ctx.cache.set(address.toLowerCase(), report)
  return report
}

async function readSafeOnce(ctx: Context, address: Address, depth: number, path: readonly Address[]): Promise<SafeReport> {
  const { client, blockNumber } = ctx
  ctx.safesRead++
  ctx.progress(depth === 0 ? 'Reading the Safe' : `Reading the Safe ${address} that owns it`)
  const call = <T>(fn: () => Promise<T>) => settled(fn())
  const safeRead = (functionName: 'getOwners' | 'getThreshold' | 'nonce') =>
    call(() => client.readContract({ address, abi: SAFE_ABI, functionName, blockNumber }) as Promise<unknown>)
  const [code, slot0, owners, threshold, nonce, guard, fallbackHandler, moduleGuard, modules, balances] = await Promise.all([
    call(() => client.getCode({ address, blockNumber })),
    call(() => client.getStorageAt({ address, slot: SLOTS.singleton, blockNumber })),
    safeRead('getOwners'),
    safeRead('getThreshold'),
    safeRead('nonce'),
    call(() => client.getStorageAt({ address, slot: SLOTS.guard, blockNumber })),
    call(() => client.getStorageAt({ address, slot: SLOTS.fallbackHandler, blockNumber })),
    call(() => client.getStorageAt({ address, slot: SLOTS.moduleGuard, blockNumber })),
    call(() => client.readContract({ address, abi: SAFE_ABI, functionName: 'getModulesPaginated', args: [SENTINEL, MODULES_PAGE], blockNumber })),
    depth === 0 ? readBalances(ctx, address) : Promise.resolve(null),
  ])
  if (!code.ok) throw new CheckError('rpc', `The RPC endpoint didn’t answer (${short(code.error)})`)
  if (!code.value || code.value === '0x') throw new CheckError('no-contract', 'There is no contract at this address on this network')
  if (!owners.ok || !threshold.ok) throw new CheckError('not-a-safe', 'This contract doesn’t answer as a Safe (getOwners, getThreshold)')
  // storage reads don't revert: a failure is the endpoint's, and a wrong blank would mislead
  for (const r of [slot0, guard, fallbackHandler, moduleGuard]) if (!r.ok) throw new CheckError('rpc', `The RPC endpoint didn’t answer (${short(r.error)})`)

  const proxyVersion = PROXY_CODE_HASHES[keccak256(code.value)]
  const singletonAddress = slot0.ok ? slotAddress(slot0.value) : null
  const singleton = singletonAddress ? officialSingleton(ctx.chainId, singletonAddress) : undefined
  const official = { proxy: proxyVersion !== undefined, singleton: singleton !== undefined }
  const limits: Limit[] = []

  let moduleList: Address[]
  let modulesComplete = true
  if (modules.ok) {
    const [array, next] = modules.value
    moduleList = [...array]
    if (!isAddressEqual(next, SENTINEL) && !/^0x0{40}$/.test(next)) {
      modulesComplete = false
      limits.push({ type: 'modules-page', safe: address, shown: moduleList.length })
    }
  } else if (singleton?.version === '1.0.0') {
    const all = await settled(client.readContract({ address, abi: SAFE_ABI, functionName: 'getModules', blockNumber }))
    if (!all.ok) throw new CheckError('rpc', `Couldn’t read the Safe’s modules (${short(all.error)})`)
    moduleList = [...all.value]
  } else if (official.proxy && official.singleton) {
    throw new CheckError('rpc', `Couldn’t read the Safe’s modules (${short(modules.error)})`)
  } else {
    // not an official Safe: the verdict is "can't tell" anyway
    moduleList = []
    modulesComplete = false
  }

  const ownerList = (owners.value as readonly Address[]).map((o) => getAddress(o))
  const t = Number(threshold.value as bigint)
  ctx.progress(depth === 0 ? `Reading ${ownerList.length} owner${ownerList.length === 1 ? '' : 's'}` : `Reading the owners of ${address}`)
  const facts = await Promise.all(ownerList.map((o) => readOwner(ctx, address, o, depth, [...path, address], limits)))

  // the service, only if a key's class depends on it
  let service: SafeReport['service'] = null
  if (facts.some((f) => f.kind === 'key' && f.nonce === 0)) {
    if (ctx.service) {
      ctx.progress(`Reading signatures for ${depth === 0 ? 'the Safe' : address} at Safe’s Transaction Service`)
      const s = await ctx.service.signatures(address)
      service = s.summary
      for (const c of s.capped) {
        limits.push({ type: 'service-cap', safe: address, list: c.list, read: c.read, total: c.total, pages: s.summary.maxPages, pageSize: s.summary.pageSize })
      }
      if (s.error) limits.push({ type: 'service-unavailable', safe: address, reason: s.error.reason, detail: s.error.detail })
      const nothingRead = s.error !== undefined && s.summary.transactions.read + s.summary.messages.read === 0
      ownerList.forEach((o, i) => {
        const f = facts[i]
        if (f.kind === 'key') f.signatures = nothingRead ? null : (s.bySigner.get(o.toLowerCase()) ?? { byType: {} })
      })
    } else {
      limits.push({ type: 'service-unavailable', safe: address, reason: 'failed', detail: 'not asked' })
      for (const f of facts) if (f.kind === 'key') f.signatures = null
    }
  }

  const ownerReports: OwnerReport[] = ownerList.map((a, i) => ({ address: a, facts: facts[i], class: classify(facts[i]) }))
  const verdict = verdictOf({
    threshold: t,
    classes: ownerReports.map((o) => o.class),
    modules: moduleList.length,
    official: official.proxy && official.singleton,
  })
  return {
    chainId: ctx.chainId,
    address,
    block: blockNumber,
    singleton: singletonAddress ?? '0x0000000000000000000000000000000000000000',
    version: official.proxy && singleton ? singleton.version : null,
    l2: singleton?.l2 ?? false,
    official,
    threshold: t,
    nonce: nonce.ok ? (nonce.value as bigint) : null,
    owners: ownerReports,
    modules: moduleList,
    modulesComplete,
    guard: guard.ok ? slotAddress(guard.value) : null,
    moduleGuard: moduleGuard.ok ? slotAddress(moduleGuard.value) : null,
    fallbackHandler: fallbackHandler.ok ? slotAddress(fallbackHandler.value) : null,
    balances,
    verdict,
    changes: changesFor(verdict),
    limits,
    service,
    depth,
  }
}

async function readBalances(ctx: Context, address: Address): Promise<Balances | null> {
  const { client, blockNumber } = ctx
  const [native, ...tokens] = await Promise.all([
    settled(client.getBalance({ address, blockNumber })),
    ...ctx.tokens.map((token) => settled(client.readContract({ address: token.address, abi: ERC20_ABI, functionName: 'balanceOf', args: [address], blockNumber }))),
  ])
  if (!native.ok) return null
  return {
    native: native.value as bigint,
    tokens: ctx.tokens.map((token, i) => ({ token, balance: tokens[i].ok ? (tokens[i].value as bigint) : null })),
  }
}

async function readOwner(ctx: Context, safe: Address, owner: Address, depth: number, path: readonly Address[], limits: Limit[]): Promise<OwnerFacts> {
  const { client, blockNumber } = ctx
  const [code, nonce] = await Promise.all([
    settled(client.getCode({ address: owner, blockNumber })),
    settled(client.getTransactionCount({ address: owner, blockNumber })),
  ])
  if (!code.ok) return { kind: 'unread', error: short(code.error) }
  if (!nonce.ok) return { kind: 'unread', error: short(nonce.error) }
  const c = (code.value ?? '0x').toLowerCase() as Hex
  if (c === '0x') return { kind: 'key', nonce: nonce.value }
  // EIP-7702: 0xef0100 followed by the delegate's address
  if (c.length === 2 + 23 * 2 && c.startsWith('0xef0100')) return { kind: 'delegated-key', nonce: nonce.value, delegate: getAddress(`0x${c.slice(8)}`) }
  const memberKey = memberKeyOf(owner, c)
  if (memberKey) return { kind: 'winterlock', memberKey }
  if (isAddressEqual(owner, PASSKEY_SHARED_SIGNER)) {
    const r = await settled(client.readContract({ address: owner, abi: SHARED_SIGNER_ABI, functionName: 'getConfiguration', args: [safe], blockNumber }))
    if (r.ok) return { kind: 'passkey-shared', configured: r.value.verifiers !== 0n, x: r.value.x, y: r.value.y }
  }
  const passkey = await passkeyOf(ctx, owner, c)
  if (passkey) return passkey
  if (PROXY_CODE_HASHES[keccak256(c)] !== undefined) {
    if (path.some((p) => isAddressEqual(p, owner))) {
      limits.push({ type: 'cycle', safe, owner })
      return { kind: 'cycle' }
    }
    if (depth + 1 > ctx.maxDepth) {
      limits.push({ type: 'depth', safe, owner, maxDepth: ctx.maxDepth })
      return { kind: 'not-read', why: 'depth' }
    }
    if (!ctx.cache.has(owner.toLowerCase()) && ctx.safesRead >= ctx.maxSafes) {
      limits.push({ type: 'safes-cap', safe, owner, maxSafes: ctx.maxSafes })
      return { kind: 'not-read', why: 'safes-cap' }
    }
    try {
      return { kind: 'safe', report: await readSafe(ctx, owner, depth + 1, path) }
    } catch (e) {
      if (!(e instanceof CheckError) || e.code !== 'not-a-safe') return { kind: 'unread', error: short(e) }
    }
  }
  return { kind: 'contract', size: (c.length - 2) / 2, codeHash: keccak256(c) }
}

/** Safe's passkey signer: code that holds a factory's singleton as an immutable, whose
 * configuration (x, y, verifiers) the factory maps to this very address. */
async function passkeyOf(ctx: Context, owner: Address, code: Hex): Promise<OwnerFacts | null> {
  const factory = PASSKEY_FACTORIES.find((f) => code.includes(f.singleton.slice(2).toLowerCase()))
  if (!factory) return null
  const { client, blockNumber } = ctx
  const config = await settled(client.readContract({ address: owner, abi: PASSKEY_SIGNER_ABI, functionName: 'getConfiguration', blockNumber }))
  if (!config.ok) return null
  const [x, y, verifiers] = config.value
  const signer = await settled(client.readContract({ address: factory.address, abi: PASSKEY_FACTORY_ABI, functionName: 'getSigner', args: [x, y, verifiers], blockNumber }))
  if (!signer.ok || !isAddressEqual(signer.value, owner)) return null
  return { kind: 'passkey', factoryVersion: factory.version, x, y }
}
