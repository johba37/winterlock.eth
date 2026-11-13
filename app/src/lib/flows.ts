// What the app does, step by step, following the Python signer (cli.py, cli_devices.py) where it
// has a counterpart. Screens call these; they report progress through `step`.

import { type Address, encodeFunctionData, getAddress, hexToBytes, isAddress, keccak256, padHex, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { CHAINS, chainById, enabledChains } from './chains'
import {
  afterTx,
  type Ctx,
  FACTORY_ABI,
  OWNER_ABI,
  type SafeState,
  factoryAddress,
  executionResult,
  isValidSignature,
  ownerDeployed,
  readDevice,
  readTree,
  safeState,
  sendFromGas,
  short,
  usableCtx,
} from './chain'
import {
  type CertRecord,
  type DeviceRecord,
  type HeldRecord,
  type Hex,
  type StatelessRecord,
  type TreeRecord,
  certs,
  get,
  getDevice,
  putSafe,
  putTree,
  treeId,
  treesFor,
  writeStrict,
} from './db'
import { type Core, Refused, recordThenSign } from './keylog'
import {
  ERC20_ABI,
  MULTISEND,
  SAFE_ABI,
  type SafeTx,
  batchCalls,
  contractSignature,
  decode,
  encodeForCore,
  execCalldata,
  fromService,
  pack,
  parseSignature,
  safeTx,
  signatureDevice,
  stripMetadata,
} from './safe'
import { Service, type ServiceTx, writerFor } from './service'
import { sources, staleLogCheck } from './stale'

export interface Env {
  db: IDBDatabase
  core: Core
}

export type Step = (label: string, progress?: { done: number; total: number }) => void

export const TREE_HEIGHT = 10
export const MAX_DEVICE = 3

/** A member session's calls (client.ts's memberSession, or the tests' stand-in). */
export interface Session {
  call<T>(op: string, args?: unknown, progress?: (done: number, total: number) => void): Promise<T>
  end(): void
}

const hex = (b: Uint8Array) => toHex(b)

async function recordStateless(db: IDBDatabase, rec: Omit<StatelessRecord, 'at'>) {
  await writeStrict(db, 'stateless', [{ ...rec, at: Date.now() }])
}

export function service(chainId: number): Service {
  return new Service(chainById(chainId).service)
}

// --- create and pair ---

interface Derived {
  memberKey: Hex
  owner: Address
  gasKey: Hex
}

async function derive(session: Session, step: Step): Promise<Derived> {
  step('Making your member key from the phrase')
  const d = await session.call<{ memberKey: Uint8Array; owner: Uint8Array; gasKey: Uint8Array }>('derive', {}, (done, total) =>
    step('Making your member key from the phrase', { done, total }),
  )
  const out = { memberKey: hex(d.memberKey), owner: getAddress(hex(d.owner)), gasKey: hex(d.gasKey) }
  d.gasKey.fill(0)
  return out
}

async function newDeviceKey(env: Env, step: Step) {
  step('Making this device’s key')
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const k = await env.core.call<{ publicKey: Uint8Array; keptLeaves: Uint8Array }>('newDeviceKey', { seed }, (done, total) =>
    step('Making this device’s key', { done, total }),
  )
  const out = { seed: hex(seed), publicKey: hex(k.publicKey), keptLeaves: hex(k.keptLeaves) }
  seed.fill(0)
  return out
}

async function certifyWithMemberKey(env: Env, session: Session, chain: number, device: number, generation: number, publicKey: Hex): Promise<CertRecord> {
  await recordStateless(env.db, { kind: 'device-cert', signer: 'member', chain, detail: `device ${device}, generation ${generation}, key ${publicKey}` })
  const sig = await session.call<Uint8Array>('certifyDevice', { chain, device, generation, deviceKey: hexToBytes(publicKey) })
  return { chain, device, generation, key: publicKey, signature: hex(sig), status: 'pending', at: Date.now() }
}

/**
 * Create, after the backup check: the member key, owner address and gas account from the phrase;
 * device key 1 from a fresh seed, certified by the member key on each enabled chain. Then the
 * session ends, which forgets the phrase and the member key. The certificates are sent once the
 * gas account holds ETH (submitCertificates).
 */
export async function createDevice(env: Env, session: Session, step: Step): Promise<DeviceRecord> {
  try {
    if (await getDevice(env.db)) throw new Error('This browser already holds a device.')
    const [d, k] = await Promise.all([derive(session, step), newDeviceKey(env, step)])
    const out: CertRecord[] = []
    for (const c of enabledChains()) {
      step(`Your member key certifies this device on ${c.name}`)
      out.push(await certifyWithMemberKey(env, session, c.id, 1, 1, k.publicKey))
    }
    session.end()
    const rec: DeviceRecord = {
      id: 'this',
      owner: d.owner,
      memberKey: d.memberKey,
      gasKey: d.gasKey,
      gasAddress: getAddress(gasAddressOf(d.gasKey)),
      device: 1,
      ...k,
      how: 'create',
      createdAt: Date.now(),
    }
    await writeStrict(env.db, 'device', [rec])
    await writeStrict(env.db, 'certs', out)
    return rec
  } finally {
    session.end()
  }
}

function gasAddressOf(gasKey: Hex): Address {
  return privateKeyToAccount(gasKey).address
}

/**
 * Pair this device from the phrase: a device key for the next free device number, certified by
 * the member key on each enabled chain, then sent from the gas account. The session ends once the
 * member key has signed.
 */
export async function pairDevice(env: Env, session: Session, step: Step): Promise<{ device: DeviceRecord; report: string[] }> {
  let rec: DeviceRecord
  try {
    if (await getDevice(env.db)) throw new Error('This browser already holds a device.')
    const d = await derive(session, step)
    // the device number: the lowest one that isn't active on any enabled chain
    const gens = new Map<number, number[]>()
    for (const c of enabledChains()) {
      step(`Reading your devices on ${c.name}`)
      const ctx = await usableCtx(env.db, env.core, c.id)
      const deployed = await ownerDeployed(ctx, env.core, d.owner, d.memberKey)
      const states = []
      for (let n = 1; n <= MAX_DEVICE; n++) states.push(deployed ? await readDevice(ctx, d.owner, n) : { key: '0x' as Hex, generation: 0, active: false })
      gens.set(c.id, states.map((s) => (s.active ? -1 : s.generation)))
    }
    let device = 0
    for (let n = 1; n <= MAX_DEVICE && !device; n++) {
      if ([...gens.values()].every((g) => g[n - 1] >= 0)) device = n
    }
    if (!device) throw new Error('All three device numbers are in use. Revoke a device you no longer use (Devices), then pair this one.')
    const k = await newDeviceKey(env, step)
    const out: CertRecord[] = []
    for (const c of enabledChains()) {
      step(`Your member key certifies this device on ${c.name}`)
      out.push(await certifyWithMemberKey(env, session, c.id, device, gens.get(c.id)![device - 1] + 1, k.publicKey))
    }
    session.end()
    rec = { id: 'this', owner: d.owner, memberKey: d.memberKey, gasKey: d.gasKey, gasAddress: gasAddressOf(d.gasKey), device, ...k, how: 'pair', createdAt: Date.now() }
    await writeStrict(env.db, 'device', [rec])
    await writeStrict(env.db, 'certs', out)
  } finally {
    session.end()
  }
  const report = await submitCertificates(env, rec, step)
  return { device: rec, report }
}

/**
 * Sends this device's pending certificates: creates the member's owner first where it doesn't
 * exist (the factory's deploy, as `device certify` does), then certifyDevice. Per chain, a line
 * of what happened.
 */
export async function submitCertificates(env: Env, dev: DeviceRecord, step: Step): Promise<string[]> {
  const report: string[] = []
  for (const cert of await certs(env.db)) {
    const c = chainById(cert.chain)
    if (!c.enabled || cert.status === 'submitted') continue
    try {
      const ctx = await usableCtx(env.db, env.core, c.id)
      let created: { blockNumber: bigint } | undefined
      if (!(await ownerDeployed(ctx, env.core, dev.owner, dev.memberKey))) {
        step(`Creating your owner contract on ${c.name}`)
        const factory = await factoryAddress(env.core)
        const data = encodeFunctionData({ abi: FACTORY_ABI, functionName: 'deploy', args: [dev.memberKey] })
        const { result } = await ctx.client.simulateContract({ account: gasAddressOf(dev.gasKey), address: factory, abi: FACTORY_ABI, functionName: 'deploy', args: [dev.memberKey] })
        if (getAddress(result) !== dev.owner) throw new Error('The factory would create another owner: refusing.')
        const sent = await sendFromGas(ctx, dev.gasKey, factory, data, { onSent: (h) => step(`Creating your owner contract on ${c.name} (${h.slice(0, 10)}…)`) })
        if (!(await afterTx(sent.receipt, (b) => ownerDeployed(ctx, env.core, dev.owner, dev.memberKey, b)))) throw new Error(`The factory's deploy was mined (${sent.hash}), but there is no owner at ${dev.owner}.`)
        report.push(`${c.name}: owner created (${sent.receipt.gasUsed.toLocaleString()} gas, ${sent.hash})`)
        created = sent.receipt
      }
      const now = created ? await afterTx(created, (b) => readDevice(ctx, dev.owner, dev.device, b)) : await readDevice(ctx, dev.owner, dev.device)
      if (now.active && now.key.toLowerCase() === dev.publicKey.toLowerCase()) {
        await writeStrict(env.db, 'certs', [{ ...cert, status: 'submitted' }])
        report.push(`${c.name}: device ${dev.device} is already certified (generation ${now.generation})`)
        continue
      }
      if (now.generation + 1 !== cert.generation) {
        throw new Error(
          `Device ${dev.device} on ${c.name} is at generation ${now.generation}${now.active ? ' with another key' : ''}, so this device's certificate (generation ${cert.generation}) no longer fits. Forget this device and pair it again with your phrase.`,
        )
      }
      step(`Certifying this device on ${c.name}`)
      const data = encodeFunctionData({ abi: OWNER_ABI, functionName: 'certifyDevice', args: [dev.device, cert.generation, dev.publicKey, cert.signature] })
      await ctx.client.call({ account: gasAddressOf(dev.gasKey), to: dev.owner, data }).catch((e) => {
        throw new Error(`certifyDevice would revert: ${short(e)}`)
      })
      const sent = await sendFromGas(ctx, dev.gasKey, dev.owner, data, { onSent: (h) => step(`Certifying this device on ${c.name} (${h.slice(0, 10)}…)`) })
      const after = await afterTx(sent.receipt, (b) => readDevice(ctx, dev.owner, dev.device, b))
      if (!after.active || after.key.toLowerCase() !== dev.publicKey.toLowerCase() || after.generation !== cert.generation) {
        throw new Error(`certifyDevice was mined (${sent.hash}), but device ${dev.device} doesn't read as certified.`)
      }
      await writeStrict(env.db, 'certs', [{ ...cert, status: 'submitted', tx: sent.hash }])
      report.push(`${c.name}: device ${dev.device} certified at generation ${cert.generation} (${sent.receipt.gasUsed.toLocaleString()} gas, ${sent.hash})`)
    } catch (e) {
      report.push(`${c.name}: not yet: ${short(e)}`)
      throw Object.assign(new Error(short(e)), { report })
    }
  }
  return report
}

// --- this device's state on a chain ---

export type DeviceStateKind = 'active' | 'pending' | 'revoked' | 'replaced' | 'no-owner'

export interface DeviceOnChain {
  kind: DeviceStateKind
  generation: number
  text: string
}

/** Whether this device signs on a chain, in words (cli.py's device_state). */
export async function deviceState(env: Env, dev: DeviceRecord, ctx: Ctx): Promise<DeviceOnChain> {
  const cert = await get<CertRecord>(env.db, 'certs', ctx.chain.id)
  if (!(await ownerDeployed(ctx, env.core, dev.owner, dev.memberKey))) {
    return { kind: cert?.status === 'pending' ? 'pending' : 'no-owner', generation: 0, text: `Your owner contract doesn't exist on ${ctx.chain.name} yet.` }
  }
  const s = await readDevice(ctx, dev.owner, dev.device)
  const mine = s.key.toLowerCase() === dev.publicKey.toLowerCase()
  if (mine && s.active) return { kind: 'active', generation: s.generation, text: `Device ${dev.device}, active at generation ${s.generation}.` }
  if (mine) return { kind: 'revoked', generation: s.generation, text: `This device was REVOKED on ${ctx.chain.name}: it signs nothing there. To use it again, forget it here and pair it again with your phrase.` }
  if (cert?.status === 'pending' && s.generation + 1 === cert.generation) {
    return { kind: 'pending', generation: s.generation, text: `This device's certificate hasn't been sent on ${ctx.chain.name} yet.` }
  }
  return { kind: 'replaced', generation: s.generation, text: `Device ${dev.device} on ${ctx.chain.name} now holds another key: this device was replaced and signs nothing there. Forget it here and pair it again with your phrase.` }
}

export async function requireActive(env: Env, dev: DeviceRecord, ctx: Ctx): Promise<number> {
  const s = await deviceState(env, dev, ctx)
  if (s.kind !== 'active') throw new Refused(s.text)
  return s.generation
}

/** The member's devices on a chain, from the owner contract. */
export async function devicesOn(env: Env, dev: DeviceRecord, ctx: Ctx) {
  if (!(await ownerDeployed(ctx, env.core, dev.owner, dev.memberKey))) return null
  const out = []
  for (let n = 1; n <= MAX_DEVICE; n++) out.push({ device: n, ...(await readDevice(ctx, dev.owner, n)) })
  return out
}

// --- Safes ---

export function parseAddress(s: string): Address {
  const t = s.trim().replace(/^[a-z0-9]+:/i, '')
  if (!isAddress(t, { strict: false })) throw new Error('That isn’t an address: 0x and 40 hex digits.')
  const digits = t.slice(2)
  if (/[a-f]/.test(digits) && /[A-F]/.test(digits) && getAddress(t) !== t) throw new Error('The address’s checksum doesn’t match: check for a typo.')
  return getAddress(t)
}

export async function addSafe(env: Env, chainId: number, safe: Address) {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const st = await safeState(ctx, safe)
  await putSafe(env.db, { chain: chainId, safe, addedAt: Date.now() })
  return st
}

export interface SafeView {
  ctx: Ctx
  state: SafeState
  isOwner: boolean
  device: DeviceOnChain
  tree: TreeRecord | null
  treeProblem?: string
  left?: number
  capacity?: number
}

/** Where this member stands with a Safe: owner or not, the device, the key tree and its nonces. */
export async function safeView(env: Env, dev: DeviceRecord, chainId: number, safe: Address): Promise<SafeView> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const state = await safeState(ctx, safe)
  const isOwner = state.owners.some((o) => o.toLowerCase() === dev.owner.toLowerCase())
  const device = await deviceState(env, dev, ctx)
  let tree: TreeRecord | null = null
  let treeProblem: string | undefined
  if (device.kind === 'active') {
    try {
      tree = await signingTree(env, dev, ctx, safe, device.generation)
    } catch (e) {
      treeProblem = (e as Error).message
    }
  }
  const view: SafeView = { ctx, state, isOwner, device, tree, treeProblem }
  if (tree) {
    view.capacity = 2 ** (tree.height - 1)
    view.left = tree.start + view.capacity - Math.max(state.nonce, tree.start)
  }
  return view
}

/** The key log's tree enrolled on-chain for this device and Safe (cli.py's signing_tree). */
export async function signingTree(env: Env, dev: DeviceRecord, ctx: Ctx, safe: Address, generation: number): Promise<TreeRecord> {
  const onchain = await readTree(ctx, dev.owner, safe, dev.device)
  const mine = (await treesFor(env.db, ctx.chain.id, safe)).filter((t) => t.device === dev.device)
  if (!onchain.root) throw new Refused('No key tree is enrolled for this device on this Safe yet: enrol one.')
  if (onchain.generation !== generation) throw new Refused('The key tree enrolled for this device is from before it was certified again: enrol a fresh one.')
  const rec = mine.find((t) => t.root.toLowerCase() === onchain.root!.toLowerCase())
  if (!rec) {
    if (mine.some((t) => t.start > onchain.start && t.generation === generation)) throw new Refused('Your newest key tree isn’t enrolled yet: enrol to send its certificate.')
    throw new Refused(
      `The key tree enrolled for device ${dev.device} (from nonce ${onchain.start}) isn't in this browser's key log: another copy of this device made it. Revoke this device and pair it again.`,
    )
  }
  if (rec.start !== onchain.start || rec.height !== onchain.height || rec.generation !== onchain.generation) {
    throw new Refused('The enrolled key tree differs from the key log: refusing.')
  }
  return rec
}

/**
 * Enrol: a fresh key tree of height 10 (512 nonces) for the Safe, recorded first, certified by
 * this device's key and sent from the gas account (cli.py's enroll).
 */
export async function enrol(env: Env, dev: DeviceRecord, chainId: number, safe: Address, step: Step, height = TREE_HEIGHT): Promise<{ tree: TreeRecord; hash: Hex; gasUsed: bigint }> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const gen = await requireActive(env, dev, ctx)
  const state = await safeState(ctx, safe)
  const onchain = await readTree(ctx, dev.owner, safe, dev.device)
  const sameGen = onchain.root !== null && onchain.generation === gen
  const mine = (await treesFor(env.db, chainId, safe)).filter((t) => t.device === dev.device && t.generation === gen)
  if (sameGen && !mine.some((t) => t.root.toLowerCase() === onchain.root!.toLowerCase())) {
    throw new Refused(
      `The Safe holds a key tree for device ${dev.device} that this browser didn't make: another copy of this device's key is in use. Revoke this device and pair it again.`,
    )
  }
  let tree = mine.filter((t) => !sameGen || t.start > onchain.start).at(-1)
  if (!tree) {
    const start = Math.max(state.nonce, sameGen ? onchain.start + 1 : 0, ...mine.map((t) => t.start + 1))
    const salt = crypto.getRandomValues(new Uint8Array(32))
    step('Making a key tree for this Safe')
    const built = await env.core.call<{ cache: Uint8Array; root: Uint8Array }>(
      'buildTree',
      { seed: hexToBytes(dev.seed), chain: chainId, owner: hexToBytes(dev.owner), safe: hexToBytes(safe), device: dev.device, generation: gen, start, salt, height },
      (done, total) => step('Making a key tree for this Safe', { done, total }),
    )
    tree = {
      id: treeId(chainId, safe, hex(built.root)),
      chain: chainId,
      safe,
      owner: dev.owner,
      device: dev.device,
      generation: gen,
      start,
      height,
      salt: hex(salt),
      root: hex(built.root),
      cache: hex(built.cache),
      createdAt: Date.now(),
    }
    salt.fill(0)
    await putTree(env.db, tree)
  }
  step('This device’s key certifies the key tree')
  await recordStateless(env.db, { kind: 'tree-cert', signer: 'device', chain: chainId, detail: `${safe} root ${tree.root} start ${tree.start} height ${tree.height}` })
  const sig = await env.core.call<Uint8Array>('certifyTree', {
    seed: hexToBytes(dev.seed),
    keptLeaves: hexToBytes(dev.keptLeaves),
    publicKey: hexToBytes(dev.publicKey),
    chain: chainId,
    owner: hexToBytes(dev.owner),
    safe: hexToBytes(safe),
    device: dev.device,
    generation: gen,
    root: hexToBytes(tree.root),
    height: tree.height,
    start: tree.start,
  })
  const data = encodeFunctionData({ abi: OWNER_ABI, functionName: 'enroll', args: [safe, dev.device, padHex(tree.root, { size: 32, dir: 'right' }), tree.height, BigInt(tree.start), hex(sig)] })
  await ctx.client.call({ account: dev.gasAddress, to: dev.owner, data }).catch((e) => {
    throw new Error(`enroll would revert: ${short(e)}`)
  })
  step('Sending the key tree’s certificate')
  const sent = await sendFromGas(ctx, dev.gasKey, dev.owner, data, { onSent: (h) => step(`Sending the key tree’s certificate (${h.slice(0, 10)}…)`) })
  const after = await afterTx(sent.receipt, (b) => readTree(ctx, dev.owner, safe, dev.device, b))
  if (after.root?.toLowerCase() !== tree.root.toLowerCase() || after.start !== tree.start || after.generation !== gen) {
    throw new Error(`enroll was mined (${sent.hash}), but the Safe's tree for this device differs.`)
  }
  tree = { ...tree, enrolTx: sent.hash }
  await putTree(env.db, tree)
  return { tree, hash: sent.hash, gasUsed: sent.receipt.gasUsed }
}

// --- transactions ---

export interface QueueItem {
  tx: SafeTx
  hash: Hex
  hashOk: boolean
  service: ServiceTx
  decoding: ReturnType<typeof decode>
  confirmations: number
  mine: boolean
}

export async function safeTxHash(core: Core, chainId: number, safe: Address, tx: SafeTx): Promise<Hex> {
  return hex(await core.call<Uint8Array>('safeTxHash', { chain: chainId, safe: hexToBytes(safe), tx: encodeForCore(tx) }))
}

/** The Safe's pending transactions from Safe's service, each decoded and its hash checked here. */
export async function queue(env: Env, dev: DeviceRecord, chainId: number, safe: Address, fromNonce: number): Promise<QueueItem[]> {
  const items = await service(chainId).pending(safe, fromNonce)
  const out: QueueItem[] = []
  for (const s of items) {
    let tx: SafeTx
    try {
      tx = fromService(s)
    } catch {
      continue
    }
    const hash = await safeTxHash(env.core, chainId, safe, tx)
    out.push({
      tx,
      hash,
      hashOk: hash.toLowerCase() === s.safeTxHash.toLowerCase(),
      service: s,
      decoding: decode(tx, safe),
      confirmations: (s.confirmations ?? []).length,
      mine: (s.confirmations ?? []).some((c) => c.owner?.toLowerCase() === dev.owner.toLowerCase()),
    })
  }
  return out
}

interface Prepared {
  ctx: Ctx
  state: SafeState
  hash: Hex
  tree: TreeRecord
}

/** A batch delegatecalls MultiSendCallOnly: its code on this chain must be Safe v1.4.1's
 * (safelibs.py). The decoder trusts the canonical address; this checks what is there. */
export async function checkMultiSend(ctx: Ctx): Promise<void> {
  const code = await ctx.client.getCode({ address: MULTISEND.address })
  if (!code || code === '0x') throw new Refused(`There is no MultiSendCallOnly at ${MULTISEND.address} on ${ctx.chain.name}: the app won’t sign a batch here.`)
  if (keccak256(code) !== MULTISEND.codeHash && keccak256(stripMetadata(hexToBytes(code))) !== MULTISEND.codeWithoutMetadataHash) {
    throw new Refused(`The code at ${MULTISEND.address} isn’t Safe’s MultiSendCallOnly v1.4.1: the app won’t sign a delegatecall to it.`)
  }
}

/** The checks before a one-time signature (cli.py's prepare), then the stale-log check. */
async function prepare(env: Env, dev: DeviceRecord, chainId: number, safe: Address, tx: SafeTx, step: Step, expect?: Hex): Promise<Prepared> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  step('Checking the Safe and this device')
  const state = await safeState(ctx, safe)
  if (!state.owners.some((o) => o.toLowerCase() === dev.owner.toLowerCase())) throw new Refused(`Your owner ${dev.owner} isn't an owner of this Safe.`)
  if (tx.nonce < BigInt(state.nonce)) throw new Refused(`Nonce ${tx.nonce} is used already (the Safe is at nonce ${state.nonce}).`)
  const hash = await safeTxHash(env.core, chainId, safe, tx)
  if (expect && hash.toLowerCase() !== expect.toLowerCase()) throw new Refused(`The fields hash to ${hash}, not ${expect}: refusing.`)
  const onchain = await ctx.client.readContract({
    address: safe,
    abi: SAFE_ABI,
    functionName: 'getTransactionHash',
    args: [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, tx.nonce],
  })
  if (onchain.toLowerCase() !== hash.toLowerCase()) throw new Refused(`The Safe computes ${onchain} for these fields, not ${hash}: refusing.`)
  // a batch, from a dapp or from the queue, shows as its calls: the code it delegatecalls must be
  // the MultiSendCallOnly those calls were decoded for
  if (batchCalls(tx)) {
    step('Checking MultiSendCallOnly’s code')
    await checkMultiSend(ctx)
  }
  const gen = await requireActive(env, dev, ctx)
  const tree = await signingTree(env, dev, ctx, safe, gen)
  const cap = 2 ** (tree.height - 1)
  if (tx.nonce < BigInt(tree.start) || tx.nonce >= BigInt(tree.start + cap)) {
    throw new Refused(`Nonce ${tx.nonce} is outside this device's key tree (nonces ${tree.start} to ${tree.start + cap - 1}): enrol a fresh one.`)
  }
  step('Checking for signatures this browser doesn’t know (the stale-log check)')
  await staleLogCheck(env.db, env.core, tree, sources(ctx, service(chainId), safe, tree.start, tree.start + cap))
  return { ctx, state, hash, tree }
}

async function sign(env: Env, dev: DeviceRecord, p: Prepared, tx: SafeTx, step: Step) {
  step('Recording the one-time key’s use, then signing')
  const s = await recordThenSign(env.db, env.core, dev, p.tree, encodeForCore(tx), Number(tx.nonce), p.hash)
  step('Your owner contract checks the signature')
  if (!(await isValidSignature(p.ctx, dev.owner, p.hash, s.data))) throw new Error('Your owner contract refuses the signature (isValidSignature): not sending it.')
  return { ...s, signature: contractSignature(dev.owner, s.data) }
}

/** The next free nonce: after the Safe's, the queue's, and any in `also` (proposals made here that
 * the service may not list yet). */
export async function nextNonce(chainId: number, safe: Address, safeNonce: number, also: number[] = []): Promise<number> {
  const pending = await service(chainId).pending(safe, safeNonce)
  return Math.max(safeNonce, ...pending.map((p) => Number(p.nonce) + 1), ...also.filter((n) => n >= safeNonce).map((n) => n + 1))
}

export interface Transfer {
  to: Address
  amount: bigint
  token?: Address
}

export interface Proposed {
  hash: Hex
  nonce: number
  slot: number
  /** what the kept check found, if the service didn't keep this signature as is */
  note?: string
}

/** Propose a Safe transaction, signed by this device, to Safe's service: the checks, the stale-log
 * check, record then sign, the owner contract's check, the proposal, the kept check. */
export async function proposeTx(env: Env, dev: DeviceRecord, chainId: number, safe: Address, tx: SafeTx, step: Step): Promise<Proposed> {
  const p = await prepare(env, dev, chainId, safe, tx, step)
  const s = await sign(env, dev, p, tx, step)
  step('Proposing it at Safe’s service')
  await writerFor(chainById(chainId).service).propose(safe, tx, p.hash, dev.owner, s.signature)
  const note = await keptCheck(env, dev, chainId, safe, p.hash, s.signature)
  return { hash: p.hash, nonce: Number(tx.nonce), slot: s.slot, note }
}

/** Propose an ETH or ERC-20 transfer, signed by this device, to Safe's service. */
export async function propose(env: Env, dev: DeviceRecord, chainId: number, safe: Address, t: Transfer, step: Step): Promise<Proposed> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const st = await safeState(ctx, safe)
  const nonce = await nextNonce(chainId, safe, st.nonce)
  const tx = t.token
    ? safeTx({ to: t.token, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [t.to, t.amount] }), nonce: BigInt(nonce) })
    : safeTx({ to: t.to, value: t.amount, nonce: BigInt(nonce) })
  return proposeTx(env, dev, chainId, safe, tx, step)
}

/** Confirm a proposal from Safe's service with this device's next one-time key. */
export async function confirm(env: Env, dev: DeviceRecord, chainId: number, safe: Address, hash: Hex, step: Step): Promise<{ note?: string; slot?: number }> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  step('Fetching the proposal')
  const rec = await service(chainId).transaction(hash)
  if (getAddress(rec.safe) !== getAddress(safe)) throw new Refused('That proposal is for another Safe.')
  const tx = fromService(rec)
  // the Safe counts an owner once: another device's valid confirmation is enough
  for (const c of rec.confirmations ?? []) {
    if (c.owner?.toLowerCase() !== dev.owner.toLowerCase() || !c.signature) continue
    const p = parseSignature(c.signature)
    const d = signatureDevice(p.data)
    if (p.contract && (await isValidSignature(ctx, dev.owner, hash, p.data))) {
      return { note: d === dev.device ? 'You already confirmed it from this device.' : `Your owner already confirmed it from device ${d}: the Safe counts each owner once.` }
    }
  }
  const p = await prepare(env, dev, chainId, safe, tx, step, hash)
  const s = await sign(env, dev, p, tx, step)
  step('Sending the confirmation to Safe’s service')
  await writerFor(chainById(chainId).service).confirm(hash, s.signature)
  const note = await keptCheck(env, dev, chainId, safe, hash, s.signature)
  return { note, slot: s.slot }
}

/**
 * After a proposal or confirmation: whether the service holds this signature. It keeps an
 * owner's first confirmation (get_or_create), so after a revoke or a fresh tree it may keep one
 * that no longer counts. Then this device keeps the new signature and uses it when it executes.
 */
async function keptCheck(env: Env, dev: DeviceRecord, chainId: number, safe: Address, hash: Hex, sig: Hex): Promise<string | undefined> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  for (let i = 0; i < 3; i++) {
    const rec = await service(chainId).transaction(hash).catch(() => null)
    const held = rec?.confirmations?.find((c) => c.owner?.toLowerCase() === dev.owner.toLowerCase())?.signature
    if (held && held.toLowerCase() === sig.toLowerCase()) return undefined
    if (held) {
      const p = parseSignature(held)
      if (p.contract && (await isValidSignature(ctx, dev.owner, hash, p.data))) return 'The service holds another confirmation of your owner that counts.'
      const rec2: HeldRecord = { safeTxHash: hash.toLowerCase() as Hex, chain: chainId, safe, signature: sig, at: Date.now() }
      await writeStrict(env.db, 'held', [rec2])
      return 'Safe’s service kept your owner’s earlier confirmation, which no longer counts. Your new signature is kept on this device: execute it from here.'
    }
    await new Promise((r) => setTimeout(r, 1500))
  }
  return 'The service doesn’t show your confirmation yet.'
}

export interface Collected {
  sigs: { owner: Address; data: Uint8Array; contract: boolean }[]
  refused: Address[]
  /** Each signature's data (hex, lower case) and whether it counts now: per signature, since an
   * owner may have one that counts and an older one that doesn't. */
  verdicts: Map<string, boolean>
  /** This owner's signature that the service didn't keep, held on this device. */
  held?: Hex
  threshold: number
  nonce: number
}

/** The signatures that count for a proposal: each owner once, checked by its owner contract. */
export async function collect(env: Env, chainId: number, safe: Address, hash: Hex, rec?: ServiceTx): Promise<Collected> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const st = await safeState(ctx, safe)
  rec ??= await service(chainId).transaction(hash)
  const owners = new Set(st.owners.map((o) => o.toLowerCase()))
  const held = await get<HeldRecord>(env.db, 'held', hash.toLowerCase())
  const found = [...(held ? [{ owner: undefined as Address | undefined, signature: held.signature }] : []), ...(rec.confirmations ?? [])]
  const sigs: Collected['sigs'] = []
  const refused: Address[] = []
  const verdicts = new Map<string, boolean>()
  const counted = new Set<string>()
  for (const c of found) {
    if (!c.signature) continue
    let p
    try {
      p = parseSignature(c.signature)
    } catch {
      continue
    }
    const o = getAddress(p.owner ?? c.owner!)
    if (!owners.has(o.toLowerCase())) continue
    const ok = !p.contract || (await isValidSignature(ctx, o, hash, p.data))
    verdicts.set(toHex(p.data).toLowerCase(), ok)
    if (!ok) {
      refused.push(o)
      continue
    }
    if (counted.has(o.toLowerCase())) continue
    counted.add(o.toLowerCase())
    sigs.push({ owner: o, data: p.data, contract: p.contract })
  }
  return { sigs, refused, verdicts, held: held?.signature, threshold: st.threshold, nonce: st.nonce }
}

/** Execute a fully confirmed transaction, paid by the gas account (cli.py's execute). `onSent` gets
 * the transaction's hash once it is sent, before it is mined. */
export async function execute(env: Env, dev: DeviceRecord, chainId: number, safe: Address, hash: Hex, step: Step, onSent?: (tx: Hex) => void): Promise<{ tx: Hex; gasUsed: bigint }> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  step('Fetching the proposal and its confirmations')
  const rec = await service(chainId).transaction(hash)
  const tx = fromService(rec)
  if ((await safeTxHash(env.core, chainId, safe, tx)).toLowerCase() !== hash.toLowerCase()) throw new Refused('The proposal’s fields don’t hash to its SafeTx hash: refusing.')
  step('Checking each signature with its owner contract')
  const c = await collect(env, chainId, safe, hash, rec)
  if (Number(tx.nonce) !== c.nonce) throw new Error(`The Safe is at nonce ${c.nonce}; this transaction has nonce ${tx.nonce}.`)
  if (c.sigs.length < c.threshold) throw new Error(`${c.sigs.length} valid signature${c.sigs.length === 1 ? '' : 's'} of ${c.threshold} needed.`)
  const blob = pack(c.sigs.sort((a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : 1)).slice(0, c.threshold))
  const data = execCalldata(tx, blob)
  step('Checking that it executes (a dry run)')
  await ctx.client.call({ account: dev.gasAddress, to: safe, data }).catch((e) => {
    throw new Error(`execTransaction would revert: ${short(e)}`)
  })
  step('Executing, paid by your gas account')
  const sent = await sendFromGas(ctx, dev.gasKey, safe, data, {
    onSent: (h) => {
      step(`Executing (${h.slice(0, 10)}…)`)
      onSent?.(h)
    },
  })
  const r = executionResult(sent.receipt, safe, hash)
  if (r === 'failure') throw new Error(`Executed, but the Safe's call failed (ExecutionFailure): ${sent.hash}`)
  if (r !== 'success') throw new Error(`No ExecutionSuccess event in ${sent.hash}`)
  return { tx: sent.hash, gasUsed: sent.receipt.gasUsed }
}

// --- revoking ---

/** Revoke device `target` on every enabled chain where it is active, with the member key from the
 * phrase (cli_devices.py's revoke). */
export async function revokeDevice(env: Env, dev: DeviceRecord, session: Session, target: number, step: Step): Promise<string[]> {
  const report: string[] = []
  try {
    const d = await derive(session, step)
    if (d.owner.toLowerCase() !== dev.owner.toLowerCase()) throw new Refused('That phrase belongs to another member: its owner address isn’t this one.')
    for (const c of enabledChains()) {
      const ctx = await usableCtx(env.db, env.core, c.id)
      if (!(await ownerDeployed(ctx, env.core, dev.owner, dev.memberKey))) {
        report.push(`${c.name}: no owner there, so no device`)
        continue
      }
      const s = await readDevice(ctx, dev.owner, target)
      if (s.generation === 0) {
        report.push(`${c.name}: device ${target} was never certified`)
        continue
      }
      if (!s.active) {
        report.push(`${c.name}: device ${target} is revoked already`)
        continue
      }
      step(`Your member key signs the revocation on ${c.name}`)
      await recordStateless(env.db, { kind: 'revocation', signer: 'member', chain: c.id, detail: `device ${target}, generation ${s.generation}` })
      const sig = await session.call<Uint8Array>('revokeDevice', { chain: c.id, device: target, generation: s.generation })
      const data = encodeFunctionData({ abi: OWNER_ABI, functionName: 'revokeDevice', args: [target, s.generation, hex(sig)] })
      await ctx.client.call({ account: dev.gasAddress, to: dev.owner, data }).catch((e) => {
        throw new Error(`revokeDevice would revert: ${short(e)}`)
      })
      step(`Sending the revocation on ${c.name}`)
      const sent = await sendFromGas(ctx, dev.gasKey, dev.owner, data, { onSent: (h) => step(`Sending the revocation on ${c.name} (${h.slice(0, 10)}…)`) })
      if ((await afterTx(sent.receipt, (b) => readDevice(ctx, dev.owner, target, b))).active) throw new Error(`revokeDevice was mined (${sent.hash}), but device ${target} still reads as active.`)
      report.push(`${c.name}: device ${target} REVOKED at generation ${s.generation} (${sent.hash})`)
    }
  } finally {
    session.end()
  }
  return report
}

// --- small reads ---

export async function tokenInfo(ctx: Ctx, token: Address): Promise<{ symbol: string; decimals: number }> {
  const [symbol, decimals] = await Promise.all([
    ctx.client.readContract({ address: token, abi: ERC20_ABI, functionName: 'symbol' }).catch(() => 'tokens'),
    ctx.client.readContract({ address: token, abi: ERC20_ABI, functionName: 'decimals' }),
  ])
  return { symbol, decimals: Number(decimals) }
}

export const allChains = CHAINS
