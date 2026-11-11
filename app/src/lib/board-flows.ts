// The app's flows with a board (docs/notes/signer-app.md, decision 7): the board holds the member
// key (device 0), its key trees and their key log, and signs every enrolment and confirmation
// after showing it. The app reads the chain and Safe's service, sends what the board signed from
// the gas account, and holds no key but the gas key the board gives it.
//
// No device keys here: no pairing or revoking, no stale-log check (the key log is the board's
// own), no messages, no dapps. Proposing, collecting and executing are flows.ts's.

import { type Address, encodeFunctionData, getAddress, hexToBytes, padHex, parseAbi, size, slice, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { type BoardClient, type BoardStatus, type BoardTree, type Identity, type Waiting } from '../board/client'
import { chainById } from './chains'
import { type Ctx, FACTORY_ABI, OWNER_ABI, type OnchainTree, type SafeState, factoryAddress, isValidSignature, ownerDeployed, readTree, safeState, sendFromGas, short, usableCtx } from './chain'
import { type BoardRecord, type Hex, type PendingEnrolment, getDevice, hasMember, putSetting, setting, writeStrict } from './db'
import { type Env, type Step, type Transfer, keptCheck, nextNonce, safeTxHash, service } from './flows'
import { Refused } from './keylog'
import { ERC20_ABI, SAFE_ABI, type SafeTx, contractSignature, encodeForCore, fromService, parseSignature, safeTx } from './safe'
import { writerFor } from './service'

const APPROVE_HASH = '0xd4d9bdcd'
const APPROVE_ABI = parseAbi(['function approveHash(bytes32 hashToApprove)'])

// --- the board as the member ---

/** Why this board can't be this member's, or null. */
export function boardMismatch(rec: BoardRecord, s: BoardStatus): string | null {
  if (s.state === 'blank') return 'This board is blank (erased, or new): recover it on the board with your 24 words.'
  if (s.state === 'damaged') return 'The board’s storage is damaged: it signs nothing. Erase it from its menu, then recover it with your 24 words.'
  if (s.memberKey?.toLowerCase() !== rec.memberKey.toLowerCase()) return `This board holds another member key (owner ${s.owner}), not yours (owner ${rec.owner}).`
  return null
}

/**
 * Takes an unlocked board as this browser's member: its member key and owner address, and its gas
 * key (GAS_KEY), checked against the owner the core computes for the member key.
 */
export async function adoptBoard(env: Env, client: BoardClient, linkKind: 'serial' | 'virtual', how: BoardRecord['how'], id?: Identity): Promise<BoardRecord> {
  if (await getDevice(env.db)) throw new Error('This browser already holds a device key: forget it first (Devices) to use a board here.')
  const s = await client.status()
  if (s.state === 'locked') throw new Refused('Enter your PIN on the board first.')
  if (s.state !== 'unlocked' || !s.memberKey || !s.owner) throw new Refused('The board isn’t set up.')
  if (id && (id.memberKey.toLowerCase() !== s.memberKey.toLowerCase() || id.owner !== s.owner)) throw new Error('The board reports another identity than it just gave: refusing.')
  const computed = getAddress(toHex(await env.core.call<Uint8Array>('ownerAddress', { memberKey: hexToBytes(s.memberKey) })))
  if (computed !== s.owner) throw new Error(`The board’s owner address ${s.owner} isn’t its member key’s (${computed}): refusing.`)
  const key = await client.gasKey()
  const gasKey = toHex(key)
  key.fill(0)
  const rec: BoardRecord = {
    id: 'this',
    kind: 'board',
    link: linkKind,
    owner: s.owner,
    memberKey: s.memberKey,
    gasKey,
    gasAddress: privateKeyToAccount(gasKey).address,
    how,
    createdAt: Date.now(),
  }
  await writeStrict(env.db, 'device', [rec])
  return rec
}

/** Setup on the board, with 32 random bytes from this browser mixed into the seed. */
export async function setupBoard(env: Env, client: BoardClient, linkKind: 'serial' | 'virtual', w: Waiting): Promise<BoardRecord> {
  if (await hasMember(env.db)) throw new Error('This browser already holds a device or a board.')
  const r = crypto.getRandomValues(new Uint8Array(32))
  const id = await client.setup(r, w)
  r.fill(0)
  return adoptBoard(env, client, linkKind, 'setup', id)
}

export async function recoverBoard(env: Env, client: BoardClient, linkKind: 'serial' | 'virtual', w: Waiting, expect?: BoardRecord): Promise<BoardRecord> {
  const id = await client.recover(w)
  if (expect && id.memberKey.toLowerCase() !== expect.memberKey.toLowerCase()) {
    throw new Error(`Those words give another member (owner ${id.owner}), not yours (${expect.owner}). The board now holds them; erase it from its menu to try again.`)
  }
  return adoptBoard(env, client, linkKind, 'recover', id)
}

/** After a reconnect: the same board, unlocked, and the same gas key. */
export async function checkBoard(rec: BoardRecord, client: BoardClient): Promise<BoardStatus> {
  const s = await client.status()
  const m = boardMismatch(rec, s)
  if (m) throw new Refused(m)
  if (s.state !== 'unlocked') throw new Refused('Enter your PIN on the board first.')
  return s
}

// --- a Safe ---

export interface BoardSafeView {
  ctx: Ctx
  state: SafeState
  isOwner: boolean
  deployed: boolean
  /** the member key's tree enrolled on-chain for this Safe (device 0) */
  onchain: OnchainTree
  /** the board's trees for this Safe and chain, if the board is connected and unlocked */
  boardTrees: BoardTree[] | null
  /** the board's tree that is enrolled on-chain */
  tree: BoardTree | null
  /** a certificate the board signed that the gas account hasn't sent yet */
  pending: PendingEnrolment | null
  treeProblem?: string
  left?: number
  capacity?: number
}

const enrolKey = (chain: number, safe: Address) => `board-enrolment:${chain}:${safe.toLowerCase()}`

const NO_TREE: OnchainTree = { root: null, height: 0, start: 0, generation: 0 }

export async function boardSafeView(env: Env, rec: BoardRecord, chainId: number, safe: Address, client: BoardClient | null): Promise<BoardSafeView> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const state = await safeState(ctx, safe)
  const isOwner = state.owners.some((o) => o.toLowerCase() === rec.owner.toLowerCase())
  const deployed = await ownerDeployed(ctx, env.core, rec.owner, rec.memberKey)
  const onchain = deployed ? await readTree(ctx, rec.owner, safe, 0) : NO_TREE
  let boardTrees: BoardTree[] | null = null
  if (client) {
    try {
      boardTrees = (await client.trees()).filter((t) => t.chain === chainId && t.safe.toLowerCase() === safe.toLowerCase())
    } catch {
      /* locked or busy: shown as unknown */
    }
  }
  const tree = (onchain.root && boardTrees?.find((t) => t.root.toLowerCase() === onchain.root!.toLowerCase())) || null
  const pending = (await setting<PendingEnrolment>(env.db, enrolKey(chainId, safe))) ?? null
  const view: BoardSafeView = { ctx, state, isOwner, deployed, onchain, boardTrees, tree, pending }
  if (onchain.root) {
    view.capacity = 2 ** (onchain.height - 1)
    view.left = onchain.start + view.capacity - Math.max(state.nonce, onchain.start)
    if (boardTrees && !tree) view.treeProblem = 'The key tree enrolled for your owner on this Safe isn’t on this board (a recovered board can’t rebuild its keys): enrol a new one.'
  }
  return view
}

/**
 * Enrol: the board makes a height-10 key tree for the Safe and signs its certificate with the
 * member key after the member confirms; the gas account sends it (enroll, or deployAndEnroll when
 * the owner contract doesn't exist yet: the first enrolment creates it). A certificate the board
 * signed is kept until it is sent, so a failed send can be retried without the board.
 */
export async function boardEnrol(env: Env, rec: BoardRecord, client: BoardClient, chainId: number, safe: Address, step: Step, w: Waiting): Promise<{ start: number; height: number; hash: Hex; gasUsed: bigint; created: boolean }> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const state = await safeState(ctx, safe)
  const deployed = await ownerDeployed(ctx, env.core, rec.owner, rec.memberKey)
  const onchain = deployed ? await readTree(ctx, rec.owner, safe, 0) : NO_TREE
  let p = await setting<PendingEnrolment>(env.db, enrolKey(chainId, safe))
  if (p && onchain.root && p.start <= onchain.start) {
    // sent already, or overtaken by a later tree
    await putSetting(env.db, enrolKey(chainId, safe), null)
    p = undefined
  }
  if (!p) {
    await checkBoard(rec, client)
    const mine = (await client.trees()).filter((t) => t.chain === chainId && t.safe.toLowerCase() === safe.toLowerCase())
    const start = Math.max(state.nonce, onchain.root ? onchain.start + 1 : 0, ...mine.map((t) => t.start + 1))
    step('Check the board: it shows the Safe, the network and the first nonce. Confirm there (hold both buttons). Then it makes the key tree and signs its certificate, about a minute on the board')
    const e = await client.enrol(chainId, safe, start, w)
    if (e.chain !== chainId || e.safe.toLowerCase() !== safe.toLowerCase() || e.start !== start) throw new Error('The board enrolled another place than asked: refusing.')
    step('Checking the certificate with your member key')
    const ok = await env.core.call<boolean>('certificateValid', {
      memberKey: hexToBytes(rec.memberKey),
      chain: chainId,
      owner: hexToBytes(rec.owner),
      safe: hexToBytes(safe),
      root: hexToBytes(e.root),
      height: e.height,
      start: e.start,
      signature: e.signature,
    })
    if (!ok) throw new Error('The board’s certificate doesn’t verify against your member key: not sending it.')
    p = { chain: chainId, safe, start: e.start, height: e.height, root: e.root, signature: toHex(e.signature), at: Date.now() }
    await putSetting(env.db, enrolKey(chainId, safe), p)
  }
  const root32 = padHex(p.root, { size: 32, dir: 'right' })
  let to: Address
  let data: Hex
  if (deployed) {
    to = rec.owner
    data = encodeFunctionData({ abi: OWNER_ABI, functionName: 'enroll', args: [safe, 0, root32, p.height, BigInt(p.start), p.signature] })
    await ctx.client.call({ account: rec.gasAddress, to, data }).catch((e) => {
      throw new Error(`enroll would revert: ${short(e)}`)
    })
  } else {
    to = await factoryAddress(env.core)
    data = encodeFunctionData({ abi: FACTORY_ABI, functionName: 'deployAndEnroll', args: [rec.memberKey, safe, root32, p.height, BigInt(p.start), p.signature] })
    const { result } = await ctx.client
      .simulateContract({ account: rec.gasAddress, address: to, abi: FACTORY_ABI, functionName: 'deployAndEnroll', args: [rec.memberKey, safe, root32, p.height, BigInt(p.start), p.signature] })
      .catch((e) => {
        throw new Error(`deployAndEnroll would revert: ${short(e)}`)
      })
    if (getAddress(result) !== getAddress(rec.owner)) throw new Error('The factory would create another owner: refusing.')
  }
  const what = deployed ? 'the key tree’s certificate' : 'your owner contract and the key tree’s certificate'
  step(`Sending ${what}, paid by your gas account`)
  const sent = await sendFromGas(ctx, rec.gasKey, to, data, { onSent: (h) => step(`Sending ${what} (${h.slice(0, 10)}…)`) })
  const after = await readTree(ctx, rec.owner, safe, 0)
  if (after.root?.toLowerCase() !== p.root.toLowerCase() || after.start !== p.start) throw new Error(`The enrolment was mined (${sent.hash}), but the Safe’s tree for your owner differs.`)
  await putSetting(env.db, enrolKey(chainId, safe), null)
  return { start: p.start, height: p.height, hash: sent.hash, gasUsed: sent.receipt.gasUsed, created: !deployed }
}

// --- transactions ---

/** approveHash(bytes32)'s argument, if `tx` is that call. */
export function approveHashOf(tx: SafeTx): Hex | null {
  if (tx.operation !== 0 || tx.value !== 0n || size(tx.data) !== 36 || slice(tx.data, 0, 4).toLowerCase() !== APPROVE_HASH) return null
  return slice(tx.data, 4, 36)
}

/** The parent Safe's transaction an approveHash approves: its fields from Safe's service, checked
 * here to hash to the argument. The board checks them again. */
export async function parentOf(env: Env, chainId: number, tx: SafeTx): Promise<SafeTx | null> {
  const h = approveHashOf(tx)
  if (!h) return null
  const rec = await service(chainId)
    .transaction(h)
    .catch(() => {
      throw new Refused(`This approves transaction ${h.slice(0, 10)}… of the Safe at ${tx.to}, which Safe’s service doesn’t know: the board needs its fields to show it.`)
    })
  if (getAddress(rec.safe) !== getAddress(tx.to)) throw new Refused('The approved transaction belongs to another Safe than the one called: refusing.')
  const parent = fromService(rec)
  if ((await safeTxHash(env.core, chainId, tx.to, parent)).toLowerCase() !== h.toLowerCase()) throw new Refused('The parent transaction’s fields don’t hash to the approved hash: refusing.')
  return parent
}

interface Prepared {
  ctx: Ctx
  hash: Hex
  root: Hex
}

/** The checks before the board signs: owner, nonce, the hash computed here and by the Safe, the
 * tree enrolled on-chain and on the board. */
async function prepare(env: Env, rec: BoardRecord, client: BoardClient, chainId: number, safe: Address, tx: SafeTx, step: Step, expect?: Hex): Promise<Prepared> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  step('Checking the Safe, your owner and the board')
  const state = await safeState(ctx, safe)
  if (!state.owners.some((o) => o.toLowerCase() === rec.owner.toLowerCase())) throw new Refused(`Your owner ${rec.owner} isn't an owner of this Safe.`)
  if (tx.nonce < BigInt(state.nonce)) throw new Refused(`Nonce ${tx.nonce} is used already (the Safe is at nonce ${state.nonce}).`)
  const hash = await safeTxHash(env.core, chainId, safe, tx)
  if (expect && hash.toLowerCase() !== expect.toLowerCase()) throw new Refused(`The fields hash to ${hash}, not ${expect}: refusing.`)
  const onSafe = await ctx.client.readContract({
    address: safe,
    abi: SAFE_ABI,
    functionName: 'getTransactionHash',
    args: [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, tx.nonce],
  })
  if (onSafe.toLowerCase() !== hash.toLowerCase()) throw new Refused(`The Safe computes ${onSafe} for these fields, not ${hash}: refusing.`)
  if (!(await ownerDeployed(ctx, env.core, rec.owner, rec.memberKey))) throw new Refused('Your owner contract doesn’t exist on this network yet: enrol a key tree first, which creates it.')
  const onchain = await readTree(ctx, rec.owner, safe, 0)
  if (!onchain.root) throw new Refused('No key tree is enrolled for your owner on this Safe yet: enrol one.')
  const cap = 2 ** (onchain.height - 1)
  if (tx.nonce < BigInt(onchain.start) || tx.nonce >= BigInt(onchain.start + cap)) {
    throw new Refused(`Nonce ${tx.nonce} is outside your key tree (nonces ${onchain.start} to ${onchain.start + cap - 1}): enrol a fresh one.`)
  }
  await checkBoard(rec, client)
  const trees = await client.trees()
  if (!trees.some((t) => t.chain === chainId && t.safe.toLowerCase() === safe.toLowerCase() && t.root.toLowerCase() === onchain.root!.toLowerCase())) {
    throw new Refused('The key tree enrolled for your owner on this Safe isn’t on this board (a recovered board can’t rebuild its keys): enrol a new one.')
  }
  return { ctx, hash, root: onchain.root }
}

async function boardSign(env: Env, rec: BoardRecord, client: BoardClient, chainId: number, safe: Address, p: Prepared, tx: SafeTx, step: Step, w: Waiting) {
  const parent = await parentOf(env, chainId, tx)
  step(
    parent
      ? 'Check the board: it shows the parent Safe’s transaction this approves. Confirm there (hold both buttons on the last page)'
      : 'Check the board: it shows what this transaction does. Confirm there (hold both buttons on the last page)',
  )
  const s = await client.sign({ chain: chainId, safe, root: p.root, tx: encodeForCore(tx), parent: parent ? encodeForCore(parent) : undefined }, w)
  if (s.hash.toLowerCase() !== p.hash.toLowerCase()) throw new Error(`The board signed ${s.hash}, not ${p.hash}: not sending it.`)
  step('Your owner contract checks the signature')
  if (!(await isValidSignature(p.ctx, rec.owner, p.hash, s.data))) throw new Error('Your owner contract refuses the board’s signature (isValidSignature): not sending it.')
  return { ...s, signature: contractSignature(rec.owner, s.data) }
}

/** Propose an ETH or ERC-20 transfer, confirmed on the board, to Safe's service. */
export async function boardPropose(env: Env, rec: BoardRecord, client: BoardClient, chainId: number, safe: Address, t: Transfer, step: Step, w: Waiting): Promise<{ hash: Hex; nonce: number; slot: number }> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  const st = await safeState(ctx, safe)
  const nonce = await nextNonce(chainId, safe, st.nonce)
  const tx = t.token
    ? safeTx({ to: t.token, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [t.to, t.amount] }), nonce: BigInt(nonce) })
    : safeTx({ to: t.to, value: t.amount, nonce: BigInt(nonce) })
  const p = await prepare(env, rec, client, chainId, safe, tx, step)
  const s = await boardSign(env, rec, client, chainId, safe, p, tx, step, w)
  step('Proposing it at Safe’s service')
  await writerFor(chainById(chainId).service).propose(safe, tx, p.hash, rec.owner, s.signature)
  await keptCheck(env, rec, chainId, safe, p.hash, s.signature)
  return { hash: p.hash, nonce, slot: s.slot }
}

/** Confirm a proposal from Safe's service on the board. */
export async function boardConfirm(env: Env, rec: BoardRecord, client: BoardClient, chainId: number, safe: Address, hash: Hex, step: Step, w: Waiting): Promise<{ note?: string; slot?: number }> {
  const ctx = await usableCtx(env.db, env.core, chainId)
  step('Fetching the proposal')
  const r = await service(chainId).transaction(hash)
  if (getAddress(r.safe) !== getAddress(safe)) throw new Refused('That proposal is for another Safe.')
  const tx = fromService(r)
  for (const c of r.confirmations ?? []) {
    if (c.owner?.toLowerCase() !== rec.owner.toLowerCase() || !c.signature) continue
    const ps = parseSignature(c.signature)
    if (ps.contract && (await isValidSignature(ctx, rec.owner, hash, ps.data))) return { note: 'Your owner already confirmed it.' }
  }
  const p = await prepare(env, rec, client, chainId, safe, tx, step, hash)
  const s = await boardSign(env, rec, client, chainId, safe, p, tx, step, w)
  step('Sending the confirmation to Safe’s service')
  await writerFor(chainById(chainId).service).confirm(hash, s.signature)
  const note = await keptCheck(env, rec, chainId, safe, hash, s.signature)
  return { note, slot: s.slot }
}

/** The calldata of approveHash(hash), for a transaction to a parent Safe. */
export function approveHashData(hash: Hex): Hex {
  return encodeFunctionData({ abi: APPROVE_ABI, args: [hash] })
}

