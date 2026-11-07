// Record, then sign: every one-time signature goes through here.
//
// The core's KeyLogStore is synchronous and IndexedDB isn't, so the core's rules run twice around
// a durable write (core-wasm/src/lib.rs):
//   1. the core picks the slot from the uses the log holds and says which use to record
//   2. that use is written in a strict-durability transaction, and this waits until it completes;
//      the store refuses a second use of the same key (its key is chain, Safe, root, key index)
//   3. the uses are read back, and the core signs only if its rules find this use among them:
//      its store can't append, so a use missing from the durable log means no signature
// All three steps run under a Web Lock for the device, so two tabs can't pick the same key.

import { bytesToHex, hexToBytes } from 'viem'
import { type DeviceRecord, type Hex, type TreeRecord, type UseRecord, usesOf, writeStrict } from './db'

export interface Core {
  call<T>(op: string, args?: unknown, progress?: (done: number, total: number) => void): Promise<T>
}

/** The uses of one tree as the core reads them: key index (8 bytes, big-endian) ‖ hash (32). */
export function encodeUses(uses: UseRecord[]): Uint8Array {
  const out = new Uint8Array(40 * uses.length)
  const dv = new DataView(out.buffer)
  uses.forEach((u, i) => {
    dv.setBigUint64(40 * i, BigInt(u.keyIndex))
    out.set(hexToBytes(u.hash), 40 * i + 8)
  })
  return out
}

export function lockName(device: Pick<DeviceRecord, 'owner' | 'device'>): string {
  return `winterlock-device-${device.owner.toLowerCase()}-${device.device}`
}

export interface Signed {
  /** The owner signature data (slot, device, Safe, SafeTx words, WOTS signature, path). */
  data: Uint8Array
  slot: number
  keyIndex: number
  /** This key had already signed this same hash: the same signature again. */
  already: boolean
}

export class Refused extends Error {}

/**
 * Signs `tx` (the core's SafeTx encoding, whose hash is `hash` at `nonce`) with the tree's next
 * one-time key, recording the use durably first.
 */
export async function recordThenSign(
  db: IDBDatabase,
  core: Core,
  device: DeviceRecord,
  tree: TreeRecord,
  tx: Uint8Array,
  nonce: number,
  hash: Hex,
  locks: LockManager = navigator.locks,
): Promise<Signed> {
  const at = { chain: tree.chain, safe: hexToBytes(tree.safe), root: hexToBytes(tree.root) }
  return locks.request(lockName(device), { mode: 'exclusive' }, async () => {
    // 1. pick
    const before = await usesOf(db, tree.chain, tree.safe, tree.root)
    let pick: { slot: number; already: boolean; keyIndex: number }
    try {
      pick = await core.call('pickUse', { ...at, start: tree.start, height: tree.height, nonce, hash: hexToBytes(hash), uses: encodeUses(before) })
    } catch (e) {
      throw new Refused((e as Error).message)
    }
    // 2. record, durably
    if (!pick.already) {
      const use: UseRecord = {
        chain: tree.chain,
        safe: tree.safe.toLowerCase(),
        root: tree.root.toLowerCase() as Hex,
        keyIndex: pick.keyIndex,
        nonce,
        slot: pick.slot,
        start: tree.start,
        hash: hash.toLowerCase() as Hex,
        at: Date.now(),
      }
      try {
        await writeStrict(db, 'uses', [use], 'add')
      } catch (e) {
        throw new Refused(`the key log refused to record one-time key ${pick.keyIndex}: ${(e as Error)?.message ?? e}. Nothing was signed.`)
      }
    }
    // 3. sign from what the durable log holds
    const after = await usesOf(db, tree.chain, tree.safe, tree.root)
    const data = await core.call<Uint8Array>('signTransaction', {
      seed: hexToBytes(device.seed),
      chain: tree.chain,
      owner: hexToBytes(tree.owner),
      safe: at.safe,
      device: tree.device,
      generation: tree.generation,
      start: tree.start,
      salt: hexToBytes(tree.salt),
      cache: hexToBytes(tree.cache),
      uses: encodeUses(after),
      tx,
    })
    return { data, slot: pick.slot, keyIndex: pick.keyIndex, already: pick.already }
  })
}

export const toHex = (b: Uint8Array) => bytesToHex(b)
