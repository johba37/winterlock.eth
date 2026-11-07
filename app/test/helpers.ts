import { readFileSync } from 'node:fs'
import { IDBFactory } from 'fake-indexeddb'
import { type Address, getAddress, toHex } from 'viem'
import * as wasm from '../src/wasm/core.js'
import { deviceOps } from '../src/core/ops'
import { type DeviceRecord, type Hex, type TreeRecord, openDb, putTree, treeId } from '../src/lib/db'
import type { Core } from '../src/lib/keylog'

wasm.initSync({ module: readFileSync(new URL('../src/wasm/core_bg.wasm', import.meta.url)) })

export { wasm }

/** The device worker's operations, called directly. */
export function directCore(): Core {
  const ops = deviceOps(wasm)
  return { call: async (op, args, progress) => ops[op](args, progress ?? (() => {})) as any }
}

export const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n))
export const randAddress = (): Address => getAddress(toHex(rand(20)))

/** A fresh browser's storage. */
export async function freshDb(factory = new IDBFactory()) {
  return { factory, db: await openDb(factory) }
}

export interface Setup {
  core: Core
  device: DeviceRecord
  tree: TreeRecord
}

/** A device with a key tree for a Safe (height 4: nonces start to start + 7). */
export async function deviceWithTree(db: IDBDatabase, core = directCore(), start = 5, height = 4): Promise<Setup> {
  const seed = rand(32)
  const owner = randAddress()
  const safe = randAddress()
  const k = await core.call<{ publicKey: Uint8Array; keptLeaves: Uint8Array }>('newDeviceKey', { seed })
  const device: DeviceRecord = {
    id: 'this',
    owner,
    memberKey: toHex(rand(32)),
    gasKey: toHex(rand(32)),
    gasAddress: randAddress(),
    device: 2,
    seed: toHex(seed),
    publicKey: toHex(k.publicKey),
    keptLeaves: toHex(k.keptLeaves),
    how: 'pair',
    createdAt: 0,
  }
  const salt = rand(32)
  const built = await core.call<{ cache: Uint8Array; root: Uint8Array }>('buildTree', {
    seed,
    chain: 11155111,
    owner: hexBytes(owner),
    safe: hexBytes(safe),
    device: 2,
    generation: 3,
    start,
    salt,
    height,
  })
  const tree: TreeRecord = {
    id: treeId(11155111, safe, toHex(built.root)),
    chain: 11155111,
    safe,
    owner,
    device: 2,
    generation: 3,
    start,
    height,
    salt: toHex(salt),
    root: toHex(built.root),
    cache: toHex(built.cache),
    createdAt: 0,
  }
  await putTree(db, tree)
  return { core, device, tree }
}

export function hexBytes(h: string): Uint8Array {
  return Uint8Array.from(Buffer.from(h.slice(2), 'hex'))
}

export type { Hex }
