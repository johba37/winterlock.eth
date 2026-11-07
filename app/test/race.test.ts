// Two tabs racing for the same one-time key: each tab has its own IndexedDB connection to the
// same database and takes the same Web Lock (Node's navigator.locks, as a browser's).

import { toHex } from 'viem'
import { describe, expect, it } from 'vitest'
import { openDb, usesOf } from '../src/lib/db'
import { recordThenSign } from '../src/lib/keylog'
import { encodeForCore, safeTx } from '../src/lib/safe'
import { deviceWithTree, freshDb, hexBytes, randAddress, wasm } from './helpers'

const noLocks = { request: (_n: string, _o: unknown, f: () => unknown) => Promise.resolve().then(f) } as unknown as LockManager

async function setup() {
  const { factory, db } = await freshDb()
  const s = await deviceWithTree(db)
  // a second tab: another connection to the same database
  const db2 = await openDb(factory)
  const db3 = await openDb(factory)
  const to = randAddress()
  const txs = [1n, 2n, 3n].map((v) => safeTx({ to, value: v, nonce: 9n }))
  const hashes = txs.map((t) => toHex(wasm.safe_tx_hash(BigInt(s.tree.chain), hexBytes(s.tree.safe), encodeForCore(t))))
  return { ...s, dbs: [db, db2, db3], txs, hashes }
}

describe('two tabs', () => {
  it('different transactions at one nonce: slot 0 and slot 1, never one key twice', async () => {
    const { core, device, tree, dbs, txs, hashes } = await setup()
    const [a, b] = await Promise.all([0, 1].map((i) => recordThenSign(dbs[i], core, device, tree, encodeForCore(txs[i]), 9, hashes[i])))
    expect(new Set([a.slot, b.slot])).toEqual(new Set([0, 1]))
    expect(a.keyIndex).not.toBe(b.keyIndex)
    const uses = await usesOf(dbs[0], tree.chain, tree.safe, tree.root)
    expect(uses.map((u) => u.hash).sort()).toEqual([hashes[0], hashes[1]].sort())
  })

  it('the same transaction in both: one record, the same signature', async () => {
    const { core, device, tree, dbs, txs, hashes } = await setup()
    const [a, b] = await Promise.all([0, 1].map((i) => recordThenSign(dbs[i], core, device, tree, encodeForCore(txs[0]), 9, hashes[0])))
    expect([a.already, b.already].sort()).toEqual([false, true])
    expect(toHex(a.data)).toBe(toHex(b.data))
    expect(await usesOf(dbs[1], tree.chain, tree.safe, tree.root)).toHaveLength(1)
  })

  it('three tabs, three versions: two sign, the third is refused', async () => {
    const { core, device, tree, dbs, txs, hashes } = await setup()
    const r = await Promise.allSettled([0, 1, 2].map((i) => recordThenSign(dbs[i], core, device, tree, encodeForCore(txs[i]), 9, hashes[i])))
    expect(r.filter((x) => x.status === 'fulfilled')).toHaveLength(2)
    const refused = r.find((x) => x.status === 'rejected') as PromiseRejectedResult
    expect(String(refused.reason)).toMatch(/both keys for nonce 9/)
    expect(await usesOf(dbs[2], tree.chain, tree.safe, tree.root)).toHaveLength(2)
  })

  it('even without the lock, the store’s unique key lets only one tab use a key', async () => {
    const { core, device, tree, dbs, txs, hashes } = await setup()
    const r = await Promise.allSettled([0, 1].map((i) => recordThenSign(dbs[i], core, device, tree, encodeForCore(txs[i]), 9, hashes[i], noLocks)))
    const ok = r.filter((x) => x.status === 'fulfilled') as PromiseFulfilledResult<{ keyIndex: number }>[]
    const keys = ok.map((x) => x.value.keyIndex)
    // both may sign only with different keys; at least one must have been refused or moved to slot 1
    expect(new Set(keys).size).toBe(keys.length)
    const uses = await usesOf(dbs[0], tree.chain, tree.safe, tree.root)
    expect(uses).toHaveLength(ok.length)
  })
})
