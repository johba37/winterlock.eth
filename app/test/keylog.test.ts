// The key log store: record, then sign, over IndexedDB (fake-indexeddb here).

import { toHex } from 'viem'
import { describe, expect, it, vi } from 'vitest'
import { all, usesOf, writeStrict } from '../src/lib/db'
import { Refused, encodeUses, recordThenSign } from '../src/lib/keylog'
import { encodeForCore, safeTx } from '../src/lib/safe'
import { treeUse } from '../src/lib/stale'
import { deviceWithTree, freshDb, hexBytes, randAddress, wasm } from './helpers'

function tx(nonce: number, value: bigint, to = randAddress()) {
  const t = safeTx({ to, value, nonce: BigInt(nonce) })
  return t
}

function hashOf(tree: { chain: number; safe: string }, t: ReturnType<typeof tx>) {
  return toHex(wasm.safe_tx_hash(BigInt(tree.chain), hexBytes(tree.safe), encodeForCore(t)))
}

describe('key log', () => {
  it('records the use durably, then signs; the signature is the tree’s', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const t = tx(6, 1000n)
    const h = hashOf(tree, t)
    const spy = vi.spyOn(db, 'transaction')
    const s = await recordThenSign(db, core, device, tree, encodeForCore(t), 6, h)
    // the write that recorded the use asked for strict durability
    const write = spy.mock.calls.find((c) => c[0] === 'uses' && c[1] === 'readwrite')
    expect(write?.[2]).toEqual({ durability: 'strict' })
    spy.mockRestore()
    expect(s.slot).toBe(0)
    expect(s.keyIndex).toBe(2) // (6 - 5) * 2 + 0
    expect(s.already).toBe(false)
    const uses = await usesOf(db, tree.chain, tree.safe, tree.root)
    expect(uses.map((u) => [u.keyIndex, u.nonce, u.slot, u.hash])).toEqual([[2, 6, 0, h]])
    const use = await treeUse(core, tree, s.data)
    expect(use).toEqual({ keyIndex: 2, nonce: 6, slot: 0, hash: h })
  })

  it('the same hash again: the same key and signature, nothing appended', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const t = tx(5, 1n)
    const h = hashOf(tree, t)
    const a = await recordThenSign(db, core, device, tree, encodeForCore(t), 5, h)
    const b = await recordThenSign(db, core, device, tree, encodeForCore(t), 5, h)
    expect(b.already).toBe(true)
    expect(toHex(b.data)).toBe(toHex(a.data))
    expect(await usesOf(db, tree.chain, tree.safe, tree.root)).toHaveLength(1)
  })

  it('a second version at a nonce takes slot 1; a third is refused and nothing is recorded', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const to = randAddress()
    const [t1, t2, t3] = [tx(7, 1n, to), tx(7, 2n, to), tx(7, 3n, to)]
    expect((await recordThenSign(db, core, device, tree, encodeForCore(t1), 7, hashOf(tree, t1))).slot).toBe(0)
    expect((await recordThenSign(db, core, device, tree, encodeForCore(t2), 7, hashOf(tree, t2))).slot).toBe(1)
    await expect(recordThenSign(db, core, device, tree, encodeForCore(t3), 7, hashOf(tree, t3))).rejects.toThrow(/both keys for nonce 7/)
    expect(await usesOf(db, tree.chain, tree.safe, tree.root)).toHaveLength(2)
  })

  it('a nonce outside the tree is refused before anything is recorded', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const t = tx(13, 1n) // the tree covers 5 to 12
    await expect(recordThenSign(db, core, device, tree, encodeForCore(t), 13, hashOf(tree, t))).rejects.toBeInstanceOf(Refused)
    expect(await usesOf(db, tree.chain, tree.safe, tree.root)).toHaveLength(0)
  })

  it('the core signs nothing whose use isn’t in the durable log', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const t = tx(8, 1n)
    const args = {
      seed: hexBytes(device.seed),
      chain: tree.chain,
      owner: hexBytes(tree.owner),
      safe: hexBytes(tree.safe),
      device: tree.device,
      generation: tree.generation,
      start: tree.start,
      salt: hexBytes(tree.salt),
      cache: hexBytes(tree.cache),
      tx: encodeForCore(t),
    }
    await expect(core.call('signTransaction', { ...args, uses: new Uint8Array() })).rejects.toThrow(/record it first/)
    // slot 0 used for another hash: the rules move to slot 1, which isn't recorded either
    const other = new Uint8Array(80)
    new DataView(other.buffer).setBigUint64(0, 6n) // key (8 - 5) * 2 + 0
    other.fill(9, 8, 40)
    await expect(core.call('signTransaction', { ...args, uses: other.slice(0, 40) })).rejects.toThrow(/record it first/)
    // both keys of the nonce used for other hashes: no third version
    new DataView(other.buffer).setBigUint64(40, 7n)
    other.fill(8, 48)
    await expect(core.call('signTransaction', { ...args, uses: other })).rejects.toThrow(/both keys for nonce 8/)
    // with the use recorded: signed
    const ok = encodeUses([{ chain: tree.chain, safe: tree.safe, root: tree.root, keyIndex: 6, nonce: 8, slot: 0, start: 5, hash: hashOf(tree, t), at: 0 }])
    expect((await core.call<Uint8Array>('signTransaction', { ...args, uses: ok })).length).toBe(22 + 320 + 1176 + 24 * 4)
  })

  it('the store refuses a second record of the same key', async () => {
    const { db } = await freshDb()
    const use = { chain: 1, safe: '0xab', root: '0xcd' as const, keyIndex: 4, nonce: 2, slot: 0, start: 0, hash: '0x01' as const, at: 0 }
    await writeStrict(db, 'uses', [use], 'add')
    await expect(writeStrict(db, 'uses', [{ ...use, hash: '0x02' }], 'add')).rejects.toThrow()
    expect(await all(db, 'uses')).toHaveLength(1)
  })
})
