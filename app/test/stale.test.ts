// The stale-log check: a copied browser (its IndexedDB copied after one signature) must refuse
// once the original has signed again; the original passes.

import { IDBFactory } from 'fake-indexeddb'
import { type Address, toHex } from 'viem'
import { describe, expect, it } from 'vitest'
import { type TreeRecord, all, openDb, writeStrict } from '../src/lib/db'
import { type Core, recordThenSign } from '../src/lib/keylog'
import { contractSignature, encodeForCore, execCalldata, pack, safeTx } from '../src/lib/safe'
import type { ServiceTx } from '../src/lib/service'
import { StaleLog, type StaleSources, staleLogCheck } from '../src/lib/stale'
import { deviceWithTree, freshDb, hexBytes, randAddress, wasm } from './helpers'

const STORES = ['device', 'certs', 'trees', 'uses', 'stateless', 'safes', 'settings', 'checked', 'held']

/** A copy of a browser's IndexedDB, as a restored backup or a copied profile would bring back. */
async function copyDb(from: IDBDatabase): Promise<IDBDatabase> {
  const to = await openDb(new IDBFactory())
  for (const s of STORES) {
    const rows = await all<unknown>(from, s)
    if (rows.length) await writeStrict(to, s, rows)
  }
  return to
}

function sign(db: IDBDatabase, core: Core, device: any, tree: TreeRecord, nonce: number, value: bigint) {
  const t = safeTx({ to: randAddress(), value, nonce: BigInt(nonce) })
  const h = toHex(wasm.safe_tx_hash(BigInt(tree.chain), hexBytes(tree.safe), encodeForCore(t)))
  return recordThenSign(db, core, device, tree, encodeForCore(t), nonce, h).then((s) => ({ ...s, tx: t, hash: h }))
}

function serviceTx(tree: TreeRecord, nonce: number, hash: string, confirmations: { owner: Address; signature: string }[], executed?: { txHash: string }): ServiceTx {
  return {
    safe: tree.safe,
    nonce,
    safeTxHash: hash,
    isExecuted: !!executed,
    transactionHash: executed?.txHash ?? null,
    confirmations,
  } as unknown as ServiceTx
}

function src(txs: ServiceTx[], inputs: Record<string, string> = {}): StaleSources {
  return { serviceTxs: async () => txs, executionInput: async (h) => inputs[h] as any }
}

describe('stale-log check', () => {
  it('a copy made after one signature refuses once the original signs again', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const first = await sign(db, core, device, tree, 5, 1n)
    const copy = await copyDb(db)
    const second = await sign(db, core, device, tree, 6, 2n)
    const service = [
      serviceTx(tree, 5, first.hash, [{ owner: device.owner, signature: contractSignature(device.owner, first.data) }]),
      serviceTx(tree, 6, second.hash, [{ owner: device.owner, signature: contractSignature(device.owner, second.data) }]),
    ]
    // the original knows both
    await expect(staleLogCheck(db, core, tree, src(service))).resolves.toEqual({ signatures: 2, executions: 0 })
    // the copy doesn't know the second
    await expect(staleLogCheck(copy, core, tree, src(service))).rejects.toBeInstanceOf(StaleLog)
    await expect(staleLogCheck(copy, core, tree, src(service))).rejects.toThrow(/nonce 6/)
  })

  it('finds a signature on-chain, in an execution, even when the service lists no confirmation', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const copy = await copyDb(db)
    const s = await sign(db, core, device, tree, 5, 7n)
    const other = randAddress()
    const blob = pack([
      { owner: device.owner, data: s.data, contract: true },
      { owner: other, data: Uint8Array.from([1, 2, 3]), contract: true },
    ])
    const txHash = toHex(new Uint8Array(32).fill(0xee))
    const service = [serviceTx(tree, 5, s.hash, [], { txHash })]
    const inputs = { [txHash]: execCalldata(s.tx, blob) }
    await expect(staleLogCheck(copy, core, tree, src(service, inputs))).rejects.toThrow(/on-chain/)
    const ok = await staleLogCheck(db, core, tree, src(service, inputs))
    expect(ok).toEqual({ signatures: 1, executions: 1 })
    // a checked execution isn't read again
    expect(await staleLogCheck(db, core, tree, src(service, {}))).toEqual({ signatures: 0, executions: 0 })
  })

  it('ignores other owners, other devices and other trees', async () => {
    const { db } = await freshDb()
    const a = await deviceWithTree(db)
    // the same member's other device, and another tree of this device (another salt), same Safe
    const { db: db2 } = await freshDb()
    const b = await deviceWithTree(db2, a.core)
    const s = await sign(db2, b.core, b.device, b.tree, 5, 1n)
    const service = [
      serviceTx(a.tree, 5, s.hash, [
        { owner: a.device.owner, signature: contractSignature(a.device.owner, s.data) },
        { owner: randAddress(), signature: contractSignature(randAddress(), s.data) },
      ]),
    ]
    await expect(staleLogCheck(db, a.core, a.tree, src(service))).resolves.toEqual({ signatures: 0, executions: 0 })
  })

  it('a signature the log records with another hash is stale too', async () => {
    const { db } = await freshDb()
    const { core, device, tree } = await deviceWithTree(db)
    const s = await sign(db, core, device, tree, 5, 1n)
    // the log of another copy holds this key for another hash
    const copy = await copyDb(db)
    const rows = await all<any>(copy, 'uses')
    await writeStrict(copy, 'uses', rows.map((u) => ({ ...u, hash: toHex(new Uint8Array(32).fill(1)) })))
    const service = [serviceTx(tree, 5, s.hash, [{ owner: device.owner, signature: contractSignature(device.owner, s.data) }])]
    await expect(staleLogCheck(copy, core, tree, src(service))).rejects.toBeInstanceOf(StaleLog)
  })
})
