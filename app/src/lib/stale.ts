// The stale-log check (docs/notes/signer-app.md, "Copies"): before every one-time signature, look
// for signatures by this device's key tree that this browser's key log doesn't record. A browser
// restored from a backup, or a profile copied or synced to another machine, brings back an old
// key log with the same device key; signing from it could use a one-time key twice.
//
// What it compares, for the tree's whole range of nonces:
//   - Safe's Transaction Service: every transaction it holds for the Safe at those nonces,
//     executed or pending, and each one's confirmations by this member's owner; for executed
//     ones also the signatures the service indexed from the execution
//   - the chain: for each executed transaction the service lists, the execTransaction calldata
//     of its transaction hash, and this owner's signature inside it. A checked execution is
//     remembered (it can't change).
// A signature counts as this tree's when it names this device, its SafeTx words hash to a nonce
// in the tree, and the core's WOTS verification against the tree gives the tree's root.
//
// What it can't see: signatures passed between members as files or links and never posted;
// executions the service hasn't indexed (finding them would need log scans); a copy that signs
// after this check passed; a service that withholds data. See decisions.md, "the signer app,
// first build".

import { type Address, hexToBytes, toHex } from 'viem'
import { type Ctx } from './chain'
import { type CheckedRecord, type Hex, type TreeRecord, type UseRecord, get, usesOf, writeStrict } from './db'
import type { Core } from './keylog'
import { blobSignatureOf, execSignatures, parseSignature } from './safe'
import type { Service, ServiceTx } from './service'

export class StaleLog extends Error {}

export interface Found {
  keyIndex: number
  nonce: number
  slot: number
  hash: Hex
  where: string
}

export const STALE_ADVICE =
  'This browser’s key log is out of date: another copy of this device (a restored backup or a copied browser profile) has signed with its keys. ' +
  'To keep a one-time key from being used twice, this copy signs nothing more. Revoke this device (Devices, with your recovery phrase), then pair it again.'

/** This tree's use in `data` (an owner's signature data), if it is one. */
export async function treeUse(core: Core, tree: TreeRecord, data: Uint8Array): Promise<Omit<Found, 'where'> | null> {
  const r = await core.call<{ keyIndex: number; nonce: number; slot: number; hash: Uint8Array } | null>('treeSignatureUse', {
    data,
    chain: tree.chain,
    owner: hexToBytes(tree.owner),
    safe: hexToBytes(tree.safe),
    device: tree.device,
    generation: tree.generation,
    start: tree.start,
    height: tree.height,
    root: hexToBytes(tree.root),
  })
  return r && { keyIndex: r.keyIndex, nonce: r.nonce, slot: r.slot, hash: toHex(r.hash) }
}

/** The uses that `found` shows and the log doesn't record (or records with another hash). */
export function unrecorded(found: Found[], log: UseRecord[]): Found[] {
  const byKey = new Map(log.map((u) => [u.keyIndex, u.hash.toLowerCase()]))
  return found.filter((f) => byKey.get(f.keyIndex) !== f.hash.toLowerCase())
}

export interface StaleSources {
  /** Transactions the service holds at the tree's nonces. */
  serviceTxs(): Promise<ServiceTx[]>
  /** The execTransaction calldata of an execution, or undefined if the chain doesn't have it. */
  executionInput(txHash: Hex): Promise<Hex | undefined>
}

export function sources(ctx: Ctx, service: Service, safe: Address, from: number, to: number): StaleSources {
  return {
    serviceTxs: () => service.inRange(safe, from, to),
    executionInput: async (h) => {
      const tx = await ctx.client.getTransaction({ hash: h }).catch(() => undefined)
      return tx?.input
    },
  }
}

/**
 * Refuses (StaleLog) if the service or the chain holds a signature by `tree` that the durable
 * log doesn't record. Returns what it compared.
 */
export async function staleLogCheck(db: IDBDatabase, core: Core, tree: TreeRecord, src: StaleSources): Promise<{ signatures: number; executions: number }> {
  const owner = tree.owner as Address
  const found: Found[] = []
  const txs = await src.serviceTxs()
  let executions = 0
  const checkedNow: CheckedRecord[] = []
  for (const tx of txs) {
    const sigs: { data: Uint8Array; where: string }[] = []
    for (const c of tx.confirmations ?? []) {
      if (c.owner?.toLowerCase() !== owner.toLowerCase() || !c.signature) continue
      try {
        const p = parseSignature(c.signature)
        if (p.contract) sigs.push({ data: p.data, where: `a confirmation at Safe's service (nonce ${tx.nonce})` })
      } catch {
        /* not ours to judge */
      }
    }
    const indexed = (tx as any).signatures as Hex | null | undefined
    if (tx.isExecuted && indexed) {
      const d = blobSignatureOf(indexed, owner)
      if (d) sigs.push({ data: d, where: `the execution of nonce ${tx.nonce}, as Safe's service indexed it` })
    }
    if (tx.isExecuted && tx.transactionHash) {
      const seen = await get<CheckedRecord>(db, 'checked', tx.transactionHash.toLowerCase())
      if (!seen) {
        const input = await src.executionInput(tx.transactionHash)
        const blob = input && execSignatures(input)
        const d = blob && blobSignatureOf(blob, owner)
        if (d) sigs.push({ data: d, where: `the execution of nonce ${tx.nonce} on-chain (${tx.transactionHash})` })
        if (input) {
          executions++
          checkedNow.push({ txHash: tx.transactionHash.toLowerCase() as Hex, chain: tree.chain, at: Date.now() })
        }
      }
    }
    for (const s of sigs) {
      const u = await treeUse(core, tree, s.data)
      if (u) found.push({ ...u, where: s.where })
    }
  }
  const log = await usesOf(db, tree.chain, tree.safe, tree.root)
  const missing = unrecorded(found, log)
  if (missing.length) {
    const m = missing[0]
    throw new StaleLog(
      `${STALE_ADVICE} (Found: one-time key ${m.keyIndex}, nonce ${m.nonce}, signed ${m.hash.slice(0, 10)}… in ${m.where}; this browser's key log doesn't record it.)`,
    )
  }
  // remember the executions read from the chain that checked out
  if (checkedNow.length) await writeStrict(db, 'checked', checkedNow)
  return { signatures: found.length, executions }
}
