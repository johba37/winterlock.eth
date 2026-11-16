// Safe{Wallet}'s nested transaction envelope (in Safe's app since 2026-10-09; its source is
// apps/web/src/services/tx/nestedTxEnvelope.ts in safe-global/safe-wallet-monorepo). When the
// account connected to Safe's app is itself a Safe and confirms a transaction of a Safe it owns,
// the app appends that transaction's fields to the call it asks the wallet for:
//
//   approveHash(hash) ‖ MAGIC ‖ abi.encode(Envelope[])
//
// MAGIC is the first four bytes of keccak256("SafeNestedChildTxV1"). The first envelope is the
// transaction whose hash is approved; a further one is the transaction the one before it approves
// in turn. approveHash ignores what follows its argument, so the call does the same on-chain with
// or without the envelope.
//
// A wallet is meant to check the fields against the hash, take them off the call and show them.
// Safe's app then doesn't propose a new transaction to Safe's service itself: it leaves that to the
// wallet, so the app sees that the transaction gets there (flows.ts, listApproved).
//
// Nothing here hashes: the caller checks the first envelope with the core's SafeTx hash. Safe's app
// calls the approving Safe the parent and the Safe it owns nested (its transaction the child's);
// the board's screens say "Nested" for that Safe too, while the code that feeds the board still
// names it the parent (decode.rs). This file says "the approved transaction".

import { type Address, concat, decodeAbiParameters, getAddress, padHex, parseAbiParameters, size, slice } from 'viem'
import type { Hex } from './db'
import type { SafeTx } from './safe'

/** approveHash(bytes32) */
export const APPROVE_HASH = '0xd4d9bdcd'
/** keccak256("SafeNestedChildTxV1")[:4] */
export const NESTED_MAGIC = '0xfb4e87b0'

const ENVELOPES = parseAbiParameters(
  '(uint256 chainId, address safe, uint256 nonce, address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver)[]',
)

export interface Envelope {
  chainId: bigint
  safe: Address
  tx: SafeTx
}

/** approveHash's argument and whatever follows it, if `data` is that call. */
export function splitApprove(data: Hex): { hash: Hex; rest: Hex } | null {
  if (size(data) < 36 || slice(data, 0, 4).toLowerCase() !== APPROVE_HASH) return null
  return { hash: slice(data, 4, 36).toLowerCase() as Hex, rest: size(data) > 36 ? slice(data, 36) : '0x' }
}

/** approveHash(hash), with nothing after it. */
export function approveCall(hash: Hex): Hex {
  return concat([APPROVE_HASH, hash]).toLowerCase() as Hex
}

/** The envelopes in what follows approveHash's argument, or null if that isn't Safe's payload. */
export function envelopes(rest: Hex): Envelope[] | null {
  if (size(rest) <= 4 || slice(rest, 0, 4).toLowerCase() !== NESTED_MAGIC) return null
  try {
    const [list] = decodeAbiParameters(ENVELOPES, slice(rest, 4))
    if (list.length === 0) return null
    return list.map((e) => {
      if (e.operation !== 0 && e.operation !== 1) throw new Error('operation must be 0 or 1')
      return {
        chainId: e.chainId,
        safe: getAddress(e.safe),
        tx: {
          to: getAddress(e.to),
          value: e.value,
          data: e.data.toLowerCase() as Hex,
          operation: e.operation,
          safeTxGas: e.safeTxGas,
          baseGas: e.baseGas,
          gasPrice: e.gasPrice,
          gasToken: getAddress(e.gasToken),
          refundReceiver: getAddress(e.refundReceiver),
          nonce: e.nonce,
        },
      }
    })
  } catch {
    return null
  }
}

/** Safe's signature form for a hash an owner approved on-chain: r = the owner, s = 0, v = 1.
 * Safe's service takes it once approvedHashes(owner, hash) is set. */
export function approvedHashSignature(owner: Address): Hex {
  return concat([padHex(owner, { size: 32 }), padHex('0x', { size: 32 }), '0x01']).toLowerCase() as Hex
}
