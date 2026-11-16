// Recognising a Winterlock owner: a port of member_key_of in core/src/owner.rs, for owner v2 and
// for the earlier owner v1. Both are a 77-byte ERC-1167 clone of their version's pinned
// implementation with the member key (32 bytes) appended, at the address their version's pinned
// factory gives that key (CREATE2, salt = the key). The implementation and the factory are
// themselves CREATE2 deployments of pinned creation code, so the address check pins the code.
// Their signatures are hash-based only: one-time WOTS keys and a stateless leanSphincs-keccak key,
// with no admin, no upgrade and no other signature path (contracts/src/safe/WinterlockOwner.sol;
// for v1, the same file at commit 357c25f).
// - v2: the core's pinned contracts, tested against core/tests/vectors/owner.json.
// - v1: derived from the creation code the Python signer pinned for v1
//   (git show d2dda10:signer/winterlock_signer/contracts.json), salts
//   "Winterlock.safe-owner.implementation.v1" and "Winterlock.safe-owner.factory.v1", the same
//   parameters and stateless verifier; these are the addresses docs/decisions.md records for the
//   live Sepolia run of 2026-11-05. test/winterlock.test.ts re-derives them
//   (test/vectors/owner-v1.json).

import { type Address, type Hex, getContractAddress, isAddressEqual, keccak256 } from 'viem'

export interface WinterlockVersion {
  version: 1 | 2
  implementation: Address
  factory: Address
}

/** The pinned v2 contracts (core/src/owner.rs), the same on every chain. */
export const WINTERLOCK_IMPLEMENTATION: Address = '0x114caAB223BaccD9BcA92C28ABBCf1edC0C3bCdf'
export const WINTERLOCK_FACTORY: Address = '0x90835a46Fb205B7f038B0EE46e798ead45a6fA7F'

export const WINTERLOCK_VERSIONS: readonly WinterlockVersion[] = [
  { version: 2, implementation: WINTERLOCK_IMPLEMENTATION, factory: WINTERLOCK_FACTORY },
  { version: 1, implementation: '0xC4Aa38F766020e66136cd6cb1c547CeCAd175f2e', factory: '0x13D4cB5F9A9D076dB123CE8Eb5f404e2FA01fEa5' },
]

const OWNER_CODE_BYTES = 77
const KEY_OFFSET = 0x2d
const CLONE_HEAD = '363d3d373d3d3d363d73'
const CLONE_TAIL = '5af43d82803e903d91602b57fd5bf3'
const INIT_HEAD = '3d81600a3d39f3'

const hex = (h: string) => h.slice(2).toLowerCase()

/** A stateless public key as the contracts take it: 32 bytes, both halves nonzero. */
function validKey(key: Hex): boolean {
  const k = hex(key)
  return k.length === 64 && !/^0{32}/.test(k) && !/0{32}$/.test(k)
}

/** The 77 bytes of code a member's owner has: the ERC-1167 proxy, then the key. */
export function proxyRuntime(implementation: Address, key: Hex): Hex {
  return `0x${CLONE_HEAD}${hex(implementation)}${CLONE_TAIL}${hex(key)}`
}

/** Solady LibClone.initCode(implementation, abi.encodePacked(key)). */
export function proxyInitCode(implementation: Address, key: Hex): Hex {
  if (!validKey(key)) throw new Error('a stateless key is 32 bytes with both halves nonzero')
  return `0x61${(KEY_OFFSET + 32).toString(16).padStart(4, '0')}${INIT_HEAD}${hex(proxyRuntime(implementation, key))}`
}

/** WinterlockOwnerFactory.predict(key) with a version's pinned contracts (v2 unless told). */
export function ownerAddress(key: Hex, v: WinterlockVersion = WINTERLOCK_VERSIONS[0]): Address {
  return getContractAddress({
    opcode: 'CREATE2',
    from: v.factory,
    salt: key,
    bytecodeHash: keccak256(proxyInitCode(v.implementation, key)),
  })
}

/** The Winterlock owner in `code` at `address`, of either version: its version and member key,
 * or null if the code isn't exactly a pinned version's owner for that address. */
export function winterlockOwnerOf(address: Address, code: Hex): { version: 1 | 2; memberKey: Hex } | null {
  const c = hex(code)
  if (c.length !== OWNER_CODE_BYTES * 2) return null
  const key: Hex = `0x${c.slice(KEY_OFFSET * 2)}`
  if (!validKey(key)) return null
  for (const v of WINTERLOCK_VERSIONS) {
    if (c === hex(proxyRuntime(v.implementation, key)) && isAddressEqual(ownerAddress(key, v), address)) return { version: v.version, memberKey: key }
  }
  return null
}

/** member_key_of (core/src/owner.rs): the member key if `code` is a v2 owner at `address`. */
export function memberKeyOf(address: Address, code: Hex): Hex | null {
  const o = winterlockOwnerOf(address, code)
  return o?.version === 2 ? o.memberKey : null
}
