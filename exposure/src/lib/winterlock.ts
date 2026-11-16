// Recognising a Winterlock owner: a port of member_key_of in core/src/owner.rs. An owner v2 is a
// 77-byte ERC-1167 clone of the pinned implementation with the member key (32 bytes) appended,
// at the address the pinned factory gives that key (CREATE2, salt = the key). Its signatures are
// hash-based only: one-time WOTS keys and a stateless leanSphincs-keccak key. Tested against the
// core's own vectors (core/tests/vectors/owner.json) and the live Sepolia owners.

import { type Address, type Hex, getContractAddress, isAddressEqual, keccak256 } from 'viem'

/** The pinned v2 contracts (core/src/owner.rs), the same on every chain. */
export const WINTERLOCK_IMPLEMENTATION: Address = '0x114caAB223BaccD9BcA92C28ABBCf1edC0C3bCdf'
export const WINTERLOCK_FACTORY: Address = '0x90835a46Fb205B7f038B0EE46e798ead45a6fA7F'

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

/** WinterlockOwnerFactory.predict(key) with the pinned contracts. */
export function ownerAddress(key: Hex): Address {
  return getContractAddress({
    opcode: 'CREATE2',
    from: WINTERLOCK_FACTORY,
    salt: key,
    bytecodeHash: keccak256(proxyInitCode(WINTERLOCK_IMPLEMENTATION, key)),
  })
}

/** The member key in `code` if it is the code of a v2 owner of the pinned implementation at
 * `address` (the factory's proxy for that key), else null. */
export function memberKeyOf(address: Address, code: Hex): Hex | null {
  const c = hex(code)
  if (c.length !== OWNER_CODE_BYTES * 2) return null
  const key: Hex = `0x${c.slice(KEY_OFFSET * 2)}`
  if (!validKey(key)) return null
  if (c !== hex(proxyRuntime(WINTERLOCK_IMPLEMENTATION, key))) return null
  if (!isAddressEqual(ownerAddress(key), address)) return null
  return key
}
