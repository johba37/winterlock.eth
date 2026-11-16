// The port of member_key_of against the core's own vectors (core/tests/vectors/owner.json, made
// by the Python signer, which the Rust core is tested against too).

import { readFileSync } from 'node:fs'
import { type Address, type Hex, concat, encodeAbiParameters, getContractAddress, keccak256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'
import { WINTERLOCK_FACTORY, WINTERLOCK_IMPLEMENTATION, WINTERLOCK_VERSIONS, memberKeyOf, ownerAddress, proxyInitCode, proxyRuntime, winterlockOwnerOf } from '../src/lib/winterlock'

const vectors = JSON.parse(readFileSync(new URL('../../core/tests/vectors/owner.json', import.meta.url), 'utf8'))
const v1 = JSON.parse(readFileSync(new URL('vectors/owner-v1.json', import.meta.url), 'utf8'))
const [V2, V1] = WINTERLOCK_VERSIONS
const PROXY = '0x4e59b44847b379578588920cA78FbF26c0B4956C'

describe('Winterlock owner v2', () => {
  it('pins the same contracts as the core', () => {
    expect(vectors.pinned.implementation).toBe(WINTERLOCK_IMPLEMENTATION)
    expect(vectors.pinned.factory).toBe(WINTERLOCK_FACTORY)
  })

  it('derives the owner addresses, init code and runtime code', () => {
    expect(vectors.addresses.length).toBeGreaterThan(0)
    for (const c of vectors.addresses as { key: Hex; owner: Address; init_code: Hex; runtime: Hex }[]) {
      expect(ownerAddress(c.key)).toBe(c.owner)
      expect(proxyInitCode(WINTERLOCK_IMPLEMENTATION, c.key)).toBe(c.init_code.toLowerCase())
      expect(proxyRuntime(WINTERLOCK_IMPLEMENTATION, c.key)).toBe(c.runtime.toLowerCase())
    }
  })

  it('member_key_of', () => {
    for (const c of vectors.member_key_of as { address: Address; code: Hex; key: Hex | null }[]) {
      expect(memberKeyOf(c.address, c.code)).toBe(c.key === null ? null : c.key.toLowerCase())
    }
  })

  it('refuses a key with a zero half, and other code', () => {
    const zero = `0x${'00'.repeat(16)}${'11'.repeat(16)}` as Hex
    expect(() => ownerAddress(zero)).toThrow()
    const code = proxyRuntime(WINTERLOCK_IMPLEMENTATION, zero)
    expect(memberKeyOf('0x0000000000000000000000000000000000000001', code)).toBeNull()
    expect(memberKeyOf('0x0000000000000000000000000000000000000001', '0x')).toBeNull()
  })

  it('ignores the case of the address and the code', () => {
    const c = vectors.member_key_of[0] as { address: Address; code: Hex }
    expect(memberKeyOf(c.address.toLowerCase() as Address, c.code.toUpperCase().replace('0X', '0x') as Hex)).not.toBeNull()
  })
})

describe('Winterlock owner v1', () => {
  it('its implementation and factory derive from the creation code the signer pinned for v1', () => {
    for (const c of [v1.WinterlockOwner, v1.WinterlockOwnerFactory]) expect(keccak256(c.creation_code)).toBe(c.creation_code_hash)
    // the same parameter set and stateless verifier as v2
    expect(v1.params).toBe(vectors.pinned.params)
    expect(v1.verifier).toBe(vectors.pinned.verifier)
    const implementation = getContractAddress({
      opcode: 'CREATE2',
      from: PROXY,
      salt: keccak256(toHex(v1.implementation_salt_preimage)),
      bytecodeHash: keccak256(concat([v1.WinterlockOwner.creation_code, encodeAbiParameters([{ type: 'uint256' }, { type: 'address' }], [BigInt(v1.params), v1.verifier])])),
    })
    const factory = getContractAddress({
      opcode: 'CREATE2',
      from: PROXY,
      salt: keccak256(toHex(v1.factory_salt_preimage)),
      bytecodeHash: keccak256(concat([v1.WinterlockOwnerFactory.creation_code, encodeAbiParameters([{ type: 'address' }], [implementation])])),
    })
    expect({ implementation, factory }).toEqual({ implementation: v1.recorded.implementation, factory: v1.recorded.factory })
    expect(V1).toEqual({ version: 1, implementation, factory })
    expect(V2).toEqual({ version: 2, implementation: WINTERLOCK_IMPLEMENTATION, factory: WINTERLOCK_FACTORY })
  })

  it('recognises the owners docs/decisions.md records, at their addresses', () => {
    for (const o of v1.recorded.owners as { address: Address; key: Hex }[]) {
      expect(ownerAddress(o.key, V1)).toBe(o.address)
      const code = proxyRuntime(V1.implementation, o.key)
      expect(winterlockOwnerOf(o.address, code)).toEqual({ version: 1, memberKey: o.key })
      // member_key_of is v2's alone
      expect(memberKeyOf(o.address, code)).toBeNull()
    }
  })

  it("keeps the versions apart: one version's code at the other's address is nothing", () => {
    const key = v1.recorded.owners[0].key as Hex
    expect(winterlockOwnerOf(ownerAddress(key, V2), proxyRuntime(V1.implementation, key))).toBeNull()
    expect(winterlockOwnerOf(ownerAddress(key, V1), proxyRuntime(V2.implementation, key))).toBeNull()
    expect(winterlockOwnerOf(ownerAddress(key, V2), proxyRuntime(V2.implementation, key))).toEqual({ version: 2, memberKey: key })
    // a byte off, or another implementation, is nothing
    const code = proxyRuntime(V1.implementation, key)
    expect(winterlockOwnerOf(ownerAddress(key, V1), `${code.slice(0, -2)}00` as Hex)).toBeNull()
    expect(winterlockOwnerOf(ownerAddress(key, V1), proxyRuntime('0x0000000000000000000000000000000000000001', key))).toBeNull()
  })
})
