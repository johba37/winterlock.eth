// The port of member_key_of against the core's own vectors (core/tests/vectors/owner.json, made
// by the Python signer, which the Rust core is tested against too).

import { readFileSync } from 'node:fs'
import type { Address, Hex } from 'viem'
import { describe, expect, it } from 'vitest'
import { WINTERLOCK_FACTORY, WINTERLOCK_IMPLEMENTATION, memberKeyOf, ownerAddress, proxyInitCode, proxyRuntime } from '../src/lib/winterlock'

const vectors = JSON.parse(readFileSync(new URL('../../core/tests/vectors/owner.json', import.meta.url), 'utf8'))

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
