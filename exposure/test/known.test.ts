import { getAddress, keccak256 } from 'viem'
import { describe, expect, it } from 'vitest'
import { CHAINS } from '../src/lib/chains'
import { NAMES, PASSKEY_FACTORIES, PASSKEY_SHARED_SIGNER, PROXY_CODE_HASHES, PROXY_FACTORIES, SINGLETONS, officialSingleton } from '../src/lib/known'
import { PROXY_100, PROXY_141 } from './fake'

describe('the tables', () => {
  it("chains: unique, with Safe's service and an https endpoint", () => {
    expect(new Set(CHAINS.map((c) => c.id)).size).toBe(CHAINS.length)
    expect(new Set(CHAINS.map((c) => c.shortName)).size).toBe(CHAINS.length)
    for (const c of CHAINS) {
      expect(c.service).toBe(`https://api.safe.global/tx-service/${c.shortName}/api`)
      expect(c.rpc).toMatch(/^https:\/\//)
      for (const t of c.tokens) expect(getAddress(t.address)).toBe(t.address)
    }
    expect(CHAINS.map((c) => c.shortName)).toEqual(['eth', 'sep', 'base', 'arb1', 'oeth', 'gno'])
  })

  it('singletons: checksummed, on known chains, each version with a Safe and an L2 one from 1.3.0', () => {
    const ids = CHAINS.map((c) => c.id)
    for (const s of SINGLETONS) {
      expect(getAddress(s.address)).toBe(s.address)
      for (const c of s.chains) expect(ids).toContain(c)
    }
    expect(officialSingleton(1, '0xd9db270c1b5e3bd161e8c8503c55ceabee709552')?.version).toBe('1.3.0')
    expect(officialSingleton(11155111, '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762')).toMatchObject({ version: '1.4.1', l2: true })
    expect(officialSingleton(8453, '0x6851D6fDFAfD08c0295C392436245E5bc78B0185')).toBeUndefined()
  })

  it("proxy code: the test data hashes to the table, and every factory's version is in it", () => {
    expect(PROXY_CODE_HASHES[keccak256(PROXY_141)]).toBe('1.4.1')
    expect(PROXY_CODE_HASHES[keccak256(PROXY_100)]).toBe('1.0.0')
    for (const f of PROXY_FACTORIES) expect(Object.values(PROXY_CODE_HASHES)).toContain(f.version)
  })

  it('passkey contracts and names: checksummed and lower-case keys', () => {
    for (const f of PASSKEY_FACTORIES) {
      expect(getAddress(f.address)).toBe(f.address)
      expect(getAddress(f.singleton)).toBe(f.singleton)
    }
    expect(getAddress(PASSKEY_SHARED_SIGNER)).toBe(PASSKEY_SHARED_SIGNER)
    for (const k of Object.keys(NAMES)) expect(k).toBe(k.toLowerCase())
  })
})
