// The TypeScript layer against the Python signer's vectors (core/tests/vectors/): the encodings
// the app hands the core, and the gas account's address.

import { readFileSync } from 'node:fs'
import { getAddress, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { describe, expect, it } from 'vitest'
import { encodeForCore, fromService, contractSignature, parseSignature, pack, blobSignatureOf, execCalldata, execSignatures, decode, safeTx, formatUnits, parseUnits } from '../src/lib/safe'
import { hexBytes, wasm } from './helpers'

const vec = (name: string) => JSON.parse(readFileSync(new URL(`../../core/tests/vectors/${name}`, import.meta.url), 'utf8'))

describe('vectors', () => {
  it('gas account: key and address from the phrase seed', () => {
    for (const k of vec('keys.json').keys) {
      const key = wasm.gas_key(hexBytes(k.seed))
      expect(toHex(key)).toBe(k.gas_key)
      expect(privateKeyToAccount(toHex(key)).address).toBe(k.gas_address)
    }
  })

  it('member key, owner address', () => {
    const k = vec('keys.json').keys[3]
    const b = wasm.KeyBuilder.member(hexBytes(k.seed))
    while (b.done() < b.total()) b.step(64)
    const mk = b.finish()
    expect(toHex(mk.public_key())).toBe(k.member_key)
    expect(getAddress(toHex(mk.owner()))).toBe(k.owner)
    expect(getAddress(toHex(wasm.owner_address(hexBytes(k.member_key))))).toBe(k.owner)
  })

  it('SafeTx hashes from the app encoding of the fields', () => {
    for (const c of vec('safe.json').cases) {
      const t = c.tx
      const tx = fromService({
        to: t.to,
        value: t.value,
        data: t.data,
        operation: t.operation,
        safeTxGas: t.safe_tx_gas,
        baseGas: t.base_gas,
        gasPrice: t.gas_price,
        gasToken: t.gas_token,
        refundReceiver: t.refund_receiver,
        nonce: t.nonce,
      })
      expect(toHex(wasm.safe_tx_hash(BigInt(c.chain), hexBytes(c.safe), encodeForCore(tx)))).toBe(c.hash)
    }
  })

  it('phrase round trip and the parser errors', () => {
    for (const r of vec('phrase.json').round_trips) {
      expect(wasm.phrase_of_seed(hexBytes(r.seed))).toBe(r.words)
      expect(toHex(wasm.phrase_to_seed(r.words))).toBe(r.seed)
    }
    expect(() => wasm.phrase_to_seed('abandon abandon')).toThrow(/24 words/)
  })

  it('a transaction signature is recognised as its tree’s', () => {
    const l = vec('owner.json').layouts.tx
    const p = l.tree
    const r = wasm.tree_signature_use(hexBytes(l.data), BigInt(p.chain), hexBytes(p.owner), hexBytes(p.safe), 2, p.gen, BigInt(p.start), 6, hexBytes(l.root))
    // the vector's data names device 2 but its tree is device 0's: not this device's tree
    expect(r).toBeUndefined()
    const r0 = wasm.tree_signature_use(hexBytes(l.data), BigInt(p.chain), hexBytes(p.owner), hexBytes(p.safe), 0, p.gen, BigInt(p.start), 6, hexBytes(l.root))
    expect(r0).toBeUndefined()
    // with the device byte set to the tree's device it is the tree's
    const d = hexBytes(l.data)
    d[1] = 0
    const r1 = wasm.tree_signature_use(d, BigInt(p.chain), hexBytes(p.owner), hexBytes(p.safe), 0, p.gen, BigInt(p.start), 6, hexBytes(l.root))!
    expect(Number(new DataView(r1.buffer, r1.byteOffset).getBigUint64(0))).toBe(l.key_index)
    expect(toHex(r1.slice(17, 49))).toBe(l.hash)
  })
})

describe('Safe formats', () => {
  it('contract signatures, the blob, and finding an owner in it', () => {
    const a = getAddress('0x00000000000000000000000000000000000000aa')
    const b = getAddress('0x00000000000000000000000000000000000000bb')
    const da = Uint8Array.from([1, 2, 3])
    const db = Uint8Array.from([4, 5, 6, 7])
    const s = contractSignature(a, da)
    expect(parseSignature(s)).toEqual({ owner: a, data: da, contract: true })
    const blob = pack([
      { owner: b, data: db, contract: true },
      { owner: a, data: da, contract: true },
    ])
    expect(blobSignatureOf(blob, a)).toEqual(da)
    expect(blobSignatureOf(blob, b)).toEqual(db)
    const tx = safeTx({ to: a, value: 5n, nonce: 3n })
    expect(execSignatures(execCalldata(tx, blob))).toBe(blob)
  })

  it('decodes transfers and marks anything else', () => {
    const safe = getAddress('0x00000000000000000000000000000000000000cc')
    const to = getAddress('0x00000000000000000000000000000000000000dd')
    expect(decode(safeTx({ to, value: 10n ** 16n, nonce: 0n }), safe).decoded).toEqual({ kind: 'eth', to, value: 10n ** 16n })
    const data = ('0xa9059cbb' + to.slice(2).padStart(64, '0') + (1234n).toString(16).padStart(64, '0')) as `0x${string}`
    expect(decode(safeTx({ to: safe, data, nonce: 0n }), getAddress('0x00000000000000000000000000000000000000ee')).decoded).toEqual({ kind: 'erc20', token: safe, to, amount: 1234n })
    const raw = decode(safeTx({ to, data: '0xdeadbeef', nonce: 0n }), safe)
    expect(raw.decoded.kind).toBe('raw')
    expect(raw.warnings.join(' ')).toMatch(/Not decoded/)
    expect(decode(safeTx({ to: safe, nonce: 1n }), safe).decoded.kind).toBe('cancel')
    expect(decode(safeTx({ to, nonce: 1n, operation: 1, data: '0x12345678' }), safe).warnings[0]).toMatch(/DELEGATECALL/)
  })

  it('amounts, exactly', () => {
    expect(formatUnits(10n ** 17n, 18)).toBe('0.1')
    expect(formatUnits(1234567890n, 6)).toBe('1,234.56789')
    expect(parseUnits('0.000000000000000001', 18)).toBe(1n)
    expect(parseUnits('1.5', 6)).toBe(1_500_000n)
    expect(() => parseUnits('1.0000001', 6)).toThrow(/decimals/)
    expect(() => parseUnits('abc', 18)).toThrow()
  })
})
