// The board link's frames and payloads against the Python client's known answers
// (hardware/board-signer/tools/frame_vectors.py writes them from board_client.py).

import { readFileSync } from 'node:fs'
import { toHex } from 'viem'
import { describe, expect, it } from 'vitest'
import { encodeForCore, safeTx } from '../src/lib/safe'
import { parseEnrolled, parseError, parseIdentity, parseSigned, parseStatus, parseTrees, signPayload, enrolPayload } from '../src/board/client'
import { Deframer, crc16, crc32, encode } from '../src/board/frame'
import { hexBytes } from './helpers'

const v = JSON.parse(readFileSync(new URL('../../hardware/board-signer/logic/tests/vectors/frames.json', import.meta.url), 'utf8'))
const b = (h: string) => hexBytes(`0x${h}`)
const h = (x: Uint8Array) => toHex(x).slice(2)

describe('board frames (the Python client’s vectors)', () => {
  it('CRC-16/CCITT-FALSE and CRC-32', () => {
    for (const c of v.crc) {
      expect(crc16(b(c.data))).toBe(c.crc16)
      expect(crc32(b(c.data))).toBe(c.crc32)
    }
  })

  it('encodes every frame as the Python client does, and reads it back', () => {
    for (const f of v.frames) {
      const enc = encode(f.type, f.id, b(f.payload))
      expect(h(enc)).toBe(f.frame)
      const d = new Deframer()
      d.push(enc)
      const got = d.next()!
      expect([got.type, got.id, h(got.payload)]).toEqual([f.type, f.id, f.payload])
      expect(d.next()).toBeNull()
      expect(d.held()).toBe(0)
    }
    expect(() => encode(1, 1, new Uint8Array(16 * 1024 + 1))).toThrow(/too long/)
  })

  it('builds the request payloads the Python client builds', () => {
    for (const r of v.requests) {
      let payload: Uint8Array
      if (r.name === 'setup') payload = b(r.args.appRandom)
      else if (r.name === 'recover') payload = new Uint8Array()
      else if (r.name === 'enrol') payload = enrolPayload(r.args.chain, `0x${r.args.safe}`, r.args.start)
      else payload = signPayload({ chain: r.args.chain, safe: `0x${r.args.safe}`, root: /^0+$/.test(r.args.root) ? undefined : `0x${r.args.root}`, tx: b(r.args.tx), parent: r.args.parent ? b(r.args.parent) : undefined })
      expect(h(payload)).toBe(r.payload)
      expect(h(encode(r.type, r.id, payload))).toBe(r.frame)
    }
  })

  it('encodes a transaction’s fields as the board reads them (the app’s core encoding)', () => {
    for (const t of v.transactions) {
      const f = t.fields
      const tx = safeTx({
        to: `0x${f.to}`,
        value: BigInt(f.value ?? 0),
        data: f.data ? `0x${f.data}` : '0x',
        nonce: BigInt(f.nonce),
        safeTxGas: BigInt(f.safeTxGas ?? 0),
        baseGas: BigInt(f.baseGas ?? 0),
        gasPrice: BigInt(f.gasPrice ?? 0),
        ...(f.gasToken ? { gasToken: `0x${f.gasToken}` } : {}),
        ...(f.refundReceiver ? { refundReceiver: `0x${f.refundReceiver}` } : {}),
      })
      expect(h(encodeForCore(tx))).toBe(t.encoded)
    }
  })

  it('parses the answers as the Python client does', () => {
    const a = v.answers
    const s = parseStatus(b(a.status.payload))
    const ps = a.status.parsed
    expect({ ...s, memberKey: s.memberKey?.slice(2), owner: s.owner?.slice(2).toLowerCase() }).toEqual({
      protocol: ps.protocol,
      version: ps.version,
      state: ps.state === 'ready' ? 'unlocked' : ps.state,
      busy: ps.busy,
      testHooks: ps.test_hooks,
      recovered: ps.recovered,
      memberKey: ps.member_key,
      owner: ps.owner,
      trees: ps.trees,
      storageUsed: ps.storage_used,
      storageSize: ps.storage_size,
      statelessSignatures: ps.stateless_signatures,
    })
    const sg = parseSigned(b(a.signed.payload))
    expect([sg.slot, sg.keyIndex, sg.hash.slice(2), h(sg.data)]).toEqual([a.signed.parsed.slot, a.signed.parsed.key_index, a.signed.parsed.hash, a.signed.parsed.data])
    const en = parseEnrolled(b(a.enrolled.payload))
    const pe = a.enrolled.parsed
    expect([en.chain, en.safe.slice(2).toLowerCase(), en.start, en.height, en.root.slice(2), h(en.signature)]).toEqual([pe.chain, pe.safe, pe.start, pe.height, pe.root, pe.signature])
    const tr = parseTrees(b(a.trees.payload))
    expect(tr.map((t) => [t.chain, t.safe.slice(2).toLowerCase(), t.start, t.height, t.root.slice(2), t.used, t.certified])).toEqual(
      a.trees.parsed.map((t: any) => [t.chain, t.safe, t.start, t.height, t.root, t.used, t.certified]),
    )
    const id = parseIdentity(b(a.identity.payload))
    expect([id.memberKey.slice(2), id.owner.slice(2).toLowerCase(), id.recovered]).toEqual([a.identity.parsed.member_key, a.identity.parsed.owner, a.identity.parsed.recovered])
    expect(parseError(b(a.error.payload))).toEqual({ code: a.error.code, text: a.error.text })
  })

  it('finds the frames in a noisy stream, in pieces, as the Python reader does', () => {
    const s = v.stream
    const bytes = b(s.bytes)
    const d = new Deframer()
    const got: { type: number; id: number; payload: string }[] = []
    let last = 0
    for (const c of [...s.chunks, bytes.length]) {
      d.push(bytes.subarray(last, c))
      last = c
      let f
      while ((f = d.next())) got.push({ type: f.type, id: f.id, payload: h(f.payload) })
    }
    expect(got).toEqual(s.frames)
    expect(d.skipped).toBe(s.noise.length / 2)
    expect(d.held()).toBe(s.held)
    expect(d.noise.startsWith('ets Jun  8 2016')).toBe(true)
  })

  it('gives up a frame that stopped, and finds the next', () => {
    const a = encode(0x88, 7)
    const d = new Deframer()
    d.push(a.subarray(0, 13))
    expect(d.next()).toBeNull()
    d.stalled()
    d.push(a)
    expect(d.next()?.id).toBe(7)
    // one byte at a time
    const e = new Deframer()
    const frames = []
    for (const x of encode(0x81, 300, Uint8Array.from({ length: 70 }, (_, i) => i))) {
      e.push(Uint8Array.of(x))
      const f = e.next()
      if (f) frames.push(f)
    }
    expect(frames.map((f) => [f.type, f.id, f.payload.length])).toEqual([[0x81, 300, 70]])
  })
})
