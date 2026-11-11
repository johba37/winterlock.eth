// The board's USB link, its frames (hardware/board-signer/PROTOCOL.md): the same bytes as the
// board's proto.rs and the Python client's board_client.py, whose known answers the tests check.
//
//   0   4  magic A5 57 4C 5A
//   4   1  version (1)
//   5   1  type
//   6   2  id: a request's own number, which its answer repeats; 0 for an event
//   8   2  payload length, at most 16,384
//  10   2  CRC-16/CCITT-FALSE of bytes 4..10
//  12   n  payload
// 12+n  4  CRC-32 (zlib's) of bytes 4..12+n
//
// All numbers big-endian. The serial port also carries the bootloader's text, so the reader hunts
// for the magic and checks both CRCs; whatever fails is skipped one byte at a time.

export const MAGIC = Uint8Array.of(0xa5, 0x57, 0x4c, 0x5a)
export const VERSION = 1
export const HEADER = 12
export const MAX_PAYLOAD = 16 * 1024

/** Message types: requests below 0x80, answers and events above. */
export const T = {
  STATUS: 0x01,
  SETUP: 0x02,
  RECOVER: 0x03,
  GAS_KEY: 0x04,
  TREES: 0x05,
  ENROL: 0x06,
  SIGN: 0x07,
  CANCEL: 0x08,
  // test builds only (the firmware's test-hooks feature)
  TEST_BUTTONS: 0x70,
  TEST_SCREEN: 0x71,
  A_STATUS: 0x81,
  A_IDENTITY: 0x82,
  A_GAS_KEY: 0x84,
  A_TREES: 0x85,
  A_ENROLLED: 0x86,
  A_SIGNED: 0x87,
  A_DONE: 0x88,
  A_ERROR: 0x8f,
  EV_BOOTED: 0xa0,
  A_SCREEN: 0xf0,
} as const

// --- checksums ---

const T32 = (() => {
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[i] = c >>> 0
  }
  return t
})()

/** CRC-32 (IEEE 802.3, zlib's crc32). */
export function crc32(data: Uint8Array): number {
  let c = 0xffffffff
  for (let i = 0; i < data.length; i++) c = T32[(c ^ data[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

/** CRC-16/CCITT-FALSE: polynomial 0x1021, initial 0xFFFF, no reflection (binascii.crc_hqx(b, 0xFFFF)). */
export function crc16(data: Uint8Array): number {
  let c = 0xffff
  for (let i = 0; i < data.length; i++) {
    c ^= data[i] << 8
    for (let k = 0; k < 8; k++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) & 0xffff : (c << 1) & 0xffff
  }
  return c
}

// --- frames ---

export interface Frame {
  version: number
  type: number
  id: number
  payload: Uint8Array
}

export function encode(type: number, id: number, payload: Uint8Array = new Uint8Array()): Uint8Array {
  if (payload.length > MAX_PAYLOAD) throw new Error('payload too long for a frame')
  const f = new Uint8Array(HEADER + payload.length + 4)
  const v = new DataView(f.buffer)
  f.set(MAGIC, 0)
  f[4] = VERSION
  f[5] = type
  v.setUint16(6, id)
  v.setUint16(8, payload.length)
  v.setUint16(10, crc16(f.subarray(4, 10)))
  f.set(payload, HEADER)
  v.setUint32(HEADER + payload.length, crc32(f.subarray(4, HEADER + payload.length)))
  return f
}

function find(buf: Uint8Array, len: number): number {
  for (let i = 0; i + 4 <= len; i++) if (buf[i] === 0xa5 && buf[i + 1] === 0x57 && buf[i + 2] === 0x4c && buf[i + 3] === 0x5a) return i
  return -1
}

/**
 * Frames out of a byte stream that also carries other text: whatever doesn't check out is
 * skipped one byte at a time, so a frame that starts inside skipped bytes is still found.
 */
export class Deframer {
  private buf = new Uint8Array(4096)
  private len = 0
  /** Bytes skipped since the start (noise), for diagnostics. */
  skipped = 0
  /** The skipped bytes, as text, up to a few kilobytes (the bootloader's lines). */
  noise = ''

  push(bytes: Uint8Array) {
    if (this.len + bytes.length > this.buf.length) {
      const b = new Uint8Array(Math.max(this.buf.length * 2, this.len + bytes.length))
      b.set(this.buf.subarray(0, this.len))
      this.buf = b
    }
    this.buf.set(bytes, this.len)
    this.len += bytes.length
  }

  /** Bytes held, waiting for the rest of a frame. */
  held(): number {
    return this.len
  }

  private drop(n: number) {
    this.skipped += n
    if (this.noise.length < 4096) this.noise += String.fromCharCode(...this.buf.subarray(0, Math.min(n, 4096)))
    this.buf.copyWithin(0, n, this.len)
    this.len -= n
  }

  /** The next whole frame, if the bytes so far hold one. */
  next(): Frame | null {
    for (;;) {
      const i = find(this.buf, this.len)
      if (i < 0) {
        // keep a tail that could be the start of the magic
        let keep = 0
        for (let k = 3; k >= 1; k--) {
          if (this.len >= k && MAGIC.subarray(0, k).every((m, j) => this.buf[this.len - k + j] === m)) {
            keep = k
            break
          }
        }
        this.drop(this.len - keep)
        return null
      }
      if (i > 0) this.drop(i)
      if (this.len < HEADER) return null
      const v = new DataView(this.buf.buffer, 0, this.len)
      const n = v.getUint16(8)
      if (crc16(this.buf.subarray(4, 10)) !== v.getUint16(10) || n > MAX_PAYLOAD) {
        this.drop(1)
        continue
      }
      if (this.len < HEADER + n + 4) return null
      if (crc32(this.buf.subarray(4, HEADER + n)) !== v.getUint32(HEADER + n)) {
        this.drop(1)
        continue
      }
      const f: Frame = { version: this.buf[4], type: this.buf[5], id: v.getUint16(6), payload: this.buf.slice(HEADER, HEADER + n) }
      this.buf.copyWithin(0, HEADER + n + 4, this.len)
      this.len -= HEADER + n + 4
      return f
    }
  }

  /** After a pause in the stream: a frame that started and stopped is given up. */
  stalled() {
    if (this.len >= 4 && find(this.buf, 4) === 0) this.drop(1)
  }
}

// --- payloads ---

export class Reader {
  private at = 0
  constructor(private b: Uint8Array) {}
  take(n: number): Uint8Array {
    if (this.at + n > this.b.length) throw new Error('the board’s answer is too short')
    const out = this.b.slice(this.at, this.at + n)
    this.at += n
    return out
  }
  u8(): number {
    return this.take(1)[0]
  }
  u16(): number {
    const t = this.take(2)
    return (t[0] << 8) | t[1]
  }
  u32(): number {
    return new DataView(this.take(4).buffer).getUint32(0)
  }
  u64(): bigint {
    return new DataView(this.take(8).buffer).getBigUint64(0)
  }
  text(): string {
    return String.fromCharCode(...this.take(this.u8()))
  }
  end() {
    if (this.at !== this.b.length) throw new Error('the board’s answer is too long')
  }
  rest(): number {
    return this.b.length - this.at
  }
}

export class Writer {
  private parts: number[] = []
  u8(v: number) {
    this.parts.push(v & 0xff)
    return this
  }
  u16(v: number) {
    this.parts.push((v >> 8) & 0xff, v & 0xff)
    return this
  }
  u64(v: bigint | number) {
    const b = new Uint8Array(8)
    new DataView(b.buffer).setBigUint64(0, BigInt(v))
    return this.bytes(b)
  }
  bytes(b: Uint8Array) {
    for (const x of b) this.parts.push(x)
    return this
  }
  out(): Uint8Array {
    return Uint8Array.from(this.parts)
  }
}
