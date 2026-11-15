// The app's side of the board's USB link (PROTOCOL.md): every request, with its own id, and the
// board's answers and errors. It agrees with the Python client (tools/board_client.py) byte for
// byte; the tests check its frames against that client's.
//
// Some requests wait for the member on the board: setup and recovery (minutes, at the member's
// pace), an enrolment (the member confirms, then about 42 s for the tree and up to 32 s for its
// certificate on the chip) and a signature. They have no timeout: the caller shows progress and
// may cancel (an AbortSignal sends CANCEL). Once the member has confirmed on the board, the board
// finishes the job and answers with its result, cancelled or not.
//
// While the board computes it doesn't read the port, and bytes sent then may be lost: the short
// requests (STATUS, GAS_KEY, TREES, CANCEL) are retried after a timeout.

import { type Address, type Hex, getAddress, toHex } from 'viem'
import { Deframer, type Frame, Reader, T, Writer, encode } from './frame'
import type { Transport } from './transport'

export const ERROR_CODES: Record<number, string> = {
  1: 'unknown type',
  2: 'bad payload',
  3: 'bad version',
  4: 'busy',
  5: 'locked',
  6: 'not set up',
  7: 'already set up',
  8: 'rejected',
  9: 'cancelled',
  10: 'refused',
  11: 'storage failed',
  12: 'storage full',
  13: 'storage damaged',
}

export const CODE = { BUSY: 4, LOCKED: 5, NOT_SET_UP: 6, ALREADY_SET_UP: 7, REJECTED: 8, CANCELLED: 9, REFUSED: 10, DAMAGED: 13 } as const

/** Where a request failed: the board's error code, or the link. */
export type Failure = number | 'timeout' | 'disconnected' | 'restarted'

export class BoardError extends Error {
  constructor(
    readonly code: Failure,
    readonly text: string,
  ) {
    super(BoardError.say(code, text))
  }

  static say(code: Failure, text: string): string {
    switch (code) {
      case CODE.LOCKED:
        return 'The board is locked: enter your PIN on the board.'
      case CODE.REJECTED:
        return 'Rejected on the board: nothing was signed.'
      case CODE.CANCELLED:
        return 'Cancelled: the board signed nothing.'
      case CODE.BUSY:
        return 'The board is busy with another request: finish or reject it on the board.'
      case 'timeout':
        return `The board doesn’t answer (${text}). Check the cable, or restart the board.`
      case 'disconnected':
        return `The board’s link closed (${text}).`
      case 'restarted':
        return 'The board restarted: whatever it was doing was dropped. Enter the PIN on the board, then try again.'
      default:
        return `The board says: ${text} (${ERROR_CODES[code] ?? `error ${code}`}).`
    }
  }
}

export type BoardState = 'blank' | 'locked' | 'unlocked' | 'damaged'
const STATES: BoardState[] = ['blank', 'locked', 'unlocked', 'damaged']

export interface BoardStatus {
  protocol: number
  version: string
  state: BoardState
  busy: boolean
  testHooks: boolean
  recovered: boolean
  /** null while blank */
  memberKey: Hex | null
  owner: Address | null
  trees: number
  storageUsed: number
  storageSize: number
  statelessSignatures: number
}

export interface Identity {
  memberKey: Hex
  owner: Address
  recovered: boolean
}

export interface BoardTree {
  chain: number
  safe: Address
  start: number
  height: number
  /** 24 bytes */
  root: Hex
  used: number
  certified: boolean
}

export interface Enrolled {
  chain: number
  safe: Address
  start: number
  height: number
  root: Hex
  /** the member key's stateless signature of the tree certificate */
  signature: Uint8Array
}

export interface Signed {
  slot: number
  keyIndex: number
  hash: Hex
  /** the owner signature data: [slot][device 0][Safe][SafeTx words][WOTS][path] */
  data: Uint8Array
}

export interface SignRequest {
  chain: number
  safe: Address
  /** the key tree to sign with (24 bytes), or none for the board's newest for this Safe */
  root?: Hex
  /** the SafeTx fields in the core's encoding (safe.ts, encodeForCore) */
  tx: Uint8Array
  /** for approveHash on a parent Safe: the parent transaction's fields */
  parent?: Uint8Array
}

export interface Waiting {
  signal?: AbortSignal
}

const hex = (b: Uint8Array) => toHex(b)
const bytes = (h: string) => Uint8Array.from((h.startsWith('0x') ? h.slice(2) : h).match(/../g) ?? [], (x) => parseInt(x, 16))
const isZero = (b: Uint8Array) => b.every((x) => x === 0)

export function parseStatus(p: Uint8Array): BoardStatus {
  const r = new Reader(p)
  const protocol = r.u8()
  const version = r.text()
  const state = STATES[r.u8()]
  if (!state) throw new Error('the board reports an unknown state')
  const busy = r.u8() === 1
  const flags = r.u8()
  const mk = r.take(32)
  const owner = r.take(20)
  const s: BoardStatus = {
    protocol,
    version,
    state,
    busy,
    testHooks: (flags & 1) !== 0,
    recovered: (flags & 2) !== 0,
    memberKey: isZero(mk) ? null : hex(mk),
    owner: isZero(owner) ? null : getAddress(hex(owner)),
    trees: r.u16(),
    storageUsed: r.u32(),
    storageSize: r.u32(),
    statelessSignatures: r.u32(),
  }
  r.end()
  return s
}

export function parseIdentity(p: Uint8Array): Identity {
  const r = new Reader(p)
  const id = { memberKey: hex(r.take(32)), owner: getAddress(hex(r.take(20))), recovered: r.u8() === 1 }
  r.end()
  return id
}

export function parseTrees(p: Uint8Array): BoardTree[] {
  const r = new Reader(p)
  const n = r.u16()
  const out: BoardTree[] = []
  for (let i = 0; i < n; i++) {
    out.push({
      chain: Number(r.u64()),
      safe: getAddress(hex(r.take(20))),
      start: Number(r.u64()),
      height: r.u8(),
      root: hex(r.take(24)),
      used: r.u16(),
      certified: r.u8() === 1,
    })
  }
  r.end()
  return out
}

export function parseEnrolled(p: Uint8Array): Enrolled {
  const r = new Reader(p)
  const e = { chain: Number(r.u64()), safe: getAddress(hex(r.take(20))), start: Number(r.u64()), height: r.u8(), root: hex(r.take(24)), signature: r.take(r.rest()) }
  if (e.signature.length !== 5684) throw new Error(`a tree certificate is 5,684 bytes, not ${e.signature.length}`)
  return e
}

export function parseSigned(p: Uint8Array): Signed {
  const r = new Reader(p)
  const slot = r.u8()
  const keyIndex = Number(r.u64())
  const hash = hex(r.take(32))
  const data = r.take(r.u16())
  r.end()
  return { slot, keyIndex, hash, data }
}

export function parseError(p: Uint8Array): { code: number; text: string } {
  const r = new Reader(p)
  return { code: r.u8(), text: r.text() }
}

export function parseScreen(p: Uint8Array): string[] {
  const r = new Reader(p)
  const n = r.u8()
  return Array.from({ length: n }, () => r.text())
}

export function enrolPayload(chain: number, safe: Address, start: number): Uint8Array {
  return new Writer().u64(chain).bytes(bytes(safe)).u64(start).out()
}

export function signPayload(s: SignRequest): Uint8Array {
  const root = s.root ? bytes(s.root) : new Uint8Array(24)
  if (root.length !== 24) throw new Error('a tree root is 24 bytes')
  const parent = s.parent ?? new Uint8Array()
  return new Writer().u64(s.chain).bytes(bytes(s.safe)).bytes(root).u16(s.tx.length).bytes(s.tx).u16(parent.length).bytes(parent).out()
}

interface Pending {
  type: number
  answer: number
  resolve(f: Frame): void
  reject(e: Error): void
}

type Listener<A> = (a: A) => void

export class BoardClient {
  private d = new Deframer()
  private pending = new Map<number, Pending>()
  private nextId = 1
  private quiet: ReturnType<typeof setTimeout> | undefined
  private open = false
  private booted = new Set<Listener<BoardStatus>>()
  private closedL = new Set<Listener<string>>()
  /** Frames that answered no request of this client (another client's, or late ones). */
  strays = 0

  constructor(readonly transport: Transport) {}

  async connect() {
    await this.transport.open({ data: (b) => this.data(b), closed: (why) => this.closed(why) })
    this.open = true
  }

  get connected() {
    return this.open
  }

  /** A request of this client is waiting for its answer. */
  get busy() {
    return this.pending.size > 0
  }

  /** The bootloader's text and anything else that wasn't a frame, for diagnostics. */
  get noise() {
    return this.d.noise
  }

  onBooted(f: Listener<BoardStatus>) {
    this.booted.add(f)
    return () => this.booted.delete(f)
  }

  onClosed(f: Listener<string>) {
    this.closedL.add(f)
    return () => this.closedL.delete(f)
  }

  async close() {
    if (!this.open) return
    await this.transport.close()
    this.closed('closed by the app')
  }

  private closed(why: string) {
    if (!this.open) return
    this.open = false
    clearTimeout(this.quiet)
    for (const p of this.pending.values()) p.reject(new BoardError('disconnected', why))
    this.pending.clear()
    for (const f of this.closedL) f(why)
  }

  private data(b: Uint8Array) {
    this.d.push(b)
    this.drain()
  }

  private drain() {
    let f: Frame | null
    while ((f = this.d.next())) this.frame(f)
    clearTimeout(this.quiet)
    // a frame that started and stopped for 500 ms is given up (the Python client's pause)
    if (this.d.held())
      this.quiet = setTimeout(() => {
        const before = this.d.held()
        this.d.stalled()
        if (this.d.held() !== before) this.drain()
      }, 500)
  }

  private frame(f: Frame) {
    if (f.type === T.EV_BOOTED) {
      // the board started again: whatever it was doing is gone
      for (const p of this.pending.values()) p.reject(new BoardError('restarted', 'the board restarted'))
      this.pending.clear()
      let s: BoardStatus
      try {
        s = parseStatus(f.payload)
      } catch {
        return
      }
      for (const l of this.booted) l(s)
      return
    }
    const p = this.pending.get(f.id)
    if (!p) {
      this.strays++
      return
    }
    this.pending.delete(f.id)
    if (f.type === T.A_ERROR) {
      let e = { code: 0, text: 'an error the app can’t read' }
      try {
        e = parseError(f.payload)
      } catch {
        /* keep the generic one */
      }
      p.reject(new BoardError(e.code, e.text))
    } else if (f.type !== p.answer) {
      p.reject(new Error(`the board answered request type ${p.type} with type ${f.type}`))
    } else p.resolve(f)
  }

  private id(): number {
    const id = this.nextId
    this.nextId = (this.nextId % 0xffff) + 1
    return id
  }

  /** Sends a request and waits for its answer (no timeout unless one is given). */
  async request(type: number, payload: Uint8Array, answer: number, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<Frame> {
    if (!this.open) throw new BoardError('disconnected', 'no board connected')
    opts.signal?.throwIfAborted()
    const id = this.id()
    let timer: ReturnType<typeof setTimeout> | undefined
    let onAbort: (() => void) | undefined
    const done = new Promise<Frame>((resolve, reject) => {
      this.pending.set(id, { type, answer, resolve, reject })
      if (opts.timeoutMs) {
        timer = setTimeout(() => {
          if (this.pending.delete(id)) reject(new BoardError('timeout', `no answer in ${opts.timeoutMs! / 1000} s`))
        }, opts.timeoutMs)
      }
      if (opts.signal) {
        onAbort = () => {
          void this.cancelWhile(id)
        }
        opts.signal.addEventListener('abort', onAbort, { once: true })
      }
    })
    try {
      await this.transport.write(encode(type, id, payload))
      return await done
    } finally {
      clearTimeout(timer)
      this.pending.delete(id)
      if (onAbort) opts.signal!.removeEventListener('abort', onAbort)
    }
  }

  /** CANCEL until the request `id` is answered (the board may be computing and miss a frame). */
  private async cancelWhile(id: number) {
    for (let i = 0; i < 20 && this.pending.has(id) && this.open; i++) {
      try {
        await this.cancel()
        return
      } catch {
        /* the board missed it: again */
      }
    }
  }

  /**
   * A short request: a timeout, and retries (each with a new id), after a timeout or after the
   * board restarted while it waited. Many ESP32 boards reset when their port opens, so the first
   * STATUS can meet BOOTED. Every short request only reads, or cancels, so asking again is safe.
   */
  private async short(type: number, payload: Uint8Array, answer: number, timeoutMs = 4000, tries = 3): Promise<Frame> {
    let last: unknown
    for (let i = 0; i < tries; i++) {
      try {
        return await this.request(type, payload, answer, { timeoutMs })
      } catch (e) {
        last = e
        if (!(e instanceof BoardError && (e.code === 'timeout' || e.code === 'restarted'))) throw e
      }
    }
    throw last
  }

  async status(): Promise<BoardStatus> {
    return parseStatus((await this.short(T.STATUS, new Uint8Array(), T.A_STATUS)).payload)
  }

  /** Setup on the board, with the app's 32 random bytes; the member goes through it on the board. */
  async setup(appRandom: Uint8Array, w: Waiting = {}): Promise<Identity> {
    if (appRandom.length !== 32) throw new Error('the app’s randomness is 32 bytes')
    return parseIdentity((await this.request(T.SETUP, appRandom, T.A_IDENTITY, w)).payload)
  }

  /** Recovery: the member enters the 24 words and a PIN on the board. */
  async recover(w: Waiting = {}): Promise<Identity> {
    return parseIdentity((await this.request(T.RECOVER, new Uint8Array(), T.A_IDENTITY, w)).payload)
  }

  /** The gas account's private key (unlocked boards only). */
  async gasKey(): Promise<Uint8Array> {
    const k = (await this.short(T.GAS_KEY, new Uint8Array(), T.A_GAS_KEY)).payload
    if (k.length !== 32) throw new Error('a gas key is 32 bytes')
    return k
  }

  async trees(): Promise<BoardTree[]> {
    return parseTrees((await this.short(T.TREES, new Uint8Array(), T.A_TREES)).payload)
  }

  async enrol(chain: number, safe: Address, start: number, w: Waiting = {}): Promise<Enrolled> {
    return parseEnrolled((await this.request(T.ENROL, enrolPayload(chain, safe, start), T.A_ENROLLED, w)).payload)
  }

  async sign(s: SignRequest, w: Waiting = {}): Promise<Signed> {
    return parseSigned((await this.request(T.SIGN, signPayload(s), T.A_SIGNED, w)).payload)
  }

  /** Cancels the request the board is working on, if any. */
  async cancel(): Promise<void> {
    await this.short(T.CANCEL, new Uint8Array(), T.A_DONE, 3000, 2)
  }

  // --- test builds only (the firmware's test hooks) ---

  /** Presses buttons ("L", "R", "B" for both) and returns the screen's text after them. */
  async testButtons(events: string): Promise<string[]> {
    const ev = Uint8Array.from(events, (c) => ({ L: 1, R: 2, B: 3 })[c as 'L' | 'R' | 'B'] ?? 0)
    return parseScreen((await this.request(T.TEST_BUTTONS, ev, T.A_SCREEN, { timeoutMs: 600_000 })).payload)
  }

  async testScreen(): Promise<string[]> {
    return parseScreen((await this.short(T.TEST_SCREEN, new Uint8Array(), T.A_SCREEN)).payload)
  }
}
