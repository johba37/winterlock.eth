// The virtual board's host: the board's logic in WebAssembly (hardware/board-signer/wasm), its
// flash kept sector by sector in a store, and one rule the real board keeps with its flash:
// nothing the board sends leaves before the sectors it wrote are stored. After each request or
// button press the changed sectors are saved (IndexedDB: a strict-durability transaction,
// completed), and only then are the board's frames passed on. So a one-time signature never
// leaves before its key log record is stored, and a page that closes mid-signature loses only
// what never left.
//
// The worker (virtual-worker.ts) runs one with IndexedDB; the tests run one in Node with memory.

import type * as BoardWasm from '../wasm/board.js'

/** Sectors by index; a sector of all 0xFF (erased) is stored as missing. */
export interface SectorStore {
  load(): Promise<Map<number, Uint8Array>>
  save(changed: Map<number, Uint8Array | null>): Promise<void>
}

export interface RunnerEvents {
  /** A frame from the board, once what it depends on is stored. */
  frame(bytes: Uint8Array): void
  /** A screen, as soon as it is drawn (progress screens too). */
  screen(pixels: Uint8Array, text: string): void
  /** The board stopped: its storage failed or the logic panicked. */
  fatal(message: string): void
}

export const LEFT = 1
export const RIGHT = 2
export const BOTH = 3

export class MemorySectors implements SectorStore {
  sectors = new Map<number, Uint8Array>()
  saves = 0
  async load() {
    return new Map(this.sectors)
  }
  async save(changed: Map<number, Uint8Array | null>) {
    for (const [i, s] of changed) {
      if (s) this.sectors.set(i, s.slice())
      else this.sectors.delete(i)
    }
    this.saves++
  }
}

export class VirtualBoardRunner {
  private board: BoardWasm.VirtualBoard | undefined
  private outbox: Uint8Array[] = []
  private queue: Promise<void> = Promise.resolve()
  private dead: string | undefined
  /** The last screen. */
  pixels = new Uint8Array(1024)
  text = ''

  constructor(
    private w: typeof BoardWasm,
    private store: SectorStore,
    private ev: RunnerEvents,
  ) {}

  /** Starts the board from the stored flash: it shows its first screen and sends BOOTED. */
  start(): Promise<void> {
    return this.op(async () => {
      const size = this.w.VirtualBoard.partition_size()
      const sector = this.w.VirtualBoard.sector_size()
      const stored = await this.store.load()
      let image = new Uint8Array()
      if (stored.size) {
        image = new Uint8Array(size).fill(0xff)
        for (const [i, s] of stored) image.set(s, i * sector)
      }
      const host = {
        // views into the WebAssembly memory: copied before the call returns
        send: (b: Uint8Array) => this.outbox.push(b.slice()),
        show: (p: Uint8Array, t: string) => {
          this.pixels = p.slice()
          this.text = t
          this.ev.screen(this.pixels, t)
        },
      }
      this.board = new this.w.VirtualBoard(host, image)
    })
  }

  /** Bytes from the app. */
  receive(bytes: Uint8Array): Promise<void> {
    return this.op(() => this.board!.receive(bytes))
  }

  /** A button event: LEFT, RIGHT or BOTH (held). */
  button(event: number): Promise<void> {
    return this.op(() => this.board!.button(event))
  }

  get unlocked(): boolean {
    return this.board?.unlocked() ?? false
  }

  /** Stops the board as a pulled cable would: what is stored stays. */
  stop() {
    this.dead ??= 'stopped'
    this.board?.free()
    this.board = undefined
  }

  private op(f: () => void | Promise<void>): Promise<void> {
    const run = async () => {
      if (this.dead) return
      try {
        await f()
        await this.persist()
      } catch (e) {
        // nothing leaves that depends on what failed
        this.outbox = []
        this.dead = e instanceof Error ? e.message : String(e)
        this.board = undefined
        this.ev.fatal(this.dead)
        return
      }
      const out = this.outbox
      this.outbox = []
      for (const b of out) this.ev.frame(b)
    }
    this.queue = this.queue.then(run)
    return this.queue
  }

  private async persist() {
    const b = this.board
    if (!b) return
    const dirty = b.take_dirty()
    if (!dirty.length) return
    const changed = new Map<number, Uint8Array | null>()
    for (const i of dirty) {
      const s = b.sector(i)
      changed.set(i, s.every((x) => x === 0xff) ? null : s)
    }
    await this.store.save(changed)
  }
}
