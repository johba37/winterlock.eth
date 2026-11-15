// A board that restarts while a short request waits for its answer. Many ESP32 boards reset when
// a program opens their serial port (DTR and RTS drive EN and BOOT), so the app's first STATUS
// can meet the board's BOOTED. The short requests only read, or cancel, so the client asks again.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { BoardClient, type BoardStatus } from '../src/board/client'
import { Deframer, T, encode } from '../src/board/frame'
import type { Transport, TransportEvents } from '../src/board/transport'
import { hexBytes } from './helpers'

const v = JSON.parse(readFileSync(new URL('../../hardware/board-signer/logic/tests/vectors/frames.json', import.meta.url), 'utf8'))
const STATUS = hexBytes(`0x${v.answers.status.payload}`)

/** Answers its first `restarts` STATUS requests with BOOTED (as a board starting again), then with the status. */
class RestartingBoard implements Transport {
  readonly kind = 'serial' as const
  readonly label = 'a board that restarts'
  private ev: TransportEvents | undefined
  private d = new Deframer()
  statusRequests = 0

  constructor(private restarts: number) {}

  async open(ev: TransportEvents) {
    this.ev = ev
  }

  async write(bytes: Uint8Array) {
    this.d.push(bytes)
    for (let f = this.d.next(); f; f = this.d.next()) {
      if (f.type !== T.STATUS) continue
      this.statusRequests++
      const out = this.statusRequests <= this.restarts ? encode(T.EV_BOOTED, 0, STATUS) : encode(T.A_STATUS, f.id, STATUS)
      queueMicrotask(() => this.ev?.data(out))
    }
  }

  async close() {}
}

describe('a board that restarts during a short request', () => {
  it('asks again and reads the status', async () => {
    const t = new RestartingBoard(1)
    const c = new BoardClient(t)
    const booted: BoardStatus[] = []
    c.onBooted((s) => booted.push(s))
    await c.connect()
    const s = await c.status()
    expect(s.state).toBe('unlocked')
    expect(t.statusRequests).toBe(2)
    expect(booted).toHaveLength(1)
    expect(c.connected).toBe(true)
  })

  it('gives up after its tries', async () => {
    const t = new RestartingBoard(10)
    const c = new BoardClient(t)
    await c.connect()
    await expect(c.status()).rejects.toMatchObject({ code: 'restarted' })
    expect(t.statusRequests).toBe(3)
  })
})
