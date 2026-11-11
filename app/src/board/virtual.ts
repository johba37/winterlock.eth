// The virtual board as a link: the board's logic in a worker (virtual-worker.ts), reached through
// the same frames as a board on USB. A development board: its keys live in this browser.
//
// Restarting it is pressing the board's reset button: the worker stops (what it stored stays) and a
// new one starts from the stored flash, sends BOOTED and asks for the PIN, while the link stays open.

import type { Transport, TransportEvents } from './transport'

export interface Screen {
  pixels: Uint8Array
  text: string
}

type ScreenListener = (s: Screen) => void

export class VirtualTransport implements Transport {
  readonly kind = 'virtual' as const
  readonly label = 'virtual board (this browser)'
  private worker: Worker | undefined
  private events: TransportEvents | undefined
  private listeners = new Set<ScreenListener>()
  private fatalL = new Set<(m: string) => void>()
  screen: Screen | null = null
  fatal: string | null = null

  async open(events: TransportEvents) {
    this.events = events
    await this.boot()
  }

  private boot(): Promise<void> {
    this.fatal = null
    const w = new Worker(new URL('./virtual-worker.ts', import.meta.url), { type: 'module' })
    this.worker = w
    return new Promise<void>((resolve, reject) => {
      w.onmessage = (e: MessageEvent) => {
        const m = e.data
        if (w !== this.worker) return
        if (m.t === 'tx') this.events?.data(m.bytes)
        else if (m.t === 'screen') {
          this.screen = { pixels: m.pixels, text: m.text }
          for (const l of this.listeners) l(this.screen)
        } else if (m.t === 'started') resolve()
        else if (m.t === 'fatal') {
          this.fatal = m.message
          for (const l of this.fatalL) l(m.message)
          reject(new Error(m.message))
          this.stopWorker()
          this.events?.closed(`the virtual board stopped: ${m.message}`)
        }
      }
      w.onerror = (e) => {
        const msg = e.message || 'the virtual board’s worker failed'
        reject(new Error(msg))
        this.events?.closed(msg)
      }
      w.postMessage({ t: 'start' })
    })
  }

  private stopWorker() {
    this.worker?.terminate()
    this.worker = undefined
  }

  async write(bytes: Uint8Array) {
    if (!this.worker) throw new Error('the virtual board isn’t running')
    this.worker.postMessage({ t: 'rx', bytes })
  }

  async close() {
    this.stopWorker()
    this.events = undefined
  }

  /** A button event: 1 left, 2 right, 3 both held. */
  button(event: 1 | 2 | 3) {
    this.worker?.postMessage({ t: 'button', event })
  }

  /** The reset button: a new worker from the stored flash; the link stays open. */
  async restart() {
    this.stopWorker()
    await this.boot()
  }

  onScreen(f: ScreenListener) {
    this.listeners.add(f)
    if (this.screen) f(this.screen)
    return () => this.listeners.delete(f)
  }

  onFatal(f: (m: string) => void) {
    this.fatalL.add(f)
    return () => this.fatalL.delete(f)
  }
}
