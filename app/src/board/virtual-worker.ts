// The virtual board's worker: the board's logic in WebAssembly, its flash in IndexedDB
// (flash-store.ts), its randomness from crypto.getRandomValues.
//
// One virtual board per browser profile: the worker holds a Web Lock for as long as it runs, and a
// second tab's board refuses to start. Two boards started from the same stored flash would each
// keep their own key log in memory, and could use a one-time key twice.
//
// Messages in:  {t: 'start'} | {t: 'rx', bytes} | {t: 'button', event}
// Messages out: {t: 'started'} | {t: 'tx', bytes} | {t: 'screen', pixels, text} | {t: 'fatal', message}

import init, * as board from '../wasm/board.js'
import { LOCK, idbSectors, openFlash } from './flash-store'
import { VirtualBoardRunner } from './runner'

declare const self: DedicatedWorkerGlobalScope

let runner: VirtualBoardRunner | undefined
const post = (m: unknown, transfer: Transferable[] = []) => self.postMessage(m, transfer)

self.onmessage = async (e: MessageEvent) => {
  const m = e.data
  try {
    if (m.t === 'start') {
      let held = false
      // a board this page just stopped releases the lock a moment later
      for (let i = 0; i < 20 && !held; i++) {
        if (i) await new Promise((r) => setTimeout(r, 100))
        held = await new Promise<boolean>((resolve) => {
          navigator.locks.request(LOCK, { ifAvailable: true }, (lock) => {
            resolve(!!lock)
            // held until the worker stops
            return lock ? new Promise(() => {}) : undefined
          })
        })
      }
      if (!held) throw new Error('The virtual board is running in another tab of this browser: close it there first.')
      await init()
      runner = new VirtualBoardRunner(board, idbSectors(await openFlash()), {
        frame: (b) => post({ t: 'tx', bytes: b }, [b.buffer]),
        screen: (p, text) => post({ t: 'screen', pixels: p, text }),
        fatal: (message) => post({ t: 'fatal', message }),
      })
      await runner.start()
      post({ t: 'started' })
    } else if (m.t === 'rx') await runner?.receive(m.bytes)
    else if (m.t === 'button') await runner?.button(m.event)
  } catch (err) {
    post({ t: 'fatal', message: err instanceof Error ? err.message : String(err) })
  }
}
