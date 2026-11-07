// A Web Worker of the core: the WebAssembly bindings and the operations of ops.ts, off the page's
// thread. device-worker.ts and member-worker.ts start one of each kind.

import init, * as wasm from '../wasm/core.js'
import { deviceOps, memberOps } from './ops'

export function serve(kind: 'device' | 'member') {
  const ready = init()
  let ops: ReturnType<typeof deviceOps> | undefined
  self.onmessage = async (e: MessageEvent) => {
    const { id, op, args } = e.data
    try {
      await ready
      ops ??= kind === 'member' ? memberOps(wasm) : deviceOps(wasm)
      const f = ops[op]
      if (!f) throw new Error(`unknown operation ${op}`)
      let last = 0
      const value = await f(args, (done, total) => {
        const now = performance.now()
        if (now - last > 50 || done === total) {
          last = now
          self.postMessage({ id, progress: { done, total } })
        }
      })
      self.postMessage({ id, ok: true, value })
    } catch (err) {
      self.postMessage({ id, ok: false, error: err instanceof Error ? err.message : String(err) })
    }
  }
}
