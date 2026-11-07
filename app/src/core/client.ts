// The page's side of the core's workers: calls with progress, and the two kinds of worker.

import type { Progress } from './ops'

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void; progress?: Progress }

export class CoreError extends Error {}

export class WorkerClient {
  private worker: Worker
  private next = 1
  private pending = new Map<number, Pending>()

  constructor(kind: 'device' | 'member') {
    // two literal URLs, so that the bundler finds both workers
    this.worker =
      kind === 'member'
        ? new Worker(new URL('./member-worker.ts', import.meta.url), { type: 'module' })
        : new Worker(new URL('./device-worker.ts', import.meta.url), { type: 'module' })
    this.worker.onmessage = (e: MessageEvent) => {
      const { id, ok, value, error, progress } = e.data
      const p = this.pending.get(id)
      if (!p) return
      if (progress) {
        p.progress?.(progress.done, progress.total)
        return
      }
      this.pending.delete(id)
      if (ok) p.resolve(value)
      else p.reject(new CoreError(error))
    }
    this.worker.onerror = (e) => {
      for (const p of this.pending.values()) p.reject(new CoreError(e.message || 'the worker failed'))
      this.pending.clear()
    }
  }

  call<T>(op: string, args: unknown = {}, progress?: Progress): Promise<T> {
    const id = this.next++
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject, progress })
      this.worker.postMessage({ id, op, args })
    })
  }

  terminate() {
    this.worker.terminate()
    for (const p of this.pending.values()) p.reject(new CoreError('stopped'))
    this.pending.clear()
  }
}

let device: WorkerClient | undefined

/** The long-lived device worker. */
export function core(): WorkerClient {
  device ??= new WorkerClient('device')
  return device
}

/** A new member session. Call end() as soon as the member key has signed: it terminates the
 * worker, which discards the phrase's seed and the member key with its memory. */
export function memberSession() {
  const w = new WorkerClient('member')
  return {
    call: <T>(op: string, args?: unknown, progress?: Progress) => w.call<T>(op, args, progress),
    end() {
      // it zeroes what it holds, then it stops; stopping discards its memory either way
      w.call('forget').catch(() => {}).finally(() => w.terminate())
      setTimeout(() => w.terminate(), 500)
    },
  }
}

export type MemberSession = ReturnType<typeof memberSession>
