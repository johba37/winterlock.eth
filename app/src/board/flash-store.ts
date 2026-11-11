// The virtual board's flash in IndexedDB: a database of its own, "winterlock-board", apart from the
// app's, as a board is apart from the computer. One record per sector that isn't erased.

import type { SectorStore } from './runner'

export const FLASH_DB = 'winterlock-board'
/** Held by the virtual board's worker while it runs: one virtual board per browser profile. */
export const LOCK = 'winterlock-virtual-board'

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((res, rej) => {
    r.onsuccess = () => res(r.result)
    r.onerror = () => rej(r.error)
  })
}

export async function openFlash(factory: IDBFactory = indexedDB): Promise<IDBDatabase> {
  const r = factory.open(FLASH_DB, 1)
  r.onupgradeneeded = () => r.result.createObjectStore('sectors')
  return req(r)
}

export function idbSectors(db: IDBDatabase): SectorStore {
  return {
    async load() {
      const t = db.transaction('sectors', 'readonly')
      const s = t.objectStore('sectors')
      const [keys, values] = await Promise.all([req(s.getAllKeys()), req(s.getAll())])
      return new Map(keys.map((k, i) => [Number(k), new Uint8Array(values[i] as ArrayBuffer)]))
    },
    save(changed) {
      return new Promise<void>((res, rej) => {
        const t = db.transaction('sectors', 'readwrite', { durability: 'strict' })
        const s = t.objectStore('sectors')
        for (const [i, b] of changed) {
          if (b) s.put(b.slice().buffer, i)
          else s.delete(i)
        }
        t.oncomplete = () => res()
        t.onerror = () => rej(t.error)
        t.onabort = () => rej(t.error ?? new Error('the virtual board’s flash write was aborted'))
      })
    },
  }
}

/** Sectors stored (not erased): 0 for a board that was never set up or was erased. */
export async function storedSectors(factory: IDBFactory = indexedDB): Promise<number> {
  const db = await openFlash(factory)
  try {
    return await req(db.transaction('sectors', 'readonly').objectStore('sectors').count())
  } finally {
    db.close()
  }
}
