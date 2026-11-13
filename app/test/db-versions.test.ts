// The database between versions of the app open in two tabs: an older tab blocks an upgrade until
// it closes, and from version 2 on a tab gives way to a newer version opened elsewhere.

import { IDBFactory } from 'fake-indexeddb'
import { describe, expect, it } from 'vitest'
import { DB_VERSION, openDb, setting } from '../src/lib/db'

function openAt(factory: IDBFactory, version: number): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = factory.open('winterlock', version)
    r.onupgradeneeded = () => {
      if (!r.result.objectStoreNames.contains('settings')) r.result.createObjectStore('settings', { keyPath: 'key' })
    }
    r.onsuccess = () => res(r.result)
    r.onerror = () => rej(r.error)
  })
}

describe('the database across versions in two tabs', () => {
  it('an older tab that stays open blocks the upgrade, with a message', async () => {
    const factory = new IDBFactory()
    const old = await openAt(factory, 1)
    await expect(openDb(factory)).rejects.toThrow(/older version in another tab: close that tab, then reload this page/)
    old.close()
    const db = await openDb(factory)
    expect(db.version).toBe(DB_VERSION)
    expect(await setting(db, 'missing')).toBeUndefined()
  })

  it('this version gives way to a newer one', async () => {
    const factory = new IDBFactory()
    let newer = 0
    await openDb(factory, 'winterlock', () => newer++)
    const next = await openAt(factory, DB_VERSION + 1)
    expect(newer).toBe(1)
    expect(next.version).toBe(DB_VERSION + 1)
  })
})
