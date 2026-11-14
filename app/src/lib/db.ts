// The app's storage: one IndexedDB database per origin. In the first round nothing is encrypted at
// rest (docs/notes/signer-app.md, decision 3): the device's own screen lock protects it.
//
// Stores:
//   device     "this": the member's owner, this device's number, seed and key, the gas key, and which
//              derivation made them (KEYS; a record without it is from a build before ERC-8499)
//   certs      device certificates this device holds, per chain (signed by the member key)
//   trees      key trees: where they belong, the salt (secret), the root, the public cache
//   uses       the key log: one record per one-time key used, unique per (chain, Safe, root, key)
//   stateless  stateless signatures, recorded before they are made (they count against a budget)
//   safes      the Safes this member joined, per chain
//   settings   RPC URLs and the like
//   checked    executions whose signatures the stale-log check has already compared
//   held       this owner's signatures the Transaction Service didn't keep (it keeps the first)
//   dapp       (version 2) the SafeTx hashes the app gave dapps over WalletConnect, with what it
//              learned of their execution: for receipts and wallet_getCallsStatus
//
// Writes that a signature depends on use a strict-durability transaction and wait for it to
// complete: the record is on disk before the signature exists.

export type Hex = `0x${string}`

export const DB_NAME = 'winterlock'
export const DB_VERSION = 2

/** The derivation this build's keys follow: ERC-8499 (core: derive::erc8499), since 2026-11-14. */
export const KEYS = 'erc-8499'

/** The last build before ERC-8499, which still opens the Safes of devices it set up. */
export const EARLIER_BUILD = {
  commit: '494703c',
  cid: 'bafybeieyirqeaqtufndkvf2a7rcz2lxfhjbj7py6icoy22jfwt6smexuja',
  url: 'https://bafybeieyirqeaqtufndkvf2a7rcz2lxfhjbj7py6icoy22jfwt6smexuja.ipfs.inbrowser.link/',
} as const

export interface DeviceRecord {
  id: 'this'
  /** KEYS. Absent in a record of an earlier build, whose keys came from the phrase's entropy under Keccak labels: this
   * build neither makes nor uses those. */
  keys?: typeof KEYS
  owner: Hex
  memberKey: Hex
  gasKey: Hex
  gasAddress: Hex
  device: number
  seed: Hex
  publicKey: Hex
  keptLeaves: Hex
  how: 'create' | 'pair'
  createdAt: number
}

export interface CertRecord {
  chain: number
  device: number
  generation: number
  key: Hex
  signature: Hex
  status: 'pending' | 'submitted'
  tx?: Hex
  at: number
}

export interface TreeRecord {
  id: string
  chain: number
  safe: Hex
  owner: Hex
  device: number
  generation: number
  start: number
  height: number
  salt: Hex
  root: Hex
  cache: Hex
  createdAt: number
  enrolTx?: Hex
}

export interface UseRecord {
  chain: number
  safe: string // lower case
  root: Hex
  keyIndex: number
  nonce: number
  slot: number
  start: number
  hash: Hex
  at: number
}

export interface StatelessRecord {
  id?: number
  kind: 'device-cert' | 'revocation' | 'tree-cert'
  signer: 'member' | 'device'
  chain: number
  detail: string
  at: number
}

export interface SafeRecord {
  chain: number
  safe: Hex
  addedAt: number
}

export interface CheckedRecord {
  txHash: Hex
  chain: number
  at: number
}

/** A Safe transaction proposed for a dapp (lib/walletconnect.ts); the dapp got its SafeTx hash. */
export interface DappTxRecord {
  /** lower case */
  safeTxHash: Hex
  chain: number
  safe: Hex
  nonce: number
  /** 1 for a call, more for a batch */
  calls: number
  method: string
  /** the WalletConnect request and session it answered */
  requestId: number
  topic: string
  /** the dapp as it described itself (unverified) */
  dapp: { name: string; url: string }
  at: number
  /** whether the answer reached the relay before the request expired */
  answered: boolean
  /** the transaction that executed it, once known */
  execution?: { tx: Hex; success: boolean }
}

export interface HeldRecord {
  safeTxHash: Hex
  chain: number
  safe: Hex
  signature: Hex
  at: number
}

const STRICT: IDBTransactionOptions = { durability: 'strict' }

export function treeId(chain: number, safe: string, root: string): string {
  return `${chain}:${safe.toLowerCase()}:${root.toLowerCase()}`
}

/** Opens the app's database, upgrading it if needed. An open tab of an older version blocks the
 * upgrade (it has to close first); this version gives way to a newer one opened in another tab and
 * calls `onNewer`. */
export function openDb(factory: IDBFactory = indexedDB, name = DB_NAME, onNewer?: () => void): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(name, DB_VERSION)
    req.onupgradeneeded = (e) => {
      const db = req.result
      if (e.oldVersion < 1) {
        db.createObjectStore('device', { keyPath: 'id' })
        db.createObjectStore('certs', { keyPath: 'chain' })
        const trees = db.createObjectStore('trees', { keyPath: 'id' })
        trees.createIndex('place', ['chain', 'safeLower'])
        db.createObjectStore('uses', { keyPath: ['chain', 'safe', 'root', 'keyIndex'] })
        db.createObjectStore('stateless', { keyPath: 'id', autoIncrement: true })
        db.createObjectStore('safes', { keyPath: ['chain', 'safeLower'] })
        db.createObjectStore('settings', { keyPath: 'key' })
        db.createObjectStore('checked', { keyPath: 'txHash' })
        db.createObjectStore('held', { keyPath: 'safeTxHash' })
      }
      if (e.oldVersion < 2) db.createObjectStore('dapp', { keyPath: 'safeTxHash' })
    }
    req.onsuccess = () => {
      const db = req.result
      // a newer version in another tab waits for this connection: let it go
      db.onversionchange = () => {
        db.close()
        onNewer?.()
      }
      resolve(db)
    }
    req.onerror = () => reject(req.error)
    req.onblocked = () => reject(new Error('the app is open in an older version in another tab: close that tab, then reload this page'))
  })
}

function done(t: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    t.oncomplete = () => resolve()
    t.onerror = () => reject(t.error)
    t.onabort = () => reject(t.error ?? new Error('transaction aborted'))
  })
}

function result<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result)
    r.onerror = () => reject(r.error)
  })
}

/** Writes records in one strict-durability transaction and resolves once it has completed. `add`
 * refuses an existing key, which is how a one-time key's use stays unique. */
export async function writeStrict(db: IDBDatabase, store: string, records: unknown[], mode: 'put' | 'add' = 'put'): Promise<void> {
  const t = db.transaction(store, 'readwrite', STRICT)
  const s = t.objectStore(store)
  const fin = done(t)
  for (const r of records) {
    const req = mode === 'add' ? s.add(r) : s.put(r)
    // an error aborts the transaction; the abort is what rejects
    req.onerror = (e) => e.preventDefault()
  }
  await fin
}

export async function get<T>(db: IDBDatabase, store: string, key: IDBValidKey): Promise<T | undefined> {
  const t = db.transaction(store, 'readonly')
  return (await result(t.objectStore(store).get(key))) as T | undefined
}

export async function all<T>(db: IDBDatabase, store: string, query?: IDBKeyRange | IDBValidKey): Promise<T[]> {
  const t = db.transaction(store, 'readonly')
  return (await result(t.objectStore(store).getAll(query))) as T[]
}

export async function remove(db: IDBDatabase, store: string, key: IDBValidKey): Promise<void> {
  const t = db.transaction(store, 'readwrite', STRICT)
  const fin = done(t)
  t.objectStore(store).delete(key)
  await fin
}

// --- typed helpers ---

export const getDevice = (db: IDBDatabase) => get<DeviceRecord>(db, 'device', 'this')

export const certs = (db: IDBDatabase) => all<CertRecord>(db, 'certs')

export async function treesFor(db: IDBDatabase, chain: number, safe: string): Promise<TreeRecord[]> {
  const t = db.transaction('trees', 'readonly')
  const rows = (await result(t.objectStore('trees').index('place').getAll([chain, safe.toLowerCase()]))) as TreeRecord[]
  return rows.sort((a, b) => a.generation - b.generation || a.start - b.start)
}

export function putTree(db: IDBDatabase, tree: TreeRecord): Promise<void> {
  return writeStrict(db, 'trees', [{ ...tree, safeLower: tree.safe.toLowerCase() }])
}

/** The key log's uses of one tree. */
export function usesOf(db: IDBDatabase, chain: number, safe: string, root: string): Promise<UseRecord[]> {
  const s = safe.toLowerCase()
  const r = root.toLowerCase()
  return all<UseRecord>(db, 'uses', IDBKeyRange.bound([chain, s, r, 0], [chain, s, r, Number.MAX_SAFE_INTEGER]))
}

export const safes = (db: IDBDatabase) => all<SafeRecord>(db, 'safes')

export function putSafe(db: IDBDatabase, rec: SafeRecord): Promise<void> {
  return writeStrict(db, 'safes', [{ ...rec, safeLower: rec.safe.toLowerCase() }])
}

export async function setting<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return (await get<{ key: string; value: T }>(db, 'settings', key))?.value
}

export function putSetting(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return writeStrict(db, 'settings', [{ key, value }])
}

/** Everything this device holds, for "forget this device". */
export async function wipe(db: IDBDatabase): Promise<void> {
  const names = Array.from(db.objectStoreNames)
  const t = db.transaction(names, 'readwrite', STRICT)
  const fin = done(t)
  for (const n of names) t.objectStore(n).clear()
  await fin
}
