// WalletConnect's state as the screens see it, without the SDK: lib/walletconnect.ts (Reown's
// WalletKit, a separate chunk) loads only when a member opens a Safe's dapps or has a session, and
// writes here.

import { useEffect, useState } from 'preact/hooks'
import type { Address } from 'viem'
import type { DappInfo } from './dapp'
import { type DappTxRecord, type Hex, get, putSetting, setting, writeStrict } from './db'
import type { Env } from './flows'
import type { Call } from './safe'

/** The build's WalletConnect project ID (VITE_WALLETCONNECT_PROJECT_ID at build time). A published
 * build contains it, as every dapp's does. */
export const PROJECT_ID: string | undefined = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || undefined

export interface DappSession {
  topic: string
  chain: number
  safe: Address
  dapp: DappInfo
  /** seconds */
  expiry: number
  /** chains the dapp required besides the Safe's, where the app refuses requests */
  others: string[]
}

export interface DappProposal {
  id: number
  pairingTopic: string
  dapp: DappInfo
  /** the Safe whose dapps screen took the link, if this page did */
  target?: { chain: number; safe: Address }
  /** seconds */
  expiry: number
}

export interface DappRequest {
  id: number
  topic: string
  chain: number
  safe: Address
  dapp: DappInfo
  method: 'eth_sendTransaction' | 'wallet_sendCalls'
  calls: Call[]
  /** ms; the dapp stops waiting then */
  expiry?: number
  received: number
  expired: boolean
  busy: boolean
}

/** A request the member confirmed: proposed, and answered if the dapp was still waiting. */
export interface DappDone {
  id: number
  chain: number
  safe: Address
  dapp: DappInfo
  hash: Hex
  nonce: number
  answered: boolean
  note?: string
  /** this member's confirmation meets the threshold and the Safe is at its nonce, not executed yet */
  ready: boolean
  executed?: Hex
  /** executed at once on the confirm (the member's confirmation was enough) */
  atOnce?: boolean
  /** why executing at once failed; the proposal stands */
  executeError?: string
  /** the dapp's answer was the execution's transaction hash, not the SafeTx hash */
  gotTx?: boolean
}

/** Something the app answered by itself that the member should see: a refusal, a disconnection. */
export interface DappEvent {
  at: number
  chain?: number
  safe?: Address
  dapp: string
  text: string
}

export interface WcState {
  status: 'off' | 'starting' | 'on' | 'failed'
  error?: string
  /** a pasted link waiting for the dapp's proposal */
  pairing?: { topic: string; since: number; target: { chain: number; safe: Address } }
  sessions: DappSession[]
  proposals: DappProposal[]
  requests: DappRequest[]
  done: DappDone[]
  log: DappEvent[]
}

let state: WcState = { status: 'off', sessions: [], proposals: [], requests: [], done: [], log: [] }
const subs = new Set<() => void>()

export function wcState(): WcState {
  return state
}

export function setWc(f: (s: WcState) => WcState) {
  state = f(state)
  for (const s of subs) s()
}

export function logWc(e: Omit<DappEvent, 'at'>) {
  setWc((s) => ({ ...s, log: [{ ...e, at: Date.now() }, ...s.log].slice(0, 30) }))
}

export function useWc(): WcState {
  const [, tick] = useState(0)
  useEffect(() => {
    const f = () => tick((x) => x + 1)
    subs.add(f)
    return () => {
      subs.delete(f)
    }
  }, [])
  return state
}

/** After this app executed a Safe transaction (from a dapp's card or the transaction's screen): if a
 * dapp got its SafeTx hash, keep the execution for its receipt and status. */
export async function noteExecution(db: IDBDatabase, hash: Hex, tx: Hex) {
  const rec = await get<DappTxRecord>(db, 'dapp', hash.toLowerCase())
  if (rec) await writeStrict(db, 'dapp', [{ ...rec, execution: { tx, success: true } }])
  setWc((s) => ({ ...s, done: s.done.map((d) => (d.hash === hash.toLowerCase() ? { ...d, ready: false, executed: tx } : d)) }))
}

/** The SDK's module, loaded on first use. */
export const wcModule = () => import('./walletconnect')

/** Starts WalletConnect if this browser had a session before (a setting the module keeps), so a
 * dapp's requests reach the app after a reload. */
export async function resumeWc(env: Env) {
  if (!PROJECT_ID || !(await setting<boolean>(env.db, 'wc:on'))) return
  await (await wcModule()).start(env)
}

/** Before "forget this device": ends every session and drops the SDK's storage. */
export async function forgetWc(env: Env) {
  if (await setting<boolean>(env.db, 'wc:on')) {
    try {
      await (await wcModule()).disconnectAll(env)
    } catch {
      /* the dapps see the session lapse instead */
    }
    await putSetting(env.db, 'wc:on', false)
  }
  // completes once the SDK's connection closes, at the latest when the page does
  indexedDB.deleteDatabase('WALLET_CONNECT_V2_INDEXED_DB')
}
