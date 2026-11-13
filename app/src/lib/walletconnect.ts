// The app as the wallet a dapp connects to (docs/notes/walletconnect.md, "The app"): Reown's
// WalletKit, bundled, with the Safe as the dapp's account. lib/dapp.ts decides what to answer; this
// runs it against the relay, the chain and Safe's service, and the member confirms each transaction
// on the Safe's dapps screen.
//
// Network: the SDK reaches only Reown's relay (wss://relay.walletconnect.org). It would also post
// telemetry, fetch the Verify API's key and attestations, and (WalletKit) load a payments client;
// those are switched off below, the payments package is replaced at build time
// (src/lib/wc-pay-stub.ts), and a guard refuses any fetch to WalletConnect's or Reown's servers.
// Without Verify, a dapp's name and URL are what it claims.
//
// Storage: the SDK keeps its keys, pairings, sessions and pending requests in this origin's
// IndexedDB (WALLET_CONNECT_V2_INDEXED_DB), unencrypted like the app's own. The SafeTx hashes given
// to dapps are in the app's database (store "dapp").

import { type IWalletKit, WalletKit, type WalletKitTypes } from '@reown/walletkit'
import { Core } from '@walletconnect/core'
import type { Address } from 'viem'
import { ctxFor, safeState, short, usableCtx } from './chain'
import { chainById } from './chains'
import {
  CODE,
  type Ctx as PlanCtx,
  type Execution,
  MEMBER_REFUSED,
  type RawReceipt,
  RpcFail,
  answerFor,
  callsStatus,
  dappInfo,
  findExecution,
  pendingTransaction,
  plan,
  sessionNamespaces,
  sessionProperties,
  sessionSafe,
  txFor,
} from './dapp'
import { type DappTxRecord, type Hex, all, get, putSetting, writeStrict } from './db'
import { type Env, type Proposed, type Step, collect, nextNonce, service } from './flows'
import type { SafeTx } from './safe'
import { type DappRequest, type DappSession, PROJECT_ID, logWc, setWc, wcState } from './wc-state'

export const RELAY = 'wss://relay.walletconnect.org'

const USER_REJECTED = { code: 5000, message: 'User rejected.' }
const USER_DISCONNECTED = { code: 6000, message: 'User disconnected.' }

let kit: IWalletKit | undefined
let starting: Promise<IWalletKit> | undefined
let env: Env
/** whether the member's signer takes batches, and why not */
let mode: { batches: boolean; noBatches?: string } = { batches: true }

/** How the member signs and proposes a Safe transaction (flows.proposeTx with this device). */
export type Propose = (chain: number, safe: Address, tx: SafeTx, step: Step) => Promise<Proposed>
/** pasted links: pairing topic → the Safe whose screen took it */
const targets = new Map<string, { chain: number; safe: Address }>()

// --- no third parties ---

const THIRD_PARTY = /(^|\.)(walletconnect\.(org|com)|reown\.com)$/i
/** Hosts the guard refused (also on globalThis.__winterlockRefused, for the tests). */
export const refused: string[] = []
;(globalThis as unknown as { __winterlockRefused: string[] }).__winterlockRefused = refused

/** Refuses fetches to WalletConnect's and Reown's servers. The relay is a WebSocket, not a fetch;
 * the RPC and Safe's service go through unchanged. */
function guardFetch() {
  const g = globalThis as unknown as { __winterlockGuard?: boolean; fetch: typeof fetch }
  if (g.__winterlockGuard) return
  const inner = g.fetch.bind(globalThis)
  g.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    let host = ''
    try {
      host = new URL(input instanceof Request ? input.url : String(input), location.href).hostname
    } catch {
      /* let fetch refuse it */
    }
    if (THIRD_PARTY.test(host)) {
      refused.push(host)
      return Promise.reject(new TypeError(`the app sends nothing to ${host}`))
    }
    return inner(input, init)
  }
  g.__winterlockGuard = true
}

/** The core with telemetry, Verify and push registration switched off. */
function quietCore(projectId: string) {
  const core = new Core({ projectId, relayUrl: RELAY, telemetryEnabled: false })
  const c = core as any
  // WalletKit's init posts an INIT event whatever telemetryEnabled says
  c.eventClient.init = async () => {}
  c.eventClient.sendEvent = async () => new Response(null, { status: 204 })
  // Verify: a key and attestations from verify.walletconnect.org (and, for dapps, an iframe)
  c.verify.resolve = async () => undefined
  c.verify.register = async () => ''
  c.verify.fetchPublicKey = async () => undefined
  c.echoClient.registerDeviceToken = async () => {}
  return core
}

function metadata() {
  return { name: 'Winterlock', description: 'The signer app for members of a Safe with Winterlock owners', url: location.origin, icons: [] as string[] }
}

/** Starts WalletKit once: connects to the relay, restores sessions and pending requests. */
export async function start(e: Env, m?: { batches: boolean; noBatches?: string }): Promise<void> {
  env = e
  if (m) mode = m
  if (kit) return
  if (!PROJECT_ID) {
    setWc((s) => ({ ...s, status: 'failed', error: 'This build has no WalletConnect project ID.' }))
    return
  }
  starting ??= (async () => {
    setWc((s) => ({ ...s, status: 'starting', error: undefined }))
    guardFetch()
    const k = await WalletKit.init({
      core: quietCore(PROJECT_ID),
      metadata: metadata(),
      // every request at once: reads and status polls are answered while a transaction waits
      signConfig: { disableRequestQueue: true },
    })
    // the payments client stays off (wc-pay-stub.ts says it isn't available)
    k.on('session_proposal', (p) => onProposal(p))
    k.on('session_request', (r) => void onRequest(r))
    k.on('session_delete', (d) => onDeleted(d.topic))
    k.on('proposal_expire', ({ id }) => setWc((s) => ({ ...s, proposals: s.proposals.filter((p) => p.id !== id) })))
    k.on('session_request_expire', ({ id }) => setWc((s) => ({ ...s, requests: s.requests.map((r) => (r.id === id ? { ...r, expired: true } : r)) })))
    kit = k
    refreshSessions()
    for (const p of Object.values(k.getPendingSessionProposals())) onProposal({ id: p.id, params: p, verifyContext: undefined as any })
    for (const r of k.getPendingSessionRequests()) await onRequest(r as WalletKitTypes.SessionRequest)
    setWc((s) => ({ ...s, status: 'on' }))
    return k
  })()
  try {
    await starting
  } catch (err) {
    starting = undefined
    setWc((s) => ({ ...s, status: 'failed', error: `Can’t reach WalletConnect’s relay: ${short(err)}` }))
    throw err
  }
}

async function ready(): Promise<IWalletKit> {
  if (!kit) await start(env)
  if (!kit) throw new Error(wcState().error ?? 'WalletConnect isn’t running')
  return kit
}

// --- sessions ---

function refreshSessions() {
  if (!kit) return
  const out: DappSession[] = []
  for (const s of Object.values(kit.getActiveSessions())) {
    const accounts = s.namespaces.eip155?.accounts ?? []
    const at = sessionSafe(accounts, (c) => CHAINS_ON(c))
    if (!at) continue
    out.push({
      topic: s.topic,
      ...at,
      dapp: dappInfo(s.peer.metadata),
      expiry: s.expiry,
      others: (s.namespaces.eip155?.chains ?? []).filter((c) => c !== `eip155:${at.chain}`),
    })
  }
  setWc((st) => ({ ...st, sessions: out }))
  // the next start connects to the relay only while a session lasts
  if (env) putSetting(env.db, 'wc:on', out.length > 0).catch(() => {})
}

const CHAINS_ON = (c: number) => {
  try {
    return chainById(c).enabled
  } catch {
    return false
  }
}

function onDeleted(topic: string) {
  const s = wcState().sessions.find((x) => x.topic === topic)
  setWc((st) => ({ ...st, requests: st.requests.filter((r) => r.topic !== topic) }))
  refreshSessions()
  if (s) logWc({ chain: s.chain, safe: s.safe, dapp: s.dapp.name, text: 'The dapp disconnected.' })
}

/** Pairs with a dapp from its link; its proposal then shows on the Safe's dapps screen. The link
 * holds the pairing's key, so no error repeats it. */
export async function pair(uri: string, target: { chain: number; safe: Address }) {
  const u = uri.trim()
  const m = u.match(/^wc:([0-9a-f]{64})@2\?(.*)$/i)
  if (!m || !/(^|&)symKey=[0-9a-f]{64}(&|$)/i.test(m[2])) throw new Error('That isn’t a WalletConnect link: copy it again from the dapp (it starts with wc: and holds @2).')
  const k = await ready()
  targets.set(m[1].toLowerCase(), target)
  setWc((s) => ({ ...s, pairing: { topic: m[1].toLowerCase(), since: Date.now(), target } }))
  try {
    await k.pair({ uri: u })
  } catch (err) {
    setWc((s) => ({ ...s, pairing: undefined }))
    throw new Error(`The dapp’s link didn’t pair: ${short(err).replace(/[0-9a-f]{64}/gi, '…')}. Copy a fresh link from the dapp.`)
  }
}

function onProposal(p: WalletKitTypes.SessionProposal) {
  const pt = p.params.pairingTopic?.toLowerCase()
  const target = targets.get(pt)
  setWc((s) => ({
    ...s,
    pairing: s.pairing?.topic === pt ? undefined : s.pairing,
    proposals: [...s.proposals.filter((x) => x.id !== p.id), { id: p.id, pairingTopic: pt, dapp: dappInfo(p.params.proposer?.metadata), target, expiry: p.params.expiryTimestamp }],
  }))
}

/** Approves a proposal for this Safe: it must be the member's, on an enabled chain, and the dapp
 * must offer that chain (otherwise the dapp gets 5100 and the member the reason). */
export async function approve(id: number, owner: Hex, target: { chain: number; safe: Address }): Promise<{ notes: string[] }> {
  const k = await ready()
  // a list, whatever its type says
  const p = Object.values(k.getPendingSessionProposals()).find((x) => x.id === id)
  if (!p) throw new Error('That proposal has expired: copy a fresh link from the dapp.')
  if (!chainById(target.chain).enabled) throw new Error(`${chainById(target.chain).name} isn’t enabled in the app.`)
  const st = await safeState(await usableCtx(env.db, env.core, target.chain), target.safe)
  if (!st.owners.some((o) => o.toLowerCase() === owner.toLowerCase())) throw new Error('Your owner isn’t an owner of this Safe: the dapp could see it, but you couldn’t sign for it.')
  let ns
  try {
    ns = sessionNamespaces(p, target.chain, target.safe)
  } catch (err) {
    if (err instanceof RpcFail) {
      await k.rejectSession({ id, reason: { code: err.code, message: err.message } }).catch(() => {})
      setWc((s) => ({ ...s, proposals: s.proposals.filter((x) => x.id !== id) }))
      throw new Error(`Refused: ${err.message}.`)
    }
    throw err
  }
  await k.approveSession({ id, namespaces: ns.namespaces, sessionProperties: sessionProperties(target.chain, target.safe, mode.batches) })
  await putSetting(env.db, 'wc:on', true)
  setWc((s) => ({ ...s, proposals: s.proposals.filter((x) => x.id !== id) }))
  refreshSessions()
  return { notes: ns.notes }
}

export async function reject(id: number) {
  const k = await ready()
  await k.rejectSession({ id, reason: USER_REJECTED }).catch(() => {})
  setWc((s) => ({ ...s, proposals: s.proposals.filter((x) => x.id !== id) }))
}

export async function disconnect(topic: string) {
  const k = await ready()
  const s = wcState().sessions.find((x) => x.topic === topic)
  try {
    await k.disconnectSession({ topic, reason: USER_DISCONNECTED })
  } finally {
    setWc((st) => ({ ...st, requests: st.requests.filter((r) => r.topic !== topic) }))
    refreshSessions()
    if (s) logWc({ chain: s.chain, safe: s.safe, dapp: s.dapp.name, text: 'Disconnected.' })
  }
}

/** Ends every session (before "forget this device"). */
export async function disconnectAll(e: Env) {
  await start(e)
  for (const s of Object.values(kit?.getActiveSessions() ?? {})) await kit!.disconnectSession({ topic: s.topic, reason: USER_DISCONNECTED }).catch(() => {})
  refreshSessions()
}

// --- requests ---

async function respond(topic: string, id: number, out: { result: unknown } | { error: { code: number; message: string } }) {
  const k = await ready()
  await k.respondSessionRequest({ topic, response: { id, jsonrpc: '2.0', ...out } as any })
}

function sessionOf(topic: string) {
  return wcState().sessions.find((s) => s.topic === topic)
}

function planCtx(chain: number, safe: Address): PlanCtx {
  return { chain, safe, ...mode }
}

/** Requests this page has taken: the SDK may hand one over twice (seen after a reload, for a read
 * the relay delivered again), and a dapp must get one answer. */
const taken = new Set<number>()

async function onRequest(r: WalletKitTypes.SessionRequest) {
  const { id, topic } = r
  const { request, chainId } = r.params
  if (taken.has(id) || wcState().requests.some((x) => x.id === id)) return
  taken.add(id)
  let s = sessionOf(topic)
  if (!s) {
    refreshSessions()
    s = sessionOf(topic)
  }
  if (!s) return respond(topic, id, { error: { code: CODE.chains, message: 'this session serves no Safe on an enabled chain' } }).catch(() => {})
  const where = { chain: s.chain, safe: s.safe, dapp: s.dapp.name }
  try {
    const p = plan(request.method, request.params, chainId, planCtx(s.chain, s.safe))
    if (p.kind === 'tx') {
      // proposed before a reload, but not answered: answer now
      const before = (await all<DappTxRecord>(env.db, 'dapp')).find((x) => x.requestId === id && x.topic === topic)
      if (before) {
        await respond(topic, id, { result: answerFor(request.method, before.safeTxHash) })
        await writeStrict(env.db, 'dapp', [{ ...before, answered: true }])
        return
      }
      const expiry = request.expiryTimestamp ? request.expiryTimestamp * 1000 : undefined
      const item: DappRequest = { id, topic, ...where, dapp: s.dapp, method: p.method, calls: p.calls, expiry, received: Date.now(), expired: !!expiry && expiry < Date.now(), busy: false }
      setWc((st) => ({ ...st, requests: [...st.requests, item] }))
      return
    }
    await respond(topic, id, { result: await run(p, s.chain, s.safe) })
  } catch (err) {
    const code = err instanceof RpcFail ? err.code : CODE.internal
    const message = err instanceof RpcFail ? err.message : `the app failed: ${short(err)}`
    await respond(topic, id, { error: { code, message } }).catch(() => {})
    if (err instanceof RpcFail && code !== CODE.unknownBundle) logWc({ ...where, text: `Refused ${request.method} (${code}): ${message}.` })
  }
}

/** Runs a plan that needs no member. */
async function run(p: Exclude<ReturnType<typeof plan>, { kind: 'tx' }>, chain: number, safe: Address): Promise<unknown> {
  if (p.kind === 'answer') return p.result
  const ctx = await ctxFor(env.db, chain)
  if (p.kind === 'rpc') return ctx.client.request({ method: p.method as any, params: p.params as any })
  const rec = await get<DappTxRecord>(env.db, 'dapp', p.kind === 'status' ? p.id : p.hash)
  const ours = rec && rec.chain === chain && rec.safe.toLowerCase() === safe.toLowerCase()
  if (p.kind === 'lookup') {
    if (!ours) return ctx.client.request({ method: p.method, params: p.params as any })
    const ex = await execution(rec)
    if (ex.state === 'executed') return ctx.client.request({ method: p.method, params: [ex.tx] })
    return p.method === 'eth_getTransactionReceipt' ? null : pendingTransaction(rec.safeTxHash, safe)
  }
  if (!ours) throw new RpcFail(CODE.unknownBundle, 'unknown bundle id (the app knows only the calls it proposed for a dapp)')
  const ex = await execution(rec)
  const receipt = ex.state === 'executed' ? ((await ctx.client.request({ method: 'eth_getTransactionReceipt', params: [ex.tx] })) as unknown as RawReceipt | null) : null
  return callsStatus(rec, ex, receipt)
}

/** findExecution from the chain and Safe's service; an execution found is kept in the record. */
async function execution(rec: DappTxRecord): Promise<Execution> {
  const ctx = await ctxFor(env.db, rec.chain)
  const svc = service(rec.chain)
  const ex = await findExecution(rec, {
    safeNonce: async () => (await safeState(ctx, rec.safe)).nonce,
    serviceTx: (h) => svc.transaction(h).catch(() => null),
    executedAt: async (n) => (await svc.atNonce(rec.safe, n).catch(() => [])).filter((t) => t.isExecuted).map((t) => t.safeTxHash),
  })
  if (ex.state === 'executed' && !rec.execution) {
    const r = await ctx.client.getTransactionReceipt({ hash: ex.tx }).catch(() => null)
    if (r) await writeStrict(env.db, 'dapp', [{ ...rec, execution: { tx: ex.tx, success: r.status === 'success' } }])
  }
  return ex
}

function update(id: number, f: (r: DappRequest) => DappRequest) {
  setWc((s) => ({ ...s, requests: s.requests.map((r) => (r.id === id ? f(r) : r)) }))
}

/**
 * The member confirms a transaction request: propose it with this device's confirmation (the same
 * checks and key log as any proposal), keep its SafeTx hash, and answer the dapp if it is still
 * waiting. A refusal by the app (the stale-log check, no key tree, ...) or a failure leaves the
 * request waiting, so the member can fix it and try again, or refuse it.
 */
export async function confirmRequest(id: number, propose: Propose, step: Step) {
  const r = wcState().requests.find((x) => x.id === id)
  if (!r) throw new Error('That request is gone.')
  if (r.busy) throw new Error('That request is being signed already.')
  update(id, (x) => ({ ...x, busy: true }))
  try {
    const ctx = await usableCtx(env.db, env.core, r.chain)
    step('Picking the nonce')
    const st = await safeState(ctx, r.safe)
    const mine = (await all<DappTxRecord>(env.db, 'dapp')).filter((x) => x.chain === r.chain && x.safe.toLowerCase() === r.safe.toLowerCase())
    const nonce = await nextNonce(r.chain, r.safe, st.nonce, mine.map((x) => x.nonce))
    // a batch's MultiSendCallOnly code is checked with the rest, before signing (flows.ts, prepare)
    const tx = txFor(r.calls, BigInt(nonce))
    const p = await propose(r.chain, r.safe, tx, step)
    const rec: DappTxRecord = {
      safeTxHash: p.hash.toLowerCase() as Hex,
      chain: r.chain,
      safe: r.safe,
      nonce,
      calls: r.calls.length,
      method: r.method,
      requestId: id,
      topic: r.topic,
      dapp: { name: r.dapp.name, url: r.dapp.url },
      at: Date.now(),
      answered: false,
    }
    await writeStrict(env.db, 'dapp', [rec])
    let answered = false
    if (!r.expiry || Date.now() < r.expiry) {
      step('Answering the dapp')
      try {
        await respond(r.topic, id, { result: answerFor(r.method, rec.safeTxHash) })
        answered = !r.expiry || Date.now() < r.expiry
      } catch {
        /* the session ended meanwhile */
      }
      if (answered) await writeStrict(env.db, 'dapp', [{ ...rec, answered }])
    }
    step('Counting the confirmations')
    const col = await collect(env, r.chain, r.safe, p.hash).catch(() => null)
    const isReady = !!col && col.sigs.length >= col.threshold && col.nonce === nonce
    setWc((s) => ({
      ...s,
      requests: s.requests.filter((x) => x.id !== id),
      done: [{ id, chain: r.chain, safe: r.safe, dapp: r.dapp, hash: rec.safeTxHash, nonce, answered, note: p.note, ready: isReady }, ...s.done].slice(0, 20),
    }))
    return { hash: rec.safeTxHash, nonce, answered, ready: isReady }
  } catch (err) {
    update(id, (x) => ({ ...x, busy: false }))
    throw err
  }
}

/** The member refuses a request: the dapp gets 4001. */
export async function refuseRequest(id: number) {
  const r = wcState().requests.find((x) => x.id === id)
  if (!r) return
  setWc((s) => ({ ...s, requests: s.requests.filter((x) => x.id !== id) }))
  if (!r.expired) await respond(r.topic, id, { error: { code: CODE.rejected, message: MEMBER_REFUSED } }).catch(() => {})
  logWc({ chain: r.chain, safe: r.safe, dapp: r.dapp.name, text: r.expired ? 'Dismissed an expired request.' : `Refused ${r.method}: you rejected it.` })
}
