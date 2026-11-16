// Reading owners' signatures from Safe's Transaction Service (checked against its source and the
// live Sepolia service on 2026-11-16, service 6.14.0):
// - GET /api/v1/safes/{address}/ : 404 for a Safe the service doesn't know (the lists below
//   answer an empty page for one).
// - GET /api/v2/safes/{address}/multisig-transactions/?limit=&offset= : executed and queued
//   transactions, each with confirmations [{owner, signatureType, ...}]; trusted ones only by
//   default, which includes every transaction with at least one owner's signature.
// - GET /api/v1/safes/{address}/messages/?limit=&offset= : off-chain messages, each with
//   confirmations [{owner, signatureType, ...}].
// - Both are limit/offset pages {count, next, results}, at most 200 per page.
// - signatureType is one of CONTRACT_SIGNATURE, APPROVED_HASH, EOA, ETH_SIGN and SECP256R1
//   (safe-eth-py's SafeSignatureType; SECP256R1 is for a Safe version after 1.5.0).
// - Reads work without an API key from any origin (Access-Control-Allow-Origin: *). Without a
//   key the service allows 2 requests per second (Safe's documentation) and 5,000 per window
//   (its X-RateLimit-Limit header); it answers 429 past either. Requests are spaced to stay
//   under 2 per second, and the number of pages read is capped.

import { type Address, type Hex, getAddress } from 'viem'
import type { OwnerSignatures, ServiceSummary, SignatureSeen } from './types'
import { EXPOSING_TYPES } from './model'

export interface ServiceOptions {
  /** The service up to and including /api, e.g. https://api.safe.global/tx-service/sep/api */
  url: string
  /** Injectable for tests; defaults to the global fetch. */
  fetch?: typeof fetch
  /** Pages read per list (transactions, messages). Default 5. */
  maxPages?: number
  /** Results per page, at most 200. Default 200. */
  pageSize?: number
  /** Milliseconds between requests. Default 600 (under 2 per second). */
  interval?: number
}

export interface ServiceRead {
  bySigner: Map<string, OwnerSignatures>
  summary: ServiceSummary
  /** Lists that had more than the cap allowed to read. */
  capped: { list: 'transactions' | 'messages'; read: number; total: number }[]
  error?: { reason: 'not-indexed' | 'rate-limited' | 'failed'; detail: string }
}

class ServiceFailure extends Error {
  constructor(
    readonly reason: 'not-indexed' | 'rate-limited' | 'failed',
    detail: string,
  ) {
    super(detail)
  }
}

interface Confirmation {
  owner?: unknown
  signatureType?: unknown
}

export class SafeService {
  private readonly fetch: typeof fetch
  private readonly maxPages: number
  private readonly pageSize: number
  private readonly interval: number
  private last = 0
  private gate: Promise<void> = Promise.resolve()
  requests = 0

  constructor(readonly options: ServiceOptions) {
    this.fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init))
    this.maxPages = Math.max(1, options.maxPages ?? 5)
    this.pageSize = Math.min(200, Math.max(1, options.pageSize ?? 200))
    this.interval = options.interval ?? 600
  }

  /** Waits for this request's turn: one start per interval, whoever asks. */
  private async turn(): Promise<void> {
    const before = this.gate
    let release = () => {}
    this.gate = new Promise((r) => (release = r))
    await before
    const wait = this.last + this.interval - Date.now()
    if (wait > 0) await new Promise((r) => setTimeout(r, wait))
    this.last = Date.now()
    release()
  }

  private async get(path: string, safeInfo = false): Promise<any> {
    await this.turn()
    this.requests++
    let res: Response
    try {
      res = await this.fetch(this.options.url.replace(/\/+$/, '') + path, { headers: { Accept: 'application/json' } })
    } catch (e) {
      throw new ServiceFailure('failed', `no answer (${(e as Error).message})`)
    }
    if (res.status === 404 && safeInfo) throw new ServiceFailure('not-indexed', 'HTTP 404')
    if (res.status === 429) throw new ServiceFailure('rate-limited', 'HTTP 429')
    if (res.status !== 200) throw new ServiceFailure('failed', `HTTP ${res.status}`)
    let json: any
    try {
      json = await res.json()
    } catch {
      throw new ServiceFailure('failed', 'an answer that isn’t JSON')
    }
    if (!json || typeof json !== 'object') throw new ServiceFailure('failed', 'an empty answer')
    if (!safeInfo && (!Array.isArray(json.results) || typeof json.count !== 'number')) throw new ServiceFailure('failed', 'an answer without results')
    return json
  }

  /** Every owner signature the service holds for `safe`, within the page cap. */
  async signatures(safe: Address): Promise<ServiceRead> {
    const before = this.requests
    const bySigner = new Map<string, OwnerSignatures>()
    const summary: ServiceSummary = {
      transactions: { read: 0, total: 0 },
      messages: { read: 0, total: 0 },
      requests: 0,
      pageSize: this.pageSize,
      maxPages: this.maxPages,
    }
    const capped: ServiceRead['capped'] = []
    const note = (c: Confirmation, seen: Omit<SignatureSeen, 'signatureType'>) => {
      if (typeof c.owner !== 'string' || typeof c.signatureType !== 'string') return
      let owner: string
      try {
        owner = getAddress(c.owner).toLowerCase()
      } catch {
        return
      }
      const s = bySigner.get(owner) ?? { byType: {} }
      s.byType[c.signatureType] = (s.byType[c.signatureType] ?? 0) + 1
      if (!s.example && EXPOSING_TYPES.includes(c.signatureType)) s.example = { ...seen, signatureType: c.signatureType }
      bySigner.set(owner, s)
    }
    const lists = [
      { list: 'transactions' as const, path: `/v2/safes/${safe}/multisig-transactions/` },
      { list: 'messages' as const, path: `/v1/safes/${safe}/messages/` },
    ]
    try {
      // the lists answer an empty page for a Safe the service doesn't know; this answers 404
      await this.get(`/v1/safes/${safe}/`, true)
      for (const { list, path } of lists) {
        let offset = 0
        for (let page = 0; ; page++) {
          if (page === this.maxPages) {
            capped.push({ list, read: summary[list].read, total: summary[list].total })
            break
          }
          const r = await this.get(`${path}?limit=${this.pageSize}&offset=${offset}`)
          summary[list].total = r.count
          for (const item of r.results as any[]) {
            summary[list].read++
            const confirmations: Confirmation[] = Array.isArray(item?.confirmations) ? item.confirmations : []
            const hash = (list === 'transactions' ? item?.safeTxHash : item?.messageHash) as Hex
            const nonce = list === 'transactions' && item?.nonce != null ? Number(item.nonce) : undefined
            const executed = list === 'transactions' ? Boolean(item?.isExecuted) : undefined
            for (const c of confirmations) note(c, { source: list === 'transactions' ? 'transaction' : 'message', hash, nonce, executed })
          }
          offset += r.results.length
          if (!r.next || r.results.length === 0) break
        }
      }
    } catch (e) {
      summary.requests = this.requests - before
      if (e instanceof ServiceFailure) return { bySigner, summary, capped, error: { reason: e.reason, detail: e.message } }
      throw e
    }
    summary.requests = this.requests - before
    return { bySigner, summary, capped }
  }
}
