// Safe's Transaction Service (service.py): the queue, proposals and confirmations. The app reads
// and writes straight from the browser, without an API key: on 2026-11-07 the Sepolia service
// allowed any origin and answered reads and writes without one, within a rate limit of 5,000
// requests per window for callers without a key. Writes go through a ServiceWriter, so another way
// to post (a proxy holding a key, or links between members) can replace it without touching the
// flows.
//
// The service holds public data only. The app decodes and checks everything it gets from it.

import type { Address } from 'viem'
import type { Hex } from './db'
import { type SafeTx, toService } from './safe'

export class ServiceError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message)
  }
}

export interface ServiceTx {
  safe: Address
  to: Address
  value: string
  data: Hex | null
  operation: number
  safeTxGas: string | number
  baseGas: string | number
  gasPrice: string
  gasToken: Address
  refundReceiver: Address
  nonce: string | number
  safeTxHash: Hex
  proposer?: Address
  isExecuted: boolean
  isSuccessful?: boolean | null
  transactionHash?: Hex | null
  confirmationsRequired?: number
  confirmations?: { owner: Address; signature: Hex | null; signatureType?: string; submissionDate?: string }[]
  submissionDate?: string
  executionDate?: string | null
}

export interface ServiceWriter {
  propose(safe: Address, tx: SafeTx, safeTxHash: Hex, sender: Address, signature: Hex): Promise<void>
  confirm(safeTxHash: Hex, signature: Hex): Promise<void>
}

async function request(base: string, method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
  let res: Response
  try {
    res = await fetch(base + path, {
      method,
      headers: body ? { 'Content-Type': 'application/json', Accept: 'application/json' } : { Accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch (e) {
    throw new ServiceError(`Safe's Transaction Service didn't answer (${(e as Error).message})`)
  }
  const text = await res.text()
  let json: any = text
  try {
    json = text ? JSON.parse(text) : null
  } catch {
    /* keep the text */
  }
  return { status: res.status, json }
}

function detail(json: any): string {
  const s = typeof json === 'string' ? json : JSON.stringify(json)
  return s.slice(0, 400)
}

export class Service {
  constructor(readonly base: string) {}

  private async get(path: string): Promise<any> {
    const { status, json } = await request(this.base, 'GET', path)
    if (status !== 200) throw new ServiceError(`Safe's Transaction Service: HTTP ${status}: ${detail(json)}`, status)
    return json
  }

  /** Whether the service has indexed the Safe (a new Safe takes a little while). */
  async knowsSafe(safe: Address): Promise<boolean> {
    const { status } = await request(this.base, 'GET', `/v1/safes/${safe}/`)
    return status === 200
  }

  async transaction(safeTxHash: Hex): Promise<ServiceTx> {
    return this.get(`/v2/multisig-transactions/${safeTxHash}/`)
  }

  /** Pending transactions from `fromNonce` on, in nonce order. */
  async pending(safe: Address, fromNonce: number): Promise<ServiceTx[]> {
    const r = await this.get(`/v2/safes/${safe}/multisig-transactions/?executed=false&nonce__gte=${fromNonce}&limit=100&ordering=nonce`)
    return (r.results as ServiceTx[]).sort((a, b) => Number(a.nonce) - Number(b.nonce) || (a.submissionDate ?? '').localeCompare(b.submissionDate ?? ''))
  }

  /** Every transaction the service holds for the Safe at nonces in [from, to), executed or not. */
  async inRange(safe: Address, from: number, to: number): Promise<ServiceTx[]> {
    const out: ServiceTx[] = []
    let path: string | null = `/v2/safes/${safe}/multisig-transactions/?nonce__gte=${from}&nonce__lt=${to}&limit=100&ordering=nonce`
    for (let page = 0; path && page < 20; page++) {
      const r: any = await this.get(path)
      out.push(...(r.results as ServiceTx[]))
      path = r.next ? new URL(r.next).pathname.replace(/^.*\/api/, '') + new URL(r.next).search : null
    }
    return out
  }

  async atNonce(safe: Address, nonce: number): Promise<ServiceTx[]> {
    const r = await this.get(`/v2/safes/${safe}/multisig-transactions/?nonce=${nonce}`)
    return r.results as ServiceTx[]
  }
}

/** Posts straight to the service, without a key. */
export class DirectWriter implements ServiceWriter {
  constructor(readonly base: string) {}

  async propose(safe: Address, tx: SafeTx, safeTxHash: Hex, sender: Address, signature: Hex) {
    const body = { ...toService(tx), contractTransactionHash: safeTxHash, sender, signature, origin: null }
    const { status, json } = await request(this.base, 'POST', `/v2/safes/${safe}/multisig-transactions/`, body)
    if (status !== 200 && status !== 201) throw new ServiceError(`The service didn't take the proposal: HTTP ${status}: ${detail(json)}`, status)
  }

  async confirm(safeTxHash: Hex, signature: Hex) {
    const { status, json } = await request(this.base, 'POST', `/v1/multisig-transactions/${safeTxHash}/confirmations/`, { signature })
    if (status !== 200 && status !== 201) throw new ServiceError(`The service didn't take the confirmation: HTTP ${status}: ${detail(json)}`, status)
  }
}

/** The writer for a chain. Development only: VITE_SERVICE_PROXY routes writes through the Vite
 * dev server's proxy (vite.config.ts), which adds a key from the environment. */
export function writerFor(base: string): ServiceWriter {
  const proxy = import.meta.env.DEV ? import.meta.env.VITE_SERVICE_PROXY : undefined
  if (proxy) return new DirectWriter(`${proxy}${new URL(base).pathname}`)
  return new DirectWriter(base)
}
