// A stand-in for Safe's Transaction Service on a local chain, answering the browser's requests to
// api.safe.global through Playwright's routing: proposals, confirmations, a Safe's transactions
// and one by its hash, with the Safe's nonce read from the chain. Only what the app uses.
// It keeps an owner's first confirmation, as the real service does.

import type { Page, Route } from '@playwright/test'
import { type Address, type Hex, type PublicClient, getAddress, hexToBytes, parseAbi, toHex } from 'viem'

const SAFE = parseAbi(['function nonce() view returns (uint256)', 'function getThreshold() view returns (uint256)', 'function getOwners() view returns (address[])'])

export interface Tx {
  safe: Address
  to: Address
  value: string
  data: Hex | null
  operation: number
  safeTxGas: string
  baseGas: string
  gasPrice: string
  gasToken: Address
  refundReceiver: Address
  nonce: number
  safeTxHash: Hex
  proposer: Address | null
  confirmations: { owner: Address; signature: Hex; signatureType: string; submissionDate: string }[]
  submissionDate: string
  isExecuted: boolean
  transactionHash: Hex | null
}

const BASE = 'https://api.safe.global/tx-service/sep/api'
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'content-type, accept' }

export class FakeService {
  txs = new Map<string, Tx>()
  posts: { path: string; body: any }[] = []

  constructor(private chain: PublicClient) {}

  async install(page: Page) {
    await page.route(`${BASE}/**`, (r) => this.handle(r))
  }

  /** A transaction as a proposal without signatures (another owner's, say, made in Safe's app). */
  add(safe: Address, fields: Omit<Tx, 'safe' | 'safeTxHash' | 'proposer' | 'confirmations' | 'submissionDate' | 'isExecuted' | 'transactionHash'>, hash: Hex) {
    const t: Tx = { safe: getAddress(safe), ...fields, safeTxHash: hash, proposer: null, confirmations: [], submissionDate: new Date().toISOString(), isExecuted: false, transactionHash: null }
    this.txs.set(hash.toLowerCase(), t)
    return t
  }

  private async nonceOf(safe: Address): Promise<number> {
    return Number(await this.chain.readContract({ address: safe, abi: SAFE, functionName: 'nonce' }))
  }

  private async view(t: Tx): Promise<Tx> {
    return { ...t, isExecuted: (await this.nonceOf(t.safe)) > t.nonce }
  }

  private json(r: Route, status: number, body: unknown) {
    return r.fulfill({ status, headers: { ...CORS, 'content-type': 'application/json' }, body: JSON.stringify(body) })
  }

  private async handle(r: Route) {
    const req = r.request()
    if (req.method() === 'OPTIONS') return r.fulfill({ status: 204, headers: CORS })
    const url = new URL(req.url())
    const path = url.pathname.replace(/^\/tx-service\/sep\/api/, '')
    let m: RegExpMatchArray | null
    try {
      if (req.method() === 'GET' && (m = path.match(/^\/v1\/safes\/(0x[0-9a-fA-F]{40})\/$/))) {
        const safe = getAddress(m[1])
        const [nonce, threshold, owners] = await Promise.all([
          this.nonceOf(safe),
          this.chain.readContract({ address: safe, abi: SAFE, functionName: 'getThreshold' }),
          this.chain.readContract({ address: safe, abi: SAFE, functionName: 'getOwners' }),
        ])
        return this.json(r, 200, { address: safe, nonce, threshold: Number(threshold), owners })
      }
      if (req.method() === 'GET' && (m = path.match(/^\/v2\/safes\/(0x[0-9a-fA-F]{40})\/multisig-transactions\/$/))) {
        const safe = getAddress(m[1])
        const q = url.searchParams
        let list = await Promise.all([...this.txs.values()].filter((t) => t.safe === safe).map((t) => this.view(t)))
        if (q.get('executed') === 'false') list = list.filter((t) => !t.isExecuted)
        if (q.has('nonce__gte')) list = list.filter((t) => t.nonce >= Number(q.get('nonce__gte')))
        if (q.has('nonce__lt')) list = list.filter((t) => t.nonce < Number(q.get('nonce__lt')))
        if (q.has('nonce')) list = list.filter((t) => t.nonce === Number(q.get('nonce')))
        list.sort((a, b) => a.nonce - b.nonce)
        return this.json(r, 200, { count: list.length, next: null, previous: null, results: list })
      }
      if (req.method() === 'GET' && (m = path.match(/^\/v2\/multisig-transactions\/(0x[0-9a-fA-F]{64})\/$/))) {
        const t = this.txs.get(m[1].toLowerCase())
        return t ? this.json(r, 200, await this.view(t)) : this.json(r, 404, { detail: 'Not found.' })
      }
      if (req.method() === 'POST' && (m = path.match(/^\/v2\/safes\/(0x[0-9a-fA-F]{40})\/multisig-transactions\/$/))) {
        const b = JSON.parse(req.postData() ?? '{}')
        this.posts.push({ path, body: b })
        const hash = (b.contractTransactionHash as Hex).toLowerCase()
        if (!this.txs.has(hash)) {
          this.add(m[1] as Address, { to: getAddress(b.to), value: String(b.value), data: b.data ?? null, operation: b.operation, safeTxGas: String(b.safeTxGas), baseGas: String(b.baseGas), gasPrice: String(b.gasPrice), gasToken: b.gasToken, refundReceiver: b.refundReceiver, nonce: Number(b.nonce) }, hash as Hex)
        }
        const t = this.txs.get(hash)!
        t.proposer = getAddress(b.sender)
        this.confirm(t, b.signature)
        return this.json(r, 201, {})
      }
      if (req.method() === 'POST' && (m = path.match(/^\/v1\/multisig-transactions\/(0x[0-9a-fA-F]{64})\/confirmations\/$/))) {
        const b = JSON.parse(req.postData() ?? '{}')
        this.posts.push({ path, body: b })
        const t = this.txs.get(m[1].toLowerCase())
        if (!t) return this.json(r, 404, { detail: 'Not found.' })
        this.confirm(t, b.signature)
        return this.json(r, 201, {})
      }
      return this.json(r, 404, { detail: `the fake service has no ${req.method()} ${path}` })
    } catch (e) {
      return this.json(r, 500, { detail: String(e) })
    }
  }

  private confirm(t: Tx, signature: Hex) {
    // a contract signature: r = the owner
    const owner = getAddress(toHex(hexToBytes(signature).slice(12, 32)))
    if (t.confirmations.some((c) => c.owner === owner)) return
    t.confirmations.push({ owner, signature, signatureType: 'CONTRACT_SIGNATURE', submissionDate: new Date().toISOString() })
  }
}
