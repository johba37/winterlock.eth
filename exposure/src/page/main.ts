// The lookup page: a form, the hash route (#/eth:0x...) and the report, in plain DOM. All the
// checking is the library's (../lib); this file only asks it and shows the answer. Text goes in
// with textContent, never as markup.

import './styles.css'
import { type Address, createPublicClient, http } from 'viem'
import { CHAINS, type Chain, chainByShortName } from '../lib/chains'
import * as explain from '../lib/explain'
import { parseSafeInput, routeFor } from '../lib/input'
import { nameOf } from '../lib/known'
import { allLimits } from '../lib/model'
import { CheckError, checkSafe } from '../lib/read'
import type { OwnerClass, OwnerReport, SafeReport } from '../lib/types'

type Child = Node | string | null | undefined | false

/** The landing page's contact section: the page is built to sit in the landing site's check/ folder. */
const CONTACT = '../#contact'

function h(tag: string, props: Record<string, string | boolean | undefined> | null, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag)
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v === undefined || v === false) continue
    el.setAttribute(k, v === true ? '' : v)
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) el.append(c)
  return el
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
const form = $<HTMLFormElement>('lookup')
const input = $<HTMLInputElement>('safe')
const select = $<HTMLSelectElement>('chain')
const rpcInput = $<HTMLInputElement>('rpc')
const formError = $<HTMLParagraphElement>('form-error')
const result = $<HTMLElement>('result')
const go = $<HTMLButtonElement>('go')

// --- the RPC endpoint, per network, kept in this browser only ---

const rpcKey = (c: Chain) => `winterlock-exposure.rpc.${c.shortName}`

function rpcFor(c: Chain): string {
  try {
    return localStorage.getItem(rpcKey(c)) || c.rpc
  } catch {
    return c.rpc
  }
}

function storeRpc(c: Chain, url: string) {
  try {
    if (!url || url === c.rpc) localStorage.removeItem(rpcKey(c))
    else localStorage.setItem(rpcKey(c), url)
  } catch {
    /* private window: the endpoint lasts for this page only */
  }
}

/** scheme://host only: an RPC URL may carry an API key in its path. */
function host(url: string): string {
  try {
    const u = new URL(url)
    return `${u.protocol}//${u.host}`
  } catch {
    return 'an invalid URL'
  }
}

function validRpc(url: string): boolean {
  try {
    const u = new URL(url)
    return u.protocol === 'https:' || (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1'))
  } catch {
    return false
  }
}

const chosen = (): Chain => chainByShortName(select.value) ?? CHAINS[0]

function showPeers() {
  const c = chosen()
  $('rpc-chain').textContent = c.name
  rpcInput.value = rpcFor(c)
  const peers = $('peers')
  peers.replaceChildren(
    'The address you check goes to two places only: the RPC endpoint, ',
    h('code', null, host(rpcFor(c))),
    ', and Safe’s Transaction Service, ',
    h('code', null, host(c.service)),
    '. Each of them sees which Safe you looked up. The page sends nothing else and has no analytics.',
  )
}

// --- the report ---

function badge(c: OwnerClass): HTMLElement {
  return h('span', { class: `badge ${c}`, title: explain.classMeaning(c) }, explain.classLabel(c))
}

function addressLink(chain: Chain, a: Address): HTMLElement {
  return h('a', { href: `${chain.explorer}/address/${a}`, rel: 'noopener noreferrer', class: 'mono' }, a)
}

function ownersTable(r: SafeReport, chain: Chain): HTMLElement {
  return h(
    'table',
    { class: 'owners' },
    h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Owner'), h('th', { scope: 'col' }, 'Kind'), h('th', { scope: 'col' }, 'Class'), h('th', { scope: 'col' }, 'Evidence'))),
    h('tbody', null, ...r.owners.map((o) => ownerRow(o, r, chain))),
  )
}

function ownerRow(o: OwnerReport, r: SafeReport, chain: Chain): HTMLElement {
  const evidence = h('td', { class: 'evidence' }, explain.ownerEvidence(o.facts, r.chainId))
  if (o.facts.kind === 'safe') {
    const inner = o.facts.report
    evidence.append(
      h(
        'details',
        { class: 'nested' },
        h('summary', null, `Its owners, and its verdict: ${explain.verdictTitle(inner.verdict.kind)}`),
        ...explain.verdictText(inner).map((t) => h('p', null, t)),
        ownersTable(inner, chain),
      ),
    )
  }
  return h('tr', null, h('td', { class: 'addr' }, addressLink(chain, o.address)), h('td', null, explain.ownerKind(o.facts)), h('td', null, badge(o.class)), evidence)
}

function named(a: Address): string {
  const n = nameOf(a)
  return n ? `${a} (${n})` : a
}

function report(r: SafeReport, chain: Chain): Node[] {
  const v = r.verdict
  const out: Node[] = []
  const safeLine = h('p', { class: 'safe-line' }, addressLink(chain, r.address), ` on ${chain.name}`, r.version ? `, Safe ${r.version}${r.l2 ? ' (L2)' : ''}` : '', `, read at block ${r.block}`)
  out.push(h('div', { class: `verdict ${v.kind}` }, h('p', { class: 'kicker' }, 'Verdict'), h('h2', { id: 'verdict' }, explain.verdictTitle(v.kind)), safeLine, ...explain.verdictText(r).map((t) => h('p', null, t))))

  const facts = h('dl', { class: 'facts' }, h('div', null, h('dt', null, 'Threshold'), h('dd', null, `${r.threshold} of ${r.owners.length}`)))
  if (r.nonce !== null) facts.append(h('div', null, h('dt', null, 'Transactions executed'), h('dd', null, r.nonce.toString())))
  if (r.balances) {
    facts.append(h('div', null, h('dt', null, chain.native), h('dd', null, explain.amount(r.balances.native, 18))))
    for (const t of r.balances.tokens) facts.append(h('div', null, h('dt', null, t.token.symbol), h('dd', null, t.balance === null ? 'not read' : explain.amount(t.balance, t.token.decimals))))
  }
  out.push(facts)

  out.push(h('h3', null, 'Owners'), ownersTable(r, chain))

  if (r.changes.length) {
    out.push(h('h3', null, 'What would change the verdict'), h('ul', { class: 'plain' }, ...r.changes.map((c) => h('li', null, explain.changeText(c, v)))))
    if (r.changes.some((c) => c.type === 'replace-owners' || c.type === 'raise-threshold')) {
      out.push(h('p', { class: 'hint' }, 'Hash-based owners for Safe are at the research stage: Winterlock’s run on Sepolia only, and its contracts are not audited.'))
    }
  }

  out.push(h('p', { class: 'talk' }, 'Want to talk this result through, or plan ahead for your Safe? ', h('a', { href: CONTACT }, 'Get in contact'), '.'))

  const extras = h('ul', { class: 'plain' })
  extras.append(h('li', null, r.modules.length ? `Modules: ${r.modules.map(named).join(', ')}${r.modulesComplete ? '' : ', and more'}.` : 'No module is enabled.'))
  extras.append(h('li', null, r.guard ? `Guard: ${named(r.guard)}. A guard can refuse transactions; the check doesn’t read what it allows.` : 'No guard is set.'))
  if (r.moduleGuard) extras.append(h('li', null, `Module guard: ${named(r.moduleGuard)}.`))
  extras.append(h('li', null, r.fallbackHandler ? `Fallback handler: ${named(r.fallbackHandler)}.` : 'No fallback handler is set.'))
  out.push(h('h3', null, 'Modules, guard and fallback handler'), extras)

  const limits = h('ul', { class: 'plain' })
  for (const l of allLimits(r)) limits.append(h('li', null, explain.limitText(l)))
  limits.append(
    h(
      'li',
      null,
      r.service
        ? `Safe’s Transaction Service: read ${r.service.transactions.read} of ${r.service.transactions.total} transactions and ${r.service.messages.read} of ${r.service.messages.total} messages for this Safe, in ${r.service.requests} requests.`
        : r.limits.some((l) => l.type === 'service-unavailable')
          ? 'Safe’s Transaction Service couldn’t be used for this Safe.'
          : 'Safe’s Transaction Service wasn’t needed for this Safe: every owner was settled by the chain.',
    ),
  )
  for (const s of explain.scopeNotes(r.chainId)) limits.append(h('li', null, s))
  out.push(h('h3', null, 'What the check couldn’t see'), limits)
  return out
}

function failure(e: unknown, chain: Chain, address: Address): Node {
  const lines: string[] = []
  if (e instanceof CheckError) {
    if (e.code === 'no-contract') lines.push(`There is no contract at ${address} on ${chain.name}.`, 'Is the Safe on another network?')
    else if (e.code === 'not-a-safe') lines.push(`${address} on ${chain.name} doesn’t answer as a Safe.`, 'This check reads Safes only.')
    else if (e.code === 'wrong-chain') lines.push(`${e.message}.`, 'Check the RPC endpoint for this network.')
    else lines.push(`${e.message}.`, 'Try again, or set another RPC endpoint for this network.')
  } else {
    lines.push(`The check stopped: ${(e as Error)?.message ?? String(e)}`)
  }
  return h('div', { class: 'error', role: 'alert' }, ...lines.map((l) => h('p', null, l)))
}

// --- running a check ---

let current = 0

async function run(chain: Chain, address: Address) {
  const id = ++current
  const status = h('p', { class: 'status', role: 'status' }, 'Starting')
  result.replaceChildren(status)
  result.setAttribute('aria-busy', 'true')
  go.disabled = true
  try {
    const client = createPublicClient({ transport: http(rpcFor(chain), { batch: { batchSize: 40 }, retryCount: 1, timeout: 20_000 }) })
    const r = await checkSafe(address, {
      client,
      chainId: chain.id,
      service: { url: chain.service },
      tokens: chain.tokens,
      onProgress: (s) => {
        if (id === current) status.textContent = s
      },
    })
    if (id !== current) return
    result.replaceChildren(...report(r, chain))
  } catch (e) {
    if (id !== current) return
    result.replaceChildren(failure(e, chain, address))
  } finally {
    if (id === current) {
      result.setAttribute('aria-busy', 'false')
      go.disabled = false
    }
  }
}

function fromHash() {
  const route = decodeURIComponent(location.hash)
  if (!/^#\/?[a-z0-9-]+:/i.test(route)) return
  const p = parseSafeInput(route)
  if (!p.ok) {
    formError.textContent = p.error
    formError.hidden = false
    return
  }
  formError.hidden = true
  input.value = `${p.chain.shortName}:${p.address}`
  select.value = p.chain.shortName
  showPeers()
  void run(p.chain, p.address)
}

// --- the page ---

$('background').textContent = explain.BACKGROUND
$('classes').replaceChildren(
  ...(['exposed', 'not-known', 'hash-based', 'unknown'] as OwnerClass[]).map((c) => h('div', null, h('dt', null, explain.classLabel(c)), h('dd', null, explain.classMeaning(c)))),
)
$('scope').replaceChildren(...explain.scopeNotes().map((s) => h('li', null, s)))
for (const c of CHAINS) select.append(h('option', { value: c.shortName }, c.testnet ? `${c.name} (testnet)` : c.name))
select.value = CHAINS[0].shortName
showPeers()

select.addEventListener('change', showPeers)
rpcInput.addEventListener('change', () => {
  const url = rpcInput.value.trim()
  if (url && !validRpc(url)) {
    formError.textContent = 'The RPC endpoint must start with https:// (or http://localhost for a local node).'
    formError.hidden = false
    return
  }
  formError.hidden = true
  storeRpc(chosen(), url)
  showPeers()
})
$('rpc-reset').addEventListener('click', () => {
  storeRpc(chosen(), '')
  showPeers()
})

form.addEventListener('submit', (e) => {
  e.preventDefault()
  const p = parseSafeInput(input.value, chosen())
  if (!p.ok) {
    formError.textContent = p.error
    formError.hidden = false
    return
  }
  formError.hidden = true
  const route = routeFor(p.chain, p.address)
  if (location.hash === route) fromHash()
  else location.hash = route
})
window.addEventListener('hashchange', fromHash)
fromHash()
