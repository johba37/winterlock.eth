// What a reader types: a bare address with a chosen network, an EIP-3770 address such as
// eth:0x..., a link from Safe's app (?safe=eth:0x... or the older /eth:0x.../ path), or this
// page's own route #/eth:0x....

import { type Address, getAddress, isAddress } from 'viem'
import { CHAINS, type Chain, chainById, chainByShortName } from './chains'

export type Parsed = { ok: true; chain: Chain; address: Address } | { ok: false; error: string }

const KNOWN = CHAINS.map((c) => c.shortName).join(', ')

function fail(error: string): Parsed {
  return { ok: false, error }
}

function address(text: string): { ok: true; address: Address } | { ok: false; error: string } {
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) return { ok: false, error: 'That isn’t an address: an address is 0x followed by 40 hexadecimal digits.' }
  if (!isAddress(text, { strict: true })) return { ok: false, error: 'The address’s capital letters don’t match its checksum. Check it for a typo.' }
  return { ok: true, address: getAddress(text) }
}

function prefixed(text: string): Parsed {
  const m = /^([a-z0-9-]+):(0x[0-9a-fA-F]*)$/i.exec(text)
  if (!m) return fail('That isn’t an address: an address is 0x followed by 40 hexadecimal digits.')
  const chain = chainByShortName(m[1])
  if (!chain) return fail(`“${m[1]}” isn’t a network this check knows. It knows ${KNOWN}.`)
  const a = address(m[2])
  return a.ok ? { ok: true, chain, address: a.address } : a
}

/** The Safe a reader means. `fallback` is the network chosen beside the input, for a bare address. */
export function parseSafeInput(input: string, fallback?: Chain | number): Parsed {
  let text = input.trim()
  if (!text) return fail('Enter a Safe’s address, such as eth:0x…, or a link from Safe’s app.')
  // this page's route, with or without the hash
  text = text.replace(/^#?\/?(?=[a-z0-9-]+:0x)/i, '')
  if (/^(https?:\/\/|app\.safe\.global\/)/i.test(text)) {
    let url: URL
    try {
      url = new URL(/^https?:/i.test(text) ? text : `https://${text}`)
    } catch {
      return fail('That link can’t be read.')
    }
    const param = url.searchParams.get('safe')
    if (param) return prefixed(param.trim())
    const seg = url.pathname.split('/').find((s) => /^[a-z0-9-]+:0x/i.test(decodeURIComponent(s)))
    if (seg) return prefixed(decodeURIComponent(seg))
    const route = /^#\/?([a-z0-9-]+:0x[0-9a-fA-F]*)$/i.exec(url.hash)
    if (route) return prefixed(route[1])
    return fail('That link doesn’t name a Safe. A link from Safe’s app has ?safe=eth:0x… in it.')
  }
  if (text.includes(':')) return prefixed(text)
  const a = address(text)
  if (!a.ok) return a
  const chain = typeof fallback === 'number' ? chainById(fallback) : fallback
  if (!chain) return fail('Choose a network, or write the address with its prefix, such as eth:0x….')
  return { ok: true, chain, address: a.address }
}

/** This page's route for a Safe: #/eth:0x... */
export function routeFor(chain: Chain, address: Address): string {
  return `#/${chain.shortName}:${address}`
}
