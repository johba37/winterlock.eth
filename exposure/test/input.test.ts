import { describe, expect, it } from 'vitest'
import { chainByShortName } from '../src/lib/chains'
import { parseSafeInput, routeFor } from '../src/lib/input'

const A = '0xA5dA2Ab05Cb7EE8D3FBbB486Dee542dcCb5197E6'
const sep = chainByShortName('sep')!
const eth = chainByShortName('eth')!

const ok = (text: string, fallback?: number) => {
  const r = parseSafeInput(text, fallback)
  if (!r.ok) throw new Error(r.error)
  return `${r.chain.shortName}:${r.address}`
}
const err = (text: string, fallback?: number) => {
  const r = parseSafeInput(text, fallback)
  if (r.ok) throw new Error(`parsed ${text}`)
  return r.error
}

describe('reading what the reader typed', () => {
  it('a prefixed address', () => {
    expect(ok(`sep:${A}`)).toBe(`sep:${A}`)
    expect(ok(`  eth:${A.toLowerCase()} `)).toBe(`eth:${A}`)
    expect(ok(`SEP:${A}`)).toBe(`sep:${A}`)
    for (const s of ['eth', 'sep', 'base', 'arb1', 'oeth', 'gno']) expect(ok(`${s}:${A}`)).toBe(`${s}:${A}`)
  })
  it('a bare address with the chosen network', () => {
    expect(ok(A, 1)).toBe(`eth:${A}`)
    expect(ok(A.toLowerCase(), 11155111)).toBe(`sep:${A}`)
    expect(err(A)).toMatch(/Choose a network/)
  })
  it("links from Safe's app", () => {
    expect(ok(`https://app.safe.global/home?safe=sep:${A}`)).toBe(`sep:${A}`)
    expect(ok(`https://app.safe.global/transactions/history?safe=eth%3A${A}`)).toBe(`eth:${A}`)
    expect(ok(`app.safe.global/balances?safe=base:${A}&foo=1`)).toBe(`base:${A}`)
    expect(ok(`https://app.safe.global/eth:${A}/balances`)).toBe(`eth:${A}`)
    expect(err('https://app.safe.global/welcome')).toMatch(/doesn’t name a Safe/)
  })
  it("this page's route", () => {
    expect(ok(`#/sep:${A}`)).toBe(`sep:${A}`)
    expect(ok(`/eth:${A}`)).toBe(`eth:${A}`)
    expect(ok(`https://example.org/exposure/#/sep:${A}`)).toBe(`sep:${A}`)
    expect(routeFor(sep, A)).toBe(`#/sep:${A}`)
    expect(ok(routeFor(eth, A))).toBe(`eth:${A}`)
  })
  it("refuses what isn't an address", () => {
    expect(err('')).toMatch(/Enter a Safe’s address/)
    expect(err('0x1234', 1)).toMatch(/0x followed by 40/)
    expect(err(`sep:${A}00`)).toMatch(/0x followed by 40/)
    expect(err('vitalik.eth', 1)).toMatch(/0x followed by 40/)
  })
  it('refuses a mixed-case address with a wrong checksum', () => {
    const bad = A.replace('A5dA', 'a5DA')
    expect(err(bad, 1)).toMatch(/checksum/)
    expect(err(`eth:${bad}`)).toMatch(/checksum/)
  })
  it('names the networks it knows when the prefix is another', () => {
    expect(err(`matic:${A}`)).toMatch(/“matic” isn’t a network this check knows\. It knows eth, sep, base, arb1, oeth, gno\./)
  })
})
