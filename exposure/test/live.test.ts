// Live, read-only checks against public endpoints: run with EXPOSURE_LIVE=1 (npm run test:live).
// Skipped otherwise, so that npm test stays offline. A handful of RPC batches and service
// requests per Safe.

import { appendFileSync } from 'node:fs'
import { createPublicClient, http, keccak256, concat, encodeAbiParameters, parseAbi, type Address } from 'viem'
import { describe, expect, it } from 'vitest'
import { chainByShortName } from '../src/lib/chains'
import { PASSKEY_FACTORIES, PROXY_CODE_HASHES, PROXY_FACTORIES } from '../src/lib/known'
import { allLimits } from '../src/lib/model'
import { checkSafe } from '../src/lib/read'
import type { SafeReport } from '../src/lib/types'

const LIVE = process.env.EXPOSURE_LIVE === '1'
// EXPOSURE_LIVE_LOG=FILE appends each Safe's summary to FILE
const log = (text: string) => process.env.EXPOSURE_LIVE_LOG && appendFileSync(process.env.EXPOSURE_LIVE_LOG, `${text}\n`)

function client(shortName: string) {
  const chain = chainByShortName(shortName)!
  return { chain, client: createPublicClient({ transport: http(chain.rpc, { batch: { batchSize: 40 }, retryCount: 2 }) }) }
}

async function check(shortName: string, address: Address): Promise<SafeReport> {
  const { chain, client: c } = client(shortName)
  return checkSafe(address, { client: c, chainId: chain.id, service: { url: chain.service }, tokens: chain.tokens })
}

function summary(r: SafeReport): string {
  const owners = r.owners.map((o) => `  ${o.address} ${o.facts.kind} ${o.class}${o.facts.kind === 'key' ? ` nonce=${o.facts.nonce}` : ''}`).join('\n')
  return `${r.address} v${r.version} ${r.threshold}/${r.owners.length} -> ${r.verdict.kind} [${r.verdict.reasons}] modules=${r.modules.length} service=${JSON.stringify(r.service)}\n${owners}\n  limits: ${JSON.stringify(allLimits(r))}`
}

describe.skipIf(!LIVE)('live, Sepolia', () => {
  it("0xA5dA...97E6: 2 of 2, both Winterlock owners: protected", async () => {
    const r = await check('sep', '0xA5dA2Ab05Cb7EE8D3FBbB486Dee542dcCb5197E6')
    log(summary(r))
    expect(r.official).toEqual({ proxy: true, singleton: true })
    expect(r.owners.map((o) => o.facts.kind)).toEqual(['winterlock', 'winterlock'])
    expect(r.verdict.kind).toBe('protected')
  })

  it("0xA8B1...1Cc5: 2 of 3, an ECDSA key and two Winterlock owners: protected", async () => {
    const r = await check('sep', '0xA8B1581F7DDF0DE335828Ba68aEBb4C0D53A1Cc5')
    log(summary(r))
    expect(r.owners.filter((o) => o.facts.kind === 'winterlock')).toHaveLength(2)
    // the ECDSA key never sent a transaction on Sepolia: its signatures at Safe's service expose it
    const key = r.owners.find((o) => o.facts.kind === 'key')!
    expect(key.class).toBe('exposed')
    expect(key.facts).toMatchObject({ nonce: 0, signatures: { byType: { EOA: expect.any(Number) } } })
    expect(r.verdict.kind).toBe('protected')
  })

  it("0xb0ad...1075: threshold 1 with an ECDSA owner that has sent transactions: exposed", async () => {
    // on 2026-11-16: Safe 1.5.0, three owners (two Winterlock owners and the ECDSA key)
    const r = await check('sep', '0xb0ad7064b7fa1FFF27611DC800CF85D70C861075')
    log(summary(r))
    expect(r.threshold).toBe(1)
    expect(r.owners.find((o) => o.address === '0x8db6B632D743aef641146DC943acb64957155388')).toMatchObject({ class: 'exposed', facts: { kind: 'key' } })
    expect(r.verdict.kind).toBe('exposed')
  })

  it('a Safe with a passkey signer owner', async () => {
    const r = await check('sep', '0xfAE87C85C189593f18bd71ffda9b8C19fA3ceEA6')
    log(summary(r))
    expect(r.owners.some((o) => o.facts.kind === 'passkey' && o.class === 'exposed')).toBe(true)
  })
})

describe.skipIf(!LIVE)("live, Sepolia: the landing page's Safes, with owner v1", () => {
  // owner v1 proxies (docs/decisions.md, 2026-11-05: proxy owners): protected
  for (const [address, owners] of [
    ['0x68f64486FC720D1dB14507bC7Fa64896bE6Bef07', 2],
    ['0x1726e1f9Ad2a6580E6a3BeaeF040a2cCE4708767', 3],
  ] as const) {
    it(`${address}: ${owners} Winterlock owners v1, protected`, async () => {
      const r = await check('sep', address)
      log(summary(r))
      expect(r.official).toEqual({ proxy: true, singleton: true })
      expect(r.owners.map((o) => (o.facts.kind === 'winterlock' ? o.facts.version : o.facts.kind))).toEqual(Array(owners).fill(1))
      expect(r.verdict.kind).toBe('protected')
    })
  }

  // the earlier full-contract owners (docs/decisions.md, 2026-11-05: Safe owner, live on Sepolia;
  // commit fdf67c8): 7,114 bytes each, whose creation code no file in the repository pins, so the
  // check doesn't recognise them
  it("0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2: full-contract owners, can't tell", async () => {
    const r = await check('sep', '0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2')
    log(summary(r))
    expect(r.owners.map((o) => (o.facts.kind === 'contract' ? o.facts.size : o.facts.kind))).toEqual([7114, 7114, 7114])
    expect(r.verdict).toMatchObject({ kind: 'cannot-tell', reasons: ['unknown-owners'] })
  })
})

describe.skipIf(!LIVE)('live, Ethereum', () => {
  for (const [name, address] of [
    ['ychad.eth (Yearn)', '0xFEB4acf3df3cDEA7399794D0869ef76A6EfAff52'],
    ['GnosisDAO', '0x849D52316331967b6fF1198e5E32A0eB168D039d'],
  ] as const) {
    it(name, async () => {
      const r = await check('eth', address)
      log(`${name}: ${summary(r)}`)
      expect(r.official).toEqual({ proxy: true, singleton: true })
      expect(r.verdict.kind).not.toBe('protected')
    })
  }

  it('the proxy code hashes and passkey singletons are what the factories give', async () => {
    const { client: c } = client('eth')
    for (const f of PROXY_FACTORIES) {
      const [creation] = await c
        .call({ to: f.address, data: '0x53e5d935' })
        .then((r) => [r.data!])
        .then(([d]) => [`0x${d.slice(2 + 128)}`.slice(0, 2 + 2 * Number(BigInt(`0x${d.slice(66, 130)}`)))] as const)
      const runtime = await c.call({ data: concat([creation as `0x${string}`, encodeAbiParameters([{ type: 'address' }], [f.singleton])]) })
      expect(PROXY_CODE_HASHES[keccak256(runtime.data!)]).toBe(f.version)
    }
    for (const f of PASSKEY_FACTORIES) {
      const s = await c.readContract({ address: f.address, abi: parseAbi(['function SINGLETON() view returns (address)']), functionName: 'SINGLETON' })
      expect(s).toBe(f.singleton)
    }
  })
})
