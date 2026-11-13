// A batch shows as its calls because it delegatecalls Safe's MultiSendCallOnly at its canonical
// address. Before signing one, from a dapp or from the queue, the app checks the code there: a
// delegatecall runs that code as the Safe.

import { readFileSync } from 'node:fs'
import { type Hex, createPublicClient, custom } from 'viem'
import { describe, expect, it } from 'vitest'
import { type Ctx } from '../src/lib/chain'
import { CHAINS } from '../src/lib/chains'
import { checkMultiSend } from '../src/lib/flows'
import { Refused } from '../src/lib/keylog'
import { MULTISEND } from '../src/lib/safe'

// Safe v1.4.1's runtime code at the canonical address, from Sourcify (the Python signer's vectors)
const CANONICAL = JSON.parse(readFileSync(new URL('../../signer/tests/vectors/safe_libs_canonical.json', import.meta.url), 'utf8')).MultiSendCallOnly as Hex

function ctxWith(code: Hex | undefined): Ctx {
  const client = createPublicClient({
    transport: custom(
      {
        async request({ method, params }) {
          if (method !== 'eth_getCode') throw new Error(`unexpected ${method}`)
          expect((params as [string])[0].toLowerCase()).toBe(MULTISEND.address.toLowerCase())
          return code ?? '0x'
        },
      },
      { retryCount: 0 },
    ),
  })
  return { chain: CHAINS[0], rpcUrl: 'test', client: client as unknown as Ctx['client'] }
}

describe('MultiSendCallOnly’s code before a batch is signed', () => {
  it('passes Safe v1.4.1’s release code', async () => {
    await expect(checkMultiSend(ctxWith(CANONICAL))).resolves.toBeUndefined()
  })

  it('refuses when nothing is there', async () => {
    await expect(checkMultiSend(ctxWith(undefined))).rejects.toThrow(Refused)
    await expect(checkMultiSend(ctxWith(undefined))).rejects.toThrow(/no MultiSendCallOnly/)
  })

  it('refuses other code at the address', async () => {
    const other = `${CANONICAL.slice(0, -2)}${CANONICAL.endsWith('00') ? '01' : '00'}` as Hex
    await expect(checkMultiSend(ctxWith(other))).rejects.toThrow(/isn’t Safe’s MultiSendCallOnly/)
    await expect(checkMultiSend(ctxWith('0x6080604052'))).rejects.toThrow(Refused)
  })
})
