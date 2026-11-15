// ETH or tokens to a Winterlock owner contract are refused before a key signs: the contract has no
// receive, fallback or payable function, and can't move tokens. The first wired board signed
// 0.01 ETH to its own owner contract (2026-11-15): valid on-chain, never executable.

import { type Address, createPublicClient, custom, encodeFunctionData } from 'viem'
import { describe, expect, it } from 'vitest'
import { type Ctx, isOwnerContract } from '../src/lib/chain'
import { CHAINS } from '../src/lib/chains'
import { type Env, payees, refusePaymentToOwner } from '../src/lib/flows'
import { ERC20_ABI, batchTx, decode, safeTx } from '../src/lib/safe'

const SAFE = '0x00000000000000000000000000000000000000b0' as Address
const OWN = '0x00000000000000000000000000000000000000a1' as Address
const OTHER_OWNER = '0x00000000000000000000000000000000000000a2' as Address
const PERSON = '0x00000000000000000000000000000000000000c3' as Address
const TOKEN = '0x00000000000000000000000000000000000000d4' as Address

/** OTHER_OWNER holds an owner proxy (the core says so), TOKEN some other code, the rest nothing. */
const ctx: Ctx = {
  chain: CHAINS[0],
  rpcUrl: 'test',
  client: createPublicClient({
    transport: custom({
      async request({ method, params }) {
        if (method !== 'eth_getCode') throw new Error(`unexpected ${method}`)
        const a = (params as [string])[0].toLowerCase()
        return a === OTHER_OWNER ? '0x01' : a === TOKEN ? '0x02' : '0x'
      },
    }),
  }) as unknown as Ctx['client'],
}
const env = {
  core: { call: async (op: string, a: { code: Uint8Array }) => (op === 'memberKeyOf' && a.code[0] === 1 ? new Uint8Array(32) : null) },
} as unknown as Env

const eth = (to: Address, value = 10n ** 16n) => safeTx({ to, value, nonce: 4n })
const tokenTo = (to: Address) => safeTx({ to: TOKEN, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [to, 5n] }), nonce: 4n })
const refused = (tx: ReturnType<typeof eth>) => refusePaymentToOwner(env, ctx, SAFE, tx, OWN)

describe('payments to a Winterlock owner contract', () => {
  it('ETH to the member’s own owner contract: refused (the first wired board’s nonce 4)', async () => {
    await expect(refused(eth(OWN))).rejects.toThrow(/your owner contract\. It can’t receive ETH, so the transaction could never execute/)
  })

  it('an empty call to it, without ETH, reverts as well: refused', async () => {
    await expect(refused(eth(OWN, 0n))).rejects.toThrow(/can’t receive ETH/)
  })

  it('tokens to it: refused, they would stay there', async () => {
    await expect(refused(tokenTo(OWN))).rejects.toThrow(/tokens .* your owner contract\. It can’t move them/)
  })

  it('ETH to another member’s owner contract (a co-owner of the Safe): refused', async () => {
    await expect(isOwnerContract(ctx, env.core, OTHER_OWNER)).resolves.toBe(true)
    await expect(refused(eth(OTHER_OWNER))).rejects.toThrow(/another member’s Winterlock owner contract/)
  })

  it('a call in a batch: refused', async () => {
    const b = batchTx([{ to: PERSON, value: 1n, data: '0x' }, { to: OWN, value: 1n, data: '0x' }], 4n)
    expect(payees(decode(b, SAFE).decoded).map((p) => p.to.toLowerCase())).toEqual([PERSON, OWN])
    await expect(refused(b)).rejects.toThrow(/your owner contract/)
  })

  it('ETH and tokens to anyone else: allowed', async () => {
    await expect(refused(eth(PERSON))).resolves.toBeUndefined()
    await expect(refused(tokenTo(PERSON))).resolves.toBeUndefined()
    await expect(refused(eth(TOKEN))).resolves.toBeUndefined()
  })

  it('a call with data and no ETH to the owner contract: allowed (the Safe may call its owner)', async () => {
    await expect(refused(safeTx({ to: OWN, data: '0x12345678', nonce: 4n }))).resolves.toBeUndefined()
  })
})
