// The checks after a transaction read at the block that mined it. A load-balanced endpoint can
// answer from a node that hasn't reached that block: asked for the latest state, it gives the
// state from before; asked for the block, it refuses until it has it (2026-11-13, Sepolia).

import { type Address, type Hex, createPublicClient, custom, encodeFunctionResult, padHex } from 'viem'
import { describe, expect, it } from 'vitest'
import { CHAINS } from '../src/lib/chains'
import { type Ctx, OWNER_ABI, afterTx, readTree } from '../src/lib/chain'

const OWNER = '0x00000000000000000000000000000000000000a4' as Address
const SAFE = '0x00000000000000000000000000000000000000b0' as Address
const ROOT = '0xbd47a6a38f7b59d183fbdc188b378babfd72a87cd586d085' as Hex
const MINED = 12126953n

const tree = (root: Hex, height: number, start: bigint, generation: number) =>
  encodeFunctionResult({ abi: OWNER_ABI, functionName: 'tree', result: [padHex(root, { size: 32, dir: 'right' }), 0n, height, start, generation] })

/** A node one block behind: no tree at "latest", and "header not found" for the mining block the first `refusals` times. */
function laggingCtx(refusals: number): { ctx: Ctx; calls: string[] } {
  const calls: string[] = []
  let refused = 0
  const client = createPublicClient({
    transport: custom({
      async request({ method, params }) {
        if (method !== 'eth_call') throw new Error(`unexpected ${method}`)
        const block = (params as [unknown, string])[1]
        calls.push(block)
        if (block === 'latest') return tree(padHex('0x', { size: 24 }), 0, 0n, 0)
        if (BigInt(block) !== MINED) throw new Error(`unexpected block ${block}`)
        if (refused < refusals) {
          refused++
          throw new Error('header not found')
        }
        return tree(ROOT, 10, 2n, 1)
      },
      // viem's own retries off, so the calls counted are afterTx's
    }, { retryCount: 0 }),
  })
  return { ctx: { chain: CHAINS[0], rpcUrl: 'test', client: client as unknown as Ctx['client'] }, calls }
}

describe('reads after a transaction', () => {
  it('a read of the latest state can miss the transaction', async () => {
    const { ctx } = laggingCtx(0)
    expect((await readTree(ctx, OWNER, SAFE, 2)).root).toBeNull()
  })

  it('reads at the mining block, asking again while the node lacks it', async () => {
    const { ctx, calls } = laggingCtx(2)
    const t = await afterTx({ blockNumber: MINED }, (b) => readTree(ctx, OWNER, SAFE, 2, b), 15, 1)
    expect(t).toEqual({ root: ROOT, height: 10, start: 2, generation: 1 })
    expect(calls).toEqual(['0xb90ae9', '0xb90ae9', '0xb90ae9'])
  })

  it('gives up after its tries with the node’s error', async () => {
    const { ctx, calls } = laggingCtx(100)
    await expect(afterTx({ blockNumber: MINED }, (b) => readTree(ctx, OWNER, SAFE, 2, b), 3, 1)).rejects.toThrow(/header not found/)
    expect(calls).toHaveLength(3)
  })
})
