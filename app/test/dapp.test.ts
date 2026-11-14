// Requests from dapps (src/lib/dapp.ts): the session's namespaces, what each request gets, the
// batch encoding and its decoding, and the answers about an execution. No SDK, no network.

import { encodeFunctionData, encodePacked, getAddress, keccak256, padHex } from 'viem'
import { describe, expect, it } from 'vitest'
import {
  CODE,
  EXECUTION_FAILURE,
  EXECUTION_SUCCESS,
  type ExecutionSource,
  MESSAGES_LATER,
  RpcFail,
  answerFor,
  callsStatus,
  findExecution,
  outcome,
  plan,
  printable,
  sessionNamespaces,
  sessionProperties,
  sessionSafe,
  txFor,
} from '../src/lib/dapp'
import { safeTxHash } from '../src/lib/flows'
import { ERC20_ABI, MAX_UINT256, MULTISEND, batchCalls, controlsSafe, decode, multiSendData, safeTx, stripMetadata } from '../src/lib/safe'
import { directCore } from './helpers'

const SAFE = getAddress('0x6c315c5c9aDbFE50217B976a70BA54Cd11EC04EA')
const CHAIN = 11155111
const ctx = { chain: CHAIN, safe: SAFE, batches: true }
const A = getAddress('0x1111111111111111111111111111111111111111')
const TOKEN = getAddress('0x2222222222222222222222222222222222222222')
const B = getAddress('0x3333333333333333333333333333333333333333')
const SPENDER = getAddress('0x4444444444444444444444444444444444444444')

function fails(f: () => unknown, code: number, text?: RegExp) {
  try {
    f()
  } catch (e) {
    expect(e).toBeInstanceOf(RpcFail)
    expect((e as RpcFail).code).toBe(code)
    if (text) expect((e as RpcFail).message).toMatch(text)
    return
  }
  throw new Error('no RpcFail')
}

const transfer = encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [B, 1_000_000n] })
const approveAll = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, MAX_UINT256] })

describe('the session', () => {
  it('offers the Safe on its chain, with the methods the app answers', () => {
    const { namespaces, notes } = sessionNamespaces(
      { optionalNamespaces: { eip155: { chains: [`eip155:${CHAIN}`, 'eip155:1'], methods: ['eth_sendTransaction', 'eth_chainId', 'eth_signTypedData_v4', 'wallet_grantPermissions'], events: ['chainChanged', 'message'] } } },
      CHAIN,
      SAFE,
    )
    expect(namespaces.eip155.chains).toEqual([`eip155:${CHAIN}`])
    expect(namespaces.eip155.accounts).toEqual([`eip155:${CHAIN}:${SAFE}`])
    expect(namespaces.eip155.methods).toContain('eth_chainId')
    expect(namespaces.eip155.methods).toContain('wallet_sendCalls')
    expect(namespaces.eip155.methods).toContain('personal_sign')
    expect(namespaces.eip155.methods).not.toContain('wallet_grantPermissions')
    expect(namespaces.eip155.events).toEqual(['accountsChanged', 'chainChanged'])
    expect(notes).toEqual([])
  })

  it('lists chains a dapp requires, and says the app refuses requests there', () => {
    const { namespaces, notes } = sessionNamespaces({ requiredNamespaces: { eip155: { chains: ['eip155:1'], methods: ['eth_sign'], events: [] } }, optionalNamespaces: { eip155: { chains: [`eip155:${CHAIN}`] } } }, CHAIN, SAFE)
    expect(namespaces.eip155.chains).toEqual(['eip155:1', `eip155:${CHAIN}`])
    expect(namespaces.eip155.methods).toContain('eth_sign')
    expect(notes.join(' ')).toMatch(/eip155:1 too/)
    expect(notes.join(' ')).toMatch(/eth_sign, which the app refuses/)
  })

  it('refuses a dapp that doesn’t offer the Safe’s chain (5100) or wants another namespace (5104)', () => {
    fails(() => sessionNamespaces({ optionalNamespaces: { eip155: { chains: ['eip155:1'] } } }, CHAIN, SAFE), CODE.chains)
    fails(() => sessionNamespaces({ requiredNamespaces: { solana: { chains: ['solana:x'] } }, optionalNamespaces: { eip155: { chains: [`eip155:${CHAIN}`] } } }, CHAIN, SAFE), CODE.namespace)
  })

  it('finds the Safe in a session’s accounts, on an enabled chain', () => {
    expect(sessionSafe([`eip155:1:${SAFE}`, `eip155:${CHAIN}:${SAFE.toLowerCase()}`], (c) => c === CHAIN)).toEqual({ chain: CHAIN, safe: SAFE })
    expect(sessionSafe([`eip155:1:${SAFE}`], (c) => c === CHAIN)).toBeUndefined()
    expect(JSON.parse(sessionProperties(CHAIN, SAFE, true).capabilities)).toEqual({ [SAFE]: { '0xaa36a7': { atomicBatch: { supported: true } } } })
  })
})

describe('requests', () => {
  it('answers the account and chain itself', () => {
    expect(plan('eth_accounts', [], `eip155:${CHAIN}`, ctx)).toEqual({ kind: 'answer', result: [SAFE] })
    expect(plan('eth_requestAccounts', undefined, undefined, ctx)).toEqual({ kind: 'answer', result: [SAFE] })
    expect(plan('eth_chainId', [], undefined, ctx)).toEqual({ kind: 'answer', result: '0xaa36a7' })
    expect(plan('net_version', [], undefined, ctx)).toEqual({ kind: 'answer', result: '11155111' })
    expect(plan('wallet_switchEthereumChain', [{ chainId: '0xaa36a7' }], undefined, ctx)).toEqual({ kind: 'answer', result: null })
    fails(() => plan('wallet_switchEthereumChain', [{ chainId: '0x1' }], undefined, ctx), CODE.unknownChain)
    expect(plan('wallet_getCapabilities', [SAFE], undefined, ctx)).toEqual({ kind: 'answer', result: { '0xaa36a7': { atomicBatch: { supported: true }, atomic: { status: 'supported' } } } })
    expect(plan('wallet_getCapabilities', [A], undefined, ctx)).toEqual({ kind: 'answer', result: {} })
  })

  it('forwards reads to the RPC, and maps lookups of a hash', () => {
    expect(plan('eth_getBalance', [SAFE, 'latest'], undefined, ctx)).toEqual({ kind: 'rpc', method: 'eth_getBalance', params: [SAFE, 'latest'] })
    const h = keccak256('0x01')
    expect(plan('eth_getTransactionReceipt', [h.toUpperCase().replace('0X', '0x')], undefined, ctx)).toMatchObject({ kind: 'lookup', hash: h })
    expect(plan('wallet_getCallsStatus', [h], undefined, ctx)).toEqual({ kind: 'status', id: h })
    fails(() => plan('wallet_getCallsStatus', ['0x1234'], undefined, ctx), CODE.unknownBundle)
  })

  it('takes an ETH transfer and an ERC-20 transfer as one call each', () => {
    expect(plan('eth_sendTransaction', [{ from: SAFE.toLowerCase(), to: A, value: '0x38d7ea4c68000', gas: '0x5208', nonce: '0x9' }], `eip155:${CHAIN}`, ctx)).toEqual({
      kind: 'tx',
      method: 'eth_sendTransaction',
      calls: [{ to: A, value: 10n ** 15n, data: '0x' }],
    })
    expect(plan('eth_sendTransaction', [{ to: TOKEN.toLowerCase(), input: transfer, chainId: CHAIN }], undefined, ctx)).toEqual({
      kind: 'tx',
      method: 'eth_sendTransaction',
      calls: [{ to: TOKEN, value: 0n, data: transfer }],
    })
  })

  it('refuses a transaction that isn’t the Safe’s or isn’t well formed', () => {
    fails(() => plan('eth_sendTransaction', [{ from: A, to: B }], undefined, ctx), CODE.params, /not this Safe/)
    fails(() => plan('eth_sendTransaction', [{ to: B, chainId: '0x1' }], undefined, ctx), CODE.chains)
    fails(() => plan('eth_sendTransaction', [{ data: '0x6080' }], undefined, ctx), CODE.unsupported, /creates a contract/)
    fails(() => plan('eth_sendTransaction', [{ to: 'bob' }], undefined, ctx), CODE.params)
    fails(() => plan('eth_sendTransaction', [{ to: B, data: '0xzz' }], undefined, ctx), CODE.params)
    fails(() => plan('eth_sendTransaction', [{ to: B, value: '-1' }], undefined, ctx), CODE.params)
    fails(() => plan('eth_sendTransaction', [], undefined, ctx), CODE.params)
  })

  it('refuses a call that changes who controls the Safe, alone or in a batch', () => {
    const add = encodeFunctionData({ abi: [{ type: 'function', name: 'addOwnerWithThreshold', inputs: [{ type: 'address' }, { type: 'uint256' }], outputs: [] }], args: [A, 1n] })
    expect(controlsSafe({ to: SAFE, data: add }, SAFE)).toBe(true)
    expect(controlsSafe({ to: A, data: add }, SAFE)).toBe(false)
    fails(() => plan('eth_sendTransaction', [{ to: SAFE, data: add }], undefined, ctx), CODE.rejected, /owners, threshold/)
    fails(() => plan('wallet_sendCalls', [{ calls: [{ to: A, value: '0x1' }, { to: SAFE, data: add }] }], undefined, ctx), CODE.rejected)
  })

  it('refuses a request for another chain (5100)', () => {
    fails(() => plan('eth_chainId', [], 'eip155:1', ctx), CODE.chains, /not eip155:1/)
    fails(() => plan('wallet_sendCalls', [{ chainId: '0x1', calls: [{ to: A }] }], undefined, ctx), CODE.chains)
  })

  it('refuses messages for now (4001), raw transactions and unknown methods (4200)', () => {
    for (const m of ['personal_sign', 'eth_sign', 'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4']) fails(() => plan(m, ['0x00', SAFE], undefined, ctx), CODE.rejected, new RegExp(MESSAGES_LATER))
    fails(() => plan('eth_signTransaction', [{}], undefined, ctx), CODE.unsupported, /raw transactions/)
    fails(() => plan('eth_sendRawTransaction', ['0x00'], undefined, ctx), CODE.unsupported)
    fails(() => plan('wallet_grantPermissions', [], undefined, ctx), CODE.unsupported)
  })

  it('takes wallet_sendCalls: one call, a batch, and refuses what it can’t do', () => {
    const one = plan('wallet_sendCalls', [{ version: '2.0.0', from: SAFE, chainId: '0xaa36a7', atomicRequired: true, calls: [{ to: A, value: '0x1' }] }], undefined, ctx)
    expect(one).toEqual({ kind: 'tx', method: 'wallet_sendCalls', calls: [{ to: A, value: 1n, data: '0x' }] })
    const two = plan('wallet_sendCalls', [{ calls: [{ to: TOKEN, data: approveAll }, { to: TOKEN, data: transfer }] }], undefined, ctx)
    expect(two.kind === 'tx' && two.calls.length).toBe(2)
    fails(() => plan('wallet_sendCalls', [{ calls: [{ to: A }, { to: B }] }], undefined, { ...ctx, batches: false, noBatches: 'the board refuses delegate calls' }), CODE.rejected, /board/)
    fails(() => plan('wallet_sendCalls', [{ calls: [] }], undefined, ctx), CODE.params)
    fails(() => plan('wallet_sendCalls', [{ calls: [{ to: A }], capabilities: { paymasterService: { url: 'x', optional: false } } }], undefined, ctx), CODE.capability)
    expect(answerFor('wallet_sendCalls', '0xab')).toEqual({ id: '0xab' })
    expect(answerFor('eth_sendTransaction', '0xab')).toBe('0xab')
  })

  it('shows a dapp’s strings without hidden characters', () => {
    const rlo = String.fromCodePoint(0x202e)
    const zw = String.fromCodePoint(0x200b)
    expect(printable(`Uni${zw}swap${rlo}ppa`)).toBe('Uni·swap·ppa')
    expect(printable('a\nb')).toBe('a·b')
    expect(printable('x'.repeat(200), 10)).toBe(`${'x'.repeat(10)}…`)
  })
})

describe('batches', () => {
  // made by the Python signer's encoding (bridge.py's send_calls): an ETH transfer, an ERC-20
  // transfer, and an unlimited allowance
  const PY =
    '0x8d80ff0a0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000018700111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000038d7ea4c68000000000000000000000000000000000000000000000000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000f424000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044095ea7b30000000000000000000000004444444444444444444444444444444444444444ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000'
  const calls = [
    { to: A, value: 10n ** 15n, data: '0x' as const },
    { to: TOKEN, value: 0n, data: transfer },
    { to: TOKEN, value: 0n, data: approveAll },
  ]

  it('encodes calls as the Python signer does, and as encodePacked does', () => {
    expect(multiSendData(calls)).toBe(PY)
    const packed = encodePacked(
      calls.flatMap(() => ['uint8', 'address', 'uint256', 'uint256', 'bytes'] as const),
      calls.flatMap((c) => [0, c.to, c.value, BigInt((c.data.length - 2) / 2), c.data]) as any,
    )
    expect(multiSendData(calls)).toBe(encodeFunctionData({ abi: [{ type: 'function', name: 'multiSend', inputs: [{ type: 'bytes' }], outputs: [], stateMutability: 'payable' }], args: [packed] }))
  })

  it('hashes a batch as the Python signer does', async () => {
    const t = txFor(calls, 7n)
    expect(t.operation).toBe(1)
    expect(t.to).toBe(MULTISEND.address)
    expect(await safeTxHash(directCore(), CHAIN, SAFE, t)).toBe('0xe9f3de877ce58442607a58858b1f2061a7380b5ec9d7ceff058ed6d13de03d24')
    expect(txFor([calls[0]], 7n)).toEqual(safeTx({ to: A, value: 10n ** 15n, nonce: 7n }))
  })

  it('decodes each call of a batch', () => {
    const d = decode(txFor(calls, 0n), SAFE)
    expect(d.decoded.kind).toBe('batch')
    if (d.decoded.kind !== 'batch') return
    expect(d.decoded.calls.map((c) => c.decoding.decoded.kind)).toEqual(['eth', 'erc20', 'allowance'])
    expect(d.decoded.calls[2].decoding.decoded).toEqual({ kind: 'allowance', token: TOKEN, spender: SPENDER, amount: MAX_UINT256 })
    expect(d.warnings).toEqual(['Call 3: Unlimited allowance: the spender may take all of this token the Safe holds, now and later'])
    expect(batchCalls(txFor(calls, 0n))).toEqual(calls)
  })

  it('decodes no other delegatecall as a batch', () => {
    const t = txFor(calls, 0n)
    // another address
    let d = decode({ ...t, to: A }, SAFE)
    expect(d.decoded.kind).toBe('raw')
    expect(d.warnings[0]).toMatch(/^DELEGATECALL/)
    // a call, not a delegatecall
    expect(batchCalls({ ...t, operation: 0 })).toBeUndefined()
    // value on the outer transaction
    expect(batchCalls({ ...t, value: 1n })).toBeUndefined()
    // an inner delegatecall (operation byte 1), which MultiSendCallOnly refuses
    const inner = `${t.data.slice(0, 2 + 8 + 128)}01${t.data.slice(2 + 8 + 128 + 2)}` as `0x${string}`
    d = decode({ ...t, data: inner }, SAFE)
    expect(d.decoded.kind).toBe('raw')
    // a truncated payload
    expect(batchCalls({ ...t, data: multiSendData([calls[1]]).slice(0, -64) as `0x${string}` })).toBeUndefined()
  })

  it('strips the CBOR metadata from code', () => {
    const body = new Uint8Array([0x60, 0x80, 0x60, 0x40])
    const meta = new Uint8Array([0xa2, 0x64, 0x69, 0x70, 0x66, 0x73])
    const code = new Uint8Array([...body, ...meta, 0x00, meta.length])
    expect(stripMetadata(code)).toEqual(body)
    expect(stripMetadata(new Uint8Array([0x60, 0xff, 0xff]))).toEqual(new Uint8Array([0x60, 0xff, 0xff]))
  })
})

describe('what happened to a SafeTx the app gave out', () => {
  const H = keccak256('0x02')
  const OTHER = keccak256('0x03')
  const TX = keccak256('0x04')
  const src = (nonce: number, svc: { isExecuted: boolean; transactionHash?: `0x${string}` | null } | null, at: `0x${string}`[] = []): ExecutionSource => ({
    safeNonce: async () => nonce,
    serviceTx: async () => svc,
    executedAt: async () => at,
  })
  const rec = { safeTxHash: H, nonce: 5, chain: CHAIN, safe: SAFE }

  it('is pending until the Safe’s nonce passes it', async () => {
    expect(await findExecution(rec, src(5, { isExecuted: true, transactionHash: TX }))).toEqual({ state: 'pending' })
  })
  it('is executed when the service says so, or the app executed it', async () => {
    expect(await findExecution(rec, src(6, { isExecuted: true, transactionHash: TX }))).toEqual({ state: 'executed', tx: TX })
    expect(await findExecution({ ...rec, execution: { tx: TX, success: true } }, src(0, null))).toEqual({ state: 'executed', tx: TX })
  })
  it('is replaced when another transaction executed at its nonce', async () => {
    expect(await findExecution(rec, src(6, { isExecuted: false }, [OTHER]))).toEqual({ state: 'replaced' })
  })
  it('stays pending while the service hasn’t indexed the execution', async () => {
    expect(await findExecution(rec, src(6, { isExecuted: false }, []))).toEqual({ state: 'pending' })
    expect(await findExecution(rec, src(6, null, [H]))).toEqual({ state: 'pending' })
  })

  const log = (topic: `0x${string}`, hash: `0x${string}`, address: string = SAFE) => ({ address, topics: [topic, hash], data: padHex('0x00', { size: 32 }) })
  const receipt = (logs: ReturnType<typeof log>[]) => ({ transactionHash: TX, blockHash: keccak256('0x05'), blockNumber: '0x10' as const, gasUsed: '0x5208' as const, status: '0x1' as const, logs })

  it('reads the Safe’s event for this SafeTx from a receipt', () => {
    expect(outcome([log(EXECUTION_SUCCESS, H)], SAFE, H)).toBe('success')
    expect(outcome([log(EXECUTION_FAILURE, H)], SAFE, H)).toBe('failure')
    expect(outcome([log(EXECUTION_SUCCESS, OTHER)], SAFE, H)).toBe('none')
    expect(outcome([log(EXECUTION_SUCCESS, H, A)], SAFE, H)).toBe('none')
    // Safe v1.3.0: the hash in the data
    expect(outcome([{ address: SAFE, topics: [EXECUTION_SUCCESS], data: `${H}${'0'.repeat(64)}` as `0x${string}` }], SAFE, H)).toBe('success')
  })

  it('answers wallet_getCallsStatus: 100, 200, 400, 500', () => {
    expect(callsStatus(rec, { state: 'pending' }, null)).toEqual({ version: '2.0.0', id: H, chainId: '0xaa36a7', atomic: true, status: 100 })
    expect(callsStatus(rec, { state: 'replaced' }, null).status).toBe(400)
    expect(callsStatus(rec, { state: 'executed', tx: TX }, null).status).toBe(100)
    const ok = callsStatus(rec, { state: 'executed', tx: TX }, receipt([log(EXECUTION_SUCCESS, H)]))
    expect(ok.status).toBe(200)
    expect((ok as any).receipts[0]).toMatchObject({ transactionHash: TX, status: '0x1', blockNumber: '0x10' })
    expect(callsStatus(rec, { state: 'executed', tx: TX }, receipt([log(EXECUTION_FAILURE, H)])).status).toBe(500)
  })
})

describe('the decoder', () => {
  it('shows an allowance, and flags an unlimited one', () => {
    const d = decode(safeTx({ to: TOKEN, data: approveAll, nonce: 0n }), SAFE)
    expect(d.decoded).toEqual({ kind: 'allowance', token: TOKEN, spender: SPENDER, amount: MAX_UINT256 })
    expect(d.warnings).toEqual(['Unlimited allowance: the spender may take all of this token the Safe holds, now and later'])
    const some = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, 5n] })
    expect(decode(safeTx({ to: TOKEN, data: some, nonce: 0n }), SAFE).warnings).toEqual([])
  })
})

describe('storage', () => {
  it('upgrades a version 1 database: the dapp store is added, the rest kept', async () => {
    const { IDBFactory } = await import('fake-indexeddb')
    const factory = new IDBFactory()
    const v1: IDBDatabase = await new Promise((res, rej) => {
      const r = factory.open('winterlock', 1)
      r.onupgradeneeded = () => {
        for (const [name, key] of [['device', 'id'], ['settings', 'key'], ['held', 'safeTxHash']] as const) r.result.createObjectStore(name, { keyPath: key })
      }
      r.onsuccess = () => res(r.result)
      r.onerror = () => rej(r.error)
    })
    await new Promise<void>((res) => {
      const t = v1.transaction('settings', 'readwrite')
      t.objectStore('settings').put({ key: 'rpc:11155111', value: 'https://example.org' })
      t.oncomplete = () => res()
    })
    v1.close()
    const { openDb, setting, DB_VERSION } = await import('../src/lib/db')
    const db = await openDb(factory)
    expect(DB_VERSION).toBe(2)
    expect(Array.from(db.objectStoreNames)).toContain('dapp')
    expect(await setting(db, 'rpc:11155111')).toBe('https://example.org')
  })
})
