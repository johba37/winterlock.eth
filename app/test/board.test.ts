// The virtual board (the board's own logic in WebAssembly) under Node, through the app's board
// client, in whole flows: setup, a restart and unlock, the gas key, enrolment, an ETH transfer, an
// approveHash with the parent's fields, a call that isn't decoded, a refused delegate call, a
// rejection, a cancel, both keys of a nonce, and a recovery. Every output is checked with the core
// (core-wasm), as the owner contract checks it.

import { type Address, encodeFunctionData, getAddress, hexToBytes, parseAbi, toHex } from 'viem'
import { describe, expect, it } from 'vitest'
import { BoardClient, BoardError, CODE, type Signed } from '../src/board/client'
import { T, encode } from '../src/board/frame'
import { MemorySectors } from '../src/board/runner'
import { encodeForCore, safeTx } from '../src/lib/safe'
import { DirectBoard, confirmOnBoard, pinKeys, setupOnBoard, typeWord, unlockOnBoard } from './board-helpers'
import { wasm } from './helpers'

const CHAIN = 11155111
const SAFE: Address = getAddress('0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a')
const PARENT: Address = getAddress('0x7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e')
const BOB: Address = getAddress('0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0')
const APPROVE = parseAbi(['function approveHash(bytes32 hashToApprove)'])

async function connected(store = new MemorySectors()) {
  const t = new DirectBoard(store)
  const c = new BoardClient(t)
  const booted: string[] = []
  c.onBooted((s) => booted.push(s.state))
  await c.connect()
  return { t, c, booted }
}

/** What the owner contract checks of a transaction signature: its words hash to the SafeTx hash,
 * and its WOTS signature and path lead to the enrolled root (core-wasm's tree_signature_use). */
function checkSigned(s: Signed, owner: Address, tree: { start: number; height: number; root: string }, tx: Uint8Array, safe = SAFE) {
  const hash = toHex(wasm.safe_tx_hash(BigInt(CHAIN), hexToBytes(safe), tx))
  expect(s.hash).toBe(hash)
  expect(s.data.length).toBe(1758)
  expect(s.data[1]).toBe(0) // device 0: the member key's tree
  const u = wasm.tree_signature_use(s.data, BigInt(CHAIN), hexToBytes(owner), hexToBytes(safe), 0, 0, BigInt(tree.start), tree.height, hexToBytes(tree.root as `0x${string}`))
  expect(u, 'the signature leads to the enrolled root').toBeTruthy()
  const v = new DataView(u!.buffer, u!.byteOffset)
  expect(Number(v.getBigUint64(0))).toBe(s.keyIndex)
  expect(u![16]).toBe(s.slot)
  expect(toHex(u!.slice(17, 49))).toBe(hash)
}

describe('the virtual board through the board client', () => {
  it('runs the whole flow, checked by the core', async () => {
    const store = new MemorySectors()
    const { t, c, booted } = await connected(store)
    expect(booted).toEqual(['blank'])
    const s0 = await c.status()
    expect([s0.state, s0.testHooks, s0.version, s0.storageSize]).toEqual(['blank', false, '0.1.0 virtual', 0x2f0000])

    // --- setup: the words on the board, three asked back, a PIN twice ---
    const appRandom = crypto.getRandomValues(new Uint8Array(32))
    const pending = c.setup(appRandom)
    const words = await setupOnBoard(t)
    const id = await pending
    const seed = wasm.phrase_to_seed(words.join(' '))
    const kb = wasm.KeyBuilder.member(seed)
    while (kb.done() < kb.total()) kb.step(256)
    const mk = kb.finish()
    expect(id.memberKey).toBe(toHex(mk.public_key()))
    expect(id.owner).toBe(getAddress(toHex(mk.owner())))
    expect(id.recovered).toBe(false)
    expect(t.title()).toBe('Owner address')
    expect(t.lines().slice(1, 4).join('').replace(/ /g, '')).toBe(id.owner) // the full address, EIP-55
    await t.press('RR')
    expect(t.title()).toBe('Winterlock')
    // a second setup is refused
    await expect(c.setup(appRandom)).rejects.toMatchObject({ code: CODE.ALREADY_SET_UP })

    // --- the gas key: the core's for these words ---
    expect(toHex(await c.gasKey())).toBe(toHex(wasm.gas_key(seed)))

    // --- restart: locked until the PIN ---
    await t.restart()
    expect(booted).toEqual(['blank', 'locked'])
    await expect(c.gasKey()).rejects.toMatchObject({ code: CODE.LOCKED })
    await expect(c.trees()).rejects.toThrow(/enter your PIN on the board/)
    await unlockOnBoard(t)
    const s1 = await c.status()
    expect([s1.state, s1.memberKey, s1.owner, s1.trees]).toEqual(['unlocked', id.memberKey, id.owner, 0])

    // --- enrol: the member confirms, the board makes the tree and signs its certificate ---
    const e1 = c.enrol(CHAIN, SAFE, 0)
    const enrolPages = await confirmOnBoard(t)
    const e = await e1
    expect(enrolPages[0]).toMatch(/^Enrol key tree/)
    expect([e.chain, e.safe, e.start, e.height]).toEqual([CHAIN, SAFE, 0, 10])
    const digest = wasm.certificate_digest(BigInt(CHAIN), hexToBytes(id.owner), hexToBytes(SAFE), 0, 0, hexToBytes(e.root), 10, 0n)
    expect(wasm.stateless_verify(hexToBytes(id.memberKey), digest, e.signature), 'the member key signed the certificate').toBe(true)
    // the certificate's record and the tree were stored before ENROLLED left
    const enrolled = t.sent.find((x) => x.bytes[5] === T.A_ENROLLED)!
    expect(enrolled.saves).toBeGreaterThan(0)
    await t.press('R')
    const tree = { start: 0, height: 10, root: e.root }
    expect(await c.trees()).toEqual([{ chain: CHAIN, safe: SAFE, start: 0, height: 10, root: e.root, used: 0, certified: true }])
    // a tree that doesn't start after the last is refused at once
    await expect(c.enrol(CHAIN, SAFE, 0)).rejects.toMatchObject({ code: CODE.REFUSED })

    // --- an ETH transfer ---
    const tx1 = encodeForCore(safeTx({ to: BOB, value: 25n * 10n ** 16n, nonce: 0n }))
    const p1 = c.sign({ chain: CHAIN, safe: SAFE, tx: tx1 })
    const pages1 = await confirmOnBoard(t)
    const s1sig = await p1
    expect(pages1[0]).toMatch(/^Send/)
    expect(pages1.at(-1)).toMatch(/^Sign\?/)
    checkSigned(s1sig, id.owner, tree, tx1)
    expect([s1sig.slot, s1sig.keyIndex]).toEqual([0, 0])
    await t.press('R')
    // the same transaction again: the same key, the same signature (nothing new used)
    const again = c.sign({ chain: CHAIN, safe: SAFE, root: e.root, tx: tx1 })
    await confirmOnBoard(t)
    const s1b = await again
    expect([s1b.slot, s1b.keyIndex, toHex(s1b.data)]).toEqual([0, 0, toHex(s1sig.data)])
    await t.press('R')

    // --- approveHash of a parent Safe's transfer, with the parent's fields ---
    const parent = encodeForCore(safeTx({ to: BOB, value: 10n ** 17n, nonce: 4n }))
    const parentHash = toHex(wasm.safe_tx_hash(BigInt(CHAIN), hexToBytes(PARENT), parent))
    const approve = encodeForCore(safeTx({ to: PARENT, data: encodeFunctionData({ abi: APPROVE, args: [parentHash] }), nonce: 1n }))
    const p2 = c.sign({ chain: CHAIN, safe: SAFE, tx: approve, parent })
    const pages2 = await confirmOnBoard(t)
    const s2 = await p2
    expect(pages2[0]).toMatch(/^Approve/)
    expect(pages2.some((p) => p.startsWith('Parent: Send'))).toBe(true)
    checkSigned(s2, id.owner, tree, approve)
    await t.press('R')
    // a parent whose fields don't hash to the argument: refused
    const wrongParent = encodeForCore(safeTx({ to: BOB, value: 10n ** 17n + 1n, nonce: 4n }))
    await expect(c.sign({ chain: CHAIN, safe: SAFE, tx: approve, parent: wrongParent })).rejects.toMatchObject({ code: CODE.REFUSED })
    await t.press('R')

    // --- a call the board can't decode: a second confirmation ---
    const raw = encodeForCore(safeTx({ to: BOB, data: '0x12345678deadbeef', nonce: 2n }))
    const p3 = c.sign({ chain: CHAIN, safe: SAFE, tx: raw })
    const pages3 = await confirmOnBoard(t)
    expect(pages3[0]).toMatch(/^NOT DECODED/)
    expect(pages3.at(-1)).toBe('Not decoded')
    checkSigned(await p3, id.owner, tree, raw)
    await t.press('R')

    // --- a delegate call: refused, nothing shown to confirm ---
    const delegate = encodeForCore(safeTx({ to: BOB, data: '0x12345678', operation: 1, nonce: 3n }))
    const refused = await c.sign({ chain: CHAIN, safe: SAFE, tx: delegate }).catch((x) => x)
    expect(refused).toBeInstanceOf(BoardError)
    expect([refused.code, refused.text]).toEqual([CODE.REFUSED, 'delegate calls are refused'])
    expect(t.title()).toBe('Refused')
    await t.press('R')

    // --- rejected on the board, and cancelled by the app ---
    const tx4 = encodeForCore(safeTx({ to: BOB, value: 1n, nonce: 3n }))
    const p4 = c.sign({ chain: CHAIN, safe: SAFE, tx: tx4 })
    await t.until('Send')
    await t.press('L')
    await expect(p4).rejects.toMatchObject({ code: CODE.REJECTED })
    await t.press('R')
    const ac = new AbortController()
    const p5 = c.sign({ chain: CHAIN, safe: SAFE, tx: tx4 }, { signal: ac.signal })
    await t.until('Send')
    // another request meanwhile: busy
    await expect(c.enrol(CHAIN, SAFE, 512)).rejects.toMatchObject({ code: CODE.BUSY })
    ac.abort()
    await expect(p5).rejects.toMatchObject({ code: CODE.CANCELLED })
    expect(t.title()).toBe('Winterlock')

    // --- both keys of a nonce, then a third transaction refused ---
    const tx5 = encodeForCore(safeTx({ to: BOB, value: 2n, nonce: 0n }))
    const p6 = c.sign({ chain: CHAIN, safe: SAFE, tx: tx5 })
    await confirmOnBoard(t)
    const s6 = await p6
    checkSigned(s6, id.owner, tree, tx5)
    expect([s6.slot, s6.keyIndex]).toEqual([1, 1])
    await t.press('R')
    const tx6 = encodeForCore(safeTx({ to: BOB, value: 3n, nonce: 0n }))
    await expect(c.sign({ chain: CHAIN, safe: SAFE, tx: tx6 })).rejects.toMatchObject({ code: CODE.REFUSED, text: 'both keys for this nonce signed other transactions' })
    await t.press('R')
    expect((await c.trees())[0].used).toBe(4)

    // --- every signature that left was stored first: a board restarted from the store knows it ---
    const copy = new MemorySectors()
    copy.sectors = new Map(store.sectors)
    const other = await connected(copy)
    await unlockOnBoard(other.t)
    expect((await other.c.trees())[0].used).toBe(4)
    await other.c.close()

    // --- a request the board doesn't know, and a bad version ---
    await expect(c.request(0x55, new Uint8Array(), 0x81, { timeoutMs: 2000 })).rejects.toMatchObject({ code: 1 })
    const bad = encode(T.STATUS, 999)
    bad[4] = 2 // the version byte: its header CRC no longer matches, so the board skips it
    await t.write(bad)
    expect((await c.status()).state).toBe('unlocked')

    // --- erase from the menu, then recover from the words ---
    await t.press('R') // home -> menu
    await t.press('RR') // Erase this board
    await t.press('B')
    expect(t.title()).toBe('Erase board?')
    await t.press('B')
    expect(t.title()).toBe('Erased')
    await t.press('R')
    expect((await c.status()).state).toBe('blank')
    const r = c.recover()
    await t.until('Recover')
    await t.press('R')
    for (const w of words) await typeWord(t, w)
    expect(t.title()).toBe('Choose a PIN')
    await t.press('R' + pinKeys([1, 2, 3, 4]) + pinKeys([1, 2, 3, 4]))
    const rid = await r
    expect([rid.memberKey, rid.owner, rid.recovered]).toEqual([id.memberKey, id.owner, true])
    await t.press('RR')
    const s2r = await c.status()
    expect([s2r.recovered, s2r.trees]).toEqual([true, 0])
    // the old tree's salt is gone: nothing signs until a new tree is enrolled
    await expect(c.sign({ chain: CHAIN, safe: SAFE, tx: tx4 })).rejects.toMatchObject({ code: CODE.REFUSED, text: 'no key tree for this Safe on this chain: enrol first' })
    await c.close()
  })
})
