// The operations the core's worker runs, over the WebAssembly bindings (core-wasm). The worker
// (worker.ts) and the unit tests run this same code; the tests load the WebAssembly in Node.
//
// Two kinds of worker run these:
//   the device worker   long-lived: device keys, key trees, tree certificates, the key log's
//                       one-time signatures, hashes and checks
//   a member session    short-lived: it holds the recovery phrase's seed and the member key, and
//                       the app terminates it as soon as the member key has signed, which discards
//                       its whole WebAssembly memory

import type * as Wasm from '../wasm/core.js'

export type Progress = (done: number, total: number) => void
type Op = (args: any, progress: Progress) => unknown | Promise<unknown>

const STEP = 16

function u64(b: Uint8Array, at: number): number {
  const v = new DataView(b.buffer, b.byteOffset + at, 8).getBigUint64(0)
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('number out of range')
  return Number(v)
}

function build(builder: { total(): number; done(): number; step(n: number): number }, progress: Progress) {
  const total = builder.total()
  progress(0, total)
  while (builder.done() < total) progress(builder.step(STEP), total)
}

function zero(b: Uint8Array | undefined) {
  b?.fill(0)
}

export function deviceOps(w: typeof Wasm): Record<string, Op> {
  // the device key, kept between calls (public key -> key)
  const keys = new Map<string, Wasm.StatelessKey>()
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

  function deviceKey(seed: Uint8Array, kept: Uint8Array, publicKey: Uint8Array): Wasm.StatelessKey {
    const id = hex(publicKey)
    let k = keys.get(id)
    if (!k) {
      k = w.StatelessKey.device_from_cache(seed, kept, publicKey)
      keys.set(id, k)
    }
    return k
  }

  return {
    newDeviceKey({ seed }: { seed: Uint8Array }, progress) {
      const b = w.KeyBuilder.device(seed)
      build(b, progress)
      const k = b.finish()
      const out = { publicKey: k.public_key(), keptLeaves: k.kept_leaves() }
      keys.set(hex(out.publicKey), k)
      return out
    },
    buildTree(a: { seed: Uint8Array; chain: number; owner: Uint8Array; safe: Uint8Array; device: number; generation: number; start: number; salt: Uint8Array; height: number }, progress) {
      const b = new w.TreeBuilder(a.seed, BigInt(a.chain), a.owner, a.safe, a.device, a.generation, BigInt(a.start), a.salt, a.height)
      build(b, progress)
      const cache = b.finish()
      return { cache, root: w.tree_root(cache) }
    },
    certifyTree(a: { seed: Uint8Array; keptLeaves: Uint8Array; publicKey: Uint8Array; chain: number; owner: Uint8Array; safe: Uint8Array; device: number; generation: number; root: Uint8Array; height: number; start: number }) {
      const k = deviceKey(a.seed, a.keptLeaves, a.publicKey)
      return k.certify_tree(BigInt(a.chain), a.owner, a.safe, a.device, a.generation, a.root, a.height, BigInt(a.start))
    },
    pickUse(a: { chain: number; safe: Uint8Array; root: Uint8Array; start: number; height: number; nonce: number; hash: Uint8Array; uses: Uint8Array }) {
      const r = w.pick_use(BigInt(a.chain), a.safe, a.root, BigInt(a.start), a.height, BigInt(a.nonce), a.hash, a.uses)
      return { slot: r[0], already: r[1] === 1, keyIndex: u64(r, 2) }
    },
    signTransaction(a: { seed: Uint8Array; chain: number; owner: Uint8Array; safe: Uint8Array; device: number; generation: number; start: number; salt: Uint8Array; cache: Uint8Array; uses: Uint8Array; tx: Uint8Array }) {
      return w.sign_transaction(a.seed, BigInt(a.chain), a.owner, a.safe, a.device, a.generation, BigInt(a.start), a.salt, a.cache, a.uses, a.tx)
    },
    treeSignatureUse(a: { data: Uint8Array; chain: number; owner: Uint8Array; safe: Uint8Array; device: number; generation: number; start: number; height: number; root: Uint8Array }) {
      const r = w.tree_signature_use(a.data, BigInt(a.chain), a.owner, a.safe, a.device, a.generation, BigInt(a.start), a.height, a.root)
      if (!r) return null
      return { keyIndex: u64(r, 0), nonce: u64(r, 8), slot: r[16], hash: r.slice(17, 49) }
    },
    safeTxHash(a: { chain: number; safe: Uint8Array; tx: Uint8Array }) {
      return w.safe_tx_hash(BigInt(a.chain), a.safe, a.tx)
    },
    ownerAddress(a: { memberKey: Uint8Array }) {
      return w.owner_address(a.memberKey)
    },
    memberKeyOf(a: { address: Uint8Array; code: Uint8Array }) {
      return w.member_key_of(a.address, a.code) ?? null
    },
    checkCode(a: { owner: Uint8Array; device: number; key: Uint8Array }) {
      return w.check_code(a.owner, a.device, a.key)
    },
    pinned() {
      const b = w.pinned_contracts()
      return [0, 1, 2, 3].map((i) => b.slice(20 * i, 20 * i + 20))
    },
    parsePhrase(a: { text: string }) {
      // only whether it parses, and the core's reason if not; the seed stays here
      const s = w.phrase_to_seed(a.text)
      zero(s)
      return true
    },
    /** Timings of the heavy operations in this worker, for the measurements. */
    bench(a: { runs?: number }) {
      const seed = crypto.getRandomValues(new Uint8Array(32))
      const t0 = performance.now()
      const mb = w.KeyBuilder.member(seed)
      build(mb, () => {})
      const mk = mb.finish()
      const tKey = performance.now() - t0
      const owner = mk.owner()
      const safe = crypto.getRandomValues(new Uint8Array(20))
      const salt = crypto.getRandomValues(new Uint8Array(32))
      const t1 = performance.now()
      const tb = new w.TreeBuilder(seed, 11155111n, owner, safe, 1, 1, 0n, salt, 10)
      build(tb, () => {})
      const cache = tb.finish()
      const tTree = performance.now() - t1
      const root = w.tree_root(cache)
      const sigs: number[] = []
      for (let i = 0; i < (a.runs ?? 5); i++) {
        const t = performance.now()
        mk.certify_tree(11155111n, owner, safe, 1, 1, root, 10, BigInt(i))
        sigs.push(performance.now() - t)
      }
      // one-time signatures through the key log's read-only store, with the use already recorded
      const wots: number[] = []
      for (let n = 0; n < (a.runs ?? 5); n++) {
        const tx = new Uint8Array(221)
        tx[19] = 1
        new DataView(tx.buffer).setBigUint64(189 + 24, BigInt(n))
        const hash = w.safe_tx_hash(11155111n, safe, tx)
        const pick = w.pick_use(11155111n, safe, root, 0n, 10, BigInt(n), hash, new Uint8Array())
        const use = new Uint8Array(40)
        use.set(pick.slice(2, 10), 0)
        use.set(hash, 8)
        const t = performance.now()
        w.sign_transaction(seed, 11155111n, owner, safe, 1, 1, 0n, salt, cache, use, tx)
        wots.push(performance.now() - t)
      }
      mk.free()
      zero(seed)
      const median = (xs: number[]) => [...xs].sort((x, y) => x - y)[Math.floor(xs.length / 2)]
      return { backend: w.keccak_backend(), memberKeyMs: tKey, tree10Ms: tTree, statelessMs: median(sigs), statelessAll: sigs, wotsMs: median(wots) }
    },
  }
}

/** A member session: the phrase's seed and the member key live only here, in a worker the app
 * terminates after use. The seed never leaves; the words leave once, to be shown. */
export function memberOps(w: typeof Wasm): Record<string, Op> {
  let seed: Uint8Array | undefined
  let words: string | undefined
  let key: Wasm.StatelessKey | undefined

  return {
    newPhrase() {
      zero(seed)
      seed = crypto.getRandomValues(new Uint8Array(32))
      words = w.phrase_of_seed(seed)
      return words.split(' ')
    },
    checkWord(a: { position: number; answer: string }) {
      if (!words) throw new Error('no phrase in this session')
      return w.phrase_matches(words, a.position, a.answer)
    },
    fromPhrase(a: { text: string }) {
      zero(seed)
      seed = w.phrase_to_seed(a.text)
      words = undefined
      return true
    },
    derive(_a: unknown, progress) {
      if (!seed) throw new Error('no phrase in this session')
      const b = w.KeyBuilder.member(seed)
      build(b, progress)
      key = b.finish()
      return { memberKey: key.public_key(), owner: key.owner(), gasKey: w.gas_key(seed) }
    },
    certifyDevice(a: { chain: number; device: number; generation: number; deviceKey: Uint8Array }) {
      if (!key) throw new Error('the member key isn’t derived')
      return key.certify_device(BigInt(a.chain), a.device, a.generation, a.deviceKey)
    },
    revokeDevice(a: { chain: number; device: number; generation: number }) {
      if (!key) throw new Error('the member key isn’t derived')
      return key.revoke_device(BigInt(a.chain), a.device, a.generation)
    },
    forget() {
      zero(seed)
      seed = undefined
      words = undefined
      key?.free()
      key = undefined
      return true
    },
  }
}
