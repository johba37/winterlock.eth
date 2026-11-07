//! leanSphincs over keccak256 (leansphincs.py): the stateless key of members and devices
//! (decisions D11, D12).
//!
//! Parameters: n = 16, one XMSS layer of height 26, FORS with k = 24 trees of height a = 10 (no
//! tree roots: the two level-9 tops of each tree), WOTS+C with 64 chains of w = 4 and target sum
//! 120; 5,684-byte signatures. Reproduces the upstream known answers
//! (contracts/test/fixtures/leansphincs-keccak-kat.json).
//!
//! Pruned keys: the key keeps a subtree of height b of the 2^26 one-time leaves; the siblings above
//! it are pseudo-random surrogates, and a signature grinds the randomizer until its leaf index
//! falls in the kept subtree (about 2^(26 - b) digests). b is part of the key.
//!
//! Making a key is mostly its 2^b leaves. [`plan`] and [`leaves`] compute any range of them, so a
//! platform can split the work (two cores, workers) and pass them to [`Key::from_leaves`], or
//! cache them ([`Key::kept_leaves`]).
//!
//! Hash: Th(P, address, M) = keccak256(P ‖ address ‖ M)[0:16]. Address (16 bytes): lo as u32
//! little endian, hi as u24 little endian, t | step << 5, eight zero bytes.

use alloc::vec;
use alloc::vec::Vec;

use crate::Error;
use crate::keccak::{Keccak256, keccak256, keccak256_parts};

pub const H: u32 = 26;
pub const K: usize = 24;
pub const A: u32 = 10;
pub const V: usize = 64;
pub const TARGET: u32 = 120;
pub const NB: usize = 16;
pub const SIG_BYTES: usize = 5684;
/// The kept-subtree height of member and device keys (16 KiB of leaves).
pub const DEFAULT_B: u32 = 10;

/// A 16-byte hash value.
pub type Node = [u8; NB];

const PRF: u8 = 0;
const CHAIN: u8 = 1;
const LEAF: u8 = 2;
const NODE: u8 = 3;
const ENC: u8 = 4;
const PARAMETER: u8 = 5;
const RANDOMIZER: u8 = 7;
const FTS_PRF: u8 = 8;
const FTS_LEAF: u8 = 9;
const FTS_NODE: u8 = 10;
const MSG: u8 = 12;
const SURROGATE: u8 = 13;

const Z8: [u8; 8] = [0; 8];

/// Offsets of the parts of a signature.
const COUNTER_AT: usize = 16 + 176 * K; // 4240
const CHAINS_AT: usize = COUNTER_AT + 4; // 4244
const PATH_AT: usize = CHAINS_AT + NB * V; // 5268

const DIGIT_SUM: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut b = 0;
    while b < 256 {
        t[b] = ((b & 3) + ((b >> 2) & 3) + ((b >> 4) & 3) + (b >> 6)) as u8;
        b += 1;
    }
    t
};

fn addr(t: u8, step: u8, hi: u32, lo: u32) -> [u8; 16] {
    debug_assert!(t < 32 && step < 8 && hi < 1 << 24);
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&lo.to_le_bytes());
    a[4..7].copy_from_slice(&hi.to_le_bytes()[..3]);
    a[7] = t | (step << 5);
    a
}

/// Address bytes 4..15 after a lo already written: hi (u24 LE), the type byte, eight zero bytes.
fn hi_type(t: u8, hi: u32) -> [u8; 12] {
    let mut a = [0u8; 12];
    a[..3].copy_from_slice(&hi.to_le_bytes()[..3]);
    a[3] = t;
    a
}

#[inline(always)]
fn trunc(d: [u8; 32]) -> Node {
    let mut n = [0u8; NB];
    n.copy_from_slice(&d[..NB]);
    n
}

fn node(p: &Node, level: u32, j: u32, left: &Node, right: &Node) -> Node {
    let mut b = [0u8; 64];
    b[..16].copy_from_slice(p);
    b[16..32].copy_from_slice(&addr(NODE, 0, level, j));
    b[32..48].copy_from_slice(left);
    b[48..].copy_from_slice(right);
    trunc(keccak256(&b))
}

/// One step of WOTS+C chain `i` at leaf `lo`.
#[inline(always)]
fn chain_step(p: &Node, lo: &[u8; 4], i: u8, step: u8, x: &Node) -> Node {
    let mut b = [0u8; 48];
    b[..16].copy_from_slice(p);
    b[16..20].copy_from_slice(lo);
    b[20] = i;
    b[23] = CHAIN | (step << 5);
    b[32..].copy_from_slice(x);
    trunc(keccak256(&b))
}

/// The 64 bytes of two chain secrets: PRF call `t` at leaf `lo`.
#[inline(always)]
fn chain_secrets(p: &Node, lo: &[u8; 4], t: u8, seed: &[u8; 32]) -> [u8; 32] {
    let mut b = [0u8; 64];
    b[..16].copy_from_slice(p);
    b[16..20].copy_from_slice(lo);
    b[20] = t;
    b[23] = PRF;
    b[32..].copy_from_slice(seed);
    keccak256(&b)
}

fn leaf_hasher(p: &Node, lo: &[u8; 4]) -> Keccak256 {
    let mut h = Keccak256::new();
    h.update(p).update(lo).update(&[0, 0, 0, LEAF]).update(&Z8);
    h
}

/// The WOTS+C one-time public key at leaf `e`: 32 PRF calls give 64 chain secrets, each walked 3
/// steps.
pub fn leaf(p: &Node, seed: &[u8; 32], e: u32) -> Node {
    let lo = e.to_le_bytes();
    let mut lh = leaf_hasher(p, &lo);
    for t in 0..32u8 {
        let d = chain_secrets(p, &lo, t, seed);
        for half in 0..2u8 {
            let i = 2 * t + half;
            let mut x = trunc_at(&d, half as usize);
            for step in 0..3 {
                x = chain_step(p, &lo, i, step, &x);
            }
            lh.update(&x);
        }
    }
    trunc(lh.finalize())
}

#[inline(always)]
fn trunc_at(d: &[u8; 32], half: usize) -> Node {
    let mut n = [0u8; NB];
    n.copy_from_slice(&d[NB * half..NB * half + NB]);
    n
}

/// Leaves `first`, `first + 1`, ... into `out` (one per slot). Any range: split a key's leaves
/// between cores or workers and join them for [`Key::from_leaves`].
pub fn leaves(p: &Node, seed: &[u8; 32], first: u32, out: &mut [Node]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = leaf(p, seed, first + i as u32);
    }
}

/// P, the key's public parameter: Th(0^16, address(PARAMETER), seed).
pub fn parameter(seed: &[u8; 32]) -> Node {
    trunc(keccak256_parts(&[&[0u8; 16], &addr(PARAMETER, 0, 0, 0), seed]))
}

/// What making a key with kept-subtree height b involves: P, the kept subtree's index s, and its
/// leaves `first .. first + count`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub p: Node,
    pub b: u32,
    pub s: u32,
    pub first: u32,
    pub count: u32,
}

pub fn plan(seed: &[u8; 32], b: u32) -> Result<Plan, Error> {
    if b > H {
        return Err(Error::Invalid("the kept-subtree height b is 0 to 26"));
    }
    let p = parameter(seed);
    let s = if b < H {
        (u64::from_le_bytes(p[..8].try_into().unwrap()) & ((1u64 << (H - b)) - 1)) as u32
    } else {
        0
    };
    Ok(Plan { p, b, s, first: s << b, count: 1 << b })
}

/// A leanSphincs key with a kept subtree of height b. Holds the secret seed.
#[derive(Clone)]
pub struct Key {
    seed: [u8; 32],
    plan: Plan,
    /// Levels 0 ..= b of the kept subtree, one after the other: level l has 2^(b - l) nodes.
    tree: Vec<Node>,
    /// The H - b surrogate siblings above the kept subtree.
    surrogates: Vec<Node>,
    root: Node,
}

fn level_offset(b: u32, l: u32) -> usize {
    (1usize << (b + 1)) - (1usize << (b + 1 - l))
}

impl Key {
    /// Makes the key: all 2^b leaves on this core.
    pub fn new(seed: &[u8; 32], b: u32) -> Result<Key, Error> {
        let plan = plan(seed, b)?;
        let mut kept = vec![[0u8; NB]; plan.count as usize];
        leaves(&plan.p, seed, plan.first, &mut kept);
        Key::from_plan(seed, plan, kept)
    }

    /// The key from its kept leaves (computed elsewhere, or cached). The leaves aren't checked
    /// here: a wrong one gives another public key, which the caller compares with the one it
    /// expects.
    pub fn from_leaves(seed: &[u8; 32], b: u32, kept: Vec<Node>) -> Result<Key, Error> {
        Key::from_plan(seed, plan(seed, b)?, kept)
    }

    /// The key from this seed's plan and its leaves.
    fn from_plan(seed: &[u8; 32], plan: Plan, kept: Vec<Node>) -> Result<Key, Error> {
        let b = plan.b;
        if kept.len() != plan.count as usize {
            return Err(Error::Invalid("kept leaves: a key has 2^b of them"));
        }
        let p = plan.p;
        let s = plan.s;
        let mut tree = kept;
        tree.reserve_exact(plan.count as usize - 1);
        for lvl in 1..=b {
            let below = level_offset(b, lvl - 1);
            let off = s << (b - lvl);
            for j in 0..(1usize << (b - lvl)) {
                let v = node(&p, lvl, off + j as u32, &tree[below + 2 * j], &tree[below + 2 * j + 1]);
                tree.push(v);
            }
        }
        let mut v = tree[level_offset(b, b)];
        let mut surrogates = Vec::with_capacity((H - b) as usize);
        for t in 0..H - b {
            let sib = trunc(keccak256_parts(&[&p, &addr(SURROGATE, 0, b + t, 0), seed]));
            surrogates.push(sib);
            let j = s >> t;
            v = if j & 1 == 1 {
                node(&p, b + t + 1, j >> 1, &sib, &v)
            } else {
                node(&p, b + t + 1, j >> 1, &v, &sib)
            };
        }
        Ok(Key { seed: *seed, plan, tree, surrogates, root: v })
    }

    pub fn b(&self) -> u32 {
        self.plan.b
    }

    /// P
    pub fn p(&self) -> Node {
        self.plan.p
    }

    /// The kept subtree's index among the 2^(26 - b).
    pub fn subtree(&self) -> u32 {
        self.plan.s
    }

    pub fn root(&self) -> Node {
        self.root
    }

    /// root ‖ P (32 bytes): WinterlockOwner's KEY.
    pub fn public_key(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(&self.root);
        k[16..].copy_from_slice(&self.plan.p);
        k
    }

    /// The 2^b kept leaves: public values, safe to cache.
    pub fn kept_leaves(&self) -> &[Node] {
        &self.tree[..self.plan.count as usize]
    }

    /// The kept leaves as one byte string (16 bytes each), the Python signer's cache format.
    pub fn kept_leaves_bytes(&self) -> Vec<u8> {
        self.kept_leaves().concat()
    }

    /// Signs a 32-byte message: the 5,684-byte signature.
    pub fn sign(&self, m: &[u8; 32]) -> Vec<u8> {
        let p = self.plan.p;
        let (rho, idx) = self.grind(m);
        let u = fors_indices(&p, m, &rho);
        let lo = idx.to_le_bytes();
        let mut out = Vec::with_capacity(SIG_BYTES);
        out.extend_from_slice(&rho);
        let mut nodes = vec![[0u8; NB]; 1 << A];
        let mut enc = Keccak256::new();
        enc.update(&p).update(&lo).update(&[0, 0, 0, ENC]).update(&Z8);
        for (kappa, &uk) in u.iter().enumerate() {
            let (t0, t1) = self.fors_tree(&lo, kappa as u32, uk as usize, &mut nodes, &mut out);
            enc.update(&t0).update(&t1);
        }
        let (c, x) = encode(enc);
        out.extend_from_slice(&c.to_le_bytes());
        for t in 0..32u8 {
            let d = chain_secrets(&p, &lo, t, &self.seed);
            for half in 0..2u8 {
                let i = 2 * t + half;
                let mut v = trunc_at(&d, half as usize);
                for step in 0..digit(&x, i as usize) {
                    v = chain_step(&p, &lo, i, step, &v);
                }
                out.extend_from_slice(&v);
            }
        }
        let b = self.plan.b;
        assert!(idx >> b == self.plan.s, "leaf outside the kept subtree");
        let local = (idx - (self.plan.s << b)) as usize;
        for lvl in 0..H {
            if lvl < b {
                out.extend_from_slice(&self.tree[level_offset(b, lvl) + ((local >> lvl) ^ 1)]);
            } else {
                out.extend_from_slice(&self.surrogates[(lvl - b) as usize]);
            }
        }
        assert_eq!(out.len(), SIG_BYTES);
        out
    }

    /// ρ = R_0 + i (u128 little endian) for the least i whose digest's leaf index lies in the kept
    /// subtree.
    fn grind(&self, m: &[u8; 32]) -> ([u8; 16], u32) {
        let p = &self.plan.p;
        let r0 = trunc(keccak256_parts(&[p, &addr(RANDOMIZER, 0, 0, 0), &self.seed, m]));
        let mut r = u128::from_le_bytes(r0);
        let mut block = [0u8; 80];
        block[..16].copy_from_slice(p);
        block[16..32].copy_from_slice(&addr(MSG, 0, 0, 0));
        block[32..64].copy_from_slice(m);
        let (b, s) = (self.plan.b, self.plan.s);
        loop {
            block[64..].copy_from_slice(&r.to_le_bytes());
            let d = keccak256(&block);
            let idx = leaf_index(&d);
            if idx >> b == s {
                return (r.to_le_bytes(), idx);
            }
            r = r.wrapping_add(1);
        }
    }

    /// FORS tree κ of the instance at leaf lo: appends the opened secret and its path (10
    /// siblings) to `out`, and returns the two tops.
    fn fors_tree(&self, lo: &[u8; 4], kappa: u32, uk: usize, nodes: &mut [Node], out: &mut Vec<u8>) -> (Node, Node) {
        let p = &self.plan.p;
        let mut prf = [0u8; 64];
        prf[..16].copy_from_slice(p);
        prf[16..20].copy_from_slice(lo);
        prf[32..].copy_from_slice(&self.seed);
        let mut lf = [0u8; 48];
        lf[..16].copy_from_slice(p);
        lf[16..20].copy_from_slice(lo);
        let mut sk_open = [0u8; NB];
        for t in 0..512u32 {
            prf[20..32].copy_from_slice(&hi_type(FTS_PRF, kappa + (t << 9)));
            let d = keccak256(&prf);
            for half in 0..2usize {
                let j = 2 * t as usize + half;
                let sk = trunc_at(&d, half);
                if j == uk {
                    sk_open = sk;
                }
                lf[20..32].copy_from_slice(&hi_type(FTS_LEAF, kappa + ((j as u32) << 9)));
                lf[32..].copy_from_slice(&sk);
                nodes[j] = trunc(keccak256(&lf));
            }
        }
        out.extend_from_slice(&sk_open);
        let mut nd = [0u8; 64];
        nd[..16].copy_from_slice(p);
        nd[16..20].copy_from_slice(lo);
        let mut len = 1usize << A;
        for lvl in 0..A {
            out.extend_from_slice(&nodes[(uk >> lvl) ^ 1]);
            if lvl + 1 == A {
                break;
            }
            for j in 0..len / 2 {
                nd[20..32].copy_from_slice(&hi_type(FTS_NODE, kappa + ((lvl + 1) << 5) + ((j as u32) << 9)));
                nd[32..48].copy_from_slice(&nodes[2 * j]);
                nd[48..].copy_from_slice(&nodes[2 * j + 1]);
                nodes[j] = trunc(keccak256(&nd));
            }
            len /= 2;
        }
        (nodes[0], nodes[1])
    }
}

/// The leaf index a message digest selects: 26 bits from bytes 16..20.
#[inline(always)]
fn leaf_index(d: &[u8; 32]) -> u32 {
    d[16] as u32 | (d[17] as u32) << 8 | (d[18] as u32) << 16 | ((d[19] & 3) as u32) << 24
}

#[inline(always)]
fn digit(x: &Node, i: usize) -> u8 {
    (x[i >> 2] >> (2 * (i & 3))) & 3
}

fn digit_sum(x: &Node) -> u32 {
    x.iter().map(|&b| DIGIT_SUM[b as usize] as u32).sum()
}

/// WOTS+C: the least counter whose encoding of the tops has digit sum 120. `prefix` has absorbed
/// P ‖ lo ‖ address(ENC) ‖ tops; each try only adds the counter.
fn encode(prefix: Keccak256) -> (u32, Node) {
    for c in 0..=u32::MAX {
        let mut h = prefix.clone();
        h.update(&c.to_le_bytes());
        let x = trunc(h.finalize());
        if digit_sum(&x) == TARGET {
            return (c, x);
        }
    }
    unreachable!("no counter hits the target sum")
}

/// The 24 FORS indices: tree κ in digest call κ / 12, word (κ mod 12) / 6, bits 10 (κ mod 6).
pub fn fors_indices(p: &Node, m: &[u8; 32], rho: &[u8; 16]) -> [u16; K] {
    let d = [0u32, 1].map(|c| keccak256_parts(&[p, &addr(MSG, 0, c, 0), m, rho]));
    core::array::from_fn(|kappa| {
        let r = kappa % 12;
        let w = u64::from_le_bytes(d[kappa / 12][8 * (r / 6)..8 * (r / 6) + 8].try_into().unwrap());
        ((w >> (A as usize * (r % 6))) & 0x3FF) as u16
    })
}

/// The leaf index a signature's randomizer selects.
pub fn signature_leaf_index(p: &Node, m: &[u8; 32], rho: &[u8; 16]) -> u32 {
    leaf_index(&keccak256_parts(&[p, &addr(MSG, 0, 0, 0), m, rho]))
}

/// Verifies a signature against root ‖ P, as LeanSphincsAsm.verify does.
pub fn verify(public_key: &[u8; 32], m: &[u8; 32], sig: &[u8]) -> bool {
    if sig.len() != SIG_BYTES {
        return false;
    }
    let root: Node = public_key[..16].try_into().unwrap();
    let p: Node = public_key[16..].try_into().unwrap();
    let rho: [u8; 16] = sig[..16].try_into().unwrap();
    let idx = signature_leaf_index(&p, m, &rho);
    let u = fors_indices(&p, m, &rho);
    let lo = idx.to_le_bytes();
    let mut enc = Keccak256::new();
    enc.update(&p).update(&lo).update(&[0, 0, 0, ENC]).update(&Z8);
    let mut b = [0u8; 64];
    b[..16].copy_from_slice(&p);
    b[16..20].copy_from_slice(&lo);
    for (kappa, &uk) in u.iter().enumerate() {
        let kappa = kappa as u32;
        let uk = uk as u32;
        let off = 16 + 176 * kappa as usize;
        let path = |lvl: u32| -> &[u8] { &sig[off + 16 + 16 * lvl as usize..off + 32 + 16 * lvl as usize] };
        b[20..32].copy_from_slice(&hi_type(FTS_LEAF, kappa + (uk << 9)));
        b[32..48].copy_from_slice(&sig[off..off + 16]);
        let mut v = trunc(keccak256(&b[..48]));
        for lvl in 0..A - 1 {
            let j = uk >> (lvl + 1);
            b[20..32].copy_from_slice(&hi_type(FTS_NODE, kappa + ((lvl + 1) << 5) + (j << 9)));
            if (uk >> lvl) & 1 == 1 {
                b[32..48].copy_from_slice(path(lvl));
                b[48..].copy_from_slice(&v);
            } else {
                b[32..48].copy_from_slice(&v);
                b[48..].copy_from_slice(path(lvl));
            }
            v = trunc(keccak256(&b));
        }
        if (uk >> (A - 1)) & 1 == 1 {
            enc.update(path(A - 1)).update(&v);
        } else {
            enc.update(&v).update(path(A - 1));
        }
    }
    enc.update(&sig[COUNTER_AT..CHAINS_AT]);
    let x = trunc(enc.finalize());
    if digit_sum(&x) != TARGET {
        return false;
    }
    let mut lh = leaf_hasher(&p, &lo);
    for i in 0..V {
        let mut v: Node = sig[CHAINS_AT + 16 * i..CHAINS_AT + 16 + 16 * i].try_into().unwrap();
        for step in digit(&x, i)..3 {
            v = chain_step(&p, &lo, i as u8, step, &v);
        }
        lh.update(&v);
    }
    let mut v = trunc(lh.finalize());
    let mut j = idx;
    for lvl in 0..H {
        let sib: Node = sig[PATH_AT + 16 * lvl as usize..PATH_AT + 16 + 16 * lvl as usize].try_into().unwrap();
        v = if j & 1 == 1 { node(&p, lvl + 1, j >> 1, &sib, &v) } else { node(&p, lvl + 1, j >> 1, &v, &sib) };
        j >>= 1;
    }
    v == root
}

/// The signature's parts, for showing or checking: randomizer, WOTS+C counter, leaf index.
pub fn signature_counter(sig: &[u8]) -> Option<u32> {
    (sig.len() == SIG_BYTES).then(|| u32::from_le_bytes(sig[COUNTER_AT..CHAINS_AT].try_into().unwrap()))
}
