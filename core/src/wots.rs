//! WOTS one-time signatures and their trees, parameter set D6 (wots.py): n = 24 bytes, w = 16,
//! 48 message chains whose digits add up to 431, no checksum chains, keccak256 truncated to 24
//! bytes. Signing is only through a key log record ([`sign_recorded`]): a one-time key signs once.
//!
//! Hash inputs start with a 32-byte tweak (WotsVerifier.sol):
//! ```text
//!     bits 255..128  public seed (128 bits, per tree)       byte  0..15
//!     bits 127..120  type: 0 chain, 1 pk compression,       byte 16
//!                    2 tree node, 3 message digest
//!     bits 119..56   key index (or parent node index)       bytes 17..24
//!     bits  55..48   chain index                            byte 25
//!     bits  47..40   chain step or tree level               byte 26
//! ```
//! Values are n bytes, hashed as 32-byte words with the low bytes zero.
//!
//! Secrets and randomizers come from keccak256(abi.encode(label, skSeed, ...)) with the labels of
//! a [`Prf`].

use alloc::vec;
use alloc::vec::Vec;

use crate::Error;
use crate::abi::{label_hash, word_u64};
use crate::keccak::{Keccak256, keccak256};
use crate::keylog::Recorded;

pub const N: usize = 24;
pub const LOG_W: u32 = 4;
pub const W: u32 = 16;
pub const WM1: u8 = 15;
pub const TARGET_SUM: u32 = 431;
pub const CHAINS: usize = 48;
pub const SIG_BYTES: usize = N * (1 + CHAINS); // 1,176
pub const HASH_KECCAK: u64 = 0;
/// WotsVerifier.encodeParams(24, 4, 0, 431)
pub const PARAMS: u64 = N as u64 | (LOG_W as u64) << 8 | HASH_KECCAK << 16 | (TARGET_SUM as u64) << 32;
pub const MAX_TRIES: u32 = 1_000_000;
/// The tallest tree whose leaves this crate makes (the Python signer's limit too).
pub const MAX_REAL_HEIGHT: u32 = 20;
/// The tallest tree a certificate may name.
pub const MAX_HEIGHT: u32 = 40;

/// A 24-byte value.
pub type Value = [u8; N];
/// A tree's public seed: 128 bits, big-endian.
pub type Seed = [u8; 16];

const TYPE_CHAIN: u8 = 0;
const TYPE_PK: u8 = 1;
const TYPE_NODE: u8 = 2;
const TYPE_DIGEST: u8 = 3;

const NIBBLES: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut b = 0;
    while b < 256 {
        t[b] = ((b >> 4) + (b & 15)) as u8;
        b += 1;
    }
    t
};

/// Labels of the secret-key PRF (keccak256 of abi.encode(label, ...)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prf {
    pub sk: &'static [u8],
    pub r: &'static [u8],
    pub sibling: &'static [u8],
}

impl Prf {
    /// The Solidity test signer's labels.
    pub const TEST: Prf = Prf {
        sk: b"winterlock.test.sk",
        r: b"winterlock.test.R",
        sibling: b"winterlock.test.sibling",
    };
    /// The signer's labels.
    pub const SIGNER: Prf = Prf {
        sk: b"winterlock.signer.wots.sk.v1",
        r: b"winterlock.signer.wots.R.v1",
        sibling: b"winterlock.signer.wots.sibling.v1",
    };

    /// The secret of chain `i` of key `key_index`.
    pub fn secret(&self, sk_seed: &[u8; 32], key_index: u64, i: u32) -> Value {
        first24(&label_hash(self.sk, &[*sk_seed, word_u64(key_index), word_u64(i as u64)]))
    }

    /// The randomizer of try `counter` for `message`.
    pub fn randomizer(&self, sk_seed: &[u8; 32], key_index: u64, message: &[u8; 32], counter: u64) -> Value {
        first24(&label_hash(self.r, &[*sk_seed, word_u64(key_index), *message, word_u64(counter)]))
    }

    /// A fixed sibling above the real subtree (test trees only).
    pub fn upper_sibling(&self, sk_seed: &[u8; 32], level: u32) -> Value {
        first24(&label_hash(self.sibling, &[*sk_seed, word_u64(level as u64)]))
    }
}

#[inline(always)]
fn first24(d: &[u8; 32]) -> Value {
    let mut v = [0u8; N];
    v.copy_from_slice(&d[..N]);
    v
}

/// tweak(seed, type, index, chain, step) as a 32-byte word.
pub fn tweak(seed: &Seed, typ: u8, index: u64, chain: u8, step: u8) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[..16].copy_from_slice(seed);
    t[16] = typ;
    t[17..25].copy_from_slice(&index.to_be_bytes());
    t[25] = chain;
    t[26] = step;
    t
}

/// Chain steps `from .. to` of chain `chain` of key `key_index`, from x.
fn chain(seed: &Seed, key_index: u64, chain: u8, mut x: Value, from: u8, to: u8) -> Value {
    let mut b = tweak(seed, TYPE_CHAIN, key_index, chain, 0);
    let mut block = [0u8; 64];
    for j in from..to {
        b[26] = j;
        block[..32].copy_from_slice(&b);
        block[32..56].copy_from_slice(&x);
        x = first24(&keccak256(&block));
    }
    x
}

/// trunc(H(tweak(seed, 3, keyIndex) ‖ R ‖ message)); R is a 24-byte value.
pub fn digest(seed: &Seed, key_index: u64, r: &Value, message: &[u8; 32]) -> Value {
    let mut block = [0u8; 96];
    block[..32].copy_from_slice(&tweak(seed, TYPE_DIGEST, key_index, 0, 0));
    block[32..56].copy_from_slice(r);
    block[64..].copy_from_slice(message);
    first24(&keccak256(&block))
}

pub fn digit_sum(d: &Value) -> u32 {
    d.iter().map(|&b| NIBBLES[b as usize] as u32).sum()
}

/// The 48 message digits of a digest, most significant first.
pub fn digits(d: &Value) -> [u8; CHAINS] {
    core::array::from_fn(|i| if i % 2 == 0 { d[i / 2] >> 4 } else { d[i / 2] & 15 })
}

/// Retries the randomizer until the digits hit the target sum: (digits, R, tries).
pub fn encode(seed: &Seed, sk_seed: &[u8; 32], key_index: u64, message: &[u8; 32], prf: &Prf) -> Result<([u8; CHAINS], Value, u32), Error> {
    // abi.encode(label, skSeed, keyIndex, message, counter): the first 136 bytes (the offset, skSeed,
    // keyIndex, message and the counter's top 8 bytes) are the same for every try below 2^64, so
    // they are absorbed once.
    let mut base = Keccak256::new();
    base.update(&word_u64(32 * 5)).update(sk_seed).update(&word_u64(key_index)).update(message).zeros(8);
    let label = prf.r;
    for c in 0..MAX_TRIES {
        let mut h = base.clone();
        h.zeros(16).update(&(c as u64).to_be_bytes());
        h.update(&word_u64(label.len() as u64)).update(label).zeros((32 - label.len() % 32) % 32);
        let r = first24(&h.finalize());
        let d = digest(seed, key_index, &r, message);
        if digit_sum(&d) == TARGET_SUM {
            return Ok((digits(&d), r, c + 1));
        }
    }
    Err(Error::Invalid("target sum not reached"))
}

fn leaf_hasher(seed: &Seed, key_index: u64) -> Keccak256 {
    let mut h = Keccak256::new();
    h.update(seed).update(&[TYPE_PK]).update(&key_index.to_be_bytes()).zeros(7);
    h
}

/// The one-time public key of `key_index`, compressed.
pub fn leaf(seed: &Seed, sk_seed: &[u8; 32], key_index: u64, prf: &Prf) -> Value {
    let mut lh = leaf_hasher(seed, key_index);
    for i in 0..CHAINS {
        let x = prf.secret(sk_seed, key_index, i as u32);
        lh.update(&chain(seed, key_index, i as u8, x, 0, WM1)).zeros(8);
    }
    first24(&lh.finalize())
}

/// Leaves `first`, `first + 1`, ... into `out`. Any range: split a tree's leaves between cores or
/// workers and join them for [`Tree::from_leaves`].
pub fn leaves(seed: &Seed, sk_seed: &[u8; 32], first: u64, prf: &Prf, out: &mut [Value]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = leaf(seed, sk_seed, first + i as u64, prf);
    }
}

/// [R][x_0]...[x_47], n bytes each. Only reachable through a key log record.
fn sign(seed: &Seed, sk_seed: &[u8; 32], key_index: u64, message: &[u8; 32], prf: &Prf) -> Result<Vec<u8>, Error> {
    let (a, r, _) = encode(seed, sk_seed, key_index, message, prf)?;
    let mut out = Vec::with_capacity(SIG_BYTES);
    out.extend_from_slice(&r);
    for (i, &ai) in a.iter().enumerate() {
        let x = prf.secret(sk_seed, key_index, i as u32);
        out.extend_from_slice(&chain(seed, key_index, i as u8, x, 0, ai));
    }
    Ok(out)
}

/// A tree node.
pub fn node(seed: &Seed, level: u8, index: u64, left: &Value, right: &Value) -> Value {
    let mut block = [0u8; 96];
    block[..32].copy_from_slice(&tweak(seed, TYPE_NODE, index, 0, level));
    block[32..56].copy_from_slice(left);
    block[64..88].copy_from_slice(right);
    first24(&keccak256(&block))
}

/// WotsVerifier.computeRoot: the root that a signature and path imply, or None if the digits miss
/// the target (or the lengths are wrong).
pub fn verify_root(seed: &Seed, key_index: u64, message: &[u8; 32], sig: &[u8], path: &[u8]) -> Option<Value> {
    if sig.len() != SIG_BYTES || path.len() % N != 0 {
        return None;
    }
    let r: Value = sig[..N].try_into().unwrap();
    let d = digest(seed, key_index, &r, message);
    if digit_sum(&d) != TARGET_SUM {
        return None;
    }
    let a = digits(&d);
    let mut lh = leaf_hasher(seed, key_index);
    for (i, &ai) in a.iter().enumerate() {
        let x: Value = sig[N * (i + 1)..N * (i + 2)].try_into().unwrap();
        lh.update(&chain(seed, key_index, i as u8, x, ai, WM1)).zeros(8);
    }
    let mut v = first24(&lh.finalize());
    let mut idx = key_index;
    for (lvl, sib) in path.chunks_exact(N).enumerate() {
        let sib: Value = sib.try_into().unwrap();
        let bit = idx & 1;
        idx >>= 1;
        let level = (lvl + 1) as u8;
        v = if bit == 1 { node(seed, level, idx, &sib, &v) } else { node(seed, level, idx, &v, &sib) };
    }
    Some(v)
}

/// A tree of WOTS keys (WotsTree in WotsSigner.sol). Leaves [0, 2^k) are real; levels above k,
/// if any, use fixed pseudo-random siblings (test trees only: the signer's trees have k =
/// height). Holds only public values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    pub seed: Seed,
    pub height: u32,
    pub k: u32,
    /// Levels 0 ..= k, one after the other: level l has 2^(k - l) nodes.
    nodes: Vec<Value>,
    upper: Vec<Value>,
    pub root: Value,
}

fn level_offset(k: u32, l: u32) -> usize {
    (1usize << (k + 1)) - (1usize << (k + 1 - l))
}

impl Tree {
    /// The tree over given leaves and upper siblings.
    pub fn from_leaves(seed: &Seed, height: u32, k: u32, leaves: Vec<Value>, upper: Vec<Value>) -> Result<Tree, Error> {
        if k > height || height > MAX_HEIGHT || k > MAX_REAL_HEIGHT {
            return Err(Error::Invalid("bad tree height"));
        }
        if leaves.len() != 1 << k || upper.len() != (height - k) as usize {
            return Err(Error::Invalid("tree shape"));
        }
        let mut nodes = leaves;
        nodes.reserve_exact((1 << k) - 1);
        for lvl in 1..=k {
            let below = level_offset(k, lvl - 1);
            for i in 0..(1usize << (k - lvl)) {
                let v = node(seed, lvl as u8, i as u64, &nodes[below + 2 * i], &nodes[below + 2 * i + 1]);
                nodes.push(v);
            }
        }
        let mut v = nodes[level_offset(k, k)];
        for lvl in k..height {
            v = node(seed, (lvl + 1) as u8, 0, &v, &upper[(lvl - k) as usize]);
        }
        Ok(Tree { seed: *seed, height, k, nodes, upper, root: v })
    }

    /// A signer's tree: every leaf real (k = height), on this core.
    pub fn create(seed: &Seed, sk_seed: &[u8; 32], height: u32, prf: &Prf) -> Result<Tree, Error> {
        Tree::create_partial(seed, sk_seed, height, height, prf)
    }

    /// A tree with 2^k real leaves and fixed siblings above them.
    pub fn create_partial(seed: &Seed, sk_seed: &[u8; 32], height: u32, k: u32, prf: &Prf) -> Result<Tree, Error> {
        if k > height || height > MAX_HEIGHT || k > MAX_REAL_HEIGHT {
            return Err(Error::Invalid("bad tree height"));
        }
        let upper = (k..height).map(|lvl| prf.upper_sibling(sk_seed, lvl)).collect();
        let mut ls = vec![[0u8; N]; 1 << k];
        leaves(seed, sk_seed, 0, prf, &mut ls);
        Tree::from_leaves(seed, height, k, ls, upper)
    }

    pub fn leaves(&self) -> &[Value] {
        &self.nodes[..1 << self.k]
    }

    /// The authentication path of `index`: 24 bytes per level, `height` levels.
    pub fn path(&self, index: u64) -> Result<Vec<u8>, Error> {
        if index >= 1 << self.k {
            return Err(Error::Invalid("index outside the real subtree"));
        }
        let mut out = Vec::with_capacity(N * self.height as usize);
        for lvl in 0..self.k {
            out.extend_from_slice(&self.nodes[level_offset(self.k, lvl) + ((index >> lvl) ^ 1) as usize]);
        }
        for u in &self.upper {
            out.extend_from_slice(u);
        }
        Ok(out)
    }

    /// The cache format of the Python signer (public values only): height, k, seed, leaves,
    /// upper siblings.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(18 + N * ((1 << self.k) + self.upper.len()));
        b.push(self.height as u8);
        b.push(self.k as u8);
        b.extend_from_slice(&self.seed);
        for x in self.leaves() {
            b.extend_from_slice(x);
        }
        for u in &self.upper {
            b.extend_from_slice(u);
        }
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Tree, Error> {
        if b.len() < 18 {
            return Err(Error::Invalid("tree cache has the wrong size"));
        }
        let (height, k) = (b[0] as u32, b[1] as u32);
        if k > height || k > MAX_REAL_HEIGHT {
            return Err(Error::Invalid("bad tree height"));
        }
        let seed: Seed = b[2..18].try_into().unwrap();
        let body = &b[18..];
        if body.len() != N * ((1usize << k) + (height - k) as usize) {
            return Err(Error::Invalid("tree cache has the wrong size"));
        }
        let xs: Vec<Value> = body.chunks_exact(N).map(|c| c.try_into().unwrap()).collect();
        let upper = xs[1 << k..].to_vec();
        let mut ls = xs;
        ls.truncate(1 << k);
        Tree::from_leaves(&seed, height, k, ls, upper)
    }
}

/// Signs the hash of a key log record with its one-time key, and checks the signature against the
/// tree before returning it: (signature, path). The record proves that the use was stored first.
pub fn sign_recorded(rec: &Recorded, tree: &Tree, sk_seed: &[u8; 32], prf: &Prf) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let u = rec.key_use();
    if u.root != tree.root {
        return Err(Error::Invalid("the record is for another tree"));
    }
    let k = u.key_index;
    let path = tree.path(k)?;
    let sig = sign(&tree.seed, sk_seed, k, &u.hash, prf)?;
    if verify_root(&tree.seed, k, &u.hash, &sig, &path) != Some(tree.root) {
        return Err(Error::SelfCheck("WOTS signature"));
    }
    Ok((sig, path))
}
