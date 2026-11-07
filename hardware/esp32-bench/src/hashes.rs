//! The keccak256 implementations under test.
//!
//! Each one is a `step`: hash the 64-byte buffer with keccak256 and write the digest over its first
//! 32 bytes. A 64-byte input fits in one 136-byte block, so one step is one Keccak-f[1600]
//! permutation. Chaining the steps (each input depends on the previous digest) is what WOTS
//! chains do, and it stops the compiler from skipping work.

pub type Step = fn(&mut [u8; 64]);

pub struct Impl {
    pub name: &'static str,
    /// At most 9 characters, for the OLED.
    pub short: &'static str,
    pub step: Step,
}

pub const IMPLS: [Impl; 4] = [
    Impl {
        name: "sha3 0.12 Keccak256 (RustCrypto)",
        short: "sha3",
        step: sha3_api,
    },
    Impl {
        name: "keccak 0.2 f1600 + one-block sponge",
        short: "keccak-f",
        step: keccak_raw,
    },
    Impl {
        name: "tiny-keccak 2.0 Keccak::v256",
        short: "tiny",
        step: tiny_api,
    },
    Impl {
        name: "tiny-keccak 2.0 keccakf + one-block sponge",
        short: "tiny-f",
        step: tiny_raw,
    },
];

fn sha3_api(buf: &mut [u8; 64]) {
    use sha3::{Digest, Keccak256};
    let out = Keccak256::digest(&buf[..]);
    buf[..32].copy_from_slice(&out);
}

fn tiny_api(buf: &mut [u8; 64]) {
    use tiny_keccak::{Hasher, Keccak};
    let mut h = Keccak::v256();
    h.update(&buf[..]);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    buf[..32].copy_from_slice(&out);
}

fn keccak_raw(buf: &mut [u8; 64]) {
    keccak::Keccak::new().with_f1600(|f1600| sponge(buf, f1600));
}

fn tiny_raw(buf: &mut [u8; 64]) {
    sponge(buf, tiny_keccak::keccakf);
}

/// keccak256 of exactly 64 bytes with a bare permutation: absorb 8 lanes, pad (0x01 after the
/// data, 0x80 at the end of the 136-byte rate), permute once, squeeze 4 lanes.
#[inline(always)]
fn sponge(buf: &mut [u8; 64], f1600: fn(&mut [u64; 25])) {
    let mut s = [0u64; 25];
    for (lane, bytes) in s.iter_mut().zip(buf.chunks_exact(8)) {
        *lane = u64::from_le_bytes(bytes.try_into().unwrap());
    }
    s[8] = 0x01;
    s[16] = 0x80 << 56;
    f1600(&mut s);
    for (bytes, lane) in buf[..32].chunks_exact_mut(8).zip(s.iter()) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
}

/// The buffer every chain starts from: bytes 0, 1, ..., 63.
pub fn seed() -> [u8; 64] {
    core::array::from_fn(|i| i as u8)
}

/// keccak256 of 64 zero bytes.
const ZERO64: [u8; 32] = hex32("ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5");
/// The first 32 bytes after 1,000 steps from `seed()`, computed on a PC with pycryptodome.
const CHAIN1000: [u8; 32] =
    hex32("5cfc72b798043048cc34e0a0b18149e912ae3804ce0924da44e98984c5be0c8a");

/// Checks an implementation against digests computed on a PC, so a miscompiled hash on
/// Xtensa shows up as a failure instead of a fast but wrong number.
pub fn self_test(step: Step) -> bool {
    let mut zero = [0u8; 64];
    step(&mut zero);
    let mut chain = seed();
    for _ in 0..1000 {
        step(&mut chain);
    }
    zero[..32] == ZERO64 && chain[..32] == CHAIN1000
}

const fn hex32(s: &str) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not hex"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}
