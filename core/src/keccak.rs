//! keccak256 as Ethereum uses it (Keccak padding 0x01, not SHA3-256's 0x06): a small sponge over a
//! Keccak-f[1600] backend, chosen by feature.
//!
//! - `tiny-keccak` (default): `tiny_keccak::keccakf`.
//! - `sha3`: RustCrypto's permutation (the `keccak` crate, which their `sha3` is built on).
//!
//! With both features on, [`set_backend`] picks one at run time (tiny-keccak until then), so a
//! firmware can time both in one image. The hasher never allocates.

#[cfg(not(any(feature = "tiny-keccak", feature = "sha3")))]
compile_error!("winterlock-core needs a keccak backend: enable the `tiny-keccak` or the `sha3` feature");

/// The sponge's rate for a 256-bit output: 136 bytes per permutation.
pub const RATE: usize = 136;

/// A Keccak-f[1600] backend.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backend {
    /// `tiny_keccak::keccakf`
    TinyKeccak,
    /// RustCrypto's `keccak::f1600`
    RustCrypto,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::TinyKeccak => "tiny-keccak",
            Backend::RustCrypto => "sha3",
        }
    }
}

#[cfg(all(feature = "tiny-keccak", feature = "sha3"))]
static RUSTCRYPTO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Picks the backend at run time. Only with both features on; returns false (and changes nothing)
/// when the backend asked for isn't compiled in.
pub fn set_backend(b: Backend) -> bool {
    #[cfg(all(feature = "tiny-keccak", feature = "sha3"))]
    {
        RUSTCRYPTO.store(b == Backend::RustCrypto, core::sync::atomic::Ordering::Relaxed);
        true
    }
    #[cfg(not(all(feature = "tiny-keccak", feature = "sha3")))]
    {
        b == backend()
    }
}

/// The backend in use.
pub fn backend() -> Backend {
    #[cfg(all(feature = "tiny-keccak", feature = "sha3"))]
    {
        if RUSTCRYPTO.load(core::sync::atomic::Ordering::Relaxed) {
            Backend::RustCrypto
        } else {
            Backend::TinyKeccak
        }
    }
    #[cfg(all(feature = "tiny-keccak", not(feature = "sha3")))]
    {
        Backend::TinyKeccak
    }
    #[cfg(all(feature = "sha3", not(feature = "tiny-keccak")))]
    {
        Backend::RustCrypto
    }
}

#[cfg(feature = "sha3")]
#[inline(always)]
fn rustcrypto_f1600(st: &mut [u64; 25]) {
    keccak::Keccak::new().with_f1600(|f| f(st));
}

#[cfg(feature = "count")]
mod counter {
    use core::sync::atomic::{AtomicU32, Ordering};
    // A plain load and store, not an atomic add: cheap on every target. Counts from two cores
    // hashing at once can lose increments.
    static N: AtomicU32 = AtomicU32::new(0);
    #[inline(always)]
    pub fn bump() {
        N.store(N.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    }
    pub fn get() -> u32 {
        N.load(Ordering::Relaxed)
    }
    pub fn reset() {
        N.store(0, Ordering::Relaxed);
    }
}

/// Keccak-f[1600] permutations since the last [`reset_permutations`] (feature `count`; one core
/// at a time, or the count is approximate).
#[cfg(feature = "count")]
pub fn permutations() -> u32 {
    counter::get()
}

#[cfg(feature = "count")]
pub fn reset_permutations() {
    counter::reset()
}

/// One Keccak-f[1600] permutation with the backend in use.
#[inline(always)]
pub fn permute(st: &mut [u64; 25]) {
    #[cfg(feature = "count")]
    counter::bump();
    #[cfg(all(feature = "tiny-keccak", feature = "sha3"))]
    {
        if RUSTCRYPTO.load(core::sync::atomic::Ordering::Relaxed) {
            rustcrypto_f1600(st)
        } else {
            tiny_keccak::keccakf(st)
        }
    }
    #[cfg(all(feature = "tiny-keccak", not(feature = "sha3")))]
    tiny_keccak::keccakf(st);
    #[cfg(all(feature = "sha3", not(feature = "tiny-keccak")))]
    rustcrypto_f1600(st);
}

/// A streaming keccak256.
#[derive(Clone)]
pub struct Keccak256 {
    st: [u64; 25],
    buf: [u8; RATE],
    pos: usize,
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Keccak256 {
    #[inline]
    pub const fn new() -> Self {
        Keccak256 {
            st: [0; 25],
            buf: [0; RATE],
            pos: 0,
        }
    }

    #[inline]
    pub fn update(&mut self, mut data: &[u8]) -> &mut Self {
        while !data.is_empty() {
            let take = (RATE - self.pos).min(data.len());
            self.buf[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];
            if self.pos == RATE {
                self.absorb();
                self.pos = 0;
            }
        }
        self
    }

    /// Feeds `n` zero bytes.
    #[inline]
    pub fn zeros(&mut self, mut n: usize) -> &mut Self {
        while n > 0 {
            let take = (RATE - self.pos).min(n);
            self.buf[self.pos..self.pos + take].fill(0);
            self.pos += take;
            n -= take;
            if self.pos == RATE {
                self.absorb();
                self.pos = 0;
            }
        }
        self
    }

    #[inline(always)]
    fn absorb(&mut self) {
        for (lane, b) in self.st.iter_mut().zip(self.buf.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        }
        permute(&mut self.st);
    }

    #[inline]
    pub fn finalize(mut self) -> [u8; 32] {
        self.buf[self.pos..].fill(0);
        self.buf[self.pos] ^= 0x01;
        self.buf[RATE - 1] ^= 0x80;
        self.absorb();
        let mut out = [0u8; 32];
        for (o, lane) in out.chunks_exact_mut(8).zip(self.st.iter()) {
            o.copy_from_slice(&lane.to_le_bytes());
        }
        out
    }
}

/// keccak256 of `data`.
#[inline]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize()
}

/// keccak256 of the concatenation of `parts`.
#[inline]
pub fn keccak256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn empty_and_split() {
        assert_eq!(
            keccak256(b""),
            crate::hex::h32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        let data: [u8; 300] = core::array::from_fn(|i| i as u8);
        let one = keccak256(&data);
        for cut in [0, 1, 135, 136, 137, 271, 272, 300] {
            let mut h = Keccak256::new();
            h.update(&data[..cut]).update(&data[cut..]);
            assert_eq!(h.finalize(), one, "cut at {cut}");
        }
        let mut z = Keccak256::new();
        z.update(&data[..10]).zeros(200);
        let mut flat = [0u8; 210];
        flat[..10].copy_from_slice(&data[..10]);
        assert_eq!(z.finalize(), keccak256(&flat));
    }
}
