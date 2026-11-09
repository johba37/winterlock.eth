//! Winterlock's signer core: the cryptography and key rules of the Python signer
//! (`signer/winterlock_signer`), ported to `no_std` Rust with `alloc` for the browser
//! (WebAssembly), an ESP32 board and native tests. Python stays the reference: the tests read
//! vectors that `signer/tools/core_vectors.py` writes and must match them byte for byte.
//!
//! Nothing here is random, reads a clock or talks to the outside: every random input (seeds, tree
//! salts, phrase entropy) is a parameter, and storage is the platform's ([`keylog::KeyLogStore`]).
//!
//! - [`keccak`]: keccak256, with a choice of Keccak-f backend
//! - [`phrase`]: 24 BIP-39 words for the 32-byte seed, and the pairing check code
//! - [`leansphincs`]: the stateless key (leanSphincs-keccak, pruned at kept-subtree height b)
//! - [`wots`]: one-time keys of parameter set D6 and their trees
//! - [`derive`]: the member key, device keys and tree secret seeds from a seed
//! - [`hbkd`]: hash-based key derivation from BIP-39 (draft ERC), library code not used yet
//!   (feature `hbkd`, on by default)
//! - [`owner`]: WinterlockOwner v2's digests, signature layouts and addresses
//! - [`safe`]: the SafeTx and SafeMessage hashes, from fields
//! - [`keylog`]: which one-time key may sign what, recorded before it signs

#![no_std]
#![forbid(unsafe_code)]
// `x % n == 0` and `chunks_exact(8)` read plainly here; a parsed transaction signature is meant
// to be a large variant.
#![allow(clippy::manual_is_multiple_of, clippy::chunks_exact_to_as_chunks, clippy::large_enum_variant)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

pub mod abi;
pub mod derive;
#[cfg(feature = "hbkd")]
pub mod hbkd;
pub mod hex;
pub mod keccak;
pub mod keylog;
pub mod leansphincs;
pub mod owner;
pub mod phrase;
pub mod safe;
pub mod u256;
#[doc(hidden)]
pub mod wordlist;
pub mod wots;

pub use u256::U256;

use core::fmt;

/// Why the core refused an input or an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// An input outside what the format allows; the text says which.
    Invalid(&'static str),
    /// A nonce that the tree doesn't cover.
    NonceOutsideTree { nonce: U256, start: u64, last: u64 },
    /// A signature that failed its own verification, so it was not released.
    SelfCheck(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(what) => f.write_str(what),
            Error::NonceOutsideTree { nonce, start, last } => {
                write!(f, "nonce {nonce} is outside the tree (nonces {start} to {last})")
            }
            Error::SelfCheck(what) => write!(f, "{what} failed its own verification: not released"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
