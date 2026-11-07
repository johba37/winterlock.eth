//! What a seed gives (member.py), each keccak256(abi.encode(label, ...)):
//!
//! ```text
//!   member key       ("winterlock.signer.stateless.v1", seed) -> leanSphincs key, b = 10
//!   device key       ("winterlock.signer.device-key.v1", seed) -> leanSphincs key, b = 10
//!   tree secret seed ("winterlock.signer.ops.v2", seed, chain, owner, safe, device, generation,
//!                    start, salt); salt: 32 random bytes recorded only in the key log
//! ```
//! The member key's seed is the recovery phrase's; a device's seed is random and has no phrase.

use crate::abi::{label_hash, word_address, word_u64};
use crate::leansphincs::{self, DEFAULT_B};
use crate::Error;

pub const MEMBER_KEY_LABEL: &[u8] = b"winterlock.signer.stateless.v1";
pub const DEVICE_KEY_LABEL: &[u8] = b"winterlock.signer.device-key.v1";
pub const TREE_SECRET_LABEL: &[u8] = b"winterlock.signer.ops.v2";
/// The kept-subtree height of member and device keys.
pub const STATELESS_B: u32 = DEFAULT_B;

/// The leanSphincs seed of the member key.
pub fn member_key_seed(seed: &[u8; 32]) -> [u8; 32] {
    label_hash(MEMBER_KEY_LABEL, &[*seed])
}

/// The leanSphincs seed of a device key.
pub fn device_key_seed(seed: &[u8; 32]) -> [u8; 32] {
    label_hash(DEVICE_KEY_LABEL, &[*seed])
}

/// The member key (device 0) of a recovery phrase's seed, made on this core.
pub fn member_key(seed: &[u8; 32]) -> Result<leansphincs::Key, Error> {
    leansphincs::Key::new(&member_key_seed(seed), STATELESS_B)
}

/// The device key of a device's seed, made on this core.
pub fn device_key(seed: &[u8; 32]) -> Result<leansphincs::Key, Error> {
    leansphincs::Key::new(&device_key_seed(seed), STATELESS_B)
}

/// Where a key tree belongs: its secret seed's inputs besides the seed and salt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreePlace {
    pub chain: u64,
    pub owner: [u8; 20],
    pub safe: [u8; 20],
    pub device: u8,
    pub generation: u16,
    pub start: u64,
}

/// A key tree's secret seed, from which wots::Prf::SIGNER draws its secrets.
pub fn tree_secret_seed(seed: &[u8; 32], at: &TreePlace, salt: &[u8; 32]) -> [u8; 32] {
    label_hash(
        TREE_SECRET_LABEL,
        &[
            *seed,
            word_u64(at.chain),
            word_address(&at.owner),
            word_address(&at.safe),
            word_u64(at.device as u64),
            word_u64(at.generation as u64),
            word_u64(at.start),
            *salt,
        ],
    )
}

/// The tree's public seed (owner::tree_seed) for the same place.
pub fn tree_public_seed(at: &TreePlace) -> crate::wots::Seed {
    crate::owner::tree_seed(at.chain, &at.owner, &at.safe, at.device, at.generation, at.start)
}
