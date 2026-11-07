//! What a seed gives (member.py), each keccak256(abi.encode(label, ...)):
//!
//! ```text
//!   member key       ("winterlock.signer.stateless.v1", seed) -> leanSphincs key, b = 10
//!   device key       ("winterlock.signer.device-key.v1", seed) -> leanSphincs key, b = 10
//!   tree secret seed ("winterlock.signer.ops.v2", seed, chain, owner, safe, device, generation,
//!                    start, salt); salt: 32 random bytes recorded only in the key log
//!   gas key          ("winterlock.app.gas.v1", seed) -> a secp256k1 private key (the app's)
//! ```
//! The member key's seed is the recovery phrase's; a device's seed is random and has no phrase.
//!
//! The gas key is the signer app's: an ordinary account that pays gas for a member, one per
//! member, so every device paired from the phrase holds the same one (docs/notes/signer-app.md).
//! It isn't an owner, and keccak256 keeps the phrase's seed out of reach of anyone who holds it.

use crate::abi::{label_hash, word_address, word_u64};
use crate::leansphincs::{self, DEFAULT_B};
use crate::Error;

pub const MEMBER_KEY_LABEL: &[u8] = b"winterlock.signer.stateless.v1";
pub const DEVICE_KEY_LABEL: &[u8] = b"winterlock.signer.device-key.v1";
pub const TREE_SECRET_LABEL: &[u8] = b"winterlock.signer.ops.v2";
pub const GAS_KEY_LABEL: &[u8] = b"winterlock.app.gas.v1";
/// secp256k1's group order n, big-endian: a private key is 1 to n - 1.
pub const SECP256K1_N: [u8; 32] = crate::hex::h32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
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

/// Whether `key` is a secp256k1 private key: not zero, and below the group order n.
pub fn check_secp256k1_key(key: &[u8; 32]) -> Result<(), Error> {
    if key.iter().all(|&b| b == 0) {
        return Err(Error::Invalid("a secp256k1 private key can't be zero"));
    }
    // big-endian byte arrays compare as the numbers they spell
    if *key >= SECP256K1_N {
        return Err(Error::Invalid("a secp256k1 private key must be below the group order n"));
    }
    Ok(())
}

/// The gas account's private key of a recovery phrase's seed: keccak256(abi.encode(
/// "winterlock.app.gas.v1", seed)). Refused if it is zero or not below n, which no seed is known
/// to give (the chance is about 2^-128).
pub fn gas_key(seed: &[u8; 32]) -> Result<[u8; 32], Error> {
    let key = label_hash(GAS_KEY_LABEL, &[*seed]);
    check_secp256k1_key(&key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minus(mut v: [u8; 32], k: u8) -> [u8; 32] {
        // v - k for a small k, with borrow
        let mut borrow = k as u16;
        for b in v.iter_mut().rev() {
            let x = *b as u16;
            if x >= borrow {
                *b = (x - borrow) as u8;
                return v;
            }
            *b = (x + 256 - borrow) as u8;
            borrow = 1;
        }
        v
    }

    #[test]
    fn secp256k1_key_range() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(check_secp256k1_key(&one).is_ok());
        assert!(check_secp256k1_key(&minus(SECP256K1_N, 1)).is_ok());
        assert!(check_secp256k1_key(&[0; 32]).is_err());
        assert!(check_secp256k1_key(&SECP256K1_N).is_err());
        let mut above = SECP256K1_N;
        above[31] += 1;
        assert!(check_secp256k1_key(&above).is_err());
        assert!(check_secp256k1_key(&[0xff; 32]).is_err());
        // the high bytes alone decide when they differ from n's
        let mut high = [0u8; 32];
        high[..15].copy_from_slice(&SECP256K1_N[..15]);
        high[15] = 0xff;
        assert!(check_secp256k1_key(&high).is_err());
    }

    #[test]
    fn gas_key_is_the_labelled_hash() {
        let seed = [7u8; 32];
        assert_eq!(gas_key(&seed).unwrap(), label_hash(GAS_KEY_LABEL, &[seed]));
        assert_ne!(gas_key(&seed).unwrap(), member_key_seed(&seed));
    }
}
