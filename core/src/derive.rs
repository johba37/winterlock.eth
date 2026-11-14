//! Winterlock's keys. Two derivations:
//!
//! - [`erc8499`]: ERC-8499 (Hash-Based Key Derivation from BIP-39), which the signer app uses
//!   since 2026-11-14 (erc8499.py).
//! - The earlier one, below, from the phrase's entropy under Keccak labels: the command-line
//!   signer's homes still use it (member.py), and the app's builds up to 494703c did. The same
//!   words give unrelated keys under the two, so another member key and another owner.
//!
//! What a seed gives under the earlier derivation (member.py), each keccak256(abi.encode(label, ...)):
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

/// Winterlock's keys under ERC-8499 (`hbkd`), as erc8499.py derives them:
///
/// ```text
///   phrase root   R = HKDF-Extract("HBKD/v1", BIP-39 seed of the phrase's 24 words, no passphrase)
///   device root   R = HKDF-Extract("HBKD/v1", 32 random bytes): a random root; a device has no phrase
///
///   member key    stateless, phrase root, key type KEY_TYPE, L = 32, account 0
///   device key    stateless, device root, key type KEY_TYPE, L = 32, account 0
///   tree secret   stateful, the root of the device that holds the tree, key type
///                 tree_key_type(height), L = 32, account 0; context = owner::tree_place_digest of
///                 the tree's place, instance = the tree's salt (32 random bytes made with the tree)
///   gas key       application secret, phrase root, label GAS_LABEL, L = 32, account 0
/// ```
///
/// [`KEY_TYPE`] names leanSPHINCS over Keccak-256 at this core's parameters with the top tree
/// pruned to a kept subtree of height 10 ([`STATELESS_B`]); the ERC's test cases use the same
/// string. A tree's key type names WOTS parameter set D6 and the tree's height, which both change
/// its root; the place goes into the context. One phrase is one member: account 0 throughout.
#[cfg(feature = "hbkd")]
pub mod erc8499 {
    use super::{STATELESS_B, TreePlace, check_secp256k1_key};
    use crate::{Error, hbkd, leansphincs, owner};

    /// The key type of member and device keys.
    pub const KEY_TYPE: &str = "leanSphincs-keccak/wambsgans-keccak/b10";
    /// A tree's key type: this, then its height in decimal.
    pub const TREE_KEY_TYPE: &str = "winterlock-wots-d6-keccak/tree-h";
    /// The gas key's application label.
    pub const GAS_LABEL: &str = "winterlock.eth/gas";
    /// The one account a phrase's member uses.
    pub const ACCOUNT: u32 = 0;

    /// A root: 64 bytes.
    pub type Root = [u8; hbkd::HASH_LEN];

    /// The root of a recovery phrase from its seed (the phrase's BIP-39 entropy): PBKDF2 over
    /// its 24 words, no passphrase, then HKDF-Extract.
    pub fn phrase_root(seed: &[u8; 32]) -> Result<Root, Error> {
        hbkd::winterlock_root(seed, "")
    }

    /// A device's random root from the 32 random bytes it keeps.
    pub fn device_root(random: &[u8; 32]) -> Root {
        hbkd::hkdf_extract(hbkd::SALT, random)
    }

    /// The leanSphincs seed of a root's stateless key: the member key of a phrase root, the
    /// device key of a device root.
    pub fn stateless_key_seed(root: &Root) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        hbkd::stateless_seed_into(root, KEY_TYPE, ACCOUNT, &mut out)?;
        Ok(out)
    }

    /// A root's stateless key, made on this core.
    pub fn stateless_key(root: &Root) -> Result<leansphincs::Key, Error> {
        let mut seed = stateless_key_seed(root)?;
        let key = leansphincs::Key::new(&seed, STATELESS_B);
        seed.fill(0);
        key
    }

    /// The key type of a tree of `height`, 1 to the owner's [`owner::MAX_HEIGHT`]: written into
    /// `buf`, which it borrows.
    pub fn tree_key_type(height: u32, buf: &mut [u8; 34]) -> Result<&str, Error> {
        if height == 0 || height > owner::MAX_HEIGHT {
            return Err(Error::Invalid("a tree is 1 to 40 high"));
        }
        let p = TREE_KEY_TYPE.len();
        buf[..p].copy_from_slice(TREE_KEY_TYPE.as_bytes());
        let n = if height >= 10 {
            buf[p] = b'0' + (height / 10) as u8;
            buf[p + 1] = b'0' + (height % 10) as u8;
            2
        } else {
            buf[p] = b'0' + height as u8;
            1
        };
        core::str::from_utf8(&buf[..p + n]).map_err(|_| Error::Invalid("a key type is ASCII"))
    }

    /// A tree's context: its place's digest.
    pub fn tree_context(at: &TreePlace) -> [u8; 32] {
        owner::tree_place_digest(at.chain, &at.owner, &at.safe, at.device, at.generation, at.start)
    }

    /// The secret seed (wots::Prf's skSeed) of the tree of `height` at `at` with its `salt`, from
    /// the root of the device that holds it.
    pub fn tree_secret_seed(root: &Root, at: &TreePlace, height: u32, salt: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut kt = [0u8; 34];
        let key_type = tree_key_type(height, &mut kt)?;
        let mut out = [0u8; 32];
        hbkd::stateful_seed_into(root, key_type, &tree_context(at), salt, ACCOUNT, &mut out)?;
        Ok(out)
    }

    /// The gas account's private key of a phrase root. Refused if it is zero or not below n, which
    /// no root is known to give (the chance is about 2^-128).
    pub fn gas_key(root: &Root) -> Result<[u8; 32], Error> {
        let mut key = [0u8; 32];
        hbkd::app_secret_into(root, GAS_LABEL, ACCOUNT, &mut key)?;
        check_secp256k1_key(&key)?;
        Ok(key)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::hex::{decode, h32};
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        #[test]
        fn zero_seed_is_the_ercs_first_phrase() {
            // "abandon" 23 times and "art": the ERC's first test phrase, so its stateless seed
            let root = phrase_root(&[0; 32]).unwrap();
            assert_eq!(root[..], decode("31a48aa502c800ed2e98d6ea19e8121861876ac755601b53f3772c4c910cc292e8f1650268f6df3f7b7f030536b6b4e55a13b0d673b24e7e6a8fdecb9c5854ed").unwrap()[..]);
            assert_eq!(stateless_key_seed(&root).unwrap(), h32("fe1de5038bcc56fc434f8cba07eb53ab972de18ec0779c7465fd0d789a966879"));
        }

        #[test]
        fn tree_key_types() {
            let mut b = [0u8; 34];
            assert_eq!(tree_key_type(1, &mut b).unwrap(), "winterlock-wots-d6-keccak/tree-h1");
            assert_eq!(tree_key_type(9, &mut b).unwrap(), "winterlock-wots-d6-keccak/tree-h9");
            assert_eq!(tree_key_type(10, &mut b).unwrap(), "winterlock-wots-d6-keccak/tree-h10");
            assert_eq!(tree_key_type(40, &mut b).unwrap(), "winterlock-wots-d6-keccak/tree-h40");
            assert!(tree_key_type(0, &mut b).is_err());
            assert!(tree_key_type(41, &mut b).is_err());
            for h in 1..=40 {
                assert!(hbkd::is_key_type(tree_key_type(h, &mut b).unwrap()));
            }
        }

        #[test]
        fn tree_seed_is_the_contexts_head() {
            let at = TreePlace { chain: 5, owner: [1; 20], safe: [2; 20], device: 3, generation: 4, start: 6 };
            assert_eq!(super::super::tree_public_seed(&at)[..], tree_context(&at)[..16]);
        }

        #[test]
        fn differs_from_the_earlier_derivation() {
            let s = [7u8; 32];
            let r = phrase_root(&s).unwrap();
            assert_ne!(stateless_key_seed(&r).unwrap(), super::super::member_key_seed(&s));
            assert_ne!(gas_key(&r).unwrap(), super::super::gas_key(&s).unwrap());
            assert_ne!(phrase_root(&s).unwrap(), device_root(&s));
        }
    }
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
