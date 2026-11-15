//! The ERC-8499 vectors the board checks: core/tests/vectors/erc8499.json, written by
//! signer/tools/core_vectors.py from the Python reference (erc8499.py) and made into Rust data by
//! build.rs at build time.

use winterlock_core::derive::TreePlace;

/// One phrase seed's values, and the same 32 bytes as a device's random input.
pub struct Keys {
    /// The phrase's BIP-39 entropy (all zero: the ERC's first test phrase).
    pub seed: [u8; 32],
    pub phrase_root: [u8; 64],
    pub member_key_seed: [u8; 32],
    pub member_key: [u8; 32],
    pub owner: [u8; 20],
    pub gas_key: [u8; 32],
    pub device_root: [u8; 64],
    pub device_key_seed: [u8; 32],
}

/// A tree's secret seed from a device's random root.
pub struct TreeSecret {
    pub place: TreePlace,
    pub height: u32,
    pub device_random: [u8; 32],
    pub root: [u8; 64],
    pub key_type: &'static str,
    pub context: [u8; 32],
    pub salt: [u8; 32],
    pub sk_seed: [u8; 32],
}

/// A whole tree of height 4, from a device's random input down to its root.
pub struct SmallTree {
    pub place: TreePlace,
    pub height: u32,
    pub device_random: [u8; 32],
    pub salt: [u8; 32],
    pub sk_seed: [u8; 32],
    pub tree_root: [u8; 24],
}

include!(concat!(env!("OUT_DIR"), "/erc8499.rs"));
