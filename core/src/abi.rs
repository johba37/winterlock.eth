//! The bits of ABI encoding the formats use: 32-byte words, the labelled PRF
//! `keccak256(abi.encode(string label, words...))`, and CREATE2.

use crate::keccak::{Keccak256, keccak256_parts};

/// A uint as a 32-byte big-endian word.
pub fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// An address, left-padded to 32 bytes.
pub fn word_address(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// keccak256(abi.encode(string label, bytes32 / uint256 / address words...)): the string's offset
/// word, the words, then the string's length and bytes padded to 32. Streams; no allocation.
pub fn label_hash(label: &[u8], words: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(&word_u64(32 * (words.len() as u64 + 1)));
    for w in words {
        h.update(w);
    }
    h.update(&word_u64(label.len() as u64));
    h.update(label);
    h.zeros((32 - label.len() % 32) % 32);
    h.finalize()
}

/// The address CREATE2 gives: keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(init code))[12..].
pub fn create2(deployer: &[u8; 20], salt: &[u8; 32], init_code_hash: &[u8; 32]) -> [u8; 20] {
    let h = keccak256_parts(&[&[0xff], deployer, salt, init_code_hash]);
    h[12..].try_into().unwrap()
}
