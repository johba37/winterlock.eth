//! Every key the board derives from its seed comes from here, and only here, so the derivation
//! can change in one place (docs/notes/signer-app.md, "Security": "the derivation sits in one
//! place"). Today it is the core's `derive` module, as the Python signer and the app use it:
//!
//! ```text
//!   seed             keccak256(abi.encode("winterlock.board.seed.v1", board random, app random))
//!                    at setup; or the 24 words' entropy at a recovery
//!   phrase           the seed's 24 BIP-39 words (core::phrase)
//!   member key       leanSphincs-keccak, b = 10, from ("winterlock.signer.stateless.v1", seed)
//!   tree secret seed ("winterlock.signer.ops.v2", seed, chain, owner, Safe, device, generation,
//!                    start, salt)
//!   gas key          ("winterlock.app.gas.v1", seed)
//! ```
//!
//! The PIN's check value is here too, since it is the only other hash of a secret the board keeps.

use winterlock_core::abi::label_hash;
use winterlock_core::derive::{self, TreePlace};
use winterlock_core::{Error, leansphincs, phrase};

pub const SEED_LABEL: &[u8] = b"winterlock.board.seed.v1";
pub const PIN_LABEL: &[u8] = b"winterlock.board.pin.v1";
/// The member key's kept-subtree height.
pub const MEMBER_B: u32 = derive::STATELESS_B;

/// The seed of a new board: the board's randomness hashed with the app's, so neither side alone
/// sets it.
pub fn mix_seed(board: &[u8; 32], app: &[u8; 32]) -> [u8; 32] {
    label_hash(SEED_LABEL, &[*board, *app])
}

/// The seed's 24 words, as indices into the BIP-39 English list.
pub fn phrase_indices(seed: &[u8; 32]) -> [u16; phrase::WORDS] {
    let words = phrase::to_phrase(seed);
    core::array::from_fn(|i| phrase::index_of(words[i]).expect("a word of the list"))
}

/// The seed 24 words encode, if their checksum matches.
pub fn seed_of_indices(ix: &[u16; phrase::WORDS]) -> Result<[u8; 32], phrase::PhraseError> {
    let list = phrase::wordlist();
    let words: [&str; phrase::WORDS] = core::array::from_fn(|i| list[ix[i] as usize]);
    phrase::from_words(&words)
}

/// What the member key's leaves are made from: the leanSphincs plan of the seed.
pub fn member_plan(seed: &[u8; 32]) -> (leansphincs::Plan, [u8; 32]) {
    let ks = derive::member_key_seed(seed);
    (leansphincs::plan(&ks, MEMBER_B).expect("b = 10"), ks)
}

/// The member key from its kept leaves (made at setup, or read from flash).
pub fn member_key(seed: &[u8; 32], leaves: alloc::vec::Vec<leansphincs::Node>) -> Result<leansphincs::Key, Error> {
    leansphincs::Key::from_leaves(&derive::member_key_seed(seed), MEMBER_B, leaves)
}

/// A key tree's secret seed.
pub fn tree_secret(seed: &[u8; 32], at: &TreePlace, salt: &[u8; 32]) -> [u8; 32] {
    derive::tree_secret_seed(seed, at, salt)
}

/// The gas account's private key.
pub fn gas_key(seed: &[u8; 32]) -> Result<[u8; 32], Error> {
    derive::gas_key(seed)
}

/// The PIN's check value: keccak256(abi.encode("winterlock.board.pin.v1", salt, pin)), the PIN
/// as a word of its digit count and its digits (1 to 8 of them, each 0 to 9).
pub fn pin_check(salt: &[u8; 32], digits: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[0] = digits.len() as u8;
    w[1..1 + digits.len()].copy_from_slice(digits);
    label_hash(PIN_LABEL, &[*salt, w])
}
