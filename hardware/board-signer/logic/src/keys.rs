//! Every key the board derives from its seed comes from here, and only here, so the derivation
//! can change in one place (docs/notes/signer-app.md, "Security": "the derivation sits in one
//! place"). Since 2026-11-14 it is ERC-8499, through the core's `derive::erc8499`, as the app
//! derives its keys (decisions.md, D15):
//!
//! ```text
//!   seed             keccak256(abi.encode("winterlock.board.seed.v1", board random, app random))
//!                    at setup; or the 24 words' entropy at a recovery
//!   phrase           the seed's 24 BIP-39 words (core::phrase)
//!   root             HKDF-Extract("HBKD/v1", BIP-39 seed of the 24 words, no passphrase): made
//!                    at setup, recovery and unlock (PBKDF2, 2,048 rounds), kept for the session
//!   member key       leanSphincs-keccak, b = 10: the root's stateless key of type
//!                    leanSphincs-keccak/wambsgans-keccak/b10, account 0
//!   tree secret seed the root's stateful key of type winterlock-wots-d6-keccak/tree-h<height>;
//!                    context: the tree's place (chain, owner, Safe, device 0, generation, start),
//!                    instance: the tree's random salt
//!   gas key          the root's application secret "winterlock.eth/gas"
//! ```
//!
//! The board is the member's only device, device 0, so its trees come from the phrase's root.
//!
//! The PIN's check value is here too, since it is the only other hash of a secret the board keeps.

use winterlock_core::abi::label_hash;
use winterlock_core::derive::{self, TreePlace, erc8499};
use winterlock_core::{Error, leansphincs, phrase};

/// A root: 64 bytes.
pub type Root = erc8499::Root;

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

/// The seed's root: PBKDF2 over its 24 words, then HKDF-Extract.
pub fn root(seed: &[u8; 32]) -> Result<Root, Error> {
    erc8499::phrase_root(seed)
}

/// What the member key's leaves are made from: the leanSphincs plan of the root's stateless key.
pub fn member_plan(root: &Root) -> (leansphincs::Plan, [u8; 32]) {
    let ks = erc8499::stateless_key_seed(root).expect("the key type and its length are constants");
    (leansphincs::plan(&ks, MEMBER_B).expect("b = 10"), ks)
}

/// The member key from its kept leaves (made at setup, or read from flash).
pub fn member_key(root: &Root, leaves: alloc::vec::Vec<leansphincs::Node>) -> Result<leansphincs::Key, Error> {
    let mut ks = erc8499::stateless_key_seed(root)?;
    let key = leansphincs::Key::from_leaves(&ks, MEMBER_B, leaves);
    ks.fill(0);
    key
}

/// A key tree's secret seed.
pub fn tree_secret(root: &Root, at: &TreePlace, height: u8, salt: &[u8; 32]) -> Result<[u8; 32], Error> {
    erc8499::tree_secret_seed(root, at, height as u32, salt)
}

/// The gas account's private key.
pub fn gas_key(root: &Root) -> Result<[u8; 32], Error> {
    erc8499::gas_key(root)
}

/// The PIN's check value: keccak256(abi.encode("winterlock.board.pin.v1", salt, pin)), the PIN
/// as a word of its digit count and its digits (1 to 8 of them, each 0 to 9).
pub fn pin_check(salt: &[u8; 32], digits: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[0] = digits.len() as u8;
    w[1..1 + digits.len()].copy_from_slice(digits);
    label_hash(PIN_LABEL, &[*salt, w])
}
