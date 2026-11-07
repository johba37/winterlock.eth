//! The key log's rules for one-time keys (keylog.py: `pick_slot`, `record_sign`), over storage
//! that the platform implements.
//!
//! The rules: a one-time key signs one hash only (the same hash again is allowed: signatures are
//! deterministic). The slot is picked here, never by the user: slot 0 first, slot 1 for a
//! second, different SafeTx at the same nonce (D4), and nothing after that.
//!
//! The contract between core and platform: [`KeyLogStore::append_use`] returns only once the use
//! is durable (written and flushed: fsync, a committed IndexedDB transaction, a flash write read
//! back). A WOTS signature is only made from the [`Recorded`] that [`record_sign`] returns after
//! that append, so the record always exists before the signature does. A crash can lose a
//! signature, never the record of one.

use alloc::vec::Vec;
use core::fmt;

use crate::owner::{SLOTS, key_index};
use crate::wots::Value;
use crate::{Error, hex};

/// A one-time key tree as the key log knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeRef {
    pub chain: u64,
    pub safe: [u8; 20],
    pub root: Value,
    pub start: u64,
    pub height: u32,
}

/// One use of a one-time key: the key log's "sign" record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUse {
    pub chain: u64,
    pub safe: [u8; 20],
    pub root: Value,
    pub start: u64,
    pub nonce: u64,
    pub slot: u8,
    pub key_index: u64,
    /// The SafeTx hash (or other 32-byte message) it signs.
    pub hash: [u8; 32],
}

/// The storage a platform gives the key log.
pub trait KeyLogStore {
    type Error;
    /// The hash that one-time key `key_index` of the tree (chain, Safe, root) signed, if the log
    /// records a use of it.
    fn find_use(&self, chain: u64, safe: &[u8; 20], root: &Value, key_index: u64) -> Result<Option<[u8; 32]>, Self::Error>;
    /// Appends a use. Returns Ok only once it is durable.
    fn append_use(&mut self, key_use: &KeyUse) -> Result<(), Self::Error>;
}

/// Proof that a key use is in the log: only [`record_sign`] makes one, and signing a one-time
/// key needs one ([`crate::wots::sign_recorded`], [`crate::owner::sign_transaction`]).
#[derive(Debug)]
pub struct Recorded {
    key_use: KeyUse,
    /// The log already held this use (the same hash signed again); nothing was appended.
    pub already: bool,
}

impl Recorded {
    pub fn key_use(&self) -> &KeyUse {
        &self.key_use
    }
}

/// Why the key log won't let a key sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused<E> {
    /// Both keys of the nonce signed other hashes: no third version at a nonce.
    ThirdVersion { nonce: u64, first: [u8; 32], second: [u8; 32] },
    /// This key already signed another hash.
    KeyReused { key_index: u64, nonce: u64, slot: u8, signed: [u8; 32], asked: [u8; 32] },
    /// Not a key of the tree: a nonce outside it, or a bad slot.
    NotInTree(Error),
    /// The storage failed: nothing may be signed.
    Store(E),
}

impl<E: fmt::Debug> fmt::Display for Refused<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::ThirdVersion { nonce, first, second } => write!(
                f,
                "both keys for nonce {nonce} are used (your first signed {}, your second {}): you can't sign a third version at nonce {nonce}",
                hex::encode0x(first),
                hex::encode0x(second)
            ),
            Refused::KeyReused { key_index, nonce, slot, signed, asked } => write!(
                f,
                "one-time key {key_index} (nonce {nonce}, slot {slot}) already signed {}; signing {} with it would reuse it",
                hex::encode0x(signed),
                hex::encode0x(asked)
            ),
            Refused::NotInTree(e) => write!(f, "{e}"),
            Refused::Store(e) => write!(f, "the key log's storage failed: {e:?}"),
        }
    }
}

/// The slot to sign `hash` at `nonce` with, and whether that key already signed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pick {
    pub slot: u8,
    pub already: bool,
}

/// Which slot signs `hash` at `nonce` (keylog.py's pick_slot): the slot that already signed this
/// hash, else the first unused one; refused when both signed other hashes.
pub fn pick_slot<S: KeyLogStore>(store: &S, tree: &TreeRef, nonce: u64, hash: &[u8; 32]) -> Result<Pick, Refused<S::Error>> {
    let mut used: [Option<[u8; 32]>; SLOTS] = [None; SLOTS];
    for slot in 0..SLOTS as u8 {
        let k = key_index(nonce, tree.start, slot, tree.height).map_err(Refused::NotInTree)?;
        if let Some(h) = store.find_use(tree.chain, &tree.safe, &tree.root, k).map_err(Refused::Store)? {
            if h == *hash {
                return Ok(Pick { slot, already: true });
            }
            used[slot as usize] = Some(h);
        }
    }
    for slot in 0..SLOTS as u8 {
        if used[slot as usize].is_none() {
            return Ok(Pick { slot, already: false });
        }
    }
    Err(Refused::ThirdVersion { nonce, first: used[0].unwrap(), second: used[1].unwrap() })
}

/// Checks the key and records its use, durably, before anything signs with it (keylog.py's
/// record_sign). The same hash again returns the existing record without appending.
pub fn record_sign<S: KeyLogStore>(store: &mut S, tree: &TreeRef, nonce: u64, slot: u8, hash: &[u8; 32]) -> Result<Recorded, Refused<S::Error>> {
    let k = key_index(nonce, tree.start, slot, tree.height).map_err(Refused::NotInTree)?;
    let key_use = KeyUse {
        chain: tree.chain,
        safe: tree.safe,
        root: tree.root,
        start: tree.start,
        nonce,
        slot,
        key_index: k,
        hash: *hash,
    };
    if let Some(prior) = store.find_use(tree.chain, &tree.safe, &tree.root, k).map_err(Refused::Store)? {
        if prior != *hash {
            return Err(Refused::KeyReused { key_index: k, nonce, slot, signed: prior, asked: *hash });
        }
        return Ok(Recorded { key_use, already: true });
    }
    store.append_use(&key_use).map_err(Refused::Store)?;
    Ok(Recorded { key_use, already: false })
}

/// Picks the slot and records the use: what the Python signer does before every one-time
/// signature.
pub fn record<S: KeyLogStore>(store: &mut S, tree: &TreeRef, nonce: u64, hash: &[u8; 32]) -> Result<Recorded, Refused<S::Error>> {
    let pick = pick_slot(store, tree, nonce, hash)?;
    record_sign(store, tree, nonce, pick.slot, hash)
}

/// A key log in memory: a model of the storage contract, and enough for tests. It isn't durable,
/// so a real signer needs its own.
#[derive(Clone, Debug, Default)]
pub struct MemoryLog {
    pub uses: Vec<KeyUse>,
}

impl KeyLogStore for MemoryLog {
    type Error = core::convert::Infallible;

    fn find_use(&self, chain: u64, safe: &[u8; 20], root: &Value, key_index: u64) -> Result<Option<[u8; 32]>, Self::Error> {
        Ok(self
            .uses
            .iter()
            .find(|u| u.chain == chain && u.safe == *safe && u.root == *root && u.key_index == key_index)
            .map(|u| u.hash))
    }

    fn append_use(&mut self, key_use: &KeyUse) -> Result<(), Self::Error> {
        self.uses.push(*key_use);
        Ok(())
    }
}
