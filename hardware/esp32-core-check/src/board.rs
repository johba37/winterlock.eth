//! The Python vectors the board checks: core/tests/vectors/board.json, made into Rust data by
//! build.rs at build time (signer/tools/core_vectors.py writes the file).

use winterlock_core::U256;
use winterlock_core::derive::TreePlace;
use winterlock_core::safe::{Operation, SafeTx};

pub struct Stateless {
    pub message: [u8; 32],
    pub sig: &'static [u8],
    /// Randomizer tries the grind needed, in Python.
    pub grind_tries: u64,
}

pub struct Tx {
    pub to: [u8; 20],
    pub value: [u8; 32],
    pub data: &'static [u8],
    pub operation: u8,
    pub safe_tx_gas: [u8; 32],
    pub base_gas: [u8; 32],
    pub gas_price: [u8; 32],
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
    pub nonce: [u8; 32],
}

impl Tx {
    pub fn safe_tx(&self) -> SafeTx {
        SafeTx {
            to: self.to,
            value: U256(self.value),
            data: self.data.to_vec(),
            operation: Operation::from_u8(self.operation).unwrap(),
            safe_tx_gas: U256(self.safe_tx_gas),
            base_gas: U256(self.base_gas),
            gas_price: U256(self.gas_price),
            gas_token: self.gas_token,
            refund_receiver: self.refund_receiver,
            nonce: U256(self.nonce),
        }
    }
}

pub struct WotsSig {
    pub nonce: u64,
    pub slot: u8,
    pub key_index: u64,
    pub tx: Tx,
    pub hash: [u8; 32],
    pub sig: &'static [u8],
    pub path: &'static [u8],
    /// The owner signature data: [slot][device][safe][SafeTx][WOTS signature][path].
    pub data: &'static [u8],
}

pub struct Tree {
    pub chain: u64,
    pub owner: [u8; 20],
    pub safe: [u8; 20],
    pub device: u8,
    pub generation: u16,
    pub start: u64,
    pub salt: [u8; 32],
    pub tree_seed: [u8; 16],
    pub sk_seed: [u8; 32],
    pub root: [u8; 24],
    pub sigs: &'static [WotsSig],
}

impl Tree {
    pub fn place(&self) -> TreePlace {
        TreePlace {
            chain: self.chain,
            owner: self.owner,
            safe: self.safe,
            device: self.device,
            generation: self.generation,
            start: self.start,
        }
    }
}

pub struct SafeTxCase {
    pub tx: Tx,
    pub chain: u64,
    pub safe: [u8; 20],
    pub hash: [u8; 32],
}

pub struct DeviceDigest {
    pub chain: u64,
    pub owner: [u8; 20],
    pub device: u8,
    pub generation: u16,
    pub key: [u8; 32],
    pub digest: [u8; 32],
}

pub struct CheckCode {
    pub owner: [u8; 20],
    pub device: u8,
    pub key: [u8; 32],
    pub code: &'static str,
}

pub struct KeylogTree {
    pub chain: u64,
    pub safe: [u8; 20],
    pub root: [u8; 24],
    pub start: u64,
    pub height: u32,
}

pub enum Expect {
    Signed { slot: u8, already: bool, appended: bool },
    Refused(&'static str),
}

pub struct KeylogStep {
    /// pick the slot and record (else: record at `slot`)
    pub sign: bool,
    pub tree: usize,
    pub nonce: u64,
    pub slot: u8,
    pub hash: [u8; 32],
    pub expect: Expect,
}

pub struct KeyUseV {
    pub chain: u64,
    pub safe: [u8; 20],
    pub root: [u8; 24],
    pub start: u64,
    pub nonce: u64,
    pub slot: u8,
    pub key_index: u64,
    pub hash: [u8; 32],
}

include!(concat!(env!("OUT_DIR"), "/board.rs"));
