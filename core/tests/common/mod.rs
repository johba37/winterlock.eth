//! Shared by the test files: the vectors (compiled in, so the WebAssembly tests need no file
//! system) and small decoders.
#![allow(dead_code)]

use serde_json::Value;
use winterlock_core::safe::{Operation, SafeTx};
use winterlock_core::{U256, hex};

pub const PHRASE: &str = include_str!("../vectors/phrase.json");
pub const KEYS: &str = include_str!("../vectors/keys.json");
pub const LEANSPHINCS: &str = include_str!("../vectors/leansphincs.json");
pub const WOTS: &str = include_str!("../vectors/wots.json");
pub const SAFE: &str = include_str!("../vectors/safe.json");
pub const OWNER: &str = include_str!("../vectors/owner.json");
pub const KEYLOG: &str = include_str!("../vectors/keylog.json");
pub const BOARD: &str = include_str!("../vectors/board.json");
/// ERC-8499, hash-based key derivation from BIP-39 (the hbkd feature).
pub const HBKD: &str = include_str!("../vectors/hbkd.json");
/// Winterlock's keys under ERC-8499 (the signer app's derivation since 2026-11-14).
pub const ERC8499: &str = include_str!("../vectors/erc8499.json");
/// The upstream leanSphincs-keccak known answers (SPHINCs-), which the Python signer reproduces.
pub const KAT: &str = include_str!("../../../contracts/test/fixtures/leansphincs-keccak-kat.json");
/// The pinned v2 creation code, as the Python signer reads it.
pub const CONTRACTS: &str = include_str!("../../../signer/winterlock_signer/contracts.json");

pub fn load(s: &str) -> Value {
    serde_json::from_str(s).expect("vector JSON")
}

pub fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("a hex string")).expect("hex")
}

pub fn arr<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().expect("length")
}

/// A checksummed address, through the core's own parser (which checks the checksum).
pub fn address(v: &Value) -> [u8; 20] {
    let s = v.as_str().expect("an address");
    let a = hex::parse_address(s).expect("an address with a good checksum");
    assert_eq!(hex::checksum(&a), s, "EIP-55 spelling");
    a
}

pub fn uint(v: &Value) -> u64 {
    v.as_u64().expect("an integer")
}

pub fn u256(v: &Value) -> U256 {
    U256::from_dec_str(v.as_str().expect("a decimal string")).expect("decimal")
}

pub fn str_(v: &Value) -> &str {
    v.as_str().expect("a string")
}

pub fn safe_tx(v: &Value) -> SafeTx {
    SafeTx {
        to: address(&v["to"]),
        value: u256(&v["value"]),
        data: bytes(&v["data"]),
        operation: Operation::from_u8(uint(&v["operation"]) as u8).unwrap(),
        safe_tx_gas: u256(&v["safe_tx_gas"]),
        base_gas: u256(&v["base_gas"]),
        gas_price: u256(&v["gas_price"]),
        gas_token: address(&v["gas_token"]),
        refund_receiver: address(&v["refund_receiver"]),
        nonce: u256(&v["nonce"]),
    }
}

/// Every position in a buffer of length `n` worth flipping: the ends and a spread between.
pub fn positions(n: usize) -> Vec<usize> {
    let mut p: Vec<usize> = (0..n).step_by((n / 23).max(1)).collect();
    p.push(n - 1);
    p
}
