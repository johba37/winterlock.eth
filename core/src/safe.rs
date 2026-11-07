//! Safe's hashes (safe.py, messages.py), from fields: the SafeTx EIP-712 hash, the SafeMessage
//! hash, and EIP-191's personal-message hash. Safe v1.3.0 and later (a domain of chain id and
//! Safe). A board shows what it signs, so it never takes a hash on trust: it computes it here.

use alloc::vec::Vec;

use crate::U256;
use crate::abi::{word_address, word_u64};
use crate::hex::h32;
use crate::keccak::{Keccak256, keccak256, keccak256_parts};

/// keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
pub const DOMAIN_TYPEHASH: [u8; 32] = h32("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218");
/// keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
pub const SAFE_TX_TYPEHASH: [u8; 32] = h32("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8");
/// keccak256("SafeMessage(bytes message)")
pub const SAFE_MSG_TYPEHASH: [u8; 32] = h32("60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca");

/// Call or delegatecall.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Operation {
    #[default]
    Call = 0,
    DelegateCall = 1,
}

impl Operation {
    pub fn from_u8(v: u8) -> Option<Operation> {
        match v {
            0 => Some(Operation::Call),
            1 => Some(Operation::DelegateCall),
            _ => None,
        }
    }
}

/// A Safe transaction's fields.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SafeTx {
    pub to: [u8; 20],
    pub value: U256,
    pub data: Vec<u8>,
    pub operation: Operation,
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
    pub nonce: U256,
}

/// The ten SafeTx words after the type hash: 320 bytes, as WinterlockOwner's transaction signature
/// carries them (data as its keccak256).
pub type SafeTxWords = [[u8; 32]; 10];

impl SafeTx {
    pub fn words(&self) -> SafeTxWords {
        [
            word_address(&self.to),
            self.value.0,
            keccak256(&self.data),
            word_u64(self.operation as u64),
            self.safe_tx_gas.0,
            self.base_gas.0,
            self.gas_price.0,
            word_address(&self.gas_token),
            word_address(&self.refund_receiver),
            self.nonce.0,
        ]
    }

    /// The 320 bytes of [`SafeTx::words`].
    pub fn encode(&self) -> [u8; 320] {
        let mut out = [0u8; 320];
        for (o, w) in out.chunks_exact_mut(32).zip(self.words().iter()) {
            o.copy_from_slice(w);
        }
        out
    }

    pub fn struct_hash(&self) -> [u8; 32] {
        struct_hash_of_words(&self.words())
    }

    /// The SafeTx hash that owners sign: EIP-712 under the Safe's domain on `chain_id`.
    pub fn hash(&self, chain_id: u64, safe: &[u8; 20]) -> [u8; 32] {
        eip712(chain_id, safe, &self.struct_hash())
    }

    /// The 66 bytes Safe v1.4.1 passes to a contract owner's legacy isValidSignature(bytes, bytes).
    pub fn preimage(&self, chain_id: u64, safe: &[u8; 20]) -> [u8; 66] {
        let mut p = [0u8; 66];
        p[..2].copy_from_slice(&[0x19, 0x01]);
        p[2..34].copy_from_slice(&domain_separator(chain_id, safe));
        p[34..].copy_from_slice(&self.struct_hash());
        p
    }
}

/// The SafeTx struct hash from its ten words (as WinterlockOwner computes it from a signature).
pub fn struct_hash_of_words(words: &SafeTxWords) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(&SAFE_TX_TYPEHASH);
    for w in words {
        h.update(w);
    }
    h.finalize()
}

/// The SafeTx hash from its ten words.
pub fn hash_of_words(chain_id: u64, safe: &[u8; 20], words: &SafeTxWords) -> [u8; 32] {
    eip712(chain_id, safe, &struct_hash_of_words(words))
}

pub fn domain_separator(chain_id: u64, safe: &[u8; 20]) -> [u8; 32] {
    keccak256_parts(&[&DOMAIN_TYPEHASH, &word_u64(chain_id), &word_address(safe)])
}

/// keccak256(0x1901 ‖ the Safe's domain separator ‖ struct hash)
pub fn eip712(chain_id: u64, safe: &[u8; 20], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak256_parts(&[&[0x19, 0x01], &domain_separator(chain_id, safe), struct_hash])
}

/// The hash of a SafeMessage's message: keccak256(message). For an app's isValidSignature(bytes32
/// h, sig), the message is abi.encode(h), which is h itself.
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    keccak256(message)
}

/// The SafeMessage hash (Safe's CompatibilityFallbackHandler, v1.3.0 to v1.5.0):
/// keccak256(0x1901 ‖ domain ‖ keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)))).
pub fn safe_message_hash(chain_id: u64, safe: &[u8; 20], message: &[u8]) -> [u8; 32] {
    let s = keccak256_parts(&[&SAFE_MSG_TYPEHASH, &message_hash(message)]);
    eip712(chain_id, safe, &s)
}

/// EIP-191 version 0x45: what personal_sign signs and an app checks.
pub fn personal_hash(message: &[u8]) -> [u8; 32] {
    let mut len = [0u8; 20];
    let mut n = message.len();
    let mut i = len.len();
    loop {
        i -= 1;
        len[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    keccak256_parts(&[b"\x19Ethereum Signed Message:\n", &len[i..], message])
}
