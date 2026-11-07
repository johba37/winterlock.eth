//! WinterlockOwner v2 (owner.py): a member's EIP-1271 Safe owner. Its digests, signature layouts
//! and deterministic addresses.
//!
//! Devices: device 0 is the member key (fixed in the member's proxy, always active at generation
//! 0); devices 1-3 are device keys that the member key certifies and revokes, per chain.
//!
//! Signature data (the contract signature that Safe appends to its blob; byte 0 is the kind):
//! ```text
//!   transaction  [slot: 1][device: 1][safe: 20][SafeTx: 10 x 32][WOTS signature: 1,176][path: 24 x height]
//!   message      [0x02][device: 1][safe: 20][keccak256(message): 32][stateless signature: 5,684]
//!   approved     [0x03][safe: 20][keccak256(message): 32]   valid once the Safe approved it on-chain
//! ```
//! Key index: (nonce - start) * 2 + slot; a tree of height h covers 2^(h-1) nonces from start.
//!
//! Digests (keccak256 of abi.encode(DOMAIN, chainid, owner, ...); owner: the member's proxy):
//! ```text
//!   device certificate  (device, generation, key)                            signed by the member key
//!   revocation          (device, generation)                                 signed by the member key
//!   tree certificate    (safe, device, generation, root, height, start)      signed by the device's key
//!   message             (safe, device, generation, SafeMessage hash)         signed by the device's key
//!   tree seed           first 16 bytes of (safe, device, generation, start)  derived, not signed
//! ```

use alloc::vec::Vec;

use crate::abi::{create2, word_address, word_u64};
use crate::hex::{h20, h32};
use crate::keccak::{Keccak256, keccak256, keccak256_parts};
use crate::keylog::Recorded;
use crate::safe::{SafeTx, SafeTxWords};
use crate::{Error, U256, leansphincs, wots};

pub const SLOTS: usize = 2;
pub const MAX_HEIGHT: u32 = 40;
pub const MAX_START: u64 = (1 << 40) - 1;
pub const MAX_DEVICE: u8 = 3;
pub const MAX_GENERATION: u16 = u16::MAX;
pub const STATELESS_SIG_LEN: usize = leansphincs::SIG_BYTES;
pub const KIND_MESSAGE: u8 = 0x02;
pub const KIND_APPROVED: u8 = 0x03;
/// kind or slot, device, safe
pub const PREFIX: usize = 1 + 1 + 20;
pub const TX_HEADER: usize = PREFIX + 320;
pub const MESSAGE_LEN: usize = PREFIX + 32 + STATELESS_SIG_LEN;
pub const APPROVED_LEN: usize = 1 + 20 + 32;
pub const VERSION: u32 = 2;

/// keccak256("Winterlock.safe-owner.device.v2")
pub const DEVICE_DOMAIN: [u8; 32] = h32("0e96099429f6e109b94d2a8267e400ed61ac52465c1c96499f666f82d28668db");
/// keccak256("Winterlock.safe-owner.revocation.v2")
pub const REVOCATION_DOMAIN: [u8; 32] = h32("cefe2cb0875f6f92c5a7be78735b6fbe9144663d98612043e6676954a17ea2c9");
/// keccak256("Winterlock.safe-owner.certificate.v2")
pub const CERTIFICATE_DOMAIN: [u8; 32] = h32("d3f4d8c742af78d21f389e68a4faad839f8b289df4cf467ee39fb59a71c05d6d");
/// keccak256("Winterlock.safe-owner.message.v2")
pub const MESSAGE_DOMAIN: [u8; 32] = h32("971edb1c8cd8603cd9bc672444c9dbb015ed18f81773b03a06bd07ca7461f53c");
/// keccak256("Winterlock.safe-owner.tree-seed.v2")
pub const TREE_SEED_DOMAIN: [u8; 32] = h32("3bd3f583e8b28b1950b16718f61a2f49c8a16e6c6de5c0921a47afbf5062bae1");
/// EIP-1271's isValidSignature(bytes32, bytes) magic value.
pub const MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
pub const LEGACY_MAGIC: [u8; 4] = [0x20, 0xc1, 0x3b, 0x0b];

/// The deterministic deployment proxy.
pub const PROXY: [u8; 20] = h20("4e59b44847b379578588920cA78FbF26c0B4956C");
/// keccak256("Winterlock.stateless-verifier.v1")
pub const VERIFIER_SALT: [u8; 32] = h32("a2c1735f16a28c1c20e15e4b0b4d7af36be29ca3dae1d25433f1b08295a75857");
/// keccak256("Winterlock.wots-verifier.v1")
pub const WOTS_VERIFIER_SALT: [u8; 32] = h32("608d22009e8088b8ea17fe0f3d6a46dcb2da2961d2842893843c2ee584c46de4");
/// keccak256("Winterlock.safe-owner.implementation.v2")
pub const IMPLEMENTATION_SALT: [u8; 32] = h32("16abaed744bd46d37bb7c65fc01ae8191e56f613734133d129655fe5a0009fd6");
/// keccak256("Winterlock.safe-owner.factory.v2")
pub const FACTORY_SALT: [u8; 32] = h32("f392e4cd8c532e6a7d02f4dc5828fb4c0d774e50c4eb01b432ae4e5a9e905754");

/// The pinned v2 contracts (signer/winterlock_signer/contracts.json, commit 1add437), the same on
/// every chain. The tests derive them from the pinned creation code.
pub const VERIFIER: [u8; 20] = h20("6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254");
pub const WOTS_VERIFIER: [u8; 20] = h20("272138c7D3b508bd510bE5166fbE2461561e410D");
pub const IMPLEMENTATION: [u8; 20] = h20("114caAB223BaccD9BcA92C28ABBCf1edC0C3bCdf");
pub const FACTORY: [u8; 20] = h20("90835a46Fb205B7f038B0EE46e798ead45a6fA7F");

pub const OWNER_CODE_BYTES: usize = 77;
pub const KEY_OFFSET: usize = 0x2D;

const CLONE_HEAD: [u8; 10] = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
const CLONE_TAIL: [u8; 15] = [0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3];
const INIT_HEAD: [u8; 7] = [0x3d, 0x81, 0x60, 0x0a, 0x3d, 0x39, 0xf3];

// --- addresses ---

/// The stateless verifier's address from LeanSphincsAsm's creation code.
pub fn verifier_address(creation: &[u8]) -> [u8; 20] {
    create2(&PROXY, &VERIFIER_SALT, &keccak256(creation))
}

/// The shared WOTS verifier's address from SharedWotsVerifier's creation code.
pub fn wots_verifier_address(creation: &[u8]) -> [u8; 20] {
    create2(&PROXY, &WOTS_VERIFIER_SALT, &keccak256(creation))
}

/// The implementation's address: creation code ‖ abi.encode(params, verifier, WOTS verifier).
pub fn implementation_address(creation: &[u8], params: u64, verifier: &[u8; 20], wots_verifier: &[u8; 20]) -> [u8; 20] {
    let mut h = Keccak256::new();
    h.update(creation).update(&word_u64(params)).update(&word_address(verifier)).update(&word_address(wots_verifier));
    create2(&PROXY, &IMPLEMENTATION_SALT, &h.finalize())
}

/// The factory's address: creation code ‖ abi.encode(implementation).
pub fn factory_address(creation: &[u8], implementation: &[u8; 20]) -> [u8; 20] {
    let mut h = Keccak256::new();
    h.update(creation).update(&word_address(implementation));
    create2(&PROXY, &FACTORY_SALT, &h.finalize())
}

/// A stateless public key (root ‖ P) as the contracts take it: both halves nonzero.
pub fn check_key(key: &[u8; 32]) -> Result<(), Error> {
    if key[..16].iter().all(|&b| b == 0) || key[16..].iter().all(|&b| b == 0) {
        return Err(Error::Invalid("a stateless key is 32 bytes with both halves nonzero"));
    }
    Ok(())
}

/// Solady LibClone.initCode(implementation, abi.encodePacked(key)): a clone with immutable args.
pub fn proxy_init_code(implementation: &[u8; 20], key: &[u8; 32]) -> Result<[u8; 87], Error> {
    check_key(key)?;
    let mut c = [0u8; 87];
    c[0] = 0x61;
    c[1..3].copy_from_slice(&(0x2Du16 + 32).to_be_bytes());
    c[3..10].copy_from_slice(&INIT_HEAD);
    c[10..20].copy_from_slice(&CLONE_HEAD);
    c[20..40].copy_from_slice(implementation);
    c[40..55].copy_from_slice(&CLONE_TAIL);
    c[55..].copy_from_slice(key);
    Ok(c)
}

/// The 77 bytes of code a member's owner has: the ERC-1167 proxy, then the key.
pub fn proxy_runtime(implementation: &[u8; 20], key: &[u8; 32]) -> [u8; OWNER_CODE_BYTES] {
    let mut c = [0u8; OWNER_CODE_BYTES];
    c[..10].copy_from_slice(&CLONE_HEAD);
    c[10..30].copy_from_slice(implementation);
    c[30..45].copy_from_slice(&CLONE_TAIL);
    c[45..].copy_from_slice(key);
    c
}

/// WinterlockOwnerFactory.predict(key) for a given implementation and factory.
pub fn owner_address_with(key: &[u8; 32], implementation: &[u8; 20], factory: &[u8; 20]) -> Result<[u8; 20], Error> {
    let init = proxy_init_code(implementation, key)?;
    Ok(create2(factory, key, &keccak256(&init)))
}

/// The member's owner address for a member key, with the pinned v2 contracts.
pub fn owner_address(key: &[u8; 32]) -> Result<[u8; 20], Error> {
    owner_address_with(key, &IMPLEMENTATION, &FACTORY)
}

/// The member key in `code` if it is the code of a v2 owner of the pinned implementation at
/// `address` (the factory's proxy for that key).
pub fn member_key_of(address: &[u8; 20], code: &[u8]) -> Option<[u8; 32]> {
    if code.len() != OWNER_CODE_BYTES {
        return None;
    }
    let key: [u8; 32] = code[KEY_OFFSET..].try_into().unwrap();
    if code != proxy_runtime(&IMPLEMENTATION, &key) || owner_address(&key).ok()? != *address {
        return None;
    }
    Some(key)
}

// --- digests ---

fn check_device(device: u8) -> Result<(), Error> {
    if device > MAX_DEVICE {
        return Err(Error::Invalid("devices are numbered 0 to 3"));
    }
    Ok(())
}

/// The seed of a device's tree for a Safe: the first 16 bytes of keccak256(abi.encode(TREE_SEED_DOMAIN,
/// chain, owner, safe, device, generation, start)).
pub fn tree_seed(chain_id: u64, owner: &[u8; 20], safe: &[u8; 20], device: u8, generation: u16, start: u64) -> wots::Seed {
    let d = keccak256_parts(&[
        &TREE_SEED_DOMAIN,
        &word_u64(chain_id),
        &word_address(owner),
        &word_address(safe),
        &word_u64(device as u64),
        &word_u64(generation as u64),
        &word_u64(start),
    ]);
    d[..16].try_into().unwrap()
}

/// A tree root (24 bytes) high-aligned in a bytes32.
pub fn root_word(root: &wots::Value) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..24].copy_from_slice(root);
    w
}

/// What the member key signs to certify `key` as device `device`'s key from `generation` on.
pub fn device_digest(chain_id: u64, owner: &[u8; 20], device: u8, generation: u16, key: &[u8; 32]) -> [u8; 32] {
    keccak256_parts(&[
        &DEVICE_DOMAIN,
        &word_u64(chain_id),
        &word_address(owner),
        &word_u64(device as u64),
        &word_u64(generation as u64),
        key,
    ])
}

/// What the member key signs to revoke device `device` at `generation`.
pub fn revocation_digest(chain_id: u64, owner: &[u8; 20], device: u8, generation: u16) -> [u8; 32] {
    keccak256_parts(&[
        &REVOCATION_DOMAIN,
        &word_u64(chain_id),
        &word_address(owner),
        &word_u64(device as u64),
        &word_u64(generation as u64),
    ])
}

/// What the device's key (the member key for device 0) signs to certify a tree.
#[allow(clippy::too_many_arguments)]
pub fn certificate_digest(chain_id: u64, owner: &[u8; 20], safe: &[u8; 20], device: u8, generation: u16, root: &wots::Value, height: u32, start: u64) -> [u8; 32] {
    keccak256_parts(&[
        &CERTIFICATE_DOMAIN,
        &word_u64(chain_id),
        &word_address(owner),
        &word_address(safe),
        &word_u64(device as u64),
        &word_u64(generation as u64),
        &root_word(root),
        &word_u64(height as u64),
        &word_u64(start),
    ])
}

/// What the device's key (the member key for device 0) signs to approve a SafeMessage.
pub fn message_digest(chain_id: u64, owner: &[u8; 20], safe: &[u8; 20], device: u8, generation: u16, safe_message_hash: &[u8; 32]) -> [u8; 32] {
    keccak256_parts(&[
        &MESSAGE_DOMAIN,
        &word_u64(chain_id),
        &word_address(owner),
        &word_address(safe),
        &word_u64(device as u64),
        &word_u64(generation as u64),
        safe_message_hash,
    ])
}

// --- key indices ---

/// Nonces a tree of `height` covers (two keys each). Like owner.py, this takes heights above
/// [`MAX_HEIGHT`], which no certificate allows (up to 64 here; Python has no limit).
pub fn capacity(height: u32) -> Result<u64, Error> {
    if height == 0 || height > 64 {
        return Err(Error::Invalid("tree height is 1 to 64"));
    }
    Ok(1 << (height - 1))
}

/// (nonce - start) * 2 + slot, for a nonce the tree covers.
pub fn key_index(nonce: u64, start: u64, slot: u8, height: u32) -> Result<u64, Error> {
    if slot as usize >= SLOTS {
        return Err(Error::Invalid("slot must be 0 or 1"));
    }
    let cap = capacity(height)?;
    if nonce < start || nonce - start >= cap {
        return Err(Error::NonceOutsideTree { nonce: U256::from_u64(nonce), start, last: start.saturating_add(cap - 1) });
    }
    Ok((nonce - start) * SLOTS as u64 + slot as u64)
}

// --- signature layouts ---

/// [slot][device][safe][SafeTx words][WOTS signature][path]
pub fn tx_signature_data(slot: u8, device: u8, safe: &[u8; 20], words: &SafeTxWords, wots_sig: &[u8], path: &[u8]) -> Result<Vec<u8>, Error> {
    check_device(device)?;
    let mut d = Vec::with_capacity(TX_HEADER + wots_sig.len() + path.len());
    d.push(slot);
    d.push(device);
    d.extend_from_slice(safe);
    for w in words {
        d.extend_from_slice(w);
    }
    d.extend_from_slice(wots_sig);
    d.extend_from_slice(path);
    Ok(d)
}

/// A transaction signature's parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxSignature<'a> {
    pub slot: u8,
    pub device: u8,
    pub safe: [u8; 20],
    pub words: SafeTxWords,
    pub wots_sig: &'a [u8],
    pub path: &'a [u8],
}

impl TxSignature<'_> {
    /// The tree height the path implies.
    pub fn height(&self) -> usize {
        self.path.len() / wots::N
    }

    /// The SafeTx nonce, from the last word.
    pub fn nonce(&self) -> U256 {
        U256(self.words[9])
    }
}

/// The parts of a transaction signature, or None if it isn't one (as owner.py's
/// parse_tx_signature_data).
pub fn parse_tx_signature_data(data: &[u8]) -> Option<TxSignature<'_>> {
    if data.len() < TX_HEADER + wots::SIG_BYTES
        || data[0] as usize >= SLOTS
        || data[1] > MAX_DEVICE
        || (data.len() - TX_HEADER - wots::SIG_BYTES) % wots::N != 0
    {
        return None;
    }
    let words = core::array::from_fn(|i| data[PREFIX + 32 * i..PREFIX + 32 + 32 * i].try_into().unwrap());
    Some(TxSignature {
        slot: data[0],
        device: data[1],
        safe: data[2..PREFIX].try_into().unwrap(),
        words,
        wots_sig: &data[TX_HEADER..TX_HEADER + wots::SIG_BYTES],
        path: &data[TX_HEADER + wots::SIG_BYTES..],
    })
}

/// [0x02][device][safe][keccak256(message)][stateless signature of message_digest]
pub fn message_signature_data(device: u8, safe: &[u8; 20], msg_hash: &[u8; 32], stateless_sig: &[u8]) -> Result<Vec<u8>, Error> {
    check_device(device)?;
    if stateless_sig.len() != STATELESS_SIG_LEN {
        return Err(Error::Invalid("a stateless signature is 5,684 bytes"));
    }
    let mut d = Vec::with_capacity(MESSAGE_LEN);
    d.push(KIND_MESSAGE);
    d.push(device);
    d.extend_from_slice(safe);
    d.extend_from_slice(msg_hash);
    d.extend_from_slice(stateless_sig);
    Ok(d)
}

/// A message signature's parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSignature<'a> {
    pub device: u8,
    pub safe: [u8; 20],
    pub msg_hash: [u8; 32],
    pub stateless_sig: &'a [u8],
}

/// The parts of a message signature, or None (the contract's length and device checks).
pub fn parse_message_signature_data(data: &[u8]) -> Option<MessageSignature<'_>> {
    if data.len() != MESSAGE_LEN || data[0] != KIND_MESSAGE || data[1] > MAX_DEVICE {
        return None;
    }
    Some(MessageSignature {
        device: data[1],
        safe: data[2..PREFIX].try_into().unwrap(),
        msg_hash: data[PREFIX..PREFIX + 32].try_into().unwrap(),
        stateless_sig: &data[PREFIX + 32..],
    })
}

/// [0x03][safe][keccak256(message)]: valid for any v2 owner of the Safe once the Safe has approved
/// the SafeMessage on-chain (SignMessageLib). No key signs it.
pub fn approved_signature_data(safe: &[u8; 20], msg_hash: &[u8; 32]) -> [u8; APPROVED_LEN] {
    let mut d = [0u8; APPROVED_LEN];
    d[0] = KIND_APPROVED;
    d[1..21].copy_from_slice(safe);
    d[21..].copy_from_slice(msg_hash);
    d
}

/// (safe, keccak256(message)) of an approved signature, or None.
pub fn parse_approved_signature_data(data: &[u8]) -> Option<([u8; 20], [u8; 32])> {
    if data.len() != APPROVED_LEN || data[0] != KIND_APPROVED {
        return None;
    }
    Some((data[1..21].try_into().unwrap(), data[21..].try_into().unwrap()))
}

/// Any of the three kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerSignature<'a> {
    Transaction(TxSignature<'a>),
    Message(MessageSignature<'a>),
    Approved { safe: [u8; 20], msg_hash: [u8; 32] },
}

/// The kind is byte 0: a slot (0, 1) for a transaction, 0x02 a message, 0x03 approved.
pub fn parse_signature_data(data: &[u8]) -> Option<OwnerSignature<'_>> {
    match *data.first()? {
        KIND_APPROVED => parse_approved_signature_data(data).map(|(safe, msg_hash)| OwnerSignature::Approved { safe, msg_hash }),
        KIND_MESSAGE => parse_message_signature_data(data).map(OwnerSignature::Message),
        _ => parse_tx_signature_data(data).map(OwnerSignature::Transaction),
    }
}

// --- signing ---

/// The owner signature data for `tx`, signed with the one-time key that `rec` recorded: the
/// record must be for this transaction's hash and nonce on its chain and Safe, and for `tree`.
/// The signature is checked against the tree before it is returned.
pub fn sign_transaction(rec: &Recorded, tree: &wots::Tree, sk_seed: &[u8; 32], device: u8, tx: &SafeTx) -> Result<Vec<u8>, Error> {
    check_device(device)?;
    let u = rec.key_use();
    if tx.hash(u.chain, &u.safe) != u.hash || tx.nonce != U256::from_u64(u.nonce) {
        return Err(Error::Invalid("the key log record is for another transaction"));
    }
    if key_index(u.nonce, u.start, u.slot, tree.height)? != u.key_index {
        return Err(Error::Invalid("the key log record is for another tree"));
    }
    let (sig, path) = wots::sign_recorded(rec, tree, sk_seed, &wots::Prf::SIGNER)?;
    tx_signature_data(u.slot, device, &u.safe, &tx.words(), &sig, &path)
}

/// A stateless signature of `digest`, verified before it is returned (as the signer's
/// stateless_sign). It counts against the key's signature budget: a platform records it first.
pub fn stateless_sign(key: &leansphincs::Key, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let sig = key.sign(digest);
    if !leansphincs::verify(&key.public_key(), digest, &sig) {
        return Err(Error::SelfCheck("stateless signature"));
    }
    Ok(sig)
}

/// The member key's device certificate: its signature of [`device_digest`].
pub fn certify_device(member_key: &leansphincs::Key, chain_id: u64, owner: &[u8; 20], device: u8, generation: u16, device_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    check_key(device_key)?;
    if device == 0 || device > MAX_DEVICE {
        return Err(Error::Invalid("device keys are devices 1 to 3"));
    }
    stateless_sign(member_key, &device_digest(chain_id, owner, device, generation, device_key))
}

/// The member key's revocation: its signature of [`revocation_digest`].
pub fn revoke_device(member_key: &leansphincs::Key, chain_id: u64, owner: &[u8; 20], device: u8, generation: u16) -> Result<Vec<u8>, Error> {
    check_device(device)?;
    stateless_sign(member_key, &revocation_digest(chain_id, owner, device, generation))
}

/// The owner signature data for a SafeMessage (messages.py's signature_data): `message` is what
/// the Safe hashes, an app's bytes32 for isValidSignature(bytes32, bytes).
#[allow(clippy::too_many_arguments)]
pub fn sign_message(key: &leansphincs::Key, chain_id: u64, owner: &[u8; 20], safe: &[u8; 20], device: u8, generation: u16, message: &[u8]) -> Result<Vec<u8>, Error> {
    check_device(device)?;
    let smh = crate::safe::safe_message_hash(chain_id, safe, message);
    let sig = stateless_sign(key, &message_digest(chain_id, owner, safe, device, generation, &smh))?;
    message_signature_data(device, safe, &crate::safe::message_hash(message), &sig)
}
