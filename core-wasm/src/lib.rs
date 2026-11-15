//! WebAssembly bindings of `winterlock-core` for the signer app (`app/`). Thin wrappers: every
//! format, digest and rule is the core's. Bytes cross as `Uint8Array`; errors as `Error` with the
//! core's own words.
//!
//! The key log's storage contract across the boundary (the core's `KeyLogStore` is synchronous,
//! IndexedDB isn't):
//! 1. [`pick_use`] reads the uses the app's durable log holds for a tree and says which slot and
//!    key would sign the hash: the use to record.
//! 2. The app writes that use to IndexedDB (a strict-durability transaction, completed), under a
//!    Web Lock for the device.
//! 3. [`sign_transaction`] gets the uses read back from IndexedDB, now including the new one, and
//!    runs the core's `keylog::record` over a store that can't append. It finds the use already
//!    recorded and returns the core's `Recorded`, which is the only thing that signs. If the use
//!    isn't in what was read back, the append fails and nothing is signed.
//!
//! Keys follow ERC-8499 (`derive::erc8499`): a phrase's seed (its BIP-39 entropy) gives the phrase
//! root, from which come the member key and the gas key; a device's 32 random bytes give its random
//! root, from which come its device key and its trees. The earlier derivation (`derive`'s own
//! functions, the app's builds up to 494703c) isn't reachable from here.
//!
//! Secrets: wrappers zero their own copies of seeds and roots when dropped. The core's leanSphincs key keeps
//! its own copy, which this crate can't reach; the app holds the member key only in a worker it
//! terminates afterwards, which discards the whole WebAssembly memory.

#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;
use winterlock_core::derive::{self, TreePlace, erc8499};
use winterlock_core::keylog::{self, KeyLogStore, KeyUse, TreeRef};
use winterlock_core::leansphincs::{self, Node};
use winterlock_core::safe::{Operation, SafeTx};
use winterlock_core::{U256, keccak, owner, phrase, safe, wots};

fn js(e: impl core::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn arr<const N: usize>(b: &[u8], what: &str) -> Result<[u8; N], JsError> {
    b.try_into().map_err(|_| JsError::new(&format!("{what}: expected {N} bytes, got {}", b.len())))
}

fn wipe(b: &mut [u8]) {
    b.fill(0);
    core::hint::black_box(b);
}

/// The phrase root of a phrase's seed; the caller's copy of the seed is untouched.
fn phrase_root(phrase_seed: &[u8]) -> Result<erc8499::Root, JsError> {
    let mut s = arr::<32>(phrase_seed, "seed")?;
    let r = erc8499::phrase_root(&s).map_err(js);
    wipe(&mut s);
    r
}

/// The random root of a device's 32 random bytes.
fn device_root(device_seed: &[u8]) -> Result<erc8499::Root, JsError> {
    let mut s = arr::<32>(device_seed, "seed")?;
    let r = erc8499::device_root(&s);
    wipe(&mut s);
    Ok(r)
}

/// The stateless key seed of a root, wiping the root.
fn stateless_seed(mut root: erc8499::Root) -> Result<[u8; 32], JsError> {
    let k = erc8499::stateless_key_seed(&root).map_err(js);
    wipe(&mut root);
    k
}

/// A tree's secret seed from its device's random bytes.
fn tree_secret(device_seed: &[u8], at: &TreePlace, height: u32, salt: &[u8]) -> Result<[u8; 32], JsError> {
    let salt = arr::<32>(salt, "salt")?;
    let mut root = device_root(device_seed)?;
    let sk = erc8499::tree_secret_seed(&root, at, height, &salt).map_err(js);
    wipe(&mut root);
    sk
}

// --- phrase ---

/// The 24 words of a seed, separated by single spaces.
#[wasm_bindgen]
pub fn phrase_of_seed(seed: &[u8]) -> Result<String, JsError> {
    let mut s = arr::<32>(seed, "seed")?;
    let words = phrase::to_phrase(&s).join(" ");
    wipe(&mut s);
    Ok(words)
}

/// The seed a phrase encodes, as typed (forgiving: case, numbering, commas, four-letter
/// abbreviations). The error names the problem.
#[wasm_bindgen]
pub fn phrase_to_seed(text: &str) -> Result<Vec<u8>, JsError> {
    phrase::to_seed(text).map(|s| s.to_vec()).map_err(js)
}

/// The word of the list a typed token means, if one.
#[wasm_bindgen]
pub fn phrase_word(token: &str) -> Option<String> {
    phrase::word(token).map(|w| w.into())
}

/// Whether `answer` is word `position` (1 to 24) of `words` (space-separated), as typed.
#[wasm_bindgen]
pub fn phrase_matches(words: &str, position: usize, answer: &str) -> bool {
    if !(1..=phrase::WORDS).contains(&position) {
        return false;
    }
    let ws: Vec<&str> = words.split(' ').collect();
    phrase::matches(&ws, position, answer)
}

/// The pairing check code: five words for (owner, device, key).
#[wasm_bindgen]
pub fn check_code(owner_addr: &[u8], device: u8, key: &[u8]) -> Result<String, JsError> {
    Ok(phrase::check_code_text(&arr(owner_addr, "owner")?, device, &arr(key, "key")?))
}

// --- keys ---

/// The gas account's private key for a phrase's seed (refused if zero or not below n).
#[wasm_bindgen]
pub fn gas_key(phrase_seed: &[u8]) -> Result<Vec<u8>, JsError> {
    let mut root = phrase_root(phrase_seed)?;
    let k = erc8499::gas_key(&root).map_err(js);
    wipe(&mut root);
    Ok(k?.to_vec())
}

/// Makes a stateless key (the member key or a device key) a few leaves at a time, so a worker can
/// report progress between steps.
#[wasm_bindgen]
pub struct KeyBuilder {
    seed: [u8; 32],
    plan: leansphincs::Plan,
    leaves: Vec<Node>,
    done: u32,
}

impl Drop for KeyBuilder {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

#[wasm_bindgen]
impl KeyBuilder {
    fn with_seed(ls_seed: [u8; 32]) -> Result<KeyBuilder, JsError> {
        let plan = leansphincs::plan(&ls_seed, derive::STATELESS_B).map_err(js)?;
        Ok(KeyBuilder { seed: ls_seed, plan, leaves: vec![[0u8; 16]; plan.count as usize], done: 0 })
    }

    /// The member key of a recovery phrase's seed.
    pub fn member(phrase_seed: &[u8]) -> Result<KeyBuilder, JsError> {
        KeyBuilder::with_seed(stateless_seed(phrase_root(phrase_seed)?)?)
    }

    /// The device key of a device's random seed.
    pub fn device(device_seed: &[u8]) -> Result<KeyBuilder, JsError> {
        KeyBuilder::with_seed(stateless_seed(device_root(device_seed)?)?)
    }

    pub fn total(&self) -> u32 {
        self.plan.count
    }

    pub fn done(&self) -> u32 {
        self.done
    }

    /// Computes up to `n` more leaves; returns how many are done.
    pub fn step(&mut self, n: u32) -> u32 {
        let end = (self.done + n).min(self.plan.count);
        let (a, b) = (self.done as usize, end as usize);
        leansphincs::leaves(&self.plan.p, &self.seed, self.plan.first + self.done, &mut self.leaves[a..b]);
        self.done = end;
        end
    }

    /// The key, once every leaf is done.
    pub fn finish(mut self) -> Result<StatelessKey, JsError> {
        if self.done != self.plan.count {
            return Err(JsError::new("the key's leaves aren't all done"));
        }
        let leaves = core::mem::take(&mut self.leaves);
        let key = leansphincs::Key::from_leaves(&self.seed, derive::STATELESS_B, leaves).map_err(js)?;
        Ok(StatelessKey { key })
    }
}

/// A leanSphincs-keccak key: the member key (device 0) or a device key.
#[wasm_bindgen]
pub struct StatelessKey {
    key: leansphincs::Key,
}

#[wasm_bindgen]
impl StatelessKey {
    /// A device key from its seed and its cached kept leaves (public values), checked against the
    /// public key it must have.
    pub fn device_from_cache(device_seed: &[u8], kept: &[u8], public_key: &[u8]) -> Result<StatelessKey, JsError> {
        let mut ls_seed = stateless_seed(device_root(device_seed)?)?;
        if kept.len() != 16 << derive::STATELESS_B {
            return Err(JsError::new("the kept leaves have the wrong size"));
        }
        let leaves: Vec<Node> = kept.chunks_exact(16).map(|c| c.try_into().unwrap()).collect();
        let key = leansphincs::Key::from_leaves(&ls_seed, derive::STATELESS_B, leaves).map_err(js);
        wipe(&mut ls_seed);
        let key = key?;
        if key.public_key()[..] != *public_key {
            return Err(JsError::new("the cached key leaves give another public key"));
        }
        Ok(StatelessKey { key })
    }

    /// root ‖ P: the member key in the owner's code, or a device key in its certificate.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_vec()
    }

    /// The kept leaves (16 KB of public values), to cache.
    pub fn kept_leaves(&self) -> Vec<u8> {
        self.key.kept_leaves_bytes()
    }

    /// The owner address of this key as a member key (the pinned v2 factory's proxy).
    pub fn owner(&self) -> Result<Vec<u8>, JsError> {
        Ok(owner::owner_address(&self.key.public_key()).map_err(js)?.to_vec())
    }

    /// As the member key: the certificate of `device_key` as device `device` at `generation` on
    /// `chain` (a stateless signature of the device digest, checked before it is returned).
    pub fn certify_device(&self, chain: u64, device: u8, generation: u16, device_key: &[u8]) -> Result<Vec<u8>, JsError> {
        let own = owner::owner_address(&self.key.public_key()).map_err(js)?;
        owner::certify_device(&self.key, chain, &own, device, generation, &arr(device_key, "device key")?).map_err(js)
    }

    /// As the member key: the revocation of device `device` at `generation` on `chain`.
    pub fn revoke_device(&self, chain: u64, device: u8, generation: u16) -> Result<Vec<u8>, JsError> {
        let own = owner::owner_address(&self.key.public_key()).map_err(js)?;
        owner::revoke_device(&self.key, chain, &own, device, generation).map_err(js)
    }

    /// As the device's key: the certificate of a key tree (a stateless signature of the
    /// certificate digest). The app records it before calling this.
    #[allow(clippy::too_many_arguments)]
    pub fn certify_tree(
        &self,
        chain: u64,
        owner_addr: &[u8],
        safe_addr: &[u8],
        device: u8,
        generation: u16,
        root: &[u8],
        height: u32,
        start: u64,
    ) -> Result<Vec<u8>, JsError> {
        let d = owner::certificate_digest(
            chain,
            &arr(owner_addr, "owner")?,
            &arr(safe_addr, "safe")?,
            device,
            generation,
            &arr(root, "root")?,
            height,
            start,
        );
        owner::stateless_sign(&self.key, &d).map_err(js)
    }
}

// --- key trees ---

#[allow(clippy::too_many_arguments)]
fn place(chain: u64, owner_addr: &[u8], safe_addr: &[u8], device: u8, generation: u16, start: u64) -> Result<TreePlace, JsError> {
    Ok(TreePlace { chain, owner: arr(owner_addr, "owner")?, safe: arr(safe_addr, "safe")?, device, generation, start })
}

/// Makes a device's key tree for a Safe a few leaves at a time.
#[wasm_bindgen]
pub struct TreeBuilder {
    seed: wots::Seed,
    sk: [u8; 32],
    height: u32,
    leaves: Vec<wots::Value>,
    done: u32,
}

impl Drop for TreeBuilder {
    fn drop(&mut self) {
        wipe(&mut self.sk);
    }
}

#[wasm_bindgen]
impl TreeBuilder {
    /// The tree of `device_seed` for (chain, owner, safe, device, generation, start) with the
    /// key log's random `salt`, of `height` (2^(height-1) nonces).
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_seed: &[u8],
        chain: u64,
        owner_addr: &[u8],
        safe_addr: &[u8],
        device: u8,
        generation: u16,
        start: u64,
        salt: &[u8],
        height: u32,
    ) -> Result<TreeBuilder, JsError> {
        if height == 0 || height > wots::MAX_REAL_HEIGHT {
            return Err(JsError::new("a key tree here is 1 to 20 high"));
        }
        let at = place(chain, owner_addr, safe_addr, device, generation, start)?;
        let sk = tree_secret(device_seed, &at, height, salt)?;
        Ok(TreeBuilder { seed: derive::tree_public_seed(&at), sk, height, leaves: vec![[0u8; wots::N]; 1 << height], done: 0 })
    }

    pub fn total(&self) -> u32 {
        1 << self.height
    }

    pub fn done(&self) -> u32 {
        self.done
    }

    pub fn step(&mut self, n: u32) -> u32 {
        let end = (self.done + n).min(self.total());
        let (a, b) = (self.done as usize, end as usize);
        wots::leaves(&self.seed, &self.sk, self.done as u64, &wots::Prf::SIGNER, &mut self.leaves[a..b]);
        self.done = end;
        end
    }

    /// The tree's cache (public values: height, seed, leaves), once every leaf is done.
    pub fn finish(mut self) -> Result<Vec<u8>, JsError> {
        if self.done != self.total() {
            return Err(JsError::new("the tree's leaves aren't all done"));
        }
        let leaves = core::mem::take(&mut self.leaves);
        let t = wots::Tree::from_leaves(&self.seed, self.height, self.height, leaves, Vec::new()).map_err(js)?;
        Ok(t.to_bytes())
    }
}

/// The root (24 bytes) of a tree cache.
#[wasm_bindgen]
pub fn tree_root(cache: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(wots::Tree::from_bytes(cache).map_err(js)?.root.to_vec())
}

// --- Safe transactions ---

/// A SafeTx from the app's encoding: to (20) ‖ value (32) ‖ operation (1) ‖ safeTxGas (32) ‖
/// baseGas (32) ‖ gasPrice (32) ‖ gasToken (20) ‖ refundReceiver (20) ‖ nonce (32) ‖ data.
fn decode_tx(b: &[u8]) -> Result<SafeTx, JsError> {
    const HEAD: usize = 20 + 32 + 1 + 32 * 3 + 20 + 20 + 32;
    if b.len() < HEAD {
        return Err(JsError::new("a SafeTx encoding is at least 221 bytes"));
    }
    let u = |o: usize| U256::from_be_bytes(b[o..o + 32].try_into().unwrap());
    let operation = Operation::from_u8(b[52]).ok_or_else(|| JsError::new("operation must be 0 or 1"))?;
    Ok(SafeTx {
        to: b[0..20].try_into().unwrap(),
        value: u(20),
        operation,
        safe_tx_gas: u(53),
        base_gas: u(85),
        gas_price: u(117),
        gas_token: b[149..169].try_into().unwrap(),
        refund_receiver: b[169..189].try_into().unwrap(),
        nonce: u(189),
        data: b[HEAD..].to_vec(),
    })
}

/// The SafeTx hash that owners sign, from the fields.
#[wasm_bindgen]
pub fn safe_tx_hash(chain: u64, safe_addr: &[u8], tx: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(decode_tx(tx)?.hash(chain, &arr(safe_addr, "safe")?).to_vec())
}

// --- the key log ---

/// The uses the app's durable log holds for one tree: key index (8 bytes, big-endian) ‖ hash (32)
/// each. Read-only: appending fails, so the core's rules can only find a use already recorded.
struct DurableUses<'a> {
    chain: u64,
    safe: [u8; 20],
    root: wots::Value,
    uses: &'a [u8],
}

const USE_BYTES: usize = 40;

impl KeyLogStore for DurableUses<'_> {
    type Error = &'static str;

    fn find_use(&self, chain: u64, safe_addr: &[u8; 20], root: &wots::Value, key_index: u64) -> Result<Option<[u8; 32]>, Self::Error> {
        if chain != self.chain || *safe_addr != self.safe || *root != self.root {
            return Ok(None);
        }
        if self.uses.len() % USE_BYTES != 0 {
            return Err("the key log's uses are malformed");
        }
        Ok(self
            .uses
            .chunks_exact(USE_BYTES)
            .find(|u| u64::from_be_bytes(u[..8].try_into().unwrap()) == key_index)
            .map(|u| u[8..].try_into().unwrap()))
    }

    fn append_use(&mut self, _: &KeyUse) -> Result<(), Self::Error> {
        Err("this use isn't in the durable key log: record it first")
    }
}

fn nonce_u64(n: &U256) -> Result<u64, JsError> {
    n.to_u64().ok_or_else(|| JsError::new("the nonce is too large for a key tree"))
}

/// Step 1: which slot (and key) of the tree would sign `hash` at `nonce`, given the uses the
/// durable log holds for it. Returns slot (1) ‖ already (1: this key already signed this hash) ‖
/// key index (8, big-endian), or the core's refusal.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn pick_use(chain: u64, safe_addr: &[u8], root: &[u8], start: u64, height: u32, nonce: u64, hash: &[u8], uses: &[u8]) -> Result<Vec<u8>, JsError> {
    let tree = TreeRef { chain, safe: arr(safe_addr, "safe")?, root: arr(root, "root")?, start, height };
    let store = DurableUses { chain, safe: tree.safe, root: tree.root, uses };
    let h = arr::<32>(hash, "hash")?;
    let pick = keylog::pick_slot(&store, &tree, nonce, &h).map_err(js)?;
    let k = owner::key_index(nonce, start, pick.slot, height).map_err(js)?;
    let mut out = vec![pick.slot, pick.already as u8];
    out.extend_from_slice(&k.to_be_bytes());
    Ok(out)
}

/// Step 3: the owner signature data for `tx`, from the tree's one-time key that the durable log
/// already records for this hash. `uses` are read back from that log after the record was
/// committed. Checked against the tree before it is returned.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn sign_transaction(
    device_seed: &[u8],
    chain: u64,
    owner_addr: &[u8],
    safe_addr: &[u8],
    device: u8,
    generation: u16,
    start: u64,
    salt: &[u8],
    tree_cache: &[u8],
    uses: &[u8],
    tx: &[u8],
) -> Result<Vec<u8>, JsError> {
    let at = place(chain, owner_addr, safe_addr, device, generation, start)?;
    let t = decode_tx(tx)?;
    let tree = wots::Tree::from_bytes(tree_cache).map_err(js)?;
    if tree.seed != derive::tree_public_seed(&at) {
        return Err(JsError::new("the tree cache is for another place"));
    }
    let hash = t.hash(chain, &at.safe);
    let nonce = nonce_u64(&t.nonce)?;
    let tref = TreeRef { chain, safe: at.safe, root: tree.root, start, height: tree.height };
    let mut store = DurableUses { chain, safe: at.safe, root: tree.root, uses };
    let rec = keylog::record(&mut store, &tref, nonce, &hash).map_err(js)?;
    let mut sk = tree_secret(device_seed, &at, tree.height, salt)?;
    let out = owner::sign_transaction(&rec, &tree, &sk, device, &t).map_err(js);
    wipe(&mut sk);
    out
}

/// If `data` (an owner's transaction signature data) was signed by the tree of (chain, owner,
/// safe, device, generation, start) with this root: key index (8) ‖ nonce (8) ‖ slot (1) ‖ hash
/// (32). Otherwise undefined: another device, another tree or Safe, or not a transaction
/// signature. The stale-log check compares these uses with the durable log.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn tree_signature_use(
    data: &[u8],
    chain: u64,
    owner_addr: &[u8],
    safe_addr: &[u8],
    device: u8,
    generation: u16,
    start: u64,
    height: u32,
    root: &[u8],
) -> Result<Option<Vec<u8>>, JsError> {
    let at = place(chain, owner_addr, safe_addr, device, generation, start)?;
    let root: wots::Value = arr(root, "root")?;
    let Some(sig) = owner::parse_tx_signature_data(data) else { return Ok(None) };
    if sig.device != device || sig.safe != at.safe || sig.height() != height as usize {
        return Ok(None);
    }
    let Some(nonce) = sig.nonce().to_u64() else { return Ok(None) };
    let Ok(k) = owner::key_index(nonce, start, sig.slot, height) else { return Ok(None) };
    let hash = safe::hash_of_words(chain, &at.safe, &sig.words);
    if wots::verify_root(&derive::tree_public_seed(&at), k, &hash, sig.wots_sig, sig.path) != Some(root) {
        return Ok(None);
    }
    let mut out = k.to_be_bytes().to_vec();
    out.extend_from_slice(&nonce.to_be_bytes());
    out.push(sig.slot);
    out.extend_from_slice(&hash);
    Ok(Some(out))
}

// --- owners ---

/// The owner address of a member key.
#[wasm_bindgen]
pub fn owner_address(member_key: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(owner::owner_address(&arr(member_key, "member key")?).map_err(js)?.to_vec())
}

/// The digest a tree certificate signs (the owner's `enroll` checks it): for a board's trees,
/// device 0 (the member key) and generation 0.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn certificate_digest(chain: u64, owner_addr: &[u8], safe_addr: &[u8], device: u8, generation: u16, root: &[u8], height: u32, start: u64) -> Result<Vec<u8>, JsError> {
    Ok(owner::certificate_digest(chain, &arr(owner_addr, "owner")?, &arr(safe_addr, "safe")?, device, generation, &arr(root, "root")?, height, start).to_vec())
}

/// Whether `signature` is a stateless signature of `message` (32 bytes) by `public_key` (root ‖ P),
/// as the stateless verifier checks it.
#[wasm_bindgen]
pub fn stateless_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    Ok(leansphincs::verify(&arr(public_key, "public key")?, &arr(message, "message")?, signature))
}

/// The member key in `code` if it is a v2 owner of the pinned implementation at `address`.
#[wasm_bindgen]
pub fn member_key_of(address: &[u8], code: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
    Ok(owner::member_key_of(&arr(address, "address")?, code).map(|k| k.to_vec()))
}

/// The pinned shared contracts, 20 bytes each: stateless verifier, WOTS verifier,
/// implementation, factory (the same on every chain).
#[wasm_bindgen]
pub fn pinned_contracts() -> Vec<u8> {
    [owner::VERIFIER, owner::WOTS_VERIFIER, owner::IMPLEMENTATION, owner::FACTORY].concat()
}

/// keccak256, for checks.
#[wasm_bindgen]
pub fn keccak256(data: &[u8]) -> Vec<u8> {
    keccak::keccak256(data).to_vec()
}

/// The Keccak-f backend this build uses.
#[wasm_bindgen]
pub fn keccak_backend() -> String {
    keccak::backend().name().into()
}
