//! Hash-Based Key Derivation from BIP-39 (HBKD; draft ERC: "Hash-Based Key Derivation from
//! BIP-39"), as in hbkd.py: the secret seeds of hash-based keys from a BIP-39 phrase, through
//! HMAC-SHA512 only (BIP-39's PBKDF2, then HKDF-SHA512), never BIP-32 or elliptic-curve
//! arithmetic.
//!
//! ```text
//!   M     = the mnemonic's words as they appear in the BIP-39 wordlist, joined by single spaces
//!   S     = PBKDF2-HMAC-SHA512(M, "mnemonic" ‖ passphrase, 2048)   BIP-39's seed, 64 bytes
//!   R     = HKDF-Extract(salt = "HBKD/v1", IKM)   the root, 64 bytes; IKM is S, or ≥ 32 random bytes
//!   value = HKDF-Expand(R, info, L)               32 ≤ L ≤ 16320 (255 blocks of SHA-512)
//!   info  = purpose ‖ be32(account) ‖ be16(L) ‖ len8(name) ‖ name ‖ tail
//!
//!   stateless key:      purpose 0x01, name = key type, tail empty
//!   stateful key:       purpose 0x02, name = key type, tail = context ‖ instance (32 bytes each)
//!   application secret: purpose 0x03, name = UTF-8 label, tail empty
//! ```
//!
//! [`bip39_seed`] takes the words and refuses a count other than 12, 15, 18, 21 or 24, a word
//! outside the English list, or a failed checksum, as the draft ERC requires; what a member types
//! is made canonical first ([`phrase::parse`] does that for Winterlock's 24-word phrases).
//! [`bip39_seed_unchecked`] is the PBKDF2 step alone, for tests and vectors.
//!
//! A key type is 1 to 255 bytes of printable ASCII other than the space (0x21 to 0x7e) naming the
//! scheme, its parameters, its seed length L and its key generation. An account is a `u32`, so
//! 2^32 can't be given. L is a `usize`, checked at run time: 32 to 16320. A label is 1 to 255
//! bytes of UTF-8 as given, without Unicode normalisation (the ERC says labels SHOULD be ASCII). A
//! stateful instance's `instance` is 32 random bytes that the caller makes when it creates the
//! instance and stores with the instance's state: nothing here is random. Roots, contexts and
//! instances are fixed-size arrays, so a wrong length can't be given either.
//!
//! Each derived value comes as a `Vec` of L bytes, or, through the `_into` forms, fills a buffer
//! whose length is L, without allocating.
//!
//! **SLH-DSA** (FIPS 205): the twelve parameter set names ([`SLH_DSA`]) are key types of their
//! own, stateless only, with L = 3n; the seed is SK.seed ‖ SK.prf ‖ PK.seed, the inputs of
//! slh_keygen_internal ([`slh_dsa_seeds`]). Key generation itself is not here.
//!
//! **ASCII only.** BIP-39 normalises the mnemonic and the passphrase to Unicode NFKD before
//! PBKDF2, and `no_std` has no Unicode normalisation. English words are ASCII, so only the
//! passphrase is at issue: [`bip39_seed`], [`bip39_seed_unchecked`] and [`winterlock_root`] take an
//! ASCII passphrase only and refuse any other byte with [`Error::Invalid`]; nothing is passed
//! through unnormalised. NFKD leaves ASCII as it is, so for ASCII input the seed is BIP-39's. The
//! Python signer (hbkd.py) normalises fully and takes any passphrase. Winterlock's own phrases are
//! ASCII: words of the English list, separated by single spaces. Labels are not normalised by
//! either side, so any label is taken.
//!
//! Library code only: nothing in the core derives keys this way yet. Winterlock's own keys
//! ([`crate::derive`]: member key, device keys, tree secret seeds, gas key) come from the phrase's
//! entropy and are unrelated. [`winterlock_root`] is the bridge: a Winterlock seed is the BIP-39
//! entropy of its 24 words, so those words have an HBKD root too.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::{Error, phrase};

type HmacSha512 = Hmac<Sha512>;

/// HKDF-Extract's salt: the ERC's name and version.
pub const SALT: &[u8] = b"HBKD/v1";
/// The purpose byte of `info` for a stateless key's seed.
pub const STATELESS: u8 = 1;
/// The purpose byte of `info` for a stateful key instance's seed.
pub const STATEFUL: u8 = 2;
/// The purpose byte of `info` for an application secret.
pub const APPLICATION: u8 = 3;
/// SHA-512's output, and so R's length and HKDF-Expand's block.
pub const HASH_LEN: usize = 64;
/// The shortest derived value, L.
pub const MIN_LENGTH: usize = 32;
/// The longest derived value, L: RFC 5869's limit of 255 blocks.
pub const MAX_LENGTH: usize = 255 * HASH_LEN;
/// The shortest input key material [`root`] takes.
pub const MIN_IKM: usize = 32;
/// BIP-39's PBKDF2 iterations.
pub const PBKDF2_ROUNDS: u32 = 2048;

/// The SLH-DSA key types: FIPS 205's parameter set names, with each one's hash length n in bytes.
/// Their seeds are 3n bytes.
pub const SLH_DSA: [(&str, usize); 12] = [
    ("SLH-DSA-SHA2-128s", 16),
    ("SLH-DSA-SHA2-128f", 16),
    ("SLH-DSA-SHA2-192s", 24),
    ("SLH-DSA-SHA2-192f", 24),
    ("SLH-DSA-SHA2-256s", 32),
    ("SLH-DSA-SHA2-256f", 32),
    ("SLH-DSA-SHAKE-128s", 16),
    ("SLH-DSA-SHAKE-128f", 16),
    ("SLH-DSA-SHAKE-192s", 24),
    ("SLH-DSA-SHAKE-192f", 24),
    ("SLH-DSA-SHAKE-256s", 32),
    ("SLH-DSA-SHAKE-256f", 32),
];

/// n for an SLH-DSA key type, `None` for any other string.
pub fn slh_dsa_n(key_type: &str) -> Option<usize> {
    SLH_DSA.iter().find(|(name, _)| *name == key_type).map(|&(_, n)| n)
}

// --- HKDF-SHA512 (RFC 5869) ---

/// HKDF-Extract(salt, IKM) = HMAC-SHA512(key = salt, message = IKM). An empty salt is HMAC's
/// empty key, the same as RFC 5869's default of 64 zero bytes.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = HmacSha512::new_from_slice(salt).expect("HMAC takes a key of any length");
    mac.update(ikm);
    let mut prk = [0u8; HASH_LEN];
    prk.copy_from_slice(&mac.finalize().into_bytes());
    prk
}

/// HKDF-Expand with `info` in parts, into `out`: T(1) ‖ T(2) ‖ … cut to `out.len()` bytes, where
/// T(i) = HMAC-SHA512(PRK, T(i-1) ‖ info ‖ i).
fn expand(prk: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    if out.len() > MAX_LENGTH {
        return Err(Error::Invalid("HKDF-Expand gives at most 255 * 64 = 16320 bytes"));
    }
    let keyed = HmacSha512::new_from_slice(prk).expect("HMAC takes a key of any length");
    let mut t = [0u8; HASH_LEN];
    for (i, chunk) in out.chunks_mut(HASH_LEN).enumerate() {
        let mut mac = keyed.clone();
        if i > 0 {
            mac.update(&t);
        }
        for part in info {
            mac.update(part);
        }
        mac.update(&[u8::try_from(i + 1).expect("at most 255 blocks")]);
        t.copy_from_slice(&mac.finalize().into_bytes());
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    Ok(())
}

/// HKDF-Expand(PRK, info, L) into `out`, L = `out.len()`: 0 to 16320 bytes (RFC 5869's limit;
/// HBKD's own values are at least 32).
pub fn hkdf_expand_into(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    expand(prk, &[info], out)
}

/// HKDF-Expand(PRK, info, L): `length` bytes, 0 to 16320.
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    if length > MAX_LENGTH {
        return Err(Error::Invalid("HKDF-Expand gives at most 255 * 64 = 16320 bytes"));
    }
    let mut out = vec![0u8; length];
    expand(prk, &[info], &mut out)?;
    Ok(out)
}

// --- BIP-39 ---

/// PBKDF2-HMAC-SHA512 with a 64-byte output (RFC 8018, section 5.2), which is one SHA-512 block:
/// U1 ⊕ U2 ⊕ … ⊕ Uc, where U1 = HMAC(password, salt ‖ be32(1)) and Ui = HMAC(password, Ui-1).
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[&[u8]], rounds: u32) -> [u8; 64] {
    let keyed = HmacSha512::new_from_slice(password).expect("HMAC takes a key of any length");
    let mut mac = keyed.clone();
    for part in salt {
        mac.update(part);
    }
    mac.update(&1u32.to_be_bytes());
    let mut u = [0u8; 64];
    u.copy_from_slice(&mac.finalize().into_bytes());
    let mut t = u;
    for _ in 1..rounds {
        let mut mac = keyed.clone();
        mac.update(&u);
        u.copy_from_slice(&mac.finalize().into_bytes());
        for (a, b) in t.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    t
}

/// BIP-39's mnemonic lengths.
pub const WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// Whether `words` is a BIP-39 English mnemonic in canonical form: 12, 15, 18, 21 or 24 words,
/// each exactly as it appears in the wordlist, whose checksum holds. The draft ERC makes wallets
/// refuse anything else (BIP-39 itself asks only for a warning), since a mistyped word that passed
/// would restore other keys.
pub fn check_mnemonic(words: &[&str]) -> Result<(), Error> {
    let n = words.len();
    if !WORD_COUNTS.contains(&n) {
        return Err(Error::Invalid("a mnemonic has 12, 15, 18, 21 or 24 words"));
    }
    // 11 bits per word: the entropy (32 n / 3 bits, a whole number of bytes), then n / 3 bits of
    // checksum, the first bits of the entropy's SHA-256
    let mut bits = [0u8; 33];
    for (i, w) in words.iter().enumerate() {
        let ix = phrase::index_of(w)
            .ok_or(Error::Invalid("a word outside the BIP-39 English list, or not as it appears there"))?;
        for k in 0..11 {
            if (ix >> (10 - k)) & 1 == 1 {
                let bit = 11 * i + k;
                bits[bit / 8] |= 0x80 >> (bit % 8);
            }
        }
    }
    let entropy = n * 4 / 3;
    let shift = 8 - n / 3;
    if Sha256::digest(&bits[..entropy])[0] >> shift != bits[entropy] >> shift {
        return Err(Error::Invalid("the words don't match their BIP-39 checksum"));
    }
    Ok(())
}

/// BIP-39's 64-byte seed of a mnemonic, given as its words exactly as they appear in the English
/// wordlist, and a passphrase ("" for none): the conforming entry point. Refused unless
/// [`check_mnemonic`] passes; typed text (other case, spacing, abbreviations) must be made
/// canonical first. The passphrase must be ASCII here (see the module's notes).
pub fn bip39_seed(words: &[&str], passphrase: &str) -> Result<[u8; 64], Error> {
    check_mnemonic(words)?;
    let mut sentence = String::with_capacity(9 * words.len());
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            sentence.push(' ');
        }
        sentence.push_str(w);
    }
    bip39_seed_unchecked(&sentence, passphrase)
}

/// The PBKDF2 step alone: BIP-39's seed of any sentence and passphrase, with no word list and no
/// checksum. Not conforming on its own (the ERC requires canonical words and a valid checksum):
/// use [`bip39_seed`].
///
/// **ASCII only:** BIP-39 normalises both to NFKD first, which this core can't do; NFKD is the
/// identity on ASCII. A non-ASCII byte in either is refused ([`Error::Invalid`]), never hashed as
/// it is.
pub fn bip39_seed_unchecked(sentence: &str, passphrase: &str) -> Result<[u8; 64], Error> {
    if !sentence.is_ascii() {
        return Err(Error::Invalid(
            "a mnemonic must be ASCII here: this core has no Unicode normalisation (NFKD)",
        ));
    }
    if !passphrase.is_ascii() {
        return Err(Error::Invalid(
            "a BIP-39 passphrase must be ASCII here: this core has no Unicode normalisation (NFKD)",
        ));
    }
    Ok(pbkdf2_hmac_sha512(sentence.as_bytes(), &[b"mnemonic", passphrase.as_bytes()], PBKDF2_ROUNDS))
}

// --- the root and the derived values ---

/// The root R = HKDF-Extract("HBKD/v1", IKM). IKM is a BIP-39 seed ([`bip39_seed`]), or at least
/// 32 bytes from a cryptographically secure random number generator for a key holder without a
/// phrase; shorter is refused. No upper bound: IKM is HMAC's message.
pub fn root(ikm: &[u8]) -> Result<[u8; HASH_LEN], Error> {
    if ikm.len() < MIN_IKM {
        return Err(Error::Invalid("input key material is at least 32 bytes"));
    }
    Ok(hkdf_extract(SALT, ikm))
}

/// Whether `key_type` is a key type: 1 to 255 bytes of printable ASCII other than the space,
/// 0x21 to 0x7e.
pub fn is_key_type(key_type: &str) -> bool {
    (1..=255).contains(&key_type.len()) && key_type.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

fn key_type_bytes(key_type: &str) -> Result<&[u8], Error> {
    if !is_key_type(key_type) {
        return Err(Error::Invalid(
            "a key type is 1 to 255 bytes of printable ASCII other than the space (0x21 to 0x7e)",
        ));
    }
    Ok(key_type.as_bytes())
}

fn label_bytes(label: &str) -> Result<&[u8], Error> {
    if !(1..=255).contains(&label.len()) {
        return Err(Error::Invalid("a label is 1 to 255 bytes of UTF-8"));
    }
    Ok(label.as_bytes())
}

fn check_length(length: usize) -> Result<(), Error> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(Error::Invalid("a derived value is 32 to 16320 bytes"));
    }
    Ok(())
}

/// purpose ‖ be32(account) ‖ be16(L) ‖ len8(name): the fixed-width start of `info`.
fn header(purpose: u8, account: u32, length: usize, name: &[u8]) -> Result<[u8; 8], Error> {
    check_length(length)?;
    if !(1..=255).contains(&name.len()) {
        return Err(Error::Invalid("a key type or label is 1 to 255 bytes"));
    }
    let mut h = [0u8; 8];
    h[0] = purpose;
    h[1..5].copy_from_slice(&account.to_be_bytes());
    h[5..7].copy_from_slice(&u16::try_from(length).expect("checked: at most 16320").to_be_bytes());
    h[7] = name.len() as u8;
    Ok(h)
}

/// purpose ‖ be32(account) ‖ be16(L) ‖ len8(name) ‖ name ‖ tail: HKDF-Expand's `info` for one
/// derived value, for tests and other implementations. Checks the layout only (the purpose, L, a
/// name of 1 to 255 bytes, a 64-byte tail exactly when stateful); the derivations below also check
/// the key type or label, and build the same bytes without allocating.
pub fn info(purpose: u8, account: u32, length: usize, name: &[u8], tail: &[u8]) -> Result<Vec<u8>, Error> {
    if !matches!(purpose, STATELESS | STATEFUL | APPLICATION) {
        return Err(Error::Invalid("a purpose is 1 (stateless), 2 (stateful) or 3 (application)"));
    }
    if tail.len() != if purpose == STATEFUL { 64 } else { 0 } {
        return Err(Error::Invalid(
            "the tail is context || instance (64 bytes) for a stateful key, and empty otherwise",
        ));
    }
    let h = header(purpose, account, length, name)?;
    let mut v = Vec::with_capacity(h.len() + name.len() + tail.len());
    v.extend_from_slice(&h);
    v.extend_from_slice(name);
    v.extend_from_slice(tail);
    Ok(v)
}

/// A `length`-byte value from `fill`, after checking the length (so nothing absurd is allocated).
fn to_vec(length: usize, fill: impl FnOnce(&mut [u8]) -> Result<(), Error>) -> Result<Vec<u8>, Error> {
    check_length(length)?;
    let mut out = vec![0u8; length];
    fill(&mut out)?;
    Ok(out)
}

/// The seed of the stateless key of `key_type` for `account`, filling `out` (L = `out.len()`, which
/// the key type defines: 32 to 16320, and 3n for an SLH-DSA key type). The same root always gives
/// the same key. Refused if `key_type` isn't one ([`is_key_type`]).
pub fn stateless_seed_into(root: &[u8; HASH_LEN], key_type: &str, account: u32, out: &mut [u8]) -> Result<(), Error> {
    let kt = key_type_bytes(key_type)?;
    if slh_dsa_n(key_type).is_some_and(|n| out.len() != 3 * n) {
        return Err(Error::Invalid("an SLH-DSA key type's seed is 3n bytes"));
    }
    let h = header(STATELESS, account, out.len(), kt)?;
    expand(root, &[&h, kt], out)
}

/// The `length`-byte seed of the stateless key of `key_type` for `account`: see
/// [`stateless_seed_into`].
pub fn stateless_seed(root: &[u8; HASH_LEN], key_type: &str, length: usize, account: u32) -> Result<Vec<u8>, Error> {
    to_vec(length, |out| stateless_seed_into(root, key_type, account, out))
}

/// The seed of one instance of a stateful key, filling `out` (L = `out.len()`, 32 to 16320).
/// `context` is 32 bytes the application defines; `instance` is 32 random bytes, made when the
/// instance is created and stored with its state: never derive it. Refused if `key_type` isn't one
/// ([`is_key_type`]) or is an SLH-DSA key type, which is stateless.
pub fn stateful_seed_into(
    root: &[u8; HASH_LEN],
    key_type: &str,
    context: &[u8; 32],
    instance: &[u8; 32],
    account: u32,
    out: &mut [u8],
) -> Result<(), Error> {
    let kt = key_type_bytes(key_type)?;
    if slh_dsa_n(key_type).is_some() {
        return Err(Error::Invalid("SLH-DSA key types are stateless"));
    }
    let h = header(STATEFUL, account, out.len(), kt)?;
    expand(root, &[&h, kt, context, instance], out)
}

/// The `length`-byte seed of one instance of a stateful key: see [`stateful_seed_into`].
pub fn stateful_seed(
    root: &[u8; HASH_LEN],
    key_type: &str,
    length: usize,
    context: &[u8; 32],
    instance: &[u8; 32],
    account: u32,
) -> Result<Vec<u8>, Error> {
    to_vec(length, |out| stateful_seed_into(root, key_type, context, instance, account, out))
}

/// An application's secret under its label, filling `out` (L = `out.len()`, 32 to 16320; 32
/// unless the application says otherwise). The label is 1 to 255 bytes of UTF-8 as given, without
/// Unicode normalisation (labels SHOULD be ASCII, and namespaced). Not a key type's seed, as
/// stateless and stateful keys have their own derivations; it may be other key material, such as
/// an ECDSA gas key.
pub fn app_secret_into(root: &[u8; HASH_LEN], label: &str, account: u32, out: &mut [u8]) -> Result<(), Error> {
    let lb = label_bytes(label)?;
    let h = header(APPLICATION, account, out.len(), lb)?;
    expand(root, &[&h, lb], out)
}

/// An application's `length`-byte secret under its label: see [`app_secret_into`].
pub fn app_secret(root: &[u8; HASH_LEN], label: &str, length: usize, account: u32) -> Result<Vec<u8>, Error> {
    to_vec(length, |out| app_secret_into(root, label, account, out))
}

/// The three inputs of FIPS 205's slh_keygen_internal (Algorithm 18) for an SLH-DSA key type, cut
/// from its 3n-byte stateless seed: SK.seed ‖ SK.prf ‖ PK.seed, n bytes each. The public key is
/// PK.seed ‖ PK.root. No `Debug`: these are secret.
#[derive(Clone)]
pub struct SlhDsaSeeds {
    n: usize,
    seed: [u8; 96],
}

impl SlhDsaSeeds {
    /// The parameter set's hash length: 16, 24 or 32.
    pub fn n(&self) -> usize {
        self.n
    }
    /// The whole 3n-byte stateless seed.
    pub fn seed(&self) -> &[u8] {
        &self.seed[..3 * self.n]
    }
    pub fn sk_seed(&self) -> &[u8] {
        &self.seed[..self.n]
    }
    pub fn sk_prf(&self) -> &[u8] {
        &self.seed[self.n..2 * self.n]
    }
    /// Public: the first half of the public key.
    pub fn pk_seed(&self) -> &[u8] {
        &self.seed[2 * self.n..3 * self.n]
    }
}

/// SK.seed, SK.prf and PK.seed of the SLH-DSA key of `key_type` (one of [`SLH_DSA`]) for
/// `account`. Refused for any other key type.
pub fn slh_dsa_seeds(root: &[u8; HASH_LEN], key_type: &str, account: u32) -> Result<SlhDsaSeeds, Error> {
    let n = slh_dsa_n(key_type)
        .ok_or(Error::Invalid("an SLH-DSA key type is a FIPS 205 parameter set's name, such as SLH-DSA-SHA2-128s"))?;
    let mut seed = [0u8; 96];
    stateless_seed_into(root, key_type, account, &mut seed[..3 * n])?;
    Ok(SlhDsaSeeds { n, seed })
}

/// The 64-byte HBKD root of a Winterlock seed: its 24 words ([`phrase::to_phrase`]; the seed is
/// their BIP-39 entropy, so the words are canonical and their checksum holds), through
/// [`bip39_seed`] with `passphrase` ("" for none), then [`root`]. A non-ASCII passphrase is
/// refused, as in [`bip39_seed`]. For a phrase as a member typed it:
/// `winterlock_root(&phrase::to_seed(text)?, ..)`.
pub fn winterlock_root(seed: &[u8; 32], passphrase: &str) -> Result<[u8; HASH_LEN], Error> {
    root(&bip39_seed(&phrase::to_phrase(seed), passphrase)?)
}

#[cfg(test)]
mod tests {
    //! The draft ERC's own test cases, hard-coded from its text (snapshot 14708d88), and a few
    //! Wycheproof HKDF-SHA512 vectors: tests/python_vectors.rs checks the core against the Python
    //! signer instead.
    use super::*;
    use crate::hex::{decode, decode_array, h32};
    use crate::leansphincs;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const KEY_TYPE: &str = "leanSphincs-keccak/wambsgans-keccak/b10";
    const LABEL: &str = "example.app.gas";
    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon art";
    const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

    struct Case {
        mnemonic: &'static str,
        passphrase: &'static str,
        s: &'static str,
        r: &'static str,
        stateless0: &'static str,
        stateless1: &'static str,
        stateful0: &'static str,
        app: &'static str,
    }

    const CASES: [Case; 3] = [
        Case {
            mnemonic: ABANDON,
            passphrase: "",
            s: "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70\
                5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
            r: "31a48aa502c800ed2e98d6ea19e8121861876ac755601b53f3772c4c910cc292\
                e8f1650268f6df3f7b7f030536b6b4e55a13b0d673b24e7e6a8fdecb9c5854ed",
            stateless0: "fe1de5038bcc56fc434f8cba07eb53ab972de18ec0779c7465fd0d789a966879",
            stateless1: "dae839ce92eb35bdd99718114d73d0b1ef6a2c66ad0bdd41b1fc7e99ee36ff82",
            stateful0: "675a2390347bd7f57af7086cd3596929701d22f554100304555a946403542c9f",
            app: "4a50286a3a17be26017002484f0e99f10b6a19bc6202fbc3f079760fd9b1c000",
        },
        Case {
            mnemonic: ABANDON,
            passphrase: "TREZOR",
            s: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971\
                70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            r: "36115dbd5c9909f705901905fdfcd5b59af8a03773b107a4cbc01de190810425\
                edabf87db6ceaebf3684dbfaf5ea46ec34d2b91a0d7661310b03b4ec1b5202bf",
            stateless0: "3d5ad9f82a782c1578db5b40443cfba75c151167312a133d4c90457f6a98179d",
            stateless1: "e5fa8baf57d6a7fecf5cdd9b7e1d1714cfbbdd4c86e7de882d4494d02fe65433",
            stateful0: "20023fe84a406e7f050108053e586d5741db708b721554c6a9e1e1cb16bd6b6b",
            app: "63cf757802534428b39551535e5560831be70a5996f1eab6240d399a0798c151",
        },
        Case {
            mnemonic: LEGAL,
            passphrase: "TREZOR",
            s: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f\
                a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            r: "c9f92a198541dcb5caf89f801827ef3baa8aafadcd3cee67d973ddbced8edad2\
                30dd8e77b5d30e60650c5d6ac22328a701b0e87ef959ea6a78c7e170354c3fbf",
            stateless0: "601ae30e33d5058eed33e0cc0ec25cb5bf8659481104a7bd0f10c0ebdd30b967",
            stateless1: "7d3b358bf3d671dc6eb66dcfc58f7d91e6bb06bfe4cf92da9c19051a44516943",
            stateful0: "52f7f43010563686fa971066e92e0e389d1caddf2c14a1dbb27f589a5f90dfee",
            app: "27ed4acb2aed9f052692619b763f96da377a3f96f2b242d8d636d19e1d06a3be",
        },
    ];
    /// The first case's stateless seed at L = 48 (account 0).
    const STATELESS_48: &str = "da22b68be432f40bc516b7f4633ac9238970b93fe22e198438f32750cb42c45a\
                                7eaa9c32c1bc6a3fb120d9d3e3cd9d51";
    /// The random input 0x20..0x3f: its root, then its stateless and stateful seeds and app secret
    /// at account 2^32 - 1.
    const RANDOM_R: &str = "719bbea6f6e3bec595afff3dccc8558972a4aa4893a654ce6b793616eab6f3d5\
                            c18887c81e3a4009c5488c1070b86a65e6bb32279473b8d8a21548e8d02fc07a";
    const RANDOM_STATELESS: &str = "6a0989ffde23947e80f0dfe22f5c9f7df46b79403db776b90fdd127b84f76ceb";
    const RANDOM_STATEFUL: &str = "0faee1dc2f4f8cdb4cd3fb634429c53d2305644fcc3903f5507ce05a64c6f5e8";
    const RANDOM_APP: &str = "dadb75da4b8194cfac6575b65705b93e5343172e4c2ed271e2e3627ffadfa950";
    /// The `info` of the first stateless seed (account 0, L = 32), 47 bytes.
    const INFO: &str = "01000000000020276c65616e537068696e63732d6b656363616b2f77616d627367616e732d6b656363616b2f623130";
    /// SLH-DSA key types for the first case (account 0): key type, seed, public key.
    const SLH: [(&str, &str, &str); 3] = [
        (
            "SLH-DSA-SHA2-128s",
            "9a4f5ec07d81f8f9b5ad67afe96d81793158212491f532a49a3139ac24e97105\
             9feb56347e8b95e5c18e1879d3ecf3bd",
            "9feb56347e8b95e5c18e1879d3ecf3bd8aa1a5ce8e63e5240b7521b3648b8298",
        ),
        (
            "SLH-DSA-SHA2-192s",
            "dd0257c7e6c82971da01e82c2e100827025e587bf4beb0837771faee59e9da38\
             3041f5ef899c5c7af8527461fb5922b0b2ee3215b5859539d83576885c3ec291\
             35f3878148585575",
            "b2ee3215b5859539d83576885c3ec29135f387814858557560f7ac4140534ed3\
             55a93fffba557aeb7a425407ff4bdd96",
        ),
        (
            "SLH-DSA-SHAKE-256s",
            "0771852b79bc31a74ed79f000965b5c36263e098f19def34204fdcefad597187\
             e11fbe0ccf0aa665307ab0becd1d7183af5c2a3f8c136e6976161b6d6fe9e4ac\
             be4e3fe70e626bafe1538ed6c50cdffe7918192469ce47798357d6ca901f3d78",
            "be4e3fe70e626bafe1538ed6c50cdffe7918192469ce47798357d6ca901f3d78\
             7a7fd9278d47cc69476b93a1b22fe671b4c1c102e5dddaf05870138189dc068e",
        ),
    ];
    /// A Winterlock regression value, not the ERC's: root ‖ public parameter of Winterlock's
    /// leanSphincs key at b = 10 from the first case's account-0 stateless seed (L = 32), as the
    /// Python signer computes it (leansphincs.Key).
    const WINTERLOCK_B10_PUBLIC_KEY: &str = "3262892101810781d0692ec03d73ae03d1c6b5a62c97cd145ec18f9979111bb2";

    fn words(sentence: &str) -> Vec<&str> {
        sentence.split(' ').collect()
    }

    fn h(s: &str) -> Vec<u8> {
        decode(s).unwrap()
    }

    fn h64(s: &str) -> [u8; 64] {
        decode_array(s).unwrap()
    }

    fn random_input() -> [u8; 32] {
        core::array::from_fn(|i| 0x20 + i as u8)
    }

    fn context() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    const INSTANCE: [u8; 32] = [0xa5; 32];

    #[test]
    fn erc_test_cases() {
        for c in &CASES {
            let s = h64(c.s);
            let r = h64(c.r);
            assert_eq!(bip39_seed(&words(c.mnemonic), c.passphrase).unwrap(), s, "S of {:?}", c.passphrase);
            assert_eq!(root(&s).unwrap(), r);
            assert_eq!(stateless_seed(&r, KEY_TYPE, 32, 0).unwrap(), h(c.stateless0));
            assert_eq!(stateless_seed(&r, KEY_TYPE, 32, 1).unwrap(), h(c.stateless1));
            assert_eq!(stateful_seed(&r, KEY_TYPE, 32, &context(), &INSTANCE, 0).unwrap(), h(c.stateful0));
            assert_eq!(app_secret(&r, LABEL, 32, 0).unwrap(), h(c.app));
            // the _into forms give the same bytes
            let mut out = [0u8; 32];
            stateless_seed_into(&r, KEY_TYPE, 1, &mut out).unwrap();
            assert_eq!(out, h32(c.stateless1));
            stateful_seed_into(&r, KEY_TYPE, &context(), &INSTANCE, 0, &mut out).unwrap();
            assert_eq!(out, h32(c.stateful0));
            app_secret_into(&r, LABEL, 0, &mut out).unwrap();
            assert_eq!(out, h32(c.app));
        }
        assert_eq!(context()[0x1f], 0x1f);
    }

    /// "The line with L = 48 shows that a longer seed does not start with the shorter one."
    #[test]
    fn erc_stateless_48() {
        let r = h64(CASES[0].r);
        let s48 = stateless_seed(&r, KEY_TYPE, 48, 0).unwrap();
        assert_eq!(s48, h(STATELESS_48));
        assert_ne!(s48[..32], h(CASES[0].stateless0)[..]);
        // HKDF alone would make it a prefix: L in info is what separates them
        let info32 = info(STATELESS, 0, 32, KEY_TYPE.as_bytes(), &[]).unwrap();
        assert_eq!(hkdf_expand(&r, &info32, 48).unwrap()[..32], h(CASES[0].stateless0)[..]);
    }

    #[test]
    fn erc_random_input_at_the_top_account() {
        let ikm = random_input();
        assert_eq!((ikm[0], ikm[31]), (0x20, 0x3f));
        let r = root(&ikm).unwrap();
        assert_eq!(r, h64(RANDOM_R));
        assert_eq!(stateless_seed(&r, KEY_TYPE, 32, u32::MAX).unwrap(), h(RANDOM_STATELESS));
        assert_eq!(stateful_seed(&r, KEY_TYPE, 32, &context(), &INSTANCE, u32::MAX).unwrap(), h(RANDOM_STATEFUL));
        assert_eq!(app_secret(&r, LABEL, 32, u32::MAX).unwrap(), h(RANDOM_APP));
    }

    #[test]
    fn erc_info_bytes() {
        let want = h(INFO);
        assert_eq!(want.len(), 47);
        assert_eq!(want[..8], [0x01, 0, 0, 0, 0, 0x00, 0x20, 0x27]);
        assert_eq!(info(STATELESS, 0, 32, KEY_TYPE.as_bytes(), &[]).unwrap(), want);
        let r = h64(CASES[0].r);
        assert_eq!(hkdf_expand(&r, &want, 32).unwrap(), h(CASES[0].stateless0));
        // the other two purposes, from the same layout
        let mut tail = context().to_vec();
        tail.extend_from_slice(&INSTANCE);
        let sf = info(STATEFUL, 0, 32, KEY_TYPE.as_bytes(), &tail).unwrap();
        assert_eq!(sf.len(), 47 + 64);
        assert_eq!(hkdf_expand(&r, &sf, 32).unwrap(), h(CASES[0].stateful0));
        let app = info(APPLICATION, 0, 32, LABEL.as_bytes(), &[]).unwrap();
        assert_eq!(app[..8], [0x03, 0, 0, 0, 0, 0x00, 0x20, 15]);
        assert_eq!(hkdf_expand(&r, &app, 32).unwrap(), h(CASES[0].app));
        // what info refuses: a purpose outside 1 to 3, a tail that doesn't fit the purpose
        assert!(info(0, 0, 32, b"x", &[]).is_err());
        assert!(info(4, 0, 32, b"x", &[]).is_err());
        assert!(info(STATEFUL, 0, 32, b"x", &[]).is_err());
        assert!(info(STATELESS, 0, 32, b"x", &tail).is_err());
        assert!(info(STATEFUL, 0, 32, b"x", &tail[..63]).is_err());
    }

    #[test]
    fn erc_slh_dsa() {
        let r = h64(CASES[0].r);
        for (kt, seed, pk) in SLH {
            let n = slh_dsa_n(kt).unwrap();
            let (seed, pk) = (h(seed), h(pk));
            assert_eq!((seed.len(), pk.len()), (3 * n, 2 * n), "{kt}");
            assert_eq!(stateless_seed(&r, kt, 3 * n, 0).unwrap(), seed, "{kt}");
            let s = slh_dsa_seeds(&r, kt, 0).unwrap();
            assert_eq!(s.n(), n);
            assert_eq!(s.seed(), seed);
            assert_eq!(s.sk_seed(), &seed[..n]);
            assert_eq!(s.sk_prf(), &seed[n..2 * n]);
            assert_eq!(s.pk_seed(), &seed[2 * n..]);
            // the public key is PK.seed ‖ PK.root
            assert_eq!(s.pk_seed(), &pk[..n], "{kt}");
        }
    }

    #[test]
    fn slh_dsa_key_types() {
        assert_eq!(SLH_DSA.len(), 12);
        let r = h64(CASES[0].r);
        for (i, &(kt, n)) in SLH_DSA.iter().enumerate() {
            // the FIPS 205 names: SHA2 then SHAKE, 128, 192, 256, s then f
            let want = alloc::format!(
                "SLH-DSA-{}-{}{}",
                ["SHA2", "SHAKE"][i / 6],
                [128, 192, 256][i / 2 % 3],
                ["s", "f"][i % 2]
            );
            assert_eq!(kt, want);
            assert_eq!(n, [16, 24, 32][i / 2 % 3]);
            assert!(is_key_type(kt));
            let s = slh_dsa_seeds(&r, kt, 7).unwrap();
            assert_eq!(s.seed(), stateless_seed(&r, kt, 3 * n, 7).unwrap());
            for bad in [32, 3 * n - 1, 3 * n + 1, 2 * n, 4 * n] {
                assert!(stateless_seed(&r, kt, bad, 0).is_err(), "{kt} at {bad}");
            }
            assert!(stateful_seed(&r, kt, 3 * n, &context(), &INSTANCE, 0).is_err(), "{kt}");
        }
        // other key types aren't SLH-DSA's, however close
        for other in [KEY_TYPE, "slh-dsa-sha2-128s", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128", "SLH-DSA-SHA2-128s/x"] {
            assert_eq!(slh_dsa_n(other), None);
            assert!(slh_dsa_seeds(&r, other, 0).is_err());
            assert!(stateless_seed(&r, other, 32, 0).is_ok());
        }
    }

    /// "An implementation rejects each of these inputs".
    #[test]
    fn erc_rejections() {
        let r = root(&random_input()).unwrap();
        let ctx = context();
        // the mnemonic abandon x 24, whose checksum fails
        assert!(bip39_seed(&["abandon"; 24], "").is_err());
        assert!(check_mnemonic(&["abandon"; 24]).is_err());
        // the key types "" and "leanSphincs keccak", and one of 256 bytes
        let long = "k".repeat(256);
        for bad in ["", "leanSphincs keccak", long.as_str()] {
            assert!(!is_key_type(bad));
            assert!(stateless_seed(&r, bad, 32, 0).is_err(), "{bad:?}");
            assert!(stateful_seed(&r, bad, 32, &ctx, &INSTANCE, 0).is_err(), "{bad:?}");
        }
        // account 2^32: a u32 can't hold it
        assert!(u32::try_from(1u64 << 32).is_err());
        // the lengths 31 and 16321, in every form
        for bad in [31, 16321] {
            let mut out = vec![0u8; bad];
            assert!(stateless_seed(&r, KEY_TYPE, bad, 0).is_err());
            assert!(stateless_seed_into(&r, KEY_TYPE, 0, &mut out).is_err());
            assert!(stateful_seed(&r, KEY_TYPE, bad, &ctx, &INSTANCE, 0).is_err());
            assert!(stateful_seed_into(&r, KEY_TYPE, &ctx, &INSTANCE, 0, &mut out).is_err());
            assert!(app_secret(&r, LABEL, bad, 0).is_err());
            assert!(app_secret_into(&r, LABEL, 0, &mut out).is_err());
            assert!(info(STATELESS, 0, bad, b"x", &[]).is_err());
        }
        // SLH-DSA-SHA2-128s at a length other than 48, or as a stateful key
        for bad in [32, 47, 49, 64, 72, 96] {
            assert!(stateless_seed(&r, "SLH-DSA-SHA2-128s", bad, 0).is_err(), "{bad}");
        }
        assert!(stateless_seed(&r, "SLH-DSA-SHA2-128s", 48, 0).is_ok());
        assert!(stateful_seed(&r, "SLH-DSA-SHA2-128s", 48, &ctx, &INSTANCE, 0).is_err());
    }

    #[test]
    fn other_refusals() {
        let r = h64(CASES[0].r);
        // input key material: at least 32 bytes, no upper bound
        assert!(root(&[]).is_err());
        assert!(root(&[7; 31]).is_err());
        assert_eq!(root(&[7; 32]).unwrap(), hkdf_extract(b"HBKD/v1", &[7; 32]));
        assert!(root(&[7; 100_000]).is_ok());
        // labels: 1 to 255 bytes of UTF-8, counted in bytes
        let at_most = ["a".repeat(255), "\u{e9}".repeat(127) + "a", "\u{4f8b}".repeat(85)];
        for ok in &at_most {
            assert_eq!(ok.len(), 255);
            assert!(app_secret(&r, ok, 32, 0).is_ok());
        }
        for bad in ["".into(), "a".repeat(256), "\u{e9}".repeat(128), "\u{4f8b}".repeat(85) + "a"] {
            assert!(app_secret(&r, &bad, 32, 0).is_err(), "{} bytes", bad.len());
            assert!(app_secret_into(&r, &bad, 0, &mut [0; 32]).is_err());
        }
        // a root, context or instance of the wrong length: the array types can't hold one
        assert!(<&[u8; 64]>::try_from(&[0u8; 63][..]).is_err());
        assert!(<&[u8; 32]>::try_from(&[0u8; 31][..]).is_err());
        assert!(<&[u8; 32]>::try_from(&[0u8; 33][..]).is_err());
        // the ends of L
        assert_eq!(stateless_seed(&r, KEY_TYPE, 16320, 0).unwrap().len(), 16320);
        assert_eq!(app_secret(&r, LABEL, 32, 0).unwrap().len(), 32);
        assert!(app_secret(&r, LABEL, 0, 0).is_err());
        assert!(app_secret(&r, LABEL, usize::MAX, 0).is_err());
    }

    /// HKDF-SHA512 against Wycheproof (C2SP/wycheproof, testvectors_v1/hkdf_sha512_test.json):
    /// tcId, IKM, salt, info, OKM. Empty salts, a salt longer than 64 bytes, info longer than a
    /// block, and output over two blocks.
    const WYCHEPROOF: [(u32, &str, &str, &str, &str); 5] = [
        (1, "24aeff2645e3e0f5494a9a102778c43a", "", "", "dd2599840b09699c6200b5cba79002b3aa75c61b"),
        (
            8,
            "be0df9811ad0bf3b08358a3dc4a05981",
            "c98618bfeb59295f8bf1dd3804b1bf2c",
            "",
            "c5cc73041ea99289bfbc39aaf64595129b461651c69d3de5297d66f844b4d59257be9a82bddf228630c8",
        ),
        (
            19,
            "df27ab960ad87bfe2e173a4659e3546b",
            "1e7ec49981fd4b0b7c20dd4dd5bdfbf2195e707f4d0354611b4893b8a86f61467aca2cf726ccc3ef0b0b4f3240d945ce\
             506197e2be00322b17b48209c312ef9f",
            "",
            "a1cca923d8f07cf98d658b425425a146a6cfea8910dbfee9a28962d0b1a1f40716ebfd19d094a1bba684",
        ),
        (
            23,
            "d04f44faa4542b34f958d8a863801f2c",
            "",
            "ff6b5b655cbf2421a66d2f28408395a2ce57264f76bd60befd51cbfd9474faa47a97a9aa0f0e4338635633023cb36da1\
             2a3051f1f369355b687304e74c5218b315",
            "76ebb3133cbf07afb653393bea4e4ecdab9d8e8fcc5e79e67d5346312ce9e46e937b3393170b811e25f7621923f74e51\
             9b604ae2b9884fe2d7202782ee9e20100f95341d8b6ff1f39db23bab7b7edcd6",
        ),
        (
            75,
            "ddba77f227f237c791c07ee7e1ce9d933ecad3614212cc98d4f12afc90a3b21f4c7c3b4c54f44ad7d1e8ce45cd36aad5\
             cb0bbf84e90cb054a1e7dc558690c5fa",
            "bd37d35e915d6a3431e8ab0fe1f1a3d129d9b6dfcdcb627ae7eb6d15068145cff05fa37e6bca0721e9ae696281759f6f\
             1f6784db7c8d30c4b75342ec6d6a1cc2af",
            "6b478027231379b6bbed6c61732aad5636b5aab2",
            "54b3b9a5d7f1713194b8e0621d8d33c6f2034b5005d47bbc90e5883d6af9bc42",
        ),
    ];

    #[test]
    fn hkdf_wycheproof() {
        for (id, ikm, salt, info, okm) in WYCHEPROOF {
            let okm = h(okm);
            let prk = hkdf_extract(&h(salt), &h(ikm));
            assert_eq!(hkdf_expand(&prk, &h(info), okm.len()).unwrap(), okm, "tcId {id}");
            let mut out = vec![0u8; okm.len()];
            hkdf_expand_into(&prk, &h(info), &mut out).unwrap();
            assert_eq!(out, okm, "tcId {id}");
        }
        // tcId 21, the maximal output (16320 bytes; its SHA-256 here), and tcId 22, one byte more
        let prk = hkdf_extract(
            &h("7ea9bd3ed65fdbec456e4859209d0e87336b0a04bd342fccede6fa4cb12331789a9af13d3c96e955a74550883aa5a80e\
                055ad7682a26c8b2343088d05f15f80d"),
            &h("83c6fa101a922bf4e0ab38c1853b82f8"),
        );
        let okm = hkdf_expand(&prk, &h("c893d162bf0036e4"), 16320).unwrap();
        assert_eq!(okm[..16], h("c80c2cce5fc294e1e680e665bbd7aac8")[..]);
        assert_eq!(Sha256::digest(&okm)[..], h32("f1d2571780c8a83db38dd812b9cab70a8c2e66bfaf1a2fb3632a154ce63a524a"));
        assert!(hkdf_expand(&prk, &h("b0aaceb3b0b8c885"), 16321).is_err());
        assert!(hkdf_expand_into(&prk, &[], &mut [0u8; 16321]).is_err());
        // HKDF itself takes any length up to 16320, 0 included
        assert_eq!(hkdf_expand(&prk, &[], 0).unwrap(), Vec::<u8>::new());
        assert_eq!(hkdf_expand(&prk, &[], 1).unwrap()[..], hkdf_expand(&prk, &[], 64).unwrap()[..1]);
    }

    #[test]
    fn winterlock_b10_regression() {
        let key = leansphincs::Key::new(&h32(CASES[0].stateless0), 10).unwrap();
        assert_eq!(key.public_key(), h32(WINTERLOCK_B10_PUBLIC_KEY));
        assert_eq!(key.public_key()[..16], key.root());
        assert_eq!(key.public_key()[16..], key.p());
    }

    #[test]
    fn winterlock_root_of_the_zero_seed() {
        // the ERC's first phrase is the 24 words of 32 zero bytes
        assert_eq!(phrase::to_phrase(&[0; 32]).join(" "), ABANDON);
        assert_eq!(winterlock_root(&[0; 32], "").unwrap(), h64(CASES[0].r));
        assert_eq!(winterlock_root(&[0; 32], "TREZOR").unwrap(), h64(CASES[1].r));
        assert!(winterlock_root(&[0; 32], "TR\u{c9}ZOR").is_err());
        let r = winterlock_root(&[0; 32], "").unwrap();
        assert_eq!(stateless_seed(&r, KEY_TYPE, 32, 0).unwrap(), h(CASES[0].stateless0));
    }

    #[test]
    fn ascii_only() {
        let w = words(ABANDON);
        assert!(bip39_seed(&w, "p\u{e4}ssphrase").is_err());
        assert!(bip39_seed(&w, "pa\u{308}ssphrase").is_err());
        assert!(bip39_seed_unchecked(ABANDON, "p\u{e4}ssphrase").is_err());
        assert!(bip39_seed_unchecked(&ABANDON.replace(' ', "\u{3000}"), "").is_err());
        assert!(bip39_seed_unchecked(&ABANDON.replace(' ', "\u{a0}"), "").is_err());
        // any ASCII passphrase is hashed as it is, control characters included
        assert!(bip39_seed(&w, "\0\t\x7f").is_ok());
        assert!(bip39_seed_unchecked("\t\x7f", "\0").is_ok());
    }

    #[test]
    fn mnemonics() {
        // the conforming path and the raw step agree on canonical words
        for c in &CASES {
            assert_eq!(bip39_seed(&words(c.mnemonic), c.passphrase), bip39_seed_unchecked(c.mnemonic, c.passphrase));
        }
        // 12 and 24 words, all-zero and all-one entropy
        for ok in [ABANDON, LEGAL, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                                    abandon about"] {
            assert!(check_mnemonic(&words(ok)).is_ok(), "{ok}");
        }
        let zoo: Vec<&str> = core::iter::repeat_n("zoo", 23).chain(["vote"]).collect();
        assert!(check_mnemonic(&zoo).is_ok());
        assert!(check_mnemonic(&phrase::to_phrase(&[0x5a; 32])).is_ok());
        let w = words(ABANDON);
        let mut refused: Vec<Vec<&str>> = Vec::new();
        refused.push(w[..22].iter().copied().chain(["art", "abandon"]).collect()); // two swapped
        refused.push(w[..11].to_vec()); // 11 words
        refused.push(w.iter().copied().chain(["abandon"]).collect()); // 25
        refused.push(Vec::new());
        refused.push(words(LEGAL).into_iter().chain(["abandon"]).collect()); // 13
        refused.push(core::iter::once("Abandon").chain(w[1..].iter().copied()).collect()); // case
        refused.push(core::iter::once("ABANDON").chain(w[1..].iter().copied()).collect());
        refused.push(core::iter::once("aban").chain(w[1..].iter().copied()).collect()); // abbreviated
        refused.push(w[..23].iter().copied().chain(["art "]).collect()); // spacing
        refused.push(w[..23].iter().copied().chain([""]).collect());
        refused.push(core::iter::once("abandon abandon").chain(w[2..].iter().copied()).collect());
        refused.push(w[..23].iter().copied().chain(["\u{e1}rt"]).collect()); // not in the list
        refused.push(core::iter::repeat_n("abandon", 12).collect()); // checksum, 12 words
        for bad in &refused {
            assert!(check_mnemonic(bad).is_err(), "{bad:?}");
            assert!(bip39_seed(bad, "").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn key_types() {
        let r = h64(CASES[0].r);
        let longest: String = (0..255).map(|i| (0x21 + i % 94) as u8 as char).collect();
        assert_eq!(longest.len(), 255);
        for good in ["!", "~", "x", "a-key-type,with_punctuation:!\"#$%&'()*+-./;<=>?@[\\]^_`{|}~", longest.as_str()] {
            assert!(is_key_type(good), "{good:?}");
            assert!(stateless_seed(&r, good, 32, 0).is_ok());
            assert!(stateful_seed(&r, good, 32, &context(), &INSTANCE, 0).is_ok());
        }
        let too_long = longest.clone() + "!";
        for bad in [
            "",
            " ",
            "leanSphincs keccak",
            "x ",
            " x",
            "\n",
            "a\tb",
            "\0",
            "\x1f",
            "\x7f",
            "caf\u{e9}",
            "\u{a0}",
            too_long.as_str(),
        ] {
            assert!(!is_key_type(bad), "{bad:?}");
            assert!(stateless_seed(&r, bad, 32, 0).is_err());
            assert!(stateful_seed(&r, bad, 32, &context(), &INSTANCE, 0).is_err());
        }
        // every byte: printable ASCII other than the space is 0x21 to 0x7e
        for c in 0u8..=0x7f {
            let s = [c];
            let t = core::str::from_utf8(&s).unwrap();
            assert_eq!(is_key_type(t), (0x21..0x7f).contains(&c), "{c:#x}");
        }
    }

    #[test]
    fn accounts_and_lengths_in_info() {
        let r = h64(CASES[0].r);
        let top = stateless_seed(&r, KEY_TYPE, 65, u32::MAX).unwrap();
        assert_ne!(top, stateless_seed(&r, KEY_TYPE, 65, 0).unwrap());
        // by hand: 01 ffffffff 0041 27 key type
        let mut i = vec![0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x41, 0x27];
        i.extend_from_slice(KEY_TYPE.as_bytes());
        assert_eq!(top, hkdf_expand(&r, &i, 65).unwrap());
        assert_eq!(info(STATELESS, u32::MAX, 65, KEY_TYPE.as_bytes(), &[]).unwrap(), i);
        // L = 16320 is 0x3fc0 in info
        assert_eq!(info(APPLICATION, 1 << 31, 16320, b"a", &[]).unwrap(), [3, 0x80, 0, 0, 0, 0x3f, 0xc0, 1, b'a']);
        assert_ne!(app_secret(&r, LABEL, 32, u32::MAX).unwrap(), app_secret(&r, LABEL, 32, 0).unwrap());
    }
}
