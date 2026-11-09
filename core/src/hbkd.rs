//! Hash-Based Key Derivation from BIP-39 (HBKD; draft ERC: "Hash-Based Key Derivation from
//! BIP-39"), as in hbkd.py: the secret seeds of hash-based keys from a BIP-39 phrase, through
//! PBKDF2-HMAC-SHA512 and keccak256 only, never BIP-32 or elliptic-curve arithmetic.
//!
//! ```text
//!   M         = the mnemonic's words as they appear in the BIP-39 wordlist, joined by single spaces
//!   S         = PBKDF2-HMAC-SHA512(M, "mnemonic" ‖ passphrase, 2048)   BIP-39's seed, 64 bytes
//!   R         = TH("HBKD/root/v1", S)                    the root, 32 bytes (or 32 random bytes)
//!   stateless = TH("HBKD/stateless/v1", R ‖ be32(account) ‖ kt)
//!   stateful  = TH("HBKD/stateful/v1", R ‖ be32(account) ‖ kt ‖ context ‖ instance)
//!   app       = TH("HBKD/app/v1", R ‖ be32(account) ‖ keccak256(utf8(label)))
//!
//!   TH(tag, data) = keccak256(keccak256(tag) ‖ data),   kt = keccak256(key type)
//! ```
//!
//! [`bip39_seed`] takes the words and refuses a count other than 12, 15, 18, 21 or 24, a word
//! outside the English list, or a failed checksum, as the draft ERC requires; what a member types
//! is made canonical first ([`phrase::parse`] does that for Winterlock's 24-word phrases).
//! [`bip39_seed_unchecked`] is the PBKDF2 step alone, for tests and vectors.
//!
//! A key type is a non-empty string of printable ASCII other than the space (0x21 to 0x7e) naming
//! the scheme, its parameters and its key generation; an account is a `u32`, so 2^32 can't be
//! given. Labels are UTF-8 as given, without Unicode normalisation (the ERC says they SHOULD be
//! ASCII). A stateful instance's
//! `instance` is 32 random bytes that the caller makes when it creates the instance and stores with
//! the instance's state: nothing here is random.
//!
//! **ASCII only.** BIP-39 normalises the mnemonic and the passphrase to Unicode NFKD before
//! PBKDF2, and `no_std` has no Unicode normalisation. English words are ASCII, so only the
//! passphrase is at issue: [`bip39_seed`], [`bip39_seed_unchecked`] and [`winterlock_root`] take an
//! ASCII passphrase only and refuse any other byte with [`Error::Invalid`]; nothing is passed
//! through unnormalised. NFKD leaves ASCII as it is, so for ASCII input the seed is BIP-39's. The
//! Python signer (hbkd.py) normalises fully and takes any passphrase. Winterlock's own phrases are
//! ASCII: words of the English list, separated by single spaces.
//!
//! Library code only: nothing in the core derives keys this way yet. Winterlock's own keys
//! ([`crate::derive`]: member key, device keys, tree secret seeds, gas key) come from the phrase's
//! entropy and are unrelated. [`winterlock_root`] is the bridge: a Winterlock seed is the BIP-39
//! entropy of its 24 words, so those words have an HBKD root too.

use alloc::string::String;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::keccak::{Keccak256, keccak256};
use crate::{Error, phrase};

pub const ROOT_TAG: &str = "HBKD/root/v1";
pub const STATELESS_TAG: &str = "HBKD/stateless/v1";
pub const STATEFUL_TAG: &str = "HBKD/stateful/v1";
pub const APP_TAG: &str = "HBKD/app/v1";
/// BIP-39's PBKDF2 iterations.
pub const PBKDF2_ROUNDS: u32 = 2048;

/// TH(tag, data) with `data` in parts: keccak256(keccak256(tag) ‖ data). The tags are the
/// constants above, all ASCII.
fn tagged_hash(tag: &str, data: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(&keccak256(tag.as_bytes()));
    for part in data {
        h.update(part);
    }
    h.finalize()
}

/// PBKDF2-HMAC-SHA512 with a 64-byte output (RFC 8018, section 5.2), which is one SHA-512 block:
/// U1 ⊕ U2 ⊕ … ⊕ Uc, where U1 = HMAC(password, salt ‖ be32(1)) and Ui = HMAC(password, Ui-1).
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[&[u8]], rounds: u32) -> [u8; 64] {
    let keyed = Hmac::<Sha512>::new_from_slice(password).expect("HMAC takes a key of any length");
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

/// The root R of a 64-byte BIP-39 seed.
pub fn root_from_seed(seed: &[u8; 64]) -> [u8; 32] {
    tagged_hash(ROOT_TAG, &[seed])
}

/// Whether `key_type` is a key type: a non-empty string of printable ASCII other than the space,
/// 0x21 to 0x7e.
pub fn is_key_type(key_type: &str) -> bool {
    !key_type.is_empty() && key_type.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

/// kt(t) = keccak256(t), for a key type only.
fn kt(key_type: &str) -> Result<[u8; 32], Error> {
    if !is_key_type(key_type) {
        return Err(Error::Invalid(
            "a key type is a non-empty string of printable ASCII other than the space (0x21 to 0x7e)",
        ));
    }
    Ok(keccak256(key_type.as_bytes()))
}

/// The seed of the stateless key of `key_type` for `account`: the same root always gives the same
/// key. Refused if `key_type` isn't one ([`is_key_type`]).
pub fn stateless_seed(root: &[u8; 32], key_type: &str, account: u32) -> Result<[u8; 32], Error> {
    let kt = kt(key_type)?;
    Ok(tagged_hash(STATELESS_TAG, &[root, &account.to_be_bytes(), &kt]))
}

/// The seed of one instance of a stateful key. `instance` is 32 random bytes, made when the
/// instance is created and stored with its state; never derive it. Refused if `key_type` isn't
/// one ([`is_key_type`]).
pub fn stateful_seed(
    root: &[u8; 32],
    key_type: &str,
    context: &[u8; 32],
    instance: &[u8; 32],
    account: u32,
) -> Result<[u8; 32], Error> {
    let kt = kt(key_type)?;
    Ok(tagged_hash(STATEFUL_TAG, &[root, &account.to_be_bytes(), &kt, context, instance]))
}

/// An application's secret under its label: any string, its UTF-8 bytes as given, without Unicode
/// normalisation (labels SHOULD be ASCII). Not a key type's seed, as stateless and stateful keys
/// have their own derivations; it may be other key material, such as an ECDSA gas key.
pub fn app_secret(root: &[u8; 32], label: &str, account: u32) -> [u8; 32] {
    tagged_hash(APP_TAG, &[root, &account.to_be_bytes(), &keccak256(label.as_bytes())])
}

/// The HBKD root of a Winterlock seed: its 24 words ([`phrase::to_phrase`]; the seed is their
/// BIP-39 entropy, so the words are canonical and their checksum holds), through [`bip39_seed`]
/// with `passphrase` ("" for none), then [`root_from_seed`]. A non-ASCII passphrase is refused, as
/// in [`bip39_seed`]. For a phrase as a member typed it: `winterlock_root(&phrase::to_seed(text)?, ..)`.
pub fn winterlock_root(seed: &[u8; 32], passphrase: &str) -> Result<[u8; 32], Error> {
    Ok(root_from_seed(&bip39_seed(&phrase::to_phrase(seed), passphrase)?))
}

#[cfg(test)]
mod tests {
    //! The draft ERC's own test cases, hard-coded from its text: tests/python_vectors.rs checks the
    //! core against the Python signer instead.
    use super::*;
    use crate::hex::{decode_array, h32};
    use crate::leansphincs;
    use alloc::vec::Vec;
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
            r: "3e6cf3c3a1af758759e9337eed8a7d4723e23a378c1e471a28baf4db10569e01",
            stateless0: "373d01c6fca9738080cf1f4186fd517ad450d134d31bcb3aecb3bb4dd340d419",
            stateless1: "8fc21bcff345bc88b412b2d4a3a8c2a0637d3ea05e187969d3ce0aa195ca2e7b",
            stateful0: "e8e1e2bc45a1a0785011021d34b601833c4e1f0fcfabb19daa53d0ffd1a47939",
            app: "fcec37951685415d996fb166633bce4891ffb650ef121354129c1fe8b6d850c7",
        },
        Case {
            mnemonic: ABANDON,
            passphrase: "TREZOR",
            s: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971\
                70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            r: "04ed2bcdefde1aad10dc37dd64ef968d3229c9b468a8407d76b1f969a2d6b335",
            stateless0: "d4438a8e081bd7cf04b632dc763fcff549eeb1f1fbea78e759d22041aa0ef295",
            stateless1: "44a8d35e0d3010c16f5256426c2c0c6b267f5a121928adcb21e6f934de5711b7",
            stateful0: "9e65891f41a97f6235a55233a3117095a86fc831b3bfc72eb429ba5c77e2160e",
            app: "1da8fa73176e364da9784eeff604937153bf9565acff932d558e678c9aca6eff",
        },
        Case {
            mnemonic: LEGAL,
            passphrase: "TREZOR",
            s: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f\
                a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            r: "fed41ed04e47cf6b7cebabb5fce9f214fc6a5e5b8ddddb38c50cbc7feaa7dee4",
            stateless0: "55b86642971ca5d137f1ce48ad68d0c79310aff96ae70b5b061dc696e5a7dd03",
            stateless1: "3347fbb9f4f0adaf77a518ccd4ff34d47247120a8b32ecf7d13b5b5575170d7e",
            stateful0: "37306d29c12f6f5490989ce516eada140d00038ec48979584aaec7a42c00b37a",
            app: "85c53633bb07dddb69b8cabe0f883410574b5db9bf90775b93b45620120227b4",
        },
    ];
    /// A random root, and its stateless and stateful seeds and app secret at account 2^32 - 1.
    const RANDOM_STATELESS: &str = "08ab99f47191e6cda022959b2081b705c6c8ad7c621bbf5dc2dc3eb25d1f8618";
    const RANDOM_STATEFUL: &str = "6f7916cfa6ddcc290922eb98746847c8b9b3eb863df42715a28e5e0432371ef4";
    const RANDOM_APP: &str = "3f19d5ebb8a58e748762da7038cf705835fd88b62b7c2b93aa9cacb3e3223529";
    /// Winterlock only (the ERC dropped it: the pruned key generation isn't specified elsewhere):
    /// root ‖ public parameter of the first case's account-0 stateless key, made by Winterlock's
    /// leanSphincs at b = 10.
    const WINTERLOCK_PUBLIC_KEY: &str = "14ea1515b0bb93f5bf7151fbad2800ca37389f2020209a2d0e55ed7fd6b2977e";

    fn words(sentence: &str) -> Vec<&str> {
        sentence.split(' ').collect()
    }

    fn random_root() -> [u8; 32] {
        core::array::from_fn(|i| 0x20 + i as u8)
    }

    fn context() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    const INSTANCE: [u8; 32] = [0xa5; 32];

    #[test]
    fn erc_test_cases() {
        for c in &CASES {
            let s: [u8; 64] = decode_array(c.s).unwrap();
            let r = h32(c.r);
            assert_eq!(bip39_seed(&words(c.mnemonic), c.passphrase).unwrap(), s, "S of {:?}", c.passphrase);
            assert_eq!(root_from_seed(&s), r);
            assert_eq!(stateless_seed(&r, KEY_TYPE, 0).unwrap(), h32(c.stateless0));
            assert_eq!(stateless_seed(&r, KEY_TYPE, 1).unwrap(), h32(c.stateless1));
            assert_eq!(stateful_seed(&r, KEY_TYPE, &context(), &INSTANCE, 0).unwrap(), h32(c.stateful0));
            assert_eq!(app_secret(&r, LABEL, 0), h32(c.app));
        }
        assert_eq!(context()[0x1f], 0x1f);
    }

    #[test]
    fn erc_random_root_at_the_top_account() {
        let r = random_root();
        assert_eq!(r[0], 0x20);
        assert_eq!(r[31], 0x3f);
        assert_eq!(stateless_seed(&r, KEY_TYPE, u32::MAX).unwrap(), h32(RANDOM_STATELESS));
        assert_eq!(stateful_seed(&r, KEY_TYPE, &context(), &INSTANCE, u32::MAX).unwrap(), h32(RANDOM_STATEFUL));
        assert_eq!(app_secret(&r, LABEL, u32::MAX), h32(RANDOM_APP));
    }

    /// "An implementation rejects each of these inputs": 24 x abandon (checksum), the key types ""
    /// and "leanSphincs keccak", and account 2^32, which a `u32` can't hold.
    #[test]
    fn erc_rejections() {
        assert!(bip39_seed(&["abandon"; 24], "").is_err());
        assert!(check_mnemonic(&["abandon"; 24]).is_err());
        for bad in ["", "leanSphincs keccak"] {
            assert!(stateless_seed(&random_root(), bad, 0).is_err(), "{bad:?}");
        }
        assert!(u32::try_from(1u64 << 32).is_err());
    }

    #[test]
    fn winterlock_public_key_b10() {
        let key = leansphincs::Key::new(&h32(CASES[0].stateless0), 10).unwrap();
        assert_eq!(key.public_key(), h32(WINTERLOCK_PUBLIC_KEY));
        assert_eq!(key.public_key()[..16], key.root());
        assert_eq!(key.public_key()[16..], key.p());
    }

    #[test]
    fn winterlock_root_of_the_zero_seed() {
        // the ERC's first phrase is the 24 words of 32 zero bytes
        assert_eq!(phrase::to_phrase(&[0; 32]).join(" "), ABANDON);
        assert_eq!(winterlock_root(&[0; 32], "").unwrap(), h32(CASES[0].r));
        assert_eq!(winterlock_root(&[0; 32], "TREZOR").unwrap(), h32(CASES[1].r));
        assert!(winterlock_root(&[0; 32], "TR\u{c9}ZOR").is_err());
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
        let r = h32(CASES[0].r);
        for good in ["!", "~", "x", "a-key-type,with_punctuation:!\"#$%&'()*+-./;<=>?@[\\]^_`{|}~"] {
            assert!(is_key_type(good), "{good:?}");
            assert!(stateless_seed(&r, good, 0).is_ok());
        }
        for bad in ["", " ", "leanSphincs keccak", "x ", " x", "\n", "a\tb", "\0", "\x1f", "\x7f", "caf\u{e9}", "\u{a0}"] {
            assert!(!is_key_type(bad), "{bad:?}");
            assert!(stateless_seed(&r, bad, 0).is_err());
            assert!(stateful_seed(&r, bad, &context(), &INSTANCE, 0).is_err());
        }
        // every byte: printable ASCII other than the space is 0x21 to 0x7e
        for c in 0u8..=0x7f {
            let s = [c];
            let t = core::str::from_utf8(&s).unwrap();
            assert_eq!(is_key_type(t), (0x21..0x7f).contains(&c), "{c:#x}");
        }
    }

    #[test]
    fn accounts_to_the_top() {
        let r = h32(CASES[0].r);
        let top = stateless_seed(&r, KEY_TYPE, u32::MAX).unwrap();
        assert_ne!(top, stateless_seed(&r, KEY_TYPE, 0).unwrap());
        let mut data = [0u8; 68];
        data[..32].copy_from_slice(&r);
        data[32..36].copy_from_slice(&[0xff; 4]);
        data[36..].copy_from_slice(&keccak256(KEY_TYPE.as_bytes()));
        assert_eq!(top, crate::keccak::keccak256_parts(&[&keccak256(STATELESS_TAG.as_bytes()), &data]));
        assert_ne!(app_secret(&r, LABEL, u32::MAX), app_secret(&r, LABEL, 0));
    }
}
