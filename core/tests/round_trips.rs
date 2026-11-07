//! Round trips (sign then verify, encode then parse) on inputs the vectors don't cover, and the
//! refusals around them. Runs natively and under Node (WebAssembly).

mod common;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use winterlock_core::keccak::{self, keccak256};
use winterlock_core::keylog::{self, MemoryLog, TreeRef};
use winterlock_core::safe::SafeTx;
use winterlock_core::{U256, leansphincs, owner, phrase, safe, wots};

fn k(label: &str, i: u32) -> [u8; 32] {
    keccak::keccak256_parts(&[label.as_bytes(), &i.to_be_bytes()])
}

#[test]
fn phrases() {
    for i in 0..64 {
        let seed = k("seed", i);
        let words = phrase::to_phrase(&seed);
        assert_eq!(phrase::to_seed(&words.join(" ")), Ok(seed));
        assert_eq!(phrase::to_seed(&words.map(|w| &w[..w.len().min(4)]).join(",")), Ok(seed));
        // another last word: the checksum catches it, except for the 1 in 256 it doesn't
        let mut other = words;
        let ix = phrase::index_of(words[23]).unwrap();
        other[23] = phrase::wordlist()[(ix as usize + 1) % 2048];
        match phrase::from_words(&other) {
            Err(phrase::PhraseError::Checksum) => {}
            Ok(s) => assert_ne!(s, seed),
            Err(e) => panic!("{e}"),
        }
    }
}

#[test]
fn leansphincs_small_keys() {
    for i in 0..3 {
        let key = leansphincs::Key::new(&k("ls", i), 4 + i).unwrap();
        let pk = key.public_key();
        let again = leansphincs::Key::from_leaves(&k("ls", i), 4 + i, key.kept_leaves().to_vec()).unwrap();
        assert_eq!(again.public_key(), pk);
        for j in 0..2 {
            let m = k("m", j);
            let sig = key.sign(&m);
            assert_eq!(sig.len(), leansphincs::SIG_BYTES);
            assert!(leansphincs::verify(&pk, &m, &sig));
            assert!(!leansphincs::verify(&pk, &k("m", j + 7), &sig));
            let mut bad = sig.clone();
            bad[5000 + j as usize] ^= 0x10;
            assert!(!leansphincs::verify(&pk, &m, &bad));
        }
        // b is part of the key
        assert_ne!(leansphincs::Key::new(&k("ls", i), 5 + i).unwrap().public_key(), pk);
    }
    assert!(leansphincs::Key::new(&k("ls", 0), 27).is_err());
}

#[test]
fn wots_every_key_of_a_small_tree() {
    let seed: wots::Seed = k("tree seed", 0)[..16].try_into().unwrap();
    let sk = k("sk", 0);
    let tree = wots::Tree::create(&seed, &sk, 4, &wots::Prf::SIGNER).unwrap();
    let tr = TreeRef { chain: 42161, safe: [7; 20], root: tree.root, start: 1000, height: 4 };
    let mut log = MemoryLog::default();
    for nonce in 1000..1008u64 {
        for slot in 0..2u8 {
            let tx = SafeTx { to: [9; 20], value: U256::from_u64(nonce * 10 + slot as u64), nonce: U256::from_u64(nonce), ..Default::default() };
            let h = tx.hash(tr.chain, &tr.safe);
            let rec = keylog::record(&mut log, &tr, nonce, &h).unwrap();
            assert_eq!(rec.key_use().slot, slot);
            let data = owner::sign_transaction(&rec, &tree, &sk, 3, &tx).unwrap();
            let p = owner::parse_tx_signature_data(&data).unwrap();
            assert_eq!((p.slot, p.device, p.height()), (slot, 3, 4));
            let ki = owner::key_index(nonce, tr.start, slot, 4).unwrap();
            assert_eq!(ki, rec.key_use().key_index);
            let hw = safe::hash_of_words(tr.chain, &p.safe, &p.words);
            assert_eq!(wots::verify_root(&seed, ki, &hw, p.wots_sig, p.path), Some(tree.root));
        }
        // a third version at the nonce is refused, and the log is unchanged
        let n = log.uses.len();
        assert!(matches!(keylog::record(&mut log, &tr, nonce, &[0xee; 32]), Err(keylog::Refused::ThirdVersion { .. })));
        assert_eq!(log.uses.len(), n);
    }
    assert!(matches!(keylog::record(&mut log, &tr, 1008, &[1; 32]), Err(keylog::Refused::NotInTree(_))));
    // a record of another tree doesn't sign with this one
    let other = wots::Tree::create(&seed, &k("sk", 1), 4, &wots::Prf::SIGNER).unwrap();
    let tr2 = TreeRef { root: other.root, ..tr };
    let rec = keylog::record(&mut log, &tr2, 1000, &[2; 32]).unwrap();
    assert!(wots::sign_recorded(&rec, &tree, &sk, &wots::Prf::SIGNER).is_err());
    // the wrong secret seed fails its own check and releases nothing
    let rec = keylog::record(&mut log, &tr2, 1001, &[3; 32]).unwrap();
    assert_eq!(wots::sign_recorded(&rec, &other, &sk, &wots::Prf::SIGNER), Err(winterlock_core::Error::SelfCheck("WOTS signature")));
}

#[test]
fn python_edges() {
    // phrase.matches indexes words[position - 1]: position 0 is the last word
    let words = phrase::to_phrase(&[0; 32]);
    assert!(phrase::matches(&words, 0, words[23]));
    assert!(!phrase::matches(&words, 25, words[23]));
    // owner.key_index takes heights above 40 (no certificate does)
    assert_eq!(owner::key_index(5, 0, 1, 41), Ok(11));
    assert_eq!(owner::capacity(64), Ok(1 << 63));
    assert!(owner::key_index(0, 0, 0, 0).is_err());
}

#[test]
fn amounts_and_decimals() {
    for i in 0..200u32 {
        let v = U256(keccak256(&i.to_be_bytes()));
        let v = if i % 3 == 0 { U256::from_u128(u128::from_be_bytes(v.0[..16].try_into().unwrap())) } else { v };
        assert_eq!(U256::from_dec_str(&v.to_dec_string()), Some(v));
    }
    assert_eq!(U256::from_u64(50_000_000_000_000_000).format_units(18), "0.05");
    assert_eq!(U256::from_u64(1_000_000).format_units(6), "1");
    assert_eq!(U256::from_u64(1_234_500).format_units(6), "1.2345");
    assert!(U256::from_dec_str("").is_none());
    assert!(U256::from_dec_str("1e18").is_none());
}

#[test]
fn keccak_backends_agree() {
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    let want = keccak256(&data);
    for b in [keccak::Backend::TinyKeccak, keccak::Backend::RustCrypto] {
        if keccak::set_backend(b) {
            assert_eq!(keccak::backend(), b);
            assert_eq!(keccak256(&data), want, "{}", b.name());
            assert_eq!(hex(&keccak256(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        }
    }
    let first = if cfg!(feature = "tiny-keccak") { keccak::Backend::TinyKeccak } else { keccak::Backend::RustCrypto };
    assert!(keccak::set_backend(first));
}

fn hex(b: &[u8]) -> String {
    winterlock_core::hex::encode(b)
}
