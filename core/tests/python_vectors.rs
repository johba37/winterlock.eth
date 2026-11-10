//! The core against the Python signer's outputs (signer/tools/core_vectors.py) and the upstream
//! leanSphincs-keccak known answers, byte for byte. Runs natively and under Node (WebAssembly).

mod common;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use common::*;
use winterlock_core::keylog::{self, KeyLogStore, MemoryLog, Refused, TreeRef};
use winterlock_core::phrase::{self, PhraseError};
use winterlock_core::{U256, derive, hex, keccak::keccak256, leansphincs, owner, safe, wordlist, wots};

// --- phrase ---

#[test]
fn phrase_tables_match_python() {
    let v = load(PHRASE);
    let words: Vec<&str> = v["words"].as_array().unwrap().iter().map(str_).collect();
    assert_eq!(words.as_slice(), phrase::wordlist().as_slice());
    let spaces: Vec<u32> = v["spaces"].as_array().unwrap().iter().map(|c| uint(c) as u32).collect();
    assert_eq!(spaces, wordlist::SPACES.iter().map(|&c| c as u32).collect::<Vec<_>>());
    let digits: Vec<u32> = v["digits"].as_array().unwrap().iter().map(|c| uint(c) as u32).collect();
    let ours: Vec<u32> = wordlist::DIGITS.iter().flat_map(|&(a, b)| a as u32..=b as u32).collect();
    assert_eq!(digits, ours);
}

#[test]
fn phrase_round_trips_and_parses() {
    let v = load(PHRASE);
    for c in v["round_trips"].as_array().unwrap() {
        let seed: [u8; 32] = arr(&c["seed"]);
        let words = phrase::to_phrase(&seed);
        assert_eq!(words.join(" "), str_(&c["words"]));
        assert_eq!(phrase::to_seed(str_(&c["words"])).unwrap(), seed);
        assert_eq!(phrase::from_words(&words).unwrap(), seed);
    }
    for c in v["parses"].as_array().unwrap() {
        assert_eq!(phrase::to_seed(str_(&c["text"])), Ok(arr(&c["seed"])), "{:?}", c["text"]);
    }
}

#[test]
fn phrase_errors_name_the_problem() {
    let v = load(PHRASE);
    for c in v["errors"].as_array().unwrap() {
        let got = phrase::to_seed(str_(&c["text"])).unwrap_err();
        let want = match str_(&c["error"]) {
            "count" => PhraseError::WordCount(uint(&c["count"]) as usize),
            "word" => PhraseError::UnknownWord {
                position: uint(&c["position"]) as usize,
                token: str_(&c["token"]).into(),
            },
            "checksum" => PhraseError::Checksum,
            e => panic!("unknown error kind {e}"),
        };
        assert_eq!(got, want, "{:?}", c["text"]);
    }
    for c in v["word_cases"].as_array().unwrap() {
        assert_eq!(phrase::word(str_(&c["token"])), c["word"].as_str(), "{:?}", c["token"]);
    }
    let words = phrase::to_phrase(&arr(&v["round_trips"][3]["seed"]));
    for c in v["match_cases"].as_array().unwrap() {
        let got = phrase::matches(&words, uint(&c["position"]) as usize, str_(&c["answer"]));
        assert_eq!(got, c["matches"].as_bool().unwrap(), "{c}");
    }
}

#[test]
fn check_codes() {
    let v = load(PHRASE);
    for c in v["check_codes"].as_array().unwrap() {
        let code = phrase::check_code_text(&address(&c["owner"]), uint(&c["device"]) as u8, &arr(&c["key"]));
        assert_eq!(code, str_(&c["code"]));
    }
}

// --- keys ---

#[test]
fn member_and_device_keys() {
    let v = load(KEYS);
    for c in v["keys"].as_array().unwrap() {
        let seed: [u8; 32] = arr(&c["seed"]);
        assert_eq!(derive::member_key_seed(&seed), arr::<32>(&c["member_key_seed"]));
        let mk = derive::member_key(&seed).unwrap();
        assert_eq!(mk.public_key(), arr::<32>(&c["member_key"]));
        assert_eq!(mk.p(), arr::<16>(&c["member_p"]));
        assert_eq!(mk.subtree() as u64, uint(&c["member_s"]));
        assert_eq!(keccak256(&mk.kept_leaves_bytes()), arr::<32>(&c["member_leaves_hash"]));
        for (i, l) in c["member_leaves_first"].as_array().unwrap().iter().enumerate() {
            assert_eq!(mk.kept_leaves()[i], arr::<16>(l));
        }
        assert_eq!(owner::owner_address(&mk.public_key()).unwrap(), address(&c["owner"]));
        assert_eq!(derive::device_key_seed(&seed), arr::<32>(&c["device_key_seed"]));
        assert_eq!(derive::device_key(&seed).unwrap().public_key(), arr::<32>(&c["device_key"]));
        assert_eq!(derive::gas_key(&seed).unwrap(), arr::<32>(&c["gas_key"]));
    }
}

#[test]
fn key_from_split_leaves() {
    // the two-core split: leaves in two ranges, joined
    let v = load(KEYS);
    let c = &v["keys"][3];
    let ks = derive::member_key_seed(&arr(&c["seed"]));
    let plan = leansphincs::plan(&ks, 10).unwrap();
    let mut ls = vec![[0u8; 16]; plan.count as usize];
    let (a, b) = ls.split_at_mut(300);
    leansphincs::leaves(&plan.p, &ks, plan.first + 300, b);
    leansphincs::leaves(&plan.p, &ks, plan.first, a);
    let key = leansphincs::Key::from_leaves(&ks, 10, ls).unwrap();
    assert_eq!(key.public_key(), arr::<32>(&c["member_key"]));
    assert!(leansphincs::Key::from_leaves(&ks, 10, vec![[0; 16]; 1023]).is_err());
}

#[test]
fn tree_secret_seeds() {
    let v = load(KEYS);
    for c in v["tree_secrets"].as_array().unwrap() {
        let at = derive::TreePlace {
            chain: uint(&c["chain"]),
            owner: address(&c["owner"]),
            safe: address(&c["safe"]),
            device: uint(&c["device"]) as u8,
            generation: uint(&c["gen"]) as u16,
            start: uint(&c["start"]),
        };
        assert_eq!(derive::tree_secret_seed(&arr(&c["seed"]), &at, &arr(&c["salt"])), arr::<32>(&c["sk_seed"]));
        assert_eq!(derive::tree_public_seed(&at), arr::<16>(&c["tree_seed"]));
    }
}

// --- leanSphincs ---

#[test]
fn leansphincs_signatures() {
    let v = load(LEANSPHINCS);
    let key = leansphincs::Key::new(&arr(&v["key_seed"]), uint(&v["b"]) as u32).unwrap();
    let pk = key.public_key();
    assert_eq!(pk, arr::<32>(&v["public_key"]));
    for c in v["signatures"].as_array().unwrap() {
        let m: [u8; 32] = arr(&c["message"]);
        let sig = key.sign(&m);
        assert_eq!(hex::encode0x(&sig), str_(&c["sig"]), "grind {}", c["grind_tries"]);
        assert!(leansphincs::verify(&pk, &m, &sig));
        assert_eq!(leansphincs::signature_counter(&sig), Some(uint(&c["counter"]) as u32));
        let fors: Vec<u64> = c["fors_indices"].as_array().unwrap().iter().map(uint).collect();
        let rho: [u8; 16] = sig[..16].try_into().unwrap();
        assert_eq!(leansphincs::fors_indices(&key.p(), &m, &rho).map(|x| x as u64).to_vec(), fors);
    }
    let b6 = &v["b6"];
    let small = leansphincs::Key::new(&arr(&b6["key_seed"]), 6).unwrap();
    assert_eq!(small.public_key(), arr::<32>(&b6["public_key"]));
    assert_eq!(small.sign(&arr(&b6["message"])), bytes(&b6["sig"]));
}

/// A signature in parts, as a board spreads it over two cores: the randomizer candidates in
/// chunks taken in turn by "two cores", the least hit, the FORS trees split in two, then finish.
/// Python's signatures, byte for byte.
#[test]
fn leansphincs_signatures_in_parts() {
    let v = load(LEANSPHINCS);
    let key = leansphincs::Key::new(&arr(&v["key_seed"]), uint(&v["b"]) as u32).unwrap();
    const CHUNK: u64 = 1000;
    for c in v["signatures"].as_array().unwrap() {
        let m: [u8; 32] = arr(&c["message"]);
        let mut round = 0u64;
        let i = loop {
            let a = key.grind_range(&m, 2 * round * CHUNK, CHUNK);
            let b = key.grind_range(&m, (2 * round + 1) * CHUNK, CHUNK);
            if let Some(i) = a.or(b) {
                break i;
            }
            round += 1;
        };
        assert_eq!(i + 1, uint(&c["grind_tries"]), "Python's grind tries");
        let mut fors = key.fors_part(&m, i, 0..13).unwrap();
        fors.extend(key.fors_part(&m, i, 13..24).unwrap());
        assert_eq!(fors.len(), 24 * leansphincs::FORS_PART);
        let sig = key.finish(&m, i, &fors).unwrap();
        assert_eq!(hex::encode0x(&sig), str_(&c["sig"]));
        // another candidate that hits gives another valid signature; one that misses is refused
        let next = key.grind_range(&m, i + 1, u64::MAX).unwrap();
        let mut fors2 = key.fors_part(&m, next, 0..24).unwrap();
        let sig2 = key.finish(&m, next, &fors2).unwrap();
        assert_ne!(sig2, sig);
        assert!(leansphincs::verify(&key.public_key(), &m, &sig2));
        if i > 0 {
            assert!(key.fors_part(&m, i - 1, 0..1).is_err());
            assert!(key.finish(&m, i - 1, &fors).is_err());
        }
        fors2.pop();
        assert!(key.finish(&m, next, &fors2).is_err());
        assert!(key.fors_part(&m, i, 20..25).is_err());
    }
}

#[test]
fn leansphincs_refuses_changes() {
    let v = load(LEANSPHINCS);
    let pk: [u8; 32] = arr(&v["public_key"]);
    let c = &v["signatures"][0];
    let m: [u8; 32] = arr(&c["message"]);
    let sig = bytes(&c["sig"]);
    assert!(leansphincs::verify(&pk, &m, &sig));
    for pos in positions(sig.len()) {
        let mut bad = sig.clone();
        bad[pos] ^= 1;
        assert!(!leansphincs::verify(&pk, &m, &bad), "byte {pos}");
    }
    let mut m2 = m;
    m2[31] ^= 1;
    assert!(!leansphincs::verify(&pk, &m2, &sig));
    let mut pk2 = pk;
    pk2[0] ^= 1;
    assert!(!leansphincs::verify(&pk2, &m, &sig));
    assert!(!leansphincs::verify(&pk, &m, &sig[..sig.len() - 1]));
}

#[test]
fn leansphincs_upstream_known_answers() {
    let v = load(KAT);
    let vs = v["vectors"].as_array().unwrap();
    assert_eq!(vs.len(), 6);
    for c in vs {
        let key = leansphincs::Key::new(&arr(&c["seed"]), uint(&c["b"]) as u32).unwrap();
        let mut pk_seed = [0u8; 32];
        pk_seed[..16].copy_from_slice(&key.p());
        assert_eq!(pk_seed, arr::<32>(&c["pkSeed"]), "{}", c["label"]);
        let mut pk_root = [0u8; 32];
        pk_root[..16].copy_from_slice(&key.root());
        assert_eq!(pk_root, arr::<32>(&c["pkRoot"]), "{}", c["label"]);
        let m: [u8; 32] = arr(&c["message"]);
        let sig = key.sign(&m);
        assert_eq!(hex::encode0x(&sig), str_(&c["sig"]), "{}", c["label"]);
        assert_eq!(sig[..16], bytes(&c["randomizer"])[..]);
        assert_eq!(leansphincs::signature_counter(&sig), Some(uint(&c["counter"]) as u32));
        let rho: [u8; 16] = sig[..16].try_into().unwrap();
        assert_eq!(leansphincs::signature_leaf_index(&key.p(), &m, &rho) as u64, uint(&c["idx"]));
        let fors: Vec<u64> = c["fors_indices"].as_array().unwrap().iter().map(uint).collect();
        assert_eq!(leansphincs::fors_indices(&key.p(), &m, &rho).map(|x| x as u64).to_vec(), fors);
        assert!(leansphincs::verify(&key.public_key(), &m, &sig));
    }
}

#[test]
fn leansphincs_upstream_crate_answer() {
    // key_gen(seed(1), 11), seed(x)[i] = 31x + i, m[i] = 7i (contracts/test/StatelessVerifier.t.sol)
    let seed: [u8; 32] = core::array::from_fn(|i| (31 + i) as u8);
    let m: [u8; 32] = core::array::from_fn(|i| (7 * i) as u8);
    let key = leansphincs::Key::new(&seed, 11).unwrap();
    assert_eq!(hex::encode(&key.public_key()), "63b118353523319f8f74f387824956482e582128e480149accc2ed4f19edcd00");
    let sig = key.sign(&m);
    assert_eq!(hex::encode(&keccak256(&sig)), "9a21b6bc61d6ba500b4d67809912c1424be1f58486eda144e4ef70afd01cf94d");
    assert_eq!(leansphincs::signature_counter(&sig), Some(1176));
}

// --- WOTS ---

fn tree_ref(place: &serde_json::Value, root: wots::Value, height: u32) -> TreeRef {
    TreeRef { chain: uint(&place["chain"]), safe: address(&place["safe"]), root, start: uint(&place["start"]), height }
}

#[test]
fn wots_trees_and_signatures() {
    let v = load(WOTS);
    assert_eq!(uint(&v["params"]), wots::PARAMS);
    for t in v["trees"].as_array().unwrap() {
        let height = uint(&t["height"]) as u32;
        let seed: wots::Seed = arr(&t["tree_seed"]);
        let sk: [u8; 32] = arr(&t["sk_seed"]);
        let place = &t["place"];
        let at = derive::TreePlace {
            chain: uint(&place["chain"]),
            owner: address(&place["owner"]),
            safe: address(&place["safe"]),
            device: uint(&place["device"]) as u8,
            generation: uint(&place["gen"]) as u16,
            start: uint(&place["start"]),
        };
        assert_eq!(derive::tree_public_seed(&at), seed);
        assert_eq!(derive::tree_secret_seed(&arr(&load(BOARD)["seed"]), &at, &arr(&place["salt"])), sk);
        // two halves, as two cores make them
        let mut ls = vec![[0u8; 24]; 1 << height];
        let (a, b) = ls.split_at_mut(1 << (height - 1));
        wots::leaves(&seed, &sk, 1 << (height - 1), &wots::Prf::SIGNER, b);
        wots::leaves(&seed, &sk, 0, &wots::Prf::SIGNER, a);
        let tree = wots::Tree::from_leaves(&seed, height, height, ls, vec![]).unwrap();
        assert_eq!(tree, wots::Tree::create(&seed, &sk, height, &wots::Prf::SIGNER).unwrap());
        assert_eq!(tree.root, arr::<24>(&t["root"]));
        assert_eq!(keccak256(&tree.leaves().concat()), arr::<32>(&t["leaves_hash"]));
        for (i, l) in t["leaves_first"].as_array().unwrap().iter().enumerate() {
            assert_eq!(tree.leaves()[i], arr::<24>(l));
        }
        let cache = tree.to_bytes();
        assert_eq!(keccak256(&cache), arr::<32>(&t["cache_hash"]));
        assert_eq!(wots::Tree::from_bytes(&cache).unwrap(), tree);
        let tr = tree_ref(place, tree.root, height);
        let mut log = MemoryLog::default();
        for s in t["signatures"].as_array().unwrap() {
            let tx = safe_tx(&s["tx"]);
            let h = tx.hash(tr.chain, &tr.safe);
            assert_eq!(h, arr::<32>(&s["hash"]));
            let nonce = tx.nonce.to_u64().unwrap();
            assert_eq!(nonce, uint(&s["nonce"]));
            let slot = uint(&s["slot"]) as u8;
            let rec = keylog::record_sign(&mut log, &tr, nonce, slot, &h).unwrap();
            assert_eq!(rec.key_use().key_index, uint(&s["key_index"]));
            let (sig, path) = wots::sign_recorded(&rec, &tree, &sk, &wots::Prf::SIGNER).unwrap();
            assert_eq!(hex::encode0x(&sig), str_(&s["sig"]));
            assert_eq!(hex::encode0x(&path), str_(&s["path"]));
            let (_, _, tries) = wots::encode(&seed, &sk, rec.key_use().key_index, &h, &wots::Prf::SIGNER).unwrap();
            assert_eq!(tries as u64, uint(&s["tries"]));
            let data = owner::sign_transaction(&rec, &tree, &sk, 0, &tx).unwrap();
            assert_eq!(hex::encode0x(&data), str_(&s["data"]));
            let k = rec.key_use().key_index;
            assert_eq!(wots::verify_root(&seed, k, &h, &sig, &path), Some(tree.root));
            // a changed byte anywhere, another message or key index: not the root
            for pos in positions(sig.len()) {
                let mut bad = sig.clone();
                bad[pos] ^= 1;
                assert_ne!(wots::verify_root(&seed, k, &h, &bad, &path), Some(tree.root), "sig byte {pos}");
            }
            for pos in positions(path.len()) {
                let mut bad = path.clone();
                bad[pos] ^= 0x80;
                assert_ne!(wots::verify_root(&seed, k, &h, &sig, &bad), Some(tree.root), "path byte {pos}");
            }
            let mut h2 = h;
            h2[0] ^= 1;
            assert_ne!(wots::verify_root(&seed, k, &h2, &sig, &path), Some(tree.root));
            assert_ne!(wots::verify_root(&seed, k ^ 1, &h, &sig, &path), Some(tree.root));
            assert_eq!(wots::verify_root(&seed, k, &h, &sig[1..], &path), None);
        }
    }
}

#[test]
fn wots_leaves_prf_and_test_trees() {
    let v = load(WOTS);
    for c in v["leaves"].as_array().unwrap() {
        let seed: wots::Seed = arr(&c["seed"]);
        let sk: [u8; 32] = arr(&c["sk_seed"]);
        let ki = uint(&c["key_index"]);
        assert_eq!(wots::leaf(&seed, &sk, ki, &wots::Prf::SIGNER), arr::<24>(&c["signer"]));
        assert_eq!(wots::leaf(&seed, &sk, ki, &wots::Prf::TEST), arr::<24>(&c["test"]));
    }
    let p = &v["partial"];
    let (seed, sk): (wots::Seed, [u8; 32]) = (arr(&p["seed"]), arr(&p["sk_seed"]));
    let t = wots::Tree::create_partial(&seed, &sk, uint(&p["height"]) as u32, uint(&p["k"]) as u32, &wots::Prf::TEST).unwrap();
    assert_eq!(t.root, arr::<24>(&p["root"]));
    assert_eq!(t.path(5).unwrap(), bytes(&p["path5"]));
    assert_eq!(t.to_bytes(), bytes(&p["cache"]));
    assert_eq!(wots::Tree::from_bytes(&bytes(&p["cache"])).unwrap(), t);
    assert!(t.path(16).is_err());
    let sk: [u8; 32] = arr(&v["leaves"][0]["sk_seed"]);
    for c in v["prf"].as_array().unwrap() {
        let prf = if str_(&c["prf"]) == "signer" { wots::Prf::SIGNER } else { wots::Prf::TEST };
        assert_eq!(prf.secret(&sk, 7, 47), arr::<24>(&c["secret"]));
        assert_eq!(prf.randomizer(&sk, 7, &keccak256(b"m"), 12345), arr::<24>(&c["randomizer"]));
        assert_eq!(prf.upper_sibling(&sk, 9), arr::<24>(&c["sibling"]));
    }
}

// --- Safe ---

#[test]
fn safe_tx_hashes() {
    let v = load(SAFE);
    let th = &v["typehashes"];
    assert_eq!(safe::DOMAIN_TYPEHASH, arr::<32>(&th["domain"]));
    assert_eq!(safe::DOMAIN_TYPEHASH, keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)"));
    assert_eq!(safe::SAFE_TX_TYPEHASH, arr::<32>(&th["safe_tx"]));
    assert_eq!(
        safe::SAFE_TX_TYPEHASH,
        keccak256(b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
    );
    assert_eq!(safe::SAFE_MSG_TYPEHASH, arr::<32>(&th["safe_message"]));
    assert_eq!(safe::SAFE_MSG_TYPEHASH, keccak256(b"SafeMessage(bytes message)"));
    for c in v["cases"].as_array().unwrap() {
        let tx = safe_tx(&c["tx"]);
        let chain = uint(&c["chain"]);
        let sf = address(&c["safe"]);
        let words: Vec<[u8; 32]> = c["words"].as_array().unwrap().iter().map(arr).collect();
        assert_eq!(tx.words().to_vec(), words);
        assert_eq!(tx.encode().to_vec(), words.concat());
        assert_eq!(tx.struct_hash(), arr::<32>(&c["struct_hash"]));
        assert_eq!(safe::domain_separator(chain, &sf), arr::<32>(&c["domain_separator"]));
        assert_eq!(tx.hash(chain, &sf), arr::<32>(&c["hash"]));
        assert_eq!(safe::hash_of_words(chain, &sf, &tx.words()), arr::<32>(&c["hash"]));
        assert_eq!(tx.preimage(chain, &sf).to_vec(), bytes(&c["preimage"]));
    }
    for c in v["safe_messages"].as_array().unwrap() {
        let app = bytes(&c["app_hash"]);
        assert_eq!(safe::message_hash(&app), arr::<32>(&c["message_hash"]));
        assert_eq!(safe::safe_message_hash(uint(&c["chain"]), &address(&c["safe"]), &app), arr::<32>(&c["safe_message_hash"]));
    }
    for c in v["personal"].as_array().unwrap() {
        assert_eq!(safe::personal_hash(&bytes(&c["message"])), arr::<32>(&c["hash"]));
    }
    for c in v["amounts"].as_array().unwrap() {
        assert_eq!(u256(&c["wei"]).fmt_eth(), str_(&c["fmt"]));
    }
    for c in v["checksums"].as_array().unwrap() {
        let a = address(c);
        assert_eq!(hex::checksum(&a), str_(c));
        let lower = str_(c).to_lowercase();
        assert_eq!(hex::parse_address(&lower).unwrap(), a);
        let mut wrong: Vec<char> = str_(c).chars().collect();
        if let Some(i) = wrong.iter().position(|ch| ch.is_ascii_alphabetic() && *ch != 'x') {
            wrong[i] = if wrong[i].is_ascii_uppercase() { wrong[i].to_ascii_lowercase() } else { wrong[i].to_ascii_uppercase() };
            let w: String = wrong.into_iter().collect();
            let mixed = w[2..].chars().any(|c| c.is_ascii_lowercase()) && w[2..].chars().any(|c| c.is_ascii_uppercase());
            if mixed {
                assert!(hex::parse_address(&w).is_err(), "{w}");
            }
        }
    }
}

// --- owner v2 ---

#[test]
fn owner_constants_and_pinned_addresses() {
    let v = load(OWNER);
    let d = &v["domains"];
    for (name, value, text) in [
        ("DEVICE_DOMAIN", owner::DEVICE_DOMAIN, "Winterlock.safe-owner.device.v2"),
        ("REVOCATION_DOMAIN", owner::REVOCATION_DOMAIN, "Winterlock.safe-owner.revocation.v2"),
        ("CERTIFICATE_DOMAIN", owner::CERTIFICATE_DOMAIN, "Winterlock.safe-owner.certificate.v2"),
        ("MESSAGE_DOMAIN", owner::MESSAGE_DOMAIN, "Winterlock.safe-owner.message.v2"),
        ("TREE_SEED_DOMAIN", owner::TREE_SEED_DOMAIN, "Winterlock.safe-owner.tree-seed.v2"),
        ("VERIFIER_SALT", owner::VERIFIER_SALT, "Winterlock.stateless-verifier.v1"),
        ("WOTS_VERIFIER_SALT", owner::WOTS_VERIFIER_SALT, "Winterlock.wots-verifier.v1"),
        ("IMPLEMENTATION_SALT", owner::IMPLEMENTATION_SALT, "Winterlock.safe-owner.implementation.v2"),
        ("FACTORY_SALT", owner::FACTORY_SALT, "Winterlock.safe-owner.factory.v2"),
    ] {
        assert_eq!(value, arr::<32>(&d[name]), "{name}");
        assert_eq!(value, keccak256(text.as_bytes()), "{name}");
    }
    let p = &v["pinned"];
    assert_eq!(owner::PROXY, address(&p["proxy"]));
    assert_eq!(uint(&p["params"]), wots::PARAMS);
    // the pinned addresses, derived from the pinned creation code as the Python signer does
    let c = load(CONTRACTS);
    assert_eq!(str_(&c["commit"]), str_(&p["commit"]));
    let code = |name: &str| bytes(&c[name]["creation_code"]);
    let verifier = owner::verifier_address(&code("LeanSphincsAsm"));
    let wots_verifier = owner::wots_verifier_address(&code("SharedWotsVerifier"));
    let implementation = owner::implementation_address(&code("WinterlockOwner"), wots::PARAMS, &verifier, &wots_verifier);
    let factory = owner::factory_address(&code("WinterlockOwnerFactory"), &implementation);
    for (ours, derived, py) in [
        (owner::VERIFIER, verifier, &p["verifier"]),
        (owner::WOTS_VERIFIER, wots_verifier, &p["wots_verifier"]),
        (owner::IMPLEMENTATION, implementation, &p["implementation"]),
        (owner::FACTORY, factory, &p["factory"]),
    ] {
        assert_eq!(ours, derived);
        assert_eq!(ours, address(py));
    }
}

#[test]
fn owner_digests_and_key_indices() {
    let v = load(OWNER);
    for c in v["digests"].as_array().unwrap() {
        let (chain, o, sf) = (uint(&c["chain"]), address(&c["owner"]), address(&c["safe"]));
        let (dev, generation) = (uint(&c["device"]) as u8, uint(&c["generation"]) as u16);
        let (height, start) = (uint(&c["height"]) as u32, uint(&c["start"]));
        assert_eq!(owner::device_digest(chain, &o, dev, generation, &arr(&c["key"])), arr::<32>(&c["device_digest"]));
        assert_eq!(owner::revocation_digest(chain, &o, dev, generation), arr::<32>(&c["revocation_digest"]));
        assert_eq!(
            owner::certificate_digest(chain, &o, &sf, dev, generation, &arr(&c["root"]), height, start),
            arr::<32>(&c["certificate_digest"])
        );
        assert_eq!(owner::message_digest(chain, &o, &sf, dev, generation, &arr(&c["smh"])), arr::<32>(&c["message_digest"]));
        assert_eq!(owner::tree_seed(chain, &o, &sf, dev, generation, start), arr::<16>(&c["tree_seed"]));
    }
    for c in v["key_indices"].as_array().unwrap() {
        let got = owner::key_index(uint(&c["nonce"]), uint(&c["start"]), uint(&c["slot"]) as u8, uint(&c["height"]) as u32);
        match c.get("index") {
            Some(i) => assert_eq!(got, Ok(uint(i)), "{c}"),
            None => assert_eq!(got.unwrap_err().to_string(), str_(&c["error"]), "{c}"),
        }
    }
}

#[test]
fn owner_addresses() {
    let v = load(OWNER);
    for c in v["addresses"].as_array().unwrap() {
        let key: [u8; 32] = arr(&c["key"]);
        assert_eq!(owner::owner_address(&key).unwrap(), address(&c["owner"]));
        assert_eq!(owner::proxy_init_code(&owner::IMPLEMENTATION, &key).unwrap().to_vec(), bytes(&c["init_code"]));
        assert_eq!(owner::proxy_runtime(&owner::IMPLEMENTATION, &key).to_vec(), bytes(&c["runtime"]));
    }
    for c in v["member_key_of"].as_array().unwrap() {
        let got = owner::member_key_of(&address(&c["address"]), &bytes(&c["code"]));
        assert_eq!(got, c["key"].as_str().map(|_| arr::<32>(&c["key"])));
    }
    let mut half_zero = [0u8; 32];
    half_zero[0] = 1;
    assert!(owner::owner_address(&half_zero).is_err());
}

#[test]
fn owner_signature_layouts() {
    let v = load(OWNER);
    let l = &v["layouts"];
    // transaction: built through the key log, then parsed back
    let t = &l["tx"];
    let place = &t["tree"];
    let board = load(BOARD);
    let at = derive::TreePlace {
        chain: uint(&place["chain"]),
        owner: address(&place["owner"]),
        safe: address(&place["safe"]),
        device: 0,
        generation: 0,
        start: uint(&place["start"]),
    };
    let sk = derive::tree_secret_seed(&arr(&board["seed"]), &at, &arr(&place["salt"]));
    let tree = wots::Tree::create(&derive::tree_public_seed(&at), &sk, 6, &wots::Prf::SIGNER).unwrap();
    assert_eq!(tree.root, arr::<24>(&t["root"]));
    let tx = safe_tx(&t["tx"]);
    let tr = tree_ref(place, tree.root, 6);
    let h = tx.hash(tr.chain, &tr.safe);
    assert_eq!(h, arr::<32>(&t["hash"]));
    let mut log = MemoryLog::default();
    let rec = keylog::record_sign(&mut log, &tr, tx.nonce.to_u64().unwrap(), uint(&t["slot"]) as u8, &h).unwrap();
    let data = owner::sign_transaction(&rec, &tree, &sk, uint(&t["device"]) as u8, &tx).unwrap();
    assert_eq!(hex::encode0x(&data), str_(&t["data"]));
    let p = owner::parse_tx_signature_data(&data).unwrap();
    let pp = &t["parsed"];
    assert_eq!((p.slot as u64, p.device as u64), (uint(&pp["slot"]), uint(&pp["device"])));
    assert_eq!(p.safe, address(&pp["safe"]));
    assert_eq!(p.words.to_vec(), pp["words"].as_array().unwrap().iter().map(arr).collect::<Vec<[u8; 32]>>());
    assert_eq!(p.wots_sig, &bytes(&pp["sig"])[..]);
    assert_eq!(p.path, &bytes(&pp["path"])[..]);
    assert_eq!(p.height(), 6);
    assert_eq!(p.nonce(), tx.nonce);
    assert_eq!(safe::hash_of_words(tr.chain, &p.safe, &p.words), h);
    assert!(matches!(owner::parse_signature_data(&data), Some(owner::OwnerSignature::Transaction(_))));
    for bad in l["not_tx"].as_array().unwrap() {
        assert!(owner::parse_tx_signature_data(&bytes(bad)).is_none());
    }
    // a record for another transaction or tree is refused
    let mut other = tx.clone();
    other.value = U256::from_u64(1);
    assert!(owner::sign_transaction(&rec, &tree, &sk, 2, &other).is_err());
    assert!(owner::sign_transaction(&rec, &tree, &sk, 4, &tx).is_err());
    // message: the member key signs the message digest
    let m = &l["message"];
    let key = derive::member_key(&arr(&board["seed"])).unwrap();
    let o = address(&m["owner"]);
    let app = bytes(&m["app_hash"]);
    let smh = safe::safe_message_hash(tr.chain, &tr.safe, &app);
    assert_eq!(smh, arr::<32>(&m["safe_message_hash"]));
    assert_eq!(owner::message_digest(tr.chain, &o, &tr.safe, 0, 0, &smh), arr::<32>(&m["digest"]));
    let data = owner::sign_message(&key, tr.chain, &o, &tr.safe, 0, 0, &app).unwrap();
    assert_eq!(hex::encode0x(&data), str_(&m["data"]));
    let pm = owner::parse_message_signature_data(&data).unwrap();
    assert_eq!((pm.device, pm.safe, pm.msg_hash), (0, tr.safe, safe::message_hash(&app)));
    assert!(leansphincs::verify(&key.public_key(), &arr(&m["digest"]), pm.stateless_sig));
    assert!(owner::parse_message_signature_data(&data[1..]).is_none());
    // approved: no key
    let a = &l["approved"];
    let ad = owner::approved_signature_data(&tr.safe, &arr(&a["msg_hash"]));
    assert_eq!(hex::encode0x(&ad), str_(&a["data"]));
    assert_eq!(owner::parse_approved_signature_data(&ad), Some((tr.safe, arr(&a["msg_hash"]))));
    assert!(matches!(owner::parse_signature_data(&ad), Some(owner::OwnerSignature::Approved { .. })));
    assert!(owner::parse_approved_signature_data(&ad[..52]).is_none());
}

#[test]
fn device_certificate_and_revocation() {
    let v = load(OWNER);
    let c = &v["digests"][4];
    let board = load(BOARD);
    let key = derive::member_key(&arr(&board["seed"])).unwrap();
    let o = address(&c["owner"]);
    let dk: [u8; 32] = arr(&c["key"]);
    let sig = owner::certify_device(&key, uint(&c["chain"]), &o, 1, 1, &dk).unwrap();
    assert!(leansphincs::verify(&key.public_key(), &arr(&c["device_digest"]), &sig));
    assert!(owner::certify_device(&key, uint(&c["chain"]), &o, 0, 1, &dk).is_err());
    let rev = owner::revoke_device(&key, uint(&c["chain"]), &o, 1, 1).unwrap();
    assert!(leansphincs::verify(&key.public_key(), &arr(&c["revocation_digest"]), &rev));
}

// --- the key log ---

#[derive(Debug, PartialEq)]
enum Outcome {
    Signed { slot: u8, already: bool, appended: bool },
    Refused(&'static str),
}

fn run_step<S: KeyLogStore>(store: &mut S, tree: &TreeRef, step: &serde_json::Value) -> Outcome
where
    S::Error: core::fmt::Debug,
{
    let nonce = uint(&step["nonce"]);
    let h: [u8; 32] = arr(&step["hash"]);
    let r = match str_(&step["op"]) {
        "sign" => keylog::record(store, tree, nonce, &h),
        "record" => keylog::record_sign(store, tree, nonce, uint(&step["slot"]) as u8, &h),
        op => panic!("unknown op {op}"),
    };
    match r {
        Ok(rec) => Outcome::Signed { slot: rec.key_use().slot, already: rec.already, appended: !rec.already },
        Err(Refused::ThirdVersion { .. }) => Outcome::Refused("third-version"),
        Err(Refused::KeyReused { .. }) => Outcome::Refused("key-reused"),
        Err(Refused::NotInTree(_)) => Outcome::Refused("not-in-tree"),
        Err(Refused::Store(e)) => panic!("store: {e:?}"),
    }
}

#[test]
fn keylog_scenarios() {
    let v = load(KEYLOG);
    let trees: Vec<TreeRef> = v["trees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| TreeRef {
            chain: uint(&t["chain"]),
            safe: address(&t["safe"]),
            root: arr(&t["root"]),
            start: uint(&t["start"]),
            height: uint(&t["height"]) as u32,
        })
        .collect();
    for s in v["scenarios"].as_array().unwrap() {
        let mut log = MemoryLog::default();
        for step in s["steps"].as_array().unwrap() {
            let e = &step["expect"];
            let want = match e.get("refused") {
                Some(r) => Outcome::Refused(match str_(r) {
                    "third-version" => "third-version",
                    "key-reused" => "key-reused",
                    "not-in-tree" => "not-in-tree",
                    x => panic!("{x}"),
                }),
                None => Outcome::Signed {
                    slot: uint(&e["slot"]) as u8,
                    already: e["already"].as_bool().unwrap(),
                    appended: e["appended"].as_bool().unwrap(),
                },
            };
            let got = run_step(&mut log, &trees[uint(&step["tree"]) as usize], step);
            assert_eq!(got, want, "{}: {step}", s["name"]);
        }
        let uses: Vec<_> = s["uses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| keylog::KeyUse {
                chain: uint(&u["chain"]),
                safe: address(&u["safe"]),
                root: arr(&u["root"]),
                start: uint(&u["start"]),
                nonce: uint(&u["nonce"]),
                slot: uint(&u["slot"]) as u8,
                key_index: uint(&u["key_index"]),
                hash: arr(&u["hash"]),
            })
            .collect();
        assert_eq!(log.uses, uses, "{}", s["name"]);
    }
}

/// A store that fails: nothing is signed.
struct Broken;

impl KeyLogStore for Broken {
    type Error = &'static str;
    fn find_use(&self, _: u64, _: &[u8; 20], _: &wots::Value, _: u64) -> Result<Option<[u8; 32]>, &'static str> {
        Ok(None)
    }
    fn append_use(&mut self, _: &keylog::KeyUse) -> Result<(), &'static str> {
        Err("disk full")
    }
}

#[test]
fn keylog_store_failure_refuses() {
    let tr = TreeRef { chain: 1, safe: [1; 20], root: [2; 24], start: 0, height: 6 };
    assert!(matches!(keylog::record(&mut Broken, &tr, 0, &[3; 32]), Err(Refused::Store("disk full"))));
}

// --- HBKD (draft ERC: Hash-Based Key Derivation from BIP-39) ---

#[cfg(feature = "hbkd")]
fn account(v: &serde_json::Value) -> u32 {
    u32::try_from(uint(v)).expect("an account fits in 32 bits")
}

#[cfg(feature = "hbkd")]
fn word_list(v: &serde_json::Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(str_).collect()
}

/// A derived value against its vector: written out ("value"), or as its SHA-256 when long.
#[cfg(feature = "hbkd")]
fn check_value(c: &serde_json::Value, got: &[u8]) {
    use sha2::{Digest, Sha256};
    assert_eq!(got.len() as u64, uint(&c["length"]), "{c}");
    match c.get("value") {
        Some(v) => assert_eq!(got, bytes(v), "{c}"),
        None => assert_eq!(Sha256::digest(got)[..], arr::<32>(&c["value_sha256"]), "{c}"),
    }
}

#[cfg(feature = "hbkd")]
#[test]
fn hbkd_roots() {
    use winterlock_core::hbkd;
    let v = load(HBKD);
    let mut lengths = Vec::new();
    for c in v["phrases"].as_array().unwrap() {
        let words = word_list(&c["words"]);
        let s = hbkd::bip39_seed(&words, str_(&c["passphrase"])).unwrap();
        assert_eq!(s, arr::<64>(&c["bip39_seed"]), "{c}");
        assert_eq!(hbkd::root(&s), Ok(arr::<64>(&c["root"])), "{c}");
        lengths.push(words.len());
    }
    lengths.sort();
    lengths.dedup();
    assert_eq!(lengths, hbkd::WORD_COUNTS);
    for c in v["winterlock"].as_array().unwrap() {
        let seed: [u8; 32] = arr(&c["seed"]);
        assert_eq!(phrase::to_phrase(&seed).join(" "), str_(&c["words"]));
        assert_eq!(hbkd::winterlock_root(&seed, str_(&c["passphrase"])), Ok(arr(&c["root"])), "{c}");
    }
    let mut ikm_lengths = Vec::new();
    for c in v["random"].as_array().unwrap() {
        let ikm = bytes(&c["ikm"]);
        assert_eq!(hbkd::root(&ikm), Ok(arr(&c["root"])), "{c}");
        ikm_lengths.push(ikm.len());
    }
    assert_eq!(ikm_lengths, [32, 64, 100]);
}

#[cfg(feature = "hbkd")]
#[test]
fn hbkd_derivations() {
    use winterlock_core::hbkd;
    let v = load(HBKD);
    let (mut lengths, mut accounts) = (Vec::new(), Vec::new());
    for c in v["stateless"].as_array().unwrap() {
        let (root, t, a, n) = (arr(&c["root"]), str_(&c["key_type"]), account(&c["account"]), uint(&c["length"]));
        let got = hbkd::stateless_seed(&root, t, n as usize, a).unwrap();
        check_value(c, &got);
        let mut out = vec![0u8; n as usize];
        hbkd::stateless_seed_into(&root, t, a, &mut out).unwrap();
        assert_eq!(out, got);
        lengths.push(n);
        accounts.push(a);
    }
    for c in v["stateful"].as_array().unwrap() {
        let (root, t, a, n) = (arr(&c["root"]), str_(&c["key_type"]), account(&c["account"]), uint(&c["length"]));
        let (ctx, inst) = (arr(&c["context"]), arr(&c["instance"]));
        let got = hbkd::stateful_seed(&root, t, n as usize, &ctx, &inst, a).unwrap();
        check_value(c, &got);
        let mut out = vec![0u8; n as usize];
        hbkd::stateful_seed_into(&root, t, &ctx, &inst, a, &mut out).unwrap();
        assert_eq!(out, got);
        lengths.push(n);
        accounts.push(a);
    }
    let mut labels = Vec::new();
    for c in v["app_secrets"].as_array().unwrap() {
        let (root, lb, a, n) = (arr(&c["root"]), str_(&c["label"]), account(&c["account"]), uint(&c["length"]));
        let got = hbkd::app_secret(&root, lb, n as usize, a).unwrap();
        check_value(c, &got);
        let mut out = vec![0u8; n as usize];
        hbkd::app_secret_into(&root, lb, a, &mut out).unwrap();
        assert_eq!(out, got);
        labels.push(lb.len());
        lengths.push(n);
    }
    lengths.sort();
    lengths.dedup();
    assert_eq!(lengths, [32, 48, 64, 65, 1000, 16320]);
    accounts.sort();
    accounts.dedup();
    assert_eq!(accounts, [0, 1, 1 << 31, u32::MAX]);
    assert!(labels.contains(&1) && labels.contains(&255));
    for c in v["infos"].as_array().unwrap() {
        let got = hbkd::info(
            uint(&c["purpose"]) as u8,
            account(&c["account"]),
            uint(&c["length"]) as usize,
            &bytes(&c["name"]),
            &bytes(&c["tail"]),
        );
        assert_eq!(got, Ok(bytes(&c["info"])), "{c}");
    }
}

#[cfg(feature = "hbkd")]
#[test]
fn hbkd_slh_dsa() {
    use winterlock_core::hbkd;
    let v = load(HBKD);
    let mut names = Vec::new();
    for c in v["slh_dsa"].as_array().unwrap() {
        let (root, t, a) = (arr(&c["root"]), str_(&c["key_type"]), account(&c["account"]));
        let n = uint(&c["n"]) as usize;
        assert_eq!(hbkd::slh_dsa_n(t), Some(n));
        let s = hbkd::slh_dsa_seeds(&root, t, a).unwrap();
        assert_eq!(s.n(), n);
        assert_eq!(s.seed(), bytes(&c["seed"]), "{c}");
        assert_eq!(s.sk_seed(), bytes(&c["sk_seed"]), "{c}");
        assert_eq!(s.sk_prf(), bytes(&c["sk_prf"]), "{c}");
        assert_eq!(s.pk_seed(), bytes(&c["pk_seed"]), "{c}");
        assert_eq!(hbkd::stateless_seed(&root, t, 3 * n, a).unwrap(), bytes(&c["seed"]));
        for bad in [32, 3 * n - 1, 3 * n + 1] {
            assert!(hbkd::stateless_seed(&root, t, bad, a).is_err(), "{t} of {bad} bytes");
        }
        assert!(hbkd::stateful_seed(&root, t, 3 * n, &[0; 32], &[0; 32], a).is_err(), "{t}");
        names.push(t);
    }
    names.sort();
    names.dedup();
    let mut all: Vec<&str> = hbkd::SLH_DSA.iter().map(|&(t, _)| t).collect();
    all.sort();
    assert_eq!(names, all);
}

/// What Python refuses, the core refuses; and what Python normalises (NFKD), the core refuses too,
/// but where the normalised text is ASCII, the core gets Python's seed from it.
#[cfg(feature = "hbkd")]
#[test]
fn hbkd_refusals() {
    use winterlock_core::hbkd;
    let v = load(HBKD);
    let root = arr::<64>(&v["phrases"][0]["root"]);
    let key_type = str_(&v["stateless"][0]["key_type"]);
    for m in v["bad_mnemonics"].as_array().unwrap() {
        let words = word_list(m);
        assert!(hbkd::check_mnemonic(&words).is_err(), "{m}");
        assert!(hbkd::bip39_seed(&words, "").is_err(), "{m}");
    }
    for t in v["bad_key_types"].as_array().unwrap() {
        let t = str_(t);
        assert!(!hbkd::is_key_type(t), "{t:?}");
        assert!(hbkd::stateless_seed(&root, t, 32, 0).is_err(), "{t:?}");
        assert!(hbkd::stateful_seed(&root, t, 32, &[0; 32], &[0; 32], 0).is_err(), "{t:?}");
    }
    for lb in v["bad_labels"].as_array().unwrap() {
        let lb = str_(lb);
        assert!(hbkd::app_secret(&root, lb, 32, 0).is_err(), "{lb:?}");
    }
    for n in v["bad_lengths"].as_array().unwrap() {
        let n = uint(n) as usize;
        let mut out = vec![0u8; n];
        assert!(hbkd::stateless_seed(&root, key_type, n, 0).is_err(), "{n}");
        assert!(hbkd::stateless_seed_into(&root, key_type, 0, &mut out).is_err(), "{n}");
        assert!(hbkd::stateful_seed(&root, key_type, n, &[0; 32], &[0; 32], 0).is_err(), "{n}");
        assert!(hbkd::stateful_seed_into(&root, key_type, &[0; 32], &[0; 32], 0, &mut out).is_err(), "{n}");
        assert!(hbkd::app_secret(&root, "example.app.gas", n, 0).is_err(), "{n}");
        assert!(hbkd::app_secret_into(&root, "example.app.gas", 0, &mut out).is_err(), "{n}");
    }
    for n in v["bad_ikm_lengths"].as_array().unwrap() {
        assert!(hbkd::root(&vec![7u8; uint(n) as usize]).is_err(), "{n}");
    }
    let mut ascii_after_nfkd = 0;
    for c in v["non_ascii"].as_array().unwrap() {
        let (words, p) = (word_list(&c["words"]), str_(&c["passphrase"]));
        assert!(!p.is_ascii());
        assert!(hbkd::bip39_seed(&words, p).is_err(), "{c}");
        let np = str_(&c["nfkd_passphrase"]);
        if np.is_ascii() {
            assert_eq!(hbkd::bip39_seed(&words, np), Ok(arr(&c["bip39_seed"])), "{c}");
            ascii_after_nfkd += 1;
        } else {
            assert!(hbkd::bip39_seed(&words, np).is_err(), "{c}");
        }
    }
    assert!(ascii_after_nfkd > 0);
}
