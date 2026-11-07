//! Native speed of the core, with the inputs of the Python signer's signer/tools/bench.py.
//! usage: cargo run --release --example speed [--features count]

use std::time::Instant;

use winterlock_core::keccak::{self, keccak256};
use winterlock_core::keylog::{self, MemoryLog, TreeRef};
use winterlock_core::{leansphincs, wots};

fn perms() -> String {
    #[cfg(feature = "count")]
    {
        let n = keccak::permutations();
        keccak::reset_permutations();
        format!(", {n} permutations")
    }
    #[cfg(not(feature = "count"))]
    String::new()
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn stats(mut v: Vec<f64>) -> (f64, f64, f64, f64) {
    v.sort_by(f64::total_cmp);
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    (v[0], v[v.len() / 2], mean, v[v.len() - 1])
}

fn main() {
    println!("winterlock-core {}, keccak backend {}", env!("CARGO_PKG_VERSION"), keccak::backend().name());
    let mut seed: wots::Seed = [0; 16];
    seed[14..].copy_from_slice(&0x1234u16.to_be_bytes());
    let sk = keccak256(b"bench");
    let prf = wots::Prf::SIGNER;
    let _ = perms();

    let t = Instant::now();
    let _ = wots::leaf(&seed, &sk, 0, &prf);
    println!("WOTS one-time key (leaf): {:.2} ms{}", ms(t), perms());

    for h in [6u32, 10, 12] {
        let t = Instant::now();
        let tree = wots::Tree::create(&seed, &sk, h, &prf).unwrap();
        let one = ms(t);
        let p1 = perms();
        let t = Instant::now();
        let mut ls = vec![[0u8; 24]; 1 << h];
        let (a, b) = ls.split_at_mut(1 << (h - 1));
        std::thread::scope(|s| {
            s.spawn(|| wots::leaves(&seed, &sk, 1 << (h - 1), &prf, b));
            wots::leaves(&seed, &sk, 0, &prf, a);
        });
        let two = wots::Tree::from_leaves(&seed, h, h, ls, vec![]).unwrap();
        assert_eq!(two.root, tree.root);
        println!("WOTS tree height {h} ({} nonces): {:.0} ms on one thread{p1}, {:.0} ms on two", 1 << (h - 1), one, ms(t));
        let _ = perms();
    }

    let tree = wots::Tree::create(&seed, &sk, 6, &prf).unwrap();
    let tr = TreeRef { chain: 1, safe: [0; 20], root: tree.root, start: 0, height: 6 };
    let mut log = MemoryLog::default();
    let mut ts = vec![];
    let mut counts = vec![];
    for i in 0..20u64 {
        let m = keccak256(format!("{i}").as_bytes());
        let rec = keylog::record_sign(&mut log, &tr, i / 2, (i % 2) as u8, &m).unwrap();
        let _ = perms();
        let t = Instant::now();
        let (sig, path) = wots::sign_recorded(&rec, &tree, &sk, &prf).unwrap();
        ts.push(ms(t));
        counts.push(perms());
        assert_eq!(wots::verify_root(&seed, rec.key_use().key_index, &m, &sig, &path), Some(tree.root));
        let _ = perms();
    }
    let (min, med, mean, max) = stats(ts);
    println!("WOTS signature, checked against the tree: median {med:.2} ms, mean {mean:.2}, min {min:.2}, max {max:.2} (20 signatures)");
    #[cfg(feature = "count")]
    println!("  permutations per signature: {}", counts.join(" ").replace(", ", "").replace(" permutations", ""));
    let _ = counts;

    let ks = keccak256(b"stateless");
    let t = Instant::now();
    let key = leansphincs::Key::new(&ks, 10).unwrap();
    println!("leanSphincs key, b = 10: {:.0} ms on one thread{}", ms(t), perms());
    let t = Instant::now();
    let plan = leansphincs::plan(&ks, 10).unwrap();
    let mut ls = vec![[0u8; 16]; plan.count as usize];
    let (a, b) = ls.split_at_mut(plan.count as usize / 2);
    std::thread::scope(|s| {
        s.spawn(|| leansphincs::leaves(&plan.p, &ks, plan.first + plan.count / 2, b));
        leansphincs::leaves(&plan.p, &ks, plan.first, a);
    });
    let key2 = leansphincs::Key::from_leaves(&ks, 10, ls).unwrap();
    assert_eq!(key2.public_key(), key.public_key());
    println!("leanSphincs key, b = 10: {:.0} ms on two threads", ms(t));
    let _ = perms();

    let mut ts = vec![];
    let mut counts = vec![];
    for i in 0..10 {
        let m = keccak256(format!("m{i}").as_bytes());
        let t = Instant::now();
        let sig = key.sign(&m);
        ts.push(ms(t));
        counts.push(perms());
        let t = Instant::now();
        assert!(leansphincs::verify(&key.public_key(), &m, &sig));
        if i == 0 {
            println!("leanSphincs verify: {:.2} ms{}", ms(t), perms());
        }
        let _ = perms();
    }
    let (min, med, mean, max) = stats(ts);
    println!("leanSphincs signature: median {med:.0} ms, mean {mean:.0}, min {min:.0}, max {max:.0} (10 signatures)");
    #[cfg(feature = "count")]
    println!("  permutations per signature: {}", counts.join(" ").replace(", ", "").replace(" permutations", ""));
    let _ = counts;
}
