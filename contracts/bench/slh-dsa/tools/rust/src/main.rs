//! RustCrypto slh-dsa 0.2.0-rc.5, an independent implementation of FIPS 205, for SLH-DSA-SHA2-128s:
//!   cargo run --release -- vectors > ../../fixtures/rustcrypto-sha2-128s.json
//!   cargo run --release -- bench [signatures]
use slh_dsa_bench::{keygen, public_key, sign, sign_internal, verify};
use std::time::Instant;

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("randomness");
    b
}

fn hex(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

struct Vector {
    reason: &'static str,
    internal: bool,
    seed: Vec<u8>,
    pk: Vec<u8>,
    message: Vec<u8>,
    ctx: Vec<u8>,
    sig: Vec<u8>,
}

fn vectors() {
    let mut out: Vec<(Vector, bool)> = Vec::new();
    let mut add = |v: Vector| {
        let valid = verify(&v.pk, &v.message, &v.ctx, &v.sig, v.internal);
        out.push((v, valid));
        valid
    };
    let (s1, s2, s3) = (random(48), random(48), random(48));
    let (k1, k2, k3) = (keygen(&s1), keygen(&s2), keygen(&s3));
    let (p1, p2, p3) = (public_key(&k1), public_key(&k2), public_key(&k3));
    let hash = random(32);
    let msg = random(300);
    let ctx = b"winterlock owner".to_vec();
    let v = |reason, internal, seed: &Vec<u8>, pk: &Vec<u8>, message: &Vec<u8>, ctx: &Vec<u8>, sig: &Vec<u8>| Vector {
        reason, internal, seed: seed.clone(), pk: pk.clone(), message: message.clone(), ctx: ctx.clone(),
        sig: sig.clone(),
    };
    let none = Vec::new();
    let a = sign(&k1, &hash, &none, &random(16));
    assert!(add(v("a 32-byte hash, empty context, hedged", false, &s1, &p1, &hash, &none, &a)));
    let b = sign(&k1, &hash, &none, &none);
    assert!(add(v("a 32-byte hash, empty context, deterministic", false, &s1, &p1, &hash, &none, &b)));
    let c = sign(&k2, &msg, &ctx, &random(16));
    assert!(add(v("a 300-byte message, a 16-byte context, hedged", false, &s2, &p2, &msg, &ctx, &c)));
    let d = sign(&k3, &none, &none, &random(16));
    assert!(add(v("an empty message, empty context, hedged", false, &s3, &p3, &none, &none, &d)));
    let e = sign_internal(&k3, &hash, &none);
    assert!(add(v("internal interface: M' = a 32-byte hash, deterministic", true, &s3, &p3, &hash, &none, &e)));
    assert!(!add(v("another message", false, &s1, &p1, &msg, &none, &a)));
    assert!(!add(v("another context", false, &s2, &p2, &msg, &b"winterlock ownes".to_vec(), &c)));
    assert!(!add(v("another key", false, &s2, &p2, &hash, &none, &a)));
    let mut flipped = c.clone();
    flipped[4000] ^= 0x10;
    assert!(!add(v("a flipped bit in the hypertree signature", false, &s2, &p2, &msg, &ctx, &flipped)));

    println!("{{");
    println!(" \"source\": \"RustCrypto slh-dsa 0.2.0-rc.5 (crates.io, Apache-2.0 OR MIT), tools/rust\",");
    println!(" \"parameterSet\": \"SLH-DSA-SHA2-128s\",");
    println!(" \"vectors\": [");
    for (i, (v, valid)) in out.iter().enumerate() {
        println!(
            "  {{\"source\": \"RustCrypto slh-dsa 0.2.0-rc.5\", \"internal\": {}, \"seed\": \"{}\", \"pk\": \"{}\", \
             \"message\": \"{}\", \"context\": \"{}\", \"signature\": \"{}\", \"valid\": {}, \"reason\": \"{}\"}}{}",
            v.internal, hex(&v.seed), hex(&v.pk), hex(&v.message), hex(&v.ctx), hex(&v.sig), valid, v.reason,
            if i + 1 < out.len() { "," } else { "" }
        );
    }
    println!(" ]\n}}");
}

fn bench(n: usize) {
    let seed = random(48);
    let t = Instant::now();
    let sk = keygen(&seed);
    let keygen_s = t.elapsed().as_secs_f64();
    let pk = public_key(&sk);
    let hash = random(32);
    let mut times = Vec::new();
    for i in 0..n {
        let rand = if i % 2 == 0 { random(16) } else { Vec::new() };
        let t = Instant::now();
        let sig = sign(&sk, &hash, &[], &rand);
        times.push(t.elapsed().as_secs_f64());
        assert!(verify(&pk, &hash, &[], &sig, false));
    }
    let sig = sign(&sk, &hash, &[], &[]);
    let t = Instant::now();
    for _ in 0..100 {
        assert!(verify(&pk, &hash, &[], &sig, false));
    }
    let verify_s = t.elapsed().as_secs_f64() / 100.0;
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "RustCrypto slh-dsa 0.2.0-rc.5, native, SLH-DSA-SHA2-128s: keygen {:.0} ms, sign median {:.0} ms \
         (min {:.0}, max {:.0}, n = {}), verify {:.2} ms",
        keygen_s * 1e3, times[n / 2] * 1e3, times[0] * 1e3, times[n - 1] * 1e3, n, verify_s * 1e3
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vectors") => vectors(),
        Some("bench") => bench(args.get(2).map_or(10, |s| s.parse().expect("a number"))),
        _ => eprintln!("usage: slh-dsa-bench vectors | bench [signatures]"),
    }
}
