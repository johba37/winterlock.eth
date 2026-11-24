//! Counts Keccak-f permutations of leanVM's leanSPHINCS signer (prepare.py) for two parameter
//! sets, and writes ../src/expected.rs: the values the board's run is checked against.
//!
//!   cargo run --release            statistics over 1,000 messages, and expected.rs
//!   cargo run --release -- 200     over 200 messages
//!
//! Message j is m[i] = 7 i + 3, with its first 8 bytes replaced by j (little endian) for j > 0.
//! The key is S[i] = 37 i + 11. Key and message 0 are leanVM's known answer.

use std::fmt::Write as _;
use std::time::Instant;

/// Signatures the board makes per set.
const BOARD_SIGNATURES: usize = 8;

fn perms() -> u64 {
    keccak256::permutation_count() as u64
}

pub fn message(j: u64) -> [u8; 32] {
    let mut m: [u8; 32] = std::array::from_fn(|i| (7 * i + 3) as u8);
    if j > 0 {
        m[..8].copy_from_slice(&j.to_le_bytes());
    }
    m
}

struct Stats {
    mean: f64,
    sd: f64,
    min: u64,
    median: u64,
    p95: u64,
    max: u64,
}

fn stats(v: &[u64]) -> Stats {
    let mut v = v.to_vec();
    v.sort();
    let n = v.len();
    let mean = v.iter().sum::<u64>() as f64 / n as f64;
    let var = v.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / n as f64;
    Stats { mean, sd: var.sqrt(), min: v[0], median: v[n / 2], p95: v[n * 95 / 100], max: v[n - 1] }
}

struct Set {
    name: &'static str,
    shape: &'static str,
    sig_size: usize,
    pk: [u8; 32],
    key: u64,
    verify: u64,
    /// (keccak256 of the signature, permutations with the top tree's leaves given), per message
    signed: Vec<([u8; 32], u64)>,
    native_ms: f64,
}

macro_rules! run {
    ($name:expr, $shape:expr, $c:ident, $n:expr) => {{
        let sk: $c::SecretKey = std::array::from_fn(|i| (37 * i + 11) as u8);
        keccak256::reset_permutations();
        let leaves = $c::top_leaves(&sk);
        let pk = $c::public_key_from_leaves(&sk, &leaves);
        let key = perms();
        assert_eq!(pk, $c::key_gen(&sk));
        let mut signed = Vec::new();
        let mut verify = 0;
        let t0 = Instant::now();
        for j in 0..$n as u64 {
            let m = message(j);
            keccak256::reset_permutations();
            let sig = $c::sign_cached(&sk, &leaves, &m);
            let p = perms();
            if j < 4 {
                // the same signature as leanVM's own entry point, which rebuilds the top tree
                assert_eq!(sig, $c::sign(&sk, &m));
            }
            keccak256::reset_permutations();
            assert!($c::verify(&pk, &m, &sig));
            verify = perms();
            signed.push((keccak256::hash(&sig.to_bytes()), p));
        }
        Set {
            name: $name,
            shape: $shape,
            sig_size: $c::SIG_SIZE,
            pk: pk.to_bytes(),
            key,
            verify,
            signed,
            native_ms: t0.elapsed().as_secs_f64() * 1e3 / $n as f64,
        }
    }};
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes(b: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        write!(s, "0x{x:02x}").unwrap();
    }
    s.push(']');
    s
}

fn main() {
    let n: usize = std::env::args().nth(1).map(|s| s.parse().unwrap()).unwrap_or(1000);
    assert!(n >= BOARD_SIGNATURES);
    let commit = include_str!("../../prepare.py")
        .lines()
        .find_map(|l| l.strip_prefix("COMMIT = \""))
        .unwrap()
        .trim_end_matches('"');

    let sets = [
        run!("2^24", "heights 7 + 7 + 10, k = 19, a = 9", ls24, n),
        run!("2^30", "heights 8 + 8 + 10, k = 24, a = 10", ls30, n),
    ];

    // leanVM's known answer: its key, and its signature of message 0
    let mut lines = include_str!("../../vendor/known_answer.hex").lines();
    let mut unhex = || {
        let s = lines.next().unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect::<Vec<_>>()
    };
    let (pk, sig) = (unhex(), unhex());
    assert_eq!(sets[1].pk[..], pk[..]);
    assert_eq!(sets[1].signed[0].0, keccak256::hash(&sig));
    println!("leanVM {}: its known answer (key, signature of message 0) is reproduced by the 2^30 set\n", &commit[..9]);

    let mut out = String::new();
    writeln!(out, "// Written by host/ (cargo run --release): what leanVM's signer gives on a PC. The board must").unwrap();
    writeln!(out, "// reproduce every value. leanVM {commit}.").unwrap();
    writeln!(out, "\npub const LEANVM_COMMIT: &str = \"{commit}\";").unwrap();
    writeln!(out, "pub const SIGNATURES: usize = {BOARD_SIGNATURES};").unwrap();
    writeln!(out, "\npub struct Expected {{\n    pub public_key: [u8; 32],\n    /// Keccak-f permutations of key generation\n    pub key: u32,\n    pub verify: u32,\n    /// keccak256 of each signature, and the permutations it took with the top tree's leaves given\n    pub signed: [([u8; 32], u32); SIGNATURES],\n    /// mean permutations per signature over {n} messages\n    pub mean: u32,\n    pub messages: u32,\n}}").unwrap();

    for s in &sets {
        let counts: Vec<u64> = s.signed.iter().map(|x| x.1).collect();
        let st = stats(&counts);
        let board = stats(&counts[..BOARD_SIGNATURES]);
        println!("{}: {}; signature {} bytes", s.name, s.shape, s.sig_size);
        println!("  public key {}", hex(&s.pk));
        println!("  key generation: {} permutations", s.key);
        println!(
            "  signature, top tree's leaves given: mean {:.0}, sd {:.0}, min {}, median {}, p95 {}, max {}  ({} messages)",
            st.mean, st.sd, st.min, st.median, st.p95, st.max, n
        );
        println!("  the board's {} messages: mean {:.0}, min {}, max {}", BOARD_SIGNATURES, board.mean, board.min, board.max);
        println!("  verification: {} permutations", s.verify);
        println!("  here: {:.1} ms per signature with its verification\n", s.native_ms);

        let id = if s.name == "2^24" { "SET24" } else { "SET30" };
        writeln!(out, "\npub const {id}: Expected = Expected {{").unwrap();
        writeln!(out, "    public_key: {},", bytes(&s.pk)).unwrap();
        writeln!(out, "    key: {},\n    verify: {},\n    signed: [", s.key, s.verify).unwrap();
        for (d, p) in &s.signed[..BOARD_SIGNATURES] {
            writeln!(out, "        ({}, {p}),", bytes(d)).unwrap();
        }
        writeln!(out, "    ],\n    mean: {},\n    messages: {n},\n}};", st.mean.round() as u64).unwrap();
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../src/expected.rs");
    std::fs::write(path, out).unwrap();
    println!("wrote src/expected.rs ({} signatures per set for the board)", BOARD_SIGNATURES);
}
