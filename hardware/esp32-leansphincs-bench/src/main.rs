//! leanVM's leanSPHINCS signer on a classic ESP32: key generation, signing and verification for
//! the 2^24 and the 2^30 parameter sets, timed on one core, with the Keccak-f permutations each
//! took. Every result is compared with what the same code gives on a PC (src/expected.rs, written
//! by host/); for the 2^30 set that includes leanVM's own known answer. Serial, 115200 baud; the
//! run ends with RESULT lines. The key is a public test vector: nothing here is secret.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

extern crate alloc;

mod expected;
mod stack;

use core::hint::black_box;

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    efuse, main,
    time::{Duration, Instant},
    xtensa_lx,
};
use esp_println::println;

use expected::{Expected, SIGNATURES};

esp_bootloader_esp_idf::esp_app_desc!();

const NAME: &str = "winterlock-esp32-leansphincs-bench";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const START_AFTER: Duration = Duration::from_secs(10);
const RATE_TIME: Duration = Duration::from_millis(2500);

/// The heap: the memory the bootloader used (96 KB) and a part of main DRAM.
const HEAP_RECLAIMED: usize = 96 * 1024;
const HEAP_MAIN: usize = 80 * 1024;

/// What one set's run gave, in microseconds and permutations.
#[derive(Default, Clone, Copy)]
struct Times {
    key_us: u64,
    key_perms: u32,
    sign_us: u64,
    sign_perms: u64,
    sign_max_us: u64,
    verify_us: u64,
    ok: bool,
}

fn message(j: u64) -> [u8; 32] {
    let mut m: [u8; 32] = core::array::from_fn(|i| (7 * i + 3) as u8);
    if j > 0 {
        m[..8].copy_from_slice(&j.to_le_bytes());
    }
    m
}

/// Milliseconds with one decimal, as two integers.
fn ms(us: u64) -> (u64, u64) {
    (us / 1000, us % 1000 / 100)
}

fn per_second(perms: u64, us: u64) -> u64 {
    perms * 1_000_000 / us.max(1)
}

/// keccak256 of 64 bytes, each digest the next input (a hash chain: one permutation per hash).
fn rate() -> u64 {
    let mut x = [0x5au8; 64];
    let mut n = 0u64;
    let t = Instant::now();
    while t.elapsed() < RATE_TIME {
        for _ in 0..64 {
            let d = keccak256::hash(black_box(&x));
            x[..32].copy_from_slice(&d);
            x[32..].copy_from_slice(&d);
        }
        n += 64;
    }
    black_box(x);
    per_second(n, t.elapsed().as_micros())
}

/// keccak256 of the empty input, and a 1,000-step chain's end.
fn self_test() -> ([u8; 32], [u8; 32]) {
    let empty = keccak256::hash(&[]);
    let mut x = [0u8; 32];
    for _ in 0..1000 {
        x = keccak256::hash(&x);
    }
    (empty, x)
}

const EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6,
    0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

macro_rules! run_set {
    ($name:expr, $shape:expr, $c:ident, $e:expr) => {{
        let e: &Expected = &$e;
        let mut t = Times { ok: true, ..Times::default() };
        println!();
        println!("{}: {}; signature {} bytes", $name, $shape, $c::SIG_SIZE);
        let sk: $c::SecretKey = core::array::from_fn(|i| (37 * i + 11) as u8);

        keccak256::reset_permutations();
        let t0 = Instant::now();
        let leaves = $c::top_leaves(&sk);
        let pk = $c::public_key_from_leaves(&sk, &leaves);
        t.key_us = t0.elapsed().as_micros();
        t.key_perms = keccak256::permutation_count();
        let ok = pk.to_bytes() == e.public_key && t.key_perms == e.key;
        t.ok &= ok;
        let (a, b) = ms(t.key_us);
        println!(
            "  key generation                 {:>6}.{} ms  {:>7} perm  {:>6} perm/s  {}",
            a,
            b,
            t.key_perms,
            per_second(t.key_perms as u64, t.key_us),
            if ok { "PASS" } else { "FAIL" }
        );

        for j in 0..SIGNATURES {
            let m = message(j as u64);
            keccak256::reset_permutations();
            let t0 = Instant::now();
            let sig = $c::sign_cached(&sk, &leaves, &m);
            let us = t0.elapsed().as_micros();
            let perms = keccak256::permutation_count();
            let digest = keccak256::hash(&sig.to_bytes());
            let ok = digest == e.signed[j].0 && perms == e.signed[j].1;
            t.ok &= ok;
            t.sign_us += us;
            t.sign_perms += perms as u64;
            t.sign_max_us = t.sign_max_us.max(us);
            let (a, b) = ms(us);
            println!(
                "  signature {}                    {:>6}.{} ms  {:>7} perm  {:>6} perm/s  {}",
                j,
                a,
                b,
                perms,
                per_second(perms as u64, us),
                if ok { "PASS" } else { "FAIL" }
            );
            if j == 0 {
                keccak256::reset_permutations();
                let t0 = Instant::now();
                let valid = $c::verify(&pk, &m, &sig);
                t.verify_us = t0.elapsed().as_micros();
                let perms = keccak256::permutation_count();
                let ok = valid && perms == e.verify;
                t.ok &= ok;
                let (a, b) = ms(t.verify_us);
                println!(
                    "  verification                   {:>6}.{} ms  {:>7} perm                 {}",
                    a,
                    b,
                    perms,
                    if ok { "PASS" } else { "FAIL" }
                );
            }
        }
        let mean_us = t.sign_us / SIGNATURES as u64;
        let (a, b) = ms(mean_us);
        let (c, d) = ms(t.sign_max_us);
        println!(
            "  signatures: mean {}.{} ms, max {}.{} ms, mean {} perm, {} perm/s",
            a,
            b,
            c,
            d,
            t.sign_perms / SIGNATURES as u64,
            per_second(t.sign_perms, t.sign_us)
        );
        // these {SIGNATURES} messages are a small sample: the mean over many, at this run's rate
        let (a, b) = ms(e.mean as u64 * t.sign_us / t.sign_perms.max(1));
        println!(
            "  at this rate, the mean over {} messages ({} perm): {}.{} ms",
            e.messages, e.mean, a, b
        );
        t
    }};
}

#[main]
fn main() -> ! {
    let _p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: HEAP_RECLAIMED);
    esp_alloc::heap_allocator!(size: HEAP_MAIN);
    stack::paint();

    println!();
    println!("{} {}", NAME, VERSION);
    println!("leanVM {} (crates/lean_sphincs, crates/keccak256), prepared by prepare.py", expected::LEANVM_COMMIT);
    let rev = efuse::chip_revision();
    println!(
        "chip: ESP32 ({:?}), Xtensa LX6, {} cores, silicon revision v{}.{}",
        efuse::chip_type(),
        efuse::core_count(),
        rev.major,
        rev.minor
    );
    let mhz = esp_hal::clock::cpu_clock().as_mhz();
    let measured = measure_mhz();
    println!("cpu clock: {} MHz set, {} MHz measured against the APB timer; one core used", mhz, measured);
    println!("heap: {} bytes", esp_alloc::HEAP.stats().size);
    println!("starts in 10 s; the run takes about 7 minutes");
    let t = Instant::now();
    while t.elapsed() < START_AFTER {}
    let started = Instant::now();

    println!();
    println!("keccak256: one permutation per hash of 64 bytes");
    let mut ok = true;
    let mut rates = [0u64; 2];
    let mut chain = [[0u8; 32]; 2];
    for (i, tiny) in [false, true].into_iter().enumerate() {
        keccak256::use_tiny(tiny);
        let (empty, end) = self_test();
        chain[i] = end;
        let pass = empty == EMPTY && end == chain[0];
        ok &= pass;
        rates[i] = rate();
        println!(
            "  {:<28} {:>6} perm/s  {}",
            if tiny { "tiny-keccak's Keccak-f" } else { "leanVM's Keccak-f" },
            rates[i],
            if pass { "PASS" } else { "FAIL" }
        );
    }
    let tiny = rates[1] >= rates[0];
    keccak256::use_tiny(tiny);
    let backend = if tiny { "tiny-keccak" } else { "leanvm" };
    println!("  the rest of the run uses the faster one: {}", backend);

    let t24 = run_set!("2^24", "heights 7 + 7 + 10, k = 19, a = 9", ls24, expected::SET24);
    let t30 = run_set!("2^30", "heights 8 + 8 + 10, k = 24, a = 10", ls30, expected::SET30);
    ok &= t24.ok && t30.ok;

    let heap = esp_alloc::HEAP.stats();
    let (s, s_size) = stack::used();
    println!();
    println!("memory");
    println!("  heap: peak {} of {} bytes, {} in use now", heap.max_usage, heap.size, heap.current_usage);
    println!("  stack: peak {} of {} bytes", s, s_size);
    println!();
    println!("run took {} s", started.elapsed().as_secs());
    let verdict = if ok { "PASS" } else { "FAIL" };
    println!(
        "RESULT {} {} leanvm={} rev=v{}.{} mhz={} checks={} keccak={} leanvm_perm_s={} tiny_perm_s={} heap_peak={} stack_peak={}",
        NAME,
        VERSION,
        &expected::LEANVM_COMMIT[..9],
        rev.major,
        rev.minor,
        measured,
        verdict,
        backend,
        rates[0],
        rates[1],
        heap.max_usage,
        s
    );
    for (name, t, e) in [("2^24", &t24, &expected::SET24), ("2^30", &t30, &expected::SET30)] {
        println!(
            "RESULT {} key_ms={} key_perm={} sign_mean_ms={} sign_max_ms={} sign_mean_perm={} sign_perm_s={} verify_ms={} signatures={} mean_of_{}_ms={}",
            name,
            (t.key_us + 500) / 1000,
            t.key_perms,
            (t.sign_us / SIGNATURES as u64 + 500) / 1000,
            (t.sign_max_us + 500) / 1000,
            t.sign_perms / SIGNATURES as u64,
            per_second(t.sign_perms, t.sign_us),
            (t.verify_us + 500) / 1000,
            SIGNATURES,
            e.messages,
            (e.mean as u64 * t.sign_us / t.sign_perms.max(1) + 500) / 1000
        );
    }
    println!("done. Press EN to run again.");
    loop {
        core::hint::spin_loop();
    }
}

/// The CPU clock in MHz, from the cycle counter over 100 ms of the APB timer.
fn measure_mhz() -> u64 {
    let c0 = xtensa_lx::timer::get_cycle_count();
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(100) {}
    let c1 = xtensa_lx::timer::get_cycle_count();
    let us = t.elapsed().as_micros().max(1);
    c1.wrapping_sub(c0) as u64 / us
}
