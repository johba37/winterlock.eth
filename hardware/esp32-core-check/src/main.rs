//! winterlock-core on a classic ESP32: checks the core against the Python signer's vectors on the
//! board, times ERC-8499's key derivation (PBKDF2 and HKDF over SHA-512) against the reference's
//! vectors, then times the real operations (stateless key and signatures, WOTS trees and
//! signatures) with both keccak backends, on one core and on two. Serial (115200 baud) has the
//! detail and ends with RESULT lines; an SSD1306 OLED on I2C is optional. The keys are public
//! test vectors: nothing here is secret.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types"
)]

extern crate alloc;

mod board;
mod dual;
mod erc8499;
mod ui;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::hint::black_box;

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    efuse,
    gpio::{Input, InputConfig, Pull},
    i2c::master::{Config as I2cConfig, I2c, SoftwareTimeout},
    main,
    system::CpuControl,
    time::{Duration, Instant, Rate},
    xtensa_lx,
};
use esp_println::println;

use ui::{Button, Line, Screen};
use winterlock_core::keccak::{self, Backend};
use winterlock_core::keylog::{self, MemoryLog, Refused, TreeRef};
use winterlock_core::derive::erc8499 as derive8499;
use winterlock_core::{derive, hbkd, hex, leansphincs, owner, phrase, wots};

esp_bootloader_esp_idf::esp_app_desc!();

const NAME: &str = "winterlock-esp32-core-check";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTO_START: Duration = Duration::from_secs(10);
const PAGE_TIME: Duration = Duration::from_secs(20);

/// The heap: the memory the bootloader used (96 KB) and a part of main DRAM.
const HEAP_RECLAIMED: usize = 96 * 1024;
const HEAP_MAIN: usize = 80 * 1024;

const BACKENDS: [Backend; 2] = [Backend::TinyKeccak, Backend::RustCrypto];

/// The outcome of every check, and the timings, for the RESULT lines and the screen.
struct Report {
    passed: u32,
    failed: u32,
    failures: Vec<&'static str>,
    t: [Timings; 2],
    e: Erc8499Times,
}

/// ERC-8499's derivations, in microseconds. SHA-512 in software: the same with either keccak
/// backend (keccak only hashes a tree's place).
#[derive(Default, Clone, Copy)]
struct Erc8499Times {
    /// a phrase's seed to its root: the 24 words, PBKDF2, HKDF-Extract (mean and max of four)
    root_mean: u64,
    root_max: u64,
    /// of it, PBKDF2 alone
    pbkdf2: u64,
    /// a root to a stateless key's seed (HKDF-Expand), mean
    key_seed: u64,
    /// a root to the gas key (HKDF-Expand, then checked below n), mean
    gas_key: u64,
    /// a device's 32 random bytes to its root (HKDF-Extract), mean
    device_root: u64,
    /// a root to a tree's secret seed (its place's digest, HKDF-Expand), mean
    tree_seed: u64,
    /// a device's random bytes to the root of a tree of height 4
    small_tree: u64,
}

#[derive(Default, Clone, Copy)]
struct Timings {
    perm_s: u32,
    key1: u64,
    key2: u64,
    spx_mean: u64,
    spx_max: u64,
    spx_verify: u64,
    h6_1: u64,
    h6_2: u64,
    h10_1: u64,
    h10_2: u64,
    wots_mean: u64,
    wots_max: u64,
}

impl Report {
    fn check(&mut self, name: &'static str, ok: bool) -> bool {
        println!("  {:<58} {}", name, if ok { "PASS" } else { "FAIL" });
        self.count(name, ok)
    }

    fn count(&mut self, name: &'static str, ok: bool) -> bool {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.failures.push(name);
        }
        ok
    }

    /// A timed operation whose result was also checked, with the Keccak-f permutations it took
    /// (not counted on two cores: their counts race).
    fn timed(&mut self, name: &str, what: &'static str, us: u64, ok: bool, two_cores: bool) {
        let perms = keccak::permutations();
        keccak::reset_permutations();
        let perms = if two_cores { text!("-") } else { text!("{}", perms) };
        println!(
            "  {:<52} {:>11}  {:>7} perm  {}",
            name,
            dur(us).as_str(),
            perms.as_str(),
            if ok { "PASS" } else { "FAIL" }
        );
        self.count(what, ok);
    }
}

/// Microseconds as milliseconds with one decimal.
fn ms(us: u64) -> Line {
    text!("{}.{} ms", us / 1000, us % 1000 / 100)
}

/// Below 1 ms in microseconds, else as [`ms`].
fn dur(us: u64) -> Line {
    if us < 1000 { text!("{} us", us) } else { ms(us) }
}

fn ms_int(us: u64) -> u64 {
    (us + 500) / 1000
}

#[main]
fn main() -> ! {
    enable_fpu();
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: HEAP_RECLAIMED);
    esp_alloc::heap_allocator!(size: HEAP_MAIN);
    dual::paint_main_stack();

    println!();
    println!("{} {}", NAME, VERSION);
    let rev = efuse::chip_revision();
    println!(
        "chip: ESP32 ({:?}), Xtensa LX6, {} cores, silicon revision v{}.{}",
        efuse::chip_type(),
        efuse::core_count(),
        rev.major,
        rev.minor
    );
    if rev.major < 3 {
        println!("note: esp-hal supports ESP32 v3.0 and later; this build lets older silicon run");
    }
    let mhz = esp_hal::clock::cpu_clock().as_mhz();
    println!(
        "cpu clock: {} MHz set (rated up to {} MHz), {} MHz measured against the APB timer",
        mhz,
        efuse::max_cpu_frequency().as_mhz(),
        measure_mhz()
    );
    println!(
        "heap: {} bytes ({} reclaimed from the bootloader + {} of main DRAM); second core's stack {} bytes",
        esp_alloc::HEAP.stats().size,
        HEAP_RECLAIMED,
        HEAP_MAIN,
        dual::APP_STACK_SIZE
    );

    let i2c_config = I2cConfig::default()
        .with_frequency(Rate::from_khz(400))
        .with_software_timeout(SoftwareTimeout::Transaction(Duration::from_millis(50)));
    let mut screen = match I2c::new(p.I2C0, i2c_config) {
        Ok(i2c) => Screen::probe(i2c.with_sda(p.GPIO21).with_scl(p.GPIO22)),
        Err(e) => {
            println!("display: I2C setup failed ({:?})", e);
            Screen::none()
        }
    };
    match screen.address {
        Some(a) => println!("display: SSD1306/SSD1315 at 0x{:02X} (SDA GPIO21, SCL GPIO22)", a),
        None => println!("display: none at 0x3C or 0x3D, serial only"),
    }
    let button = Button::new(Input::new(p.GPIO0, InputConfig::default().with_pull(Pull::Up)));

    let chip = text!("ESP32 v{}.{}  {} MHz", rev.major, rev.minor, mhz);
    screen.show(&[
        "WINTERLOCK",
        "core check",
        text!("v{}", VERSION).as_str(),
        chip.as_str(),
        "",
        "press BOOT to start",
        "(starts by itself",
        " in 10 s)",
    ]);
    println!("press BOOT to start, or wait 10 s");
    let pressed = button.wait_down(Some(AUTO_START));
    if pressed {
        button.wait_up();
    }
    println!("start: {}", if pressed { "BOOT pressed" } else { "automatic after 10 s" });

    let mut r = Report { passed: 0, failed: 0, failures: Vec::new(), t: [Timings::default(); 2], e: Erc8499Times::default() };
    let mut dual = dual::Dual::new(CpuControl::new(p.CPU_CTRL));
    let started = Instant::now();

    checks(&mut r, &mut screen);
    let e = erc8499_keys(&mut r, &mut screen);
    r.e = e;
    for (i, &b) in BACKENDS.iter().enumerate() {
        r.t[i] = timings(&mut r, &mut screen, &mut dual, b, i);
    }
    keccak::set_backend(Backend::TinyKeccak);

    let heap = esp_alloc::HEAP.stats();
    let (s0, s0_size) = dual::main_stack_used();
    let (s1, s1_size) = dual::app_stack_used();
    println!();
    println!("memory");
    println!("  heap: peak {} of {} bytes, {} in use now", heap.max_usage, heap.size, heap.current_usage);
    println!("  first core's stack: peak {} of {} bytes", s0, s0_size);
    println!("  second core's stack: peak {} of {} bytes ({} jobs)", s1, s1_size, dual.runs);
    println!();
    println!("checks: {} passed, {} failed; run took {} s", r.passed, r.failed, started.elapsed().as_secs());
    for f in &r.failures {
        println!("  FAILED: {}", f);
    }
    let verdict = if r.failed == 0 { "PASS" } else { "FAIL" };
    println!(
        "RESULT {} {} rev=v{}.{} mhz={} checks={} passed={}/{} default_backend={} heap_peak={} heap={} stack0={}/{} stack1={}/{}",
        NAME,
        VERSION,
        rev.major,
        rev.minor,
        mhz,
        verdict,
        r.passed,
        r.passed + r.failed,
        keccak::backend().name(),
        heap.max_usage,
        heap.size,
        s0,
        s0_size,
        s1,
        s1_size
    );
    for (i, b) in BACKENDS.iter().enumerate() {
        let t = &r.t[i];
        println!(
            "RESULT {} perm_s={} key_1core_ms={} key_2core_ms={} spx_mean_ms={} spx_max_ms={} spx_verify_ms={} h6_1core_ms={} h6_2core_ms={} h10_1core_ms={} h10_2core_ms={} wots_mean_ms={} wots_max_ms={}",
            b.name(),
            t.perm_s,
            ms_int(t.key1),
            ms_int(t.key2),
            ms_int(t.spx_mean),
            ms_int(t.spx_max),
            ms_int(t.spx_verify),
            ms_int(t.h6_1),
            ms_int(t.h6_2),
            ms_int(t.h10_1),
            ms_int(t.h10_2),
            ms_int(t.wots_mean),
            ms_int(t.wots_max)
        );
    }
    let e = &r.e;
    println!(
        "RESULT erc8499 phrase_root_ms={} phrase_root_max_ms={} pbkdf2_ms={} key_seed_us={} gas_key_us={} device_root_us={} tree_seed_us={} tree_h4_ms={}",
        ms_int(e.root_mean),
        ms_int(e.root_max),
        ms_int(e.pbkdf2),
        e.key_seed,
        e.gas_key,
        e.device_root,
        e.tree_seed,
        ms_int(e.small_tree)
    );

    let mut page = 0;
    loop {
        println!();
        println!("screen: summary {}/3 (BOOT or 20 s: next; EN: run again)", page + 1);
        let lines = summary(page, &r, verdict);
        show_lines(&mut screen, &lines);
        if button.wait_down(Some(PAGE_TIME)) {
            button.wait_up();
        }
        page = (page + 1) % 3;
    }
}

// --- checks: the compact subset of the Python vectors ---

fn checks(r: &mut Report, screen: &mut Screen) {
    println!();
    println!("checks against the Python signer's vectors (core/tests/vectors/board.json)");
    screen.show(&["core check", "", "checks against", "the Python vectors"]);

    for b in BACKENDS {
        keccak::set_backend(b);
        let ok = keccak_self_test();
        r.check(if b == Backend::TinyKeccak { "keccak256 (tiny-keccak): empty input, 1,000-step chain" } else { "keccak256 (sha3): empty input, 1,000-step chain" }, ok);
    }
    keccak::set_backend(Backend::TinyKeccak);

    let seed = phrase::to_seed(board::PHRASE);
    r.check("phrase (numbered, upper case) -> seed", seed == Ok(board::SEED));
    r.check("seed -> phrase -> seed", phrase::to_seed(&phrase::to_phrase(&board::SEED).join(" ")) == Ok(board::SEED));
    let mut typo = String::from(board::PHRASE);
    typo.push_str(" abandon");
    r.check("a 25th word is refused", phrase::to_seed(&typo) == Err(phrase::PhraseError::WordCount(25)));
    r.check("member key seed (winterlock.signer.stateless.v1)", derive::member_key_seed(&board::SEED) == board::MEMBER_KEY_SEED);
    r.check("owner address of the member key", owner::owner_address(&board::MEMBER_KEY) == Ok(board::OWNER));
    let cc = &board::CHECK_CODE;
    r.check("pairing check code", phrase::check_code_text(&cc.owner, cc.device, &cc.key) == cc.code);
    let d = &board::DEVICE_DIGEST;
    r.check("device certificate digest", owner::device_digest(d.chain, &d.owner, d.device, d.generation, &d.key) == d.digest);
    for (i, c) in board::SAFETX.iter().enumerate() {
        let h = c.tx.safe_tx().hash(c.chain, &c.safe);
        r.check(if i == 0 { "SafeTx hash: delegatecall with data" } else { "SafeTx hash: every field set, nonce above 2^64" }, h == c.hash);
    }
    r.check("key log scenario (first, second, third version)", keylog_scenario());
    let s = &board::STATELESS[0];
    r.check("stateless signature verifies (Python's)", leansphincs::verify(&board::MEMBER_KEY, &s.message, s.sig));
    let mut bad = s.sig.to_vec();
    bad[3000] ^= 1;
    r.check("a changed byte doesn't", !leansphincs::verify(&board::MEMBER_KEY, &s.message, &bad));
    let h6 = &board::H6;
    r.check("tree secret and public seeds", {
        let at = h6.place();
        derive::tree_secret_seed(&board::SEED, &at, &h6.salt) == h6.sk_seed && derive::tree_public_seed(&at) == h6.tree_seed
    });
    let w = &h6.sigs[0];
    r.check(
        "WOTS signature and path verify to the height-6 root",
        wots::verify_root(&h6.tree_seed, w.key_index, &w.hash, w.sig, w.path) == Some(h6.root),
    );
}

fn keccak_self_test() -> bool {
    // the bench's digests: keccak256 of nothing, and a 1,000-step chain over 64 bytes
    let empty = hex::h32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    let want = hex::h32("5cfc72b798043048cc34e0a0b18149e912ae3804ce0924da44e98984c5be0c8a");
    let mut buf: [u8; 64] = core::array::from_fn(|i| i as u8);
    for _ in 0..1000 {
        let d = keccak::keccak256(&buf);
        buf[..32].copy_from_slice(&d);
    }
    keccak::reset_permutations();
    keccak::keccak256(b"") == empty && buf[..32] == want
}

fn tree_ref(t: &board::KeylogTree) -> TreeRef {
    TreeRef { chain: t.chain, safe: t.safe, root: t.root, start: t.start, height: t.height }
}

fn keylog_scenario() -> bool {
    let trees: Vec<TreeRef> = board::KEYLOG_TREES.iter().map(tree_ref).collect();
    let mut log = MemoryLog::default();
    let mut ok = true;
    for (n, s) in board::KEYLOG_STEPS.iter().enumerate() {
        let tr = &trees[s.tree];
        let got = if s.sign {
            keylog::record(&mut log, tr, s.nonce, &s.hash)
        } else {
            keylog::record_sign(&mut log, tr, s.nonce, s.slot, &s.hash)
        };
        let good = match (&got, &s.expect) {
            (Ok(rec), board::Expect::Signed { slot, already, appended }) => {
                rec.key_use().slot == *slot && rec.already == *already && !rec.already == *appended
            }
            (Err(Refused::ThirdVersion { .. }), board::Expect::Refused(w)) => *w == "third-version",
            (Err(Refused::KeyReused { .. }), board::Expect::Refused(w)) => *w == "key-reused",
            (Err(Refused::NotInTree(_)), board::Expect::Refused(w)) => *w == "not-in-tree",
            _ => false,
        };
        if !good {
            println!("    step {} of '{}': unexpected answer", n + 1, board::KEYLOG_NAME);
        }
        ok &= good;
    }
    let same = log.uses.len() == board::KEYLOG_USES.len()
        && log.uses.iter().zip(board::KEYLOG_USES).all(|(a, b)| {
            a.chain == b.chain
                && a.safe == b.safe
                && a.root == b.root
                && a.start == b.start
                && a.nonce == b.nonce
                && a.slot == b.slot
                && a.key_index == b.key_index
                && a.hash == b.hash
        });
    ok && same
}

// --- ERC-8499 ---

/// The ERC's own stateless seed for its first test phrase ("abandon" 23 times, then "art"), account
/// 0, this key type: from the ERC's text, not from the vectors.
const ERC_FIRST_SEED: [u8; 32] = hex::h32("fe1de5038bcc56fc434f8cba07eb53ab972de18ec0779c7465fd0d789a966879");

/// ERC-8499's derivations as the app and the board make them, each timed and checked against the
/// Python reference's vectors. Runs before the long passes, so its numbers come within seconds.
fn erc8499_keys(r: &mut Report, screen: &mut Screen) -> Erc8499Times {
    keccak::set_backend(Backend::TinyKeccak);
    keccak::reset_permutations();
    let mut e = Erc8499Times::default();
    println!();
    println!("ERC-8499 key derivation (SHA-512 in software), every result checked against the reference's vectors (core/tests/vectors/erc8499.json)");
    let step = |screen: &mut Screen, what: &str| {
        screen.show(&["core check", "ERC-8499 keys", "", what]);
    };
    r.check("key type and gas label are the reference's", derive8499::KEY_TYPE == erc8499::KEY_TYPE && derive8499::GAS_LABEL == erc8499::GAS_LABEL);

    let n = erc8499::KEYS.len() as u64;
    for (i, k) in erc8499::KEYS.iter().enumerate() {
        step(screen, text!("phrase {}/{}", i + 1, n).as_str());
        let s = Instant::now();
        let root = derive8499::phrase_root(&k.seed);
        let us = s.elapsed().as_micros();
        e.root_mean += us;
        e.root_max = e.root_max.max(us);
        r.timed(&format!("phrase {}: root (24 words, PBKDF2, HKDF-Extract)", i + 1), "ERC-8499 phrase root", us, root == Ok(k.phrase_root), false);

        let s = Instant::now();
        let seed = derive8499::stateless_key_seed(&k.phrase_root);
        let us = s.elapsed().as_micros();
        e.key_seed += us;
        r.timed(&format!("phrase {}: member key seed (HKDF-Expand)", i + 1), "ERC-8499 member key seed", us, seed == Ok(k.member_key_seed), false);
        if i == 0 {
            r.check("the ERC's printed seed for its first test phrase", k.seed == [0; 32] && seed == Ok(ERC_FIRST_SEED));
        }
        r.check("owner address of the reference's member key", owner::owner_address(&k.member_key) == Ok(k.owner));

        keccak::reset_permutations();
        let s = Instant::now();
        let gas = derive8499::gas_key(&k.phrase_root);
        let us = s.elapsed().as_micros();
        e.gas_key += us;
        r.timed(&format!("phrase {}: gas key (HKDF-Expand, below n)", i + 1), "ERC-8499 gas key", us, gas == Ok(k.gas_key), false);

        let s = Instant::now();
        let dev = derive8499::device_root(&k.seed);
        let us = s.elapsed().as_micros();
        e.device_root += us;
        r.timed("the same bytes as a device's: root (HKDF-Extract)", "ERC-8499 device root", us, dev == k.device_root, false);
        r.check("its device key seed", derive8499::stateless_key_seed(&dev) == Ok(k.device_key_seed));
    }
    e.root_mean /= n;
    e.key_seed /= n;
    e.gas_key /= n;
    e.device_root /= n;

    // the phrase root's parts: PBKDF2 over the 24 words, then HKDF-Extract
    step(screen, "PBKDF2 alone");
    let k = &erc8499::KEYS[0];
    let words = phrase::to_phrase(&k.seed);
    let s = Instant::now();
    let bip = hbkd::bip39_seed(&words, "");
    e.pbkdf2 = s.elapsed().as_micros();
    r.timed("phrase 1: of its root, the BIP-39 seed alone (PBKDF2)", "ERC-8499 BIP-39 seed", e.pbkdf2, bip.and_then(|b| hbkd::root(&b)) == Ok(k.phrase_root), false);

    let m = erc8499::TREE_SECRETS.len() as u64;
    for (i, t) in erc8499::TREE_SECRETS.iter().enumerate() {
        step(screen, text!("tree seed {}/{}", i + 1, m).as_str());
        let mut kt = [0u8; 34];
        r.check(
            "tree key type, context and device root",
            derive8499::tree_key_type(t.height, &mut kt) == Ok(t.key_type)
                && derive8499::tree_context(&t.place) == t.context
                && derive8499::device_root(&t.device_random) == t.root,
        );
        keccak::reset_permutations();
        let s = Instant::now();
        let sk = derive8499::tree_secret_seed(&t.root, &t.place, t.height, &t.salt);
        let us = s.elapsed().as_micros();
        e.tree_seed += us;
        r.timed(&format!("tree secret seed, height {} (digest, HKDF-Expand)", t.height), "ERC-8499 tree secret seed", us, sk == Ok(t.sk_seed), false);
    }
    e.tree_seed /= m;

    let st = &erc8499::SMALL_TREE;
    step(screen, "tree, height 4");
    let s = Instant::now();
    let root = derive8499::device_root(&st.device_random);
    let tree = derive8499::tree_secret_seed(&root, &st.place, st.height, &st.salt)
        .and_then(|sk| wots::Tree::create(&derive::tree_public_seed(&st.place), &sk, st.height, &wots::Prf::SIGNER).map(|t| (sk, t.root)));
    e.small_tree = s.elapsed().as_micros();
    r.timed("tree of height 4: device's random bytes to its root", "ERC-8499 tree of height 4", e.small_tree, tree == Ok((st.sk_seed, st.tree_root)), false);

    println!(
        "  phrase root: mean {}, max {}; of it PBKDF2 {}. Member key seed {}, gas key {}, device root {}, tree secret seed {} (means)",
        dur(e.root_mean).as_str(),
        dur(e.root_max).as_str(),
        dur(e.pbkdf2).as_str(),
        dur(e.key_seed).as_str(),
        dur(e.gas_key).as_str(),
        dur(e.device_root).as_str(),
        dur(e.tree_seed).as_str()
    );
    e
}

// --- timings ---

fn timings(r: &mut Report, screen: &mut Screen, dual: &mut dual::Dual, b: Backend, idx: usize) -> Timings {
    keccak::set_backend(b);
    let mut t = Timings::default();
    let name = b.name();
    println!();
    println!("timings with {} (every result checked against the Python vectors)", name);
    let step = |screen: &mut Screen, what: &str| {
        screen.show(&["core check", text!("pass {}/2 {}", idx + 1, name).as_str(), "", what]);
    };

    // raw speed: keccak256 of 64 bytes, chained, for one second
    step(screen, "keccak256, 1 s");
    let mut buf: [u8; 64] = core::array::from_fn(|i| i as u8);
    let start = Instant::now();
    let mut n = 0u32;
    while start.elapsed() < Duration::from_secs(1) {
        for _ in 0..16 {
            let d = keccak::keccak256(&buf);
            buf[..32].copy_from_slice(&d);
        }
        n += 16;
    }
    black_box(&buf);
    let us = start.elapsed().as_micros();
    t.perm_s = (n as u64 * 1_000_000 / us) as u32;
    keccak::reset_permutations();
    println!("  keccak256 of 64 bytes, chained: {} per second ({} cycles each)", t.perm_s, esp_hal::clock::cpu_clock().as_hz() / t.perm_s.max(1));

    // the member key: leanSphincs, b = 10
    step(screen, "member key, 1 core");
    let ks = derive::member_key_seed(&board::SEED);
    keccak::reset_permutations();
    let s = Instant::now();
    let key = leansphincs::Key::new(&ks, 10).unwrap();
    t.key1 = s.elapsed().as_micros();
    r.timed("member key (leanSphincs, b = 10), one core", "member key, one core", t.key1, key.public_key() == board::MEMBER_KEY, false);
    step(screen, "member key, 2 cores");
    let s = Instant::now();
    let plan = leansphincs::plan(&ks, 10).unwrap();
    let mut leaves = vec![[0u8; 16]; plan.count as usize];
    let half = plan.count as usize / 2;
    let (lo, hi) = leaves.split_at_mut(half);
    let both = dual.run(
        || leansphincs::leaves(&plan.p, &ks, plan.first, lo),
        || leansphincs::leaves(&plan.p, &ks, plan.first + half as u32, hi),
    );
    if let Err(e) = both {
        println!("  second core: {}; computing its half here", e);
        leansphincs::leaves(&plan.p, &ks, plan.first + half as u32, &mut leaves[half..]);
    }
    let key2 = leansphincs::Key::from_leaves(&ks, 10, leaves).unwrap();
    t.key2 = s.elapsed().as_micros();
    r.timed("member key, both cores", "member key, both cores", t.key2, key2.public_key() == board::MEMBER_KEY && both.is_ok(), true);
    drop(key2);

    // stateless signatures
    let mut total = 0;
    for (i, v) in board::STATELESS.iter().enumerate() {
        step(screen, text!("stateless sig {}/{}", i + 1, board::STATELESS.len()).as_str());
        let s = Instant::now();
        let sig = owner::stateless_sign(&key, &v.message);
        let us = s.elapsed().as_micros();
        total += us;
        t.spx_max = t.spx_max.max(us);
        let ok = sig.as_deref() == Ok(v.sig);
        r.timed(
            &format!("stateless signature {} ({} grind tries), verified", i + 1, v.grind_tries),
            "stateless signature, byte for byte",
            us,
            ok,
            false,
        );
    }
    t.spx_mean = total / board::STATELESS.len() as u64;
    let v = &board::STATELESS[0];
    let s = Instant::now();
    let ok = leansphincs::verify(&board::MEMBER_KEY, &v.message, v.sig);
    t.spx_verify = s.elapsed().as_micros();
    r.timed("stateless verification", "stateless verification", t.spx_verify, ok, false);
    println!("  stateless signature: mean {}, max {}", ms(t.spx_mean).as_str(), ms(t.spx_max).as_str());
    drop(key);

    // WOTS trees and signatures
    let mut wots_us = Vec::new();
    for (tree, h, one, two) in [(&board::H6, 6u32, &mut t.h6_1, &mut t.h6_2), (&board::H10, 10, &mut t.h10_1, &mut t.h10_2)] {
        step(screen, text!("WOTS h{}, 1 core", h).as_str());
        let s = Instant::now();
        let t1 = wots::Tree::create(&tree.tree_seed, &tree.sk_seed, h, &wots::Prf::SIGNER).unwrap();
        *one = s.elapsed().as_micros();
        r.timed(&format!("WOTS tree, height {}, one core", h), "WOTS tree root, one core", *one, t1.root == tree.root, false);
        drop(t1);
        step(screen, text!("WOTS h{}, 2 cores", h).as_str());
        let s = Instant::now();
        let mut leaves = vec![[0u8; 24]; 1 << h];
        let half = 1usize << (h - 1);
        let (lo, hi) = leaves.split_at_mut(half);
        let both = dual.run(
            || wots::leaves(&tree.tree_seed, &tree.sk_seed, 0, &wots::Prf::SIGNER, lo),
            || wots::leaves(&tree.tree_seed, &tree.sk_seed, half as u64, &wots::Prf::SIGNER, hi),
        );
        if let Err(e) = both {
            println!("  second core: {}; computing its half here", e);
            wots::leaves(&tree.tree_seed, &tree.sk_seed, half as u64, &wots::Prf::SIGNER, &mut leaves[half..]);
        }
        let t2 = wots::Tree::from_leaves(&tree.tree_seed, h, h, leaves, Vec::new()).unwrap();
        *two = s.elapsed().as_micros();
        r.timed(&format!("WOTS tree, height {}, both cores", h), "WOTS tree root, both cores", *two, t2.root == tree.root && both.is_ok(), true);

        // signatures through the key log, as the signer makes them
        let tr = TreeRef { chain: tree.chain, safe: tree.safe, root: t2.root, start: tree.start, height: h };
        let mut log = MemoryLog::default();
        for (j, w) in tree.sigs.iter().enumerate() {
            step(screen, text!("WOTS sig h{} {}/{}", h, j + 1, tree.sigs.len()).as_str());
            let tx = w.tx.safe_tx();
            let s = Instant::now();
            let hash = tx.hash(tree.chain, &tree.safe);
            let data = keylog::record_sign(&mut log, &tr, w.nonce, w.slot, &hash)
                .map_err(|_| winterlock_core::Error::Invalid("refused"))
                .and_then(|rec| owner::sign_transaction(&rec, &t2, &tree.sk_seed, tree.device, &tx));
            let us = s.elapsed().as_micros();
            wots_us.push(us);
            r.timed(
                &format!("WOTS signature, h{} key {}, hash to signature data", h, w.key_index),
                "WOTS signature data, byte for byte",
                us,
                data.as_deref() == Ok(w.data) && hash == w.hash,
                false,
            );
        }
    }
    t.wots_mean = wots_us.iter().sum::<u64>() / wots_us.len() as u64;
    t.wots_max = wots_us.iter().copied().max().unwrap_or(0);
    println!("  WOTS signature: mean {}, max {} ({} signatures)", ms(t.wots_mean).as_str(), ms(t.wots_max).as_str(), wots_us.len());
    t
}

// --- the screen ---

fn summary(page: u8, r: &Report, verdict: &str) -> [Line; 8] {
    let row = |label: &str, f: fn(&Timings) -> u64| text!("{:<7}{:>7}{:>7}", label, ms_int(f(&r.t[0])), ms_int(f(&r.t[1])));
    if page == 0 {
        [
            text!("CORE CHECK v{}", VERSION),
            text!("checks {} {}/{}", verdict, r.passed, r.passed + r.failed),
            text!("{:<7}{:>7}{:>7}", "ms", "tiny", "sha3"),
            row("key 1c", |t| t.key1),
            row("key 2c", |t| t.key2),
            row("SPX avg", |t| t.spx_mean),
            row("SPX max", |t| t.spx_max),
            text!("BOOT: next        1/3"),
        ]
    } else if page == 1 {
        [
            text!("{:<7}{:>7}{:>7}", "ms", "tiny", "sha3"),
            row("h6 1c", |t| t.h6_1),
            row("h6 2c", |t| t.h6_2),
            row("h10 1c", |t| t.h10_1),
            row("h10 2c", |t| t.h10_2),
            row("WOTS av", |t| t.wots_mean),
            row("WOTS mx", |t| t.wots_max),
            text!("BOOT: next        2/3"),
        ]
    } else {
        let e = &r.e;
        [
            text!("ERC-8499 keys"),
            text!("{:<12}{:>6} ms", "phrase root", ms_int(e.root_mean)),
            text!("{:<12}{:>6} ms", " PBKDF2", ms_int(e.pbkdf2)),
            text!("{:<12}{:>6} us", "member seed", e.key_seed),
            text!("{:<12}{:>6} us", "gas key", e.gas_key),
            text!("{:<12}{:>6} us", "tree seed", e.tree_seed),
            text!("{:<12}{:>6} ms", "tree h4", ms_int(e.small_tree)),
            text!("BOOT: next        3/3"),
        ]
    }
}

fn show_lines(screen: &mut Screen, lines: &[Line]) {
    let strs: [&str; 8] = core::array::from_fn(|i| lines.get(i).map_or("", |l| l.as_str()));
    screen.show(&strs[..lines.len().min(8)]);
}

/// Turns on the FPU (coprocessor 0) for the calling core. esp-hal relies on the reset state for
/// this; Espressif's QEMU resets it to off, and the first float then faults over and over (the
/// exception entry saves the FPU registers and faults again) until the stack runs out.
pub fn enable_fpu() {
    // SAFETY: only sets the FPU's enable bit; no memory is touched.
    unsafe {
        core::arch::asm!(
            "rsr {v}, cpenable",
            "movi {t}, 1",
            "or {v}, {v}, {t}",
            "wsr {v}, cpenable",
            "rsync",
            v = out(reg) _,
            t = out(reg) _,
        );
    }
}

/// CPU cycles over 100 ms of the APB-clocked timer, so the clock is measured, not just set.
fn measure_mhz() -> u64 {
    let c0 = xtensa_lx::timer::get_cycle_count();
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(100) {}
    let c1 = xtensa_lx::timer::get_cycle_count();
    let us = t.elapsed().as_micros().max(1);
    c1.wrapping_sub(c0) as u64 / us
}
