//! keccak256 speed on a classic ESP32, to see whether these boards can be hash-based hardware
//! signers for Winterlock. Serial (115200 baud) has the full detail; an SSD1306 OLED on I2C is
//! optional. No keys anywhere: the mock signature hashes dummy data.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types"
)]

mod hashes;
mod ui;

use core::{
    hint::black_box,
    ptr::addr_of_mut,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    efuse,
    gpio::{Input, InputConfig, Pull},
    i2c::master::{Config as I2cConfig, I2c, SoftwareTimeout},
    main,
    system::{CpuControl, Stack},
    time::{Duration, Instant, Rate},
    xtensa_lx,
};
use esp_println::println;

use hashes::{IMPLS, Step};
use ui::{Button, Line, Press, Screen};

esp_bootloader_esp_idf::esp_app_desc!();

const NAME: &str = "winterlock-esp32-bench";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const BENCH_TIME: Duration = Duration::from_millis(2500);
const BATCH: u32 = 16;
const AUTO_START: Duration = Duration::from_secs(10);
const PAGE_TIME: Duration = Duration::from_secs(20);
const MOCK_TIMEOUT: Duration = Duration::from_secs(60);
const HOLD_TO_SIGN: Duration = Duration::from_millis(1500);

/// Keccak-f[1600] permutations per operation, counted by instrumenting the Python reference
/// signer (signer/winterlock_signer).
struct Op {
    label: &'static str,
    /// At most 9 characters, for the OLED.
    short: &'static str,
    perms: u32,
    /// Whether the work splits across both cores.
    parallel: bool,
}

const WOTS_MEAN: u32 = 3_921;

const OPS: [Op; 7] = [
    Op {
        label: "one-time (WOTS) signature, Safe tx, mean",
        short: "WOTS avg",
        perms: WOTS_MEAN,
        parallel: false,
    },
    Op {
        label: "one-time (WOTS) signature, Safe tx, max",
        short: "WOTS max",
        perms: 19_373,
        parallel: false,
    },
    Op {
        label: "stateless (leanSphincs) signature, mean",
        short: "SPX avg",
        perms: 141_974,
        parallel: true,
    },
    Op {
        label: "stateless (leanSphincs) signature, max",
        short: "SPX max",
        perms: 290_932,
        parallel: true,
    },
    Op {
        label: "stateless key (device key), made once",
        short: "dev key",
        perms: 238_624,
        parallel: true,
    },
    Op {
        label: "WOTS key tree, height 6 (32 nonces)",
        short: "tree h6",
        perms: 848_895 / 16,
        parallel: true,
    },
    Op {
        label: "WOTS key tree, height 10 (512 nonces)",
        short: "tree h10",
        perms: 848_895,
        parallel: true,
    },
];

#[main]
fn main() -> ! {
    enable_fpu();
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

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
        Some(a) => println!(
            "display: SSD1306/SSD1315 at 0x{:02X} (SDA GPIO21, SCL GPIO22)",
            a
        ),
        None => println!("display: none at 0x3C or 0x3D, serial only"),
    }
    let button = Button::new(Input::new(
        p.GPIO0,
        InputConfig::default().with_pull(Pull::Up),
    ));

    let chip = text!("ESP32 v{}.{}  {} MHz", rev.major, rev.minor, mhz);
    screen.show(&[
        "WINTERLOCK",
        "keccak256 benchmark",
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
    println!(
        "start: {}",
        if pressed {
            "BOOT pressed"
        } else {
            "automatic after 10 s"
        }
    );

    // Self-test first: a fast wrong hash is worth nothing.
    println!();
    println!(
        "self-test: keccak256 of 64 zero bytes and a 1,000-step chain, against digests from a PC"
    );
    screen.show(&["self-test", "", "checking digests"]);
    let mut ok = [false; IMPLS.len()];
    for (i, imp) in IMPLS.iter().enumerate() {
        ok[i] = hashes::self_test(imp.step);
        println!("  {:<44} {}", imp.name, if ok[i] { "ok" } else { "FAIL" });
    }

    println!();
    println!(
        "one core, {} ms each: keccak256 of a 64-byte input (one Keccak-f[1600]), chained",
        BENCH_TIME.as_millis()
    );
    let steps = IMPLS.len() + 1;
    let mut rates = [0f32; IMPLS.len()];
    for (i, imp) in IMPLS.iter().enumerate() {
        screen.show(&[
            "benchmark",
            "",
            text!("{}/{} one core", i + 1, steps).as_str(),
            imp.short,
            "",
            "about 2.5 s each",
        ]);
        let (n, us) = bench(imp.step);
        rates[i] = n as f32 * 1e6 / us as f32;
        println!(
            "  {:<44} {:>7} in {:>4} ms: {:>6.0} perm/s, {:>6} cycles/perm{}",
            imp.name,
            n,
            us / 1000,
            rates[i],
            cycles(mhz, rates[i]),
            if ok[i] {
                ""
            } else {
                "  (self-test failed: ignored)"
            }
        );
    }
    let all_failed = !ok.iter().any(|&o| o);
    let best = (0..IMPLS.len())
        .filter(|&i| ok[i] || all_failed)
        .max_by(|&a, &b| rates[a].total_cmp(&rates[b]))
        .unwrap();
    let rate1 = rates[best];
    println!("  fastest: {}", IMPLS[best].name);

    println!();
    println!(
        "both cores, {} ms: {} on each core at once",
        BENCH_TIME.as_millis(),
        IMPLS[best].short
    );
    screen.show(&[
        "benchmark",
        "",
        text!("{}/{} both cores", steps, steps).as_str(),
        IMPLS[best].short,
        "",
        "about 2.5 s",
    ]);
    let mut cpu = CpuControl::new(p.CPU_CTRL);
    let rate2 = match bench_dual(&mut cpu, IMPLS[best].step) {
        Ok(d) => {
            let rate = (d.n0 + d.n1) as f32 * 1e6 / d.us as f32;
            println!(
                "  core 0 {} + core 1 {} in {} ms: {:.0} perm/s, {:.2}x one core",
                d.n0,
                d.n1,
                d.us / 1000,
                rate,
                rate / rate1
            );
            Some(rate)
        }
        Err(e) => {
            println!("  skipped: {}", e);
            None
        }
    };

    print_estimates(best, rate1, rate2);
    println!(
        "RESULT {} {} rev=v{}.{} mhz={} impl={} perm_s_1core={:.0} perm_s_2core={:.0} selftest={}",
        NAME,
        VERSION,
        rev.major,
        rev.minor,
        mhz,
        IMPLS[best].short,
        rate1,
        rate2.unwrap_or(0.0),
        if all_failed {
            "FAIL"
        } else if ok.iter().all(|&o| o) {
            "ok"
        } else {
            "partial"
        }
    );

    // Results, a second page, then the mock confirmation; BOOT moves on, and so does a 20 s wait.
    let mut page = 0;
    loop {
        match page {
            0 | 1 => {
                println!();
                println!("screen: results {}/2 (BOOT or 20 s: next)", page + 1);
                let lines = results_page(page, best, rate1, rate2, rev, mhz, all_failed);
                show_lines(&mut screen, &lines);
                if button.wait_down(Some(PAGE_TIME)) {
                    button.wait_up();
                }
                page += 1;
            }
            _ => {
                mock_confirmation(&mut screen, &button, IMPLS[best].step);
                page = 0;
            }
        }
    }
}

/// Runs `step` in a chain for BENCH_TIME. Returns (permutations, microseconds).
fn bench(step: Step) -> (u32, u64) {
    let mut buf = hashes::seed();
    let start = Instant::now();
    let mut n = 0u32;
    loop {
        for _ in 0..BATCH {
            step(&mut buf);
        }
        n += BATCH;
        let elapsed = start.elapsed();
        if elapsed >= BENCH_TIME {
            black_box(&buf);
            return (n, elapsed.as_micros());
        }
    }
}

static APP_READY: AtomicBool = AtomicBool::new(false);
static APP_GO: AtomicBool = AtomicBool::new(false);
static APP_STOP: AtomicBool = AtomicBool::new(false);
static APP_DONE: AtomicBool = AtomicBool::new(false);
static APP_COUNT: AtomicU32 = AtomicU32::new(0);
static mut APP_STACK: Stack<16384> = Stack::new();

struct Dual {
    n0: u32,
    n1: u32,
    us: u64,
}

/// The same chain on both cores at once. Core 1's count is read when core 0's time is up, so
/// both counts cover the same window (to within one batch).
fn bench_dual(cpu: &mut CpuControl, step: Step) -> Result<Dual, &'static str> {
    // SAFETY: the only use of APP_STACK, and this runs once.
    let stack = unsafe { &mut *addr_of_mut!(APP_STACK) };
    let guard = cpu
        .start_app_core(stack, move || app_core(step))
        .map_err(|_| "the second core was already running")?;
    let t = Instant::now();
    while !APP_READY.load(Ordering::Acquire) {
        if t.elapsed() > Duration::from_millis(500) {
            return Err("the second core did not start within 500 ms");
        }
    }
    let mut buf = hashes::seed();
    APP_GO.store(true, Ordering::Release);
    let start = Instant::now();
    let mut n0 = 0u32;
    let (n1, us) = loop {
        for _ in 0..BATCH {
            step(&mut buf);
        }
        n0 += BATCH;
        let elapsed = start.elapsed();
        if elapsed >= BENCH_TIME {
            break (APP_COUNT.load(Ordering::Relaxed), elapsed.as_micros());
        }
    };
    APP_STOP.store(true, Ordering::Relaxed);
    let t = Instant::now();
    while !APP_DONE.load(Ordering::Acquire) && t.elapsed() < Duration::from_millis(500) {
        core::hint::spin_loop();
    }
    drop(guard); // parks the second core
    black_box(&buf);
    Ok(Dual { n0, n1, us })
}

fn app_core(step: Step) {
    enable_fpu();
    let mut buf = hashes::seed();
    buf[63] ^= 0xff; // a different chain from core 0's
    APP_READY.store(true, Ordering::Release);
    while !APP_GO.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let mut n = 0u32;
    while !APP_STOP.load(Ordering::Relaxed) {
        for _ in 0..BATCH {
            step(&mut buf);
        }
        n += BATCH;
        APP_COUNT.store(n, Ordering::Relaxed);
    }
    black_box(&buf);
    APP_DONE.store(true, Ordering::Release);
}

/// Turns on the FPU (coprocessor 0) for the calling core. esp-hal relies on the reset state for
/// this; Espressif's QEMU resets it to off, and the first float then faults over and over (the
/// exception entry saves the FPU registers and faults again) until the stack runs out.
fn enable_fpu() {
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

fn cycles(mhz: u32, rate: f32) -> u32 {
    if rate > 0.0 {
        (mhz as f32 * 1e6 / rate) as u32
    } else {
        0
    }
}

fn seconds(perms: u32, rate: f32) -> f32 {
    perms as f32 / rate
}

fn print_estimates(best: usize, rate1: f32, rate2: Option<f32>) {
    println!();
    match rate2 {
        Some(r2) => println!(
            "estimates from {} at {} perm/s on one core and {} perm/s on both",
            IMPLS[best].short,
            thousands(rate1 as u32).as_str(),
            thousands(r2 as u32).as_str()
        ),
        None => println!(
            "estimates from {} at {} perm/s on one core",
            IMPLS[best].short,
            thousands(rate1 as u32).as_str()
        ),
    }
    println!(
        "  {:<42} {:>8}  {:>16}  {:>16}",
        "operation", "perms", "one core", "both cores"
    );
    for op in OPS.iter() {
        let t1 = long_time(seconds(op.perms, rate1));
        let t2 = match (op.parallel, rate2) {
            (true, Some(r2)) => long_time(seconds(op.perms, r2)),
            (false, _) => text!("(mostly serial)"),
            (true, None) => text!("-"),
        };
        println!(
            "  {:<42} {:>8}  {:>16}  {:>16}",
            op.label,
            thousands(op.perms).as_str(),
            t1.as_str(),
            t2.as_str()
        );
    }
    println!(
        "  both cores assumes the work splits evenly; the WOTS signature mostly does not split"
    );
    println!("  times are for hashing only: no USB, display or other overhead");
}

fn results_page(
    page: u8,
    best: usize,
    rate1: f32,
    rate2: Option<f32>,
    rev: efuse::ChipRevision,
    mhz: u32,
    all_failed: bool,
) -> [Line; 8] {
    let row = |op: &Op| {
        let t1 = short_time(seconds(op.perms, rate1));
        let t2 = match (op.parallel, rate2) {
            (true, Some(r2)) => short_time(seconds(op.perms, r2)),
            _ => text!("-"),
        };
        text!("{:<9}{:>6}{:>6}", op.short, t1.as_str(), t2.as_str())
    };
    if page == 0 {
        let r2 = match rate2 {
            Some(r) => short_rate(r),
            None => text!("-"),
        };
        [
            text!("{:<9}{:>6}{:>6}", "Keccak-f", "1core", "2core"),
            text!(
                "{:<9}{:>6}{:>6}",
                "perm/s",
                short_rate(rate1).as_str(),
                r2.as_str()
            ),
            row(&OPS[0]),
            row(&OPS[1]),
            row(&OPS[2]),
            row(&OPS[3]),
            text!("{:<9}{:>6}", "cyc/perm", cycles(mhz, rate1)),
            text!("BOOT: next        1/2"),
        ]
    } else {
        [
            text!("{:<9}{:>6}{:>6}", "Estimate", "1core", "2core"),
            row(&OPS[4]),
            row(&OPS[5]),
            row(&OPS[6]),
            text!(""),
            text!("best: {}", IMPLS[best].short),
            if all_failed {
                text!("SELF-TEST FAILED")
            } else {
                text!("v{}.{} {}MHz test ok", rev.major, rev.minor, mhz)
            },
            text!("BOOT: next        2/2"),
        ]
    }
}

/// The feel of confirming a Safe transaction on the device. Holding BOOT runs the hashing of an
/// average one-time signature on dummy data and times it. No keys.
fn mock_confirmation(screen: &mut Screen, button: &Button, step: Step) {
    println!();
    println!("screen: mock confirmation (hold BOOT 1.5 s: sign, short press: back, 60 s: back)");
    let mut lines = [
        text!("{:<15}(mock)", "Safe tx #7"),
        text!("Send 0.05 ETH"),
        text!("to 0x1234...abcd"),
        text!("on Sepolia"),
        text!("one-time key 42/512"),
        text!(""),
        text!("hold BOOT to sign"),
        text!("short press: back"),
    ];
    show_lines(screen, &lines);
    let press = button.press(Some(MOCK_TIMEOUT), HOLD_TO_SIGN, |f| {
        lines[7] = bar(f);
        draw_lines(screen, &lines);
    });
    match press {
        Press::Short => println!("mock: short press, back to the results"),
        Press::Timeout => println!("mock: no answer in 60 s, not signed, back to the results"),
        Press::Hold => {
            println!(
                "mock: held, signing ({} permutations on dummy data)",
                WOTS_MEAN
            );
            show_lines(
                screen,
                &[
                    text!("{:<15}(mock)", "Safe tx #7"),
                    text!(""),
                    text!("signing..."),
                ],
            );
            let mut buf = hashes::seed();
            let t = Instant::now();
            for _ in 0..WOTS_MEAN {
                step(&mut buf);
            }
            let us = t.elapsed().as_micros();
            black_box(&buf);
            let took = long_time(us as f32 / 1e6);
            println!("mock: signed (mock) in {}", took.as_str());
            show_lines(
                screen,
                &[
                    text!("{:<15}(mock)", "Safe tx #7"),
                    text!("signed (mock)"),
                    text!(""),
                    text!("{} keccak-f, the", thousands(WOTS_MEAN).as_str()),
                    text!("WOTS mean, took"),
                    text!("{}", took.as_str()),
                    text!("no keys: dummy data"),
                    text!("BOOT: back"),
                ],
            );
            button.wait_up();
            let _ = button.wait_down(Some(PAGE_TIME));
            button.wait_up();
        }
    }
}

fn show_lines(screen: &mut Screen, lines: &[Line]) {
    let strs: [&str; 8] = core::array::from_fn(|i| lines.get(i).map_or("", |l| l.as_str()));
    screen.show(&strs[..lines.len().min(8)]);
}

fn draw_lines(screen: &mut Screen, lines: &[Line]) {
    let strs: [&str; 8] = core::array::from_fn(|i| lines.get(i).map_or("", |l| l.as_str()));
    screen.draw(&strs[..lines.len().min(8)]);
}

fn bar(fraction: f32) -> Line {
    let filled = ((fraction.clamp(0.0, 1.0) * 19.0) as usize).min(19);
    let mut l = text!("[");
    for i in 0..19 {
        let _ = core::fmt::Write::write_str(&mut l, if i < filled { "#" } else { "." });
    }
    let _ = core::fmt::Write::write_str(&mut l, "]");
    l
}

/// At most 5 characters: 0.33s, 11.8s, 689s, 16.7m, 420m, 12h.
fn short_time(s: f32) -> Line {
    if s < 9.995 {
        text!("{:.2}s", s)
    } else if s < 99.95 {
        text!("{:.1}s", s)
    } else if s < 999.5 {
        text!("{:.0}s", s)
    } else if s < 5997.0 {
        text!("{:.1}m", s / 60.0)
    } else if s < 59970.0 {
        text!("{:.0}m", s / 60.0)
    } else {
        text!("{:.0}h", s / 3600.0)
    }
}

fn long_time(s: f32) -> Line {
    if s < 60.0 {
        text!("{:.2} s", s)
    } else {
        let whole = s as u32;
        text!("{:.0} s ({}:{:02})", s, whole / 60, whole % 60)
    }
}

/// At most 5 characters.
fn short_rate(r: f32) -> Line {
    if r < 99_999.5 {
        text!("{:.0}", r)
    } else {
        text!("{:.0}k", r / 1000.0)
    }
}

fn thousands(n: u32) -> Line {
    if n >= 1_000_000 {
        text!("{},{:03},{:03}", n / 1_000_000, n / 1000 % 1000, n % 1000)
    } else if n >= 1000 {
        text!("{},{:03}", n / 1000, n % 1000)
    } else {
        text!("{}", n)
    }
}
