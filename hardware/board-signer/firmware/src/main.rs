//! Winterlock's board signer on an ESP32-WROOM-32 (docs/notes/signer-app.md, "The board"): the
//! logic crate (`../logic`) with a 128x64 OLED on I2C (SDA GPIO21, SCL GPIO22), two buttons (left
//! GPIO32, right GPIO33), the flash partition `signer`, and framed messages over UART0, the board's
//! USB serial chip, at 115200 baud.
//!
//! The release image prints nothing of its own on UART0: only frames go out. A build with
//! `test-hooks` (for QEMU) also takes simulated buttons over the link and prints each screen and
//! some diagnostics as text between the frames.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![deny(clippy::mem_forget, reason = "mem::forget is generally not safe to do with esp_hal types")]

extern crate alloc;

mod dual;
mod hw;

#[cfg(all(any(feature = "test-hooks", feature = "log"), feature = "release-image"))]
compile_error!("a release image has neither the test hooks nor the serial diagnostics");

#[cfg(feature = "log")]
use esp_backtrace as _;

use esp_hal::{
    clock::CpuClock,
    gpio::{Input, InputConfig, Pull},
    i2c::master::{Config as I2cConfig, I2c, SoftwareTimeout},
    main,
    rng::{Trng, TrngSource},
    system::CpuControl,
    time::{Duration, Instant, Rate},
    uart::{Config as UartConfig, Uart},
};
use esp_storage::FlashStorage;
use winterlock_board::Board;
use winterlock_board::input::{Buttons, Timing};
use winterlock_board::proto::Deframer;
use winterlock_board::ui::Screen;

use hw::{Display, Hw, Partition};

esp_bootloader_esp_idf::esp_app_desc!();

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The heap: the memory the bootloader used (96 KB) and a part of main DRAM.
const HEAP_RECLAIMED: usize = 96 * 1024;
const HEAP_MAIN: usize = 80 * 1024;
/// The signer's data partition, as build.rs read it from partitions.csv.
const SIGNER_OFFSET: u32 = parse(env!("SIGNER_OFFSET"));
const SIGNER_SIZE: u32 = parse(env!("SIGNER_SIZE"));
/// A frame that stops arriving for this long is given up.
const STALL: Duration = Duration::from_millis(300);

const fn parse(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut v = 0u32;
    let mut i = 0;
    while i < b.len() {
        v = v * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    v
}

#[cfg(not(feature = "log"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // the release image says nothing on the serial port: it stops, and the screen keeps its last
    // frame; unplugging restarts it
    loop {
        core::hint::spin_loop();
    }
}

macro_rules! log {
    ($($t:tt)*) => {
        #[cfg(feature = "log")]
        esp_println::println!($($t)*);
    };
}

/// Shows a fixed screen when the board can't start (no partition, a flash that fails).
fn halt(display: &mut Display, title: &str, lines: &[&str]) -> ! {
    let s = Screen::lines(title, lines, "", "");
    display.draw(&s.render());
    log!("halted: {} {:?}", title, lines);
    loop {
        core::hint::spin_loop();
    }
}

#[main]
fn main() -> ! {
    enable_fpu();
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: HEAP_RECLAIMED);
    esp_alloc::heap_allocator!(size: HEAP_MAIN);
    dual::paint_main_stack();
    log!("winterlock-board {} (test build: screens and diagnostics on serial)", VERSION);

    // the random number generator, with the SAR ADC as its entropy source (radio off)
    let _entropy = TrngSource::new(p.RNG, p.ADC1);
    hw::entropy_source_fix();
    let trng = Trng::try_new().expect("the entropy source is on");
    log!("rng: SAR ADC entropy source on, I2S0 clock {}", if hw::i2s0_clock_on() { "on" } else { "OFF" });

    // the OLED
    let i2c_config = I2cConfig::default().with_frequency(Rate::from_khz(400)).with_software_timeout(SoftwareTimeout::Transaction(Duration::from_millis(50)));
    let mut display = match I2c::new(p.I2C0, i2c_config) {
        Ok(i2c) => Display::probe(i2c.with_sda(p.GPIO21).with_scl(p.GPIO22)),
        Err(_) => Display::none(),
    };
    log!("display: {:?}", display.address);

    // the serial link: UART0 through the board's USB serial chip
    let uart = match Uart::new(p.UART0, UartConfig::default()) {
        Ok(u) => u.with_rx(p.GPIO3).with_tx(p.GPIO1),
        Err(_) => halt(&mut display, "Serial failed", &["The USB serial port", "didn't start."]),
    };
    let (mut rx, tx) = uart.split();

    // the buttons: push buttons to GND (low while pressed) or touch modules (high)
    let (pull, active_high) = if cfg!(feature = "touch-buttons") { (Pull::Down, true) } else { (Pull::Up, false) };
    let left = Input::new(p.GPIO32, InputConfig::default().with_pull(pull));
    let right = Input::new(p.GPIO33, InputConfig::default().with_pull(pull));
    let down = |i: &Input| i.is_high() == active_high;

    // the flash partition, checked against the table the board booted with
    let mut flash = FlashStorage::new(p.FLASH);
    let mut table = [0u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];
    let part = esp_bootloader_esp_idf::partitions::read_partition_table(&mut flash, &mut table)
        .ok()
        .and_then(|t| t.iter().find(|e| e.label_as_str() == "signer").map(|e| (e.offset(), e.len(), e.partition_type())));
    match part {
        Some((off, len, esp_bootloader_esp_idf::partitions::PartitionType::Data(esp_bootloader_esp_idf::partitions::DataPartitionSubType::Undefined)))
            if off == SIGNER_OFFSET && len == SIGNER_SIZE && (off + len) as usize <= flash.capacity() => {}
        _ => halt(&mut display, "No storage", &["The partition table", "has no signer", "partition: flash", "the full image."]),
    }
    log!("flash: {} bytes; signer partition at {:#x}, {} bytes", flash.capacity(), SIGNER_OFFSET, SIGNER_SIZE);

    let dual = dual::Dual::new(CpuControl::new(p.CPU_CTRL));
    let platform = Hw::new(tx, display, trng, dual);
    let mut board = match Board::new(Partition::new(flash, SIGNER_OFFSET, SIGNER_SIZE), platform, VERSION) {
        Ok(b) => b,
        Err(_) => {
            // the flash partition couldn't be read or written: the board can't start (the display
            // went with the platform into the board that failed, so it keeps its blank frame)
            log!("halted: the signer partition can't be read or written");
            loop {
                core::hint::spin_loop();
            }
        }
    };
    log!("started: {:?}, {} key trees", board.store.phase(), board.store.trees().len());

    let mut buttons = Buttons::new(Timing::default());
    let mut deframer = Deframer::new();
    let mut buf = [0u8; 256];
    let mut last_rx = Instant::now();
    let start = Instant::now();
    loop {
        // the link: bytes in, frames out of them
        match rx.read_buffered(&mut buf) {
            Ok(0) => {
                if deframer.held() > 0 && last_rx.elapsed() > STALL {
                    deframer.stalled();
                    last_rx = Instant::now();
                    while let Some(f) = deframer.next_frame() {
                        handle(&mut board, &f);
                    }
                }
            }
            Ok(n) => {
                deframer.push(&buf[..n]);
                last_rx = Instant::now();
                while let Some(f) = deframer.next_frame() {
                    handle(&mut board, &f);
                    last_rx = Instant::now();
                }
            }
            Err(_) => {
                // an overrun or a framing error: the bytes are lost, the frame's checks catch it
                let _ = rx.check_for_errors();
            }
        }
        // the buttons, sampled about every millisecond
        let now = start.elapsed().as_millis();
        if let Some(ev) = buttons.sample(now, down(&left), down(&right)) {
            board.button(ev);
        }
        let t = Instant::now();
        while t.elapsed() < Duration::from_micros(500) {}
    }
}

/// A frame from the app: to the board, except the test build's memory report.
fn handle(board: &mut Board<Partition, Hw>, f: &winterlock_board::proto::Frame) {
    #[cfg(feature = "test-hooks")]
    if f.ty == winterlock_board::proto::ty::TEST_MEMORY {
        let heap = esp_alloc::HEAP.stats();
        let (s0, s0_size) = dual::main_stack_used();
        let (s1, s1_size) = dual::app_stack_used();
        let mut w = winterlock_board::proto::Writer::new();
        w.u32(heap.max_usage as u32).u32(heap.size as u32).u32(heap.current_usage as u32).u32(s0 as u32).u32(s0_size as u32).u32(s1 as u32).u32(s1_size as u32).u32(board.platform.dual.runs);
        let bytes = winterlock_board::proto::encode(winterlock_board::proto::ty::A_MEMORY, f.id, &w.0);
        winterlock_board::Platform::send(&mut board.platform, &bytes);
        return;
    }
    #[cfg(feature = "test-hooks")]
    if f.ty == winterlock_board::proto::ty::TEST_STALL && f.payload.len() == 4 {
        let n = u32::from_be_bytes(f.payload[..4].try_into().unwrap());
        hw::STALL.store(n, core::sync::atomic::Ordering::Relaxed);
        let bytes = winterlock_board::proto::encode(winterlock_board::proto::ty::A_DONE, f.id, &[]);
        winterlock_board::Platform::send(&mut board.platform, &bytes);
        return;
    }
    board.frame(f);
}

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
