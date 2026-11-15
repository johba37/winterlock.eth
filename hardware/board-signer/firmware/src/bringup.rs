//! The first image for a wired board, before the signer (docs/notes/signer-app.md, "Before the
//! hardware is ready": "A small test image goes first"). It holds no key, signs nothing and writes
//! no flash.
//!
//! - **The OLED** (SDA GPIO21, SCL GPIO22): its address on the serial port, then a live screen.
//! - **The buttons** (left GPIO32, right GPIO33) and **BOOT** (GPIO0): levels and presses. Each is
//!   read with a pull-up, so its level at start tells push buttons to GND (high while idle) from
//!   touch modules (low while idle), which the signer's `touch-buttons` feature selects.
//! - **The serial link** (UART0 through the USB serial chip, 115200 baud): a status line every five
//!   seconds with the uptime, a line for each press and release, and every line typed to the board
//!   echoed back and shown on the screen. If the uptime starts again whenever a program opens the
//!   port, opening the port resets the board.
//! - **The entropy source:** DPORT's clock and reset bits for I2S0 (bit 4) and I2C0 (bit 7), and
//!   I2S0's CONF2 and SAMPLE_RATE_CONF, after `esp_hal::init`, after esp-hal's `TrngSource::new`,
//!   and after the signer's fix (hw.rs, `entropy_source_fix`), for the report to esp-hal.

#![no_std]
#![no_main]
#![deny(clippy::mem_forget, reason = "mem::forget is generally not safe to do with esp_hal types")]

extern crate alloc;

#[cfg(feature = "log")]
use esp_backtrace as _;

use alloc::format;
use alloc::string::String;
use esp_hal::{
    Blocking,
    clock::CpuClock,
    gpio::{Input, InputConfig, Pull},
    i2c::master::{Config as I2cConfig, I2c, SoftwareTimeout},
    main,
    rng::TrngSource,
    time::{Duration, Instant, Rate},
    uart::{Config as UartConfig, Uart, UartTx},
};
use ssd1306::command::AddrMode;
use ssd1306::mode::BasicMode;
use ssd1306::prelude::*;
use ssd1306::{I2CDisplayInterface, Ssd1306};
use winterlock_board::ui::Screen;

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(not(feature = "log"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

type Oled = Ssd1306<I2CInterface<I2c<'static, Blocking>>, DisplaySize128x64, BasicMode>;

/// The SSD1306 (or SSD1315) at 0x3C or 0x3D, as the signer finds it (hw.rs, `Display::probe`).
fn probe(mut i2c: I2c<'static, Blocking>) -> Option<(Oled, u8)> {
    let address = [0x3C, 0x3D].into_iter().find(|&a| i2c.write(a, &[0x00]).is_ok())?;
    let mut oled = Ssd1306::new(I2CDisplayInterface::new_custom_address(i2c, address), DisplaySize128x64, DisplayRotation::Rotate0);
    oled.init_with_addr_mode(AddrMode::Horizontal).ok()?;
    Some((oled, address))
}

fn draw(oled: &mut Option<(Oled, u8)>, s: &Screen) {
    let Some((o, _)) = oled.as_mut() else { return };
    let pages = s.render().to_pages();
    if o.set_draw_area((0, 0), (128, 64)).and_then(|_| o.draw(&pages)).is_err() {
        *oled = None;
    }
}

struct Out(UartTx<'static, Blocking>);

impl Out {
    fn line(&mut self, s: &str) {
        for part in [s.as_bytes(), b"\r\n"] {
            let mut b = part;
            while !b.is_empty() {
                match self.0.write(b) {
                    Ok(n) => b = &b[n..],
                    Err(_) => break,
                }
            }
        }
        let _ = self.0.flush();
    }
}

/// DPORT's PERIP_CLK_EN and PERIP_RST_EN, I2S0's CONF2 and SAMPLE_RATE_CONF.
fn entropy_regs() -> [u32; 4] {
    // SAFETY: reads of four registers
    unsafe {
        let d = &*esp32::DPORT::ptr();
        let i = &*esp32::I2S0::ptr();
        [d.perip_clk_en().read().bits(), d.perip_rst_en().read().bits(), i.conf2().read().bits(), i.sample_rate_conf().read().bits()]
    }
}

fn describe(r: [u32; 4]) -> String {
    format!(
        "PERIP_CLK_EN {:#010x} (I2S0 clock {}, I2C0 clock {}), PERIP_RST_EN {:#010x} (I2S0 reset {}, I2C0 reset {}), I2S0 CONF2 {:#010x}, SAMPLE_RATE_CONF {:#010x}",
        r[0],
        r[0] >> 4 & 1,
        r[0] >> 7 & 1,
        r[1],
        r[1] >> 4 & 1,
        r[1] >> 7 & 1,
        r[2],
        r[3]
    )
}

/// The signer's fix (hw.rs, `entropy_source_fix`): I2S0's clock on, out of reset, and ESP-IDF's
/// I2S0 setup again.
fn entropy_source_fix() {
    // SAFETY: the RNG and ADC1 belong to the TrngSource; nothing else here uses I2S0
    unsafe {
        let dport = &*esp32::DPORT::ptr();
        dport.perip_clk_en().modify(|_, w| w.i2s0_clk_en().set_bit());
        dport.perip_rst_en().modify(|_, w| w.i2s0_rst().clear_bit());
        let i2s0 = &*esp32::I2S0::ptr();
        i2s0.sample_rate_conf().modify(|_, w| w.rx_bck_div_num().bits(20));
        i2s0.conf2().modify(|_, w| w.camera_en().set_bit().lcd_en().set_bit().data_enable().set_bit().data_enable_test_en().set_bit());
        i2s0.conf().modify(|_, w| w.rx_start().set_bit());
    }
}

/// A button read with a pull-up, debounced over 20 ms; "pressed" is the level opposite to the one
/// it had at start.
struct Button {
    name: &'static str,
    input: Input<'static>,
    idle_high: bool,
    raw: bool,
    since: u64,
    pressed: bool,
    presses: u32,
}

impl Button {
    fn new(name: &'static str, input: Input<'static>) -> Self {
        let high = input.is_high();
        Button { name, input, idle_high: high, raw: high, since: 0, pressed: false, presses: 0 }
    }

    /// Some(true) on a press, Some(false) on a release.
    fn sample(&mut self, now: u64) -> Option<bool> {
        let raw = self.input.is_high();
        if raw != self.raw {
            self.raw = raw;
            self.since = now;
            return None;
        }
        let pressed = raw != self.idle_high;
        if pressed != self.pressed && now - self.since >= 20 {
            self.pressed = pressed;
            if pressed {
                self.presses += 1;
            }
            return Some(pressed);
        }
        None
    }

    fn kind(&self) -> &'static str {
        if self.idle_high { "push" } else { "touch" }
    }

    fn level(&self) -> &'static str {
        if self.raw { "high" } else { "low" }
    }

    fn short(&self) -> String {
        format!("{} {}", if self.pressed { "DOWN" } else { "up  " }, self.presses)
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[main]
fn main() -> ! {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 64 * 1024);

    // the entropy source's registers: before anything else touches I2C0 or I2S0
    let after_init = entropy_regs();
    let _entropy = TrngSource::new(p.RNG, p.ADC1);
    let after_esp_hal = entropy_regs();
    entropy_source_fix();
    let after_fix = entropy_regs();

    let uart = Uart::new(p.UART0, UartConfig::default()).expect("UART0").with_rx(p.GPIO3).with_tx(p.GPIO1);
    let (mut rx, tx) = uart.split();
    let mut out = Out(tx);

    let i2c_config = I2cConfig::default().with_frequency(Rate::from_khz(400)).with_software_timeout(SoftwareTimeout::Transaction(Duration::from_millis(50)));
    let mut oled = I2c::new(p.I2C0, i2c_config).ok().and_then(|i2c| probe(i2c.with_sda(p.GPIO21).with_scl(p.GPIO22)));

    let up = InputConfig::default().with_pull(Pull::Up);
    let mut buttons = [
        Button::new("left (GPIO32)", Input::new(p.GPIO32, up)),
        Button::new("right (GPIO33)", Input::new(p.GPIO33, up)),
        Button::new("BOOT (GPIO0)", Input::new(p.GPIO0, up)),
    ];

    out.line("");
    out.line(&format!("winterlock bring-up {VERSION}: no key, no signing, no flash writes"));
    out.line(&match &oled {
        Some((_, a)) => format!("oled: answers at {a:#04x}"),
        None => String::from("oled: none answers at 0x3c or 0x3d on SDA GPIO21 / SCL GPIO22"),
    });
    for b in &buttons[..2] {
        out.line(&format!(
            "{}: {} at start: {} (signer build: {})",
            b.name,
            b.level(),
            if b.idle_high { "push button to GND, or nothing wired" } else { "touch module" },
            if b.idle_high { "default" } else { "--features touch-buttons" }
        ));
    }
    out.line(&format!("{}: {} at start (high while not pressed)", buttons[2].name, buttons[2].level()));
    out.line("entropy source (for the esp-hal report):");
    out.line(&format!("  after esp_hal::init:        {}", describe(after_init)));
    out.line(&format!("  after TrngSource::new:      {}", describe(after_esp_hal)));
    out.line(&format!("  after the signer's fix:     {}", describe(after_fix)));
    out.line("type a line and Enter: the board echoes it and shows it");

    let start = Instant::now();
    let mut buf = [0u8; 64];
    let mut typed = String::new();
    let mut last = String::from("(nothing yet)");
    let mut rx_bytes: u32 = 0;
    let mut next_status = 5u64;
    let mut redraw = true;
    let mut shown_secs = u64::MAX;
    loop {
        let now = start.elapsed().as_millis();
        let secs = now / 1000;

        for b in buttons.iter_mut() {
            if let Some(pressed) = b.sample(now) {
                out.line(&format!("{} {} at {} ms ({} presses, level {})", b.name, if pressed { "pressed" } else { "released" }, now, b.presses, b.level()));
                redraw = true;
            }
        }

        match rx.read_buffered(&mut buf) {
            Ok(n) if n > 0 => {
                rx_bytes += n as u32;
                for &c in &buf[..n] {
                    if c == b'\r' || c == b'\n' {
                        if !typed.is_empty() {
                            out.line(&format!("echo: {typed}"));
                            last = core::mem::take(&mut typed);
                            redraw = true;
                        }
                    } else if (0x20..0x7f).contains(&c) && typed.len() < 60 {
                        typed.push(c as char);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {
                let _ = rx.check_for_errors();
            }
        }

        if secs >= next_status {
            next_status = secs + 5;
            out.line(&format!(
                "up {secs} s | left {} | right {} | BOOT {} | {} bytes received",
                buttons[0].short(),
                buttons[1].short(),
                buttons[2].short(),
                rx_bytes
            ));
        }

        if redraw || secs != shown_secs {
            redraw = false;
            shown_secs = secs;
            let l0 = format!("Left  {} {}", buttons[0].short(), buttons[0].kind());
            let l1 = format!("Right {} {}", buttons[1].short(), buttons[1].kind());
            let l2 = format!("BOOT  {}", buttons[2].short());
            let shown: String = last.chars().take(17).collect();
            let l3 = format!("rx: {shown}");
            let s = Screen::lines("Board check", &[&l0, &l1, &l2, &l3], "type on serial", "").with_corner(&format!("{secs}s"));
            draw(&mut oled, &s);
        }

        let t = Instant::now();
        while t.elapsed() < Duration::from_micros(1000) {}
    }
}
