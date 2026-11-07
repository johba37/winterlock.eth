//! The optional OLED, the BOOT button and a small fixed-size text buffer (from esp32-bench).

use core::fmt;

use embedded_graphics::{
    mono_font::{MonoFont, MonoTextStyle, ascii::FONT_5X8},
    pixelcolor::BinaryColor,
    prelude::*,
    text::{Baseline, Text},
};
use esp_hal::{
    Blocking,
    gpio::Input,
    i2c::master::I2c,
    time::{Duration, Instant},
};
use esp_println::println;
use ssd1306::{I2CDisplayInterface, Ssd1306, mode::BufferedGraphicsMode, prelude::*};

/// 21 columns by 8 rows: the 5x8 glyphs with one pixel between characters.
const FONT: MonoFont<'static> = MonoFont {
    character_spacing: 1,
    ..FONT_5X8
};
pub const ROWS: usize = 8;
pub const COLS: usize = 21;

/// A line of text without an allocator. Longer text is cut off.
#[derive(Clone, Copy)]
pub struct Line {
    buf: [u8; 48],
    len: usize,
}

impl Line {
    pub const fn new() -> Self {
        Line {
            buf: [0; 48],
            len: 0,
        }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &c in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = c;
                self.len += 1;
            }
        }
        Ok(())
    }
}

/// `text!("...", args)` formats into a `Line`.
#[macro_export]
macro_rules! text {
    ($($arg:tt)*) => {{
        let mut l = $crate::ui::Line::new();
        let _ = core::fmt::Write::write_fmt(&mut l, format_args!($($arg)*));
        l
    }};
}

type Oled = Ssd1306<
    I2CInterface<I2c<'static, Blocking>>,
    DisplaySize128x64,
    BufferedGraphicsMode<DisplaySize128x64>,
>;

pub struct Screen {
    oled: Option<Oled>,
    pub address: Option<u8>,
}

impl Screen {
    /// Looks for an SSD1306/SSD1315 at 0x3C, then 0x3D. Without one, everything carries on over
    /// serial only.
    pub fn probe(mut i2c: I2c<'static, Blocking>) -> Screen {
        // A control byte with no command: harmless, and the display ACKs its address.
        let address = [0x3C, 0x3D]
            .into_iter()
            .find(|&a| i2c.write(a, &[0x00]).is_ok());
        let Some(address) = address else {
            return Screen {
                oled: None,
                address: None,
            };
        };
        let interface = I2CDisplayInterface::new_custom_address(i2c, address);
        let mut oled = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
            .into_buffered_graphics_mode();
        if oled.init().is_err() {
            println!(
                "display: 0x{:02X} answered but did not take the init sequence",
                address
            );
            return Screen {
                oled: None,
                address: None,
            };
        }
        Screen {
            oled: Some(oled),
            address: Some(address),
        }
    }

    pub fn none() -> Screen {
        Screen {
            oled: None,
            address: None,
        }
    }

    /// Shows up to 8 lines and echoes them on serial, so a run without a display still shows
    /// what the screen would say.
    pub fn show(&mut self, lines: &[&str]) {
        println!("  +---------------------+");
        for l in lines.iter().take(ROWS) {
            println!("  |{:<21}|", l);
        }
        println!("  +---------------------+");
        if lines.len() > ROWS || lines.iter().any(|l| l.chars().count() > COLS) {
            println!("  (more than 8 lines or 21 characters: the display cuts it off)");
        }
        self.draw(lines);
    }

    /// Like `show`, without the serial echo (for progress bars).
    pub fn draw(&mut self, lines: &[&str]) {
        let Some(oled) = self.oled.as_mut() else {
            return;
        };
        oled.clear_buffer();
        let style = MonoTextStyle::new(&FONT, BinaryColor::On);
        for (row, l) in lines.iter().take(ROWS).enumerate() {
            let _ = Text::with_baseline(l, Point::new(0, row as i32 * 8), style, Baseline::Top)
                .draw(oled);
        }
        if oled.flush().is_err() {
            println!("display: write failed, carrying on without it");
            self.oled = None;
        }
    }
}

/// The BOOT button (GPIO0, low when pressed).
pub struct Button {
    pin: Input<'static>,
}

impl Button {
    pub fn new(pin: Input<'static>) -> Self {
        Button { pin }
    }

    #[cfg_attr(feature = "scripted-boot", allow(dead_code))]
    fn down(&self) -> bool {
        self.pin.is_low()
    }

    /// For QEMU, which can't press BOOT: every wait ends in a press after 1.5 s.
    #[cfg(feature = "scripted-boot")]
    pub fn wait_down(&self, _timeout: Option<Duration>) -> bool {
        sleep(Duration::from_millis(1500));
        println!("scripted: BOOT pressed");
        true
    }

    #[cfg(feature = "scripted-boot")]
    pub fn wait_up(&self) {}

    /// Waits for a press that starts after the button was seen released, so a pin that reads
    /// low all the time (a stuck button, an emulator) never counts as a press.
    #[cfg(not(feature = "scripted-boot"))]
    pub fn wait_down(&self, timeout: Option<Duration>) -> bool {
        let start = Instant::now();
        let mut armed = false;
        loop {
            if timeout.is_some_and(|t| start.elapsed() >= t) {
                return false;
            }
            if !self.down() {
                armed = true;
            } else if armed {
                sleep(Duration::from_millis(20));
                if self.down() {
                    return true;
                }
            }
        }
    }

    #[cfg(not(feature = "scripted-boot"))]
    pub fn wait_up(&self) {
        loop {
            while self.down() {}
            sleep(Duration::from_millis(20));
            if !self.down() {
                return;
            }
        }
    }
}

pub fn sleep(d: Duration) {
    let start = Instant::now();
    while start.elapsed() < d {}
}
