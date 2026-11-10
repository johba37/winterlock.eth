//! The board's hardware for the logic crate: the flash partition, the OLED, the random number
//! generator, the serial link and the second core.

use embedded_storage::nor_flash::{ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash};
use esp_hal::{Blocking, i2c::master::I2c, rng::Trng, uart::UartTx};
use esp_storage::FlashStorage;
use ssd1306::command::AddrMode;
use ssd1306::mode::BasicMode;
use ssd1306::prelude::*;
use ssd1306::{I2CDisplayInterface, Ssd1306};
use winterlock_board::Platform;
use winterlock_board::ui::{Frame, Screen};
use winterlock_core::keccak::Keccak256;

use crate::dual::Dual;

// --- the flash partition ---

/// A partition of the SPI flash as a NOR flash of its own: offsets from its start.
pub struct Partition {
    flash: FlashStorage<'static>,
    offset: u32,
    size: u32,
}

impl Partition {
    pub fn new(flash: FlashStorage<'static>, offset: u32, size: u32) -> Self {
        Partition { flash, offset, size }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PartitionError(NorFlashErrorKind);

impl NorFlashError for PartitionError {
    fn kind(&self) -> NorFlashErrorKind {
        self.0
    }
}

impl ErrorType for Partition {
    type Error = PartitionError;
}

/// Test builds only: flash writes and erases left until the firmware stops right after one, as if
/// the power went there (0: never).
#[cfg(feature = "test-hooks")]
pub static STALL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Called after each flash write or erase.
#[cfg(feature = "test-hooks")]
fn stall_point() {
    use core::sync::atomic::Ordering;
    let left = STALL.load(Ordering::Relaxed);
    if left == 0 {
        return;
    }
    if left == 1 {
        esp_println::println!("STALLED after a flash write (test hook): kill QEMU now");
        loop {
            core::hint::spin_loop();
        }
    }
    STALL.store(left - 1, Ordering::Relaxed);
}

impl Partition {
    fn check(&self, offset: u32, len: usize) -> Result<u32, PartitionError> {
        if offset as u64 + len as u64 > self.size as u64 {
            return Err(PartitionError(NorFlashErrorKind::OutOfBounds));
        }
        Ok(self.offset + offset)
    }
}

impl ReadNorFlash for Partition {
    const READ_SIZE: usize = <FlashStorage<'static> as ReadNorFlash>::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), PartitionError> {
        let at = self.check(offset, bytes.len())?;
        ReadNorFlash::read(&mut self.flash, at, bytes).map_err(|e| PartitionError(e.kind()))
    }

    fn capacity(&self) -> usize {
        self.size as usize
    }
}

impl NorFlash for Partition {
    const WRITE_SIZE: usize = <FlashStorage<'static> as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <FlashStorage<'static> as NorFlash>::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), PartitionError> {
        if from > to {
            return Err(PartitionError(NorFlashErrorKind::OutOfBounds));
        }
        let a = self.check(from, (to - from) as usize)?;
        let r = NorFlash::erase(&mut self.flash, a, a + (to - from)).map_err(|e| PartitionError(e.kind()));
        #[cfg(feature = "test-hooks")]
        stall_point();
        r
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), PartitionError> {
        let at = self.check(offset, bytes.len())?;
        let r = NorFlash::write(&mut self.flash, at, bytes).map_err(|e| PartitionError(e.kind()));
        #[cfg(feature = "test-hooks")]
        stall_point();
        r
    }
}

// --- the OLED ---

type Oled = Ssd1306<I2CInterface<I2c<'static, Blocking>>, DisplaySize128x64, BasicMode>;

/// The SSD1306 (or SSD1315) at 0x3C or 0x3D, if one answers.
pub struct Display {
    oled: Option<Oled>,
    #[cfg_attr(not(feature = "log"), allow(dead_code))]
    pub address: Option<u8>,
}

impl Display {
    pub fn probe(mut i2c: I2c<'static, Blocking>) -> Display {
        // a control byte with no command: harmless, and the display acknowledges its address
        let Some(address) = [0x3C, 0x3D].into_iter().find(|&a| i2c.write(a, &[0x00]).is_ok()) else {
            return Display { oled: None, address: None };
        };
        let mut oled = Ssd1306::new(I2CDisplayInterface::new_custom_address(i2c, address), DisplaySize128x64, DisplayRotation::Rotate0);
        if oled.init_with_addr_mode(AddrMode::Horizontal).is_err() {
            return Display { oled: None, address: None };
        }
        Display { oled: Some(oled), address: Some(address) }
    }

    pub fn none() -> Display {
        Display { oled: None, address: None }
    }

    pub fn draw(&mut self, frame: &Frame) {
        let Some(oled) = self.oled.as_mut() else { return };
        let pages = frame.to_pages();
        if oled.set_draw_area((0, 0), (128, 64)).and_then(|_| oled.draw(&pages)).is_err() {
            // a display that stops answering: carry on without it
            self.oled = None;
        }
    }
}

// --- randomness ---

/// esp-hal 1.2.2 turns on the SAR ADC entropy source as ESP-IDF's bootloader does
/// (`bootloader_random_enable`), except that on the classic ESP32 it enables the clock of I2C0
/// (DPORT bit 7) where ESP-IDF enables I2S0's (bit 4): I2S0 is what carries the ADC's readings to
/// the generator, and its registers don't take writes without a clock. This enables I2S0, takes
/// it out of reset and repeats ESP-IDF's I2S0 setup. Call it after `TrngSource::new`.
pub fn entropy_source_fix() {
    // SAFETY: the RNG and ADC1 peripherals are owned by the TrngSource, which configured the rest
    // of this path; I2S0 isn't used by anything else in this firmware.
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

/// Whether the I2S0 clock is on (for the start-up report).
#[cfg(feature = "log")]
pub fn i2s0_clock_on() -> bool {
    // SAFETY: a read of a clock-enable register
    unsafe { (*esp32::DPORT::ptr()).perip_clk_en().read().i2s0_clk_en().bit_is_set() }
}

// --- the platform ---

pub struct Hw {
    pub tx: UartTx<'static, Blocking>,
    pub display: Display,
    pub trng: Trng,
    pub dual: Dual<'static>,
    /// Every random byte goes through this pool: hardware words and the cycle counter, hashed.
    pool: [u8; 32],
    #[cfg(feature = "log")]
    last: alloc::vec::Vec<alloc::string::String>,
}

impl Hw {
    pub fn new(tx: UartTx<'static, Blocking>, display: Display, trng: Trng, dual: Dual<'static>) -> Self {
        let mut hw = Hw {
            tx,
            display,
            trng,
            dual,
            pool: [0; 32],
            #[cfg(feature = "log")]
            last: alloc::vec::Vec::new(),
        };
        hw.stir(256);
        hw
    }

    /// Hashes `words` words of the generator and the cycle counter into the pool.
    fn stir(&mut self, words: usize) {
        let mut h = Keccak256::new();
        h.update(b"winterlock.board.rng-pool.v1").update(&self.pool);
        for _ in 0..words {
            h.update(&self.trng.random().to_le_bytes());
            h.update(&esp_hal::xtensa_lx::timer::get_cycle_count().to_le_bytes());
        }
        self.pool = h.finalize();
    }
}

impl Platform for Hw {
    fn random(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            self.stir(16);
            let mut h = Keccak256::new();
            h.update(b"winterlock.board.rng-out.v1").update(&self.pool);
            let r = h.finalize();
            chunk.copy_from_slice(&r[..chunk.len()]);
            // the pool moves on, so an output never reveals the next
            self.stir(1);
        }
    }

    fn show(&mut self, screen: &Screen, frame: &Frame) {
        self.display.draw(frame);
        #[cfg(feature = "log")]
        {
            // test builds: the screen in a box on the serial port, when its text changes
            let text = screen.text();
            if text != self.last {
                esp_println::println!("  +---------------------+");
                for l in &text {
                    esp_println::println!("  |{:<21}|", l);
                }
                esp_println::println!("  +---------------------+");
                self.last = text;
            }
        }
        #[cfg(not(feature = "log"))]
        let _ = screen;
    }

    fn send(&mut self, bytes: &[u8]) {
        let mut b = bytes;
        while !b.is_empty() {
            match self.tx.write(b) {
                Ok(n) => b = &b[n..],
                Err(_) => break,
            }
        }
        let _ = self.tx.flush();
    }

    fn both(&mut self, here: &mut (dyn FnMut() + Send), there: &mut (dyn FnMut() + Send)) {
        if self.dual.run(|| here(), || there()).is_err() {
            // the second core didn't start: its half on this one
            there();
        }
    }
}
