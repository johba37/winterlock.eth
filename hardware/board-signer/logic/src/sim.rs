//! A NOR flash in memory that behaves like the real one where it matters, for tests and the
//! virtual board: erasing sets a 4 KB sector to 0xFF, writing only clears bits, reads and writes
//! are 4-byte aligned. Power can be cut at any write or erase: that operation is left torn (part
//! of it done, the last word half done) and every operation after it fails, until the test
//! "reboots" from the bytes left behind.

use alloc::vec;
use alloc::vec::Vec;

use embedded_storage::nor_flash::{ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash};

pub const SECTOR: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimError {
    NotAligned,
    OutOfBounds,
    /// The power is off.
    Off,
    /// A write tried to set a bit that is 0 back to 1 (only an erase does that): a bug in the
    /// caller, since real flash would silently keep the 0.
    Overwrite,
}

impl NorFlashError for SimError {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            SimError::NotAligned => NorFlashErrorKind::NotAligned,
            SimError::OutOfBounds => NorFlashErrorKind::OutOfBounds,
            _ => NorFlashErrorKind::Other,
        }
    }
}

/// A flash in memory.
#[derive(Clone)]
pub struct SimFlash {
    pub mem: Vec<u8>,
    /// Write and erase operations done so far.
    pub ops: u64,
    /// Cut the power during this operation (counted from 0).
    pub cut_at: Option<u64>,
    pub off: bool,
    /// Make this operation (a write) store one bit wrong and carry on, as a failing chip might.
    pub corrupt_at: Option<u64>,
    rng: u64,
}

impl SimFlash {
    /// A blank flash of `sectors` sectors.
    pub fn new(sectors: usize) -> Self {
        SimFlash { mem: vec![0xFF; sectors * SECTOR], ops: 0, cut_at: None, off: false, corrupt_at: None, rng: 0x9E37_79B9_7F4A_7C15 }
    }

    /// The flash as the power left it, powered again: same bytes, counters reset.
    pub fn reboot(&self) -> Self {
        SimFlash { mem: self.mem.clone(), ops: 0, cut_at: None, off: false, corrupt_at: None, rng: self.rng }
    }

    /// Cuts the power during operation `n` from now, with a pattern drawn from `seed`.
    pub fn cut_after(&mut self, n: u64, seed: u64) {
        self.cut_at = Some(self.ops + n);
        self.rng ^= seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1;
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn op(&mut self) -> Result<bool, SimError> {
        if self.off {
            return Err(SimError::Off);
        }
        let cut = self.cut_at == Some(self.ops);
        self.ops += 1;
        Ok(cut)
    }
}

impl ErrorType for SimFlash {
    type Error = SimError;
}

impl ReadNorFlash for SimFlash {
    const READ_SIZE: usize = 4;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), SimError> {
        if self.off {
            return Err(SimError::Off);
        }
        let o = offset as usize;
        if o % 4 != 0 || bytes.len() % 4 != 0 {
            return Err(SimError::NotAligned);
        }
        if o + bytes.len() > self.mem.len() {
            return Err(SimError::OutOfBounds);
        }
        bytes.copy_from_slice(&self.mem[o..o + bytes.len()]);
        Ok(())
    }

    fn capacity(&self) -> usize {
        self.mem.len()
    }
}

impl NorFlash for SimFlash {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = SECTOR;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), SimError> {
        let (f, t) = (from as usize, to as usize);
        if f % SECTOR != 0 || t % SECTOR != 0 || f > t {
            return Err(SimError::NotAligned);
        }
        if t > self.mem.len() {
            return Err(SimError::OutOfBounds);
        }
        let mut s = f;
        while s < t {
            if self.op()? {
                // torn: some words erased, some untouched, some with only some bits set
                for w in (s..s + SECTOR).step_by(4) {
                    match self.next() % 3 {
                        0 => self.mem[w..w + 4].fill(0xFF),
                        1 => {}
                        _ => {
                            let m = (self.next() as u32).to_le_bytes();
                            for (b, bits) in self.mem[w..w + 4].iter_mut().zip(m) {
                                *b |= bits;
                            }
                        }
                    }
                }
                self.off = true;
                return Err(SimError::Off);
            }
            self.mem[s..s + SECTOR].fill(0xFF);
            s += SECTOR;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), SimError> {
        let o = offset as usize;
        if o % 4 != 0 || bytes.len() % 4 != 0 {
            return Err(SimError::NotAligned);
        }
        if o + bytes.len() > self.mem.len() {
            return Err(SimError::OutOfBounds);
        }
        if self.mem[o..o + bytes.len()].iter().zip(bytes).any(|(&old, &new)| old & new != new) {
            return Err(SimError::Overwrite);
        }
        if self.op()? {
            // torn: the first words written, one word with only some of its bits cleared
            let words = bytes.len() / 4;
            let full = (self.next() % (words as u64 + 1)) as usize;
            for (m, &b) in self.mem[o..o + full * 4].iter_mut().zip(bytes) {
                *m &= b;
            }
            if full < words {
                let m = (self.next() as u32).to_le_bytes();
                for i in 0..4 {
                    let at = o + full * 4 + i;
                    // clear only some of the bits this byte should lose
                    let lose = !bytes[full * 4 + i] & self.mem[at];
                    self.mem[at] &= !(lose & m[i]);
                }
            }
            self.off = true;
            return Err(SimError::Off);
        }
        let corrupt = self.corrupt_at == Some(self.ops - 1);
        for (m, &b) in self.mem[o..o + bytes.len()].iter_mut().zip(bytes) {
            *m &= b;
        }
        if corrupt {
            // a bit that should have been cleared stays set
            if let Some(i) = (0..bytes.len()).find(|&i| bytes[i] != 0xFF) {
                let bit = bytes[i].leading_ones();
                let bit = if bit < 8 { 0x80 >> bit } else { 0 };
                self.mem[o + i] |= bit;
            }
        }
        Ok(())
    }
}
