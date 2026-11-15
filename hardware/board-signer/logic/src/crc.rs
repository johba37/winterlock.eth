//! The two checksums: CRC-32 (IEEE 802.3, as zlib's crc32) for records and frames, and
//! CRC-16/CCITT-FALSE (as Python's binascii.crc_hqx(data, 0xFFFF)) for frame headers.

const fn table32() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static T32: [u32; 256] = table32();

/// A running CRC-32.
#[derive(Clone, Copy)]
pub struct Crc32(u32);

impl Crc32 {
    pub const fn new() -> Self {
        Crc32(0xFFFF_FFFF)
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let mut c = self.0;
        for &b in data {
            c = T32[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
        self.0 = c;
        self
    }

    pub fn finish(&self) -> u32 {
        !self.0
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    Crc32::new().update(data).finish()
}

/// CRC-16/CCITT-FALSE: polynomial 0x1021, initial value 0xFFFF, no reflection.
pub fn crc16(data: &[u8]) -> u16 {
    let mut c: u16 = 0xFFFF;
    for &b in data {
        c ^= (b as u16) << 8;
        for _ in 0..8 {
            c = if c & 0x8000 != 0 { (c << 1) ^ 0x1021 } else { c << 1 };
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        // the standard check values for "123456789"
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc16(b"123456789"), 0x29B1);
        assert_eq!(crc32(b""), 0);
        let mut c = Crc32::new();
        c.update(b"1234").update(b"56789");
        assert_eq!(c.finish(), 0xCBF4_3926);
    }
}
