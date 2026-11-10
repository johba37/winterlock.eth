//! An append-only log of records on a NOR flash partition. Records are only ever appended and
//! never changed in place, so a power cut can only damage the record being written; the
//! partition is erased as a whole, and only to wipe the board.
//!
//! A record, 4-byte aligned:
//! ```text
//!   0   1  type
//!   1   1  0xA5
//!   2   2  payload length n (big-endian)
//!   4   4  the bitwise complement of bytes 0..4
//!   8   n  payload, then zero bytes up to a multiple of 4
//!   ..  4  CRC-32 of everything before it in the record (big-endian)
//! ```
//! The header (8 bytes) is written first, on its own, then the rest. Programming NOR flash only
//! clears bits, so a write cut short leaves extra 1 bits: a header and its complement can't both
//! come out valid from a torn write. So a scan reading a valid header knows the record's exact
//! length; a bad CRC there means a torn body, which the scan skips by that length. A header that
//! isn't valid and isn't blank is a torn header: nothing after it was written before the cut, so
//! the scan moves on 4 bytes at a time until it finds a valid header or blank flash. Blank flash
//! (8 bytes of 0xFF where a header would be) ends the log.

use embedded_storage::nor_flash::NorFlash;

use crate::crc::Crc32;

pub const SECTOR: u32 = 4096;
pub const HEADER: u32 = 8;
/// The bytes of a record's start that a scan hands over (every record's fixed fields fit).
pub const HEAD: usize = 128;
const CHUNK: usize = 256;
const MARK: u8 = 0xA5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogError {
    /// The flash refused an operation.
    Flash,
    /// No room for the record.
    Full,
    /// A record read back differs from what was written: it isn't durable.
    ReadBack,
}

/// A record found by a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub offset: u32,
    pub ty: u8,
    pub len: u32,
}

impl Found {
    /// Where the payload starts.
    pub fn payload(&self) -> u32 {
        self.offset + HEADER
    }
}

/// What a scan saw besides records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scanned {
    /// Bytes skipped: torn records or garbage.
    pub skipped: u32,
    /// The first skip's offset, if any.
    pub first_skip: Option<u32>,
    pub records: u32,
}

pub fn record_size(len: u32) -> u32 {
    HEADER + len.div_ceil(4) * 4 + 4
}

fn header(ty: u8, len: u16) -> [u8; 8] {
    let a = [ty, MARK, (len >> 8) as u8, len as u8];
    let c = (!u32::from_be_bytes(a)).to_be_bytes();
    [a[0], a[1], a[2], a[3], c[0], c[1], c[2], c[3]]
}

fn parse_header(h: &[u8; 8]) -> Option<(u8, u32)> {
    let a = u32::from_be_bytes(h[..4].try_into().unwrap());
    let c = u32::from_be_bytes(h[4..].try_into().unwrap());
    (a == !c && h[1] == MARK).then(|| (h[0], u16::from_be_bytes([h[2], h[3]]) as u32))
}

pub struct Log<F> {
    pub flash: F,
    size: u32,
    end: u32,
}

impl<F: NorFlash> Log<F> {
    /// A log over the whole of `flash` (a partition: a whole number of 4 KB sectors).
    pub fn new(flash: F) -> Self {
        assert!(F::WRITE_SIZE <= 4 && 4 % F::WRITE_SIZE == 0, "writes of 4 bytes must be allowed");
        assert!(F::READ_SIZE <= 4 && 4 % F::READ_SIZE == 0, "reads of 4 bytes must be allowed");
        assert!(F::ERASE_SIZE as u32 == SECTOR, "4 KB sectors");
        let size = (flash.capacity() as u32) / SECTOR * SECTOR;
        Log { flash, size, end: 0 }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Where the next record goes: the bytes in use.
    pub fn end(&self) -> u32 {
        self.end
    }

    /// Reads any bytes at any offset (the flash may need aligned reads).
    pub fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), LogError> {
        let rs = F::READ_SIZE as u32;
        if offset % rs == 0 && out.len() as u32 % rs == 0 {
            return self.flash.read(offset, out).map_err(|_| LogError::Flash);
        }
        let mut tmp = [0u8; 64];
        let mut done = 0usize;
        while done < out.len() {
            let pos = offset + done as u32;
            let aligned = pos - pos % rs;
            let skip = (pos - aligned) as usize;
            let want = (skip + out.len() - done).min(tmp.len());
            let n = want.div_ceil(rs as usize) * rs as usize;
            self.flash.read(aligned, &mut tmp[..n]).map_err(|_| LogError::Flash)?;
            let take = (n - skip).min(out.len() - done);
            out[done..done + take].copy_from_slice(&tmp[skip..skip + take]);
            done += take;
        }
        Ok(())
    }

    fn blank(&mut self, offset: u32, len: u32) -> Result<bool, LogError> {
        let mut buf = [0u8; CHUNK];
        let mut at = offset;
        while at < offset + len {
            let n = ((offset + len - at) as usize).min(CHUNK);
            self.read(at, &mut buf[..n])?;
            if buf[..n].iter().any(|&b| b != 0xFF) {
                return Ok(false);
            }
            at += n as u32;
        }
        Ok(true)
    }

    /// Reads the log from the start, calls `visit` with each valid record and its first bytes (up
    /// to [`HEAD`]), and sets the append position after the last thing written.
    pub fn scan(&mut self, mut visit: impl FnMut(Found, &[u8])) -> Result<Scanned, LogError> {
        let mut s = Scanned::default();
        let mut pos = 0u32;
        let mut head = [0u8; HEAD];
        let mut buf = [0u8; CHUNK];
        while pos + HEADER <= self.size {
            let mut h = [0u8; 8];
            self.read(pos, &mut h)?;
            if h == [0xFF; 8] {
                break;
            }
            let Some((ty, len)) = parse_header(&h) else {
                s.skipped += 4;
                s.first_skip.get_or_insert(pos);
                pos += 4;
                continue;
            };
            let total = record_size(len);
            if pos + total > self.size {
                // can't have been written whole: garbage
                s.skipped += 4;
                s.first_skip.get_or_insert(pos);
                pos += 4;
                continue;
            }
            let mut crc = Crc32::new();
            crc.update(&h);
            let body = total - HEADER - 4;
            let mut at = 0u32;
            while at < body {
                let n = ((body - at) as usize).min(CHUNK);
                self.read(pos + HEADER + at, &mut buf[..n])?;
                let k = at as usize;
                if k < HEAD {
                    let m = n.min(HEAD - k);
                    head[k..k + m].copy_from_slice(&buf[..m]);
                }
                crc.update(&buf[..n]);
                at += n as u32;
            }
            let mut c = [0u8; 4];
            self.read(pos + total - 4, &mut c)?;
            if u32::from_be_bytes(c) == crc.finish() {
                s.records += 1;
                visit(Found { offset: pos, ty, len }, &head[..(len as usize).min(HEAD)]);
            } else {
                s.skipped += total;
                s.first_skip.get_or_insert(pos);
            }
            pos += total;
        }
        self.end = pos.min(self.size);
        Ok(s)
    }

    /// Appends a record whose payload is `parts` joined, then reads it back. Returns its offset
    /// only once the flash holds it exactly: durable. A failure leaves the append position past
    /// whatever was written, so the next record doesn't overlap it.
    pub fn append(&mut self, ty: u8, parts: &[&[u8]]) -> Result<u32, LogError> {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        assert!(len <= u16::MAX as usize, "record too long");
        let total = record_size(len as u32);
        let at = self.end;
        if at + total > self.size {
            return Err(LogError::Full);
        }
        if !self.blank(at, HEADER)? {
            // something is already there: step past it rather than write over it
            self.end = at + 4;
            return Err(LogError::ReadBack);
        }
        self.end = at + total;
        let h = header(ty, len as u16);
        self.flash.write(at, &h).map_err(|_| LogError::Flash)?;
        let mut crc = Crc32::new();
        crc.update(&h);
        // the body: the payload, zero padding, the CRC, written through a buffer of CHUNK bytes
        let mut buf = [0u8; CHUNK];
        let mut fill = 0usize;
        let mut off = at + HEADER;
        let pad = (4 - len % 4) % 4;
        let zeros = [0u8; 3];
        {
            let mut emit = |bytes: &[u8], crc: Option<&mut Crc32>, flash: &mut F| -> Result<(), LogError> {
                if let Some(c) = crc {
                    c.update(bytes);
                }
                let mut b = bytes;
                while !b.is_empty() {
                    let n = b.len().min(CHUNK - fill);
                    buf[fill..fill + n].copy_from_slice(&b[..n]);
                    fill += n;
                    b = &b[n..];
                    if fill == CHUNK {
                        flash.write(off, &buf).map_err(|_| LogError::Flash)?;
                        off += CHUNK as u32;
                        fill = 0;
                    }
                }
                Ok(())
            };
            for p in parts {
                emit(p, Some(&mut crc), &mut self.flash)?;
            }
            emit(&zeros[..pad], Some(&mut crc), &mut self.flash)?;
            let c = crc.finish().to_be_bytes();
            emit(&c, None, &mut self.flash)?;
        }
        if fill > 0 {
            self.flash.write(off, &buf[..fill]).map_err(|_| LogError::Flash)?;
        }
        // read back: header, payload, padding, CRC
        let mut back = [0u8; 8];
        self.read(at, &mut back)?;
        if back != h {
            return Err(LogError::ReadBack);
        }
        let mut pos = at + HEADER;
        let mut check = Crc32::new();
        check.update(&h);
        for p in parts.iter().copied().chain(core::iter::once(&zeros[..pad])) {
            let mut b = p;
            while !b.is_empty() {
                let n = b.len().min(CHUNK);
                self.read(pos, &mut buf[..n])?;
                if buf[..n] != b[..n] {
                    return Err(LogError::ReadBack);
                }
                check.update(&buf[..n]);
                pos += n as u32;
                b = &b[n..];
            }
        }
        let mut c = [0u8; 4];
        self.read(pos, &mut c)?;
        if u32::from_be_bytes(c) != check.finish() {
            return Err(LogError::ReadBack);
        }
        Ok(at)
    }

    /// Erases the partition: the first sector first (it holds the seed), then every sector that
    /// isn't blank. Afterwards the log is empty.
    pub fn wipe(&mut self) -> Result<(), LogError> {
        self.flash.erase(0, SECTOR).map_err(|_| LogError::Flash)?;
        let mut s = SECTOR;
        while s < self.size {
            if !self.blank(s, SECTOR)? {
                self.flash.erase(s, s + SECTOR).map_err(|_| LogError::Flash)?;
            }
            s += SECTOR;
        }
        if !self.blank(0, SECTOR)? {
            return Err(LogError::ReadBack);
        }
        self.end = 0;
        Ok(())
    }
}
