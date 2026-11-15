//! The USB link: framed binary messages over the board's serial port (UART0, its CP2102). The
//! same port carries the ROM bootloader's text at every start, so the reader hunts for a frame's
//! magic and checks two checksums; anything else is skipped. PROTOCOL.md describes the messages.
//!
//! A frame (all numbers big-endian):
//! ```text
//!   0   4  magic A5 57 4C 5A ("\xA5WLZ")
//!   4   1  version (1)
//!   5   1  type
//!   6   2  id: a request's id, echoed by its answer (0 for an event)
//!   8   2  payload length, at most MAX_PAYLOAD
//!  10   2  CRC-16/CCITT-FALSE of bytes 4..10
//!  12   n  payload
//! 12+n  4  CRC-32 (zlib's) of bytes 4..12+n
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use winterlock_core::U256;
use winterlock_core::safe::{Operation, SafeTx};

use crate::crc::{crc16, crc32};
#[cfg(feature = "test-hooks")]
use crate::input::Button;

pub const MAGIC: [u8; 4] = [0xA5, b'W', b'L', 0x5A];
pub const VERSION: u8 = 1;
pub const HEADER: usize = 12;
pub const MAX_PAYLOAD: usize = 16 * 1024;
/// A frame's bytes around its payload.
pub const OVERHEAD: usize = HEADER + 4;

/// Message types: requests from the app (below 0x80), answers and events from the board.
pub mod ty {
    pub const STATUS: u8 = 0x01;
    pub const SETUP: u8 = 0x02;
    pub const RECOVER: u8 = 0x03;
    pub const GAS_KEY: u8 = 0x04;
    pub const TREES: u8 = 0x05;
    pub const ENROL: u8 = 0x06;
    pub const SIGN: u8 = 0x07;
    pub const CANCEL: u8 = 0x08;
    /// Test builds only: button events, as if pressed (feature `test-hooks`).
    #[cfg(feature = "test-hooks")]
    pub const TEST_BUTTONS: u8 = 0x70;
    /// Test builds only: the screen's text.
    #[cfg(feature = "test-hooks")]
    pub const TEST_SCREEN: u8 = 0x71;
    /// Test builds only: the firmware's heap and stack use (answered by the firmware itself).
    #[cfg(feature = "test-hooks")]
    pub const TEST_MEMORY: u8 = 0x72;
    /// Test builds only: the firmware stops right after its n-th flash write or erase from now,
    /// as if the power went there (QEMU is then killed); n = 0 turns it off.
    #[cfg(feature = "test-hooks")]
    pub const TEST_STALL: u8 = 0x73;

    pub const A_STATUS: u8 = 0x81;
    pub const A_IDENTITY: u8 = 0x82;
    pub const A_GAS_KEY: u8 = 0x84;
    pub const A_TREES: u8 = 0x85;
    pub const A_ENROLLED: u8 = 0x86;
    pub const A_SIGNED: u8 = 0x87;
    pub const A_DONE: u8 = 0x88;
    pub const A_ERROR: u8 = 0x8F;
    /// The board started (id 0).
    pub const EV_BOOTED: u8 = 0xA0;
    /// Test builds only: the screen's text.
    #[cfg(feature = "test-hooks")]
    pub const A_SCREEN: u8 = 0xF0;
    /// Test builds only: heap and stack use.
    #[cfg(feature = "test-hooks")]
    pub const A_MEMORY: u8 = 0xF1;
}

/// In the version text of a build with the test hooks, and nowhere in one without: the release
/// check looks for it in the image.
#[cfg(feature = "test-hooks")]
pub const TEST_HOOKS_MARK: &str = "WINTERLOCK-TEST-HOOKS";

/// Why a request failed (an ERROR answer's first byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Code {
    UnknownType = 1,
    BadPayload = 2,
    BadVersion = 3,
    /// Another request is waiting for the member.
    Busy = 4,
    /// The PIN hasn't been entered since the board started.
    Locked = 5,
    NotSetUp = 6,
    AlreadySetUp = 7,
    /// The member said no on the board.
    Rejected = 8,
    /// The app cancelled it.
    Cancelled = 9,
    /// The board's rules refuse it; the text says which.
    Refused = 10,
    Storage = 11,
    StorageFull = 12,
    /// The storage holds something the board can't read: it signs nothing until erased.
    Damaged = 13,
}

/// An error answer: a code and a fixed text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fail {
    pub code: Code,
    pub text: &'static str,
}

impl Fail {
    pub const fn new(code: Code, text: &'static str) -> Fail {
        Fail { code, text }
    }
}

/// A frame as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub ty: u8,
    pub id: u16,
    pub payload: Vec<u8>,
}

/// The bytes of a frame.
pub fn encode(ty: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_PAYLOAD, "payload too long for a frame");
    let mut f = Vec::with_capacity(OVERHEAD + payload.len());
    f.extend_from_slice(&MAGIC);
    f.push(VERSION);
    f.push(ty);
    f.extend_from_slice(&id.to_be_bytes());
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    let h = crc16(&f[4..10]);
    f.extend_from_slice(&h.to_be_bytes());
    f.extend_from_slice(payload);
    let c = crc32(&f[4..]);
    f.extend_from_slice(&c.to_be_bytes());
    f
}

/// Reads frames out of a byte stream that may hold other text (the bootloader's, a log line) or
/// damaged frames: whatever doesn't check out is skipped one byte at a time, so a frame that
/// starts inside skipped bytes is still found.
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
    /// Bytes skipped since the last frame (noise), for tests and diagnostics.
    pub skipped: usize,
}

impl Deframer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes held, waiting for the rest of a frame.
    pub fn held(&self) -> usize {
        self.buf.len()
    }

    fn drop_front(&mut self, n: usize) {
        self.skipped += n;
        self.buf.drain(..n);
    }

    /// The next whole frame, if the bytes so far hold one.
    pub fn next_frame(&mut self) -> Option<Frame> {
        loop {
            match self.buf.windows(4).position(|w| w == MAGIC) {
                Some(i) => self.drop_front(i),
                None => {
                    // keep a tail that could be the start of the magic
                    let keep = (1..4).rev().find(|&k| self.buf.len() >= k && self.buf[self.buf.len() - k..] == MAGIC[..k]).unwrap_or(0);
                    let n = self.buf.len() - keep;
                    self.drop_front(n);
                    return None;
                }
            }
            if self.buf.len() < HEADER {
                return None;
            }
            let hcrc = u16::from_be_bytes([self.buf[10], self.buf[11]]);
            let len = u16::from_be_bytes([self.buf[8], self.buf[9]]) as usize;
            if crc16(&self.buf[4..10]) != hcrc || len > MAX_PAYLOAD {
                self.drop_front(1);
                continue;
            }
            if self.buf.len() < HEADER + len + 4 {
                return None;
            }
            let c = u32::from_be_bytes(self.buf[HEADER + len..HEADER + len + 4].try_into().unwrap());
            if crc32(&self.buf[4..HEADER + len]) != c {
                self.drop_front(1);
                continue;
            }
            let frame = Frame {
                version: self.buf[4],
                ty: self.buf[5],
                id: u16::from_be_bytes([self.buf[6], self.buf[7]]),
                payload: self.buf[HEADER..HEADER + len].to_vec(),
            };
            self.buf.drain(..HEADER + len + 4);
            return Some(frame);
        }
    }

    /// Called after a pause in the stream: a frame that started but stopped (bytes lost, a
    /// sender that went away) is given up, and the bytes after its first are searched again.
    pub fn stalled(&mut self) {
        if self.buf.starts_with(&MAGIC) {
            self.drop_front(1);
        }
    }
}

// --- payloads ---

/// Reads a payload's fields in order.
pub struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Fail> {
        if self.b.len() < n {
            return Err(BAD);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }

    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N], Fail> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Result<u8, Fail> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Fail> {
        Ok(u16::from_be_bytes(self.arr()?))
    }

    pub fn u64(&mut self) -> Result<u64, Fail> {
        Ok(u64::from_be_bytes(self.arr()?))
    }

    pub fn end(&self) -> Result<(), Fail> {
        if self.b.is_empty() { Ok(()) } else { Err(BAD) }
    }
}

const BAD: Fail = Fail::new(Code::BadPayload, "the request's fields don't parse");

/// The app's SafeTx encoding (as core-wasm's): to (20) | value (32) | operation (1) |
/// safeTxGas (32) | baseGas (32) | gasPrice (32) | gasToken (20) | refundReceiver (20) |
/// nonce (32) | data.
pub const TX_HEAD: usize = 20 + 32 + 1 + 32 * 3 + 20 + 20 + 32;

pub fn decode_tx(b: &[u8]) -> Result<SafeTx, Fail> {
    if b.len() < TX_HEAD {
        return Err(BAD);
    }
    let u = |o: usize| U256::from_be_bytes(b[o..o + 32].try_into().unwrap());
    let operation = Operation::from_u8(b[52]).ok_or(Fail::new(Code::BadPayload, "operation must be 0 or 1"))?;
    Ok(SafeTx {
        to: b[0..20].try_into().unwrap(),
        value: u(20),
        operation,
        safe_tx_gas: u(53),
        base_gas: u(85),
        gas_price: u(117),
        gas_token: b[149..169].try_into().unwrap(),
        refund_receiver: b[169..189].try_into().unwrap(),
        nonce: u(189),
        data: b[TX_HEAD..].to_vec(),
    })
}

pub fn encode_tx(t: &SafeTx) -> Vec<u8> {
    let mut b = Vec::with_capacity(TX_HEAD + t.data.len());
    b.extend_from_slice(&t.to);
    b.extend_from_slice(&t.value.0);
    b.push(t.operation as u8);
    b.extend_from_slice(&t.safe_tx_gas.0);
    b.extend_from_slice(&t.base_gas.0);
    b.extend_from_slice(&t.gas_price.0);
    b.extend_from_slice(&t.gas_token);
    b.extend_from_slice(&t.refund_receiver);
    b.extend_from_slice(&t.nonce.0);
    b.extend_from_slice(&t.data);
    b
}

/// A transaction to confirm: its fields, the Safe and chain, which key tree, and for an
/// approveHash on a parent Safe, the parent's fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub chain: u64,
    pub safe: [u8; 20],
    /// The key tree to sign with (its root), or all zeros for the newest one for this Safe.
    pub root: [u8; 24],
    pub tx: SafeTx,
    pub parent: Option<SafeTx>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Status,
    Setup { app_random: [u8; 32] },
    Recover,
    GasKey,
    Trees,
    Enrol { chain: u64, safe: [u8; 20], start: u64 },
    Sign(SignRequest),
    Cancel,
    #[cfg(feature = "test-hooks")]
    TestButtons(Vec<Button>),
    #[cfg(feature = "test-hooks")]
    TestScreen,
}

pub fn parse_request(ty: u8, payload: &[u8]) -> Result<Request, Fail> {
    let mut r = Reader::new(payload);
    let req = match ty {
        ty::STATUS => Request::Status,
        ty::SETUP => Request::Setup { app_random: r.arr()? },
        ty::RECOVER => Request::Recover,
        ty::GAS_KEY => Request::GasKey,
        ty::TREES => Request::Trees,
        ty::ENROL => Request::Enrol { chain: r.u64()?, safe: r.arr()?, start: r.u64()? },
        ty::SIGN => {
            let chain = r.u64()?;
            let safe = r.arr()?;
            let root = r.arr()?;
            let n = r.u16()? as usize;
            let tx = decode_tx(r.take(n)?)?;
            let n = r.u16()? as usize;
            let parent = if n == 0 { None } else { Some(decode_tx(r.take(n)?)?) };
            Request::Sign(SignRequest { chain, safe, root, tx, parent })
        }
        ty::CANCEL => Request::Cancel,
        #[cfg(feature = "test-hooks")]
        ty::TEST_BUTTONS => {
            let mut evs = Vec::new();
            for &b in r.take(payload.len())? {
                evs.push(match b {
                    1 => Button::Left,
                    2 => Button::Right,
                    3 => Button::Both,
                    _ => return Err(BAD),
                });
            }
            Request::TestButtons(evs)
        }
        #[cfg(feature = "test-hooks")]
        ty::TEST_SCREEN => Request::TestScreen,
        _ => return Err(Fail::new(Code::UnknownType, "unknown request type")),
    };
    r.end()?;
    Ok(req)
}

/// Builds a payload.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    /// A short text: its length (one byte), then its bytes (cut at 255).
    pub fn text(&mut self, s: &str) -> &mut Self {
        let b = &s.as_bytes()[..s.len().min(255)];
        self.0.push(b.len() as u8);
        self.0.extend_from_slice(b);
        self
    }
}

pub fn error_payload(f: &Fail) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(f.code as u8).text(f.text);
    w.0
}

/// The text lines of a screen, for the test hooks' answer.
pub fn screen_payload(lines: &[String]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(lines.len() as u8);
    for l in lines {
        w.text(l);
    }
    w.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_survive_noise_and_damage() {
        let a = encode(ty::STATUS, 7, b"");
        let b = encode(ty::SETUP, 8, &[0x11; 32]);
        let mut d = Deframer::new();
        // bootloader text, half a magic, a frame, a damaged copy of it, a frame split in pieces
        d.push(b"ets Jun  8 2016 00:22:57\r\nrst:0x1 (POWERON_RESET),boot:0x13\r\n\xA5W");
        assert!(d.next_frame().is_none());
        d.push(&a);
        let f = d.next_frame().unwrap();
        assert_eq!((f.ty, f.id, f.payload.len()), (ty::STATUS, 7, 0));
        let mut bad = b.clone();
        bad[20] ^= 1;
        d.push(&bad);
        d.push(&b[..10]);
        assert!(d.next_frame().is_none());
        d.push(&b[10..]);
        let f = d.next_frame().unwrap();
        assert_eq!((f.ty, f.id), (ty::SETUP, 8));
        assert_eq!(f.payload, [0x11; 32]);
        assert!(d.next_frame().is_none());
        // a frame whose tail never came, then a good one: given up after a pause
        d.push(&a[..13]);
        assert!(d.next_frame().is_none());
        d.stalled();
        d.push(&a);
        assert_eq!(d.next_frame().unwrap().id, 7);
    }

    #[test]
    fn a_frame_inside_a_bad_one_is_found() {
        let inner = encode(ty::TREES, 3, b"");
        // a header claiming 40 bytes, whose payload holds a whole frame: the outer CRC fails,
        // and the reader finds the inner frame in the bytes it skipped
        let mut outer = encode(ty::SIGN, 9, &[0u8; 40]);
        outer[HEADER + 2..HEADER + 2 + inner.len()].copy_from_slice(&inner);
        let mut d = Deframer::new();
        d.push(&outer);
        let f = d.next_frame().unwrap();
        assert_eq!((f.ty, f.id), (ty::TREES, 3));
    }

    #[test]
    fn requests_parse_strictly() {
        assert_eq!(parse_request(ty::STATUS, b""), Ok(Request::Status));
        assert_eq!(parse_request(ty::STATUS, b"x").unwrap_err().code, Code::BadPayload);
        assert_eq!(parse_request(0x55, b"").unwrap_err().code, Code::UnknownType);
        let tx = SafeTx { to: [1; 20], nonce: U256::from_u64(5), data: alloc::vec![1, 2, 3], ..Default::default() };
        let enc = encode_tx(&tx);
        assert_eq!(decode_tx(&enc).unwrap(), tx);
        let mut w = Writer::new();
        w.u64(42161).bytes(&[2; 20]).bytes(&[0; 24]).u16(enc.len() as u16).bytes(&enc).u16(0);
        let Request::Sign(s) = parse_request(ty::SIGN, &w.0).unwrap() else { panic!() };
        assert_eq!((s.chain, s.safe, s.tx, s.parent), (42161, [2; 20], tx, None));
        let mut short = w.0.clone();
        short.pop();
        assert!(parse_request(ty::SIGN, &short).is_err());
    }

    /// Without the test hooks, their message types are unknown: the release image can't take
    /// simulated buttons.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn no_test_hooks_without_the_feature() {
        assert_eq!(parse_request(0x70, &[3]).unwrap_err().code, Code::UnknownType);
        assert_eq!(parse_request(0x71, b"").unwrap_err().code, Code::UnknownType);
    }
}
