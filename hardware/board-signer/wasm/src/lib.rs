//! The virtual board: `winterlock-board`, the board signer's logic, in WebAssembly for the signer
//! app (`app/`), so the app's flows run end to end without hardware. The same crate runs on the
//! ESP32 (`../firmware`); here its platform is the browser:
//!
//! - **the link:** bytes in through [`VirtualBoard::receive`], frames out through the host's
//!   `send`, exactly as over USB (PROTOCOL.md)
//! - **the buttons:** [`VirtualBoard::button`], 1 left, 2 right, 3 both held
//! - **the screen:** the 128x64 frame (one bit a pixel, row-major) and its text, through the host's
//!   `show`, and on request
//! - **the flash:** the 3 MB partition in memory; the host persists the sectors a call changed
//!   ([`VirtualBoard::take_dirty`]) before it passes on what the board sent, so a signature never
//!   leaves before its key log record is stored
//! - **randomness:** `crypto.getRandomValues`
//! - **the second core:** none; both halves of a job run one after the other
//!
//! Its keys live in the browser that runs it: it is a development board, not a signer.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;

use embedded_storage::nor_flash::{ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash};
use wasm_bindgen::prelude::*;
use winterlock_board::input::Button;
use winterlock_board::proto::Deframer;
use winterlock_board::ui::{Frame, Screen};
use winterlock_board::{Board, Platform};

/// The firmware's `signer` partition (firmware/partitions.csv): 0x2F0000 bytes.
pub const PARTITION: usize = 0x2F_0000;
pub const SECTOR: usize = 4096;
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " virtual");

#[wasm_bindgen]
extern "C" {
    /// What the page or worker gives the board: where its frames and screens go.
    pub type BoardHost;
    /// A frame's bytes, as the board would write them to its serial port.
    #[wasm_bindgen(method)]
    fn send(this: &BoardHost, bytes: &[u8]);
    /// A screen: its 1,024 bytes of pixels and its text (lines joined by newlines).
    #[wasm_bindgen(method)]
    fn show(this: &BoardHost, pixels: &[u8], text: String);

    #[wasm_bindgen(js_namespace = crypto, js_name = getRandomValues)]
    fn get_random_values(buf: &mut [u8]);
}

// --- the flash ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashError {
    NotAligned,
    OutOfBounds,
    /// A write that would set a cleared bit: only an erase does that.
    Overwrite,
}

impl NorFlashError for FlashError {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            FlashError::NotAligned => NorFlashErrorKind::NotAligned,
            FlashError::OutOfBounds => NorFlashErrorKind::OutOfBounds,
            FlashError::Overwrite => NorFlashErrorKind::Other,
        }
    }
}

struct Mem {
    bytes: Vec<u8>,
    dirty: Vec<bool>,
}

/// The partition in memory, as NOR flash: erasing sets 4 KB sectors to 0xFF, writing only clears
/// bits. Shared between the board's store and this wrapper, which hands changed sectors to the host.
#[derive(Clone)]
struct MemFlash(Rc<RefCell<Mem>>);

impl ErrorType for MemFlash {
    type Error = FlashError;
}

fn bounds(offset: u32, len: usize, size: usize) -> Result<usize, FlashError> {
    let o = offset as usize;
    if o % 4 != 0 || len % 4 != 0 {
        return Err(FlashError::NotAligned);
    }
    if o + len > size {
        return Err(FlashError::OutOfBounds);
    }
    Ok(o)
}

impl ReadNorFlash for MemFlash {
    const READ_SIZE: usize = 4;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), FlashError> {
        let m = self.0.borrow();
        let o = bounds(offset, bytes.len(), m.bytes.len())?;
        bytes.copy_from_slice(&m.bytes[o..o + bytes.len()]);
        Ok(())
    }

    fn capacity(&self) -> usize {
        self.0.borrow().bytes.len()
    }
}

impl NorFlash for MemFlash {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = SECTOR;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        let mut m = self.0.borrow_mut();
        let (f, t) = (from as usize, to as usize);
        if f % SECTOR != 0 || t % SECTOR != 0 || f > t {
            return Err(FlashError::NotAligned);
        }
        if t > m.bytes.len() {
            return Err(FlashError::OutOfBounds);
        }
        m.bytes[f..t].fill(0xFF);
        for s in f / SECTOR..t / SECTOR {
            m.dirty[s] = true;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), FlashError> {
        let mut m = self.0.borrow_mut();
        let o = bounds(offset, bytes.len(), m.bytes.len())?;
        if m.bytes[o..o + bytes.len()].iter().zip(bytes).any(|(&old, &new)| old & new != new) {
            return Err(FlashError::Overwrite);
        }
        for (b, &n) in m.bytes[o..o + bytes.len()].iter_mut().zip(bytes) {
            *b &= n;
        }
        if !bytes.is_empty() {
            for s in o / SECTOR..=(o + bytes.len() - 1) / SECTOR {
                m.dirty[s] = true;
            }
        }
        Ok(())
    }
}

// --- the platform ---

struct Web {
    host: BoardHost,
    pixels: Vec<u8>,
    text: String,
}

impl Platform for Web {
    fn random(&mut self, out: &mut [u8]) {
        // getRandomValues fills at most 65,536 bytes a call
        for c in out.chunks_mut(65_536) {
            get_random_values(c);
        }
    }

    fn show(&mut self, screen: &Screen, frame: &Frame) {
        self.pixels.clear();
        self.pixels.extend_from_slice(&frame.bits);
        self.text = screen.text().join("\n");
        self.host.show(&self.pixels, self.text.clone());
    }

    fn send(&mut self, bytes: &[u8]) {
        self.host.send(bytes);
    }

    fn both(&mut self, here: &mut (dyn FnMut() + Send), there: &mut (dyn FnMut() + Send)) {
        here();
        there();
    }
}

// --- the board ---

/// The board, running on the page's or a worker's thread.
#[wasm_bindgen]
pub struct VirtualBoard {
    board: Board<MemFlash, Web>,
    flash: MemFlash,
    link: Deframer,
}

#[wasm_bindgen]
impl VirtualBoard {
    /// Starts the board from its partition as stored (`PARTITION` bytes; empty for a new board).
    /// It shows its first screen and sends BOOTED through `host`, as a board does when it starts.
    #[wasm_bindgen(constructor)]
    pub fn new(host: BoardHost, image: &[u8]) -> Result<VirtualBoard, JsError> {
        let bytes = match image.len() {
            0 => vec![0xFF; PARTITION],
            PARTITION => image.to_vec(),
            n => return Err(JsError::new(&format!("a partition image is {PARTITION} bytes, not {n}"))),
        };
        let flash = MemFlash(Rc::new(RefCell::new(Mem { bytes, dirty: vec![false; PARTITION / SECTOR] })));
        let web = Web { host, pixels: Vec::new(), text: String::new() };
        let board = Board::new(flash.clone(), web, VERSION).map_err(|e| JsError::new(&format!("the board doesn't start: {e:?}")))?;
        Ok(VirtualBoard { board, flash, link: Deframer::new() })
    }

    /// The partition's size in bytes.
    pub fn partition_size() -> usize {
        PARTITION
    }

    pub fn sector_size() -> usize {
        SECTOR
    }

    /// Bytes from the app, as they would arrive on the serial port: each whole frame is handled
    /// in turn (answers go to the host's `send`).
    pub fn receive(&mut self, bytes: &[u8]) {
        self.link.push(bytes);
        while let Some(f) = self.link.next_frame() {
            self.board.frame(&f);
        }
    }

    /// The link went quiet: a frame that started and stopped is given up.
    pub fn stalled(&mut self) {
        self.link.stalled();
    }

    /// A button event: 1 left, 2 right, 3 both held.
    pub fn button(&mut self, event: u8) -> Result<(), JsError> {
        let b = match event {
            1 => Button::Left,
            2 => Button::Right,
            3 => Button::Both,
            _ => return Err(JsError::new("a button event is 1 (left), 2 (right) or 3 (both)")),
        };
        self.board.button(b);
        Ok(())
    }

    /// The screen's pixels: 128x64, one bit each, row-major, the leftmost pixel in a byte's top bit.
    pub fn pixels(&self) -> Vec<u8> {
        self.board.platform.pixels.clone()
    }

    /// The screen's text: the title (and corner), the body's lines, the button hints.
    pub fn text(&self) -> String {
        self.board.platform.text.clone()
    }

    pub fn unlocked(&self) -> bool {
        self.board.unlocked()
    }

    /// The sectors written or erased since the last call, by index: the host stores them.
    pub fn take_dirty(&mut self) -> Vec<u32> {
        let mut m = self.flash.0.borrow_mut();
        let out = m.dirty.iter().enumerate().filter(|(_, d)| **d).map(|(i, _)| i as u32).collect();
        m.dirty.fill(false);
        out
    }

    /// One sector's bytes.
    pub fn sector(&self, index: u32) -> Result<Vec<u8>, JsError> {
        let m = self.flash.0.borrow();
        let o = index as usize * SECTOR;
        m.bytes.get(o..o + SECTOR).map(|s| s.to_vec()).ok_or_else(|| JsError::new("no such sector"))
    }
}
