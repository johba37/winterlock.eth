//! Renders every screen of every flow to PNG, for reviewing the board's UI before anything is
//! soldered: one file per screen (3x, white on black like the OLED) and a contact sheet of all of
//! them with their names.
//!
//!     cargo run --release --example screens -- [OUT_DIR]     (default: ../screens/all)

use std::path::{Path, PathBuf};

use embedded_graphics::mono_font::{MonoTextStyle, ascii::FONT_6X10};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::{Baseline, Text};
use winterlock_board::input::Button::{self, Both, Left, Right};
use winterlock_board::proto::{self, Deframer, Writer, ty};
use winterlock_board::sim::SimFlash;
use winterlock_board::store::log::Log;
use winterlock_board::ui::{Body, Frame, HEIGHT, Screen, WIDTH};
use winterlock_board::{Board, Platform};
use winterlock_core::U256;
use winterlock_core::safe::{Operation, SafeTx};

struct P {
    rng: u64,
    shown: Vec<Screen>,
}

impl Platform for P {
    fn random(&mut self, out: &mut [u8]) {
        for b in out {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            *b = self.rng as u8;
        }
    }
    fn show(&mut self, s: &Screen, _: &Frame) {
        if let Some(why) = s.overflows() {
            panic!("a screen doesn't fit: {why}");
        }
        self.shown.push(s.clone());
    }
    fn send(&mut self, _: &[u8]) {}
    fn both(&mut self, a: &mut (dyn FnMut() + Send), b: &mut (dyn FnMut() + Send)) {
        std::thread::scope(|s| {
            s.spawn(&mut *b);
            a();
        });
    }
}

type B = Board<SimFlash, P>;

struct Shots {
    list: Vec<(String, Screen)>,
}

impl Shots {
    fn take(&mut self, name: &str, b: &B) {
        self.list.push((format!("{:02}-{}", self.list.len() + 1, name), b.screen().clone()));
    }
    fn shot(&mut self, name: &str, s: &Screen) {
        self.list.push((format!("{:02}-{}", self.list.len() + 1, name), s.clone()));
    }
    /// The last progress screen shown with this title, half done or so.
    fn progress(&mut self, name: &str, b: &B, title: &str) {
        let ps: Vec<&Screen> = b.platform.shown.iter().filter(|s| s.title == title && matches!(s.body, Body::Progress { .. })).collect();
        if let Some(s) = ps.get(ps.len() / 2) {
            let s = (*s).clone();
            self.shot(name, &s);
        }
    }
}

fn req(b: &mut B, t: u8, id: u16, p: &[u8]) {
    let mut d = Deframer::new();
    d.push(&proto::encode(t, id, p));
    b.frame(&d.next_frame().unwrap());
}

fn press(b: &mut B, bs: &[Button]) {
    for &x in bs {
        b.button(x);
    }
}

fn pin(b: &mut B, digits: &[u8]) {
    for &d in digits {
        for _ in 0..d {
            b.button(Right);
        }
        b.button(Both);
    }
    b.button(Left);
    b.button(Both);
}

fn sign_req(chain: u64, safe: &[u8; 20], tx: &SafeTx, parent: Option<&SafeTx>) -> Vec<u8> {
    let t = proto::encode_tx(tx);
    let p = parent.map(proto::encode_tx).unwrap_or_default();
    let mut w = Writer::new();
    w.u64(chain).bytes(safe).bytes(&[0; 24]).u16(t.len() as u16).bytes(&t).u16(p.len() as u16).bytes(&p);
    w.0
}

/// Takes every page of a request's flow up to its confirmation, then confirms (twice if asked).
fn pages(s: &mut Shots, b: &mut B, name: &str) {
    let mut i = 1;
    loop {
        s.take(&format!("{name}-{i}"), b);
        if b.screen().right.starts_with("hold both") {
            break;
        }
        b.button(Right);
        i += 1;
    }
    b.button(Both);
    if b.screen().title == "Not decoded" {
        s.take(&format!("{name}-again"), b);
        b.button(Both);
    }
}

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "../screens/all".into()));
    std::fs::create_dir_all(&out).unwrap();
    let mut s = Shots { list: Vec::new() };
    let chain = 42161;
    let safe = [0x5A, 0x11, 0x3C, 0x90, 0x2E, 0xB7, 0x46, 0xD1, 0x08, 0x9F, 0x63, 0xA4, 0x2B, 0xC5, 0x71, 0x0E, 0x88, 0xD2, 0x34, 0x6F];
    let bob = [0xB0, 0x4D, 0x2A, 0x91, 0x7C, 0x3E, 0x55, 0x10, 0xE8, 0x6B, 0xF2, 0x07, 0x99, 0x31, 0xC4, 0x5D, 0xA0, 0x1F, 0x86, 0x23];
    let parent_safe = [0x7E, 0xA5, 0x02, 0x6C, 0xD9, 0x41, 0x18, 0xBE, 0x93, 0x2F, 0x75, 0xE0, 0x4A, 0xC1, 0x36, 0x8D, 0x5B, 0xF7, 0x0C, 0x62];

    let mut b = Board::new(SimFlash::new(256), P { rng: 0x5EED_1234_ABCD_0042, shown: Vec::new() }, "0.1.0").unwrap();
    s.take("blank", &b);

    // setup
    req(&mut b, ty::SETUP, 1, &[7; 32]);
    s.take("setup-intro", &b);
    b.button(Right);
    let mut words = Vec::new();
    for p in 0..6 {
        s.take(&format!("setup-words-{}", p + 1), &b);
        let Body::Lines(ls) = &b.screen().body else { panic!() };
        words.extend(ls.iter().map(|l| l.split_whitespace().nth(1).unwrap().to_string()));
        b.button(Right);
    }
    s.take("setup-written", &b);
    b.button(Both);
    s.take("setup-check", &b);
    b.button(Right);
    s.take("setup-check-moved", &b);
    // a wrong pick, then the words again and a new check
    let pos: usize = b.screen().title.trim_start_matches("Word ").trim_end_matches('?').parse().unwrap();
    let Body::Choices { items, cursor } = b.screen().body.clone() else { panic!() };
    let wrong = (0..4).find(|&i| items[i] != words[pos - 1]).unwrap();
    for _ in 0..(wrong + 4 - cursor) % 4 {
        b.button(Right);
    }
    b.button(Both);
    s.take("setup-check-wrong", &b);
    b.button(Right);
    for _ in 0..6 {
        b.button(Right);
    }
    b.button(Both);
    for _ in 0..3 {
        let pos: usize = b.screen().title.trim_start_matches("Word ").trim_end_matches('?').parse().unwrap();
        let Body::Choices { items, .. } = b.screen().body.clone() else { panic!() };
        let want = items.iter().position(|w| *w == words[pos - 1]).unwrap();
        for _ in 0..want {
            b.button(Right);
        }
        b.button(Both);
    }
    s.take("pin-intro", &b);
    b.button(Right);
    s.take("pin-new", &b);
    press(&mut b, &[Right, Right, Both, Both]);
    s.take("pin-new-2-digits", &b);
    press(&mut b, &[Right, Right, Both, Both]);
    s.take("pin-new-4-digits", &b);
    b.button(Left);
    s.take("pin-new-done", &b);
    b.button(Left);
    s.take("pin-new-delete", &b);
    press(&mut b, &[Right, Both]);
    s.take("pin-again", &b);
    pin(&mut b, &[1, 1, 1, 1]);
    s.take("pin-mismatch", &b);
    b.button(Right);
    pin(&mut b, &[2, 0, 2, 6]);
    pin(&mut b, &[2, 0, 2, 6]);
    s.progress("setup-making-key", &b, "Setting up");
    s.take("setup-owner-address", &b);
    b.button(Right);
    s.take("setup-ready", &b);
    b.button(Right);
    s.take("home-no-trees", &b);

    // the menu
    b.button(Right);
    s.take("menu", &b);
    b.button(Both);
    s.take("menu-owner-address", &b);
    press(&mut b, &[Left, Right, Both]);
    s.take("menu-key-trees-none", &b);
    press(&mut b, &[Left, Right, Both]);
    s.take("menu-erase", &b);
    press(&mut b, &[Left, Right, Both]);
    s.take("home", &b);

    // enrol
    let mut w = Writer::new();
    w.u64(chain).bytes(&safe).u64(41);
    req(&mut b, ty::ENROL, 2, &w.0);
    s.take("enrol-1", &b);
    b.button(Right);
    s.take("enrol-2", &b);
    b.platform.shown.clear();
    b.button(Both);
    s.progress("enrol-making-tree", &b, "Enrolling");
    s.progress("enrol-signing", &b, "Signing");
    s.take("enrol-done", &b);
    b.button(Right);
    s.take("home-one-tree", &b);
    press(&mut b, &[Right, Right, Both]);
    s.take("menu-key-tree", &b);
    press(&mut b, &[Left, Left, Both]);

    // transactions
    let eth = SafeTx { to: bob, value: U256::from_u64(1_500_000_000_000_000_000), nonce: U256::from_u64(41), ..Default::default() };
    req(&mut b, ty::SIGN, 3, &sign_req(chain, &safe, &eth, None));
    pages(&mut s, &mut b, "eth");
    s.take("signed", &b);
    b.button(Right);

    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(&bob);
    data.extend_from_slice(&U256::from_u64(1_234_567_890).0);
    let usdc = SafeTx { to: winterlock_board::decode::TOKENS[0].address, data, nonce: U256::from_u64(42), ..Default::default() };
    req(&mut b, ty::SIGN, 4, &sign_req(chain, &safe, &usdc, None));
    pages(&mut s, &mut b, "usdc");
    b.button(Right);

    let parent = SafeTx { to: bob, value: U256::from_u64(250_000_000_000_000_000), nonce: U256::from_u64(7), ..Default::default() };
    let mut data = vec![0xd4, 0xd9, 0xbd, 0xcd];
    data.extend_from_slice(&parent.hash(chain, &parent_safe));
    let approve = SafeTx { to: parent_safe, data, nonce: U256::from_u64(43), ..Default::default() };
    req(&mut b, ty::SIGN, 5, &sign_req(chain, &safe, &approve, Some(&parent)));
    pages(&mut s, &mut b, "approve");
    b.button(Right);

    let raw = SafeTx { to: parent_safe, value: U256::from_u64(10_000_000_000_000_000), data: vec![0x09, 0x5e, 0xa7, 0xb3, 1, 2, 3, 4, 5, 6, 7, 8], nonce: U256::from_u64(44), ..Default::default() };
    req(&mut b, ty::SIGN, 6, &sign_req(chain, &safe, &raw, None));
    pages(&mut s, &mut b, "not-decoded");
    b.button(Right);

    let refund = SafeTx { gas_price: U256::from_u64(100_000_000), base_gas: U256::from_u64(50_000), refund_receiver: bob, ..SafeTx { to: bob, value: U256::from_u64(1_000_000_000_000_000), nonce: U256::from_u64(45), ..Default::default() } };
    req(&mut b, ty::SIGN, 7, &sign_req(chain, &safe, &refund, None));
    pages(&mut s, &mut b, "refund");
    b.button(Right);

    let cancel = SafeTx { to: safe, nonce: U256::from_u64(46), ..Default::default() };
    req(&mut b, ty::SIGN, 8, &sign_req(chain, &safe, &cancel, None));
    pages(&mut s, &mut b, "cancel");
    b.button(Right);

    let dc = SafeTx { operation: Operation::DelegateCall, ..eth.clone() };
    req(&mut b, ty::SIGN, 9, &sign_req(chain, &safe, &dc, None));
    s.take("refused-delegate-call", &b);
    b.button(Right);
    let third = SafeTx { value: U256::from_u64(3), ..eth.clone() };
    let second = SafeTx { value: U256::from_u64(2), ..eth.clone() };
    req(&mut b, ty::SIGN, 10, &sign_req(chain, &safe, &second, None));
    press(&mut b, &[Right, Right, Right, Both, Right]);
    req(&mut b, ty::SIGN, 11, &sign_req(chain, &safe, &third, None));
    s.take("refused-third-version", &b);
    b.button(Right);
    req(&mut b, ty::SIGN, 12, &sign_req(chain, &safe, &SafeTx { nonce: U256::from_u64(47), ..eth.clone() }, None));
    b.button(Left);
    s.take("rejected", &b);
    b.button(Right);

    // a restart: the PIN
    let flash = b.store_flash_copy();
    let mut b = Board::new(flash.reboot(), P { rng: 99, shown: Vec::new() }, "0.1.0").unwrap();
    s.take("locked", &b);
    pin(&mut b, &[9, 9, 9, 9]);
    s.take("wrong-pin", &b);
    b.button(Right);
    s.take("locked-tries-left", &b);
    pin(&mut b, &[9, 9, 9, 9]);
    b.button(Right);
    pin(&mut b, &[9, 9, 9, 9]);
    s.take("erased-3-wrong-pins", &b);
    b.button(Right);

    // recovery
    req(&mut b, ty::RECOVER, 20, &[]);
    s.take("recover-intro", &b);
    b.button(Right);
    s.take("recover-word", &b);
    for _ in 0..12 {
        b.button(Right);
    }
    b.button(Both);
    s.take("recover-word-letter", &b);
    press(&mut b, &[Right, Right, Both]);
    s.take("recover-word-two-letters", &b);
    // start again, and type the 24 words of the setup
    req(&mut b, ty::CANCEL, 22, &[]);
    req(&mut b, ty::RECOVER, 23, &[]);
    b.button(Right);
    for (i, word) in words.iter().enumerate() {
        let mut typed = String::new();
        loop {
            if b.screen().right == "both: ok" {
                if i == 0 {
                    s.take("recover-word-found", &b);
                }
                b.button(Both);
                break;
            }
            let list = winterlock_core::phrase::wordlist();
            let mut letters: Vec<u8> = list.iter().filter(|w| w.starts_with(&typed)).filter_map(|w| w.as_bytes().get(typed.len()).copied()).collect();
            letters.dedup();
            let want = if typed == *word { letters.len() } else { letters.iter().position(|&c| c == word.as_bytes()[typed.len()]).unwrap() };
            for _ in 0..want {
                b.button(Right);
            }
            b.button(Both);
            if typed != *word {
                typed.push(word.as_bytes()[typed.len()] as char);
            }
        }
    }
    s.take("recover-pin-intro", &b);
    b.button(Right);
    pin(&mut b, &[1, 2, 3, 4]);
    pin(&mut b, &[1, 2, 3, 4]);
    s.progress("recover-making-key", &b, "Recovering");
    s.take("recover-owner-address", &b);
    b.button(Right);
    s.take("recover-no-trees", &b);
    b.button(Right);

    // erase from the menu, then a bad checksum on the blank board
    press(&mut b, &[Right, Right, Right, Both, Both]);
    s.take("erased-from-menu", &b);
    b.button(Right);
    req(&mut b, ty::RECOVER, 21, &[]);
    b.button(Right);
    for _ in 0..24 {
        // "abandon" 24 times: the checksum is wrong ("a", "b", "a" pick it)
        let mut guard = 0;
        while b.screen().right != "both: ok" {
            b.button(Both);
            guard += 1;
            assert!(guard < 10, "{:?}", b.screen().text());
        }
        b.button(Both);
    }
    s.take("recover-checksum-wrong", &b);
    b.button(Right);
    s.take("recover-fix-a-word", &b);

    // a damaged log; a storage failure
    // a setup cut short after its seed was written: the board erases itself at the next start
    let mut log = Log::new(Board::new(SimFlash::new(64), P { rng: 5, shown: Vec::new() }, "0.1.0").unwrap().store_flash_copy());
    log.scan(|_, _| {}).unwrap();
    log.append(0x02, &[&[7u8; 32], &[0]]).unwrap();
    let cut = Board::new(log.flash, P { rng: 5, shown: Vec::new() }, "0.1.0").unwrap();
    s.take("erased-at-start", &cut);
    let damaged = damaged_board();
    s.take("damaged", &damaged);

    write_all(&out, &s.list);
    println!("{} screens in {}", s.list.len(), out.display());
}

/// A set-up board whose log then holds a record it doesn't know.
fn damaged_board() -> B {
    let mut b = Board::new(SimFlash::new(64), P { rng: 3, shown: Vec::new() }, "0.1.0").unwrap();
    req(&mut b, ty::SETUP, 1, &[1; 32]);
    b.button(Right);
    let mut words = Vec::new();
    for _ in 0..6 {
        let Body::Lines(ls) = &b.screen().body else { panic!() };
        words.extend(ls.iter().map(|l| l.split_whitespace().nth(1).unwrap().to_string()));
        b.button(Right);
    }
    b.button(Both);
    for _ in 0..3 {
        let pos: usize = b.screen().title.trim_start_matches("Word ").trim_end_matches('?').parse().unwrap();
        let Body::Choices { items, .. } = b.screen().body.clone() else { panic!() };
        let want = items.iter().position(|w| *w == words[pos - 1]).unwrap();
        for _ in 0..want {
            b.button(Right);
        }
        b.button(Both);
    }
    b.button(Right);
    pin(&mut b, &[1, 2, 3, 4]);
    pin(&mut b, &[1, 2, 3, 4]);
    let flash = b.store_flash_copy();
    let mut log = Log::new(flash);
    log.scan(|_, _| {}).unwrap();
    log.append(0x77, &[b"?"]).unwrap();
    Board::new(log.flash, P { rng: 3, shown: Vec::new() }, "0.1.0").unwrap()
}

trait FlashCopy {
    fn store_flash_copy(&self) -> SimFlash;
}

impl FlashCopy for B {
    /// The board's flash as it is now.
    fn store_flash_copy(&self) -> SimFlash {
        self.store.with_flash(|f| f.reboot())
    }
}

fn png(path: &Path, w: usize, h: usize, gray: &[u8]) {
    let file = std::fs::File::create(path).unwrap();
    let mut e = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
    e.set_color(png::ColorType::Grayscale);
    e.set_depth(png::BitDepth::Eight);
    e.set_compression(png::Compression::Best);
    e.write_header().unwrap().write_image_data(gray).unwrap();
}

/// One screen at `scale`, pixels as the OLED lights them (a 1-pixel dark gap between them).
fn pixels(f: &Frame, scale: usize) -> Vec<u8> {
    let (w, h) = (WIDTH * scale, HEIGHT * scale);
    let mut g = vec![0u8; w * h];
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            if f.get(x, y) {
                for dy in 0..scale {
                    for dx in 0..scale {
                        let lit = scale < 3 || (dx < scale - 1 && dy < scale - 1);
                        if lit {
                            g[(y * scale + dy) * w + x * scale + dx] = 0xF0;
                        }
                    }
                }
            }
        }
    }
    g
}

fn write_all(out: &Path, list: &[(String, Screen)]) {
    for (name, s) in list {
        let f = s.render();
        png(&out.join(format!("{name}.png")), WIDTH * 3, HEIGHT * 3, &pixels(&f, 3));
    }
    // the contact sheet: 2x screens, 6 across, names under them
    let (cols, scale, pad, label) = (6usize, 2usize, 12usize, 12usize);
    let cw = WIDTH * scale + pad;
    let ch = HEIGHT * scale + label + pad;
    let rows = list.len().div_ceil(cols);
    let (sw, sh) = (cols * cw + pad, rows * ch + pad);
    let mut sheet = vec![0x30u8; sw * sh];
    let mut text = Canvas { w: sw, h: sh, px: vec![false; sw * sh] };
    for (i, (name, s)) in list.iter().enumerate() {
        let (cx, cy) = (pad + (i % cols) * cw, pad + (i / cols) * ch);
        let px = pixels(&s.render(), scale);
        for y in 0..HEIGHT * scale {
            for x in 0..WIDTH * scale {
                sheet[(cy + y) * sw + cx + x] = px[y * WIDTH * scale + x].max(0x00);
            }
        }
        let _ = Text::with_baseline(name, Point::new(cx as i32, (cy + HEIGHT * scale + 2) as i32), MonoTextStyle::new(&FONT_6X10, BinaryColor::On), Baseline::Top).draw(&mut text);
    }
    for (i, &on) in text.px.iter().enumerate() {
        if on {
            sheet[i] = 0xC8;
        }
    }
    png(&out.join("contact-sheet.png"), sw, sh, &sheet);
}

struct Canvas {
    w: usize,
    h: usize,
    px: Vec<bool>,
}

impl OriginDimensions for Canvas {
    fn size(&self) -> Size {
        Size::new(self.w as u32, self.h as u32)
    }
}

impl DrawTarget for Canvas {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;
    fn draw_iter<I: IntoIterator<Item = Pixel<BinaryColor>>>(&mut self, it: I) -> Result<(), Self::Error> {
        for Pixel(p, c) in it {
            if p.x >= 0 && p.y >= 0 && (p.x as usize) < self.w && (p.y as usize) < self.h {
                self.px[p.y as usize * self.w + p.x as usize] = c.is_on();
            }
        }
        Ok(())
    }
}
