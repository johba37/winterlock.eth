//! Screens: what the board shows, as a small model ([`Screen`]) drawn into a 128x64 one-bit
//! frame buffer ([`Frame`]). The firmware copies the frame to the OLED; the host tool writes it to
//! a PNG. The test hooks read the same model as text.
//!
//! Layout, top to bottom (it suits the common two-colour modules, whose top 16 rows are yellow):
//! ```text
//!   rows  0-12  title (6x13 bold), a page count or note at the right
//!   row  14     a rule
//!   rows 17-56  four body lines (6x10), 21 characters each, or a choice list, a big value, a bar
//!   rows 57-63  the button hints (5x7): left's at the left, right's or "hold both" at the right
//! ```
//! Only ASCII: the fonts have nothing else.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::Infallible;

use embedded_graphics::mono_font::{MonoFont, MonoTextStyle, ascii};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Line, PrimitiveStyle, Rectangle};
use embedded_graphics::text::{Alignment, Baseline, Text, TextStyleBuilder};

pub const WIDTH: usize = 128;
pub const HEIGHT: usize = 64;
/// Characters in a body line.
pub const COLS: usize = 21;
/// Body lines on a screen.
pub const ROWS: usize = 4;

/// 128x64 pixels, one bit each: row-major, the leftmost pixel in a byte's top bit.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub bits: [u8; WIDTH * HEIGHT / 8],
}

impl Default for Frame {
    fn default() -> Self {
        Frame { bits: [0; WIDTH * HEIGHT / 8] }
    }
}

impl Frame {
    pub fn get(&self, x: usize, y: usize) -> bool {
        self.bits[y * WIDTH / 8 + x / 8] & (0x80 >> (x % 8)) != 0
    }

    pub fn set(&mut self, x: usize, y: usize, on: bool) {
        let b = &mut self.bits[y * WIDTH / 8 + x / 8];
        if on {
            *b |= 0x80 >> (x % 8);
        } else {
            *b &= !(0x80 >> (x % 8));
        }
    }

    /// The SSD1306's layout: 8 pages of 8 rows, a byte per column, the top row in bit 0.
    pub fn to_pages(&self) -> [u8; WIDTH * HEIGHT / 8] {
        let mut out = [0u8; WIDTH * HEIGHT / 8];
        for page in 0..HEIGHT / 8 {
            for x in 0..WIDTH {
                let mut v = 0u8;
                for bit in 0..8 {
                    if self.get(x, page * 8 + bit) {
                        v |= 1 << bit;
                    }
                }
                out[page * WIDTH + x] = v;
            }
        }
        out
    }
}

impl OriginDimensions for Frame {
    fn size(&self) -> Size {
        Size::new(WIDTH as u32, HEIGHT as u32)
    }
}

impl DrawTarget for Frame {
    type Color = BinaryColor;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<BinaryColor>>>(&mut self, pixels: I) -> Result<(), Infallible> {
        for Pixel(p, c) in pixels {
            if p.x >= 0 && p.y >= 0 && (p.x as usize) < WIDTH && (p.y as usize) < HEIGHT {
                self.set(p.x as usize, p.y as usize, c.is_on());
            }
        }
        Ok(())
    }
}

/// What the body of a screen holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// Up to four lines of up to 21 characters.
    Lines(Vec<String>),
    /// A small line, a value in the largest font it fits, a small line.
    Big { above: String, value: String, below: String },
    /// Up to four items, one of them picked (drawn inverted).
    Choices { items: Vec<String>, cursor: usize },
    /// A line, a bar, a line.
    Progress { text: String, done: u32, total: u32, note: String },
}

/// A screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Screen {
    pub title: String,
    /// At the right of the title: "2/5", a chain name.
    pub corner: String,
    pub body: Body,
    /// The left button's hint, at the bottom left ("< back").
    pub left: String,
    /// The right button's or both's hint, at the bottom right ("next >", "hold both: sign").
    pub right: String,
}

impl Screen {
    pub fn lines(title: &str, lines: &[&str], left: &str, right: &str) -> Screen {
        Screen {
            title: title.to_string(),
            corner: String::new(),
            body: Body::Lines(lines.iter().map(|l| l.to_string()).collect()),
            left: left.to_string(),
            right: right.to_string(),
        }
    }

    pub fn with_corner(mut self, corner: &str) -> Screen {
        self.corner = corner.to_string();
        self
    }

    /// The screen as plain lines: the title (and corner), the body, the hints.
    pub fn text(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.corner.is_empty() {
            out.push(self.title.clone());
        } else {
            out.push(alloc::format!("{} [{}]", self.title, self.corner));
        }
        match &self.body {
            Body::Lines(ls) => out.extend(ls.iter().cloned()),
            Body::Big { above, value, below } => {
                out.push(above.clone());
                out.push(value.clone());
                out.push(below.clone());
            }
            Body::Choices { items, cursor } => {
                for (i, it) in items.iter().enumerate() {
                    out.push(alloc::format!("{}{}", if i == *cursor { "> " } else { "  " }, it));
                }
            }
            Body::Progress { text, done, total, note } => {
                out.push(text.clone());
                out.push(alloc::format!("[{done}/{total}]"));
                out.push(note.clone());
            }
        }
        out.push(alloc::format!("{} | {}", self.left, self.right));
        out
    }

    /// Lines or hints wider than the screen, or too many lines: a bug in a screen's text.
    pub fn overflows(&self) -> Option<String> {
        let wide = |s: &str, n: usize| s.chars().count() > n;
        if wide(&self.title, 21 - self.corner.len().min(21) - if self.corner.is_empty() { 0 } else { 1 }) {
            return Some(alloc::format!("title {:?} with corner {:?}", self.title, self.corner));
        }
        if self.left.chars().count() + self.right.chars().count() > 24 {
            return Some(alloc::format!("hints {:?} {:?}", self.left, self.right));
        }
        match &self.body {
            Body::Lines(ls) => {
                if ls.len() > ROWS {
                    return Some(alloc::format!("{} lines", ls.len()));
                }
                ls.iter().find(|l| wide(l, COLS)).map(|l| alloc::format!("line {l:?}"))
            }
            Body::Big { above, value, below } => {
                if wide(above, COLS) || wide(below, COLS) || wide(value, COLS) {
                    Some(alloc::format!("big {above:?} {value:?} {below:?}"))
                } else {
                    None
                }
            }
            Body::Choices { items, .. } => {
                if items.len() > ROWS {
                    return Some(alloc::format!("{} choices", items.len()));
                }
                items.iter().find(|l| wide(l, COLS - 2)).map(|l| alloc::format!("choice {l:?}"))
            }
            Body::Progress { text, note, .. } => (wide(text, COLS) || wide(note, COLS)).then(|| alloc::format!("progress {text:?} {note:?}")),
        }
    }

    pub fn render(&self) -> Frame {
        let mut f = Frame::default();
        let on = BinaryColor::On;
        let left_top = TextStyleBuilder::new().baseline(Baseline::Top).alignment(Alignment::Left).build();
        let right_top = TextStyleBuilder::new().baseline(Baseline::Top).alignment(Alignment::Right).build();
        let center_top = TextStyleBuilder::new().baseline(Baseline::Top).alignment(Alignment::Center).build();
        let title = MonoTextStyle::new(&ascii::FONT_6X13_BOLD, on);
        let body = MonoTextStyle::new(&ascii::FONT_6X10, on);
        let small = MonoTextStyle::new(&ascii::FONT_5X7, on);

        let _ = Text::with_text_style(&self.title, Point::new(0, 0), title, left_top).draw(&mut f);
        if !self.corner.is_empty() {
            let _ = Text::with_text_style(&self.corner, Point::new(127, 2), body, right_top).draw(&mut f);
        }
        let _ = Line::new(Point::new(0, 14), Point::new(127, 14)).into_styled(PrimitiveStyle::with_stroke(on, 1)).draw(&mut f);

        match &self.body {
            Body::Lines(ls) => {
                for (i, l) in ls.iter().take(ROWS).enumerate() {
                    let _ = Text::with_text_style(l, Point::new(0, 17 + 10 * i as i32), body, left_top).draw(&mut f);
                }
            }
            Body::Big { above, value, below } => {
                let _ = Text::with_text_style(above, Point::new(0, 17), body, left_top).draw(&mut f);
                let font = big_font(value.len());
                let h = font.character_size.height as i32;
                let y = 27 + (20 - h) / 2;
                let _ = Text::with_text_style(value, Point::new(64, y), MonoTextStyle::new(font, on), center_top).draw(&mut f);
                let _ = Text::with_text_style(below, Point::new(0, 47), body, left_top).draw(&mut f);
            }
            Body::Choices { items, cursor } => {
                for (i, it) in items.iter().take(ROWS).enumerate() {
                    let y = 17 + 10 * i as i32;
                    if i == *cursor {
                        let _ = Rectangle::new(Point::new(0, y - 1), Size::new(128, 10)).into_styled(PrimitiveStyle::with_fill(on)).draw(&mut f);
                        let inv = MonoTextStyle::new(&ascii::FONT_6X10, BinaryColor::Off);
                        let _ = Text::with_text_style(it, Point::new(6, y), inv, left_top).draw(&mut f);
                    } else {
                        let _ = Text::with_text_style(it, Point::new(6, y), body, left_top).draw(&mut f);
                    }
                }
            }
            Body::Progress { text, done, total, note } => {
                let _ = Text::with_text_style(text, Point::new(0, 17), body, left_top).draw(&mut f);
                let _ = Rectangle::new(Point::new(4, 31), Size::new(120, 9)).into_styled(PrimitiveStyle::with_stroke(on, 1)).draw(&mut f);
                let w = if *total == 0 { 0 } else { (116u64 * (*done).min(*total) as u64 / *total as u64) as u32 };
                if w > 0 {
                    let _ = Rectangle::new(Point::new(6, 33), Size::new(w, 5)).into_styled(PrimitiveStyle::with_fill(on)).draw(&mut f);
                }
                let _ = Text::with_text_style(note, Point::new(0, 45), body, left_top).draw(&mut f);
            }
        }

        let _ = Text::with_text_style(&self.left, Point::new(0, 57), small, left_top).draw(&mut f);
        let _ = Text::with_text_style(&self.right, Point::new(127, 57), small, right_top).draw(&mut f);
        f
    }
}

/// The largest font a value of `n` characters fits across the screen in.
fn big_font(n: usize) -> &'static MonoFont<'static> {
    if n <= 12 {
        &ascii::FONT_10X20
    } else if n <= 14 {
        &ascii::FONT_9X15_BOLD
    } else if n <= 16 {
        &ascii::FONT_8X13_BOLD
    } else if n <= 18 {
        &ascii::FONT_7X13_BOLD
    } else {
        &ascii::FONT_6X10
    }
}

// --- text helpers ---

/// An address as EIP-55, shortened: "0xAbCd..1234".
pub fn short_address(a: &[u8; 20]) -> String {
    let s = winterlock_core::hex::checksum(a);
    alloc::format!("{}..{}", &s[..6], &s[38..])
}

/// An address in full, in three lines of four-character groups:
/// "0xAbCd 1234 5678 9aBc", "dEf0 1234 5678 9AbC", "dEf0 1234".
pub fn address_lines(a: &[u8; 20]) -> [String; 3] {
    let s = winterlock_core::hex::checksum(a);
    let h = &s[2..];
    let g = |i: usize| &h[4 * i..4 * i + 4];
    [
        alloc::format!("0x{} {} {} {}", g(0), g(1), g(2), g(3)),
        alloc::format!("{} {} {} {}", g(4), g(5), g(6), g(7)),
        alloc::format!("{} {}", g(8), g(9)),
    ]
}

/// Bytes as 0x-hex, shortened to the first and last `k` digits when longer.
pub fn short_hex(b: &[u8], k: usize) -> String {
    let s = winterlock_core::hex::encode(b);
    if s.len() <= 2 * k {
        alloc::format!("0x{s}")
    } else {
        alloc::format!("0x{}..{}", &s[..k], &s[s.len() - k..])
    }
}

/// A chain's name for the screen.
pub fn chain_name(chain: u64) -> String {
    match chain {
        1 => "Ethereum".into(),
        42161 => "Arbitrum One".into(),
        11155111 => "Sepolia".into(),
        421614 => "Arbitrum Sepolia".into(),
        _ => alloc::format!("chain {chain}"),
    }
}

/// Whether a chain's native currency is ETH (the chains [`chain_name`] knows).
pub fn eth_chain(chain: u64) -> bool {
    matches!(chain, 1 | 42161 | 11155111 | 421614)
}

/// Splits text into lines of at most `cols` characters at spaces.
pub fn wrap(text: &str, cols: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    for w in text.split(' ') {
        if !line.is_empty() && line.len() + 1 + w.len() > cols {
            out.push(core::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(w);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_fit() {
        let a: [u8; 20] = core::array::from_fn(|i| (i * 13 + 7) as u8);
        let l = address_lines(&a);
        assert!(l.iter().all(|x| x.len() <= COLS), "{l:?}");
        let joined: String = l.concat().replace(' ', "");
        assert_eq!(joined, winterlock_core::hex::checksum(&a));
        assert_eq!(short_address(&a).len(), 12);
    }

    #[test]
    fn frame_layouts_agree() {
        let mut f = Frame::default();
        f.set(0, 0, true);
        f.set(127, 63, true);
        f.set(5, 9, true);
        let p = f.to_pages();
        assert_eq!(p[0], 1);
        assert_eq!(p[7 * 128 + 127], 0x80);
        assert_eq!(p[128 + 5], 0x02);
    }
}
