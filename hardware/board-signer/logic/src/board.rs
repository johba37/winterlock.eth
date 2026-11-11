//! The board: button events and USB requests in, screens and answers out (docs/notes/signer-app.md,
//! "The board"). One request is worked on at a time; it is answered when its flow ends.
//!
//! - **Setup:** the seed from the board's randomness hashed with the app's; the 24 words, four a
//!   page; three of them asked back, each picked from four; a PIN of 4 to 8 digits, twice; the
//!   member key (its leaves on both cores), written to flash; the member key and owner address to
//!   the app.
//! - **Unlock:** the PIN at every start, each try counted in flash before it is checked; three
//!   wrong in a row erase the seed and the key log.
//! - **Recovery:** the 24 words letter by letter (four letters pick a word), the checksum, a PIN.
//!   A recovered board has no key trees until it enrols new ones.
//! - **Enrol:** a height-10 key tree for a Safe and chain from a fresh salt, kept with its leaves;
//!   the member key signs its certificate.
//! - **Confirm a transaction:** from its fields, decoded on the board; recorded in the key log,
//!   read back, then signed.
//! - **The gas key** to the app, once unlocked. **Erase** from the menu.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use embedded_storage::nor_flash::NorFlash;
use winterlock_core::derive::{self, TreePlace};
use winterlock_core::keylog::{self, Refused};
use winterlock_core::safe::SafeTx;
use winterlock_core::{U256, leansphincs, owner, phrase, wots};

use crate::decode::{self, Action, Decoded};
use crate::input::Button;
use crate::keys;
use crate::platform::{Platform, Secret};
use crate::proto::{self, Code, Fail, Request, Writer, ty};
use crate::store::{How, Opened, Phase, Store, StoreError};
use crate::ui::{self, Body, Screen, address_lines, chain_name, short_address, wrap};

/// Wrong PINs in a row that erase the board.
pub const PIN_TRIES: u8 = 3;
pub const PIN_MIN: usize = 4;
pub const PIN_MAX: usize = 8;
/// The height of the board's key trees: 1,024 one-time keys, 512 nonces.
pub const TREE_HEIGHT: u8 = 10;
/// Words asked back at setup, and the choices for each.
pub const CHECKS: usize = 3;
pub const CHOICES: usize = 4;
/// Randomizer candidates per core per round of a stateless signature.
const GRIND_CHUNK: u64 = 2048;
/// Rounds of member key and tree leaves (each split between the cores), for the progress bar.
const LEAF_ROUNDS: usize = 16;

// --- the PIN pad ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinItem {
    Digit(u8),
    Del,
    Done,
}

/// Left and right step through the digits (then delete and done), both takes the one shown.
struct PinPad {
    digits: Vec<u8>,
    cur: usize,
}

impl Drop for PinPad {
    fn drop(&mut self) {
        self.digits.fill(0);
    }
}

impl PinPad {
    fn new() -> Self {
        PinPad { digits: Vec::new(), cur: 0 }
    }

    fn items(&self) -> Vec<PinItem> {
        let n = self.digits.len();
        let mut v: Vec<PinItem> = if n < PIN_MAX { (0..10).map(PinItem::Digit).collect() } else { Vec::new() };
        if n >= 1 {
            v.push(PinItem::Del);
        }
        if n >= PIN_MIN {
            v.push(PinItem::Done);
        }
        v
    }

    fn item(&self) -> PinItem {
        let it = self.items();
        it[self.cur % it.len()]
    }

    fn step(&mut self, by: isize) {
        let n = self.items().len() as isize;
        self.cur = ((self.cur as isize + by).rem_euclid(n)) as usize;
    }

    /// Takes the item shown; returns the PIN when it is done.
    fn take(&mut self) -> Option<Vec<u8>> {
        match self.item() {
            PinItem::Digit(d) => self.digits.push(d),
            PinItem::Del => {
                self.digits.pop();
            }
            PinItem::Done => return Some(core::mem::take(&mut self.digits)),
        }
        // the next position starts at 0, or at done when no digit fits
        self.cur = if self.digits.len() >= PIN_MAX { self.items().len() - 1 } else { 0 };
        None
    }

    fn shown(&self) -> String {
        let cur = match self.item() {
            PinItem::Digit(d) => format!("{d}"),
            PinItem::Del => "<-".into(),
            PinItem::Done => "OK".into(),
        };
        format!("{}[{}]", "*".repeat(self.digits.len()), cur)
    }

    fn hint(&self) -> &'static str {
        match self.item() {
            PinItem::Digit(_) => "both: next",
            PinItem::Del => "both: delete",
            PinItem::Done => "both: done",
        }
    }
}

// --- the word wheel (recovery) ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WheelItem {
    Letter(u8),
    /// The prefix is itself a word, and also the start of others ("add": add, addict, address).
    Word(u16),
    Del,
}

struct Wheel {
    prefix: String,
    cur: usize,
}

/// The words of the list that start with `prefix`: (first index, count).
fn candidates(prefix: &str) -> (usize, usize) {
    let list = phrase::wordlist();
    let first = list.partition_point(|w| *w < prefix);
    let count = list[first..].iter().take_while(|w| w.starts_with(prefix)).count();
    (first, count)
}

impl Wheel {
    fn new() -> Self {
        Wheel { prefix: String::new(), cur: 0 }
    }

    fn items(&self) -> Vec<WheelItem> {
        let list = phrase::wordlist();
        let (first, count) = candidates(&self.prefix);
        let n = self.prefix.len();
        let mut v = Vec::new();
        let mut last = 0u8;
        for w in &list[first..first + count] {
            if let Some(&c) = w.as_bytes().get(n)
                && c != last
            {
                v.push(WheelItem::Letter(c));
                last = c;
            }
        }
        if count > 1 && list[first] == self.prefix {
            v.push(WheelItem::Word(first as u16));
        }
        v.push(WheelItem::Del);
        v
    }

    fn item(&self) -> WheelItem {
        let it = self.items();
        it[self.cur % it.len()]
    }

    fn step(&mut self, by: isize) {
        let n = self.items().len() as isize;
        self.cur = ((self.cur as isize + by).rem_euclid(n)) as usize;
    }
}

// --- modes ---

struct Check {
    positions: [usize; CHECKS],
    choices: [[u16; CHOICES]; CHECKS],
}

struct SignJob {
    id: u16,
    tree: usize,
    tx: SafeTx,
    hash: [u8; 32],
    nonce: u64,
    decoded: Decoded,
}

struct EnrolJob {
    id: u16,
    chain: u64,
    safe: [u8; 20],
    start: u64,
}

enum Mode {
    Blank,
    Damaged(&'static str),
    /// The board was just erased; why.
    Erased(&'static str),
    Locked(PinPad),
    WrongPin(u8),
    Home,
    Menu(usize),
    Address,
    Trees(usize),
    EraseConfirm,
    SetupIntro,
    Words(usize),
    Written,
    Check { round: usize, check: Box<Check>, cursor: usize },
    CheckWrong(usize),
    RecoverIntro,
    RecoverWord { n: usize, wheel: Wheel, fixing: bool },
    RecoverWordOk { n: usize, word: u16, fixing: bool },
    RecoverChecksum,
    RecoverFix(usize),
    PinIntro,
    PinNew(PinPad),
    PinAgain(PinPad, Vec<u8>),
    PinMismatch,
    Identity { recovered: bool, page: usize },
    Enrol { job: EnrolJob, page: usize },
    Sign { job: Box<SignJob>, pages: Vec<Screen>, page: usize, second: bool },
    Result { title: String, lines: Vec<String> },
}

/// A setup or recovery under way.
struct SetupCtx {
    id: u16,
    how: How,
    seed: Option<Secret>,
    words: [u16; 24],
}

/// What an unlock gives: the seed and the member key, until the board is erased or restarts.
struct Session {
    seed: Secret,
    key: leansphincs::Key,
}

/// The board.
pub struct Board<F: NorFlash, P: Platform> {
    pub store: Store<F>,
    pub platform: P,
    mode: Mode,
    setup: Option<SetupCtx>,
    session: Option<Session>,
    screen: Screen,
    version: &'static str,
}

fn store_fail(e: StoreError) -> Fail {
    match e {
        StoreError::Full => Fail::new(Code::StorageFull, "the board's storage is full"),
        StoreError::Damaged => Fail::new(Code::Damaged, "the board's storage is damaged"),
        _ => Fail::new(Code::Storage, "the board's storage failed: nothing was signed"),
    }
}

impl<F: NorFlash, P: Platform> Board<F, P> {
    /// Opens the storage, shows the first screen and tells the app the board started.
    /// `version` is the firmware's version, for the status answer.
    pub fn new(flash: F, platform: P, version: &'static str) -> Result<Self, StoreError> {
        let (store, opened) = Store::open(flash)?;
        let mode = match store.phase() {
            Phase::Blank if opened == Opened::Wiped => Mode::Erased("boot"),
            Phase::Blank => Mode::Blank,
            Phase::Ready => Mode::Locked(PinPad::new()),
            Phase::Damaged(why) => Mode::Damaged(why),
        };
        let mut b = Board { store, platform, mode, setup: None, session: None, screen: Screen::lines("", &[], "", ""), version };
        b.draw();
        let payload = b.status_payload();
        b.platform.send(&proto::encode(ty::EV_BOOTED, 0, &payload));
        Ok(b)
    }

    /// The screen shown now.
    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    pub fn unlocked(&self) -> bool {
        self.session.is_some()
    }

    fn draw(&mut self) {
        self.screen = self.build_screen();
        let f = self.screen.render();
        self.platform.show(&self.screen, &f);
    }

    fn go(&mut self, m: Mode) {
        self.mode = m;
        self.draw();
    }

    fn progress(&mut self, title: &str, text: &str, done: u32, total: u32, note: &str) {
        self.screen = Screen {
            title: title.into(),
            corner: String::new(),
            body: Body::Progress { text: text.into(), done, total, note: note.into() },
            left: String::new(),
            right: String::new(),
        };
        let f = self.screen.render();
        self.platform.show(&self.screen, &f);
    }

    fn send(&mut self, t: u8, id: u16, payload: &[u8]) {
        let f = proto::encode(t, id, payload);
        self.platform.send(&f);
    }

    fn fail(&mut self, id: u16, f: Fail) {
        self.send(ty::A_ERROR, id, &proto::error_payload(&f));
    }

    fn random32(&mut self) -> [u8; 32] {
        let mut r = [0u8; 32];
        self.platform.random(&mut r);
        r
    }

    /// A uniform number below n (n > 0).
    fn below(&mut self, n: u32) -> u32 {
        let zone = u32::MAX - u32::MAX % n;
        loop {
            let mut b = [0u8; 4];
            self.platform.random(&mut b);
            let v = u32::from_le_bytes(b);
            if v < zone {
                return v % n;
            }
        }
    }

    fn pending(&self) -> Option<u16> {
        match &self.mode {
            Mode::Enrol { job, .. } => Some(job.id),
            Mode::Sign { job, .. } => Some(job.id),
            _ => self.setup.as_ref().map(|s| s.id),
        }
    }

    /// Back to where the board rests: home if unlocked, else the PIN or the blank screen.
    fn rest(&mut self) {
        let m = match self.store.phase() {
            Phase::Blank => Mode::Blank,
            Phase::Damaged(w) => Mode::Damaged(w),
            Phase::Ready if self.session.is_some() => Mode::Home,
            Phase::Ready => Mode::Locked(PinPad::new()),
        };
        self.go(m);
    }

    fn result(&mut self, title: &str, text: &str) {
        self.go(Mode::Result { title: title.into(), lines: wrap(text, ui::COLS) });
    }

    // --- screens ---

    fn build_screen(&self) -> Screen {
        let s = |t: &str, l: &[&str], a: &str, b: &str| Screen::lines(t, l, a, b);
        match &self.mode {
            Mode::Blank => s("Winterlock", &["Not set up.", "Open the app to set", "up this board, or to", "recover it."], "", ""),
            Mode::Damaged(why) => {
                let mut l = wrap(why, ui::COLS);
                l.truncate(3);
                l.push("It signs nothing.".into());
                Screen { body: Body::Lines(l), ..s("Storage damaged", &[], "", "hold both: erase") }
            }
            Mode::Erased(why) => match *why {
                "pins" => s("Erased", &["3 wrong PINs: the", "seed and key log are", "gone. Recover with", "your 24 words."], "", "next >"),
                "boot" => s("Erased", &["An erase or a setup", "didn't finish, or 3", "wrong PINs: the board", "erased itself."], "", "next >"),
                _ => s("Erased", &["The seed and key log", "are gone. Recover", "with your 24 words,", "or set up anew."], "", "next >"),
            },
            Mode::Locked(pad) => {
                let tries = self.store.tries();
                let below = if tries > 0 { format!("{} tries left", PIN_TRIES - tries) } else { String::new() };
                Screen {
                    title: "Enter PIN".into(),
                    corner: String::new(),
                    body: Body::Big { above: String::new(), value: pad.shown(), below },
                    left: "< > change".into(),
                    right: pad.hint().into(),
                }
            }
            Mode::WrongPin(left) => {
                let l2 = format!("{left} more wrong and");
                s("Wrong PIN", &["That PIN is wrong.", &l2, "the board erases", "itself."], "", "next >")
            }
            Mode::Home => {
                let id = self.store.identity().expect("set up");
                let o = format!("Owner {}", short_address(&id.owner));
                let n = self.store.trees().len();
                let t = match n {
                    0 => "No key trees yet".to_string(),
                    1 => "1 key tree".to_string(),
                    _ => format!("{n} key trees"),
                };
                s("Winterlock", &["Ready to sign.", &o, &t], "", "menu >")
            }
            Mode::Menu(c) => Screen {
                title: "Menu".into(),
                corner: String::new(),
                body: Body::Choices { items: MENU.iter().map(|m| m.to_string()).collect(), cursor: *c },
                left: "< > move".into(),
                right: "hold both: open".into(),
            },
            Mode::Address => {
                let id = self.store.identity().expect("set up");
                let l = address_lines(&id.owner);
                s("Owner address", &[&l[0], &l[1], &l[2]], "< back", "")
            }
            Mode::Trees(i) => {
                let trees = self.store.trees();
                if trees.is_empty() {
                    return s("Key trees", &["No key trees yet.", "Enrol one per Safe", "from the app."], "< back", "");
                }
                let t = &trees[*i];
                let last = t.start + (1u64 << (t.height - 1)) - 1;
                let l1 = format!("Safe {}", short_address(&t.safe));
                let l2 = format!("nonces {}-{}", t.start, last);
                let l3 = format!("{} of {} keys used", t.used_keys(), t.keys());
                s("Key tree", &[&chain_name(t.chain), &l1, &l2, &l3], "< back", "next >").with_corner(&format!("{}/{}", i + 1, trees.len()))
            }
            Mode::EraseConfirm => s("Erase board?", &["Deletes the seed and", "the key log. Only", "your 24 words bring", "it back."], "< no", "hold both: erase"),
            Mode::SetupIntro => s("New board", &["The next 6 pages", "show 24 words. Write", "them on paper, in", "order. Keep it safe."], "< cancel", "next >"),
            Mode::Words(p) => {
                let ctx = self.setup.as_ref().expect("setup");
                let list = phrase::wordlist();
                let l: Vec<String> = (0..4).map(|i| format!("{:>2}. {}", 4 * p + i + 1, list[ctx.words[4 * p + i] as usize])).collect();
                Screen { body: Body::Lines(l), ..s("Your words", &[], "< back", "next >") }.with_corner(&format!("{}/6", p + 1))
            }
            Mode::Written => s("All written?", &["Check you wrote all", "24 words, in order.", "Then 3 of them are", "asked back."], "< words", "hold both: yes"),
            Mode::Check { round, check, cursor } => {
                let list = phrase::wordlist();
                Screen {
                    title: format!("Word {}?", check.positions[*round] + 1),
                    corner: format!("{}/{}", round + 1, CHECKS),
                    body: Body::Choices { items: check.choices[*round].iter().map(|&w| list[w as usize].to_string()).collect(), cursor: *cursor },
                    left: "< > move".into(),
                    right: "hold both: pick".into(),
                }
            }
            Mode::CheckWrong(pos) => {
                let l1 = format!("That isn't word {}.", pos + 1);
                s("Not that one", &[&l1, "Compare your paper", "with the words once", "more."], "", "next >")
            }
            Mode::RecoverIntro => s("Recover", &["Enter your 24 words", "letter by letter.", "4 letters pick a", "word."], "< cancel", "next >"),
            Mode::RecoverWord { n, wheel, .. } => {
                let (first, count) = candidates(&wheel.prefix);
                let list = phrase::wordlist();
                let cur = match wheel.item() {
                    WheelItem::Letter(c) => (c as char).to_string(),
                    WheelItem::Word(w) => format!("={}", list[w as usize]),
                    WheelItem::Del => "<-".into(),
                };
                let mut below = String::new();
                for w in &list[first..first + count.min(4)] {
                    if below.len() + w.len() + 1 > ui::COLS {
                        break;
                    }
                    if !below.is_empty() {
                        below.push(' ');
                    }
                    below.push_str(w);
                }
                Screen {
                    title: format!("Word {}", n + 1),
                    corner: format!("{count} match"),
                    body: Body::Big { above: String::new(), value: format!("{}[{}]", wheel.prefix, cur), below },
                    left: "< > letter".into(),
                    right: "both: pick".into(),
                }
            }
            Mode::RecoverWordOk { n, word, .. } => Screen {
                title: format!("Word {}", n + 1),
                corner: String::new(),
                body: Body::Big { above: String::new(), value: phrase::wordlist()[*word as usize].into(), below: String::new() },
                left: "< undo".into(),
                right: "both: ok".into(),
            },
            Mode::RecoverChecksum => s("Checksum wrong", &["The words don't match", "their checksum: one", "is wrong, or two are", "swapped."], "", "next >"),
            Mode::RecoverFix(c) => {
                let ctx = self.setup.as_ref().expect("recovery");
                let list = phrase::wordlist();
                let top = (*c / 4) * 4;
                let items = (top..(top + 4).min(24)).map(|i| format!("{:>2}. {}", i + 1, list[ctx.words[i] as usize])).collect();
                Screen {
                    title: "Fix a word".into(),
                    corner: format!("{}/24", c + 1),
                    body: Body::Choices { items, cursor: c - top },
                    left: "< > move".into(),
                    right: "both: retype".into(),
                }
            }
            Mode::PinIntro => s("Choose a PIN", &["4 to 8 digits. The", "board asks for it at", "every start. 3 wrong", "in a row erase it."], "", "next >"),
            Mode::PinNew(pad) | Mode::PinAgain(pad, _) => Screen {
                title: if matches!(self.mode, Mode::PinNew(_)) { "Choose a PIN".into() } else { "PIN again".into() },
                corner: String::new(),
                body: Body::Big { above: String::new(), value: pad.shown(), below: String::new() },
                left: "< > change".into(),
                right: pad.hint().into(),
            },
            Mode::PinMismatch => s("PINs differ", &["The two PINs aren't", "the same. Choose it", "again."], "", "next >"),
            Mode::Identity { recovered, page } => {
                let id = self.store.identity().expect("set up");
                if *page == 0 {
                    let l = address_lines(&id.owner);
                    s("Owner address", &[&l[0], &l[1], &l[2], "Same as in the app?"], "", "next >")
                } else if *recovered {
                    s("Recovered", &["This board has no key", "trees: enrol each", "Safe again before it", "signs there."], "", "next >")
                } else {
                    s("Ready", &["Keep the paper safe.", "It is the only way", "back if this board", "is lost."], "", "next >")
                }
            }
            Mode::Enrol { job, page } => {
                let chain = chain_name(job.chain);
                if *page == 0 {
                    let l1 = format!("Safe {}", short_address(&job.safe));
                    let l2 = format!("from nonce {}", job.start);
                    let l3 = format!("{} nonces", 1u64 << (TREE_HEIGHT - 1));
                    s("Enrol key tree", &[&chain, &l1, &l2, &l3], "< reject", "next >").with_corner("1/2")
                } else {
                    let l = address_lines(&job.safe);
                    s("Safe address", &[&l[0], &l[1], &l[2], &chain], "< back", "hold both: enrol").with_corner("2/2")
                }
            }
            Mode::Sign { pages, page, second, .. } => {
                if *second {
                    s("Not decoded", &["The board can't show", "all this does. Sign", "only if you know", "what it is."], "< reject", "hold both: sign")
                } else {
                    pages[*page].clone()
                }
            }
            Mode::Result { title, lines } => {
                let l: Vec<&str> = lines.iter().map(|x| x.as_str()).collect();
                s(title, &l, "", "next >")
            }
        }
    }

    // --- buttons ---

    pub fn button(&mut self, b: Button) {
        let mode = core::mem::replace(&mut self.mode, Mode::Blank);
        use Button::*;
        let next = match (mode, b) {
            (Mode::Blank, _) => Mode::Blank,
            (Mode::Damaged(_), Both) => Mode::EraseConfirm,
            (m @ Mode::Damaged(_), _) => m,
            (Mode::Erased(_), Right | Both) => Mode::Blank,
            (m @ Mode::Erased(_), Left) => m,
            (Mode::Locked(mut pad), Left) => {
                pad.step(-1);
                Mode::Locked(pad)
            }
            (Mode::Locked(mut pad), Right) => {
                pad.step(1);
                Mode::Locked(pad)
            }
            (Mode::Locked(mut pad), Both) => match pad.take() {
                None => Mode::Locked(pad),
                Some(pin) => return self.check_pin(pin),
            },
            (Mode::WrongPin(_), Right | Both) => Mode::Locked(PinPad::new()),
            (m @ Mode::WrongPin(_), Left) => m,
            (Mode::Home, Right) => Mode::Menu(0),
            (Mode::Home, Left) => Mode::Menu(MENU.len() - 1),
            (Mode::Home, Both) => Mode::Home,
            (Mode::Menu(c), Left) => Mode::Menu((c + MENU.len() - 1) % MENU.len()),
            (Mode::Menu(c), Right) => Mode::Menu((c + 1) % MENU.len()),
            (Mode::Menu(c), Both) => match c {
                0 => Mode::Address,
                1 => Mode::Trees(0),
                2 => Mode::EraseConfirm,
                _ => Mode::Home,
            },
            (Mode::Address, Left | Both) => Mode::Menu(0),
            (Mode::Address, Right) => Mode::Address,
            (Mode::Trees(i), Right) => Mode::Trees(if self.store.trees().is_empty() { 0 } else { (i + 1) % self.store.trees().len() }),
            (Mode::Trees(_), Left | Both) => Mode::Menu(1),
            (Mode::EraseConfirm, Left) => {
                if let Phase::Damaged(w) = self.store.phase() {
                    Mode::Damaged(w)
                } else {
                    Mode::Menu(2)
                }
            }
            (Mode::EraseConfirm, Both) => return self.erase("menu"),
            (m @ Mode::EraseConfirm, Right) => m,
            // setup
            (Mode::SetupIntro, Left) => return self.abandon_setup(),
            (Mode::SetupIntro, Right) => Mode::Words(0),
            (m @ Mode::SetupIntro, Both) => m,
            (Mode::Words(0), Left) => Mode::SetupIntro,
            (Mode::Words(p), Left) => Mode::Words(p - 1),
            (Mode::Words(5), Right) => Mode::Written,
            (Mode::Words(p), Right) => Mode::Words(p + 1),
            (m @ Mode::Words(_), Both) => m,
            (Mode::Written, Left) => Mode::Words(5),
            (Mode::Written, Both) => self.new_check(),
            (m @ Mode::Written, Right) => m,
            (Mode::Check { round, check, cursor }, Left) => Mode::Check { round, check, cursor: (cursor + CHOICES - 1) % CHOICES },
            (Mode::Check { round, check, cursor }, Right) => Mode::Check { round, check, cursor: (cursor + 1) % CHOICES },
            (Mode::Check { round, check, cursor }, Both) => {
                let ctx = self.setup.as_ref().expect("setup");
                let pos = check.positions[round];
                if check.choices[round][cursor] != ctx.words[pos] {
                    Mode::CheckWrong(pos)
                } else if round + 1 < CHECKS {
                    Mode::Check { round: round + 1, check, cursor: 0 }
                } else {
                    Mode::PinIntro
                }
            }
            (Mode::CheckWrong(_), Right | Both) => Mode::Words(0),
            (m @ Mode::CheckWrong(_), Left) => m,
            // recovery
            (Mode::RecoverIntro, Left) => return self.abandon_setup(),
            (Mode::RecoverIntro, Right) => Mode::RecoverWord { n: 0, wheel: Wheel::new(), fixing: false },
            (m @ Mode::RecoverIntro, Both) => m,
            (Mode::RecoverWord { n, mut wheel, fixing }, Left) => {
                wheel.step(-1);
                Mode::RecoverWord { n, wheel, fixing }
            }
            (Mode::RecoverWord { n, mut wheel, fixing }, Right) => {
                wheel.step(1);
                Mode::RecoverWord { n, wheel, fixing }
            }
            (Mode::RecoverWord { n, mut wheel, fixing }, Both) => match wheel.item() {
                WheelItem::Del => {
                    if wheel.prefix.pop().is_none() && n > 0 && !fixing {
                        // back to the word before
                        Mode::RecoverWord { n: n - 1, wheel: Wheel::new(), fixing }
                    } else {
                        wheel.cur = 0;
                        Mode::RecoverWord { n, wheel, fixing }
                    }
                }
                WheelItem::Word(w) => Mode::RecoverWordOk { n, word: w, fixing },
                WheelItem::Letter(c) => {
                    wheel.prefix.push(c as char);
                    wheel.cur = 0;
                    let (first, count) = candidates(&wheel.prefix);
                    if count == 1 {
                        Mode::RecoverWordOk { n, word: first as u16, fixing }
                    } else {
                        Mode::RecoverWord { n, wheel, fixing }
                    }
                }
            },
            (Mode::RecoverWordOk { n, fixing, .. }, Left) => Mode::RecoverWord { n, wheel: Wheel::new(), fixing },
            (Mode::RecoverWordOk { n, word, fixing }, Both | Right) => {
                self.setup.as_mut().expect("recovery").words[n] = word;
                if fixing || n == 23 { self.check_words() } else { Mode::RecoverWord { n: n + 1, wheel: Wheel::new(), fixing } }
            }
            (Mode::RecoverChecksum, Right | Both) => Mode::RecoverFix(0),
            (m @ Mode::RecoverChecksum, Left) => m,
            (Mode::RecoverFix(c), Left) => Mode::RecoverFix((c + 23) % 24),
            (Mode::RecoverFix(c), Right) => Mode::RecoverFix((c + 1) % 24),
            (Mode::RecoverFix(c), Both) => Mode::RecoverWord { n: c, wheel: Wheel::new(), fixing: true },
            // the PIN
            (Mode::PinIntro, Right | Both) => Mode::PinNew(PinPad::new()),
            (m @ Mode::PinIntro, Left) => m,
            (Mode::PinNew(mut pad), Left) => {
                pad.step(-1);
                Mode::PinNew(pad)
            }
            (Mode::PinNew(mut pad), Right) => {
                pad.step(1);
                Mode::PinNew(pad)
            }
            (Mode::PinNew(mut pad), Both) => match pad.take() {
                None => Mode::PinNew(pad),
                Some(pin) => Mode::PinAgain(PinPad::new(), pin),
            },
            (Mode::PinAgain(mut pad, first), Left) => {
                pad.step(-1);
                Mode::PinAgain(pad, first)
            }
            (Mode::PinAgain(mut pad, first), Right) => {
                pad.step(1);
                Mode::PinAgain(pad, first)
            }
            (Mode::PinAgain(mut pad, mut first), Both) => match pad.take() {
                None => Mode::PinAgain(pad, first),
                Some(mut pin) => {
                    let same = pin == first;
                    first.fill(0);
                    if same {
                        return self.finish_setup(pin);
                    }
                    pin.fill(0);
                    Mode::PinMismatch
                }
            },
            (Mode::PinMismatch, Right | Both) => Mode::PinNew(PinPad::new()),
            (m @ Mode::PinMismatch, Left) => m,
            (Mode::Identity { recovered, page: 0 }, Right | Both) => Mode::Identity { recovered, page: 1 },
            (Mode::Identity { .. }, Right | Both) => Mode::Home,
            (m @ Mode::Identity { .. }, Left) => m,
            // requests
            (Mode::Enrol { job, page: 0 }, Left) => return self.reject(job.id),
            (Mode::Enrol { job, page: 0 }, Right) => Mode::Enrol { job, page: 1 },
            (Mode::Enrol { job, .. }, Left) => Mode::Enrol { job, page: 0 },
            (Mode::Enrol { job, page: 1 }, Both) => return self.enrol(job),
            (m @ Mode::Enrol { .. }, _) => m,
            (Mode::Sign { job, pages, page, second }, Left) => {
                if second || page == 0 {
                    return self.reject(job.id);
                }
                Mode::Sign { job, pages, page: page - 1, second }
            }
            (Mode::Sign { job, pages, page, second: false }, Right) if page + 1 < pages.len() => Mode::Sign { job, pages, page: page + 1, second: false },
            (Mode::Sign { job, pages, page, second }, Both) if second || page + 1 == pages.len() => {
                if !second && job.decoded.needs_second() {
                    Mode::Sign { job, pages, page, second: true }
                } else {
                    return self.sign(*job);
                }
            }
            (m @ Mode::Sign { .. }, _) => m,
            (Mode::Result { .. }, Right | Both) => return self.rest(),
            (m @ Mode::Result { .. }, Left) => m,
        };
        self.go(next);
    }

    fn new_check(&mut self) -> Mode {
        let mut positions = [0usize; CHECKS];
        let mut n = 0;
        while n < CHECKS {
            let p = self.below(24) as usize;
            if !positions[..n].contains(&p) {
                positions[n] = p;
                n += 1;
            }
        }
        positions.sort_unstable();
        let words = self.setup.as_ref().expect("setup").words;
        let mut choices = [[0u16; CHOICES]; CHECKS];
        for (r, &pos) in positions.iter().enumerate() {
            let right = words[pos];
            let mut c = [right; CHOICES];
            let mut k = 1;
            while k < CHOICES {
                let w = self.below(2048) as u16;
                if !c[..k].contains(&w) {
                    c[k] = w;
                    k += 1;
                }
            }
            // put the right word at a random place
            let at = self.below(CHOICES as u32) as usize;
            c.swap(0, at);
            choices[r] = c;
        }
        Mode::Check { round: 0, check: Box::new(Check { positions, choices }), cursor: 0 }
    }

    fn check_words(&mut self) -> Mode {
        let ctx = self.setup.as_mut().expect("recovery");
        match keys::seed_of_indices(&ctx.words) {
            Ok(seed) => {
                ctx.seed = Some(Secret(seed));
                Mode::PinIntro
            }
            Err(_) => Mode::RecoverChecksum,
        }
    }

    fn abandon_setup(&mut self) {
        if let Some(ctx) = self.setup.take() {
            self.fail(ctx.id, Fail::new(Code::Rejected, "setup cancelled on the board"));
        }
        self.rest();
    }

    fn reject(&mut self, id: u16) {
        self.fail(id, Fail::new(Code::Rejected, "rejected on the board"));
        self.result("Rejected", "Nothing was signed.");
    }

    // --- the PIN ---

    fn check_pin(&mut self, mut pin: Vec<u8>) {
        let tries = match self.store.pin_try() {
            Ok(t) => t,
            Err(e) => {
                pin.fill(0);
                return self.storage_failed(None, e);
            }
        };
        let (salt, check) = *self.store.pin().expect("set up");
        let ok = keys::pin_check(&salt, &pin) == check;
        pin.fill(0);
        if !ok {
            if tries >= PIN_TRIES {
                return self.erase("pins");
            }
            return self.go(Mode::WrongPin(PIN_TRIES - tries));
        }
        if let Err(e) = self.store.pin_ok() {
            return self.storage_failed(None, e);
        }
        self.progress("Unlocking", "Reading the key", 0, 1, "");
        let r = (|| {
            let seed = Secret(self.store.seed()?);
            let leaves = self.store.member_leaves()?;
            let key = keys::member_key(&seed.0, leaves).map_err(|_| StoreError::Damaged)?;
            if Some(key.public_key()) != self.store.identity().map(|i| i.member_key) {
                return Err(StoreError::Damaged);
            }
            Ok(Session { seed, key })
        })();
        match r {
            Ok(s) => {
                self.session = Some(s);
                self.go(Mode::Home);
            }
            Err(e) => self.storage_failed(None, e),
        }
    }

    fn storage_failed(&mut self, id: Option<u16>, e: StoreError) {
        let f = store_fail(e);
        if let Some(id) = id {
            self.fail(id, f);
        }
        if let Some(ctx) = self.setup.take() {
            self.fail(ctx.id, f);
        }
        let text = match e {
            StoreError::Full => "The storage is full. Nothing was signed.",
            _ => "The storage failed. Nothing was signed.",
        };
        self.result("Storage error", text);
    }

    fn erase(&mut self, why: &'static str) {
        self.session = None;
        self.setup = None;
        self.progress("Erasing", "Erasing the seed", 0, 1, "and the key log");
        match self.store.wipe() {
            Ok(()) => self.go(Mode::Erased(why)),
            Err(e) => self.storage_failed(None, e),
        }
    }

    // --- heavy work, on both cores ---

    /// The member key's 1,024 leaves.
    fn member_leaves(&mut self, seed: &[u8; 32], title: &str) -> Vec<leansphincs::Node> {
        let (plan, ks) = keys::member_plan(seed);
        let n = plan.count as usize;
        let mut leaves = vec![[0u8; 16]; n];
        let per = n / LEAF_ROUNDS;
        for r in 0..LEAF_ROUNDS {
            let first = plan.first + (r * per) as u32;
            let (a, b) = leaves[r * per..(r + 1) * per].split_at_mut(per / 2);
            let p = plan.p;
            self.platform.both(&mut || leansphincs::leaves(&p, &ks, first, a), &mut || leansphincs::leaves(&p, &ks, first + (per / 2) as u32, b));
            self.progress(title, "Making the member key", (r + 1) as u32, LEAF_ROUNDS as u32, "about 12 s");
        }
        leaves
    }

    /// A key tree's leaves.
    fn tree_leaves(&mut self, seed: &wots::Seed, sk: &[u8; 32], height: u8) -> Vec<wots::Value> {
        let n = 1usize << height;
        let mut leaves = vec![[0u8; wots::N]; n];
        let rounds = LEAF_ROUNDS.min(n / 2);
        let per = n / rounds;
        for r in 0..rounds {
            let first = (r * per) as u64;
            let (a, b) = leaves[r * per..(r + 1) * per].split_at_mut(per / 2);
            self.platform.both(&mut || wots::leaves(seed, sk, first, &wots::Prf::SIGNER, a), &mut || wots::leaves(seed, sk, first + (per / 2) as u64, &wots::Prf::SIGNER, b));
            self.progress("Enrolling", "Making the key tree", (r + 1) as u32, rounds as u32, "about 45 s");
        }
        leaves
    }

    /// A stateless signature by the member key, spread over both cores: the randomizer search in
    /// rounds (the least hit wins, as on one core), then the FORS trees in two halves. Verified
    /// before it is returned.
    fn stateless_sign(&mut self, m: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let Board { platform, session, screen, .. } = self;
        let key = &session.as_ref().ok_or("locked")?.key;
        let mut round = 0u64;
        let i = loop {
            let (mut a, mut b) = (None, None);
            let (lo, hi) = (2 * round * GRIND_CHUNK, (2 * round + 1) * GRIND_CHUNK);
            platform.both(&mut || a = key.grind_range(m, lo, GRIND_CHUNK), &mut || b = key.grind_range(m, hi, GRIND_CHUNK));
            if let Some(i) = a.or(b) {
                break i;
            }
            round += 1;
            // about 65,536 candidates on average: the bar fills to 3/4 at twice that
            let done = (round * 2 * GRIND_CHUNK).min(3 * 65_536) as u32;
            *screen = Screen {
                title: "Signing".into(),
                corner: String::new(),
                body: Body::Progress { text: "The member key signs".into(), done, total: 4 * 65_536, note: "about 10 to 30 s".into() },
                left: String::new(),
                right: String::new(),
            };
            let f = screen.render();
            platform.show(screen, &f);
        };
        let (mut fa, mut fb) = (Ok(Vec::new()), Ok(Vec::new()));
        platform.both(&mut || fa = key.fors_part(m, i, 0..12), &mut || fb = key.fors_part(m, i, 12..24));
        let mut fors = fa.map_err(|_| "FORS")?;
        fors.extend(fb.map_err(|_| "FORS")?);
        let sig = key.finish(m, i, &fors).map_err(|_| "finish")?;
        if !leansphincs::verify(&key.public_key(), m, &sig) {
            return Err("the stateless signature failed its own verification");
        }
        Ok(sig)
    }

    // --- setup and recovery ---

    fn finish_setup(&mut self, mut pin: Vec<u8>) {
        let mut ctx = self.setup.take().expect("setup");
        let seed = ctx.seed.take().expect("a seed");
        let title = if ctx.how == How::Recovered { "Recovering" } else { "Setting up" };
        let leaves = self.member_leaves(&seed.0, title);
        let key = match keys::member_key(&seed.0, leaves) {
            Ok(k) => k,
            Err(_) => {
                pin.fill(0);
                self.fail(ctx.id, Fail::new(Code::Storage, "the member key could not be made"));
                return self.result("Failed", "The member key could not be made.");
            }
        };
        let pk = key.public_key();
        let owner = owner::owner_address(&pk).expect("a member key has both halves nonzero");
        let salt = self.random32();
        let check = keys::pin_check(&salt, &pin);
        pin.fill(0);
        if let Err(e) = self.store.setup(&seed.0, ctx.how, &pk, key.kept_leaves(), &salt, &check, &owner) {
            self.setup = Some(ctx);
            return self.storage_failed(None, e);
        }
        self.session = Some(Session { seed, key });
        let mut w = Writer::new();
        w.bytes(&pk).bytes(&owner).u8(ctx.how as u8);
        self.send(ty::A_IDENTITY, ctx.id, &w.0);
        self.go(Mode::Identity { recovered: ctx.how == How::Recovered, page: 0 });
    }

    // --- enrolment ---

    fn enrol(&mut self, job: EnrolJob) {
        let Some(s) = &self.session else { return self.rest() };
        let seed = Secret(s.seed.0);
        let owner_addr = self.store.identity().expect("set up").owner;
        let salt = Secret(self.random32());
        let place = TreePlace { chain: job.chain, owner: owner_addr, safe: job.safe, device: 0, generation: 0, start: job.start };
        let sk = Secret(keys::tree_secret(&seed.0, &place, &salt.0));
        let tseed = derive::tree_public_seed(&place);
        let leaves = self.tree_leaves(&tseed, &sk.0, TREE_HEIGHT);
        let tree = match wots::Tree::from_leaves(&tseed, TREE_HEIGHT as u32, TREE_HEIGHT as u32, leaves, Vec::new()) {
            Ok(t) => t,
            Err(_) => return self.fail_flow(job.id, "the key tree could not be made"),
        };
        // the tree and its salt, then the certificate's record: both durable before it is signed
        let i = match self.store.add_tree(job.chain, &job.safe, job.start, TREE_HEIGHT, &salt.0, &tree) {
            Ok(i) => i,
            Err(e) => return self.storage_failed(Some(job.id), e),
        };
        let root = tree.root;
        drop(tree); // 49 KB the signature can use
        let digest = owner::certificate_digest(job.chain, &owner_addr, &job.safe, 0, 0, &root, TREE_HEIGHT as u32, job.start);
        if let Err(e) = self.store.record_certificate(i, &digest) {
            return self.storage_failed(Some(job.id), e);
        }
        let sig = match self.stateless_sign(&digest) {
            Ok(s) => s,
            Err(why) => return self.fail_flow(job.id, why),
        };
        let mut w = Writer::new();
        w.u64(job.chain).bytes(&job.safe).u64(job.start).u8(TREE_HEIGHT).bytes(&root).bytes(&sig);
        self.send(ty::A_ENROLLED, job.id, &w.0);
        let text = format!("Tree for {} made. The app sends its certificate.", short_address(&job.safe));
        self.result("Enrolled", &text);
    }

    fn fail_flow(&mut self, id: u16, why: &'static str) {
        self.fail(id, Fail::new(Code::Refused, why));
        self.result("Failed", why);
    }

    // --- signing ---

    fn sign(&mut self, job: SignJob) {
        let Some(s) = &self.session else { return self.rest() };
        let seed = Secret(s.seed.0);
        let t = self.store.trees()[job.tree].clone();
        self.progress("Signing", "Recording the key use", 0, 2, "");
        // the key log: the record is written and read back before anything is signed
        let rec = match keylog::record(&mut self.store, &t.tree_ref(), job.nonce, &job.hash) {
            Ok(r) => r,
            Err(Refused::Store(e)) => return self.storage_failed(Some(job.id), e),
            Err(_) => return self.fail_flow(job.id, "the key log refuses this key"),
        };
        self.progress("Signing", "Signing", 1, 2, "");
        let owner_addr = self.store.identity().expect("set up").owner;
        let place = TreePlace { chain: t.chain, owner: owner_addr, safe: t.safe, device: 0, generation: 0, start: t.start };
        let tseed = derive::tree_public_seed(&place);
        let tree = match self.store.tree_leaves(job.tree) {
            Ok(l) => wots::Tree::from_leaves(&tseed, t.height as u32, t.height as u32, l, Vec::new()).ok().filter(|x| x.root == t.root),
            Err(e) => return self.storage_failed(Some(job.id), e),
        };
        let Some(tree) = tree else { return self.fail_flow(job.id, "the key tree's leaves don't give its root") };
        let sk = Secret(keys::tree_secret(&seed.0, &place, &t.salt));
        let data = match owner::sign_transaction(&rec, &tree, &sk.0, 0, &job.tx) {
            Ok(d) => d,
            Err(_) => return self.fail_flow(job.id, "the signature failed its own check"),
        };
        let u = rec.key_use();
        let mut w = Writer::new();
        w.u8(u.slot).u64(u.key_index).bytes(&job.hash).u16(data.len() as u16).bytes(&data);
        self.send(ty::A_SIGNED, job.id, &w.0);
        let text = format!("Nonce {} signed with key {} of this tree. The app sends it.", job.nonce, u.key_index);
        self.result("Signed", &text);
    }

    // --- requests ---

    /// Handles a frame from the app.
    pub fn frame(&mut self, f: &proto::Frame) {
        if f.version != proto::VERSION {
            return self.fail(f.id, Fail::new(Code::BadVersion, "unsupported protocol version"));
        }
        let req = match proto::parse_request(f.ty, &f.payload) {
            Ok(r) => r,
            Err(e) => return self.fail(f.id, e),
        };
        self.request(f.id, req);
    }

    fn request(&mut self, id: u16, req: Request) {
        match req {
            Request::Status => {
                let p = self.status_payload();
                return self.send(ty::A_STATUS, id, &p);
            }
            Request::Cancel => {
                if let Some(pid) = self.pending() {
                    self.fail(pid, Fail::new(Code::Cancelled, "cancelled by the app"));
                    self.setup = None;
                    self.rest();
                }
                return self.send(ty::A_DONE, id, &[]);
            }
            #[cfg(feature = "test-hooks")]
            Request::TestButtons(evs) => {
                for e in evs {
                    self.button(e);
                }
                let p = proto::screen_payload(&self.screen.text());
                return self.send(ty::A_SCREEN, id, &p);
            }
            #[cfg(feature = "test-hooks")]
            Request::TestScreen => {
                let p = proto::screen_payload(&self.screen.text());
                return self.send(ty::A_SCREEN, id, &p);
            }
            _ => {}
        }
        if self.pending().is_some() {
            return self.fail(id, Fail::new(Code::Busy, "the board is busy with another request"));
        }
        let phase = self.store.phase();
        match req {
            Request::Setup { app_random } => {
                if phase != Phase::Blank {
                    return self.fail(id, Fail::new(Code::AlreadySetUp, "the board is set up: erase it first"));
                }
                let board = Secret(self.random32());
                let seed = Secret(keys::mix_seed(&board.0, &app_random));
                let words = keys::phrase_indices(&seed.0);
                self.setup = Some(SetupCtx { id, how: How::Setup, seed: Some(seed), words });
                self.go(Mode::SetupIntro);
            }
            Request::Recover => {
                if phase != Phase::Blank {
                    return self.fail(id, Fail::new(Code::AlreadySetUp, "the board is set up: erase it first"));
                }
                self.setup = Some(SetupCtx { id, how: How::Recovered, seed: None, words: [0; 24] });
                self.go(Mode::RecoverIntro);
            }
            _ => {
                match phase {
                    Phase::Blank => return self.fail(id, Fail::new(Code::NotSetUp, "the board isn't set up")),
                    Phase::Damaged(_) => return self.fail(id, Fail::new(Code::Damaged, "the board's storage is damaged: erase it")),
                    Phase::Ready => {}
                }
                if self.session.is_none() {
                    return self.fail(id, Fail::new(Code::Locked, "enter the PIN on the board first"));
                }
                match req {
                    Request::GasKey => {
                        let k = keys::gas_key(&self.session.as_ref().unwrap().seed.0);
                        match k {
                            Ok(k) => {
                                let k = Secret(k);
                                self.send(ty::A_GAS_KEY, id, &k.0)
                            }
                            Err(_) => self.fail(id, Fail::new(Code::Refused, "this seed gives no gas key")),
                        }
                    }
                    Request::Trees => {
                        let mut w = Writer::new();
                        let trees = self.store.trees();
                        w.u16(trees.len() as u16);
                        for t in trees {
                            w.u64(t.chain).bytes(&t.safe).u64(t.start).u8(t.height).bytes(&t.root).u16(t.used_keys() as u16).u8(t.certified as u8);
                        }
                        self.send(ty::A_TREES, id, &w.0)
                    }
                    Request::Enrol { chain, safe, start } => self.request_enrol(id, chain, safe, start),
                    Request::Sign(s) => self.request_sign(id, s),
                    _ => unreachable!(),
                }
            }
        }
    }

    fn refuse(&mut self, id: u16, text: &'static str) {
        self.fail(id, Fail::new(Code::Refused, text));
        self.result("Refused", text);
    }

    fn request_enrol(&mut self, id: u16, chain: u64, safe: [u8; 20], start: u64) {
        if start > owner::MAX_START {
            return self.fail(id, Fail::new(Code::Refused, "the start nonce is too large"));
        }
        if let Some(prior) = self.store.trees().iter().filter(|t| t.chain == chain && t.safe == safe).map(|t| t.start).max()
            && start <= prior
        {
            return self.fail(id, Fail::new(Code::Refused, "a new key tree must start after the board's last one for this Safe"));
        }
        self.go(Mode::Enrol { job: EnrolJob { id, chain, safe, start }, page: 0 });
    }

    fn request_sign(&mut self, id: u16, s: proto::SignRequest) {
        let decoded = match decode::decode(s.chain, &s.safe, &s.tx, s.parent.as_ref()) {
            Ok(d) => d,
            Err(r) => return self.refuse(id, r.text()),
        };
        let Some(nonce) = s.tx.nonce.to_u64() else { return self.refuse(id, "the nonce is too large") };
        let trees = self.store.trees();
        let pick = if s.root == [0; 24] {
            trees.iter().enumerate().filter(|(_, t)| t.chain == s.chain && t.safe == s.safe).max_by_key(|(_, t)| t.start).map(|(i, _)| i)
        } else {
            trees.iter().position(|t| t.chain == s.chain && t.safe == s.safe && t.root == s.root)
        };
        let Some(ti) = pick else {
            return self.refuse(id, "no key tree for this Safe on this chain: enrol first");
        };
        let t = &trees[ti];
        if owner::key_index(nonce, t.start, 0, t.height as u32).is_err() {
            return self.refuse(id, "the nonce is outside this Safe's key tree: enrol a new one");
        }
        let hash = s.tx.hash(s.chain, &s.safe);
        if let Err(r) = keylog::pick_slot(&self.store, &t.tree_ref(), nonce, &hash) {
            return match r {
                Refused::ThirdVersion { .. } => self.refuse(id, "both keys for this nonce signed other transactions"),
                Refused::Store(e) => self.storage_failed(Some(id), e),
                _ => self.refuse(id, "the key log refuses this key"),
            };
        }
        let pages = sign_pages(s.chain, &s.safe, &decoded);
        let job = SignJob { id, tree: ti, tx: s.tx, hash, nonce, decoded };
        self.go(Mode::Sign { job: Box::new(job), pages, page: 0, second: false });
    }

    fn status_payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let state = match self.store.phase() {
            Phase::Blank => 0,
            Phase::Ready if self.session.is_some() => 2,
            Phase::Ready => 1,
            Phase::Damaged(_) => 3,
        };
        let id = self.store.identity();
        let mut flags = 0u8;
        if cfg!(feature = "test-hooks") {
            flags |= 1;
        }
        if id.is_some_and(|i| i.how == How::Recovered) {
            flags |= 2;
        }
        let (used, size) = self.store.usage();
        // a &str in both builds, so `.text(version)` below compiles (and passes clippy) in each
        #[cfg(feature = "test-hooks")]
        let marked = format!("{} {}", self.version, proto::TEST_HOOKS_MARK);
        #[cfg(feature = "test-hooks")]
        let version: &str = &marked;
        #[cfg(not(feature = "test-hooks"))]
        let version: &str = self.version;
        w.u8(proto::VERSION)
            .text(version)
            .u8(state)
            .u8(self.pending().is_some() as u8)
            .u8(flags)
            .bytes(&id.map_or([0; 32], |i| i.member_key))
            .bytes(&id.map_or([0; 20], |i| i.owner))
            .u16(self.store.trees().len() as u16)
            .u32(used)
            .u32(size)
            .u32(self.store.stateless_signatures());
        w.0
    }
}

const MENU: [&str; 4] = ["Owner address", "Key trees", "Erase this board", "Back"];

// --- the pages of a transaction ---

fn value_text(chain: u64, v: &U256) -> String {
    let unit = if ui::eth_chain(chain) { "ETH" } else { "native" };
    format!("{} {}", decode::amount(v, 18), unit)
}

/// `s` if it fits a line, else `alt`.
fn fits(s: String, alt: &str) -> String {
    if s.len() <= ui::COLS { s } else { alt.to_string() }
}

/// A page with an amount: in a big font if it fits a line, else over lines (never cut).
fn amount_screen(title: &str, above: &str, amount: &str, below: &str) -> Screen {
    let body = if amount.len() <= ui::COLS {
        Body::Big { above: above.into(), value: amount.into(), below: below.into() }
    } else {
        let mut l: Vec<String> = Vec::new();
        for w in wrap(amount, ui::COLS) {
            // a number longer than a line is split, not cut
            for c in w.as_bytes().chunks(ui::COLS) {
                l.push(String::from_utf8_lossy(c).into_owned());
            }
        }
        if l.len() < ui::ROWS {
            l.push(below.into());
        }
        Body::Lines(l)
    };
    Screen { title: title.into(), corner: String::new(), body, left: "< back".into(), right: "next >".into() }
}

fn address_screen(title: &str, a: &[u8; 20], last: &str) -> Screen {
    let l = address_lines(a);
    Screen::lines(title, &[&l[0], &l[1], &l[2], last], "< back", "next >")
}

/// The pages for one action: a transaction's, or its parent's (titled "Parent: ...").
fn action_pages(chain: u64, d: &Decoded, parent: bool, out: &mut Vec<Screen>) {
    let p = |t: &str| if parent { format!("Parent: {t}") } else { t.to_string() };
    match &d.action {
        Action::Cancel => {
            let l4 = format!("nonce {}.", d.nonce);
            out.push(Screen::lines(&p("Cancel"), &["An empty call from", "the Safe to itself:", "it only uses up", &l4], "< back", "next >"));
        }
        Action::Eth { to, value } => {
            out.push(amount_screen(&p("Send"), &chain_name(chain), &value_text(chain, value), &format!("to {}", short_address(to))));
            out.push(address_screen("To", to, ""));
        }
        Action::Token { token, to, amount } => {
            let v = format!("{} {}", decode::amount(amount, token.decimals), token.symbol);
            out.push(amount_screen(&p("Send"), &chain_name(chain), &v, &format!("to {}", short_address(to))));
            out.push(address_screen("To", to, ""));
        }
        Action::Raw { to, value, selector, data_len } => {
            let sel = match selector {
                Some(s) => format!("function {}", ui::short_hex(s, 8)),
                None => "no function data".into(),
            };
            let l1 = format!("Call {}", short_address(to));
            let l3 = format!("{data_len} bytes of data");
            let l4 = if value.is_zero() { "no value".to_string() } else { "a value: next page".to_string() };
            out.push(Screen::lines(&p("NOT DECODED"), &[&l1, &sel, &l3, &l4], "< back", "next >"));
            if !value.is_zero() {
                out.push(amount_screen(&p("Value sent"), &chain_name(chain), &value_text(chain, value), "with the call"));
            }
            out.push(address_screen("Called contract", to, ""));
        }
        Action::Approve { parent_safe, parent_hash, parent: pd } => {
            let l3 = format!("{} nonce {}", short_address(parent_safe), pd.nonce);
            let l4 = format!("tx {}", ui::short_hex(parent_hash, 6));
            out.push(Screen::lines("Approve", &["Approves a parent", "Safe's transaction:", &l3, &l4], "< back", "next >"));
            action_pages(chain, pd, true, out);
            out.push(address_screen("Parent Safe", parent_safe, &format!("nonce {}", pd.nonce)));
            if let Some(r) = &pd.refund {
                out.push(refund_screen(r, true));
            }
        }
    }
}

/// Two lines that say what an action does, each fitting a line.
fn summary(chain: u64, d: &Decoded) -> [String; 2] {
    match &d.action {
        Action::Cancel => ["Cancel: empty call".into(), format!("using up nonce {}", d.nonce)],
        Action::Eth { to, value } => [fits(format!("Send {}", value_text(chain, value)), "Send ETH (page 1)"), format!("to {}", short_address(to))],
        Action::Token { token, to, amount } => {
            let alt = format!("Send {} (page 1)", token.symbol);
            [fits(format!("Send {} {}", decode::amount(amount, token.decimals), token.symbol), &alt), format!("to {}", short_address(to))]
        }
        Action::Raw { to, .. } => ["Call, NOT DECODED".into(), format!("to {}", short_address(to))],
        Action::Approve { parent, .. } => {
            let [a, _] = summary(chain, parent);
            ["Approve parent's tx:".into(), fits(a, "(pages before)")]
        }
    }
}

fn refund_screen(r: &decode::Refund, parent: bool) -> Screen {
    let l1 = fits(format!("gas price {}", r.gas_price), "gas price: huge");
    let l2 = fits(format!("base {} safeTx {}", r.base_gas, r.safe_tx_gas), "base, safeTx: huge");
    let l3 = if r.gas_token == [0; 20] { "paid in ETH".to_string() } else { format!("token {}", short_address(&r.gas_token)) };
    let l4 = if r.refund_receiver == [0; 20] { "to the executor".to_string() } else { format!("to {}", short_address(&r.refund_receiver)) };
    Screen::lines(if parent { "Parent: refund" } else { "Gas refund" }, &[&l1, &l2, &l3, &l4], "< back", "next >")
}

fn sign_pages(chain: u64, safe: &[u8; 20], d: &Decoded) -> Vec<Screen> {
    let mut pages = Vec::new();
    action_pages(chain, d, false, &mut pages);
    if let Some(r) = &d.refund {
        pages.push(refund_screen(r, false));
    }
    pages.push(address_screen("From Safe", safe, &fits(format!("nonce {}, {}", d.nonce, chain_name(chain)), &format!("nonce {}", d.nonce))));
    let [a, b] = summary(chain, d);
    let c = if d.needs_second() { "2 confirmations" } else { "" };
    let safe_line = fits(format!("Safe {} #{}", short_address(safe), d.nonce), &format!("Safe {}", short_address(safe)));
    pages.push(Screen::lines("Sign?", &[&a, &b, &safe_line, c], "< reject", "hold both: sign"));
    let n = pages.len();
    for (i, p) in pages.iter_mut().enumerate() {
        if p.corner.is_empty() && p.title.len() + 6 <= ui::COLS {
            p.corner = format!("{}/{}", i + 1, n);
        }
        if i == 0 {
            p.left = "< reject".into();
        }
    }
    pages
}
