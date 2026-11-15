//! The test bench: a board on a simulated flash, a platform that records what the board shows
//! and sends, and helpers that press the buttons through each flow.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use winterlock_board::input::Button;
use winterlock_board::proto::{self, Deframer, Frame, Reader, Writer, ty};
use winterlock_board::sim::{SimError, SimFlash};
use winterlock_board::store::{Phase, Store};
use winterlock_board::ui::{Body, Frame as Pixels, Screen};
use winterlock_board::{Board, Platform};
use winterlock_core::keylog::KeyLogStore;
use winterlock_core::safe::SafeTx;
use winterlock_core::{leansphincs, owner, phrase, wots};

pub const SECTORS: usize = 128; // a 512 KB partition: plenty for the tests, quick to scan
pub const PIN: &[u8] = &[2, 0, 2, 6];

/// A simulated flash that the test and the board share.
#[derive(Clone)]
pub struct Shared(pub Rc<RefCell<SimFlash>>);

impl Shared {
    pub fn new() -> Self {
        Shared(Rc::new(RefCell::new(SimFlash::new(SECTORS))))
    }
    pub fn from(f: SimFlash) -> Self {
        Shared(Rc::new(RefCell::new(f)))
    }
    pub fn snapshot(&self) -> SimFlash {
        self.0.borrow().reboot()
    }
}

impl ErrorType for Shared {
    type Error = SimError;
}

impl ReadNorFlash for Shared {
    const READ_SIZE: usize = 4;
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), SimError> {
        self.0.borrow_mut().read(offset, bytes)
    }
    fn capacity(&self) -> usize {
        self.0.borrow().capacity()
    }
}

impl NorFlash for Shared {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4096;
    fn erase(&mut self, from: u32, to: u32) -> Result<(), SimError> {
        self.0.borrow_mut().erase(from, to)
    }
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), SimError> {
        self.0.borrow_mut().write(offset, bytes)
    }
}

/// Every one-time signature that left a board in this test, by (tree root, key index): the
/// hashes it signed. A key that signed two hashes is the one thing that must never happen.
#[derive(Default)]
pub struct Ledger {
    pub signed: HashMap<([u8; 24], u64), Vec<[u8; 32]>>,
    pub signatures: usize,
    pub certificates: usize,
}

impl Ledger {
    pub fn assert_no_reuse(&self) {
        for ((root, k), hashes) in &self.signed {
            let mut h = hashes.clone();
            h.sort();
            h.dedup();
            assert!(h.len() <= 1, "one-time key {k} of tree {root:02x?} signed {} hashes", h.len());
        }
    }
}

pub struct TestPlatform {
    pub flash: Shared,
    pub rng: u64,
    /// Bytes `random` gives first, before its own.
    pub queue: VecDeque<u8>,
    pub sent: Vec<Frame>,
    pub shown: Vec<Screen>,
    pub ledger: Rc<RefCell<Ledger>>,
    deframer: Deframer,
    /// Run `both`'s jobs on two threads (as two cores would) or one after the other.
    pub threads: bool,
}

impl TestPlatform {
    pub fn new(flash: Shared, ledger: Rc<RefCell<Ledger>>) -> Self {
        TestPlatform { flash, rng: 0x1234_5678_9ABC_DEF1, queue: VecDeque::new(), sent: Vec::new(), shown: Vec::new(), ledger, deframer: Deframer::new(), threads: false }
    }

    /// Checks, at the moment it leaves, that what a signature or certificate depends on is in
    /// the flash already: a board restarted right now would find the key use (or the tree and the
    /// certificate's record).
    fn check_durable(&mut self, f: &Frame) {
        if f.ty != ty::A_SIGNED && f.ty != ty::A_ENROLLED {
            return;
        }
        let flash = self.flash.snapshot();
        let (store, _) = Store::open(flash).expect("the flash opens");
        assert_eq!(store.phase(), Phase::Ready, "a signature left a board whose flash isn't ready");
        let mut l = self.ledger.borrow_mut();
        if f.ty == ty::A_SIGNED {
            let s = parse_signed(&f.payload);
            let sig = owner::parse_tx_signature_data(&s.data).expect("a transaction signature");
            let o = store.identity().unwrap().owner;
            let t = store.trees().iter().find(|t| t.safe == sig.safe && leads_to(&s, t, &o)).expect("its tree is stored");
            let found = store.find_use(t.chain, &t.safe, &t.root, s.key_index).expect("the log reads");
            assert_eq!(found, Some(s.hash), "the key use is durable before the signature leaves");
            l.signed.entry((t.root, s.key_index)).or_default().push(s.hash);
            l.signatures += 1;
        } else {
            let e = parse_enrolled(&f.payload);
            let t = store.trees().iter().find(|t| t.root == e.root).expect("the tree is durable before its certificate leaves");
            assert!(t.certified, "the certificate's record is durable before it leaves");
            l.certificates += 1;
        }
    }
}

/// Whether a signature's path leads to tree `t`'s root.
fn leads_to(s: &Signed, t: &winterlock_board::store::TreeEntry, owner_addr: &[u8; 20]) -> bool {
    let sig = owner::parse_tx_signature_data(&s.data).unwrap();
    let seed = owner::tree_seed(t.chain, owner_addr, &t.safe, 0, 0, t.start);
    wots::verify_root(&seed, s.key_index, &s.hash, sig.wots_sig, sig.path) == Some(t.root)
}

impl Platform for TestPlatform {
    fn random(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = match self.queue.pop_front() {
                Some(x) => x,
                None => {
                    self.rng ^= self.rng << 13;
                    self.rng ^= self.rng >> 7;
                    self.rng ^= self.rng << 17;
                    self.rng as u8
                }
            };
        }
    }

    fn show(&mut self, screen: &Screen, _frame: &Pixels) {
        if let Some(why) = screen.overflows() {
            panic!("a screen doesn't fit: {why}: {:?}", screen.text());
        }
        self.shown.push(screen.clone());
    }

    fn send(&mut self, bytes: &[u8]) {
        self.deframer.push(bytes);
        let f = self.deframer.next_frame().expect("the board sends whole frames");
        assert!(self.deframer.next_frame().is_none());
        self.check_durable(&f);
        self.sent.push(f);
    }

    fn both(&mut self, here: &mut (dyn FnMut() + Send), there: &mut (dyn FnMut() + Send)) {
        if self.threads {
            std::thread::scope(|s| {
                s.spawn(&mut *there);
                here();
            });
        } else {
            here();
            there();
        }
    }
}

pub type TestBoard = Board<Shared, TestPlatform>;

pub fn boot(flash: Shared, ledger: Rc<RefCell<Ledger>>) -> TestBoard {
    Board::new(flash.clone(), TestPlatform::new(flash, ledger), "test").expect("the board starts")
}

// --- answers ---

#[derive(Debug, Clone)]
pub struct Signed {
    pub slot: u8,
    pub key_index: u64,
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

impl Signed {
    pub fn nonce(&self) -> u64 {
        owner::parse_tx_signature_data(&self.data).unwrap().nonce().to_u64().unwrap()
    }
}

pub fn parse_signed(p: &[u8]) -> Signed {
    let mut r = Reader::new(p);
    let slot = r.u8().unwrap();
    let key_index = r.u64().unwrap();
    let hash = r.arr().unwrap();
    let n = r.u16().unwrap() as usize;
    let data = r.take(n).unwrap().to_vec();
    r.end().unwrap();
    Signed { slot, key_index, hash, data }
}

pub struct Enrolled {
    pub chain: u64,
    pub safe: [u8; 20],
    pub start: u64,
    pub height: u8,
    pub root: [u8; 24],
    pub sig: Vec<u8>,
}

pub fn parse_enrolled(p: &[u8]) -> Enrolled {
    let mut r = Reader::new(p);
    let e = Enrolled { chain: r.u64().unwrap(), safe: r.arr().unwrap(), start: r.u64().unwrap(), height: r.u8().unwrap(), root: r.arr().unwrap(), sig: r.take(leansphincs::SIG_BYTES).unwrap().to_vec() };
    r.end().unwrap();
    e
}

pub struct Identity {
    pub member_key: [u8; 32],
    pub owner: [u8; 20],
    pub how: u8,
}

pub fn parse_identity(p: &[u8]) -> Identity {
    let mut r = Reader::new(p);
    let i = Identity { member_key: r.arr().unwrap(), owner: r.arr().unwrap(), how: r.u8().unwrap() };
    r.end().unwrap();
    i
}

/// (code, text) of an ERROR answer.
pub fn parse_error(p: &[u8]) -> (u8, String) {
    let mut r = Reader::new(p);
    let code = r.u8().unwrap();
    let n = r.u8().unwrap() as usize;
    (code, String::from_utf8(r.take(n).unwrap().to_vec()).unwrap())
}

// --- driving the board ---

pub fn request(b: &mut TestBoard, t: u8, id: u16, payload: &[u8]) {
    let bytes = proto::encode(t, id, payload);
    let mut d = Deframer::new();
    d.push(&bytes);
    let f = d.next_frame().unwrap();
    b.frame(&f);
}

/// The answer to request `id`, if sent.
pub fn answer(b: &TestBoard, id: u16) -> Option<&Frame> {
    b.platform.sent.iter().find(|f| f.id == id)
}

pub fn press(b: &mut TestBoard, bs: &[Button]) {
    for &x in bs {
        b.button(x);
    }
}

pub fn title(b: &TestBoard) -> String {
    b.screen().title.clone()
}

pub fn text(b: &TestBoard) -> Vec<String> {
    b.screen().text()
}

pub fn enter_pin(b: &mut TestBoard, pin: &[u8]) {
    for &d in pin {
        for _ in 0..d {
            b.button(Button::Right);
        }
        b.button(Button::Both);
    }
    // from 0, one step left wraps to "done"
    b.button(Button::Left);
    assert!(matches!(&b.screen().body, Body::Big { value, .. } if value.ends_with("[OK]")), "{:?}", text(b));
    b.button(Button::Both);
}

/// Runs a whole setup through the screens; returns the 24 words read off them.
pub fn setup(b: &mut TestBoard, id: u16, app_random: [u8; 32], pin: &[u8]) -> Vec<String> {
    request(b, ty::SETUP, id, &app_random);
    assert_eq!(title(b), "New board");
    b.button(Button::Right);
    let mut words = Vec::new();
    for _ in 0..6 {
        assert_eq!(title(b), "Your words");
        let Body::Lines(ls) = &b.screen().body else { panic!() };
        for l in ls {
            words.push(l.split_whitespace().nth(1).unwrap().to_string());
        }
        b.button(Button::Right);
    }
    assert_eq!(title(b), "All written?");
    b.button(Button::Both);
    for _ in 0..3 {
        pick_check_word(b, &words);
    }
    assert_eq!(title(b), "Choose a PIN");
    b.button(Button::Right);
    enter_pin(b, pin);
    assert_eq!(title(b), "PIN again");
    enter_pin(b, pin);
    assert_eq!(title(b), "Owner address");
    words
}

pub fn pick_check_word(b: &mut TestBoard, words: &[String]) {
    let t = title(b);
    let pos: usize = t.trim_start_matches("Word ").trim_end_matches('?').parse().unwrap();
    let Body::Choices { items, cursor } = &b.screen().body else { panic!("{t}") };
    assert_eq!(*cursor, 0);
    let want = items.iter().position(|w| *w == words[pos - 1]).expect("the right word is a choice");
    for _ in 0..want {
        b.button(Button::Right);
    }
    b.button(Button::Both);
}

/// Unlocks with the PIN: the board at its PIN screen.
pub fn unlock(b: &mut TestBoard, pin: &[u8]) {
    assert_eq!(title(b), "Enter PIN");
    enter_pin(b, pin);
    assert_eq!(title(b), "Winterlock", "{:?}", text(b));
}

/// Leaves the identity pages for home.
pub fn to_home(b: &mut TestBoard) {
    while title(b) != "Winterlock" {
        b.button(Button::Right);
    }
}

/// Types one word on the recovery wheel: steps to each letter and takes it.
pub fn type_word(b: &mut TestBoard, word: &str) {
    let list = phrase::wordlist();
    let mut prefix = String::new();
    loop {
        if b.screen().right == "both: ok" {
            let Body::Big { value, .. } = &b.screen().body else { panic!() };
            assert_eq!(value, word);
            b.button(Button::Both);
            return;
        }
        // the wheel: letters that continue some word, then the prefix as a word, then delete
        let cands: Vec<&str> = list.iter().copied().filter(|w| w.starts_with(&prefix)).collect();
        let mut letters: Vec<u8> = cands.iter().filter_map(|w| w.as_bytes().get(prefix.len()).copied()).collect();
        letters.dedup();
        let want = if prefix == word {
            letters.len() // the "=word" item
        } else {
            letters.iter().position(|&c| c == word.as_bytes()[prefix.len()]).unwrap()
        };
        for _ in 0..want {
            b.button(Button::Right);
        }
        b.button(Button::Both);
        if prefix != word {
            prefix.push(word.as_bytes()[prefix.len()] as char);
        }
    }
}

// --- requests ---

pub fn enrol_payload(chain: u64, safe: &[u8; 20], start: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(chain).bytes(safe).u64(start);
    w.0
}

pub fn sign_payload(chain: u64, safe: &[u8; 20], root: &[u8; 24], tx: &SafeTx, parent: Option<&SafeTx>) -> Vec<u8> {
    let t = proto::encode_tx(tx);
    let p = parent.map(proto::encode_tx).unwrap_or_default();
    let mut w = Writer::new();
    w.u64(chain).bytes(safe).bytes(root).u16(t.len() as u16).bytes(&t).u16(p.len() as u16).bytes(&p);
    w.0
}

/// Confirms what the board shows: steps through the pages, holds both on the last, and again if
/// it asks a second time.
pub fn confirm(b: &mut TestBoard) {
    let mut guard = 0;
    while b.screen().right != "hold both: sign" && b.screen().right != "hold both: enrol" {
        b.button(Button::Right);
        guard += 1;
        assert!(guard < 20, "no confirmation page: {:?}", text(b));
    }
    b.button(Button::Both);
    if title(b) == "Not decoded" {
        b.button(Button::Both);
    }
}
