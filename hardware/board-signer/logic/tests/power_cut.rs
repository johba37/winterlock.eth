//! Power cuts at every flash write and erase of every flow that writes: setup, unlock and a
//! signature, an enrolment, the third wrong PIN, an erase from the menu. Each flow runs once to
//! count its flash operations, then once per operation with the power cut during it (that write
//! or erase left torn), and the board starts again from the bytes left behind.
//!
//! What must hold after every cut:
//! - no one-time key ever signs two hashes, across the cut and what follows it (the ledger of
//!   every signature that left a board in the test)
//! - no signature or certificate leaves before what it depends on is durable (checked by the
//!   test platform at the moment each one leaves, by opening a copy of the flash as it is then)
//! - the board comes back set up as it was, or blank with the seed gone from the flash; never
//!   half set up, never with fewer wrong PINs counted, never damaged

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::*;
use winterlock_board::input::Button::{Both, Right};
use winterlock_board::proto::ty;
use winterlock_board::sim::SimFlash;
use winterlock_board::store::Phase;
use winterlock_core::safe::SafeTx;
use winterlock_core::{U256, phrase};

const CHAIN: u64 = 11155111;
const SAFE: [u8; 20] = [0x5A; 20];

fn tx(nonce: u64, wei: u64) -> SafeTx {
    SafeTx { to: [0xB0; 20], value: U256::from_u64(wei), nonce: U256::from_u64(nonce), ..Default::default() }
}

fn alive(b: &TestBoard) -> bool {
    !b.platform.flash.0.borrow().off
}

/// Boots on a copy of `base` with the power cut during operation `cut` (None: no cut).
fn boot_cut(base: &SimFlash, cut: Option<(u64, u64)>, ledger: Rc<RefCell<Ledger>>) -> Option<TestBoard> {
    let mut f = base.reboot();
    if let Some((n, pattern)) = cut {
        f.cut_after(n, n.wrapping_mul(7919) + 1 + pattern * 104_729);
    }
    let shared = Shared::from(f);
    Board::new(shared.clone(), TestPlatform::new(shared, ledger), "test").ok()
}

use winterlock_board::Board;

/// Runs `flow` with no cut and returns how many flash operations it did; then with a cut at each
/// of them (`patterns` torn states each), calls `after` with the board started again.
fn sweep(name: &str, base: &SimFlash, flow: impl Fn(&mut TestBoard), after: impl FnMut(&mut TestBoard, u64, Before)) -> u64 {
    sweep_n(name, base, 1, flow, after)
}

fn sweep_n(name: &str, base: &SimFlash, patterns: u64, flow: impl Fn(&mut TestBoard), mut after: impl FnMut(&mut TestBoard, u64, Before)) -> u64 {
    let l = Rc::new(RefCell::new(Ledger::default()));
    let mut b = boot_cut(base, None, l.clone()).unwrap();
    flow(&mut b);
    let total = b.platform.flash.0.borrow().ops;
    assert!(total > 0, "{name}: the flow writes");
    for (n, pattern) in (0..total).flat_map(|n| (0..patterns).map(move |p| (n, p))) {
        let l = Rc::new(RefCell::new(Ledger::default()));
        let mem = match boot_cut(base, Some((n, pattern)), l.clone()) {
            Some(mut b) => {
                flow(&mut b);
                assert!(!alive(&b), "{name}: the cut at {n} happened");
                b.platform.flash.snapshot()
            }
            None => {
                // the cut came while the store opened: start again from the same bytes
                let mut f = base.reboot();
                f.cut_after(n, n.wrapping_mul(7919) + 1 + pattern * 104_729);
                let shared = Shared::from(f);
                let _ = winterlock_board::store::Store::open(shared.clone());
                shared.snapshot()
            }
        };
        let shared = Shared::from(mem);
        let mut b = Board::new(shared.clone(), TestPlatform::new(shared, l.clone()), "test").expect("the board starts after a cut");
        assert!(!matches!(b.store.phase(), Phase::Damaged(_)), "{name}: damaged after a cut at {n}: {:?}", b.store.phase());
        let before = Before { signatures: l.borrow().signatures, certificates: l.borrow().certificates };
        after(&mut b, n, before);
        l.borrow().assert_no_reuse();
    }
    total
}

/// What left the board before the cut.
#[derive(Clone, Copy)]
struct Before {
    signatures: usize,
    certificates: usize,
}

/// A set-up board's flash: (flash, words, owner), with one tree for SAFE from nonce 0 if `tree`.
fn ready_flash(tree: bool) -> (SimFlash, Vec<String>) {
    let l = Rc::new(RefCell::new(Ledger::default()));
    let mut b = boot(Shared::new(), l);
    let words = setup(&mut b, 1, [5; 32], PIN);
    to_home(&mut b);
    if tree {
        request(&mut b, ty::ENROL, 2, &enrol_payload(CHAIN, &SAFE, 0));
        confirm(&mut b);
        assert!(answer(&b, 2).is_some_and(|f| f.ty == ty::A_ENROLLED));
    }
    (b.platform.flash.snapshot(), words)
}

fn seed_of(words: &[String]) -> [u8; 32] {
    phrase::to_seed(&words.join(" ")).unwrap()
}

#[test]
fn setup_survives_a_cut_anywhere() {
    let base = SimFlash::new(SECTORS);
    // the identity a whole setup gives (the platform's randomness is the same every run)
    let (full, words) = {
        let l = Rc::new(RefCell::new(Ledger::default()));
        let mut b = boot(Shared::from(base.reboot()), l);
        let w = setup(&mut b, 1, [5; 32], PIN);
        (b.store.identity().copied().unwrap(), w)
    };
    let seed = seed_of(&words);
    let flow = |b: &mut TestBoard| {
        request(b, ty::SETUP, 1, &[5; 32]);
        b.button(Right);
        let mut ws = Vec::new();
        for _ in 0..6 {
            let winterlock_board::ui::Body::Lines(ls) = &b.screen().body else { return };
            ws.extend(ls.iter().map(|l| l.split_whitespace().nth(1).unwrap().to_string()));
            b.button(Right);
        }
        b.button(Both);
        for _ in 0..3 {
            pick_check_word(b, &ws);
        }
        b.button(Right);
        enter_pin(b, PIN);
        // the last step writes: the seed, the member key, the PIN, READY
        for &d in PIN {
            for _ in 0..d {
                b.button(Right);
            }
            b.button(Both);
        }
        b.button(winterlock_board::input::Button::Left);
        b.button(Both);
    };
    let (mut ready, mut blank) = (0, 0);
    let ops = sweep("setup", &base, flow, |b, n, _| match b.store.phase() {
        Phase::Ready => {
            assert_eq!(b.store.identity().copied(), Some(full), "cut at {n}: set up as a whole setup would");
            unlock(b, PIN);
            ready += 1;
        }
        Phase::Blank => {
            let mem = b.platform.flash.0.borrow().mem.clone();
            assert!(!mem.windows(32).any(|w| w == seed), "cut at {n}: blank, and the seed is gone");
            blank += 1;
        }
        p => panic!("cut at {n}: {p:?}"),
    });
    println!("setup: {ops} flash operations, a cut at each: {ready} came back set up, {blank} blank");
    assert!(ops >= 8);
}

#[test]
fn a_signature_never_reuses_a_key_or_leaves_early() {
    let (base, _) = ready_flash(true);
    let a = tx(3, 1);
    let b_tx = tx(3, 2);
    let flow = |b: &mut TestBoard| {
        enter_pin(b, PIN);
        if !alive(b) {
            return;
        }
        request(b, ty::SIGN, 7, &sign_payload(CHAIN, &SAFE, &[0; 24], &a, None));
        confirm(b);
    };
    let ops = sweep_n("sign", &base, 32, flow, |b, n, ledger| {
        // the board still unlocks: the cut never counted a wrong PIN, nor lost one
        assert!(b.store.tries() <= 1, "cut at {n}: {} tries", b.store.tries());
        unlock(b, PIN);
        let a_left = ledger.signatures == 1;
        // another transaction at the same nonce: the other key if A's use is durable
        request(b, ty::SIGN, 8, &sign_payload(CHAIN, &SAFE, &[0; 24], &b_tx, None));
        confirm(b);
        let s = parse_signed(&answer(b, 8).expect("signed").payload);
        let a_recorded = b.store.trees()[0].used_keys() == 2;
        assert!(!a_left || a_recorded, "cut at {n}: A left, so its use is in the log");
        assert_eq!(s.slot, if a_recorded { 1 } else { 0 }, "cut at {n}");
        b.button(Right);
        // A again: the key that signed it before, or a fresh one
        request(b, ty::SIGN, 9, &sign_payload(CHAIN, &SAFE, &[0; 24], &a, None));
        confirm(b);
        let f = answer(b, 9).expect("an answer");
        if f.ty == ty::A_SIGNED {
            assert_ne!(parse_signed(&f.payload).key_index, s.key_index, "cut at {n}");
        }
    });
    println!("unlock and sign: {ops} flash operations, a cut at each, 32 torn patterns each");
}

#[test]
fn an_enrolment_survives_a_cut_anywhere() {
    let (base, _) = ready_flash(false);
    let flow = |b: &mut TestBoard| {
        b.platform.threads = true;
        enter_pin(b, PIN);
        if !alive(b) {
            return;
        }
        request(b, ty::ENROL, 3, &enrol_payload(CHAIN, &SAFE, 0));
        confirm(b);
    };
    let ops = sweep("enrol", &base, flow, |b, n, ledger| {
        b.platform.threads = true;
        unlock(b, PIN);
        let trees = b.store.trees().len();
        assert!(trees <= 1, "cut at {n}");
        if ledger.certificates == 1 {
            assert!(b.store.trees()[0].certified, "cut at {n}: the certificate left, so its record is durable");
        }
        // the app enrols again, after the tree it may already have
        let start = if trees == 1 { 1 } else { 0 };
        request(b, ty::ENROL, 4, &enrol_payload(CHAIN, &SAFE, start));
        confirm(b);
        assert_eq!(answer(b, 4).unwrap().ty, ty::A_ENROLLED, "cut at {n}");
        b.button(Right);
        let s = parse_signed(&{
            request(b, ty::SIGN, 5, &sign_payload(CHAIN, &SAFE, &[0; 24], &tx(start, 1), None));
            confirm(b);
            answer(b, 5).unwrap().payload.clone()
        });
        assert_eq!(s.key_index, 0);
    });
    println!("enrol: {ops} flash operations, a cut at each");
}

#[test]
fn the_third_wrong_pin_erases_even_if_cut() {
    let (base, words) = ready_flash(true);
    // two wrong PINs, counted
    let base = {
        let l = Rc::new(RefCell::new(Ledger::default()));
        let mut b = boot(Shared::from(base.reboot()), l);
        for _ in 0..2 {
            enter_pin(&mut b, &[7, 7, 7, 7]);
            b.button(Right);
        }
        assert_eq!(b.store.tries(), 2);
        b.platform.flash.snapshot()
    };
    let seed = seed_of(&words);
    let flow = |b: &mut TestBoard| enter_pin(b, &[7, 7, 7, 7]);
    let ops = sweep_n("third wrong PIN", &base, 8, flow, |b, n, _| match b.store.phase() {
        Phase::Ready => {
            // the try wasn't counted, so it was never checked
            assert_eq!(b.store.tries(), 2, "cut at {n}");
            enter_pin(b, &[7, 7, 7, 7]);
            assert_eq!(b.store.phase(), Phase::Blank, "cut at {n}");
        }
        Phase::Blank => {
            let mem = b.platform.flash.0.borrow().mem.clone();
            assert!(!mem.windows(32).any(|w| w == seed), "cut at {n}: the seed is gone");
        }
        p => panic!("cut at {n}: {p:?}"),
    });
    println!("third wrong PIN: {ops} flash operations, a cut at each, 8 torn patterns each");
}

#[test]
fn an_erase_finishes_or_never_started() {
    let (base, words) = ready_flash(true);
    // a few key uses to lose or keep whole
    let base = {
        let l = Rc::new(RefCell::new(Ledger::default()));
        let mut b = boot(Shared::from(base.reboot()), l);
        unlock(&mut b, PIN);
        for (i, n) in [0u64, 0, 1].iter().enumerate() {
            request(&mut b, ty::SIGN, 10 + i as u16, &sign_payload(CHAIN, &SAFE, &[0; 24], &tx(*n, i as u64 + 1), None));
            confirm(&mut b);
            b.button(Right);
        }
        assert_eq!(b.store.trees()[0].used_keys(), 3);
        b.platform.flash.snapshot()
    };
    let seed = seed_of(&words);
    let flow = |b: &mut TestBoard| {
        enter_pin(b, PIN);
        if !alive(b) {
            return;
        }
        // menu, erase, confirm
        b.button(Right);
        b.button(Right);
        b.button(Right);
        b.button(Both);
        b.button(Both);
    };
    let ops = sweep_n("erase", &base, 8, flow, |b, n, _| match b.store.phase() {
        Phase::Ready => {
            assert_eq!(b.store.trees()[0].used_keys(), 3, "cut at {n}: not erased, and the key log whole");
        }
        Phase::Blank => {
            let mem = b.platform.flash.0.borrow().mem.clone();
            assert!(!mem.windows(32).any(|w| w == seed), "cut at {n}: the seed is gone");
        }
        p => panic!("cut at {n}: {p:?}"),
    });
    println!("erase: {ops} flash operations, a cut at each, 8 torn patterns each");
}

/// A write that seems to work but stores a bit wrong (a failing chip, no power cut): the read-back
/// catches it, nothing is signed, and the board carries on with the next record.
#[test]
fn a_write_that_does_not_stick_signs_nothing() {
    let (base, _) = ready_flash(true);
    let l = Rc::new(RefCell::new(Ledger::default()));
    let mut b = boot(Shared::from(base.reboot()), l.clone());
    unlock(&mut b, PIN);
    // the next write is the key use's header, the one after its body: spoil each in turn
    for (i, spoil) in [0u64, 1].iter().enumerate() {
        let ops = b.platform.flash.0.borrow().ops;
        b.platform.flash.0.borrow_mut().corrupt_at = Some(ops + spoil);
        let id = 20 + i as u16;
        request(&mut b, ty::SIGN, id, &sign_payload(CHAIN, &SAFE, &[0; 24], &tx(4, 1), None));
        confirm(&mut b);
        let f = answer(&b, id).unwrap();
        assert_eq!(f.ty, winterlock_board::proto::ty::A_ERROR, "write {spoil} spoiled: refused");
        assert_eq!(parse_error(&f.payload).0, winterlock_board::proto::Code::Storage as u8);
        b.button(Right);
        b.platform.flash.0.borrow_mut().corrupt_at = None;
    }
    assert_eq!(l.borrow().signatures, 0);
    // then a write that works
    request(&mut b, ty::SIGN, 30, &sign_payload(CHAIN, &SAFE, &[0; 24], &tx(4, 1), None));
    confirm(&mut b);
    assert_eq!(answer(&b, 30).unwrap().ty, ty::A_SIGNED);
    // and after a restart the spoiled records are skipped, the good one is there
    let snap = b.platform.flash.snapshot();
    let mut b = boot(Shared::from(snap), l.clone());
    unlock(&mut b, PIN);
    assert_eq!(b.store.trees()[0].used_keys(), 1);
    l.borrow().assert_no_reuse();
}
