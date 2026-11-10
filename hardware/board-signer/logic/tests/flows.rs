//! Every flow of the board, natively, through its buttons and its USB messages: setup, unlock,
//! wrong PINs, enrolment, the kinds of transaction, the key log's limits, recovery, erase, and
//! the requests a board must refuse. The outputs are checked with the core's verifiers (the
//! contracts' rules); `vectors.rs` checks them against the Python signer byte for byte.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::*;
use winterlock_board::decode::TOKENS;
use winterlock_board::input::Button::{Both, Left, Right};
use winterlock_board::proto::{Code, ty};
use winterlock_board::store::Phase;
use winterlock_core::safe::{Operation, SafeTx};
use winterlock_core::{U256, derive, leansphincs, owner, phrase, safe, wots};

const CHAIN: u64 = 42161;
const SAFE: [u8; 20] = [0x5A; 20];
const PARENT: [u8; 20] = [0x7E; 20];
const BOB: [u8; 20] = [0xB0; 20];

fn ledger() -> Rc<RefCell<Ledger>> {
    Rc::new(RefCell::new(Ledger::default()))
}

fn eth(nonce: u64, wei: u64) -> SafeTx {
    SafeTx { to: BOB, value: U256::from_u64(wei), nonce: U256::from_u64(nonce), ..Default::default() }
}

fn usdc(nonce: u64, amount: u64) -> SafeTx {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(&BOB);
    data.extend_from_slice(&U256::from_u64(amount).0);
    SafeTx { to: TOKENS[0].address, data, nonce: U256::from_u64(nonce), ..Default::default() }
}

/// A set-up, unlocked board with one key tree for SAFE from nonce 0; returns it with the words.
fn ready_board(l: Rc<RefCell<Ledger>>) -> (TestBoard, Vec<String>, Identity, Enrolled) {
    let flash = Shared::new();
    let mut b = boot(flash, l);
    let words = setup(&mut b, 1, [9; 32], PIN);
    let id = parse_identity(&answer(&b, 1).unwrap().payload);
    to_home(&mut b);
    request(&mut b, ty::ENROL, 2, &enrol_payload(CHAIN, &SAFE, 0));
    confirm(&mut b);
    let e = parse_enrolled(&answer(&b, 2).expect("enrolled").payload);
    b.button(Right);
    (b, words, id, e)
}

fn sign(b: &mut TestBoard, id: u16, tx: &SafeTx, parent: Option<&SafeTx>) -> Result<Signed, (u8, String)> {
    request(b, ty::SIGN, id, &sign_payload(CHAIN, &SAFE, &[0; 24], tx, parent));
    if answer(b, id).is_none() {
        confirm(b);
    }
    let f = answer(b, id).expect("an answer").clone();
    if title(b) != "Winterlock" {
        b.button(Right);
    }
    match f.ty {
        ty::A_SIGNED => Ok(parse_signed(&f.payload)),
        ty::A_ERROR => Err(parse_error(&f.payload)),
        t => panic!("answer type {t:#x}"),
    }
}

/// What the owner contract checks: the signature verifies to the enrolled root, and its SafeTx
/// words hash to what the Safe asks about.
fn verify(e: &Enrolled, owner_addr: &[u8; 20], tx: &SafeTx, s: &Signed) {
    let sig = owner::parse_tx_signature_data(&s.data).expect("a transaction signature");
    assert_eq!((sig.slot, sig.device, sig.safe), (s.slot, 0, SAFE));
    assert_eq!(sig.words, tx.words());
    let h = safe::hash_of_words(CHAIN, &SAFE, &sig.words);
    assert_eq!(h, tx.hash(CHAIN, &SAFE));
    assert_eq!(h, s.hash);
    let nonce = tx.nonce.to_u64().unwrap();
    assert_eq!(owner::key_index(nonce, e.start, s.slot, e.height as u32), Ok(s.key_index));
    let seed = owner::tree_seed(CHAIN, owner_addr, &SAFE, 0, 0, e.start);
    assert_eq!(wots::verify_root(&seed, s.key_index, &h, sig.wots_sig, sig.path), Some(e.root));
}

#[test]
fn setup_gives_the_identity_of_its_words() {
    let l = ledger();
    let (mut b, words, id, e) = ready_board(l.clone());
    // the words shown are the seed's, and the member key and owner are the core's for that seed
    let text = words.join(" ");
    let seed = phrase::to_seed(&text).expect("24 words with a good checksum");
    let key = derive::member_key(&seed).unwrap();
    assert_eq!(key.public_key(), id.member_key);
    assert_eq!(owner::owner_address(&id.member_key).unwrap(), id.owner);
    assert_eq!(id.how, 0);
    // the seed came from both sides' randomness, under the board's label
    let mut board_random = [0u8; 32];
    TestPlatform::new(Shared::new(), ledger()).random_first(&mut board_random);
    assert_eq!(seed, winterlock_board::keys::mix_seed(&board_random, &[9; 32]));
    // the certificate verifies under the member key, for this Safe, chain and start
    let digest = owner::certificate_digest(CHAIN, &id.owner, &SAFE, 0, 0, &e.root, 10, 0);
    assert!(leansphincs::verify(&id.member_key, &digest, &e.sig));
    assert_eq!((e.chain, e.safe, e.start, e.height), (CHAIN, SAFE, 0, 10));
    // the gas key is the core's
    request(&mut b, ty::GAS_KEY, 3, &[]);
    assert_eq!(answer(&b, 3).unwrap().payload, derive::gas_key(&seed).unwrap());
    assert_eq!(l.borrow().certificates, 1);
}

#[test]
fn transactions_of_each_kind() {
    let l = ledger();
    let (mut b, _, id, e) = ready_board(l.clone());

    // ETH: three pages and a confirmation
    let t = eth(0, 1_500_000_000_000_000_000);
    request(&mut b, ty::SIGN, 10, &sign_payload(CHAIN, &SAFE, &[0; 24], &t, None));
    assert_eq!(title(&b), "Send");
    assert!(text(&b).iter().any(|x| x.contains("1.5 ETH")), "{:?}", text(&b));
    confirm(&mut b);
    let s = parse_signed(&answer(&b, 10).unwrap().payload);
    assert_eq!((s.slot, s.key_index), (0, 0));
    verify(&e, &id.owner, &t, &s);
    b.button(Right);

    // a second, different transaction at nonce 0: the second key
    let t2 = usdc(0, 12_500_000);
    request(&mut b, ty::SIGN, 11, &sign_payload(CHAIN, &SAFE, &[0; 24], &t2, None));
    assert!(text(&b).iter().any(|x| x.contains("12.5 USDC")), "{:?}", text(&b));
    confirm(&mut b);
    let s2 = parse_signed(&answer(&b, 11).unwrap().payload);
    assert_eq!((s2.slot, s2.key_index), (1, 1));
    verify(&e, &id.owner, &t2, &s2);
    b.button(Right);

    // the first again: the same key and the same signature, no new record
    let again = sign(&mut b, 12, &t, None).unwrap();
    assert_eq!((again.slot, again.data.clone()), (0, s.data.clone()));

    // a third version at nonce 0: refused before anything is shown
    let (code, why) = sign(&mut b, 13, &eth(0, 7), None).unwrap_err();
    assert_eq!(code, Code::Refused as u8, "{why}");
    assert!(why.contains("both keys"), "{why}");

    // approveHash on a parent Safe, with the parent's fields: the parent's transfer is shown
    let parent = eth(3, 2_000_000_000_000_000_000);
    let ph = parent.hash(CHAIN, &PARENT);
    let mut data = vec![0xd4, 0xd9, 0xbd, 0xcd];
    data.extend_from_slice(&ph);
    let approve = SafeTx { to: PARENT, data, nonce: U256::from_u64(1), ..Default::default() };
    request(&mut b, ty::SIGN, 14, &sign_payload(CHAIN, &SAFE, &[0; 24], &approve, Some(&parent)));
    assert_eq!(title(&b), "Approve");
    b.button(Right);
    assert_eq!(title(&b), "Parent: Send");
    assert!(text(&b).iter().any(|x| x.contains("2 ETH")), "{:?}", text(&b));
    confirm(&mut b);
    let s3 = parse_signed(&answer(&b, 14).unwrap().payload);
    verify(&e, &id.owner, &approve, &s3);
    b.button(Right);

    // the parent's fields must hash to the argument
    let mut wrong = parent.clone();
    wrong.value = U256::from_u64(1);
    let (code, why) = sign(&mut b, 15, &approve, Some(&wrong)).unwrap_err();
    assert_eq!(code, Code::Refused as u8);
    assert!(why.contains("don't hash"), "{why}");

    // anything else: not decoded, and a second confirmation
    let raw = SafeTx { to: [0xCC; 20], data: vec![0x12, 0x34, 0x56, 0x78, 0, 1], value: U256::from_u64(5), nonce: U256::from_u64(2), ..Default::default() };
    request(&mut b, ty::SIGN, 16, &sign_payload(CHAIN, &SAFE, &[0; 24], &raw, None));
    assert_eq!(title(&b), "NOT DECODED");
    assert!(text(&b).iter().any(|x| x.contains("0x12345678")), "{:?}", text(&b));
    while b.screen().right != "hold both: sign" {
        b.button(Right);
    }
    b.button(Both);
    assert_eq!(title(&b), "Not decoded", "a second confirmation");
    assert!(answer(&b, 16).is_none(), "nothing signed after the first confirmation");
    b.button(Both);
    let s4 = parse_signed(&answer(&b, 16).unwrap().payload);
    verify(&e, &id.owner, &raw, &s4);
    b.button(Right);

    // the same, rejected at the second confirmation
    let raw2 = SafeTx { nonce: U256::from_u64(4), ..raw.clone() };
    request(&mut b, ty::SIGN, 17, &sign_payload(CHAIN, &SAFE, &[0; 24], &raw2, None));
    while b.screen().right != "hold both: sign" {
        b.button(Right);
    }
    press(&mut b, &[Both, Left]);
    assert_eq!(parse_error(&answer(&b, 17).unwrap().payload).0, Code::Rejected as u8);
    b.button(Right);

    // a delegate call: refused
    let dc = SafeTx { operation: Operation::DelegateCall, ..eth(5, 1) };
    let (code, why) = sign(&mut b, 18, &dc, None).unwrap_err();
    assert_eq!(code, Code::Refused as u8);
    assert!(why.contains("delegate"), "{why}");

    // refund fields: shown, and a second confirmation
    let gas = SafeTx { gas_price: U256::from_u64(1_000_000_000), refund_receiver: [0xEE; 20], ..eth(6, 1) };
    request(&mut b, ty::SIGN, 19, &sign_payload(CHAIN, &SAFE, &[0; 24], &gas, None));
    let mut seen = false;
    while b.screen().right != "hold both: sign" {
        seen |= title(&b) == "Gas refund";
        b.button(Right);
    }
    assert!(seen, "the refund page");
    press(&mut b, &[Both]);
    assert_eq!(title(&b), "Not decoded");
    b.button(Both);
    verify(&e, &id.owner, &gas, &parse_signed(&answer(&b, 19).unwrap().payload));
    b.button(Right);

    // rejecting on the first page
    request(&mut b, ty::SIGN, 20, &sign_payload(CHAIN, &SAFE, &[0; 24], &eth(7, 1), None));
    b.button(Left);
    assert_eq!(parse_error(&answer(&b, 20).unwrap().payload).0, Code::Rejected as u8);
    b.button(Right);

    // a nonce outside the tree (512 nonces from 0)
    let (code, _) = sign(&mut b, 21, &eth(512, 1), None).unwrap_err();
    assert_eq!(code, Code::Refused as u8);
    // another Safe: no tree
    request(&mut b, ty::SIGN, 22, &sign_payload(CHAIN, &PARENT, &[0; 24], &eth(0, 1), None));
    let (code, why) = parse_error(&answer(&b, 22).unwrap().payload);
    assert_eq!(code, Code::Refused as u8);
    assert!(why.contains("enrol first"), "{why}");

    l.borrow().assert_no_reuse();
    assert_eq!(l.borrow().signatures, 6);
}

#[test]
fn restart_locks_and_wrong_pins_erase() {
    let l = ledger();
    let (b, words, id, e) = ready_board(l.clone());
    let flash = b.platform.flash.clone();
    drop(b);
    // a restart: locked until the PIN, which is counted before it is checked
    let mut b = boot(flash.clone(), l.clone());
    assert_eq!(title(&b), "Enter PIN");
    request(&mut b, ty::SIGN, 5, &sign_payload(CHAIN, &SAFE, &[0; 24], &eth(0, 1), None));
    assert_eq!(parse_error(&answer(&b, 5).unwrap().payload).0, Code::Locked as u8);
    enter_pin(&mut b, &[1, 1, 1, 1]);
    assert_eq!(title(&b), "Wrong PIN");
    b.button(Right);
    // a restart keeps the count
    drop(b);
    let mut b = boot(flash.clone(), l.clone());
    assert!(text(&b).iter().any(|x| x.contains("2 tries left")), "{:?}", text(&b));
    // a right PIN resets it
    unlock(&mut b, PIN);
    assert_eq!(b.store.tries(), 0);
    let s = sign(&mut b, 6, &eth(0, 1), None).unwrap();
    verify(&e, &id.owner, &eth(0, 1), &s);
    drop(b);
    // three wrong in a row erase the seed and the key log
    let mut b = boot(flash.clone(), l.clone());
    for i in 0..3 {
        enter_pin(&mut b, &[9, 9, 9, 9, 9]);
        if i < 2 {
            assert_eq!(title(&b), "Wrong PIN");
            b.button(Right);
        }
    }
    assert_eq!(title(&b), "Erased");
    assert_eq!(b.store.phase(), Phase::Blank);
    let seed = phrase::to_seed(&words.join(" ")).unwrap();
    let mem = flash.0.borrow().mem.clone();
    assert!(!mem.windows(32).any(|w| w == seed), "the seed is gone from the flash");
    assert!(!mem.windows(24).any(|w| w == e.root), "the key log is gone");
    request(&mut b, ty::GAS_KEY, 7, &[]);
    assert_eq!(parse_error(&answer(&b, 7).unwrap().payload).0, Code::NotSetUp as u8);
    l.borrow().assert_no_reuse();
}

#[test]
fn recovery_from_the_words() {
    let l = ledger();
    let (b, words, id, _) = ready_board(l.clone());
    drop(b);
    // a new board, recovered letter by letter
    let mut b = boot(Shared::new(), l.clone());
    request(&mut b, ty::RECOVER, 1, &[]);
    assert_eq!(title(&b), "Recover");
    b.button(Right);
    for (i, w) in words.iter().enumerate() {
        assert_eq!(title(&b), format!("Word {}", i + 1));
        type_word(&mut b, w);
    }
    assert_eq!(title(&b), "Choose a PIN", "{:?}", text(&b));
    b.button(Right);
    enter_pin(&mut b, &[4, 4, 4, 4]);
    enter_pin(&mut b, &[4, 4, 4, 4]);
    let rid = parse_identity(&answer(&b, 1).unwrap().payload);
    assert_eq!((rid.member_key, rid.owner, rid.how), (id.member_key, id.owner, 1));
    b.button(Right);
    assert_eq!(title(&b), "Recovered");
    b.button(Right);
    // no key trees: it must enrol before it signs
    let (code, why) = sign(&mut b, 2, &eth(5, 1), None).unwrap_err();
    assert_eq!(code, Code::Refused as u8);
    assert!(why.contains("enrol first"), "{why}");
    request(&mut b, ty::ENROL, 3, &enrol_payload(CHAIN, &SAFE, 5));
    confirm(&mut b);
    let e = parse_enrolled(&answer(&b, 3).unwrap().payload);
    b.button(Right);
    let s = sign(&mut b, 4, &eth(5, 1), None).unwrap();
    verify(&e, &id.owner, &eth(5, 1), &s);
    // a start must grow per Safe
    request(&mut b, ty::ENROL, 5, &enrol_payload(CHAIN, &SAFE, 5));
    assert_eq!(parse_error(&answer(&b, 5).unwrap().payload).0, Code::Refused as u8);
    l.borrow().assert_no_reuse();
}

#[test]
fn recovery_names_a_bad_checksum_and_fixes_a_word() {
    let l = ledger();
    let seed = [0x42u8; 32];
    let words: Vec<String> = phrase::to_phrase(&seed).iter().map(|w| w.to_string()).collect();
    let mut b = boot(Shared::new(), l);
    request(&mut b, ty::RECOVER, 1, &[]);
    b.button(Right);
    // word 3 typed wrong
    let mut typed = words.clone();
    typed[2] = if words[2] == "zoo" { "abandon".into() } else { "zoo".into() };
    for w in &typed {
        type_word(&mut b, w);
    }
    assert_eq!(title(&b), "Checksum wrong");
    b.button(Right);
    assert_eq!(title(&b), "Fix a word");
    press(&mut b, &[Right, Right, Both]);
    assert_eq!(title(&b), "Word 3");
    type_word(&mut b, &words[2]);
    assert_eq!(title(&b), "Choose a PIN");
}

#[test]
fn setup_check_asks_again_after_a_wrong_word() {
    let l = ledger();
    let mut b = boot(Shared::new(), l);
    request(&mut b, ty::SETUP, 1, &[1; 32]);
    b.button(Right);
    let mut words = Vec::new();
    for _ in 0..6 {
        let winterlock_board::ui::Body::Lines(ls) = &b.screen().body else { panic!() };
        words.extend(ls.iter().map(|l| l.split_whitespace().nth(1).unwrap().to_string()));
        b.button(Right);
    }
    b.button(Both);
    // pick a wrong word
    let t = title(&b);
    let pos: usize = t.trim_start_matches("Word ").trim_end_matches('?').parse().unwrap();
    let winterlock_board::ui::Body::Choices { items, .. } = &b.screen().body else { panic!() };
    let wrong = items.iter().position(|w| *w != words[pos - 1]).unwrap();
    for _ in 0..wrong {
        b.button(Right);
    }
    b.button(Both);
    assert_eq!(title(&b), "Not that one");
    b.button(Right);
    // the words again, then a new check
    for _ in 0..6 {
        assert_eq!(title(&b), "Your words");
        b.button(Right);
    }
    b.button(Both);
    for _ in 0..3 {
        pick_check_word(&mut b, &words);
    }
    assert_eq!(title(&b), "Choose a PIN");
    // the PINs must match
    b.button(Right);
    enter_pin(&mut b, &[1, 2, 3, 4]);
    enter_pin(&mut b, &[1, 2, 3, 5]);
    assert_eq!(title(&b), "PINs differ");
    assert!(answer(&b, 1).is_none());
}

#[test]
fn erase_from_the_menu() {
    let l = ledger();
    let (mut b, _, id, _) = ready_board(l);
    b.button(Right); // the menu
    assert_eq!(title(&b), "Menu");
    b.button(Both); // owner address
    assert_eq!(title(&b), "Owner address");
    let hex = winterlock_core::hex::checksum(&id.owner);
    assert_eq!(text(&b)[1..4].concat().replace(' ', ""), hex);
    b.button(Left);
    press(&mut b, &[Right, Both]);
    assert_eq!(title(&b), "Key tree");
    assert!(text(&b).iter().any(|x| x.contains("nonces 0-511")), "{:?}", text(&b));
    press(&mut b, &[Left, Right, Both]);
    assert_eq!(title(&b), "Erase board?");
    b.button(Left);
    assert_eq!(title(&b), "Menu");
    b.button(Both);
    b.button(Both);
    assert_eq!(title(&b), "Erased");
    assert_eq!(b.store.phase(), Phase::Blank);
    // a blank board takes a new setup
    b.button(Right);
    let words = setup(&mut b, 9, [3; 32], PIN);
    assert_eq!(words.len(), 24);
}

#[test]
fn requests_a_board_refuses() {
    let l = ledger();
    let mut b = boot(Shared::new(), l.clone());
    // not set up
    for (t, p) in [(ty::GAS_KEY, vec![]), (ty::TREES, vec![]), (ty::ENROL, enrol_payload(1, &SAFE, 0))] {
        request(&mut b, t, 40 + t as u16, &p);
        assert_eq!(parse_error(&answer(&b, 40 + t as u16).unwrap().payload).0, Code::NotSetUp as u8);
    }
    // unknown type, bad payload, bad version
    request(&mut b, 0x55, 1, &[]);
    assert_eq!(parse_error(&answer(&b, 1).unwrap().payload).0, Code::UnknownType as u8);
    request(&mut b, ty::SETUP, 2, &[1, 2, 3]);
    assert_eq!(parse_error(&answer(&b, 2).unwrap().payload).0, Code::BadPayload as u8);
    // busy while a setup waits for the member, and cancelled by the app
    request(&mut b, ty::SETUP, 3, &[0; 32]);
    request(&mut b, ty::RECOVER, 4, &[]);
    assert_eq!(parse_error(&answer(&b, 4).unwrap().payload).0, Code::Busy as u8);
    request(&mut b, ty::STATUS, 5, &[]);
    assert_eq!(answer(&b, 5).unwrap().ty, ty::A_STATUS);
    request(&mut b, ty::CANCEL, 6, &[]);
    assert_eq!(parse_error(&answer(&b, 3).unwrap().payload).0, Code::Cancelled as u8);
    assert_eq!(answer(&b, 6).unwrap().ty, ty::A_DONE);
    assert_eq!(title(&b), "Winterlock");
    // set up: a second setup is refused
    let (mut b, _, _, _) = ready_board(l);
    request(&mut b, ty::SETUP, 50, &[0; 32]);
    assert_eq!(parse_error(&answer(&b, 50).unwrap().payload).0, Code::AlreadySetUp as u8);
    request(&mut b, ty::TREES, 51, &[]);
    assert_eq!(answer(&b, 51).unwrap().ty, ty::A_TREES);
    // the booted event came first, with id 0
    assert_eq!(b.platform.sent[0].ty, ty::EV_BOOTED);
}

#[test]
fn both_cores_give_the_same_bytes() {
    // the member key and a tree made with the jobs on two threads, as two cores
    let l = ledger();
    let flash = Shared::new();
    let mut b = boot(flash, l.clone());
    b.platform.threads = true;
    let words = setup(&mut b, 1, [9; 32], PIN);
    let id = parse_identity(&answer(&b, 1).unwrap().payload);
    let seed = phrase::to_seed(&words.join(" ")).unwrap();
    assert_eq!(derive::member_key(&seed).unwrap().public_key(), id.member_key);
    to_home(&mut b);
    request(&mut b, ty::ENROL, 2, &enrol_payload(CHAIN, &SAFE, 0));
    confirm(&mut b);
    let e = parse_enrolled(&answer(&b, 2).unwrap().payload);
    // the certificate is the one the core makes on one core
    let key = derive::member_key(&seed).unwrap();
    let digest = owner::certificate_digest(CHAIN, &id.owner, &SAFE, 0, 0, &e.root, 10, 0);
    assert_eq!(e.sig, key.sign(&digest));
}

impl TestPlatform {
    /// The bytes `random` gives first on a fresh platform: the board's half of the seed.
    fn random_first(&mut self, out: &mut [u8]) {
        use winterlock_board::Platform;
        self.random(out);
    }
}
