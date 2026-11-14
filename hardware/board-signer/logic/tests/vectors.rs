//! The board's outputs against the Python signer's, byte for byte (tools/board_vectors.py writes
//! tests/vectors/board_flows.json): the board runs its real flows, through its buttons and its
//! USB messages, with its randomness set to the vectors' inputs.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::*;
use serde_json::Value;
use winterlock_board::input::Button::{Both, Left, Right};
use winterlock_board::proto::ty;
use winterlock_core::safe::{Operation, SafeTx};
use winterlock_core::{U256, hex};

const VECTORS: &str = include_str!("vectors/board_flows.json");

fn b(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn a<const N: usize>(v: &Value) -> [u8; N] {
    b(v).try_into().unwrap()
}

fn address(v: &Value) -> [u8; 20] {
    hex::parse_address(v.as_str().unwrap()).unwrap()
}

fn u256(v: &Value) -> U256 {
    U256::from_dec_str(v.as_str().unwrap()).unwrap()
}

fn tx(v: &Value) -> SafeTx {
    SafeTx {
        to: address(&v["to"]),
        value: u256(&v["value"]),
        data: b(&v["data"]),
        operation: Operation::from_u8(v["operation"].as_u64().unwrap() as u8).unwrap(),
        safe_tx_gas: u256(&v["safe_tx_gas"]),
        base_gas: u256(&v["base_gas"]),
        gas_price: u256(&v["gas_price"]),
        gas_token: address(&v["gas_token"]),
        refund_receiver: address(&v["refund_receiver"]),
        nonce: u256(&v["nonce"]),
    }
}

#[test]
fn the_board_matches_the_python_signer() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let ledger = Rc::new(RefCell::new(Ledger::default()));
    let mut bd = boot(Shared::new(), ledger.clone());
    let pin: Vec<u8> = v["pin"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();

    // setup: the board's randomness, then the app's
    bd.platform.queue.extend(b(&v["board_random"]));
    request(&mut bd, ty::SETUP, 1, &a::<32>(&v["app_random"]));
    bd.button(Right);
    let mut words = Vec::new();
    for _ in 0..6 {
        let winterlock_board::ui::Body::Lines(ls) = &bd.screen().body else { panic!() };
        words.extend(ls.iter().map(|l| l.split_whitespace().nth(1).unwrap().to_string()));
        bd.button(Right);
    }
    assert_eq!(words.join(" "), v["words"].as_str().unwrap(), "the words");
    bd.button(Both);
    for _ in 0..3 {
        pick_check_word(&mut bd, &words);
    }
    bd.button(Right);
    enter_pin(&mut bd, &pin);
    // the PIN's salt is drawn when the second PIN is done
    for &d in &pin {
        for _ in 0..d {
            bd.button(Right);
        }
        bd.button(Both);
    }
    bd.button(Left);
    bd.platform.queue.extend(b(&v["pin_salt"]));
    bd.button(Both);
    let id = parse_identity(&answer(&bd, 1).expect("the identity").payload);
    assert_eq!(id.member_key, a::<32>(&v["member_key"]), "the member key");
    assert_eq!(id.owner, address(&v["owner"]), "the owner address");
    let (salt, check) = *bd.store.pin().unwrap();
    assert_eq!((salt, check), (a::<32>(&v["pin_salt"]), a::<32>(&v["pin_check"])), "the PIN's check value");
    to_home(&mut bd);

    request(&mut bd, ty::GAS_KEY, 2, &[]);
    assert_eq!(answer(&bd, 2).unwrap().payload, b(&v["gas_key"]), "the gas key");

    // enrol, with the tree's salt from the vectors
    let chain = v["chain"].as_u64().unwrap();
    let safe = address(&v["safe"]);
    let start = v["start"].as_u64().unwrap();
    request(&mut bd, ty::ENROL, 3, &enrol_payload(chain, &safe, start));
    bd.platform.queue.extend(b(&v["tree_salt"]));
    confirm(&mut bd);
    let e = parse_enrolled(&answer(&bd, 3).expect("enrolled").payload);
    assert_eq!(e.root, a::<24>(&v["tree_root"]), "the tree's root");
    assert_eq!(hex::encode0x(&e.sig), v["certificate"].as_str().unwrap(), "the certificate's stateless signature");
    bd.button(Right);

    // the transactions, each confirmed on the board
    for (i, c) in v["transactions"].as_array().unwrap().iter().enumerate() {
        let t = tx(&c["tx"]);
        let parent = c["parent"].as_object().map(|_| tx(&c["parent"]));
        let rid = 10 + i as u16;
        request(&mut bd, ty::SIGN, rid, &sign_payload(chain, &safe, &[0; 24], &t, parent.as_ref()));
        confirm(&mut bd);
        let s = parse_signed(&answer(&bd, rid).expect("signed").payload);
        let name = c["name"].as_str().unwrap();
        assert_eq!(hex::encode0x(&s.hash), c["hash"].as_str().unwrap(), "{name}: the SafeTx hash");
        assert_eq!((s.slot as u64, s.key_index), (c["slot"].as_u64().unwrap(), c["key_index"].as_u64().unwrap()), "{name}: the key");
        assert_eq!(hex::encode0x(&s.data), c["data"].as_str().unwrap(), "{name}: the owner signature data");
        bd.button(Right);
    }
    assert_eq!(ledger.borrow().signatures, 4);
    ledger.borrow().assert_no_reuse();
}
