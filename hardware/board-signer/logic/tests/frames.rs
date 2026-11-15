//! The link's frames against the Python client's (tools/frame_vectors.py writes
//! tests/vectors/frames.json from board_client.py): the CRCs, every frame byte for byte, the
//! request payloads the client builds as the board parses them, and the frames the client's reader
//! finds in a noisy stream. The app's TypeScript client checks the same file (app/test).

use serde_json::Value;
use winterlock_board::crc::{crc16, crc32};
use winterlock_board::proto::{self, Deframer, Request};
use winterlock_core::hex;

const VECTORS: &str = include_str!("vectors/frames.json");

fn b(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn frames_match_the_python_client() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    for c in v["crc"].as_array().unwrap() {
        let d = b(&c["data"]);
        assert_eq!(crc16(&d) as u64, c["crc16"].as_u64().unwrap());
        assert_eq!(crc32(&d) as u64, c["crc32"].as_u64().unwrap());
    }
    for f in v["frames"].as_array().unwrap() {
        let enc = proto::encode(f["type"].as_u64().unwrap() as u8, f["id"].as_u64().unwrap() as u16, &b(&f["payload"]));
        assert_eq!(enc, b(&f["frame"]));
    }
    // the requests the Python client builds parse on the board as what was asked
    for r in v["requests"].as_array().unwrap() {
        let mut d = Deframer::new();
        d.push(&b(&r["frame"]));
        let f = d.next_frame().expect("a whole frame");
        let req = proto::parse_request(f.ty, &f.payload).expect("the board parses it");
        let args = &r["args"];
        match (r["name"].as_str().unwrap(), req) {
            ("setup", Request::Setup { app_random }) => assert_eq!(app_random.to_vec(), b(&args["appRandom"])),
            ("recover", Request::Recover) => {}
            ("enrol", Request::Enrol { chain, safe, start }) => {
                assert_eq!((chain, start), (args["chain"].as_u64().unwrap(), args["start"].as_u64().unwrap()));
                assert_eq!(safe.to_vec(), b(&args["safe"]));
            }
            ("sign", Request::Sign(s)) => {
                assert_eq!(s.chain, args["chain"].as_u64().unwrap());
                assert_eq!(s.root.to_vec(), b(&args["root"]));
                assert_eq!(proto::encode_tx(&s.tx), b(&args["tx"]));
                assert_eq!(s.parent.map(|p| proto::encode_tx(&p)).unwrap_or_default(), b(&args["parent"]));
            }
            (n, q) => panic!("{n} parsed as {q:?}"),
        }
    }
    // the noisy stream, in the same pieces: the same frames, the same bytes skipped
    let s = &v["stream"];
    let bytes = b(&s["bytes"]);
    let mut cuts: Vec<usize> = s["chunks"].as_array().unwrap().iter().map(|c| c.as_u64().unwrap() as usize).collect();
    cuts.push(bytes.len());
    let mut d = Deframer::new();
    let mut found = Vec::new();
    let mut last = 0;
    for c in cuts {
        d.push(&bytes[last..c]);
        last = c;
        while let Some(f) = d.next_frame() {
            found.push((f.ty as u64, f.id as u64, f.payload));
        }
    }
    let want: Vec<(u64, u64, Vec<u8>)> = s["frames"].as_array().unwrap().iter().map(|f| (f["type"].as_u64().unwrap(), f["id"].as_u64().unwrap(), b(&f["payload"]))).collect();
    assert_eq!(found, want);
    assert_eq!(d.skipped, b(&s["noise"]).len());
    assert_eq!(d.held(), s["held"].as_u64().unwrap() as usize);
}
