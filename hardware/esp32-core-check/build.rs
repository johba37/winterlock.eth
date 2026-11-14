//! Links the firmware (as esp-generate's template does) and turns the Python vectors the board
//! checks (core/tests/vectors/board.json and erc8499.json) into Rust data: small values inline,
//! signatures as files in OUT_DIR, included with include_bytes!.

use std::fmt::Write as _;
use std::path::PathBuf;

use serde_json::Value;

fn main() {
    linker_be_nice();
    check_xtensa_linker_available();
    // make sure linkall.x is the last linker script (otherwise might cause problems with flip-link)
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    vectors();
    erc8499();
}

#[cfg(unix)]
fn check_xtensa_linker_available() {
    println!("cargo:rerun-if-env-changed=PATH");

    let target = std::env::var("TARGET").unwrap_or_default();
    println!(
        "cargo:rerun-if-env-changed={}",
        cargo_linker_env_var(&target)
    );

    let linker = xtensa_linker(&target);

    let error = match std::process::Command::new(&linker)
        .arg("--version")
        .output()
    {
        Ok(_) => return,
        Err(error) => error,
    };

    let export_file = std::env::var("HOME")
        .map(|home| format!("{home}/export-esp.sh"))
        .unwrap_or_else(|_| "$HOME/export-esp.sh".to_string());

    panic!(
        "Xtensa linker `{linker}` was not found in PATH or could not be executed: {error}.\n\n\
         Xtensa targets on Unix require espup's environment export file to be sourced before building.\n\
         Try: `source {export_file}`\n\n\
         If the export file does not exist, run `espup install` first.\n\
         For more details, see:\n\
         https://github.com/esp-rs/espup?tab=readme-ov-file#environment-variables-setup"
    );
}

#[cfg(not(unix))]
fn check_xtensa_linker_available() {}

#[cfg(unix)]
fn xtensa_linker(target: &str) -> String {
    if let Some(linker) = cargo_configured_linker(target) {
        return linker;
    }

    target
        .strip_prefix("xtensa-")
        .and_then(|target| target.strip_suffix("-none-elf"))
        .map(|chip| format!("xtensa-{chip}-elf-gcc"))
        .unwrap_or_else(|| "xtensa-esp32-elf-gcc".to_string())
}

#[cfg(unix)]
fn cargo_configured_linker(target: &str) -> Option<String> {
    std::env::var(cargo_linker_env_var(target)).ok()
}

#[cfg(unix)]
fn cargo_linker_env_var(target: &str) -> String {
    let target = target.replace('-', "_").to_ascii_uppercase();
    format!("CARGO_TARGET_{target}_LINKER")
}

fn linker_be_nice() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let kind = &args[1];
        let what = &args[2];

        match kind.as_str() {
            "undefined-symbol" => match what.as_str() {
                what if what.starts_with("_defmt_") => {
                    eprintln!();
                    eprintln!(
                        "💡 `defmt` not found - make sure `defmt.x` is added as a linker script and you have included `use defmt_rtt as _;`"
                    );
                    eprintln!();
                }
                "_stack_start" => {
                    eprintln!();
                    eprintln!("💡 Is the linker script `linkall.x` missing?");
                    eprintln!();
                }
                what if what.starts_with("esp_rtos_") => {
                    eprintln!();
                    eprintln!(
                        "💡 `esp-radio` has no scheduler enabled. Make sure you have initialized `esp-rtos` or provided an external scheduler."
                    );
                    eprintln!();
                }
                "embedded_test_linker_file_not_added_to_rustflags" => {
                    eprintln!();
                    eprintln!(
                        "💡 `embedded-test` not found - make sure `embedded-test.x` is added as a linker script for tests"
                    );
                    eprintln!();
                }
                "free"
                | "malloc"
                | "calloc"
                | "get_free_internal_heap_size"
                | "malloc_internal"
                | "realloc_internal"
                | "calloc_internal"
                | "free_internal" => {
                    eprintln!();
                    eprintln!(
                        "💡 Did you forget the `esp-alloc` dependency or didn't enable the `compat` feature on it?"
                    );
                    eprintln!();
                }
                _ => (),
            },
            // we don't have anything helpful for "missing-lib" yet
            _ => {
                std::process::exit(1);
            }
        }

        std::process::exit(0);
    }

    println!(
        "cargo:rustc-link-arg=-Wl,--error-handling-script={}",
        std::env::current_exe().unwrap().display()
    );
}

const BOARD: &str = "../../core/tests/vectors/board.json";
const ERC8499: &str = "../../core/tests/vectors/erc8499.json";

struct Gen {
    out: String,
    dir: PathBuf,
    blobs: usize,
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

/// A decimal uint256 as its 32-byte big-endian word.
fn word(v: &Value) -> Vec<u8> {
    let mut w = [0u8; 32];
    for c in v.as_str().expect("decimal").bytes() {
        let mut carry = (c - b'0') as u32;
        for b in w.iter_mut().rev() {
            let x = *b as u32 * 10 + carry;
            *b = x as u8;
            carry = x >> 8;
        }
        assert_eq!(carry, 0, "uint256 overflow");
    }
    w.to_vec()
}

fn u(v: &Value) -> u64 {
    v.as_u64().expect("integer")
}

impl Gen {
    fn arr(&self, b: &[u8]) -> String {
        let mut s = String::from("[");
        for x in b {
            write!(s, "{x},").unwrap();
        }
        s.push(']');
        s
    }

    /// A byte slice in a file of its own.
    fn blob(&mut self, b: &[u8]) -> String {
        self.blobs += 1;
        let path = self.dir.join(format!("blob{}.bin", self.blobs));
        std::fs::write(&path, b).unwrap();
        format!("include_bytes!({:?})", path.display().to_string())
    }

    fn tx(&mut self, t: &Value) -> String {
        format!(
            "Tx {{ to: {}, value: {}, data: {}, operation: {}, safe_tx_gas: {}, base_gas: {}, gas_price: {}, gas_token: {}, refund_receiver: {}, nonce: {} }}",
            self.arr(&unhex(&t["to"])),
            self.arr(&word(&t["value"])),
            self.blob(&unhex(&t["data"])),
            u(&t["operation"]),
            self.arr(&word(&t["safe_tx_gas"])),
            self.arr(&word(&t["base_gas"])),
            self.arr(&word(&t["gas_price"])),
            self.arr(&unhex(&t["gas_token"])),
            self.arr(&unhex(&t["refund_receiver"])),
            self.arr(&word(&t["nonce"])),
        )
    }

    fn tree(&mut self, name: &str, t: &Value) {
        let p = &t["place"];
        let mut sigs = String::new();
        for s in t["signatures"].as_array().unwrap() {
            let tx = self.tx(&s["tx"]);
            write!(
                sigs,
                "WotsSig {{ nonce: {}, slot: {}, key_index: {}, tx: {tx}, hash: {}, sig: {}, path: {}, data: {} }},",
                u(&s["nonce"]),
                u(&s["slot"]),
                u(&s["key_index"]),
                self.arr(&unhex(&s["hash"])),
                self.blob(&unhex(&s["sig"])),
                self.blob(&unhex(&s["path"])),
                self.blob(&unhex(&s["data"])),
            )
            .unwrap();
        }
        writeln!(
            self.out,
            "pub static {name}: Tree = Tree {{ chain: {}, owner: {}, safe: {}, device: {}, generation: {}, start: {}, salt: {}, tree_seed: {}, sk_seed: {}, root: {}, sigs: &[{sigs}] }};",
            u(&p["chain"]),
            self.arr(&unhex(&p["owner"])),
            self.arr(&unhex(&p["safe"])),
            u(&p["device"]),
            u(&p["gen"]),
            u(&p["start"]),
            self.arr(&unhex(&p["salt"])),
            self.arr(&unhex(&t["tree_seed"])),
            self.arr(&unhex(&t["sk_seed"])),
            self.arr(&unhex(&t["root"])),
        )
        .unwrap();
    }
}

fn vectors() {
    println!("cargo:rerun-if-changed={BOARD}");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(BOARD).expect("board.json")).expect("JSON");
    let dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let mut g = Gen { out: String::new(), dir: dir.clone(), blobs: 0 };
    let o = &mut String::new();
    writeln!(o, "pub const PHRASE: &str = {:?};", v["phrase"].as_str().unwrap()).unwrap();
    for (name, key, n) in [("SEED", "seed", 32), ("MEMBER_KEY_SEED", "member_key_seed", 32), ("MEMBER_KEY", "member_key", 32), ("OWNER", "owner", 20)] {
        writeln!(o, "pub const {name}: [u8; {n}] = {};", g.arr(&unhex(&v[key]))).unwrap();
    }
    let mut st = String::new();
    for s in v["stateless"].as_array().unwrap() {
        write!(st, "Stateless {{ message: {}, sig: {}, grind_tries: {} }},", g.arr(&unhex(&s["message"])), g.blob(&unhex(&s["sig"])), u(&s["grind_tries"])).unwrap();
    }
    writeln!(o, "pub static STATELESS: &[Stateless] = &[{st}];").unwrap();
    let mut cases = String::new();
    for c in v["safetx"].as_array().unwrap() {
        let tx = g.tx(&c["tx"]);
        write!(cases, "SafeTxCase {{ tx: {tx}, chain: {}, safe: {}, hash: {} }},", u(&c["chain"]), g.arr(&unhex(&c["safe"])), g.arr(&unhex(&c["hash"]))).unwrap();
    }
    writeln!(o, "pub static SAFETX: &[SafeTxCase] = &[{cases}];").unwrap();
    let d = &v["device_digest"];
    writeln!(
        o,
        "pub static DEVICE_DIGEST: DeviceDigest = DeviceDigest {{ chain: {}, owner: {}, device: {}, generation: {}, key: {}, digest: {} }};",
        u(&d["chain"]),
        g.arr(&unhex(&d["owner"])),
        u(&d["device"]),
        u(&d["generation"]),
        g.arr(&unhex(&d["key"])),
        g.arr(&unhex(&d["device_digest"]))
    )
    .unwrap();
    let c = &v["check_code"];
    writeln!(
        o,
        "pub static CHECK_CODE: CheckCode = CheckCode {{ owner: {}, device: {}, key: {}, code: {:?} }};",
        g.arr(&unhex(&c["owner"])),
        u(&c["device"]),
        g.arr(&unhex(&c["key"])),
        c["code"].as_str().unwrap()
    )
    .unwrap();
    let kl = &v["keylog"];
    let mut trees = String::new();
    for t in kl["trees"].as_array().unwrap() {
        write!(trees, "KeylogTree {{ chain: {}, safe: {}, root: {}, start: {}, height: {} }},", u(&t["chain"]), g.arr(&unhex(&t["safe"])), g.arr(&unhex(&t["root"])), u(&t["start"]), u(&t["height"])).unwrap();
    }
    writeln!(o, "pub static KEYLOG_TREES: &[KeylogTree] = &[{trees}];").unwrap();
    let sc = &kl["scenario"];
    writeln!(o, "pub const KEYLOG_NAME: &str = {:?};", sc["name"].as_str().unwrap()).unwrap();
    let mut steps = String::new();
    for s in sc["steps"].as_array().unwrap() {
        let e = &s["expect"];
        let expect = match e.get("refused") {
            Some(r) => format!("Expect::Refused({:?})", r.as_str().unwrap()),
            None => format!("Expect::Signed {{ slot: {}, already: {}, appended: {} }}", u(&e["slot"]), e["already"], e["appended"]),
        };
        write!(
            steps,
            "KeylogStep {{ sign: {}, tree: {}, nonce: {}, slot: {}, hash: {}, expect: {expect} }},",
            s["op"].as_str() == Some("sign"),
            u(&s["tree"]),
            u(&s["nonce"]),
            s.get("slot").map_or(0, u),
            g.arr(&unhex(&s["hash"]))
        )
        .unwrap();
    }
    writeln!(o, "pub static KEYLOG_STEPS: &[KeylogStep] = &[{steps}];").unwrap();
    let mut uses = String::new();
    for x in sc["uses"].as_array().unwrap() {
        write!(
            uses,
            "KeyUseV {{ chain: {}, safe: {}, root: {}, start: {}, nonce: {}, slot: {}, key_index: {}, hash: {} }},",
            u(&x["chain"]),
            g.arr(&unhex(&x["safe"])),
            g.arr(&unhex(&x["root"])),
            u(&x["start"]),
            u(&x["nonce"]),
            u(&x["slot"]),
            u(&x["key_index"]),
            g.arr(&unhex(&x["hash"]))
        )
        .unwrap();
    }
    writeln!(o, "pub static KEYLOG_USES: &[KeyUseV] = &[{uses}];").unwrap();
    g.out.push_str(o);
    g.tree("H6", &v["h6"]);
    g.tree("H10", &v["h10"]);
    std::fs::write(dir.join("board.rs"), g.out).unwrap();
}

/// A tree's place as a TreePlace literal.
fn place(g: &Gen, t: &Value) -> String {
    format!(
        "TreePlace {{ chain: {}, owner: {}, safe: {}, device: {}, generation: {}, start: {} }}",
        u(&t["chain"]),
        g.arr(&unhex(&t["owner"])),
        g.arr(&unhex(&t["safe"])),
        u(&t["device"]),
        u(&t["gen"]),
        u(&t["start"])
    )
}

fn erc8499() {
    println!("cargo:rerun-if-changed={ERC8499}");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(ERC8499).expect("erc8499.json")).expect("JSON");
    let g = Gen { out: String::new(), dir: PathBuf::new(), blobs: 0 };
    let o = &mut String::new();
    writeln!(o, "pub const KEY_TYPE: &str = {:?};", v["key_type"].as_str().unwrap()).unwrap();
    writeln!(o, "pub const GAS_LABEL: &str = {:?};", v["gas_label"].as_str().unwrap()).unwrap();
    let mut keys = String::new();
    for k in v["keys"].as_array().unwrap() {
        write!(keys, "Keys {{ ").unwrap();
        for f in ["seed", "phrase_root", "member_key_seed", "member_key", "owner", "gas_key", "device_root", "device_key_seed"] {
            write!(keys, "{f}: {}, ", g.arr(&unhex(&k[f]))).unwrap();
        }
        write!(keys, "}},").unwrap();
    }
    writeln!(o, "pub static KEYS: &[Keys] = &[{keys}];").unwrap();
    let mut trees = String::new();
    for t in v["tree_secrets"].as_array().unwrap() {
        write!(
            trees,
            "TreeSecret {{ place: {}, height: {}, device_random: {}, root: {}, key_type: {:?}, context: {}, salt: {}, sk_seed: {} }},",
            place(&g, t),
            u(&t["height"]),
            g.arr(&unhex(&t["device_random"])),
            g.arr(&unhex(&t["root"])),
            t["key_type"].as_str().unwrap(),
            g.arr(&unhex(&t["context"])),
            g.arr(&unhex(&t["salt"])),
            g.arr(&unhex(&t["sk_seed"]))
        )
        .unwrap();
    }
    writeln!(o, "pub static TREE_SECRETS: &[TreeSecret] = &[{trees}];").unwrap();
    let t = &v["small_tree"];
    writeln!(
        o,
        "pub static SMALL_TREE: SmallTree = SmallTree {{ place: {}, height: {}, device_random: {}, salt: {}, sk_seed: {}, tree_root: {} }};",
        place(&g, t),
        u(&t["height"]),
        g.arr(&unhex(&t["device_random"])),
        g.arr(&unhex(&t["salt"])),
        g.arr(&unhex(&t["sk_seed"])),
        g.arr(&unhex(&t["tree_root"]))
    )
    .unwrap();
    let dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(dir.join("erc8499.rs"), o).unwrap();
}
