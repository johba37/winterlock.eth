#!/usr/bin/env python3
"""Fetches leanVM's signer at a pinned commit and prepares it for this benchmark, in vendor/.

leanVM's `keccak256` and `lean_sphincs` crates are copied as they are, then changed in four
places, each an exact replacement that fails loudly if leanVM's text has moved:

  keccak256     a permutation counter, and tiny-keccak's Keccak-f as a second backend
  lean_sphincs  key generation and signing with `alloc` in place of `std` (the code only needs Vec)
  lean_sphincs  the top tree's leaves as a value, and signing from them: the 16 KiB a signer keeps
  ls24 only     five constants and three assertions, for the 2^24 set of sphincs.art

vendor/ls30 is leanVM's parameter set (2^30 signatures), vendor/ls24 the 2^24 one.
Run: python3 -I prepare.py
"""
import pathlib
import shutil
import subprocess
import sys

COMMIT = "a0fa68a6cad4ca9da886809f5fff624a250d2f62"
REPO = "https://github.com/leanEthereum/leanVM"
HERE = pathlib.Path(__file__).resolve().parent
VENDOR = HERE / "vendor"


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def replace(path, old, new, count=1):
    text = path.read_text()
    if text.count(old) != count:
        sys.exit(f"{path}: expected {count} of {old!r}, found {text.count(old)}")
    path.write_text(text.replace(old, new))


def fetch():
    src = VENDOR / "leanvm"
    if not (src / ".git").exists():
        src.mkdir(parents=True)
        run("git", "init", "-q", cwd=src)
        run("git", "remote", "add", "origin", REPO, cwd=src)
    run("git", "fetch", "-q", "--depth", "1", "origin", COMMIT, cwd=src)
    run("git", "checkout", "-q", "--detach", COMMIT, cwd=src)
    return src


def keccak(src):
    dst = VENDOR / "keccak256"
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src / "crates/keccak256/src", dst / "src")
    (dst / "Cargo.toml").write_text(
        """[package]
name = "keccak256"
version = "0.1.0"
edition = "2024"
publish = false

[features]
# tiny-keccak's Keccak-f as a second backend, picked at run time (use_tiny)
tiny = ["dep:tiny-keccak"]

[dependencies]
tiny-keccak = { version = "2.0.2", features = ["keccak"], optional = true }
"""
    )
    lib = dst / "src/lib.rs"
    replace(
        lib,
        "mod lanes;\npub mod positions;\n",
        """// --- benchmark only, not in leanVM ---

/// Keccak-f permutations of one state since the last [`reset_permutations`].
static PERMUTATIONS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static TINY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn permutation_count() -> u32 {
    PERMUTATIONS.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn reset_permutations() {
    PERMUTATIONS.store(0, core::sync::atomic::Ordering::Relaxed)
}

/// Permute with tiny-keccak's Keccak-f (true) or leanVM's own (false).
#[cfg(feature = "tiny")]
pub fn use_tiny(on: bool) {
    TINY.store(on, core::sync::atomic::Ordering::Relaxed)
}

// --- end ---

mod lanes;
pub mod positions;
""",
    )
    replace(
        lib,
        "pub fn keccak_f(a: &mut [u64; STATE_LANES]) {\n",
        """pub fn keccak_f(a: &mut [u64; STATE_LANES]) {
    // benchmark only
    PERMUTATIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    #[cfg(feature = "tiny")]
    if TINY.load(core::sync::atomic::Ordering::Relaxed) {
        return tiny_keccak::keccakf(a);
    }
""",
    )


def sphincs(src, name):
    dst = VENDOR / name
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src / "crates/lean_sphincs/src", dst / "src")
    (dst / "Cargo.toml").write_text(
        f"""[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
keccak256 = {{ path = "../keccak256" }}
"""
    )
    lib, scheme, fors = dst / "src/lib.rs", dst / "src/scheme.rs", dst / "src/fors.rs"
    # alloc in place of std
    replace(lib, '#![cfg_attr(not(any(feature = "std", test)), no_std)]\n', "#![no_std]\n")
    replace(lib, '#![cfg_attr(not(feature = "std"), allow(dead_code))]\n', "")
    replace(lib, '#[cfg(feature = "std")]\npub use scheme::{key_gen, sign};\n',
            "pub use scheme::{key_gen, public_key_from_leaves, sign, sign_cached, top_leaves};\n")
    replace(lib, "mod fors;\n", "extern crate alloc;\npub(crate) use alloc::{vec, vec::Vec};\n\nmod fors;\n")
    replace(scheme, '#[cfg(feature = "std")]\n', "", count=5)
    replace(fors, '#[cfg(feature = "std")]\n', "")
    # the top tree's leaves as a value
    replace(
        scheme,
        """pub fn sign(secret_key: &SecretKey, message: &Message) -> LeanSphincsSignature {
    let sk = &ExpandedKey::new(secret_key);
    let (pk, mut top) = keygen(sk);
""",
        """pub fn sign(secret_key: &SecretKey, message: &Message) -> LeanSphincsSignature {
    let sk = &ExpandedKey::new(secret_key);
    let (pk, top) = keygen(sk);
    sign_with(sk, pk, top, message)
}

// --- benchmark only, not in leanVM: what a signer that keeps the top tree's leaves does ---

/// The top tree's leaves: 2^10 one-time public keys, 16 KiB.
pub fn top_leaves(secret_key: &SecretKey) -> Vec<Digest> {
    let sk = &ExpandedKey::new(secret_key);
    let key = OtsKey::of_index(LAYERS - 1, 0);
    (0..1 << LAYER_HEIGHTS[LAYERS - 1])
        .map(|leaf| wots_public_leaf(sk, &OtsKey { leaf, ..key }))
        .collect()
}

fn top_from_leaves(sk: &ExpandedKey, leaves: &[Digest]) -> (LeanSphincsPublicKey, Vec<Vec<Digest>>) {
    let key = OtsKey::of_index(LAYERS - 1, 0);
    let height = LAYER_HEIGHTS[LAYERS - 1];
    assert_eq!(leaves.len(), 1 << height);
    let top = merkle_levels(leaves.to_vec(), height, |z, j, pair| node(&sk.pk_seed, &key, z, j, pair));
    let pk = LeanSphincsPublicKey {
        pk_seed: sk.pk_seed,
        root: top[height][0],
    };
    (pk, top)
}

/// The public key, from the top tree's leaves.
pub fn public_key_from_leaves(secret_key: &SecretKey, leaves: &[Digest]) -> LeanSphincsPublicKey {
    top_from_leaves(&ExpandedKey::new(secret_key), leaves).0
}

/// [`sign`] with the top tree's leaves given: the same signature.
pub fn sign_cached(secret_key: &SecretKey, leaves: &[Digest], message: &Message) -> LeanSphincsSignature {
    let sk = &ExpandedKey::new(secret_key);
    let (pk, top) = top_from_leaves(sk, leaves);
    sign_with(sk, pk, top, message)
}

// --- end ---

fn sign_with(
    sk: &ExpandedKey,
    pk: LeanSphincsPublicKey,
    mut top: Vec<Vec<Digest>>,
    message: &Message,
) -> LeanSphincsSignature {
""",
    )
    if name == "ls24":
        replace(lib, "pub const LOG_LIFETIME: usize = 30;", "pub const LOG_LIFETIME: usize = 24;")
        replace(lib, "pub const LAYER_HEIGHTS: [usize; LAYERS] = [8, 8, 10];", "pub const LAYER_HEIGHTS: [usize; LAYERS] = [7, 7, 10];")
        replace(lib, "pub const FORS_TREES: usize = 24;", "pub const FORS_TREES: usize = 19;")
        replace(lib, "pub const FORS_HEIGHT: usize = 10;", "pub const FORS_HEIGHT: usize = 9;")
        replace(lib, "assert!(H == 26 && DIGEST_BYTES == 34 && DIGEST_CALLS == 2);", "assert!(H == 24 && DIGEST_BYTES == 26 && DIGEST_CALLS == 1);")
        # sphincs.art's figures for this set: the constants above are the ones it shows
        replace(lib, "assert!(SIG_SIZE == 7740);", "assert!(SIG_SIZE == 6524);")
        replace(lib, "assert!(VERIFY_PERMUTATIONS == 515);", "assert!(VERIFY_PERMUTATIONS == 437);")


def main():
    src = fetch()
    keccak(src)
    for name in ("ls30", "ls24"):
        sphincs(src, name)
    shutil.copy(src / "crates/lean_sphincs/tests/lean_sphincs/known_answer.hex", VENDOR / "known_answer.hex")
    for f in ("LICENSE-MIT", "LICENSE-APACHE"):
        shutil.copy(src / f, VENDOR / f)
    print(f"vendor/ ready: leanVM {COMMIT[:9]}")


main()
