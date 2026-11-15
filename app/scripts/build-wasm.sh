#!/usr/bin/env bash
# Builds the WebAssembly the app runs into src/wasm/:
#   core.js, core_bg.wasm     the core's bindings (core-wasm/)
#   board.js, board_bg.wasm   the virtual board: the board signer's logic (hardware/board-signer/wasm/)
# Needs the wasm32-unknown-unknown target and wasm-bindgen-cli 0.2.130, the version both crates pin.
# FEATURES=sha3 builds the core with RustCrypto's Keccak-f instead of tiny-keccak.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
want="0.2.130"
have="$(wasm-bindgen --version | awk '{print $2}')"
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen-cli $have found; core-wasm pins $want: cargo install wasm-bindgen-cli --version $want" >&2
  exit 1
fi
# The WebAssembly mustn't depend on where the checkout is: a build in any folder gives the published
# IPFS hash. The crates are one Cargo workspace rooted at the checkout's root (../../Cargo.toml), so
# cargo passes rustc the members' paths from the root (core/src/... in panic locations) and hashes
# those, not absolute paths, into symbols' names and the order of the code. The other absolute paths
# are remapped: the checkout's root (target/, where build scripts write) becomes /winterlock and
# cargo's home (crates.io sources) /cargo. CARGO_ENCODED_RUSTFLAGS replaces any RUSTFLAGS, so the
# build doesn't depend on those either. Both files keep their debug `name` section (function names
# in stack traces): it is the same in any folder too.
root="$(cd "$here/.." && pwd -P)"
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$root=/winterlock"$'\x1f'"--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
features=()
if [ -n "${FEATURES:-}" ]; then
  features=(--no-default-features --features "$FEATURES")
fi
crate="$here/../core-wasm"
(cd "$crate" && cargo build --quiet --release --target wasm32-unknown-unknown "${features[@]}")
wasm-bindgen --target web --out-dir "$here/src/wasm" --out-name core \
  "$root/target/wasm32-unknown-unknown/release/winterlock_core_wasm.wasm"
echo "built src/wasm/core_bg.wasm: $(wc -c < "$here/src/wasm/core_bg.wasm") bytes"
board="$here/../hardware/board-signer/wasm"
(cd "$board" && cargo build --quiet --release --target wasm32-unknown-unknown)
wasm-bindgen --target web --out-dir "$here/src/wasm" --out-name board \
  "$root/target/wasm32-unknown-unknown/release/winterlock_board_wasm.wasm"
echo "built src/wasm/board_bg.wasm: $(wc -c < "$here/src/wasm/board_bg.wasm") bytes"
