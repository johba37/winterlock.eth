#!/usr/bin/env bash
# Builds the core's WebAssembly bindings (core-wasm/) into src/wasm/ for the app and its tests.
# Needs the wasm32-unknown-unknown target and wasm-bindgen-cli 0.2.130, the version core-wasm pins.
# FEATURES=sha3 builds with RustCrypto's Keccak-f instead of tiny-keccak.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
crate="$here/../core-wasm"
want="0.2.130"
have="$(wasm-bindgen --version | awk '{print $2}')"
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen-cli $have found; core-wasm pins $want: cargo install wasm-bindgen-cli --version $want" >&2
  exit 1
fi
features=()
if [ -n "${FEATURES:-}" ]; then
  features=(--no-default-features --features "$FEATURES")
fi
(cd "$crate" && cargo build --quiet --release --target wasm32-unknown-unknown "${features[@]}")
wasm-bindgen --target web --out-dir "$here/src/wasm" --out-name core \
  "$crate/target/wasm32-unknown-unknown/release/winterlock_core_wasm.wasm"
echo "built src/wasm/core_bg.wasm: $(wc -c < "$here/src/wasm/core_bg.wasm") bytes"
