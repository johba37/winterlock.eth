#!/usr/bin/env bash
# The core on its three targets: native tests (both keccak backends), the same tests in WebAssembly
# under Node, and a no_std build for the classic ESP32. Each test run reads the Python vectors.
#
# Needs: the wasm32-unknown-unknown target, wasm-bindgen-cli of the same version as the
# wasm-bindgen crate in Cargo.lock (it provides wasm-bindgen-test-runner), Node, and espup's
# Xtensa toolchain (`. ~/export-esp.sh`, done here if the file exists).
set -euo pipefail
cd "$(dirname "$0")"

echo "== native, tiny-keccak"
cargo test --quiet
echo "== native, RustCrypto (sha3 feature)"
cargo test --quiet --no-default-features --features sha3,hbkd
echo "== native, both backends (switched at run time)"
cargo test --quiet --features sha3 --test round_trips

echo "== WebAssembly under Node ($(node --version))"
# the runner takes no --quiet, so the output is filtered; pipefail keeps a failure a failure
WASM_BINDGEN_TEST_ONLY_NODE=1 cargo test --target wasm32-unknown-unknown 2>&1 | grep -E "^(running|test result|error)|FAILED|panicked"

echo "== ESP32 (xtensa-esp32-none-elf), no_std"
if [ -f "$HOME/export-esp.sh" ]; then
  # shellcheck disable=SC1091
  . "$HOME/export-esp.sh"
fi
# the last one adds hbkd (PBKDF2 through RustCrypto's hmac), which core-wasm and the board leave out
for features in "tiny-keccak" "sha3" "tiny-keccak,sha3,count" "tiny-keccak,sha3,count,hbkd"; do
  cargo +esp build --quiet --release --target xtensa-esp32-none-elf -Z build-std=core,alloc \
    --no-default-features --features "$features"
  echo "built with features: $features"
done
echo "== all three targets: ok"
