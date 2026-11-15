#!/usr/bin/env bash
# Builds the release image and proves it can't take simulated buttons and prints nothing of its own:
#   1. the test hooks' marker (proto::TEST_HOOKS_MARK, in every test build's version text) is not in the
#      release ELF or image, and is in the test build's (so the search can find it)
#   2. esp-println and esp-backtrace (the serial diagnostics) are not in the release build's dependencies
#   3. a build with both release-image and test-hooks fails (a compile_error! in main.rs)
# Then writes the images: winterlock-board.bin (to flash at 0x0) and winterlock-board-qemu.bin (padded to
# 4 MB for QEMU), and the test image winterlock-board-test-qemu.bin.
#
# usage: firmware/check-release.sh [OUT_DIR]     (default: target/images)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f "$HOME/export-esp.sh" ]; then
  # shellcheck disable=SC1091
  . "$HOME/export-esp.sh"
fi
TARGET_DIR=${CARGO_TARGET_DIR:-target}
OUT=${1:-$TARGET_DIR/images}
mkdir -p "$OUT"
ELF=$TARGET_DIR/xtensa-esp32-none-elf/release/winterlock-board
MARK=WINTERLOCK-TEST-HOOKS
IMAGE=(--chip esp32 --merge --flash-size 4mb --partition-table partitions.csv --partition-table-offset 0x8000)

echo "== the test build"
cargo build --quiet --release --features test-hooks
test_hits=$(grep -c "$MARK" "$ELF" || true)
[ "$test_hits" -ge 1 ] || { echo "FAIL: the test build lacks the marker, so the search proves nothing"; exit 1; }
echo "test build: the marker is in its ELF ($test_hits matching lines)"
espflash save-image "${IMAGE[@]}" "$ELF" "$OUT/winterlock-board-test-qemu.bin" >/dev/null

echo "== the release build"
cargo build --quiet --release --features release-image
if grep -q "$MARK" "$ELF"; then echo "FAIL: the release ELF has the test hooks"; exit 1; fi
espflash save-image "${IMAGE[@]}" --skip-padding "$ELF" "$OUT/winterlock-board.bin" >/dev/null
espflash save-image "${IMAGE[@]}" "$ELF" "$OUT/winterlock-board-qemu.bin" >/dev/null
for f in "$OUT/winterlock-board.bin" "$OUT/winterlock-board-qemu.bin"; do
  if grep -q "$MARK" "$f"; then echo "FAIL: $f has the test hooks"; exit 1; fi
done
echo "release build: no marker in its ELF or images"
deps=$(cargo tree --quiet -e normal --features release-image --prefix none | sort -u)
if echo "$deps" | grep -qE '^esp-(println|backtrace) '; then echo "FAIL: the release build has serial diagnostics"; exit 1; fi
echo "release build: no esp-println or esp-backtrace among its dependencies"

echo "== release-image with test-hooks must not build"
if cargo build --quiet --release --features release-image,test-hooks 2>/dev/null; then
  echo "FAIL: a release image with test hooks built"; exit 1
fi
echo "refused, as it should be"
cargo build --quiet --release --features release-image  # leave the release ELF in place

size=$(stat -c %s "$OUT/winterlock-board.bin")
echo "== release image: $OUT/winterlock-board.bin, $size bytes (flash at 0x0)"
echo "== all release checks passed"
