# leanSPHINCS on an ESP32: the 2^24 and the 2^30 parameter sets

A firmware for a classic ESP32 that times a stateless leanSPHINCS signature for two parameter sets, with the signer from [leanVM](https://github.com/leanEthereum/leanVM). It answers one question: what does the larger signature budget cost a hardware signer? It holds no secret: the key is a public test vector. On the chip: about 17 s per signature for 2^24 signatures and about 30 s for 2^30 ([Runs](#runs)).

| Set | Hypertree | FORS | Signature | Verification |
|---|---|---|---|---|
| 2^24 signatures | heights 7 + 7 + 10 | k = 19, a = 9 | 6,524 B | 437 permutations |
| 2^30 signatures | heights 8 + 8 + 10 | k = 24, a = 10 | 7,740 B | 515 permutations |

The 2^30 set is leanVM's. The 2^24 set is the one [sphincs.art](https://sphincs.art/) shows for that lifetime (uniform mode, FORS): the same code with five constants changed. Its size and verification count come out as the site's.

## The signer

`prepare.py` fetches leanVM at commit `a0fa68a` into `vendor/` (not in this repository) and changes its `keccak256` and `lean_sphincs` crates in four places, each an exact replacement that fails if leanVM's text has moved:

- **A permutation counter** in `keccak_f`, and tiny-keccak's Keccak-f as a second backend. The run measures both and uses the faster one.
- **`alloc` in place of `std`** for key generation and signing. The code only needs `Vec`.
- **The top tree's leaves as a value.** leanVM's `sign` builds the top tree again for every signature (271K permutations). A signer would keep its 1,024 leaves (16 KiB), so the firmware signs from them. The signature is the same.
- **The 2^24 constants,** in the second copy.

## What it measures

On one core, for each set: key generation, eight signatures and one verification, each with its time and its Keccak-f permutations. Before that, the hash rate of each Keccak-f.

Every result is compared with what the same code gives on a PC (`src/expected.rs`, written by `host/`): the public key, the keccak256 of each signature, and each permutation count. For the 2^30 set, the key and the first signature are leanVM's own known answer. A line that differs says `FAIL`.

## Counts on a PC

`host/` runs the same code over 1,000 messages (`cd host && cargo run --release`):

| Keccak-f permutations | 2^24 | 2^30 |
|---|---|---|
| Key generation | 271,363 | 271,363 |
| Signature, top tree's leaves kept: mean | 142,041 | 256,024 |
| 95th percentile | 192,211 | 303,109 |
| largest of 1,000 | 262,138 | 357,980 |
| Signature as leanVM's `sign` does it (top tree rebuilt): mean | about 412,000 | about 526,000 |

About 43,000 permutations of each signature are the three searches for a WOTS+C counter (target sum 128); they are why the count varies.

Eight messages are a small sample, so the firmware also prints the mean over the 1,000 messages at the rate it measured.

## Flashing and reading the result

The image is one file, `winterlock-esp32-leansphincs-bench.bin` (about 375 KB), written at address 0x0, as for [esp32-core-check](../esp32-core-check/README.md#flashing):

```sh
esptool --chip esp32 --baud 460800 write-flash 0x0 winterlock-esp32-leansphincs-bench.bin
python -m serial.tools.miniterm --rts 0 --dtr 0 /dev/ttyUSB0 115200
```

The run starts 10 s after a reset (EN) and takes about 7 minutes. It needs no display and no button. The lines to keep are everything from the firmware's name to `done.`; the `RESULT` lines at the end have the summary.

The image writes nothing to flash. On a board that holds the signer, it replaces the signer's app and leaves its storage (from 0x110000) alone; write the signer's image at 0x0 again afterwards.

## Building

```sh
python3 -I prepare.py                     # leanVM into vendor/
cd host && cargo run --release && cd ..   # the counts, and src/expected.rs
. ~/export-esp.sh
cargo build --release
espflash save-image --chip esp32 --merge --skip-padding --flash-size 4mb \
  target/xtensa-esp32-none-elf/release/winterlock-esp32-leansphincs-bench winterlock-esp32-leansphincs-bench.bin
```

Toolchain as for esp32-core-check (Xtensa Rust 1.97.0.0, esp-hal 1.2.2, espflash 4.7.0). In Espressif's QEMU the image needs padding to 4 MB (leave out `--skip-padding`); QEMU's times say nothing about the chip.

## Runs

**On the chip, 2026-11-24** ([log](runs/2026-11-24-esp32-v1.0.log)): an ESP32-D0WDQ6, silicon revision v1.0, 240 MHz measured, one core. Every check passes: the chip gives the PC's keys, signatures and permutation counts, leanVM's known answer among them. The run took 415 s.

| | 2^24 | 2^30 |
|---|---|---|
| Key generation (271,363 permutations) | 28.0 s | 32.6 s |
| Eight signatures: mean | 15.2 s | 28.5 s |
| slowest | 18.1 s | 32.2 s |
| their mean count | 127,872 | 245,944 |
| Rate while signing, permutations per second | 8,401 | 8,634 |
| At that rate, the mean count of 1,000 messages | 16.9 s | 29.7 s |
| Verification | 47 ms | 57 ms |

- **The larger budget costs 1.75 times the signing time,** about 13 s more per signature on this chip.
- **Signing runs below the bare hash rate.** The hash chain alone does 9,949 permutations per second with tiny-keccak's Keccak-f; the signer does 8,400 to 8,630, since it also builds addresses, copies and allocates. Counts divided by the bare rate had given 14 s and 26 s.
- **tiny-keccak's Keccak-f is 1.23 times as fast as leanVM's** on this chip (9,949 against 8,099 per second).
- **Key generation took 28.0 s in one copy of the code and 32.6 s in the other,** for the same work and the same key. The cause isn't established; where each copy lies in the chip's flash cache is the likely one.
- **Memory, as leanVM's code is written:** heap peak 103,312 of 180,224 bytes, stack peak 45,996 of 112,508. It keeps whole trees in memory.
- **Not measured:** both cores, a secure element, other hashes.

The log is the serial output as pasted from a terminal, with its indentation removed and three wrapped lines joined.

**QEMU, 2026-11-24** ([log](runs/2026-11-24-qemu.log)): every check passes, with the same counts and the same memory peaks.
