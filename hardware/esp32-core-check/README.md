# ESP32 core check

A firmware for a classic ESP32 (an ESP32-WROOM-32 dev board) that runs Winterlock's Rust core (`core/`) on the board. It answers two questions: does the core compute the same bytes as the Python signer on this chip, and how long do the real operations take? Its keys are public test vectors: it holds nothing secret and signs nothing that counts.

## What it checks

The Python signer's vectors (`core/tests/vectors/board.json`, written by `signer/tools/core_vectors.py`) are built into the image. Each check prints PASS or FAIL:

- keccak256 with both backends: the empty input and a 1,000-step chain
- a typed phrase (numbered, upper case) → the seed; the seed → phrase → seed; a 25th word refused
- the member key's seed, the member key itself (made on the board, below), its owner address
- a pairing check code and a device certificate digest
- two SafeTx hashes from their fields: a delegatecall with data, and one with every field set and a nonce above 2^64
- a key log scenario: a first, a second and a refused third version at one nonce, and the records it leaves
- a stateless signature from Python verifies; with one byte changed it doesn't
- a tree's secret and public seeds; a WOTS signature and path verify to the height-6 root

Every timed operation below is checked too: the member key's public key, each stateless signature byte for byte, each tree root, each WOTS signature's owner signature data byte for byte.

## What it times

Each in ms, once with `tiny-keccak` and once with RustCrypto's Keccak-f (`sha3`). Both are in the image; the core switches at run time.

| Operation | How |
|---|---|
| keccak256 of 64 bytes, chained | 1 s, as the benchmark firmware does |
| the member key (leanSphincs-keccak, b = 10) | on one core; then its 1,024 leaves split across both |
| stateless signatures | four messages (grinds of 243 to 251,953 tries in Python), each with its own verification; mean and max |
| stateless verification | one signature |
| WOTS trees of height 6 and 10 | on one core; then the leaves split across both |
| WOTS signatures | eight (four per tree): SafeTx hash, key log record, signature, check against the root, owner signature data; mean and max |

The serial lines also give the Keccak-f permutations each one-core operation took, counted by the core.

At the end it reports the peak heap use (of 176 KB: 96 KB reclaimed from the bootloader and 80 KB of main DRAM) and how much of each core's stack the run used (the second core's is 32 KB; the jobs on it need a few KB).

## Wiring the display (optional)

A 0.96" 128x64 OLED with an SSD1306 or SSD1315 controller on I2C, at address 0x3C (0x3D is tried too).

| OLED pin | ESP32 board pin |
|---|---|
| VCC | 3V3 |
| GND | GND |
| SDA | GPIO21 |
| SCK (SCL) | GPIO22 |

Without a display, everything still runs and prints on serial. Each screen is also printed on serial in a box, so you can see what the display would show.

## Flashing

The image is one file, `winterlock-esp32-core-check.bin` (bootloader, partition table and app, about 390 KB). It goes at address 0x0.

### In the browser (Chrome or Edge)

1. Plug the board in by USB. Open <https://espressif.github.io/esptool-js/>. It doesn't work in Safari.
2. Under **Program**: set the baud rate to 460800 and press **Connect**, then pick the board's serial port.
   - If it doesn't connect, put the board in download mode by hand: hold BOOT, press and release EN, release BOOT, then press **Connect** again.
3. Set **Flash Address** to `0x0`, choose `winterlock-esp32-core-check.bin`, and press **Program**.
4. When it's done, press **Disconnect**. Under **Console**, set the baud rate to 115200 and press **Start**, pick the port, then press EN on the board (or **Reset** on the page) to restart it.

### With esptool

```sh
pip install esptool
esptool --chip esp32 --baud 460800 write-flash 0x0 winterlock-esp32-core-check.bin
```

This is the esptool v5 spelling. Older versions use `esptool.py ... write_flash`, which v5 still accepts with a deprecation warning. Then open the serial port at 115200 baud and press EN, for example:

```sh
python -m serial.tools.miniterm --rts 0 --dtr 0 /dev/ttyUSB0 115200   # pyserial comes with esptool
screen /dev/cu.usbserial-XXXX 115200                                  # macOS; quit with Ctrl-A K
```

### If no serial port shows up

- Try another USB cable: some cables only charge.
- On macOS, run `ls /dev/cu.*` with the board unplugged and again plugged in. The new entry is the board. If none appears, the board's USB-to-UART chip (printed on the chip next to the USB socket) needs a driver. Espressif's guide points to Silicon Labs' CP210x VCP driver and says drivers usually come with the operating system. CH340 chips are made by WCH, which publishes their drivers.

## Running it

Press BOOT once the start screen is up, or wait 10 s. A run has two passes, one per backend; in QEMU it took 80 to 130 s. The display shows the pass and the step. At the end it shows two summary pages; a short BOOT press, or 20 s, moves to the other one. Press EN to run again.

## What to paste back

The serial output at 115200 baud has the full detail. Paste back:

- the three `RESULT` lines at the end, and
- if any check says FAIL, or the run stops, the whole output.

These lines are from a run in QEMU, so the numbers mean nothing:

```
RESULT winterlock-esp32-core-check 0.1.0 rev=v3.0 mhz=240 checks=PASS passed=54/54 default_backend=tiny-keccak heap_peak=82144 heap=180224 stack0=9868/73992 stack1=1644/32768
RESULT tiny-keccak perm_s=74988 key_1core_ms=4800 key_2core_ms=1940 spx_mean_ms=2188 spx_max_ms=4338 spx_verify_ms=6 h6_1core_ms=846 h6_2core_ms=425 h10_1core_ms=13277 h10_2core_ms=8106 wots_mean_ms=53 wots_max_ms=98
RESULT sha3 perm_s=32340 key_1core_ms=6862 key_2core_ms=3868 spx_mean_ms=4371 spx_max_ms=9608 spx_verify_ms=11 h6_1core_ms=1784 h6_2core_ms=956 h10_1core_ms=23662 h10_2core_ms=12975 wots_mean_ms=80 wots_max_ms=131
```

The first line: the chip, whether all 54 checks passed, the peak heap use and both stacks' peak use (bytes). The others, per backend: keccak256 hashes per second, then each operation in ms (`spx` is the stateless signature, `h6` and `h10` the WOTS trees, `1core` and `2core` one core and both).

On the display, `1c` and `2c` are one core and both; `SPX` is the stateless signature; `h6` and `h10` are the WOTS trees; times are in ms.

## Notes

- **Which keccak.** The image has both backends and times both. Outside the timings it uses `tiny-keccak`, the core's default: it was the fastest permutation in QEMU, where the benchmark firmware's times mean nothing. The board's numbers decide which feature the board's firmware builds with.
- **Chip revision.** esp-hal 1.2 supports ESP32 v3.0 and later, and by default it refuses older chips. This build accepts any revision (`.cargo/esp-config.toml`), as the benchmark firmware does, and prints the revision at start.
- **The FPU** is turned on at start on both cores, as in the benchmark firmware. The core uses no floating point.
- **The second core** is started for each two-core job and parked when it's done. If it doesn't start, the first core does its half and the check says FAIL.
- **BOOT is GPIO0.** Holding it while pressing EN starts the chip in download mode instead of the firmware, so press it only once the start screen is up.

## Building from source

```sh
cargo install espup espflash --locked     # or the prebuilt binaries from their GitHub releases
espup install --targets esp32             # the Xtensa Rust toolchain
. ~/export-esp.sh                         # in every new shell
cd hardware/esp32-core-check
cargo build --release
espflash save-image --chip esp32 --merge --skip-padding --flash-size 4mb \
  target/xtensa-esp32-none-elf/release/winterlock-esp32-core-check winterlock-esp32-core-check.bin
cargo run --release                       # or flash and watch the serial output in one step
```

Built with Xtensa Rust 1.97.0.0 (espup 0.19.0), esp-hal 1.2.2, esp-alloc 0.11.0 and espflash 4.7.0. The vectors come from `core/tests/vectors/board.json` at build time (`build.rs`).

### In QEMU

Espressif's QEMU fork ([releases](https://github.com/espressif/qemu/releases)) runs the image. It needs the image padded to 4 MB, so build it without `--skip-padding`:

```sh
qemu-system-xtensa -nographic -machine esp32 -drive file=winterlock-esp32-core-check.bin,if=mtd,format=raw -serial mon:stdio
```

It has no display and can't press BOOT, so the run starts by itself after 10 s. Built with `--features scripted-boot`, every wait for BOOT ends in a press after 1.5 s instead, to run the button paths. Its timings say nothing about the real chip.

## Files

| Path | What it is |
|---|---|
| `src/main.rs` | Start-up, checks, timings, RESULT lines and screens |
| `src/board.rs` | The vectors' types; `build.rs` writes their values from `board.json` |
| `src/dual.rs` | Jobs on the second core, and the stacks' peak use |
| `src/ui.rs` | The OLED, the BOOT button and a small text buffer (from the benchmark firmware) |
| `.cargo/esp-config.toml` | Accepts ESP32 chips older than v3.0; asks for at least 32 KB of main stack |
