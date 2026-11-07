# ESP32 keccak256 benchmark

A small firmware for a classic ESP32 (an ESP32-WROOM-32 dev board) that measures how fast it computes keccak256. It answers one question: are these boards fast enough to be hash-based hardware signers for Winterlock? It holds no keys and signs nothing.

## What it measures

- **keccak256 of a 64-byte input.** It fits in one block, so each hash is one Keccak-f[1600] permutation. Each hash takes the previous digest as its input, as a WOTS chain does.
- **Four implementations, 2.5 s each, on one core:**

  | On screen | Implementation |
  |---|---|
  | `sha3` | RustCrypto `sha3` 0.12, `Keccak256` |
  | `keccak-f` | RustCrypto `keccak` 0.2, the bare permutation with a one-block sponge |
  | `tiny` | `tiny-keccak` 2.0, `Keccak::v256` |
  | `tiny-f` | `tiny-keccak` 2.0, `keccakf` with the same one-block sponge |

- **A self-test first.** Each implementation hashes 64 zero bytes and a 1,000-step chain, and the results are compared with digests computed on a PC. An implementation that fails is reported and left out, so a miscompiled hash can't show up as a fast one.
- **Both cores.** The fastest implementation then runs on both cores at once for 2.5 s.
- **Estimates.** From the fastest rates, it estimates how long Winterlock's operations take:

  | Operation | Keccak-f permutations | Splits across cores |
  |---|---|---|
  | One-time (WOTS) signature for a Safe transaction | mean 3,921, max 19,373 | mostly not |
  | Stateless (leanSphincs-keccak) signature | mean 141,974, max 290,932 | much of it |
  | Stateless key (a device key), made once | 238,624 | much of it |
  | WOTS key tree, height 10 (512 nonces) | 848,895 | yes |
  | WOTS key tree, height 6 (32 nonces) | about 53,000 (1/16 of height 10) | yes |

  The counts come from instrumenting the Python reference signer (`signer/winterlock_signer`) to count Keccak-f[1600] calls. The two-core estimates assume the work splits evenly. All times are hashing only: no USB, display or other overhead.
- **A mock confirmation.** A screen shows a made-up Safe transaction. Holding BOOT for 1.5 s "signs" it: the chip runs 3,921 permutations (a mean WOTS signature) on dummy data and shows how long that took.

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

The image is one file, `winterlock-esp32-bench.bin` (bootloader, partition table and app, about 250 KB). It goes at address 0x0.

### In the browser (Chrome or Edge)

1. Plug the board in by USB. Open <https://espressif.github.io/esptool-js/>. It doesn't work in Safari.
2. Under **Program**: set the baud rate to 460800 and press **Connect**, then pick the board's serial port.
   - If it doesn't connect, put the board in download mode by hand: hold BOOT, press and release EN, release BOOT, then press **Connect** again.
3. Set **Flash Address** to `0x0`, choose `winterlock-esp32-bench.bin`, and press **Program**.
4. When it's done, press **Disconnect**. Under **Console**, set the baud rate to 115200 and press **Start**, pick the port, then press EN on the board (or **Reset** on the page) to restart it.

### With esptool

```sh
pip install esptool
esptool --chip esp32 --baud 460800 write-flash 0x0 winterlock-esp32-bench.bin
```

This is the esptool v5 spelling. Older versions use `esptool.py ... write_flash`, which v5 still accepts with a deprecation warning. Then open the serial port at 115200 baud and press EN, for example:

```sh
python -m serial.tools.miniterm --rts 0 --dtr 0 /dev/ttyUSB0 115200   # pyserial comes with esptool
screen /dev/cu.usbserial-XXXX 115200                                  # macOS; quit with Ctrl-A K
```

### If no serial port shows up

- Try another USB cable: some cables only charge.
- On macOS, run `ls /dev/cu.*` with the board unplugged and again plugged in. The new entry is the board. If none appears, the board's USB-to-UART chip (printed on the chip next to the USB socket) needs a driver. Espressif's guide points to Silicon Labs' CP210x VCP driver and says drivers usually come with the operating system. CH340 chips are made by WCH, which publishes their drivers.

## Reading the results

The serial output at 115200 baud has the full detail. These lines are from a run in QEMU, so the numbers mean nothing:

```
winterlock-esp32-bench 0.1.0
chip: ESP32 (Esp32D0wdq6), Xtensa LX6, 2 cores, silicon revision v3.0
cpu clock: 240 MHz set (rated up to 240 MHz), 239 MHz measured against the APB timer
display: none at 0x3C or 0x3D, serial only
...
  tiny-keccak 2.0 keccakf + one-block sponge    198432 in 2500 ms:  79373 perm/s,   3023 cycles/perm
...
  core 0 128992 + core 1 143296 in 2500 ms: 108912 perm/s, 1.37x one core
...
  stateless (leanSphincs) signature, mean     141,974            1.79 s            1.30 s
...
RESULT winterlock-esp32-bench 0.1.0 rev=v3.0 mhz=240 impl=tiny-f perm_s_1core=79373 perm_s_2core=108912 selftest=ok
```

The `RESULT` line has the key numbers on one line, for pasting into an issue or a chat.

The display shows two pages of results, then the mock confirmation. A short BOOT press moves to the next screen, and the results pages also move on after 20 s. On the results pages, `1core` and `2core` are the estimates on one core and on both. `-` means the work mostly doesn't split (the WOTS signature) or the two-core run didn't happen. Times are in seconds (`s`), minutes (`m`) or hours (`h`). `SPX` is the stateless leanSphincs-keccak signature, and `dev key` is making a stateless key.

On the mock screen, hold BOOT for 1.5 s to sign or press it briefly to go back. After 60 s without an answer it goes back without signing. Press EN to run the benchmark again.

Which numbers matter:

- **The WOTS signature** is what a member waits for on every Safe transaction.
- **The stateless signature** is for messages and for certifying key trees, so it's needed less often.
- **Making a stateless key** happens once per device.
- **A key tree** is made ahead of time, before the old one runs out.

## Notes

- **Chip revision.** esp-hal 1.2 supports ESP32 v3.0 and later, and by default it refuses older chips: the bootloader prints `chip revision check failed. Required >= v3.0`. Older ESP32-WROOM-32 modules often carry v1.0 chips, so this build accepts any revision (`.cargo/esp-config.toml`) and prints the revision at start. If an older chip misbehaves, that is the likely reason.
- **The FPU.** The firmware turns the floating-point unit on itself at start. esp-hal 1.2 doesn't, so it stays as reset and the bootloader leave it. In Espressif's QEMU it is off, and the first floating-point instruction then faults over and over until the stack runs out.
- **The clock.** The CPU runs at 240 MHz. The start lines also give the clock measured against the 80 MHz bus timer.
- **BOOT is GPIO0.** Holding it while pressing EN starts the chip in download mode instead of the firmware, so press it only once the start screen is up.

## Building from source

```sh
cargo install espup espflash --locked     # or the prebuilt binaries from their GitHub releases
espup install --targets esp32             # the Xtensa Rust toolchain
. ~/export-esp.sh                         # in every new shell
cd hardware/esp32-bench
cargo build --release
espflash save-image --chip esp32 --merge --skip-padding --flash-size 4mb \
  target/xtensa-esp32-none-elf/release/winterlock-esp32-bench winterlock-esp32-bench.bin
cargo run --release                       # or flash and watch the serial output in one step
```

Built with Xtensa Rust 1.97.0.0 (espup 0.19.0), esp-hal 1.2.2 and espflash 4.7.0. The project skeleton came from esp-generate 2.0.0.

### In QEMU

Espressif's QEMU fork ([releases](https://github.com/espressif/qemu/releases)) runs the image. It needs the image padded to 4 MB, so build it without `--skip-padding`:

```sh
qemu-system-xtensa -nographic -machine esp32 -drive file=winterlock-esp32-bench.bin,if=mtd,format=raw -serial mon:stdio
```

It emulates a v0.0 chip unless it's given an eFuse file. It has no display and can't press BOOT, so the benchmark starts by itself after 10 s. Its timings say nothing about the real chip.

## Files

| Path | What it is |
|---|---|
| `src/main.rs` | Start-up, benchmarks, estimates and screens |
| `src/hashes.rs` | The four keccak256 implementations and their self-test |
| `src/ui.rs` | The OLED, the BOOT button and a small text buffer |
| `.cargo/esp-config.toml` | Accepts ESP32 chips older than v3.0 |
