# Board signer

Winterlock's board: an ESP32-WROOM-32 with a 128×64 OLED and two buttons that holds a member's seed and signs every enrolment and confirmation after showing it (docs/notes/signer-app.md, "The board", decision 7). This is its first version, built and tested before the hardware is wired: natively, as screen images, and in QEMU. **It hasn't run on a board yet.**

| Path | What it is |
|---|---|
| `logic/` | `winterlock-board`: the signer without hardware, `no_std` with `alloc`, on `winterlock-core`. Button events and USB requests in, screens and answers out. Builds natively and for `xtensa-esp32-none-elf`. |
| `firmware/` | The ESP32 firmware around it: OLED, buttons, flash partition, serial link, both cores, the random number generator. |
| `tools/` | `board_client.py` (the protocol in Python, stdlib and pyserial), `board_vectors.py` (the Python signer's known answers), `qemu_flows.py` (the firmware in QEMU), `anvil_e2e.py` (end to end on a local chain). |
| `screens/` | `contact-sheet.png`: every screen of every flow; a few screens on their own. |
| `PROTOCOL.md` | The USB link's frames and messages. |

## What it does

- **Setup** (the app sends SETUP with 32 random bytes): the seed is keccak256(abi.encode("winterlock.board.seed.v1", the board's 32 random bytes, the app's)). The board shows the 24 words, four a page, then asks for three of them at random positions, each picked from four words. A wrong pick shows the words again and asks three new ones. Then a PIN of 4 to 8 digits, twice. The member key is made on both cores (11.7 s on the chip) and its 1,024 leaves are kept in flash, so this happens once. The app gets the member key and the owner address; the board shows the address in full.
- **Unlock:** the PIN at every start. Each try is written to flash before it is checked; a right PIN resets the count; the third wrong PIN in a row erases the seed and the key log. A start that finds three tries counted erases too.
- **Enrol** (ENROL: chain, Safe, start): the board shows the chain, the Safe and the first nonce. On confirmation it makes a height-10 tree (1,024 keys, 512 nonces) from a fresh 32-byte salt, writes the tree (salt, root, leaves) and the certificate's record, then the member key signs the certificate on both cores and the app gets it. A new tree must start after the board's last one for that Safe.
- **Confirm a transaction** (SIGN: the fields, never a hash). Decoded on the board:
  - an ETH transfer; an ERC-20 `transfer` of a listed token (amount and symbol)
  - `approveHash` on a parent Safe with the parent's fields: the board hashes them, checks the argument, and shows the parent's transfer
  - a cancel (an empty call from the Safe to itself)
  - anything else: target, value, function selector, "NOT DECODED", and a second confirmation
  - refund fields set (gas price, base gas, safeTxGas, gas token, receiver): shown, and a second confirmation
  - a delegate call, or a parent's: refused

  Then the key log record is written and read back, and only then is the one-time signature made and sent.
- **The gas key** to the app once unlocked. **Recovery:** the 24 words letter by letter, the checksum checked, a PIN; a recovered board has no key trees and enrols new ones before it signs. **Erase:** from the menu, with a confirmation.

**The token list** has only addresses checked against the issuer's or the chain's own documentation (2026-11-10, Ethereum and Base on 2026-11-11), with symbol and decimals read on-chain: USDC on Ethereum, Arbitrum One, Base, Ethereum Sepolia and Arbitrum Sepolia (Circle's "USDC contract addresses"), WETH on Ethereum (ethereum.org's "Wrapped Ether"), Arbitrum One (Arbitrum's "Contract addresses") and Base (Base's "Base Contracts"). USDT and ARB are left out: their first-party pages didn't list the addresses.

**Buttons:** left is back or no, right is next or yes, both held for 1 s confirm. For the PIN, left and right step through 0–9, delete and done; both takes the one shown. For a word, they step through the letters that continue some word of the list; four letters (fewer for some) pick a word.

## Wiring

| Part | ESP32 pin |
|---|---|
| OLED SDA / SCK | GPIO21 / GPIO22 (I2C at 0x3C, or 0x3D), VCC to 3V3, GND to GND |
| Left button | GPIO32 |
| Right button | GPIO33 |

Push buttons go to GND (the default build: active low, internal pull-ups). Touch modules (high while touched) need `--features touch-buttons` (active high, pull-downs). Nothing counts until both buttons have been seen released, so a button held at start, a stuck one, or a pin that reads pressed never confirms anything. BOOT (GPIO0) isn't used.

## Storage

The partition table (`firmware/partitions.csv`, checked by `build.rs` against the 4 MB flash):

| Partition | Offset | Size |
|---|---|---|
| bootloader, partition table | 0x1000, 0x8000 | |
| factory app | 0x10000 | 1 MB (the release app is 286,816 bytes, 27%) |
| `signer` (data, subtype undefined) | 0x110000 | 3,080,192 bytes, to the end of the 4 MB flash |

The firmware reads the table it booted with and refuses to start if `signer` isn't where the build expects.

**The partition is an append-only log of records** (`logic/src/store/`): the seed, the member key with its leaves, the PIN's salt and check value, READY; then PIN tries, key trees, certificate records and key uses. Records are never changed in place, so a power cut can only damage the one being written. Each record's 8-byte header holds a value and its complement, written on its own before the rest: programming NOR flash only clears bits, so a torn header can't come out valid, and a valid header gives the exact length to skip a torn body. A CRC-32 covers each record. The whole partition is erased only to wipe the board, starting with the sector that holds the seed, after a WIPE record. At start, anything but a complete setup (FORMAT, SEED, MEMBER, PIN, READY, one after the other) means a setup or an erase that didn't finish, and the board erases itself.

| Record | Bytes |
|---|---|
| a complete setup | 16,608 |
| a key tree (salt, root, 1,024 leaves) | 24,684 |
| a key use | 124 |
| a certificate record | 96 |
| a PIN try, a right PIN | 12 each |

So the partition holds, for example, 40 trees with 12,000 signatures. When it is full the board says so and makes no new tree or signature. The last 8 KB are kept for PIN tries (341 unlocks) and the WIPE record, so a full board still unlocks and erases; erasing and recovering starts it afresh (and costs new trees).

**Why a log of its own, not `sequential-storage`:** the board's records are appended and never updated, so it needs no map or garbage collection; `sequential-storage` is async-only today and would need an executor; and with its own format, the rules a power cut must not break fit in one file and are tested at every write.

**Why the tree's leaves are kept on the board:** a signature needs the tree's 10 path nodes. Keeping the leaves (24 KB a tree) costs about 0.1 s to rebuild the nodes before a signature, instead of 42 s to make the leaves again; the nodes are public, but keeping them on the board means the app holds nothing the board needs, and a wrong set can't be slipped in. The 1,023 inner nodes aren't kept: they come from the leaves in 1,023 hashes.

## Randomness

The seed, the tree salts and the PIN's salt come from the ESP32's random number generator with the SAR ADC as its entropy source, as ESP-IDF's bootloader does (`bootloader_random_enable`), with the radio off. The note asked for the radio on; the ADC source is the other source Espressif names as making the generator truly random, and it needs no radio stack. esp-hal 1.2.2's ESP32 version of that setup enables the I2C0 clock (DPORT bit 7) where ESP-IDF enables I2S0's (bit 4), and I2S0 is what carries the ADC readings, so the firmware enables I2S0 and repeats its setup (`firmware/src/hw.rs`). Every random byte goes through a keccak pool fed with generator words and the cycle counter. The seed is also hashed with the app's 32 random bytes.

**Not verifiable before the board:** QEMU's generator isn't the chip's, and it doesn't keep DPORT's clock bit (the test build reports "I2S0 clock OFF" in QEMU). On the board, the start-up line should read "on".

## Building and testing

```sh
# the logic, natively
cd hardware/board-signer/logic
cargo test                                   # flows, power cuts, the Python vectors, units
cargo test --features test-hooks             # the same with the test hooks
cargo run --release --example screens        # every screen as a PNG, in ../screens/all

# the firmware (espup's Xtensa toolchain: . ~/export-esp.sh)
cd ../firmware
./check-release.sh                           # builds both images and proves the release one has no test hooks
cargo build --release --features test-hooks  # the QEMU build

# QEMU and the Python client (the signer's virtualenv for the checks)
python -I ../tools/qemu_flows.py target/images/winterlock-board-test-qemu.bin target/images/winterlock-board-qemu.bin
python -I ../tools/anvil_e2e.py target/images/winterlock-board-test-qemu.bin   # needs anvil and Safe v1.4.1's build
```

The vectors: `signer/.venv/bin/python -I hardware/board-signer/tools/board_vectors.py` writes `logic/tests/vectors/board_flows.json`.

**Images.** espflash 4.7.0 needs `--partition-table-offset 0x8000` with a custom table, or it leaves the table out of a merged image:

```sh
espflash save-image --chip esp32 --merge --flash-size 4mb --partition-table partitions.csv \
  --partition-table-offset 0x8000 --skip-padding <elf> winterlock-board.bin      # to flash at 0x0
espflash flash --chip esp32 --partition-table partitions.csv <elf>              # or cargo run --release
```

QEMU needs the image padded to 4 MB (without `--skip-padding`): `qemu-system-xtensa -nographic -machine esp32 -drive file=IMAGE,if=mtd,format=raw -serial tcp:127.0.0.1:5555,server=on,wait=on`. QEMU writes the guest's flash writes back to the image file, so a board can be restarted from it.

**The test hooks** (`--features test-hooks`): simulated buttons and the screen's text over the link, a memory report, a stop after a given flash write, and each screen printed on the serial port. The release image is built with `--features release-image`, which refuses to build with the test hooks; `check-release.sh` also checks that the test build's marker string is in its ELF and not in the release ELF or images, and that the serial diagnostics (esp-println, esp-backtrace) aren't among the release build's dependencies. In QEMU the release image answers a simulated button with "unknown type" and sends nothing but frames.

## What was verified, and how (2026-11-10)

- **Native** (`cargo test`): 30 tests, 29 with the test hooks (one checks their absence):
  - 9 flows through the buttons and the messages; the outputs checked with the core's verifiers as the contracts do
  - the Python signer's outputs byte for byte: words, member key, owner, gas key, the PIN's check value, a tree's root and its 5,684-byte certificate, four transaction signatures
  - power cut at every flash write and erase, then a restart from what was left: setup (74 operations), unlock and a signature (6 operations, 32 torn patterns each), an enrolment (104), the third wrong PIN (17, 8 patterns each), an erase (19, 8 each): 658 cuts. At every cut no one-time key ever signs two hashes, no signature or certificate leaves before its record is durable (checked as each leaves, by opening a copy of the flash as it is then), and the board comes back as it was or blank with the seed gone; never half set up, with fewer wrong PINs, or damaged.
  - a write that doesn't stick (a bit left set, no power cut): the read-back catches it and nothing is signed
  - a full log refuses trees and key uses but still takes 300 unlocks, and erases
  - frames through bootloader text and damage, the debouncer, amounts, layouts
- **QEMU** (`qemu_flows.py`, Espressif's QEMU 9.2.2, the test image): setup; a restart and unlock; enrolment; an ETH transfer, an approveHash with the parent's fields, a call that isn't decoded, a refused delegate call; QEMU killed after the key use record's header (the torn record is skipped, the key unused) and after the whole record (it survives, the same transaction gets the same key and another gets the other); three wrong PINs erase the board (the seed is no longer in the flash image); a recovery gives the same owner, refuses to sign until it enrols, then signs. Every output is checked with the Python signer. The release image boots, refuses a simulated button, and sends nothing but frames.
- **On a local chain** (`anvil_e2e.py`): the board's owner deployed by the factory at the address the board computed; its certificate accepted by `enroll` from the board's gas account; a Safe whose only owner is the board executes an ETH transfer with the board's signature; a parent Safe executes a transfer on the board-confirmed approveHash.
- **Memory in QEMU:** heap peak 109,624 of 180,224 bytes; first core's stack 18,864 of 72,868; second core's 2,204 of 32,768.

## Not verified until the board runs it

- the OLED, the buttons and their debouncing, and how the screens feel at 0.96 inch
- the serial link through the CP2102 with Chrome or Edge (Web Serial), and the board's reset lines
- the random number generator with the ADC entropy source on the chip (QEMU can't show it)
- flash writes, erases and power cuts on the real chip (QEMU's flash model and the simulated NOR flash are what was tested)
- the times on the chip: QEMU's say nothing about them. The core check measured 11.7 s for the member key and 42 s for a tree on both cores, and 15 s on average (32 s at most) for a stateless signature on one core; the board spreads a signature's grind and FORS trees over both cores, which should shorten it, unmeasured
- a chip of revision v1.0 (QEMU emulates v0.0; the core check ran on v1.0)

## Files

| Path | What it is |
|---|---|
| `logic/src/board.rs` | The flows: modes, screens, buttons, requests |
| `logic/src/store/` | The record log (`log.rs`) and what the records mean (`mod.rs`), the key log's storage |
| `logic/src/proto.rs` | Frames, requests, answers |
| `logic/src/decode.rs` | What a transaction does; the token list |
| `logic/src/keys.rs` | Every key derived from the seed, in one place (today: the core's `derive`) |
| `logic/src/ui.rs`, `input.rs` | Screens and the frame buffer; the buttons |
| `logic/src/sim.rs` | A NOR flash in memory that can lose power at any write |
| `logic/tests/` | Flows, power cuts, the Python vectors |
| `logic/examples/screens.rs` | Every screen as a PNG |
| `firmware/src/main.rs`, `hw.rs`, `dual.rs` | Start-up and the main loop; the partition, OLED, RNG and platform; the second core (from the core check) |
| `firmware/partitions.csv`, `build.rs`, `check-release.sh` | The partition table and its check; the release check |
