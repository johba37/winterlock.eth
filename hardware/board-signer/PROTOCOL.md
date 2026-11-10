# The board's USB link

Framed binary messages over the board's serial port: UART0 through its USB serial chip (a CP2102 on the usual ESP32-WROOM-32 boards), 115200 baud, 8N1. The app (Web Serial) or a client sends requests; the board answers each one, and announces when it starts. Code: `logic/src/proto.rs`; a Python client: `tools/board_client.py`.

## Frames

All numbers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `A5 57 4C 5A` (`\xA5WLZ`) |
| 4 | 1 | version: 1 |
| 5 | 1 | message type |
| 6 | 2 | id: a request's own number, which its answer repeats; 0 for an event |
| 8 | 2 | payload length, at most 16,384 |
| 10 | 2 | CRC-16/CCITT-FALSE of bytes 4..10 (Python: `binascii.crc_hqx(b, 0xFFFF)`) |
| 12 | n | payload |
| 12 + n | 4 | CRC-32 of bytes 4..12+n (Python: `zlib.crc32`) |

**The same port carries other bytes.** At every start the ROM bootloader and the second-stage bootloader print text at 115200 baud, and a test build prints its screens and diagnostics. So a reader hunts for the magic, checks the header's CRC-16 and the length, waits for the rest, and checks the CRC-32. Whatever fails is skipped one byte at a time, so a frame that starts inside skipped bytes is still found. A frame that stops arriving for 300 ms (the board) or 500 ms (the client) is given up the same way. The magic's first byte, 0xA5, never occurs in the bootloader's ASCII text.

**The release image writes nothing but frames** once it runs: no logs, no panic messages (`firmware/check-release.sh`; in QEMU, 0 bytes outside frames after the bootloader's last line).

**One request at a time.** The board works on one request until it is answered; some wait for the member on the board (setup, recovery, enrolment, a signature). Meanwhile it answers STATUS and CANCEL, and refuses others with "busy". While it computes (a key, a tree, a stateless signature: seconds to a minute) it doesn't read the port, and bytes sent then may be lost; the frame checks catch that.

## Requests

| Type | Name | Payload | Answer |
|---|---|---|---|
| 0x01 | STATUS | none | STATUS |
| 0x02 | SETUP | app randomness (32) | IDENTITY, once the member is through setup on the board |
| 0x03 | RECOVER | none | IDENTITY, once the member has entered the 24 words and a PIN |
| 0x04 | GAS_KEY | none | GAS_KEY (unlocked only) |
| 0x05 | TREES | none | TREES (unlocked only) |
| 0x06 | ENROL | chain (8), Safe (20), start nonce (8) | ENROLLED, once the member confirms and the board is done (about a minute) |
| 0x07 | SIGN | chain (8), Safe (20), tree root (24, or zeros for the newest tree of this Safe), transaction length (2), transaction, parent length (2), parent transaction (0 bytes if none) | SIGNED, once the member confirms |
| 0x08 | CANCEL | none | DONE; the request in progress (if any) is answered with ERROR "cancelled" first |

A transaction is the app's encoding of a SafeTx's fields (as core-wasm's): to (20) ‖ value (32) ‖ operation (1) ‖ safeTxGas (32) ‖ baseGas (32) ‖ gasPrice (32) ‖ gasToken (20) ‖ refundReceiver (20) ‖ nonce (32) ‖ data. **Never a hash:** the board computes the SafeTx hash itself. For an `approveHash(bytes32)` on a parent Safe, the parent transaction's fields come along; the parent Safe is the call's target, and the board checks that the parent's fields hash to the argument.

## Answers and events

| Type | Name | Payload |
|---|---|---|
| 0x81 | STATUS | protocol (1); firmware version (1-byte length, ASCII); state (1: 0 blank, 1 locked, 2 unlocked, 3 damaged); busy (1); flags (1: bit 0 test hooks, bit 1 recovered); member key (32) and owner address (20), zeros if blank; key trees (2); storage used (4) and size (4); stateless signatures made (4) |
| 0x82 | IDENTITY | member key (32), owner address (20), how (1: 0 setup, 1 recovery) |
| 0x84 | GAS_KEY | the gas account's private key (32) |
| 0x85 | TREES | count (2), then for each: chain (8), Safe (20), start (8), height (1), root (24), keys used (2), certified (1) |
| 0x86 | ENROLLED | chain (8), Safe (20), start (8), height (1), root (24), the member key's stateless signature of the tree certificate (5,684) |
| 0x87 | SIGNED | slot (1), key index (8), SafeTx hash (32), length (2), the owner signature data (`[slot][device 0][Safe][SafeTx: 320][WOTS: 1,176][path: 240]`, 1,758 bytes) |
| 0x88 | DONE | none |
| 0x8F | ERROR | code (1), text (1-byte length, ASCII: a fixed sentence) |
| 0xA0 | BOOTED (event, id 0) | as STATUS: sent once when the board starts |

ENROLLED carries what the owner contract's `enroll(safe, 0, root ‖ 8 zero bytes, height, start, signature)` takes; the app sends it from the gas account. SIGNED's data is the contract signature for Safe's signature blob (`r` = the owner, `v` = 0, then the length and the data).

**Error codes:** 1 unknown type, 2 bad payload, 3 bad version, 4 busy, 5 locked (the PIN hasn't been entered since the start), 6 not set up, 7 already set up (erase first), 8 rejected (the member said no), 9 cancelled, 10 refused (the board's rules: a delegate call, no key tree for the Safe, a nonce outside the tree, both keys of a nonce used, a parent that doesn't match), 11 storage failed (nothing was signed), 12 storage full, 13 storage damaged.

## What the board sends, and doesn't

- **Never:** the seed, the words, a tree's salt, kept leaves, a PIN. The only secret it sends is the gas account's key, which pays fees and reveals nothing about the seed.
- **Nothing signed without a confirmation on its own screen:** both buttons held about a second on the last page; a second time for a call it can't decode or a transaction with refund fields set.
- **Before a one-time signature leaves:** the key log record is written and read back from flash.

## Test builds only

Built with the `test-hooks` feature (for QEMU and tests), the board also takes these. The release image doesn't: its parser has no such types (ERROR 1, unknown type), and `firmware/check-release.sh` proves the code isn't in the image.

| Type | Name | Payload | Answer |
|---|---|---|---|
| 0x70 | TEST_BUTTONS | events, one byte each: 1 left, 2 right, 3 both held | 0xF0 SCREEN: the screen's text after them (count, then each line with a 1-byte length) |
| 0x71 | TEST_SCREEN | none | 0xF0 SCREEN |
| 0x72 | TEST_MEMORY | none | 0xF1 MEMORY: heap peak, heap size, heap in use, first core's stack peak and size, second core's stack peak and size, second-core jobs (4 bytes each) |
| 0x73 | TEST_STALL | n (4) | DONE; the firmware then stops right after its n-th flash write or erase, as if the power went there (QEMU is killed next); 0 turns it off |

A test build's version text ends in `WINTERLOCK-TEST-HOOKS`.
