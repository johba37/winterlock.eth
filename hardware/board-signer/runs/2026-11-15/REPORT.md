# The first wired board (2026-11-15)

The bring-up image, the push-button signer and the app with a board, on the first wired board. Everything in this report was built from `board-app` at `ccebaac`. Serial logs are next to this file.

**Result:** the hardware works: display, both buttons, serial both ways. The signer starts blank, sets up through the app and enrols a key tree on Sepolia. The board signed both versions of one nonce with that nonce's two keys, and the Safe executed the second on the board's signature alone. Five things came up:
- The app enrolled twice, so the board's tree started one nonce past the Safe's. Another owner executed that nonce.
- The first confirmed transaction sends ETH to the board's own owner contract, which can't receive ETH, so it can't execute. Nothing warned before signing.
- Ubuntu's Firefox snap can't see serial ports.
- An older Brave loses the port as soon as it's opened.
- `board_client.py` loses its first request because opening the port restarts the board.

## The board

| | |
|---|---|
| Chip | ESP32-D0WDQ6, silicon revision v1.0, 240 MHz, 40 MHz crystal |
| USB | CP2102 (`10c4:ea60`), `/dev/ttyUSB0` on Ubuntu (Linux 6.8) |
| Display | 128×64 I2C OLED at 0x3C (SDA GPIO21, SCL GPIO22) |
| Buttons | two push buttons to GND: left GPIO32, right GPIO33 |
| Case | closed: BOOT and EN can't be reached |

## Tools and images

Xtensa Rust 1.97.0.0 (espup 0.19.0), espflash 4.7.0 (`save-image`), esptool 4.7.0 (flashing). Images built as in the README, "On the board, first":

| Image | Build | Bytes | SHA-256 |
|---|---|---|---|
| `winterlock-bringup.bin` | `--bin winterlock-bringup --features log` | 203,968 | `a6b19f4352aa670a2e23bd7ac9b3b56b9174979b62efd2eff88805c141e716e8` |
| `winterlock-board-push.bin` | `--bin winterlock-board --features log` | 402,144 | `5ad21cb7cd76d5d8cb1e1e50c4bd6951f671ad23c09210281290002e4860730b` |

Before the signer was flashed, its partition (0x110000, 0x2f0000 bytes) was erased with `esptool erase_region`, so the signer started blank whatever the board held before.

## Bring-up image

| Check | Result |
|---|---|
| OLED | First "none answers at 0x3c or 0x3d": the display's VCC wire was loose. After fixing it: **found at 0x3C**; the screen shows the press counts and the echoed text (`rx: screen ok?`). |
| Left button (GPIO32) | **Works.** High at start (push button). 3 short presses and one held 3.9 s: 4 presses and 4 releases, each counted once. |
| Right button (GPIO33) | **Works.** High at start. 3 presses: 3 presses and 3 releases, each counted once. |
| BOOT (GPIO0) | **Not tested:** the case was closed. The signer doesn't use BOOT. |
| Serial, both ways | **Works.** A line sent from the host is echoed on the port and shown on the screen. |
| Entropy registers | See below. |
| Reset on opening the port | **Yes, usually:** 3 of 4 observed opens from the host restarted the board (power-on reset, uptime from 0). |

**The entropy source registers on silicon** (`bringup-start-echo-reopen.log`):
```
after esp_hal::init:     PERIP_CLK_EN 0xf900600f (I2S0 clock 0, I2C0 clock 0), I2S0 CONF2 0x00000020, SAMPLE_RATE_CONF 0x00410186
after TrngSource::new:   PERIP_CLK_EN 0xf900608f (I2S0 clock 0, I2C0 clock 1), I2S0 CONF2 0x00000020, SAMPLE_RATE_CONF 0x00410186
after the signer's fix:  PERIP_CLK_EN 0xf900609f (I2S0 clock 1, I2C0 clock 1), I2S0 CONF2 0x00000039, SAMPLE_RATE_CONF 0x00410506
```
On the chip, esp-hal 1.2.2's `TrngSource::new` sets the I2C0 clock bit and leaves I2S0's off, as the README says. The signer's fix turns I2S0's clock on and sets up I2S0. PERIP_RST_EN read 0 throughout. The signer's own start-up line about this (`rng: ... I2S0 clock on/OFF`) was lost in the capture (see below), so the "on" is shown by the bring-up image's register dump, not by the signer.

**Port opens and resets** (pyserial 3.5 on Linux):
1. Close, then reopen with pyserial's defaults (DTR and RTS asserted): no reset.
2. Open with DTR and RTS set low before the open: reset.
3. The same again: reset.
4. With the signer, `board_client.py`'s `SerialLink`, which opens and then sets DTR and RTS low: reset (a power-on reset and the boot in the first 4 s).
5. An earlier `board_client.py` open whose STATUS got no answer: probably a reset too, not observed directly.

Linux raises DTR and RTS when a tty opens, before the program's settings apply, so the CP2102's auto-reset circuit pulses EN. Expect a restart on most connects.

## Signer (push buttons, diagnostics on)

- **Start:** the screen shows "Not set up. Open the app to set up this board, or to recover it." The serial line reads `started: Blank, 0 key trees`.
- **Start-up diagnostics were partly lost:** the capture reads `winterlock-board 0.1.0 (test build: screek-bflash: 4194304 bytes; ...`. The rest of the first line, the `rng:` line and the `display:` line are missing, cut while the board restarted on the port's open. Not looked into further.
- **STATUS over the link** (`board_client.py`): `protocol 1, version 0.1.0, state blank, test_hooks False, storage_used 24 of 3,080,192`.
- **`board_client.py`'s first request is lost.** `board_client.py --serial /dev/ttyUSB0 status` timed out after 60 s ("no answer to request 1"): opening the port restarted the board, and STATUS went out while it booted. The Python client doesn't retry (the app's client does, `app/src/board/client.ts`, `short`). Waiting about 4 s after the open, then asking, answers at once. **Suggested fix:** wait for BOOTED or retry STATUS in `SerialLink`/`Board`, as the app does.

## The app with the board

App from `board-app` at `ccebaac`: Node 24.20.0, wasm-bindgen 0.2.130, `npm run dev` (Vite 7.3.7) on http://localhost:5173.

**Browsers on Ubuntu:**

| Browser | Result |
|---|---|
| Firefox 158 (snap) | **Fails:** "no ports available". The snap has no `serial-port` or `raw-usb` connection, so the port is invisible to it. Firefox has Web Serial since 151; Mozilla's `.deb` build was not tried. |
| Brave 1.80.124 (Chromium 138) | **Fails:** the port is listed, but right after it's chosen the app says "The board's link closed (the board's serial port closed)", every time. Nothing in the console or `brave://device-log`. The browser ended the read stream (`app/src/board/serial.ts:100`); the cause wasn't found. |
| Brave 1.99.57 (Chromium 157) | **Works:** setup and enrolment below. |

The app's message "use Chrome or Edge" (`serial.ts:26`) could name what works: a recent Chromium-based browser, or Firefox 151 and later, but not the snap.

**Setup** on the board through the app: **works**: the words, the three-word check and the PIN, with the push buttons.

**Enrolment on Sepolia:** a Safe `0xb0ad7064b7fa1FFF27611DC800CF85D70C861075` (threshold 1, four owners, nonce 3); the board's owner `0x8c08fBFf5A359D2059a7De7776B76CB14C5460F3`.

| Block | Transaction | Tree root | Nonces | Gas |
|---|---|---|---|---|
| 12141344 | `0xe7a99b6c0b547a6aefa7c2f40283c4042b343249f48f69f31b21a2fe0b6d7c49` (`deployAndEnroll`) | `0xe86f08255baf…` | 3 to 514 | 606,041 |
| 12141352 | `0x5fef20c376fe73f55516b9089db27f45e820a87b063539f732de71880e5a973b` (`enroll`) | `0x19ca77ddaef9…` | 4 to 515 | 394,136 |

**What happened:** the first enrolment succeeded ("Enrolled a key tree for nonces 3 to 514, and created your owner contract (606,041 gas)"). Right after it, the Key tree panel showed its enrol button again. The member took that to mean another step was needed and clicked it. The board made and certified a second tree, and the app sent it. After the second, the button didn't come back. The board lists both trees.

**The consequence:** the owner contract holds one tree per Safe, so the second replaced the first. The first tree's keys were never used, and nothing leaked. But **the enrolled tree starts at nonce 4 while the Safe was at nonce 3**: the board can't sign nonce 3, and the app refuses it ("Nonce 3 is outside your key tree"). A new enrolment would start at 5, since a new tree always starts after the board's last one for that Safe. Another owner had to execute nonce 3 (threshold 1), which the ECDSA owner did (below). After that the board signs nonces 4 to 515. The void tree's records stay in the board's storage.

**Why the button came back (inference, not verified):** the panel shows the button when it doesn't see a usable tree (`app/src/screens/board.tsx`: `!usable || low || pending`). That happens when the owner or its tree isn't visible on-chain, or the tree isn't found on the board. After the enrolment, `boardEnrol` checks the tree at the block the transaction was mined in (`afterTx`). The panel's refresh (`onDone`) reads at the latest block instead, through `ethereum-sepolia-rpc.publicnode.com`, which spreads requests over several nodes. A node one block behind would show no owner contract, so no tree, and the button reads **Enrol**. The second enrolment didn't create anything, and its refresh found the tree.

**Suggested fixes:**
- Refresh the panel no earlier than the enrolment's block, or keep the enrolled tree from `boardEnrol`'s result until the chain shows it.
- Ask for confirmation when an enrolment would replace a tree enrolled minutes ago, or one with all its nonces left, and say that the new tree starts after it.
- Possibly: while the Safe's nonce is below the enrolled tree's start, say so in the panel and name the way out (another owner executes).

## Confirming a transaction

**Nonce 3** was executed by the ECDSA owner `0x8db6B632D743aef641146DC943acb64957155388`: 0.001 ETH to itself. The Safe moved to nonce 4, the first nonce of the board's tree.

**Nonce 4** was proposed in the app and confirmed on the board. The Safe accepts the board's signature, but the transaction can't execute:

| | |
|---|---|
| SafeTx hash | `0xc61a3aa1c7ff95cfeb0d59aa20f9eae0d0afb4599765a01d37c3f2a992a89f78` |
| Transaction | 0.01 ETH to `0x8c08fBFf5A359D2059a7De7776B76CB14C5460F3`: **the board's own owner contract**; no data, CALL, `safeTxGas` 0, `gasPrice` 0 |
| Confirmation | the board's owner, a contract signature of 1,855 bytes (Safe's Transaction Service: `CONTRACT_SIGNATURE`, 1 of 1) |
| Execution | the ECDSA owner couldn't execute it: it reverts |

**Why, from a trace** (`execTransaction` from the ECDSA owner on a fork of Sepolia, anvil, 182,843 gas):
1. `checkSignatures` → the owner's `isValidSignature(0xc61a3aa1…)` → the verifier `0x272138c7…` returns the root `0x19ca77ddaef95687b101182aa105f3486f2b63f76dcd5dc1`, the enrolled tree's root. The owner answers `0x1626ba7e`: **the board's WOTS signature is valid on-chain.**
2. The Safe then calls `0x8c08…` with 0.01 ETH. The owner proxy emits `Transfer` and delegates to its implementation `0x114caAB223BaccD9BcA92C28ABBCf1edC0C3bCdf`, which reverts: `WinterlockOwner` (`contracts/src/safe/WinterlockOwner.sol`) has no `receive` or `fallback`.
3. With `safeTxGas` and `gasPrice` at 0, Safe v1.4.1 reverts the whole `execTransaction` when the inner call fails.

`eth_call` of a plain 0.01 ETH transfer from the Safe to `0x8c08…` reverts the same way.

**The way out, and the second key:** the app always proposes at the next free nonce (`nextNonce`, `app/src/lib/flows.ts`), here 5, so it can't propose a second version of nonce 4. It can confirm one proposed elsewhere (`boardConfirm`):
1. In Safe's web app the ECDSA owner chose **Reject** on nonce 4. That made a rejection, 0 ETH from the Safe to itself (`0x99fcf517429813e7e529b641f61fae0272e3c797893d6c6bae02a6f22dea69fd`), which the ECDSA owner signed without executing.
2. In the app the rejection showed as pending and was **confirmed on the board**.
3. The app **executed** it: transaction `0x0e186ff9d6186a7d2bc6c570da855ebc0aeb87bff1b2fdd12617856a3bbb6f26`, block 12141485, 176,949 gas, from `0xB75FC5C6AB455c6bb8e6C6333be82F63A4fb357C`. The Safe moved to nonce 5.

Checked on-chain and at Safe's service:
- **Only the board's signature was sent:** the `signatures` argument is a single 1,855-byte contract signature for `0x8c08…`. The app sorts the valid signatures by owner and sends as many as the threshold (`execute`, `flows.ts:717`), and `0x8c08…` sorts before `0x8db6…`. So the Safe executed on the board's WOTS signature alone.
- **The two versions used nonce 4's two keys:** the first byte of the signature data is the slot, `00` for the transfer (`0xc61a3aa1…`, never executed) and `01` for the rejection. Both signatures carry the enrolled tree's root.

This is the board's first signature that went through a real execution. It also covers the key log's second version at one nonce on the chip.

**Nonce 5, the plain case:** 0.02 ETH to the ECDSA owner, proposed in the app, confirmed on the board and executed from the app. The board's signature (slot `00`) was the only confirmation:

| | |
|---|---|
| SafeTx hash | `0xb2effbd3ab7e89d2d6f00270c5215472c7d8d693e9910de5406f86c85480d2ea` |
| Execution | `0xf31e03182561c435ba881ba180cbc302778cd618e707b2356d2457a8ffdc815d`, block 12141504, 187,161 gas, from the gas account `0xB75FC5C6…` |

The Safe is at nonce 6.

**Suggested fix:** neither the app nor the board's logic checks the recipient against the member's owner contract. Since an ETH transfer to it always reverts, the app should refuse to propose one, and the board should refuse or warn before signing. The board would otherwise spend one of the nonce's two keys on a transaction that can never run.

## Not tested yet

- **A third version at one nonce, refused by the board's key log.** Nonce 4 was executed before it could be tried, and the app refuses a used nonce before the board sees it. To test it, keep a nonce open: propose version 1 in the app, then versions 2 and 3 in Safe's web app, and confirm each on the board. Execute only at the end.
- **Other transactions on the board:** a token transfer, approveHash with the parent's fields, a call that isn't decoded, a refused delegate call.
- **Unlock after a restart** (the PIN), **three wrong PINs** (the board erases itself), and **recovery** from the words.
- **Power cuts and flash wear** on the real chip.
- **Times on the chip** for setup, enrolment and a signature (not measured this time).
- **The touch-button build** (`--features touch-buttons`): not needed for this board.
- **The release image** (no diagnostics): the README puts the diagnostics build first.
- **BOOT** in the bring-up image (case closed).

## The core check on the same chip (same day)

- **0.2.0:** 90 of 90 checks pass. A phrase's ERC-8499 root took 25.2 s, nearly all of it PBKDF2.
- **0.2.1** (`esp32-check-erc8499` at `3b9c5c3`, built here: 416,688 bytes, SHA-256 `599ca8399ba82bf15e4726e1129a34711f2ba2017af9d0ccebb7009726b2f88f`, not byte-identical to the image built upstream):
  - all 36 ERC-8499 checks pass
  - phrase root **483.6 ms** mean (PBKDF2 481.0 ms)
  - member key seed 836 µs, gas key 817 µs, device root 1.1 ms, tree secret seed 1.0 ms
  - the run was stopped after the ERC-8499 lines

  These numbers are recorded on that branch (`7de4366`).

## Looked into afterwards (branch `board-run1-fixes`)

- **The second enrolment.** The board didn't cause it: after ENROLLED it rests on a result screen and answers TREES. The owner contract takes a new tree only from a later start than the enrolled one's (`enroll`: "within a generation, start nonces only grow"), and the board only from a later one than its own last tree's for the Safe. So any enrolment while the board holds an unused tree pushes the start past the Safe's nonce. A node behind the others answering "latest" was seen on the same endpoint on 2026-11-13 (`app/test/after-tx.test.ts`). It fits the panel's refresh, though this run can't show which read was stale. Fixed in three places:
  - The views read no state older than the block that mined the app's last transaction on that chain. They ask again while a node lacks that block (`readFresh` in `app/src/lib/chain.ts`).
  - Enrolment refuses while the board holds a tree for the Safe none of whose nonces is used (`needlessEnrolment`), and the browser-key path does the same.
  - The Key tree panel offers no enrolment while the board's trees are unknown. While the Safe's nonce is below the tree's first, the panel says so and names the way out.
- **The start-up lines.** Not a restart: the log shows one boot. `Uart::new` empties UART0's transmit FIFO (esp-hal 1.2.2: "Applying config also resets Tx/Rx FIFOs"), so up to 128 bytes of esp-println's output were lost. The `k-b` in the capture is a stale piece of `winterlock-board` from the FIFO's memory. The test build now waits for the FIFO to empty before taking the UART.
- **`board_client.py`:** STATUS, TREES, GAS_KEY and CANCEL are asked again after 4 s without an answer, and at once after BOOTED, as the app's client does.
- **Browsers:** the app names an up-to-date Chrome, Edge or Brave. An empty chooser explains the cable, "Show all serial ports" and the Snap Store's Firefox. A port that closes within 5 s of opening says an older browser can do this.
- **ETH to the owner contract.** Confirmed: `WinterlockOwner` has no `receive`, `fallback` or payable function, and an `eth_call` from the Safe with ETH to `0x8c08…` reverts, with or without data. A token transfer to it is worse: it succeeds, and the tokens stay there, since the contract can't move them. Fixed on both sides:
  - The app refuses ETH, an empty call or a token transfer to any Winterlock owner contract, the member's own or another member's. It recognises them by their code. The check covers each call of a batch and an approveHash's parent, and runs before a key signs, for proposals and confirmations alike (`refusePaymentToOwner`). The Send screen refuses at Review, and warns when the Safe's call fails now (too little ETH, a recipient that refuses it).
  - The board refuses ETH or a known token to its own owner contract, in the transaction or a parent's, before it shows anything (`decode::to_own_owner`).
- **The Safe of this run:** the ECDSA owner executed nonce 3, the board signed nonces 4 and 5, and the Safe is at nonce 6. The tree from nonce 3 stays in the board's storage, void.

## Files

| File | What |
|---|---|
| `bringup-start-echo-reopen.log` | the bring-up image's start report, the echo and the reopened port (no display yet) |
| `bringup-buttons.log` | the button presses, with host timestamps |
| `bringup-oled.log` | after the VCC fix: the OLED at 0x3C and an echo |
| `signer-first-start.log` | the signer's first start, blank, with its binary frames |
