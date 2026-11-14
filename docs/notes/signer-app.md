# A signer without a terminal: design note (proposal, 2026-11-06)

**Status:** proposal. Decided by the user on 2026-11-06: one Rust core for the browser and an ESP32 board, a TypeScript app around it, Arbitrum One with play money, and the decisions below. On 2026-11-07: the app first, without a board, developed on Ethereum Sepolia. An ESP32 timing firmware is built (branch `esp32-bench`); its numbers decide whether the board can hold the member key in the first round. **The core is built (2026-11-07, branch `rust-core`):** it matches the Python vectors byte for byte natively, under Node, in QEMU and on the ESP32 itself (all 54 board checks pass, 2026-11-10; decisions.md, "2026-11-07: Rust core"). **On 2026-11-10 the user decided: in the round, the board is each member's only device,** over USB, with two buttons and a PIN (decision 7). The app without a board stays the development path and the fallback. **The board's firmware is built the same day, before the hardware** (`hardware/board-signer/`): natively, as screen images and in QEMU, not yet on a board (decisions.md, "2026-11-10: the board signer, before the hardware").

## Why

The Python signer (`signer/`) works and stays the reference, but it needs a terminal, a Python install and environment variables. The first users outside the project don't use a terminal. They sign on laptops and phones: macOS, iOS, Android and Linux.

Their use should find the edges before the normative spec fixes the formats. The spec waits for this round.

**Chain:** Arbitrum One, with amounts people can afford to lose: the contracts are not audited. Development and tests run on Ethereum Sepolia, where owner v2 is deployed and Safe's app and Transaction Service run. Safe's service doesn't run on Arbitrum Sepolia (its chain list has only Arbitrum One, checked 2026-11-07). Deterministic deployment gives the same addresses on every chain.

## Three parts

| Part | Language | Runs on | Holds |
|---|---|---|---|
| **Core** | Rust, `no_std` with `alloc` | the browser (WebAssembly), the ESP32 (firmware), native tests | nothing: functions and the key log's rules |
| **App** | TypeScript | a current browser, installed to the home screen on phones | with a board, only the gas account; without one, also a device key and its key log |
| **Board** | Rust firmware on the core | ESP32-WROOM-32 with a 128×64 OLED and two buttons | the seed: the member key (device 0), its key trees and their key log (decision 7) |

**Python stays the reference.** The core must reproduce its outputs byte for byte. The Python signer writes the test vectors; the core's tests read them on every target. These vectors become the normative spec's.

**Safe's app stays the team's view:** balances, queue, history. Anyone can execute a fully confirmed transaction there (tested on Sepolia, nonce 6). The app doesn't rebuild that.

## The core

**In:**
- keccak256, and the phrase: 24 BIP-39 words that encode the 32-byte seed (signer-recovery.md)
- leanSphincs-keccak: pruned keys (b = 10), signing, verifying
- WOTS (D6): keys, signing with the target sum, key trees and their paths
- owner v2: every digest (device certificate, revocation, tree certificate, message, tree seed), the SafeTx and SafeMessage hashes, the three signature layouts, the pairing check code
- **the key log's rules:** which one-time key may sign what, and that the record is stored before a signature leaves. Storage is the platform's: the app and the firmware each implement one small interface.

**Out:** RPC, Safe's Transaction Service, WalletConnect, screens, encryption at rest. These differ between browser and board.

**Fields in, not hashes.** The core computes the SafeTx hash from the transaction's fields. A board must show what it signs, so it can't take a hash on trust; the app decodes from the same fields.

**Which keccak:** the faster of the RustCrypto and `tiny-keccak` crates on the ESP32 (the timing firmware measures both, and so does the core's check firmware, inside the real operations). The core has both behind features; `tiny-keccak` is the default until then.

**Tests:** native (`cargo test`), WebAssembly under Node, and a `no_std` build for the ESP32 on every change. Each runs the Python vectors.

## The app

### Where the keys live

- **First without a board** (decision 2): the app makes the phrase and shows it once. The member writes it down and types three of its words back; there is no skip (as in signer-recovery.md). The app uses the member key to pair this device and forgets both. The phrase is typed into the app again whenever a device is paired or revoked, and every device that has seen it could have leaked it.
- **Later, the board makes the phrase and keeps the member key.** It shows the 24 words once, a few per screen, and compares the three words the app passes on. From then on the board pairs and revokes devices, and the phrase is typed again only for a recovery: a lost or broken board.
- **So the app always signs with a device key** (owner v2, devices 1–3): laptop, phone and a spare. A revoked slot can be certified again with a new key.
- **The device key** is in the browser's IndexedDB, unencrypted in the first round (decision 3). The device's own screen lock protects it, and a lost or stolen device is revoked. Until then, anyone using the unlocked device, or malware in that browser, can sign as the device. An unlock with the device's passkey waits until the round asks for it.
- **The gas account** is an ordinary account, one per member: its key comes from the phrase (its own label), so every paired device holds the same account and the member funds it once. It pays for the owner's deployment, certificates, enrolments and executions. It isn't an owner, and its key reveals nothing about the phrase. A lost device can spend it, which costs a few dollars at most. A few dollars of ETH on Arbitrum last a long time.
- **Losing the browser's data** loses the device key: revoke it and pair the device again, with the phrase. No one-time key can be used twice, because the key log goes with the key.

### Risks a browser adds, and the rules against them

- **Eviction.** Safari on iOS deletes a site's storage after seven days of use without a visit, unless the site is installed to the home screen. On iOS the app makes no device key until it runs installed. Everywhere it asks for persistent storage.
- **Two tabs signing at once** could take the same one-time key. Every "record, then sign" holds a Web Lock (`navigator.locks`) for the device.
- **Copies.** A phone restored from a backup, or a synced browser profile, brings back an old key log. Unlike the Python signer, a browser has no anchor files to notice that. So before every one-time signature, the app checks the chain and Safe's service. If either holds a signature by its tree that its log doesn't record, it refuses and says to revoke and pair again. The app is online when it signs anyway.
- **One origin.** A browser keeps storage per origin. Another gateway's URL is a different, empty app. The app has one URL (decision 4).
- **Whoever serves the code holds the keys.** Anyone who can change the ENS content hash, or the gateway, serves the code that unlocks the device key. That's acceptable for play money. Before real money: a reproducible build whose IPFS hash people can check, or a shell such as a browser extension.

### What it does in the first round

1. **Create:** the app makes the phrase and runs the check. It shows the owner address and pairs itself as device 1.
2. **Add a device:** on the new device, the member types the phrase into the app, which pairs that device and forgets the phrase. (With a board, later: the new device shows its key and check code, and the board signs the certificate on a press of BOOT once both codes match.)
3. **Join the Safe:** the members' existing Safe (decision 5). The app shows the owner address, and the Safe's current owners add it in Safe's app (Settings, Owners). The owner contract is deployed with the first certificate, paid by the gas account.
4. **Enrol:** a key tree per Safe and chain, prompted when it's missing or running out.
5. **Transactions:** a queue from Safe's service, decoded; confirm; propose a transfer; execute once confirmed.
6. **Dapps over WalletConnect** (Reown's wallet SDK): sign-in, transactions, permits, with the rules of walletconnect.md, "Which path a message takes". **Transactions are built (2026-11-13):** the member pastes the dapp's link on a Safe's dapps screen, and the dapp sees the Safe as its account. Each transaction it asks for, or batch of calls, is decoded and shown, and proposed with this device's confirmation once the member confirms. The dapp gets the SafeTx hash, and its status and receipt once the Safe has executed it; with threshold 1 the app executes at once and the dapp gets the transaction hash (walletconnect.md, "The app"). Messages, sign-ins and permits are refused until Safe's Transaction Service takes longer message signatures (decided 2026-11-13).
7. **Revoke a device** with the phrase (later, from the board).

**With the board (decision 7):** the board makes the phrase, so step 1 happens on it; there are no devices to add or revoke (steps 2 and 7); the board signs every enrolment and confirmation after showing it (steps 4 and 5). The app holds no key but the gas account.

**Not in the first round:** moves (device keys never move), several chains at once.

**Phones and WalletConnect:** a web app can't receive a dapp's deep link on a phone. The user copies the pairing link into the app, or scans the QR code from another screen. Requests wait at the relay while the app is closed; iOS doesn't run web apps in the background.

### Stack

TypeScript, Vite, Preact (small enough for phones), viem for RPC, ABI and EIP-712, Reown's WalletKit, and the core through `wasm-bindgen`. A static build, no server, pinned on IPFS like the landing page.

## Arbitrum

- **Deployment:** the four shared contracts through the deterministic deployment proxy, as on Sepolia: same addresses. On Arbitrum One it costs real ETH, a few dollars (measured first on Arbitrum Sepolia), from a fresh deployer funded by the user.
- **Fees:** Arbitrum charges for the L1 data in L2 gas. Winterlock transactions are calldata-heavy (1.8 KB per signing owner, 5.9 KB per enrolment or certificate), so that part dominates. Still cents; measured on Arbitrum Sepolia first.
- **Blocks every 250 ms:** a free RPC tier that limits log queries to 10 blocks covers 2.5 seconds. The app finds executions through receipts and Safe's service, not log scans.
- **Safe's Transaction Service** runs for Arbitrum One (`arb1`).

**The members' Safe.** Winterlock owners join it next to its current owners, and Safe counts them like any other owner. All Winterlock owners share one implementation, so a bug that accepted a forged signature would forge all of them at once. While the Winterlock owners are fewer than the threshold, such a bug can't move funds on its own. Tested on Safe v1.4.1 and v1.5.0; an older Safe needs a check first.

**To check first:** whether a browser may post proposals and confirmations to Safe's service without an API key. Reads work without one: on 2026-11-06 the Sepolia service answered without a key and allowed any site to call it, with a rate limit. If writes need a key, the options are a key per user (poor), a small proxy holding ours (a server), or confirmations passed between members as links or QR codes (a signature is about 1.8 KB). **Answered on 2026-11-07: writes work without a key too.** The app proposed and confirmed live on Sepolia from a browser origin with no key; keyless callers get 5,000 requests per window (decisions.md, "2026-11-07: the signer app, first build").

## The board

- **Hardware:** ESP32-WROOM-32 (classic ESP32, two cores at 240 MHz), a 0.96-inch SSD1306 OLED (128×64, I2C) and two buttons. The OLED: VCC to 3V3, GND to GND, SDA to GPIO21, SCK to GPIO22. The buttons: left on GPIO32, right on GPIO33; touch modules (high while touched) or push buttons to GND, set in the firmware. These pins don't take part in booting. BOOT (GPIO0) isn't used in normal operation.
- **Times on the board** (v1.0 chip, `tiny-keccak`, both cores; decisions.md, "2026-11-07: Rust core"):

  | Operation | Time |
  |---|---|
  | One-time signature (a Safe transaction) | 0.3 s on average, 0.5 s at most of 8 |
  | Stateless signature (a tree's certificate) | 15 s on average, 32 s at most of 4 |
  | The member key, once at setup (its pruned tree is then kept in flash) | 11.7 s |
  | A key tree of 512 nonces (height 10) | 42 s |

- **Connection:** USB, through the board's USB serial chip, from Chrome or Edge on macOS, Windows and Linux (Web Serial). **Not in the round:** Bluetooth LE. It would reach Chrome on Android, but it needs a radio stack on the board, puts a radio on the key's holder, and saves no cable, since the board is powered over USB. **Never from an iPhone:** no browser on iOS lets a web page reach USB, and only a third-party browser reaches Bluetooth.
- **Buttons:** left is back or no, right is next or yes, and holding both for about a second confirms. For the PIN, left and right change the digit and both move to the next one, as on a Ledger.

### What it does

- **Setup:** the board makes the seed from its hardware random number generator with the radio on (the classic ESP32's generator is only truly random then), hashed together with randomness from the app, so neither side alone sets it. (The first build uses the generator's other entropy source instead, the SAR ADC as ESP-IDF's bootloader does, with no radio stack.) It shows the 24 words, a few per screen, then asks for three of them, each picked from four choices. Then the member sets a PIN of 4 to 8 digits, twice. The board gives the app the member's public key, and both show the owner address.
- **Unlock:** the PIN, on the board, at every start. The board counts a try in flash before checking it, so pulling the cable doesn't reset the count. After three wrong PINs in a row it erases the seed and the key log; the paper phrase is the backup.
- **Enrol:** a key tree per Safe and chain, 512 nonces, from a random salt that never leaves the board. The board shows the Safe, the chain and the first nonce, and signs the tree's certificate on confirm (about a minute in all). The app sends it from the gas account.
- **Confirm a Safe transaction:** the app sends the fields, never a hash. The board computes the SafeTx hash and shows the chain, the Safe, the nonce and what the transaction does:
  - a transfer of ETH, or of a token from a short list built into the firmware: recipient and amount
  - `approveHash` on a parent Safe: the app sends the parent's fields too, the board recomputes the parent's hash, checks it against the call, and shows the parent's transfer
  - anything else: the target, the value and the function selector, marked as not decoded, with a second confirmation
  - a delegate call: refused (Safe's batches use one; not in the round)

  On confirm, the key log records the one-time key, then the board signs and sends the signature.
- **The gas account:** the board derives its key and gives it to the app after an unlock. It holds a few dollars and reveals nothing about the phrase.
- **Recovery:** the 24 words are entered on the board, letter by letter; the first four letters identify any word, and the checksum is checked. The old trees' salts were lost with the old board, so a recovered board can't rebuild their keys: it enrols new trees, which replace the old ones on-chain, before it signs.
- **Erase:** from the menu, with a confirmation.
- **Not in the round:** messages (ERC-1271), which need a stateless signature of 15 to 32 s; dapps.

### The USB link

Framed binary messages with a version, a length and a checksum: requests from the app, answers from the board. The board never sends the seed, a salt or any secret but the gas account's key, and it signs nothing without a confirmation on its own screen. A small Python client speaks the same messages for tests. Built: [PROTOCOL.md](../../hardware/board-signer/PROTOCOL.md), at 115200 baud, with a magic and two CRCs so frames are found among the bootloader's text.

### Storage

A flash partition holds the seed, the PIN's check value and its try count, each tree's salt, root and place, and the key log. Writes survive a pulled cable: a key log record is written and read back before its signature leaves, as the core requires. A tree's public nodes are public, so they can live on the board (about 64 KB per tree) or in the app. **Settled in the build:** the board keeps each tree's leaves (24 KB) and rebuilds the inner nodes before a signature (about 0.1 s), in an append-only log of records in a 3 MB partition; the member key's leaves are kept too.

### Before the hardware is ready

- **The signer as a crate without hardware:** button events and USB messages in, screens and answers out. Tested natively against the core's vectors, including power cuts in the middle of a write.
- **Screens as images:** every screen rendered to a PNG on the computer, for review before anything is soldered.
- **The firmware in QEMU,** with scripted buttons (as in the core check) and the Python client on QEMU's serial port: setup, unlock, wrong PINs and erasing, enrolment, confirmation, recovery, and QEMU killed in the middle of a key log write.
- **The app's board backend** against a virtual board: the same crate compiled to WebAssembly, so the app's flows run end to end on Sepolia without hardware.

**Only on the board:** the OLED and the buttons, USB with Chrome or Edge on each system, the random number generator with the radio on, and how the screens feel. A small test image goes first: display, both buttons, BOOT, and serial both ways.

**Built on 2026-11-10,** all but the app's board backend (`hardware/board-signer/`): the crate, the screens (87, as PNGs), the firmware in QEMU with the Python client, power cuts at every flash write natively and QEMU killed in the middle of a key log write, and an anvil run where Safes execute the board's signatures.

### Security

- **Nothing online holds a key** but the gas account. A compromised computer or a bad build of the app can't sign. It can only ask the board, which shows what it computed itself. Transactions it can't decode are signed blind, after a second confirmation.
- **No secure element.** Whoever holds the board and knows the PIN signs as the member. Without the PIN, a thief can still read the flash, and published fault-injection attacks read keys out of early ESP32 revisions even with flash encryption. The round's boards don't use flash encryption: it can't be undone and it complicates updates. A stolen board means a member replacement, as a leaked phrase does. Fine for play money, not more.
- **The derivation sits in one place,** so it can change before the round without touching the rest. It did: since 2026-11-14 the board's keys follow ERC-8499, as the app's (decisions.md, D15).
- **The ESP32 accelerates SHA-256, not keccak.** Changing the hash changes the contracts (D9), so it stays a last resort.

## Decisions

Decided on 2026-11-06:
1. **Arbitrum One with play money; Ethereum Sepolia for development.** (Changed on 2026-11-07 from Arbitrum Sepolia, where Safe's service doesn't run.)
2. **The board makes the phrase, shows it once, and keeps the member key;** it pairs and revokes devices (replaced in part by decision 7: in the round, the board is the only device). The phrase is typed again only for a recovery. This keeps the phrase out of browsers: a leaked phrase would make revoking devices pointless (owner-v2.md, "The question behind several devices"). It suits a slow board: certificates are rare. **The app comes first without a board** (decided 2026-11-07): it makes the phrase and forgets it, and the phrase is typed into the app to pair or revoke a device. The board joins later, after its timings.
3. **No unlock in the app in the first round.** The device's screen lock protects the device key. The board has a PIN (decision 7). A passkey unlock waits until the round asks for it.
4. **Its own name, `app.winterlock.eth`,** so changes to the landing page can never touch the app's storage. Served through eth.limo, pinned on IPFS. The user creates the subname and sets its content hash.
5. **No Safe creation:** the members join their existing Safe.
6. **On iOS, the app runs only when installed to the home screen.**

Decided on 2026-11-10:

7. **In the round, the board is each member's only device:** it holds the member key (device 0), its key trees and their key log, and signs every enrolment and confirmation; no device keys. Over USB from Chrome or Edge on a computer; every member has one. Two buttons and a PIN entered on the board, which erases itself after three wrong PINs in a row. The member key never touches a browser, and a compromised computer can't sign. The app without a board stays the development path and the fallback.

## Order

1. **Checks:** the ESP32 timings (2026-11-09); posting to Safe's service without an API key (**works**, checked live on 2026-11-07: see "To check first").
2. **The core,** with the Python vectors, building for native, WebAssembly and the ESP32. **Built on 2026-11-07** (`core/`, decisions.md, "2026-11-07: Rust core"):
   - everything under "The core" above, `no_std` with `alloc`; the key log's rules over a two-method storage trait, and a WOTS key signs only from the record its append returns
   - vectors from `signer/tools/core_vectors.py`; the tests pass natively with both keccak backends and in WebAssembly under Node, and the crate builds for `xtensa-esp32-none-elf` (`core/check.sh`)
   - natively about 3 to 4 times as fast as the Python signer
   - `hardware/esp32-core-check/` checks the core on the board and times the real operations with both backends: all 54 checks pass in QEMU and on a v1.0 board (2026-11-10). With `tiny-keccak`, the faster backend on the chip: a member key in 11.7 s on both cores, a stateless signature in 15 s on average (32 s at most), a height-10 tree in 42 s, a WOTS signature in 0.3 s
3. **The app, on Ethereum Sepolia,** without a board: create, add a device, join a Safe, enrol, transfer, confirm, execute, dapps, revoke. A fresh-eyes run by an agent through the app's screens. Then the board's firmware, with the board's screens on the user's board. **First build on 2026-11-07, everything but dapps** (`app/`, `core-wasm/`; decisions.md, "2026-11-07: the signer app, first build"):
   - the core in WebAssembly through a bindings crate, in Web Workers; the member key only in a worker that is terminated after it signs; the gas key derived from the phrase (`winterlock.app.gas.v1`, with a Python vector; since 2026-11-14 ERC-8499's application secret `winterlock.eth/gas`, decisions.md D15)
   - every rule under "Risks a browser adds": IndexedDB with persistent storage, no device key on iOS unless installed, record then sign in a strict-durability transaction under a Web Lock, the stale-log check at Safe's service and on-chain, no third-party code at run time
   - live on Sepolia through Safe's service without an API key, next to the Python signer: create, pair a second device, join a script-made Safe, enrol, propose, confirm and execute both ways, revoke the second device while its confirmation was pending, a copied browser that refuses, and the revoked device paired again
   - in Chromium's worker: the member key in about 0.12 s, a height-10 key tree in about 0.45 s, a stateless signature in about 0.07 s
   - still to do: Safari and phones, the fresh-eyes run, and messages over WalletConnect. Transactions over WalletConnect are built (2026-11-13; decisions.md, "2026-11-13: dapps over WalletConnect in the app")
4. **The board's firmware** (decision 7): the parts in "Before the hardware is ready", then on the user's board once it is wired with the OLED and two buttons. **Built on 2026-11-10 before the hardware,** except the app's board backend (`hardware/board-signer/`; decisions.md, "2026-11-10: the board signer, before the hardware").
5. **Arbitrum One:** deploy (user-funded; a first measurement of Arbitrum's fees), the user and one other person end to end, then the rest of the round.
6. **The normative spec,** after the round, from this note, owner-v2.md and the code.
