# A signer without a terminal: design note (proposal, 2026-11-06)

**Status:** proposal. Decided by the user on 2026-11-06: one Rust core for the browser and an ESP32 board, a TypeScript app around it, Arbitrum One with play money, and the decisions below. An ESP32 timing firmware is being built (branch `esp32-bench`); its numbers decide whether the board can hold the member key in the first round.

## Why

The Python signer (`signer/`) works and stays the reference, but it needs a terminal, a Python install and environment variables. The first users outside the project don't use a terminal. They sign on laptops and phones: macOS, iOS, Android and Linux.

Their use should find the edges before the normative spec fixes the formats. The spec waits for this round.

**Chain:** Arbitrum One, with amounts people can afford to lose: the contracts are not audited. Development and tests run on Arbitrum Sepolia. Deterministic deployment gives the same addresses on both, and on Sepolia.

## Three parts

| Part | Language | Runs on | Holds |
|---|---|---|---|
| **Core** | Rust, `no_std` with `alloc` | the browser (WebAssembly), the ESP32 (firmware), native tests | nothing: functions and the key log's rules |
| **App** | TypeScript | a current browser, installed to the home screen on phones | a device key, its key log, a gas account |
| **Board** | Rust firmware on the core | ESP32-WROOM-32 with a 128×64 OLED and the BOOT button | the member key: it makes the phrase, and pairs and revokes devices (decision 2) |

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

**Which keccak:** the faster of the RustCrypto and `tiny-keccak` crates on the ESP32 (the timing firmware measures both).

**Tests:** native (`cargo test`), WebAssembly under Node, and a `no_std` build for the ESP32 on every change. Each runs the Python vectors.

## The app

### Where the keys live

- **The board makes the phrase and keeps the member key** (decision 2). It shows the 24 words once, a few per screen. The member writes them down and types three of them into the app, which hands them to the board to compare; there is no skip (as in signer-recovery.md). From then on the board pairs and revokes devices. The phrase is typed again only for a recovery: a lost or broken board.
- **Without a board** (if the timings rule it out, or for a member who has none), the app makes the phrase the same way, uses the member key to pair this device, and forgets both. The phrase is then typed into the app whenever a device is paired or revoked, and every device that has seen it could have leaked it.
- **So the app always signs with a device key** (owner v2, devices 1–3): laptop, phone and a spare. A revoked slot can be certified again with a new key.
- **The device key** is in the browser's IndexedDB, unencrypted in the first round (decision 3). The device's own screen lock protects it, and a lost or stolen device is revoked. Until then, anyone using the unlocked device, or malware in that browser, can sign as the device. An unlock with the device's passkey waits until the round asks for it.
- **The gas account** is an ordinary account that the app creates. It pays for the owner's deployment, certificates, enrolments and executions. It isn't an owner. A few dollars of ETH on Arbitrum last a long time.
- **Losing the browser's data** loses the device key: revoke it and pair the device again, with the phrase. No one-time key can be used twice, because the key log goes with the key.

### Risks a browser adds, and the rules against them

- **Eviction.** Safari on iOS deletes a site's storage after seven days of use without a visit, unless the site is installed to the home screen. On iOS the app makes no device key until it runs installed. Everywhere it asks for persistent storage.
- **Two tabs signing at once** could take the same one-time key. Every "record, then sign" holds a Web Lock (`navigator.locks`) for the device.
- **Copies.** A phone restored from a backup, or a synced browser profile, brings back an old key log. Unlike the Python signer, a browser has no anchor files to notice that. So before every one-time signature, the app checks the chain and Safe's service. If either holds a signature by its tree that its log doesn't record, it refuses and says to revoke and pair again. The app is online when it signs anyway.
- **One origin.** A browser keeps storage per origin. Another gateway's URL is a different, empty app. The app has one URL (decision 4).
- **Whoever serves the code holds the keys.** Anyone who can change the ENS content hash, or the gateway, serves the code that unlocks the device key. That's acceptable for play money. Before real money: a reproducible build whose IPFS hash people can check, or a shell such as a browser extension.

### What it does in the first round

1. **Create:** with the board connected, the board makes the phrase and the app runs the check. The app shows the owner address and pairs itself as device 1.
2. **Add a device:** the new device shows its key, as a QR code or a link, and its check code. The app connected to the board passes the key on; the board shows the check code it computed and signs the certificate on a press of BOOT, once both codes match. An iPhone is paired this way too, through a laptop or an Android phone.
3. **Join the Safe:** the members' existing Safe (decision 5). The app shows the owner address, and the Safe's current owners add it in Safe's app (Settings, Owners). The owner contract is deployed with the first certificate, paid by the gas account.
4. **Enrol:** a key tree per Safe and chain, prompted when it's missing or running out.
5. **Transactions:** a queue from Safe's service, decoded; confirm; propose a transfer; execute once confirmed.
6. **Dapps over WalletConnect** (Reown's wallet SDK): sign-in, transactions, permits, with the rules of walletconnect.md, "Which path a message takes".
7. **Revoke a device** from the board (or with the phrase, without a board).

**Not in the first round:** moves (device keys never move), several chains at once. A lost board is replaced by typing the phrase into the app once, which loads it onto a new board; the browser sees the phrase then.

**Phones and WalletConnect:** a web app can't receive a dapp's deep link on a phone. The user copies the pairing link into the app, or scans the QR code from another screen. Requests wait at the relay while the app is closed; iOS doesn't run web apps in the background.

### Stack

TypeScript, Vite, Preact (small enough for phones), viem for RPC, ABI and EIP-712, Reown's WalletKit, and the core through `wasm-bindgen`. A static build, no server, pinned on IPFS like the landing page.

## Arbitrum

- **Deployment:** the four shared contracts through the deterministic deployment proxy, as on Sepolia: same addresses. On Arbitrum One it costs real ETH, a few dollars (measured first on Arbitrum Sepolia), from a fresh deployer funded by the user.
- **Fees:** Arbitrum charges for the L1 data in L2 gas. Winterlock transactions are calldata-heavy (1.8 KB per signing owner, 5.9 KB per enrolment or certificate), so that part dominates. Still cents; measured on Arbitrum Sepolia first.
- **Blocks every 250 ms:** a free RPC tier that limits log queries to 10 blocks covers 2.5 seconds. The app finds executions through receipts and Safe's service, not log scans.
- **Safe's Transaction Service** runs for Arbitrum One (`arb1`).

**The members' Safe.** Winterlock owners join it next to its current owners, and Safe counts them like any other owner. All Winterlock owners share one implementation, so a bug that accepted a forged signature would forge all of them at once. While the Winterlock owners are fewer than the threshold, such a bug can't move funds on its own. Tested on Safe v1.4.1 and v1.5.0; an older Safe needs a check first.

**To check first:** whether a browser may post proposals and confirmations to Safe's service without an API key. Reads work without one: on 2026-11-06 the Sepolia service answered without a key and allowed any site to call it, with a rate limit. If writes need a key, the options are a key per user (poor), a small proxy holding ours (a server), or confirmations passed between members as links or QR codes (a signature is about 1.8 KB).

## The board (if the timing firmware says yes)

- **Hardware:** ESP32-WROOM-32 (classic ESP32, two cores at 240 MHz), a 0.96-inch SSD1306 OLED (128×64, I2C), and the board's BOOT button as "confirm". Four wires: VCC to 3V3, GND to GND, SDA to GPIO21, SCK to GPIO22.
- **Work per operation,** counted with the Python signer (keccak permutations):

  | Operation | Permutations |
  |---|---|
  | One-time signature (a Safe transaction) | about 3.9k on average, up to 19k |
  | Stateless signature | about 142k on average, up to 291k |
  | A device key, once | about 239k |
  | A key tree of 512 nonces (height 10) | about 849k |
  | A key tree of 32 nonces (height 6) | about 53k |

  The firmware measures permutations per second and turns these into times. Key trees and most of a stateless signature can use both cores.
- **Connection:** USB serial from Chrome or Edge on macOS, Windows and Linux; Bluetooth LE from Chrome on Android. **Not from an iPhone:** no browser on iOS lets a web page reach USB or Bluetooth.
- **As the member key's home** (decision 2), it:
  - makes the phrase from its hardware random number generator with the radio on (the classic ESP32's generator is only truly random then), mixed with randomness from the app
  - shows the phrase once, and compares the three words the app passes on
  - keeps the seed in its flash
  - signs device certificates and revocations after showing the device number and check code, on a press of BOOT
  - can also sign Safe transactions as device 0, showing the Safe, nonce, recipient and amount it computed from the fields
- **Security:** no secure element. Someone holding the board can read its flash, and published fault-injection attacks read keys out of early ESP32 revisions even with flash encryption. Since the board holds the member key, a stolen board means a member replacement, as a leaked phrase does. Fine for play money, not more.
- **The ESP32 accelerates SHA-256, not keccak.** Changing the hash changes the contracts (D9), so it stays a last resort.

## Decisions

Decided on 2026-11-06:
1. **Arbitrum One with play money; Arbitrum Sepolia for development.**
2. **The board makes the phrase, shows it once, and keeps the member key;** it pairs and revokes devices. The phrase is typed again only for a recovery. This keeps the phrase out of browsers: a leaked phrase would make revoking devices pointless (owner-v2.md, "The question behind several devices"). It suits a slow board: certificates are rare. If the timings rule it out, or for a member without a board, the app makes the phrase and forgets it, and it's typed into the app to pair or revoke.
3. **No unlock in the first round.** The device's screen lock protects the device key. A passkey unlock waits until the round asks for it.
4. **Its own name, `app.winterlock.eth`,** so changes to the landing page can never touch the app's storage. Served through eth.limo, pinned on IPFS. The user creates the subname and sets its content hash.
5. **No Safe creation:** the members join their existing Safe.
6. **On iOS, the app runs only when installed to the home screen.**

## Order

1. **Checks:** the ESP32 timings (running); posting to Safe's service without an API key; owner v2 on Arbitrum Sepolia (the testnet deployer has funds there).
2. **The core,** with the Python vectors, building for native, WebAssembly and the ESP32.
3. **The app and the board's firmware, on Arbitrum Sepolia:** create, add a device, join a Safe, enrol, transfer, confirm, execute, dapps, revoke. A fresh-eyes run by an agent through the app's screens; the board's screens on the user's board.
4. **Arbitrum One:** deploy (user-funded), the user and one other person end to end, then the rest of the round.
5. **The normative spec,** after the round, from this note, owner-v2.md and the code.
