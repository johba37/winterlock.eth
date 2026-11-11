# Winterlock signer app

The signer without a terminal: a browser app for members of a Safe whose owners are Winterlock owner contracts (owner v2). It runs on desktop browsers and on phones, and signs with the Rust core (`core/`) compiled to WebAssembly. Design: [docs/notes/signer-app.md](../docs/notes/signer-app.md). First build: decisions.md, "2026-11-07: the signer app, first build".

**Research prototype, Sepolia only.** The contracts are not audited.

## What it does

- **Create:** makes the recovery phrase in the browser, shows the 24 words once and asks for three of them back (no skip). The member key then certifies this browser as device 1, and the app forgets the phrase and the member key.
- **Pair this device:** the member types the phrase on another browser or phone. The app makes a key for the next free device number, certifies it with the member key, sends the certificate and forgets the phrase.
- **Join a Safe:** shows the owner address and the steps for the Safe's owners in Safe's app. The app doesn't create Safes.
- **Enrol:** a key tree per Safe and chain, height 10 (512 one-time keys, two per nonce).
- **Transactions:** the Safe's queue from Safe's Transaction Service, decoded (ETH, ERC-20 transfers, anything else marked raw); confirm; propose an ETH or ERC-20 transfer; execute once confirmed.
- **Revoke a device,** with the phrase.
- **Settings:** the RPC URL per chain, the gas account with its balance and a QR code.

One gas account per member, derived from the phrase, pays for everything on-chain: the owner contract, certificates, key trees and executions.

## With a board

In the round, the board is each member's only device (docs/notes/signer-app.md, decision 7): it holds the member key (device 0), its key trees and their key log, and signs every enrolment and confirmation after showing it. The app talks to it over USB and holds no key but the gas account's, which the board gives it after an unlock. The app without a board stays the development path and the fallback.

- **Use a board** (on the welcome screen): connect it by USB, or start the virtual board (development builds only). A blank board is set up on the board (the app adds 32 random bytes to its seed) or recovered on it from the 24 words; a board that is set up is taken as it is. The app checks the owner address against the member key and keeps the gas key the board gives (`GAS_KEY`).
- **A locked board:** the app says to enter the PIN on the board, and reads its status every 1.5 s until it is unlocked.
- **Enrol:** the board makes a key tree for the Safe and signs its certificate once the member confirms on it; the app checks the certificate with the core and sends it from the gas account. The first enrolment on a chain creates the owner contract with it (`deployAndEnroll`). A certificate the board signed is kept until it is sent.
- **Confirm and propose:** the app checks the Safe, the hash (here and by the Safe) and the tree enrolled on-chain, then sends the fields to the board, never a hash. For an `approveHash` on a parent Safe, it fetches the parent's transaction from Safe's service and sends its fields along; the board checks them. The app checks the board's signature with the owner contract before it posts it. Long requests show what to do on the board and can be cancelled; once the member has confirmed on the board, the board finishes.
- **Execute** as without a board, paid by the gas account.
- **Not with a board:** device pairing and revoking, the stale-log check (the key log is the board's own), messages and dapps.

**The link** (`src/board/`): one transport interface with two implementations. **Web Serial** (`serial.ts`, Chrome and Edge on a computer): the chooser lists the usual USB serial chips (CP2102 `10c4:ea60`, CH340 `1a86:7523`, CH9102 `1a86:55d4`, FTDI `0403:6001`), or every port on request; 115200 baud; DTR and RTS low; an unplugged port's link closes, and when the same port comes back the app opens it again. **The virtual board** (`virtual.ts`): the board's own logic (`hardware/board-signer/logic`) in WebAssembly (`hardware/board-signer/wasm`) in a worker, its flash in IndexedDB, its randomness from `crypto.getRandomValues`. The client (`client.ts`) speaks PROTOCOL.md: frames found among the bootloader's text by the magic and both CRCs, an id per request, BOOTED (the board restarted: what it was doing is dropped), no timeout on the requests that wait for the member, retries on the short ones.

**The virtual board** is a development board whose keys live in the browser, and the page labels it so. Only the dev server, the tests and a build with `VIRTUAL_BOARD=1` have it: `npm run build` leaves it out, its WebAssembly and worker included (decided 2026-11-11). The page draws its 128×64 screen and its buttons (keys: ← and →, ↓ or B for both held) and can restart it. Its flash is saved sector by sector in a strict-durability IndexedDB transaction after each request or button press, and only then does what the board sent reach the app, so a signature never leaves before its key log record is stored. One virtual board runs per browser profile: its worker holds a Web Lock, and a second tab's board doesn't start. It runs without the test hooks.

## Run

```sh
cd app
npm ci
npm run wasm        # builds core-wasm/ and the virtual board into src/wasm/ (needs the wasm32 target and wasm-bindgen-cli 0.2.130)
npm run dev         # http://localhost:5173
```

The core's bindings are in `core-wasm/`, a separate crate, so `core/` stays `no_std` and free of wasm-bindgen. The virtual board's are in `hardware/board-signer/wasm/` for the same reason.

## Test

```sh
npm test            # unit tests: vitest, fake-indexeddb, the WebAssembly in Node
npm run typecheck
npx playwright test e2e/bench.spec.ts    # the core's timings in Chromium's worker
```

The unit tests cover the Python vectors through the app's encodings, the key log store (record, then sign), two and three tabs racing for one key, and the stale-log check against a copied browser. With a board: the link's frames, CRCs and payloads against the Python client's (`hardware/board-signer/tools/frame_vectors.py`), and the virtual board through the board client in whole flows, every output checked with the core (`test/board.test.ts`).

**With a board, on a local chain** (anvil with Sepolia's chain id, the contracts at their pinned addresses, a stand-in for Safe's service; spends nothing):

```sh
WINTERLOCK_PYTHON=../signer/.venv/bin/python E2E_PORT=5291 npx playwright test e2e/board.spec.ts
QEMU=.../qemu-system-xtensa BOARD_TEST_IMAGE=.../winterlock-board-test-qemu.bin \
WINTERLOCK_PYTHON=../signer/.venv/bin/python E2E_PORT=5291 npx playwright test e2e/serial.spec.ts
```

- `board.spec.ts`: the virtual board in Chromium, through the app's screens and the board's drawn screen and buttons.
- `serial.spec.ts`: the app's Web Serial code against the firmware's test image in QEMU. A stand-in for `navigator.serial` in the page (`e2e/fake-serial.js`) bridges its port to QEMU's TCP serial port; the test presses the board's buttons with the test image's hooks on the same port.
- `device-local.spec.ts`: the app without a board, on the same local chain.

**With the virtual board, live on Sepolia** (as the live run above, from the same `.env`; stops past 0.03 ETH): `E2E_DIR=... WINTERLOCK_ENV_FILE=... npx playwright test e2e/live-board.spec.ts`. A Safe made by script whose ECDSA test owner adds the board's owner with threshold 2; the board and that owner each propose a transfer the other confirms.

**Live, on Sepolia** (spends test ETH; each step runs once and is skipped on a re-run):

```sh
E2E_DIR=/some/scratch/dir \
WINTERLOCK_ENV_FILE=../contracts/bench/bundlers/.env \
WINTERLOCK_PYTHON=../signer/.venv/bin/python \
npx playwright test e2e/live.spec.ts
```

- `WINTERLOCK_ENV_FILE` needs `ALCHEMY_API_KEY` and `FRESH_EYES_GAS_KEY` (a funded Sepolia account). The run stops past 0.025 ETH.
- `E2E_DIR` gets the run's state, the browser profiles, a throwaway phrase and test keys, and screenshots at phone and desktop sizes. Keep it out of the repository.
- The Python signer plays the Safe's other member. It reads `SAFE_API_KEY` from the same file; the app uses no key.

## Build

```sh
npm run build       # WebAssembly, type check, then dist/
```

`dist/` is a static site. Its Content Security Policy allows scripts only from the app itself; nothing loads from another server at run time, and there is no analytics. RPC endpoints and Safe's service are the only network peers.

## Published

**`https://app.winterlock.eth.limo`** serves the build of commit `a20d51c`, IPFS hash `bafybeiga42jsit5a4tzyp6cd75lwhbgoe5et6inocbaqxlzypfcjgs6gsi`. The name resolves through a record on winterlock.eth's resolver, not through a subname. The reason is in docs/decisions.md, "2026-11-07: the app published at app.winterlock.eth".

To check that the hash comes from this code, build that commit and hash `dist/` with [kubo](https://docs.ipfs.tech/install/command-line/):

```sh
git checkout a20d51c && cd app && npm ci && npm run build
ipfs add -r -n -Q --cid-version=1 dist
```

A second build on the same machine gave the same hash; a build on another machine hasn't been compared yet. That build used rustc 1.98.1, wasm-bindgen 0.2.130 and Node 24.14.0.

The site's storage belongs to its origin. Serving the app from another address gives an empty app, without the device keys stored at `app.winterlock.eth.limo`.

## Rules it keeps (docs/notes/signer-app.md, "Risks a browser adds")

- **Storage:** the device key, its key log and the gas key live in IndexedDB, unencrypted in this round. The app asks for persistent storage.
- **iOS:** no device key unless the app runs installed (standalone). The install steps are in the app.
- **Record before signing:** every one-time signature is recorded in a strict-durability IndexedDB transaction, completed, under a Web Lock for the device, before the core signs. The core signs only from a store that already holds the use (`core-wasm/src/lib.rs`, `src/lib/keylog.ts`).
- **Stale-log check:** before every one-time signature, the app compares the signatures of this device's key tree at Safe's service and in executions on-chain with its key log, and refuses if any is missing (`src/lib/stale.ts`).
- **Heavy work in workers:** keys, trees and signatures run in Web Workers, with progress. The member key lives only in a worker that is terminated after it signs.

## Development notes

- **RPC keys:** an RPC URL may carry an API key. The app shows only its host. For your own testing, set the URL in Settings; nothing in the build reads a key.
- **Safe's service through a key** (only if keyless writes stop working): `SAFE_API_KEY=... VITE_SERVICE_PROXY=/safe-service npm run dev` routes the app's writes through the dev server, which adds the key. It's development only and never bundled.
- **Icons:** `npm run icons` renders the PNG icons from `docs/brand/mark.svg`.
