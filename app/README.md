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

## Run

```sh
cd app
npm ci
npm run wasm        # builds core-wasm/ into src/wasm/ (needs the wasm32 target and wasm-bindgen-cli 0.2.130)
npm run dev         # http://localhost:5173
```

The core's bindings are in `core-wasm/`, a separate crate, so `core/` stays `no_std` and free of wasm-bindgen.

## Test

```sh
npm test            # unit tests: vitest, fake-indexeddb, the WebAssembly in Node
npm run typecheck
npx playwright test e2e/bench.spec.ts    # the core's timings in Chromium's worker
```

The unit tests cover the Python vectors through the app's encodings, the key log store (record, then sign), two and three tabs racing for one key, and the stale-log check against a copied browser.

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
