# Winterlock signer app

The signer without a terminal: a browser app for members of a Safe whose owners are Winterlock owner contracts (owner v2). It runs on desktop browsers and on phones, and signs with the Rust core (`core/`) compiled to WebAssembly. Design: [docs/notes/signer-app.md](../docs/notes/signer-app.md). First build: decisions.md, "2026-11-07: the signer app, first build".

**Research prototype, Sepolia only.** The contracts are not audited.

## What it does

- **Create:** makes the recovery phrase in the browser, shows the 24 words once and asks for three of them back (no skip). The member key then certifies this browser as device 1, and the app forgets the phrase and the member key.
- **Pair this device:** the member types the phrase on another browser or phone. The app makes a key for the next free device number, certifies it with the member key, sends the certificate and forgets the phrase.
- **Join a Safe:** shows the owner address and the steps for the Safe's owners in Safe's app. The app doesn't create Safes.
- **Enrol:** a key tree per Safe and chain, height 10 (512 one-time keys, two per nonce).
- **Transactions:** the Safe's queue from Safe's Transaction Service, decoded (ETH, ERC-20 transfers, anything else marked raw); confirm; propose an ETH or ERC-20 transfer; execute once confirmed.
- **Dapps over WalletConnect** (transactions): paste a dapp's `wc:` link on a Safe's dapps screen, and the dapp sees the Safe as its account. Each transaction or batch it asks for shows decoded; on a confirm the app proposes it with this device's confirmation, and the dapp gets the SafeTx hash, then the execution's receipt and status. With threshold 1 the app executes it at once, and a transaction's answer is the execution's hash. Message requests are refused.
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

Dapps need a WalletConnect project ID (cloud.reown.com, free) at build time: `VITE_WALLETCONNECT_PROJECT_ID=... npm run dev`, or the same before `npm run build`. Without one, the dapps screen says so. A published build contains the ID, as every dapp's does.

## Test

```sh
npm test            # unit tests: vitest, fake-indexeddb, the WebAssembly in Node
npm run typecheck
npx playwright test e2e/bench.spec.ts    # the core's timings in Chromium's worker
```

The unit tests cover the Python vectors through the app's encodings, the key log store (record, then sign), two and three tabs racing for one key, the stale-log check against a copied browser, and what the app answers dapps (`test/dapp.test.ts`).

**WalletConnect on a local chain** (spends nothing; needs anvil, the Python signer's virtualenv and Reown's live relay):

```sh
WINTERLOCK_ENV_FILE=../contracts/bench/bundlers/.env \
WINTERLOCK_PYTHON=../signer/.venv/bin/python \
npx playwright test e2e/walletconnect.spec.ts
```

- `WINTERLOCK_ENV_FILE` needs `WALLETCONNECT_PROJECT_ID`; the config passes it to the dev server, and nothing prints it.
- A dapp on `@walletconnect/sign-client` runs in the test process. The app runs on anvil with Sepolia's chain id and a stand-in for Safe's service (`e2e/local.ts`, `e2e/fake-service.ts`).
- `E2E_PREVIEW=1` runs it against the production build instead, under its Content Security Policy.
- `e2e/live-walletconnect.spec.ts` does it live on Sepolia, with a fresh 2-of-2 Safe and the Python signer as the other member. It needs `E2E_DIR` too, as below, and stops past 0.01 ETH.

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

`dist/` is a static site. Its Content Security Policy allows scripts only from the app itself; nothing loads from another server at run time, and there is no analytics. RPC endpoints, Safe's service and, for dapps, Reown's WalletConnect relay are the only network peers.

**WalletConnect** (Reown's WalletKit, bundled) is a separate chunk, loaded only for a Safe's dapps or a live session. It reaches only the relay, `wss://relay.walletconnect.org`, the one origin it adds to `connect-src`. The SDK's telemetry, the Verify API and push registration are off, its payments client is left out of the build, and a guard refuses fetches to WalletConnect's and Reown's servers (`src/lib/walletconnect.ts`; docs/notes/walletconnect.md, "The app").

## Published

**`https://app.winterlock.eth.limo`** serves the build of commit `494703c`, IPFS hash `bafybeieyirqeaqtufndkvf2a7rcz2lxfhjbj7py6icoy22jfwt6smexuja`. The name resolves through a record on winterlock.eth's resolver, not through a subname. The reason is in docs/decisions.md, "2026-11-07: the app published at app.winterlock.eth". The build before it, of `a20d51c` (no WalletConnect), is `bafybeiga42jsit5a4tzyp6cd75lwhbgoe5et6inocbaqxlzypfcjgs6gsi`.

To check that the hash comes from this code, build that commit and hash `dist/` with [kubo](https://docs.ipfs.tech/install/command-line/). The build holds WalletConnect's project ID, which isn't in the repository: it is the 32-character hex string in the published `assets/index-*.js` (`const …="<the ID>"`, just before WalletConnect's state).

```sh
git checkout 494703c && cd app && npm ci
VITE_WALLETCONNECT_PROJECT_ID=<the ID> npm run build
ipfs add -r -n -Q --cid-version=1 dist
```

A second build on the same machine gave the same hash; a build on another machine hasn't been compared yet. That build used rustc 1.98.1, wasm-bindgen 0.2.130, Node 24.14.0 and kubo 0.43.1.

The site's storage belongs to its origin. Serving the app from another address gives an empty app, without the device keys stored at `app.winterlock.eth.limo`.

**Updating from the build of `a20d51c`:** the app's database goes from version 1 to 2 (a store for dapps' transactions), keeping everything in it. A tab still open on the older build blocks that: the new one says to close it and reload.

## Rules it keeps (docs/notes/signer-app.md, "Risks a browser adds")

- **Storage:** the device key, its key log and the gas key live in IndexedDB, unencrypted in this round. The app asks for persistent storage.
- **iOS:** no device key unless the app runs installed (standalone). The install steps are in the app.
- **Record before signing:** every one-time signature is recorded in a strict-durability IndexedDB transaction, completed, under a Web Lock for the device, before the core signs. The core signs only from a store that already holds the use (`core-wasm/src/lib.rs`, `src/lib/keylog.ts`).
- **Stale-log check:** before every one-time signature, the app compares the signatures of this device's key tree at Safe's service and in executions on-chain with its key log, and refuses if any is missing (`src/lib/stale.ts`).
- **Dapps sign nothing by themselves:** every transaction a dapp asks for is decoded, shown and confirmed by the member, and goes through the same checks and key log as any proposal. The app picks the nonce, the gas fields are zero, and a batch goes only through Safe's MultiSendCallOnly v1.4.1, whose code is checked first. A dapp's name and URL are shown as unverified.
- **Heavy work in workers:** keys, trees and signatures run in Web Workers, with progress. The member key lives only in a worker that is terminated after it signs.

## Development notes

- **RPC keys:** an RPC URL may carry an API key. The app shows only its host. For your own testing, set the URL in Settings; nothing in the build reads a key.
- **Safe's service through a key** (only if keyless writes stop working): `SAFE_API_KEY=... VITE_SERVICE_PROXY=/safe-service npm run dev` routes the app's writes through the dev server, which adds the key. It's development only and never bundled.
- **Icons:** `npm run icons` renders the PNG icons from `docs/brand/mark.svg`.
