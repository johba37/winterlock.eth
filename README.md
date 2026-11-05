# winterlock.eth

**Winterlock** gives Ethereum smart accounts signers whose security rests on hash functions alone: one-time WOTS keys for everyday signing, and a stateless hash-based key (leanSphincs) for messages, new key trees and recovery. The aim: an alternative to ECDSA for security-conscious individuals and teams, almost as convenient and only a little more expensive in gas.

- **Teams:** Winterlock signers are owners of a [Safe](https://safe.global). Safe does the k-of-n, and teams keep Safe's app and Transaction Service. An existing Safe can switch in place, swapping its owners one at a time, without moving funds.
- **Individuals:** an ERC-7579 validator on ZeroDev Kernel (ERC-4337).

Both work live on testnets; see `docs/decisions.md` for the decisions (D1–D14), measurements and open questions. Everything here is a **research prototype: unaudited, not for real funds**.

This repository also holds the landing page published at winterlock.eth: a single static `index.html` with two self-hosted fonts. It makes no requests to other servers, so it works from any IPFS gateway, from `ipfs://` in Brave, or straight from disk. The hero includes a live Winternitz hash-chain demo that runs entirely in the browser.

## Files

| Path | What it is |
|---|---|
| `index.html` | The landing page: markup, styles and the demo script |
| `fonts/` | Atkinson Hyperlegible Next and Mono (variable, Latin subset) with their SIL Open Font License texts |
| `docs/decisions.md` | Design decisions, gas measurements and open questions |
| `docs/notes/` | Longer notes, such as the message-signing options on the Safe route |
| `docs/ux/` | The MVP proposal for teams and a clickable mockup |
| `contracts/` | The contracts: WOTS verifier, Kernel validator, Safe owner (EIP-1271) with its proxy factory, tests, gas benchmarks and testnet tooling |
| `signer/` | A minimal command-line signer for Safe members (Python) |

## Contracts

```sh
cd contracts
./setup.sh          # submodules, plus ZeroDev Kernel and Safe v1.4.1 / v1.5.0 built with their release settings
forge test          # all contract tests
./bench.sh          # local anvil, real handleOps txs, gas table from receipts
L2_RPC=https://mainnet.base.org ./bench.sh   # also price them on Base (read-only RPC calls)
./bench/bundlers/run.sh   # bundler acceptance: geth + Alto + Rundler in Docker, real ERC-7562 checks
./bench/bundlers/testnet.sh   # hosted bundlers on a testnet; needs bench/bundlers/.env (keys, funded test key)
./bench/bundlers/multichain.sh   # one Kernel account on Ethereum Sepolia and Arbitrum Sepolia, a tree per chain (D10)
```

Deterministic deployments: the addresses depend only on the code, so they are the same on every chain (`foundry.toml` sets `bytecode_hash = "none"`, so builds don't depend on the checkout path).

```sh
# the Kernel validator and its stateless verifier
forge script script/DeployValidator.s.sol --rpc-url $RPC --broadcast
# Safe route: the stateless verifier, the owner implementation and its factory (once per chain), and with
# WINTERLOCK_KEY a member's owner
WINTERLOCK_KEY=0x... forge script script/DeploySafeOwner.s.sol --rpc-url $RPC --broadcast
```

On chains with Glamsterdam's pricing of new state (Sepolia since October 2026), add `--skip-simulation --slow`: Forge's own simulation still prices the old way and would set gas limits too low.

## Signer

A minimal signer for members of a Safe whose owners are Winterlock contracts.
- **Keys:** WOTS and leanSphincs are implemented natively, checked byte for byte against the Solidity signers and the upstream known answers.
- **Safety:** it keeps a key log that is saved before any signature leaves it, refuses to reuse a key, and computes every hash it signs itself.
- **Service:** it posts to Safe's Transaction Service.

```sh
python3 -m venv signer/.venv && signer/.venv/bin/pip install -r signer/requirements.txt
signer/winterlock-signer init            # a new secret seed (or --restore on a new device)
signer/winterlock-signer address         # your owner address, the same on every chain
export WINTERLOCK_RPC=... WINTERLOCK_GAS_KEY=... SAFE_API_KEY=...
signer/winterlock-signer enroll  --chain sepolia --safe 0x...   # certify a key tree; creates your owner if needed
signer/winterlock-signer propose --chain sepolia --safe 0x... --to 0x... --value 0.01
signer/winterlock-signer confirm --chain sepolia --safe-tx-hash 0x...
signer/winterlock-signer execute --chain sepolia --safe-tx-hash 0x...
cd signer && .venv/bin/python -m unittest discover -s tests -t .   # tests
```

## Preview locally

```sh
python3 -m http.server 8000
# then open http://localhost:8000
```

## Publish to winterlock.eth

1. **Pin the site to IPFS.** Upload only `index.html` and `fonts/` to a pinning service such as Fleek, Pinata, Filebase or 4EVERLAND, or with a local node. Copy those two into an empty folder first, so nothing else in the repository (the contracts, the signer, local tool folders) is published:
   ```sh
   site=$(mktemp -d) && cp -r index.html fonts "$site"/ && ipfs add -r --cid-version 1 "$site"
   ```
   Note the CID of the folder (it starts with `bafy…`). Pinning with two services keeps the page up if one of them drops it.
2. **Point the name at it.** On [app.ens.domains](https://app.ens.domains), open `winterlock.eth` → Profile → Edit profile → Other → Content Hash, enter `ipfs://<CID>` and sign with the Manager wallet. This needs a little mainnet ETH for gas.
3. **Check it** at <https://winterlock.eth.limo> (or `winterlock.eth.link`). Brave and Opera also open `winterlock.eth` directly.

Every change produces a new CID, so repeat steps 1 and 2 for each update.

## Licenses

Contracts: MIT (SPDX headers in each file). Vendored code keeps its own licence files (`contracts/src/vendor/`, `contracts/test/vendor/`).

Fonts: Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono, © The Atkinson Hyperlegible Next Project Authors, licensed under the SIL Open Font License 1.1 (see `fonts/OFL-*.txt`).
