<h1><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup-dark.svg"><img src="docs/brand/lockup-light.svg" alt="winterlock.eth" width="320"></picture></h1>

**Winterlock lets a team's Safe be controlled by hash-based signatures instead of ECDSA.** These are signatures a quantum computer can't break, and the Safe, Safe's app and dapps keep working. It's a **research prototype: unaudited, testnet only.**

**Start here:** the [one-page overview](docs/overview.md) covers how it works, the numbers and what's live.

- **Teams:** each member's owner contract is an owner of a [Safe](https://safe.global). Safe does the k-of-n, and teams keep Safe's app and Transaction Service.
  - **One-time keys** (WOTS) sign transactions.
  - **A stateless key** (leanSphincs) signs messages, certifies new key trees and brings a member back after a lost device.
  - **An existing Safe can switch in place,** swapping its owners one at a time without moving funds.
- **Individuals:** an ERC-7579 validator on ZeroDev Kernel (ERC-4337), with built-in k-of-n.

**Live on Sepolia:**
- Safes with Winterlock owners, through Safe's Transaction Service and app.
- Dapps over WalletConnect: transactions, sign-in, typed data, Permit2.
- Recovery and moves between devices.

All decisions, measurements and open questions are in [docs/decisions.md](docs/decisions.md).

**Try it as a member of a test Safe** (details under [Signer](#signer)):

```sh
python3 -m venv signer/.venv && signer/.venv/bin/pip install -r signer/requirements.txt
signer/winterlock-signer init                                   # your recovery phrase, a three-word check, a passphrase
signer/winterlock-signer address                                # your owner address: list it when creating the Safe
signer/winterlock-signer enroll  --chain sepolia --safe 0x...   # creates your owner contract and certifies a key tree
signer/winterlock-signer connect --chain sepolia --safe 0x...   # use the Safe in a dapp over WalletConnect
```

This repository also holds the landing page published at winterlock.eth: a single static `index.html` with two self-hosted fonts. It makes no requests to other servers, so it works from any IPFS gateway, from `ipfs://` in Brave, or straight from disk. The hero includes a live Winternitz hash-chain demo that runs entirely in the browser.

## Files

| Path | What it is |
|---|---|
| `index.html` | The landing page: markup, styles and the demo script |
| `fonts/` | Atkinson Hyperlegible Next and Mono (variable, Latin subset) with their SIL Open Font License texts |
| `docs/brand/` | The look: mark, lockups, colours, and the stencil lettering generator |
| `docs/overview.md` | Winterlock in one page: how it works, numbers, what's live, terms |
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
- **Backup:** a 24-word recovery phrase (BIP-39) is the only backup. `init` shows it once and checks three of its words. On the device, the seed is encrypted with a passphrase.
- **One device at a time:** the key log is bound to its device. A copied or rolled-back key log signs nothing, and a move locks the old device for good.

Each member runs their own signer. It lives in `~/.winterlock-signer`; `--home DIR` (or `WINTERLOCK_HOME`) picks another directory, for example to try several members on one machine.

```sh
python3 -m venv signer/.venv && signer/.venv/bin/pip install -r signer/requirements.txt
signer/winterlock-signer init            # a new signer: write down the phrase, confirm three words, set a passphrase
signer/winterlock-signer address         # your owner address, the same on every chain: give it to whoever creates the Safe
export WINTERLOCK_RPC=https://...        # the chain's JSON-RPC URL
export WINTERLOCK_GAS_KEY=0x...          # the private key of any funded account: it pays for enroll and execute, and isn't an owner
export SAFE_API_KEY=...                  # Safe's Transaction Service API key, from developer.safe.global
```

**The Safe.** Its owners are the members' owner addresses. They don't have to exist on-chain yet: each member's first `enroll` creates theirs. Any way of creating a Safe works, Safe's web app included. With `cast`, from Safe's canonical v1.4.1 deployments (the same addresses on every chain; about 1.5M gas on Sepolia for three owners):

```sh
FACTORY=0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67 SAFE_L2=0x29fcB43b46531BcA003ddC8FCB67FFE91900C762 SALT=$RANDOM
HANDLER=0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99 ZERO=0x0000000000000000000000000000000000000000
SETUP=$(cast calldata "setup(address[],uint256,address,bytes,address,address,uint256,address)" \
  "[0xOWNER1,0xOWNER2,0xOWNER3]" 2 $ZERO 0x $HANDLER $ZERO 0 $ZERO)   # the owner addresses, then the threshold
cast call $FACTORY "createProxyWithNonce(address,bytes,uint256)(address)" $SAFE_L2 $SETUP $SALT --rpc-url $WINTERLOCK_RPC   # its address
cast send $FACTORY "createProxyWithNonce(address,bytes,uint256)" $SAFE_L2 $SETUP $SALT --rpc-url $WINTERLOCK_RPC --private-key $WINTERLOCK_GAS_KEY
```

Then each member enrolls, and the team signs through Safe's Transaction Service:

```sh
signer/winterlock-signer enroll  --chain sepolia --safe 0x...   # once per Safe: certify a key tree; creates your owner if needed
signer/winterlock-signer propose --chain sepolia --safe 0x... --to 0x... --value 0.01   # the value in ETH
signer/winterlock-signer queue   --chain sepolia --safe 0x...   # pending transactions, decoded, with their SafeTx hashes
signer/winterlock-signer confirm --chain sepolia --safe-tx-hash 0x...
signer/winterlock-signer execute --chain sepolia --safe-tx-hash 0x...   # anyone, once enough members have signed
(cd signer && .venv/bin/python -m unittest discover -s tests -t .)   # tests; the on-chain ones skip without anvil and contracts/setup.sh
```

The owner contracts' factory is deployed on Sepolia. On a chain without it, `enroll` says so, and `enroll --deploy` deploys it once for that chain.

**Backup, recovery and new devices.** `status` shows the device state (active, locked or moved) and when the phrase was last checked. It also warns if the key log looks like a copy or a restored backup.

```sh
signer/winterlock-signer backup --check      # check the phrase now and then (status reminds you after 90 days)
signer/winterlock-signer passphrase          # change the seed file's passphrase (--forgot: set a new one from the phrase)

# A new device, and the old one still works: a move keeps the same key trees, with no fee
signer/winterlock-signer move start                                # new device: type the phrase; it shows a move code
signer/winterlock-signer move export --code CODE --out move.json --chain sepolia   # old device: checks its log, locks itself for good, writes the bundle
signer/winterlock-signer move import move.json --chain sepolia     # new device: checks the bundle against the chain and the service

# The old device is lost: restore with fresh trees, one enroll per Safe and chain (about 0.25M gas each; 0.39M on Sepolia)
signer/winterlock-signer init --restore --lost --chain sepolia     # lists the approvals that stop counting
signer/winterlock-signer enroll --chain sepolia --safe 0x...
```

- **The old device turns up again:** it sees it was replaced and refuses to sign or enroll for that Safe, so it can't undo the restore. `enroll --take-over` overrides that, only if the other device is gone for good.
- **Phrase or device compromised:** if someone else may have your phrase or your device, restoring doesn't help. The team replaces your owner in the Safe; `init --restore` explains how.
- **Changing owners** is an ordinary Safe transaction, which the signer decodes and flags: `propose --safe SAFE --to SAFE --data $(cast calldata "swapOwner(address,address,address)" PREV OLD NEW)`, where PREV is the owner listed just before OLD in the Safe's `getOwners()`, or `0x0000000000000000000000000000000000000001` if OLD is first.
- **Copied or rolled-back key log:** it signs nothing. `device fresh-trees` retires its trees, and `enroll` then certifies fresh ones.
- **More:** design, threat model and limits are in `docs/notes/signer-recovery.md`.

### Connect to a dapp

`connect` pairs the signer with a dapp over WalletConnect v2. The dapp sees the team's Safe as its account. Each request is decoded and shown, and is signed only after you agree.
- **Transactions** (`eth_sendTransaction`, `wallet_sendCalls`): you sign one as a member, and it is proposed to Safe's Transaction Service like `propose`. The dapp gets the SafeTx hash. The other members confirm and execute as usual.
- **Sign-in and other off-chain messages:** your stateless key signs, and a message file is written. The other members sign it with `message` and send it back, or post their signatures to a collection endpoint. Once enough members have signed, the dapp gets the Safe's combined signature.
- **Permits and other messages checked on-chain:** a Safe transaction approves the message through Safe's SignMessageLib. After it executes, the dapp gets `0x`.
- **Refused:** requests the signer can't decode or that look like an attack (a bare hash, `eth_sign`, another site's sign-in, the Safe's own typed data).

```sh
export WALLETCONNECT_PROJECT_ID=...      # from cloud.reown.com; Reown's relay requires one
signer/winterlock-signer connect --chain sepolia --safe 0x...   # paste the dapp's wc: URI when asked (it isn't shown)
signer/winterlock-signer message --chain sepolia --file safe-message-....json   # another member signs a message
(cd signer && .venv/bin/python -m winterlock_signer.collect --rpc $WINTERLOCK_RPC)   # optional collection endpoint
```

This works live on Sepolia through Reown's relay, with a dapp built on the official SDK: sign-in, transfers and Permit2 (`signer/tools/live_walletconnect.py`). The design, its limits and the live results are described in [docs/notes/walletconnect.md](docs/notes/walletconnect.md).

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
