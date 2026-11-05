# winterlock.eth

The landing page for **Winterlock**, a community initiative to give [Safe](https://safe.global) smart accounts owners whose signatures rest on hash functions alone (WOTS for daily signing, SPHINCS+ for recovery), adoptable in place without moving funds.

The page is a single static `index.html` with two self-hosted fonts. It makes no requests to other servers, so it works from any IPFS gateway, from `ipfs://` in Brave, or straight from disk. The hero includes a live Winternitz hash-chain demo that runs entirely in the browser.

## Files

| Path | What it is |
|---|---|
| `index.html` | The whole page: markup, styles and the demo script |
| `fonts/` | Atkinson Hyperlegible Next and Mono (variable, Latin subset) with their SIL Open Font License texts |
| `docs/decisions.md` | Design decisions, gas measurements and open questions |
| `contracts/` | Research prototype: WOTS verifier, ERC-7579 validator, Safe owner (EIP-1271), tests and gas benchmark (unaudited, not for real funds) |

## Contracts

```sh
cd contracts
./setup.sh          # submodules, plus ZeroDev Kernel and Safe v1.4.1 / v1.5.0 built with their release settings
forge test          # unit tests per parameter set, Kernel integration tests, verifier-only gas
./bench.sh          # local anvil, real handleOps txs, gas table from receipts
L2_RPC=https://mainnet.base.org ./bench.sh   # also price them on Base (read-only RPC calls)
./bench/bundlers/run.sh   # bundler acceptance: geth + Alto + Rundler in Docker, real ERC-7562 checks
./bench/bundlers/testnet.sh   # hosted bundlers on Arbitrum Sepolia; needs bench/bundlers/.env (keys, funded test key)
forge script script/DeployValidator.s.sol --rpc-url $RPC --broadcast   # validator at its deterministic address (D10)
WINTERLOCK_KEY=0x... forge script script/DeploySafeOwner.s.sol --rpc-url $RPC --broadcast   # a member's Safe owner at its deterministic address
./bench/bundlers/multichain.sh   # one account on Ethereum Sepolia and Arbitrum Sepolia, a tree per chain (D10)
```

## Preview locally

```sh
python3 -m http.server 8000
# then open http://localhost:8000
```

## Publish to winterlock.eth

1. **Pin the folder to IPFS.** Upload this folder (with `index.html` and `fonts/`) to a pinning service such as Fleek, Pinata, Filebase or 4EVERLAND, or with a local node:
   ```sh
   ipfs add -r --cid-version 1 --ignore .git --ignore .gitmodules --ignore README.md --ignore contracts --ignore docs .
   ```
   Note the CID of the folder (it starts with `bafy…`). Pinning with two services keeps the page up if one of them drops it.
2. **Point the name at it.** On [app.ens.domains](https://app.ens.domains), open `winterlock.eth` → Profile → Edit profile → Other → Content Hash, enter `ipfs://<CID>` and sign with the Manager wallet. This needs a little mainnet ETH for gas.
3. **Check it** at <https://winterlock.eth.limo> (or `winterlock.eth.link`). Brave and Opera also open `winterlock.eth` directly.

Every change produces a new CID, so repeat steps 1 and 2 for each update.

## After posting the forum proposal

The forum links currently point to the Safe forum's Initiatives category. Once the proposal thread is live, replace `https://forum.safefoundation.org/c/safe-ecosystem/initiatives/13` in `index.html` (three places) with the thread URL.

## Licenses

Fonts: Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono, © The Atkinson Hyperlegible Next Project Authors, licensed under the SIL Open Font License 1.1 (see `fonts/OFL-*.txt`).
