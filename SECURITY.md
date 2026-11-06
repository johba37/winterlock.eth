# Security

Winterlock is a research prototype. It is unaudited and runs on testnets only, so no real funds depend on it yet. Reports are very welcome all the same, and they matter most now, before anyone relies on it.

## Reporting a vulnerability

Report it privately through GitHub: **[Report a vulnerability](https://github.com/johba37/winterlock.eth/security/advisories/new)** (also under the repository's Security tab). Only you and the maintainers see the report.

Please don't open a public issue, pull request or forum post about a vulnerability.

A useful report says:
- **what's affected:** file and line at a commit, or a deployed address
- **what an attacker needs,** and what they can then do
- **how to reproduce it.** A test or a proof of concept against a local chain or fork is welcome. Please don't test against other people's Safes or accounts.

## What happens next

- **An acknowledgement within 3 days.**
- **Updates while we assess and fix it,** in the report's private discussion.
- **Coordinated disclosure:** we publish an advisory once a fix is out, or after 90 days, whichever comes first, unless we agree on another date with you.
- **Credit** in the advisory, unless you'd rather stay anonymous.
- **No bug bounty** yet.

## Scope

**In scope:**
- **Contracts** in `contracts/src/`: the WOTS verifier, the Safe owner (`WinterlockOwner`) and its factory, and the Kernel validator. This includes how they use the vendored leanSphincs-keccak verifier. A flaw in that verifier itself is also welcome here; we'll coordinate with its upstream author.
- **The construction,** as described in [docs/decisions.md](docs/decisions.md): parameters, tweaks, nonce binding, certificates, and the wrapping of ERC-1271 messages.
- **The signer** in `signer/`: key derivation, the key log, device binding, moves and recovery, the Safe and WalletConnect handling, and what it shows before it signs.
- **The landing page** (`index.html`).

**Especially wanted:**
- a one-time key signing twice for the same Safe nonce
- a signature that verifies for the wrong Safe, chain, nonce or message
- the signer signing something it didn't show or didn't compute itself
- a lost, copied or rolled-back device undoing a restore or reusing a key

**Out of scope:**
- **Other projects:** Safe's contracts, Transaction Service and app; ZeroDev Kernel; WalletConnect and Reown; bundlers. Please report those to their projects, unless Winterlock's use of them makes things worse.
- **Testnet-only effects,** such as spending test ETH or gas griefing on testnets.
- **Best-practice suggestions with no concrete impact.** These are welcome as ordinary issues instead.
