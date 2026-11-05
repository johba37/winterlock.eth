# The signer answers dapps over WalletConnect (2026-11-05)

D14 needs the signer to answer apps itself, because Safe's app doesn't reliably pass message results back. `winterlock-signer connect` does this. A member pairs the signer with a dapp over WalletConnect v2, and the dapp sees the team's Safe as its account, as with Safe's own WalletConnect support. Each request is decoded and shown, and is signed only after the member agrees.

Code: `signer/winterlock_signer/` `walletconnect.py` and `ws.py` (protocol), `bridge.py` (requests, the `connect` and `message` commands), `messages.py` and `eip712.py` (D14's decision), `safelibs.py` (delegatecall targets), `collect.py` (collection endpoint).

## The protocol is implemented here, not taken from a library

No suitable Python library exists (checked 2026-11-05):
- **pyWalletConnect** is GPL-3.0. Its last release, 1.6.2, is from November 2023, before the relay's 2025 methods.
- **ApeWorX's `walletconnect`** is Apache-2.0, but it is version 0.1.0 of 2026-11-03, pre-alpha, and implements only the dapp side.
- **Reown** ships no Python SDK.

The needed subset is small, so it is implemented natively, as the rest of the signer is:
- about 550 lines of protocol and a 200-line WebSocket client
- X25519 written in Python (RFC 7748); Ed25519, ChaCha20-Poly1305 and HKDF from pycryptodome, which the signer already uses
- no new dependency

**What it implements:**
- the pairing URI
- keys: X25519, then HKDF-SHA256 to a symKey; a topic is the sha256 of its symKey
- type-0 envelopes
- the relay's JSON-RPC: `irn_subscribe`, `irn_publish`, `irn_unsubscribe`, and acknowledgements of `irn_subscription`
- the relay's EdDSA JWT, with a did:key issuer
- the Sign protocol: a proposal is answered with `wc_sessionSettle` first, then the answer to the proposal, in the order sign-client uses. Then requests, pings and deletion.

**What it doesn't implement:** one-click auth, link mode, the Verify API, session updates and extensions, and persistence. Session keys live in memory only, so a restart pairs again.

**How it was checked:**
- **Crypto and the JWT, byte for byte:**
  - against WalletConnect's own test values (`walletconnect-monorepo` and `walletconnect-utils`)
  - against `@walletconnect/utils` and `relay-auth` as shipped with sign-client 2.21.0
- **The protocol:**
  - against a scripted dapp
  - optionally (`WINTERLOCK_WC_JS`), against dapps built on the official `@walletconnect/sign-client` 2.21.0 and 2.26.0. Since 2.21.6, the dapp proposes through the relay method `wc_proposeSession`.
  - all of these through a stand-in relay
- **Not tested against Reown's relay** (see "A live test needs").

## What the dapp gets

| Request | What the signer does | What the dapp gets, and when |
|---|---|---|
| `eth_sendTransaction` | Builds a SafeTx (a call) and signs it with the member's WOTS key under the key log's slot rules. Proposes it to the Transaction Service, or writes a proposal file when offline. | The SafeTx hash, right after the proposal. With `--wait-for-execution`: the transaction hash if the Safe executes it before the request expires, otherwise the SafeTx hash. |
| `wallet_sendCalls` (EIP-5792) | One call, or a batch as a delegatecall to MultiSendCallOnly | `{id: SafeTx hash}`. `wallet_getCallsStatus` reports 100 (pending), 200 (executed, with the receipt), 400 (replaced at its nonce) or 500 (reverted). |
| `eth_getTransactionReceipt`, `eth_getTransactionByHash` for a SafeTx hash the signer gave out | Maps it to the execution | Before execution: `null`, or a pending placeholder transaction. After: the real receipt and transaction. |
| Message, off-chain path | Signs the SafeMessage with the stateless key and gathers the others' signatures (below). Combines k of them and checks them with the Safe's `isValidSignature` (eth_call). | The combined signature, 11,668 bytes for 2 of 3, once k members have signed. If the request expires first, the dapp gets an error; asking again later is answered at once from the collected signatures. |
| Message, on-chain path | Proposes a SafeTx that delegatecalls `SignMessageLib.signMessage(abi.encode(h))`. Watches the Safe's `signedMessages` for it. | `0x` once the approval has executed, if that happens before the request expires. Otherwise an error naming the SafeTx; asking again after execution is answered with `0x` at once. |
| Refused | Nothing is signed | Error 4001 with the reason. 4200 for an unsupported method, 5100 for another chain. |

**Why the SafeTx hash.** Safe's app does the same, read from `safe-wallet-monorepo` (`apps/web/src/services/safe-wallet-provider`):
- It answers `eth_sendTransaction` with the safeTxHash once the first owner has signed and proposed. It answers with the transaction hash only if the transaction was executed in the same flow.
- It maps a safeTxHash in `eth_getTransactionByHash` and `eth_getTransactionReceipt` to the executed transaction.

Waiting for execution instead rarely works. A team needs k members, and sign-client's default request expiry is 5 minutes. Dapps that poll their own RPC for a receipt of the SafeTx hash never find one. That is the same as with Safe's app. EIP-5792 dapps get a proper status.

**Where it differs from Safe's app:**
- **On-chain message signing:** when Safe's app signs a message on-chain (`SignMessageOnChainFlow`), no code path answers the dapp over WalletConnect. This is read from its source, not tested. The bridge waits for the approval and answers with `0x`.
- **Off-chain message signing:** Safe's app goes through the Transaction Service's message API, which refuses Winterlock's 5,834-byte owner signatures. The bridge gathers them itself.

## Which path a message takes

Every member decides again from the dapp's original request, which the message file carries. The app's hash (EIP-191 or EIP-712, checked against ethers) and the SafeMessage hash are recomputed, never taken from the file.

**`personal_sign`:**
- **Text:** off-chain.
- **A sign-in (EIP-4361):** off-chain, but refused unless:
  - the address is the Safe
  - the Chain ID is the session's chain
  - the version is 1
  - it hasn't expired
  - its domain is the dapp's claimed URL or a subdomain of it (a dapp that names no URL is refused)
- **Refused:**
  - a bare 32-byte hash
  - binary data
  - text with invisible or control characters, such as bidi overrides or zero-width characters

**`eth_sign`:** always refused.

**`eth_signTypedData_v4`** (v3 and the unversioned method are treated the same):
- **Refused:**
  - typed data for another chain
  - a bare domain
  - Safe's own types (SafeTx, SafeMessage, SafeOp, Delegate)
  - anything addressed to the Safe or one of its owners
  - a validator's enable data (Kernel's `Enable`, the Kernel and Winterlock domains)
  - DAI-style permits, which only check `ecrecover`
- **On-chain:**
  - EIP-2612 `Permit`. Its owner must be the Safe. The member is warned that tokens built on OpenZeppelin's `ERC20Permit` accept only ECDSA.
  - Permit2
  - any typed data that names a `verifyingContract`
- **Off-chain:** typed data that names no verifying contract.

Unlimited allowances and deadlines in the past are flagged.

**Why `verifyingContract` decides.** In the common cases, the contract named in the domain is what checks the signature: permits, Permit2, and orders a settlement contract checks. Typed data without one is checked by a server: logins, votes, API keys.

A wrong guess fails safe:
- **An off-chain signature also verifies on-chain.** Permit2 accepts it, at about 380k gas per use (`safe-messages.md`, option C).
- **An on-chain approval answers `0x`.** A server that verifies with viem refuses it.

**Delegatecall targets.** The signer delegatecalls only Safe v1.4.1's SignMessageLib and MultiSendCallOnly. It checks their code before each use:
- The runtime code must match the release build with its CBOR metadata removed. The pin is in `safe_libs.json`, made by `tools/pin_safe_libs.py`.
- The canonical deployments match it: Sourcify's runtime code, whose hash is the codeHash that safe-deployments lists.
- `setup.sh` now also builds SignMessageLib with the release settings.

**Transactions a dapp may not ask for.** A Safe call to itself that changes its owners, threshold, modules, guard or fallback handler is refused over WalletConnect. The team uses `propose` for those. This applies inside batches too.

## Gathering the members' message signatures

**A message file** (`safe-message-<hash>.json`) holds:
- the dapp's request
- the dapp's claimed name and URL
- the app's hash and the SafeMessage hash
- the signatures so far

The flow:
1. The connected member signs and writes the file.
2. Each other member runs `message --file`, then sends the file back into the connected member's exchange directory, under any name.
3. The bridge merges every message file there for the same message.
4. It checks each signature with the owner contract's `isValidSignature` (eth_call).
5. Once it has k, it combines them in owner order, checks the Safe's `isValidSignature`, and answers.

**A collection endpoint** (`collect.py`) serves the same documents over HTTP: PUT, POST a signature, and GET.
- **Checks before it stores anything:**
  - the request decodes to the document's hashes
  - the message takes the off-chain path
  - the Safe is on its chain
  - each signature is from an owner and is accepted by that owner's contract (eth_call)
- **What it can do:** it holds public data only, so it can withhold signatures but not forge them. It keeps them in memory.
- **How to use it:** `connect --collect URL`, and `message --collect URL --hash H` for the other members.
- **Hosting:** nothing is hosted. D8's collection service could adopt this API.

**Stateless signatures count against the key's budget.** Each message signature is recorded in the key log as a `msg` record, and `status` counts it against the stateless key's budget.

## Limits and open issues

**viem refuses `0x`.** This affects the on-chain path for apps that verify off-chain with viem. The fix is a contract change, described here and not built.
- **A new WinterlockOwner signature kind**, for example `0x03`, that defers to the Safe's own approval: `[0x03][safe: 20][keccak256(message): 32]`.
- **The owner's check:**
  - It recomputes the SafeMessage hash for that Safe on this chain, as kind `0x02` does.
  - It requires that this is the hash being checked.
  - It answers valid only if `ISafe(safe).signedMessages(hash) != 0`. That is a view call into the Safe, so it is allowed under STATICCALL.
- **The wallet's answer:** k of these owner signatures, 150 bytes each (65 + 32 + 53). For 2 of 3 that is 300 bytes.
  - viem's ERC-6492 path accepts them, because they are at least 32 bytes long.
  - The Safe's own `checkSignatures` passes, through the owners.
  - Security is that of the empty signature: the approval itself was a quorum-signed Safe transaction.
- **Costs:**
  - **New owner addresses:** any change to WinterlockOwner's code changes the implementation's address, and with it the factory's and every owner's. Teams would swap each member's owner, as in the upgrade in place.
  - **ECDSA owners can't defer:** in a Safe that still has ECDSA owners, those owners have no such kind, so it doesn't help there.

**Other limits:**
- **Dapp metadata is unverified** (no Verify API). A phishing site can claim another site's URL. The sign-in domain check only compares the message with the dapp's claim.
- **The 5-minute expiry:** dapps give up after sign-client's default of 5 minutes. Gathering signatures or executing an approval usually takes longer. The second request is then answered at once.
- **Receipts for the SafeTx hash:** a dapp that neither uses EIP-5792 nor routes receipt lookups through the wallet waits forever for a receipt of the SafeTx hash.
- **Libraries:** only Safe v1.4.1's SignMessageLib and MultiSendCallOnly are recognised, at their canonical addresses by default. They work with Safes from v1.3.0 on, whose storage layout matches.
- **Mixed Safes:** in a Safe with ECDSA and Winterlock owners, the ECDSA owners can't sign message files. The threshold has to come from Winterlock owners.
- **One session at a time:** one dapp per `connect`, and sessions live in memory. The key log stays locked while connected, so the member's other commands wait.
- **The approval flow on Reown's relay:** the wallet approves with `irn_publish`, as sign-client did up to 2.21.5. Wallets on sign-client 2.21.6 and later use the relay method `wc_approveSession`. That Reown's relay still accepts the older flow is inferred, since older SDKs remain deployed. It isn't tested.
- **X25519 timing:** this X25519 is not constant-time, because it uses Python integers. It is used only for ephemeral session keys.
- **`--yes` on `connect`** signs everything the rules allow without asking. It is meant for tests and scripts.
- **Not covered:** ERC-7739 (nested typed data), and EIP-2612 tokens that accept only ECDSA, which no Safe can sign.

## A live test needs

- **A Reown project ID** (cloud.reown.com, free), in `WALLETCONNECT_PROJECT_ID`. The relay refuses connections without one; Reown documents 401 and 403.
- **A WalletConnect dapp** on the chain of a Winterlock Safe, for example Sepolia: a sign-in demo, and Permit2 at its canonical address.
- **The members' signers,** with `SAFE_API_KEY` for Safe's Transaction Service and a gas account for execution.
- **What to look at:**
  - that Reown's relay accepts the approval through `irn_publish`
  - how the dapp handles an 11.7 KB signature
  - what a viem-based dapp does with `0x`

## Tests

40 new tests; the suite runs 86, and skips one unless Node and the SDK are available.
- `test_walletconnect.py` (14):
  - known answers
  - the URI
  - session namespaces
  - the protocol against the scripted dapp: requests, rejection, `wc_proposeSession`, a dropped relay connection, forged messages, the project ID
  - the optional JS SDK dapp
- `test_messages.py` (13):
  - EIP-712 and EIP-191 against ethers
  - the decision rules
  - message files
  - the pinned libraries, against the canonical code and the build
- `test_bridge.py` (5): request handling and refusals, without a chain.
- `test_e2e_walletconnect.py` (8): on anvil, a 2-of-3 Safe v1.4.1 (SafeL2) of proxy owners. The connected signer runs as its own process.
  - a transaction proposed, confirmed and executed, and its receipt looked up through the SafeTx hash
  - a two-call batch
  - a sign-in collected through a message file
  - a text message collected through the endpoint
  - a Permit2 approval executed, then `isValidSignature(h, 0x)`
  - refusals
  - disconnection
