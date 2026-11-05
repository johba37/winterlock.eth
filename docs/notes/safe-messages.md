# Safe messages with WinterlockOwner owners (2026-11-05)

On the Safe route (D13) a member's message signature is a 5,834-byte Transaction Service entry (65 + 32 + data), over the service's 5,000-byte cap. Three options, measured on 2-of-3 Safes. Gas is for v1.5.0 / v1.4.1, from Forge with Prague pricing.

| | A. leanSphincs-s as the stateless key | B. On-chain approval (SignMessageLib) | C. Stateless signature outside Safe's service |
|---|---|---|---|
| Size | entry 4,314 B (fits); the app gets 8,628 B | approval tx 4,228 B of calldata; the app gets 0 B | entry 5,834 B (refused); the app gets 11,668 B |
| Gas | verify 38.9k vs 52.8k; app's check 160k / 193k; enrol 191k vs 251k | approval 265k / 267k (an ETH transfer: 245k / 247k; ECDSA owners: 85k / 86k); app's check 19k / 22k | app's check 194k / 237k, plus 11.7 KB of the app's calldata per on-chain use |
| Security budget | 20K / 2.1M / 67M signatures (Light / Standard / Full), **estimated**; leanSphincs 210K / 22M / 1.15B, **proved** | members' WOTS keys (D6, one per nonce), a quorum per message; no stateless signature | as today: leanSphincs, proved |
| UX | Safe's message flow, if Safe's app relays the result (untested); new keys and owner contracts for every member | one Safe transaction per message: a nonce, gas, a wait; no clean revocation | Winterlock's collection service (D8) stores and serves it; instant, free |
| Sign-in with Ethereum | yes | `siwe` library yes; viem **no** (rejects `0x`) | yes |
| Permit2 | yes | yes (empty signature) | yes, about 380k gas per use |
| EIP-2612, OpenZeppelin `ERC20Permit` | no | no | no |
| Apps that read Safe's message API | yes | no | no |

`ERC20Permit` runs only `ECDSA.recover` (tested). Tokens whose permit checks EIP-1271 (FiatToken v2.2) behave like Permit2.

## Evidence

Tests: `test/integration/SafeMessages.t.sol` (9 per release) and `test/StatelessVerifierS.t.sol` (6).

**A.**
- **Vendored:** the leanSphincs-s verifier, test-only, from SPHINCs- at `4c76aaf` (MIT; the production verifier's commit), with its known answers. The test signer reproduces the four with b ≥ 10 byte for byte.
- **Owner:** `WinterlockOwnerS`, `WinterlockOwner` with only the signature length changed, answers the service's two eth_calls and passes the fallback handler, Permit2 and transactions.
- **Verify gas:** 38,887–39,004 with via-IR, in a one-off build where leanSphincs measures 52,750–52,896. The suite's default pipeline gives 42.6k, which the check figures include.
- **Certificates:** `enroll` calldata is 4,388 B against 5,892. Enrolment pays Prague's calldata floor, so the 1,504 fewer bytes save 60k. The validator's certificate would shrink from 5,725 to 4,205 B (estimate).
- **Budgets and signing times** are upstream's (27 s against 13 s on a Ledger-class device).
- **A switch means new seeds.** Both schemes derive the same public key from one seed (tested), which upstream forbids reusing. So: new owner contracts (KEY is the CREATE2 salt), a new verifier and a new Kernel validator.

**B.**
- **The approval:** a WOTS-signed delegatecall to Safe's SignMessageLib (compiled from each release's source) sets `signedMessages`. The handler then accepts `isValidSignature(hash, "")` for that Safe, chain and hash only; a non-empty signature still needs the owners.
- **What can't approve:** one member alone, or a phished stateless signature of the approval's hash (GS024).
- **Revocation:** nothing in Safe clears an approval; a custom delegatecall library can (tested).
- **Safe's tools** (read from their sources):
  - protocol-kit and the Safe Apps SDK check approvals with `0x`;
  - Safe{Wallet} offers "Always use on-chain signatures", but answers Safe Apps at proposal, not execution, and appears to leave WalletConnect requests unanswered (not tested);
  - the Transaction Service ignores `SignMsg`.
- **viem:** `verifyHash` sends `0x` to its ERC-6492 validator, which reverts on signatures under 32 bytes (checked locally against viem's bytecode). An ERC-6492-wrapped empty signature passes viem, but Permit2 refuses it.
- **Extra costs:** about 35k more on SafeL2, which logs the signatures (live run), and more under Glamsterdam for the new slot (not measured).

**C.**
- **Who accepts it:** the 11,668-byte signature passes the `siwe` library, viem and Permit2.
- **Cost per on-chain use:** 194k / 237k to check, plus about 187k of calldata at 16 gas per byte.

## Recommendation

**Keep leanSphincs (D12 stands), and don't fit the key to the service's cap.**
- **Messages checked on-chain (permits): use B,** Safe's own documented mechanism. Messages get WOTS keys under the Safe's nonce and a quorum, and each later check costs about 20k.
- **Messages checked off-chain (sign-in): use C,** collected by D8's service: free, instant, and accepted by both common verifiers.
- **Both need a Winterlock signer that answers apps over WalletConnect.** Safe{Wallet} can't deliver C and doesn't reliably deliver B.

**Trade-offs.**
- **B:** about 265k gas per message on L1, a Safe nonce, a wait, no clean revocation.
- **C:** about 380k per on-chain check, and invisible in Safe's message API.
- **A** would keep Safe's message flow (if Safe's app relays the result), at the cost of:
  - a Light budget ten times smaller, and unproved;
  - twice the hardware signing time;
  - new keys and owner contracts for every member;
  - no fit at category 3 (D12's backburner): 24-byte hashes make signatures about 1.5× larger (estimate).

**For D12:** under B and C the key needn't fit the cap, and B takes on-chain messages off it. leanSphincs's proved budget and hardware tier still decide.

**Proposed follow-ups:**
- **WinterlockOwner:**
  - a signature kind that defers to the Safe's `signedMessages`, so wallets can return a short signature viem accepts;
  - optionally, refusing stateless message signatures, which owners still accept under B.
- **setup.sh:** build SignMessageLib with the release settings.
- **decisions.md:** answer D11's open question (on-chain pre-approval: yes, on the Safe route) and D13's message item.
