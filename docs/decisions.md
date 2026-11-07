# Winterlock design decisions

Decisions are numbered and dated. Open questions are listed at the end. When one is settled, it moves up as a decision.

## Goal

Give individuals and teams who are serious about security an alternative to ECDSA that is almost as convenient, and only slightly more expensive in gas.

## Decisions

**D1. A shared verifier with thin platform adapters** (2026-11-04)
WOTS and Merkle verification live in one standalone library (`contracts/src/WotsVerifier.sol`). Each platform gets a thin adapter around it. The first adapter is an ERC-7579 validator module, which installs on modular 4337 accounts, including Safe through its 7579 adapter. A Safe-owner (EIP-1271) adapter for teams may follow.

**D2. One-time keys are bound to the account nonce on-chain** (2026-11-04)
The validator works out the key index from the UserOperation nonce. A signature from key *k* is only valid for the nonce that *k* belongs to. Once that nonce is used, its keys are useless, even to someone who holds several signatures from them.

**D3. Fee policy: generous caps, rebroadcast instead of "speed up"** (2026-11-04)
Wallets sign UserOperations with fee caps well above the current base fee. EIP-1559 charges only the actual base fee plus the signed priority fee, so a high cap costs nothing extra. A stuck operation is rebroadcast unchanged. Resending the identical signed operation is always safe. Wallets don't offer "speed up", and operations carry no expiry.

**D4. Two keys per nonce** (2026-11-04)
Slot 0 signs the operation. Slot 1 is kept for a genuine replacement or cancellation at the same nonce. The signer remembers which slots it used for pending nonces. A restored signer refuses to sign at a nonce that is still pending.

**D5. A rescue bundler** (2026-11-04)
Winterlock runs a bundler that includes Winterlock operations even when the base fee rises above the signed `maxFeePerGas`, and covers the shortfall itself. The EntryPoint charges `min(maxFeePerGas, maxPriorityFeePerGas + basefee)` and doesn't require the cap to cover the base fee (checked in EntryPoint v0.7.0 and v0.8.0). Operations stay ordinary and portable: any bundler can include them while fees are within the caps, and users can always submit `handleOps` themselves. The relayer never holds user funds.

**D6. Default parameter set: 24-byte hashes with target sum 431** (2026-11-04)
`WinterlockValidator(24, 431)`: keccak truncated to 24 bytes (category 3, by analogy to SLH-DSA-192), 48 message chains whose digits must add up to 431, no checksum chains. That is 1.85× an ECDSA transfer, a 1,176-byte signature, and the same gas for every signature. The signer needs about 945 digest tries per signature. It's chosen over 16-byte hashes (1.53×, category 1) for security margin, since this audience picks hash-based signatures for safety. The other parameter sets stay in the code and the benchmark for comparison.

**D7. Threshold mode in the validator** (2026-11-04)
Each account configures 1 to 16 members and a threshold. Every member has their own key tree. A private wallet is simply the 1-of-1 case.
- **Signature format.** One entry per signing member: `[member index][slot][WOTS signature][path]`. Entries come in strictly increasing member order, which proves the signers are distinct. The signature is valid when at least `threshold` entries verify and no bytes are left over.
- **Slots per member.** Each member picks their own slot, so D4 applies per person.
- **Storage.** Members are stored in a fixed-size array inside the account's mapping entry, so validation only reads storage associated with the account (ERC-7562). A dynamic array would fall outside it, and bundlers would reject the operations.
- **No duplicate trees.** Installing the same tree twice is refused, so one tree can't vote twice.

**D8. Signature collection: an optional service, with peer-to-peer always possible** (2026-11-04)
Threshold accounts collect members' signature entries through a collection service, as Safe does with its transaction service.
- **What it does.** It stores proposed UserOperations and members' entries. It checks each entry off-chain against the member's root before accepting it, shows status, and passes complete operations to any bundler.
- **What it can't do.** It only holds public data, so it can withhold or delay an operation, but not forge one.
- **Slot warnings.** It warns a member who already signed a different proposal at the same nonce. The signer's own record of used slots still has the final say (D4).
- **Optional by design.** The signature format is the same without the service, so members can always exchange operations and entries peer to peer.
- **Hosting.** Winterlock may run the service next to the rescue bundler (D5).
- **Not planned:** on-chain approvals like Safe's `approveHash`, unless teams ask for zero off-chain infrastructure.

**D9. Keep `w` = 16 and keccak within D6** (2026-11-04)
The measurements under "`w`, hash function, EIP-7976, and Base" settle it:
- `w` = 16 beats 4 and 256 on L1 today, under EIP-7976, and on Base, even if L1 data fees rose a hundredfold.
- keccak saves about 50k gas per signature compared with SHA-256.

SHA-256 support stays in the verifier, so the question can be reopened if hardware signers turn out to need it.

**D10. One address on every chain: a master tree certifies per-chain trees** (2026-11-05)
- **Install data:** each member installs a master tree of one-time keys (default height 6, so 64 certificates). The install data holds only master roots, so it is identical on every chain and so is the account's address. The validator itself is deployed at the same address on every chain.
- **Certificates:** a master key signs a certificate for one operation tree on one chain. The certificate binds the chain id, the validator, the account, the member, the tree's root and height, and the first sequence number it signs for. The tree's public seed is derived from the same bindings and the master index (since the packed storage, below).
- **Enrolment:** the first operation a member signs on a chain carries the certificate. The validator checks it and stores the tree in the account's storage on that chain. Later operations are verified against the stored tree and cost the same as before.
- **Rotation:** the same mechanism replaces an exhausted tree. Each certificate on a chain must use a higher master index than the one before, so old certificates can't be replayed to roll a tree back.
- **What the signer must guarantee:** a master key certifies at most one tree, across all chains and accounts. Certificates are rare and recorded on-chain, so the log is small and can be rebuilt.
- **The same structure as LMS/HSS and XMSS^MT** (NIST SP 800-208).

It replaces the single key tree of D2, keeps D2's binding of keys to nonces, and resolves the open questions about one address per chain and about tree exhaustion. Per-chain trees can be small and are generated when a chain is first used, which also eases key generation on devices.

**Since D12, the stateless key signs every certificate and the master tree is gone.** The rest of D10 stands: one address on every chain, a certified operation tree per chain, enrolment by the first operation, rotation. Certificates on a chain are ordered by their start sequence alone, and there is no log of used master keys to keep.

**D11. Two signing paths: WOTS for speed, a stateless hash-based key as fallback** (2026-11-05)
- **The fast path** stays WOTS one-time keys (D6, D10) for everyday operations. It has the smallest signatures (1.2–1.7 KB) and the cheapest verification.
- **The fallback:** each member also holds a stateless hash-based key from the SPHINCS+/SLH-DSA family. It is used for:
  - **off-chain messages (ERC-1271):** a stateless key needs no record of its use, so it fits a read-only `isValidSignature` check
  - **recovery when the signer loses its state:** re-certify fresh trees instead of risking key reuse
  - **a fallback** whenever the fast path is unavailable
- **Use an existing verifier rather than write one.** The leading candidate is Nicolas Consigny's MIT-licensed SPHINCS- (keccak-based SLH-DSA variants, about 3.7 KB and 260–290k gas, unaudited).
- **The same pattern as Blockstream's SHRINCS and Consigny's JARDÍN.** It answers the main gaps in the competitor analysis of 2026-11-05: message signing, recovery after state loss, and the cost of losing state with pure WOTS.

Open:
- How ERC-1271 messages are bound to the chain and account: built as an EIP-712 wrap that names the chain, the validator and the account. Open: full ERC-7739 (nested typed data), so that wallets can show the app's typed data instead of a hash.
- Whether high-value permits should use on-chain pre-approval instead.

**D12. The stateless key is the only certificate signer; leanSphincs-keccak; category 3 later** (2026-11-05)
- **Drop the master tree.** Every certificate is signed by the member's stateless key. It removes the log of used master keys, the most dangerous state in the system. Keeping the master tree next to the stateless key would add no security, since an attacker can use the weaker path. It costs about 4.4 KB more calldata per certificate, once per chain and per rotation. Done on 2026-11-05 (measured below: 4.3 KB).
- **The parameter set is leanSphincs** (5.7 KB, 52.8k gas, a proved signature budget that covers hardware signers), not leanSphincs-s.
- **Naming (2026-11-06).** The key is the keccak version of leanSPHINCS: Tom Wambsgans' leanSphincs crate on its `keccak` branch, which SPHINCs- implements as `leanSphincs-keccak`. Nicolas Consigny files keccak versions under SPHINCS- and keeps the name leanSPHINCS for the version with a hash that's cheap to prove in zero knowledge; EIP-8288's 3,000-gas check covers only that one. So outside this log we say **leanSphincs-keccak**. Inside it, leanSphincs and leanSphincs-s mean the keccak versions.
- **The security level stays category 1 for now.** The stateless key uses 16-byte hashes and can certify trees and sign messages, so it sets the account's security level. D6's 24-byte WOTS stays. On the backburner: a stateless scheme at category 3 (24-byte hashes) that would bring the whole account to D6's level.

**D13. Teams use Winterlock as Safe owners; individuals keep the Kernel validator** (2026-11-05)
- **Teams:** the primary path is a Safe whose owners are WinterlockOwner contracts (EIP-1271), one per member. Safe does the k-of-n.
  - Teams keep Safe's contracts, its Transaction Service and its app for the queue, history and confirmations.
  - An existing Safe can upgrade in place by swapping its ECDSA owners one at a time, keeping its address and funds.
- **Individuals:** they keep the ERC-7579 validator on Kernel (ERC-4337).
- **Both share the core (D1):** the WOTS verifier, the stateless key, certificates and nonce binding.
- **Why:** the live test on Sepolia ("Safe owner, live on Sepolia" under Measurements) showed transactions working end to end, with no change to Safe's contracts, service or app. Winterlock's own pieces for teams shrink to the owner contracts and a signer that posts to Safe's service.
- **Open for this path:**
  - **Built:** a cheap owner deployment (proxy owners, about 0.34M gas per member under Glamsterdam) and a minimal signer (see Measurements, 2026-11-05).
  - **Decided:** messages follow D14 (on-chain approval for on-chain checks, collection outside Safe's service for off-chain checks).
  - **To build:** the signer's port to proxy owners, and its WalletConnect support.
  - **Checked (2026-11-06):** Safe's app lets an account that isn't an owner execute a transaction that Winterlock owners have confirmed (see "Who executes" under Measurements).

**D14. Safe messages: on-chain approval for on-chain checks, collection outside Safe's service for off-chain checks** (2026-11-05)
- **Keep leanSphincs as the stateless key** (D12 stands). leanSphincs-s would fit Safe's 5,000-byte cap, but its signature budget is only estimated, and switching means new keys, owners and validators for everyone.
- **Messages that apps check on-chain** (permits, Permit2): the team approves the message in an ordinary WOTS-signed Safe transaction through SignMessageLib. The app then checks it with an empty signature.
- **Messages that apps check off-chain** (sign-in with Ethereum): members sign with their stateless keys; Winterlock's collection service (D8) gathers and serves the signatures. They verify on-chain through the Safe's `isValidSignature`.
- **Both need the signer to answer apps itself, over WalletConnect,** because Safe's app doesn't reliably pass message results back.
- **Built:** the WalletConnect bridge in the signer, and SignMessageLib built with Safe's release settings (see "WalletConnect bridge" under Measurements). Both paths work live on Sepolia through Reown's relay (see "WalletConnect, live on Sepolia").
- **To build:**
  - an owner signature kind that defers to the Safe's own approval, because viem refuses empty signatures, confirmed live (designed in docs/notes/walletconnect.md; it changes the owner's code, so every owner address). **Built in owner v2 (2026-11-06) and live on Sepolia the same day,** accepted by viem; see Measurements, "Owner v2, live on Sepolia".
  - a revocation library, if the team wants to withdraw approvals
- **Not covered:** EIP-2612 permits that accept only ECDSA, which no smart account can sign.

## Constraints that every design must respect

- **One key tree per chain and per account.** Nonces repeat across chains and accounts. If two of them share a tree, the same one-time key ends up signing two different messages. In a threshold account this applies per member: each member needs a separate tree for every account they sign for. One master seed can derive them all. Under D12 the stateless key is shared by all chains and accounts; it signs their certificates and messages, up to its proved signature budget (D11).
- **One nonce lane per validator.** EntryPoint nonces are a 192-bit key plus a 64-bit sequence. The validator only accepts its configured key. If it accepted more than one, sequence numbers would repeat across lanes.
- **No ECDSA path left over.** An account is only as strong as its weakest way in: other validators, executors, fallback handlers, hooks, owners.

## Measurements

**2026-11-04: first gas benchmark** (`contracts/bench.sh`)

Real `handleOps` transactions on anvil (Prague rules), EntryPoint v0.7, one ETH transfer per transaction. Each figure is the average of 8 steady-state operations (nonce ≥ 1), taken from transaction receipts.

| Account | tx gas | vs ECDSA | Calldata |
|---|---|---|---|
| SimpleAccount (ECDSA, reference) | 96.4k | +0.9k | 804 B |
| Minimal account + ECDSA validator (baseline) | 95.5k | 0 | 804 B |
| Minimal account + Winterlock, height 10 (512 nonces) | 212.4k | +117k (2.22×) | 3,204 B |
| Minimal account + Winterlock, height 16 (32k nonces) | 218.7k | +123k (2.29×) | 3,396 B |
| Minimal account + Winterlock, height 20 (524k nonces) | 221.0k | +125k (2.31×) | 3,524 B |

- Where the extra goes: about 40–43k is calldata (a 2.1 KB signature plus a 32-byte path per level) and about 80k is execution. The verifier library alone costs about 75–78k; the rest is storage reads and copying the signature into the validator call.
- Each additional tree level costs about 260 gas of execution and 32 bytes (about 0.5k gas) of calldata, so tree height hardly matters.
- The cost varies by ±5k per operation, because the number of hash steps depends on the message digits.
- The EIP-7623 calldata floor doesn't apply: execution gas is high enough.
- Caveats: the minimal account isn't a production 7579 account. Kernel, Nexus and Safe7579 add the same dispatch overhead to both the ECDSA and the Winterlock rows. The verifier has had one round of tuning.

**2026-11-04: hash size × encoding** (same setup, tree height 20, average of 5 steady-state operations)

The verifier now takes the hash size `n` and the encoding as parameters (`WinterlockValidator(n, targetSum)`). Every set uses a randomizer R of n bytes, chosen by the signer and mixed into the digest. The target sum T is the highest sum at which the signer needs at most about 1,000 tries on average, computed from the exact digit-sum distribution.

| Parameter set | Security (by analogy to SLH-DSA) | Signature | tx gas | vs ECDSA | Verifier alone |
|---|---|---|---|---|---|
| ECDSA baseline | — | 65 B | 95.5k | 1.00× | — |
| n=32, checksum | category 5 | 2,176 B | 224.2k | 2.35× | 82.9k (78–90k) |
| n=32, target sum 560 | category 5 | 2,080 B | 211.6k | 2.22× | 71.4k (fixed) |
| n=24, checksum | category 3 | 1,248 B | 187.0k | 1.96× | 67.3k (65–72k) |
| n=24, target sum 431 | category 3 | 1,176 B | 176.7k | 1.85× | 54.0k (fixed) |
| n=16, checksum | category 1 | 576 B | 156.3k | 1.64× | 48.0k (43–55k) |
| n=16, target sum 300 | category 1 | 528 B | 146.3k | 1.53× | 36.9k (fixed) |

The signature column excludes the 1-byte slot and the Merkle path (20 × n bytes).

- **Hash size matters most.** Going from 32 to 16 bytes halves the number of chains (67 → 35) and halves each value, which saves about 78k gas.
- **The target sum saves another 10–13k** and makes gas the same for every signature: the target-sum rows vary by about 50 gas, against about ±8k for checksum. That helps with wallet and bundler gas estimates. The cost is signing time: about 1,000 digest hashes per signature, off-chain.
- **Target sums don't cost forgery resistance in this construction.** Every other digit pattern with the same sum has some digit lower than the revealed one, so a forger has to hit the exact same digest, just as with checksum chains. Security would only drop if digests were mapped directly onto the smaller set of valid patterns instead of retrying.
- **The general code costs a little.** n=32 checksum is about 3k more than the first benchmark, because of R and the generic masking.
- **Calldata is now a small share at n=16:** about 12k of the 51k premium. Execution, mostly the hash chains, dominates on L1. On rollups, where calldata is the expensive part, smaller hashes help even more.

Not yet tried: a different `w`, further assembly tuning, and measuring on an L2.

**2026-11-04: on a production 7579 account (ZeroDev Kernel v3.3)**

Kernel is deployed from its own production build (profile `deploy`: via-IR, 200 runs). It needs via-IR to fit under the 24 KB size limit. The ECDSA baseline is Kernel's ECDSA validator, signed the way the ZeroDev SDK signs (personal_sign of the userOpHash).

| Account | tx gas | vs Kernel + ECDSA |
|---|---|---|
| Kernel + ECDSA validator | 135.3k | 1.00× |
| Kernel + Winterlock, 24-byte target sum 431 (D6) | 213.9k | +78.6k, **1.58×** |
| Kernel + Winterlock, 16-byte target sum 300 | 183.2k | +47.9k, 1.35× |

Kernel itself costs about 40k more per operation than the minimal test account; for one thing, it writes an execution-hook slot on every operation. The absolute premium is about the same on both accounts, so the relative premium for smart-account users is smaller than the minimal-account figures suggest.

**2026-11-04: threshold mode** (parameter set D6, average of 5 steady-state transfers)

Two members sign every operation. The ECDSA baseline is a k-of-n validator of the same shape: signatures sorted by signer, owners stored per account.

| Account | Winterlock | ECDSA | Ratio |
|---|---|---|---|
| Minimal account, 1-of-1 | 178.0k | 95.5k | 1.86× |
| Minimal account, 2-of-3 | 265.1k | 106.5k | 2.49× |
| Kernel v3.3, 1-of-1 | 215.2k | 135.3k | 1.59× |
| Kernel v3.3, 2-of-3 | 303.1k | 143.2k | 2.12× |

- **Each extra WOTS signature costs about 87k gas:** about 26k for its 1.66 KB of calldata, about 54k to verify it, and about 4k to read the member's settings. An extra ECDSA signature costs 8–11k, so the multisig premium grows faster than the single-signer one.
- **Threshold support costs a 1-of-1 account about 1.3k** compared with the earlier single-key validator: one more byte and the member loop.

**2026-11-04: `w`, hash function, EIP-7976, and Base** (minimal account, single signer, 24-byte target sum unless noted)

The verifier now takes `w` (4, 16, 256) and the hash function (keccak, SHA-256) as parameters too. That generality costs about 2.5k gas per signature compared with the specialised code; D6 is now 180.5k on the minimal account and 217.7k on Kernel. EIP-7976 (Last Call, deadline 2026-11-01) raises the calldata floor to 64 gas per byte. Its column below is max(gas used, 21,000 + 64 × calldata bytes). The Base columns price the same transactions with Base's `GasPriceOracle.getL1Fee` and its gas price on 2026-11-04 (0.006 gwei).

| Parameter set | Signature | L1 today | L1 with EIP-7976 | Base today | Base, L1 fees ×100 |
|---|---|---|---|---|---|
| w=16, target 431 (D6) | 1,176 B | 1.89× | 1.89× | 1.90× | 2.77× |
| w=4, target 173 | 2,328 B | 2.04× | 2.58× | 2.06× | 3.70× |
| w=256, target 3216 | 600 B | 4.83× | 4.83× | 4.83× | 4.45× |
| w=16, target 431, SHA-256 | 1,176 B | 2.42× | 2.42× | 2.43× | 3.14× |
| 16-byte, w=16, target 300 | 528 B | 1.57× | 1.57× | 1.58× | 1.97× |
| 32-byte, w=16, target 560 | 2,080 B | 2.26× | 2.54× | 2.28× | 3.79× |
| Kernel + D6 (against Kernel + ECDSA) | 1,176 B | 1.61× | 1.61× | 1.62× | 2.38× |
| 2-of-3, D6 (against ECDSA 2-of-3) | 2 × 1,176 B | 2.54× | 2.62× | 2.56× | 4.12× |

- **`w` = 16 wins in every scenario.**
  - `w` = 4 executes slightly less but doubles the signature, so it loses on L1 and loses badly once calldata gets dearer.
  - `w` = 256 halves the signature but needs about 2,900 hash steps, so it is the worst choice even when L1 data costs 100 times today's price.
- **SHA-256 costs about 50k more gas per signature than keccak** on L1, and proportionally on L2. It's only worth it if hardware signers need it.
- **EIP-7976 leaves D6 unaffected,** because enough execution gas sits on top of the calldata. It hits the calldata-heavy sets: 32-byte hashes, `w` = 4, and threshold accounts with more signatures on lean accounts.
- **On Base, L1 data is about 1% of the cost today,** so the ratios match L1. Kernel + D6 costs about 1,300 gwei (0.0000013 ETH) per transfer, against about 800 for Kernel + ECDSA. If L1 data fees rose a hundredfold, smaller signatures would start to matter, which favours 16-byte hashes.

**2026-11-04: bundler acceptance, stage 1 (local)** (`contracts/bench/bundlers/run.sh`)

**Setup.**
- **Chain:** geth v1.16.9 in dev mode, with the same fork rules as mainnet (Osaka).
- **Contracts:** the canonical EntryPoint v0.7 and EntryPointSimulations, deployed through the deterministic deployer. Kernel v3.3 from its production build, with a FactoryStaker staked in the EntryPoint (1 ETH, one-day unstake delay).
- **Bundlers:** Rundler v0.11.0 and Alto (latest image), both in Docker.
- **Operations:** each Kernel account is deployed by an ordinary transaction, then sends two WOTS-signed transfers. Two extra probes deploy through initCode.

| Parameter set | Rundler, full ERC-7562 checks | Alto, safe mode off |
|---|---|---|
| ECDSA (control) | accepted, included | accepted, included |
| D6 (24-byte, target sum 431) | accepted, included | accepted, included |
| D6 2-of-3 | accepted, included | accepted, included |
| 16-byte, target sum 300 | accepted, included | accepted, included |
| 32-byte, checksum | accepted, included | accepted, included |
| D6 with SHA-256 | accepted, included | accepted, included |
| w = 256 | tracer timeout on some operations | accepted, included |
| Counterfactual deploy (ECDSA and D6) | rejected: CREATE2 rule | accepted, included |

- **WOTS signatures pass a real ERC-7562 bundler.** Rundler traced validation and accepted every set we would use. It checks banned opcodes, associated storage only, stake and gas. Signature size is no problem: the largest operation is 3.5 KB, against Rundler's 128 KB limit.
- **`w` = 256 is too slow to trace.** Its roughly 2,900 hash steps per signature run into Rundler's tracer timeout. That's one more reason to keep `w` = 16 (D9).
- **Counterfactual deployment through Kernel's FactoryStaker fails Rundler's CREATE2 rule, for ECDSA and Winterlock alike.** Rundler requires the staked factory entity to run CREATE2 itself, but FactoryStaker delegates to KernelFactory. That's a factory question, not a signature question. Fixes: a staked factory that deploys directly, or deploying the account in a separate transaction.
- **Gas estimation underestimated WOTS validation; fixed since.** Wallets estimate with a dummy signature. In the first run, a dummy made target-sum validation stop early, so Rundler's estimate missed the hash chains (about 57k per D6 signer). A threshold signature also stopped at its first invalid entry. The fix is below ("validation gas independent of the signature").
- **Alto's ERC-7562 checks couldn't be tested locally.** In safe mode, Alto fails on a simulation-decoding error for every operation, ECDSA control included. Its estimation also returned zero verification gas for every Kernel account, ECDSA included. Both look like local-environment issues, not Winterlock ones; stage 2 with hosted Pimlico should settle them. With safe mode off and fixed gas limits, Alto accepted and included everything.
- **Side finding:** geth 1.17's dev mode runs future forks (Amsterdam, Bogota) from genesis, and charges about 3× for writing a new storage slot. Kernel writes a new slot on every operation, so its costs need re-measuring once Glamsterdam pricing is final.

**2026-11-05: validation gas independent of the signature**

Bundlers estimate verification gas by running validation with the wallet's dummy signature, so the dummy has to cost at least as much as the real signature. Two changes:
- **The verifier hashes every chain even when the digits miss the target sum.** It replaces the digits with a fixed vector that has the target sum (w − 1 as often as it fits, then the remainder, then zeros), hashes the same number of chain steps as a valid signature, climbs the tree, and returns 0.
- **The validator verifies every entry of a threshold signature,** even after one fails. Malformed entries still stop validation at once (wrong length, slot out of range, exhausted tree), but those depend only on the signature's shape, which the dummy gets right.

| Measurement (h = 20 for the verifier) | Valid signature | Dummy |
|---|---|---|
| Verifier, D6 | 56,545 | 59,530 |
| Verifier, 16-byte target sum | 39,134 | 41,167 |
| Validator, D6 2-of-3 (h = 4) | 124,621 | 126,109 |

- **A valid signature costs nothing extra.** Only an invalid one runs the digit replacement, about 60 gas per message digit. Inside the validator the surplus is smaller: 0.7k per invalid entry.
- **The surplus is free.** EntryPoint v0.7 charges for the verification gas actually used, and its 10% penalty applies only to unused execution gas. The surplus only raises the prefund a little.
- **Checksum encoding can't be estimated exactly,** since its chain steps vary by about ±8k per signature. That's one more argument for the target sum (D6).
- **Standard estimation now works.** We re-ran stage 1 on Rundler, with the driver submitting the bundler's estimates unchanged, as a wallet SDK would. Every set Rundler accepted before was accepted and included again, 2-of-3 included. The w = 256 timeout and the CREATE2 rejections are unchanged. Rundler's verification-gas estimates for the second transfer, ECDSA versus Winterlock:

  | Parameter set | Estimate |
  |---|---|
  | ECDSA (control) | 112k |
  | 16-byte | 151k |
  | D6 | 179k |
  | D6 SHA-256 | 251k |
  | D6 2-of-3 | 269k |

**2026-11-05: bundler acceptance, stage 2 (hosted bundlers, Arbitrum Sepolia)** (`contracts/bench/bundlers/testnet.sh`)

**Setup.**
- **Contracts:** the canonical EntryPoint v0.7 and ZeroDev's production Kernel v3.3 (implementation, factory, ECDSA validator), with its meta factory staked at 0.1 ETH. Only the five Winterlock validators are ours.
- **Bundlers:** Pimlico (Alto), Candide (its own bundler, public endpoint) and Alchemy (Rundler).
- **Operations:** the same as in stage 1. Every operation uses the bundler's own gas estimates and gas prices, unchanged.
- **Signing:** on a local anvil node, so the test signer, whose keys come from public labels, stays off the public chain.

| Parameter set | Pimlico | Candide | Alchemy |
|---|---|---|---|
| ECDSA (control) | included | included | included |
| D6 | included | included | included |
| D6 2-of-3 | included | included | included |
| 16-byte | included | included | included |
| 32-byte, checksum | included | included | included |
| D6 with SHA-256 | included | included | included |
| w = 256 | included | included | included |
| Counterfactual deploy (ECDSA and D6) | included | included | rejected: CREATE2 rule |

Gas used per transfer on an already deployed account (second transfer), as each bundler charged it:

| Parameter set | Pimlico | Candide | Alchemy | vs ECDSA |
|---|---|---|---|---|
| ECDSA (control) | 136,327 | 133,083 | 133,492 | 1.00× |
| 16-byte | 189,327 | 184,904 | 185,325 | 1.39× |
| D6 | 221,563 | 215,951 | 216,384 | 1.62× |
| D6 SHA-256 | 271,973 | 266,361 | 266,794 | 2.00× |
| 32-byte, checksum | 273,395 | 269,485 | 269,918 | 2.02× |
| D6 2-of-3 | 314,885 | 306,801 | 307,258 | 2.31× |
| w = 256 | 501,633 | 496,858 | 497,303 | 3.71× |

- **The three most-used bundler implementations all accept WOTS-signed operations from a production Kernel.** That holds for every parameter set, threshold signatures included, and with each bundler's own estimates. The ratios match the local benchmark: D6 costs 1.62× an ECDSA transfer on Kernel, 2-of-3 about 2.3×. At testnet prices, a D6 transfer cost about 4,400 gwei of ETH against about 2,700 for ECDSA.
- **The signature's bytes are about a third of D6's extra cost on Arbitrum.** Preverification gas rose by about 28k for 1.6 KB, roughly the calldata price. Validation adds the other ~57k.
- **Counterfactual deployment through Kernel's meta factory works on Pimlico and Candide, but not on Alchemy, for ECDSA as well.** ERC-7562 rule OP-031 only says that CREATE2 may run once during deployment and must create the sender. Rundler also demands that the staked factory run it itself, which Kernel's meta factory doesn't. So a ZeroDev account's first operation can't go through Alchemy. That's a Kernel/Rundler question, not a Winterlock one. A wallet can deploy the account in an ordinary transaction, or route the first operation to another bundler.
- **The hosted bundlers accept w = 256,** unlike the local Rundler, which timed out tracing it. The local timeout was a matter of local resources, but w = 256 costs 3.7× ECDSA, so D9 stands.
- **Practical notes:**
  - Pimlico and Arbitrum's public RPC refuse Python's default User-Agent (HTTP 403), so the driver sends its own.
  - Alchemy needs each network enabled per app.
  - Test cost: about 0.09 ETH of the 0.25 bridged, almost all of it parked as 0.003 ETH balances in 29 test accounts. Gas itself came to about 0.0002 ETH.
- **Deployed validators (Arbitrum Sepolia):**
  - D6: `0xC6b12d267b4b04f2c0aCC9dae64ed912832d69cf`
  - 16-byte: `0xAC907c93E8f7591A300a033B2ff0ED6Ebb34B43d`
  - 32-byte checksum: `0xC3C2D49CB6a207A68858114FF852fe3a4C50ceC1`
  - SHA-256: `0x18565b26FFb7BFa10f8c2f54889e71c928Fd6c08`
  - w = 256: `0xDC9f57B3caa9847F0A838ffb1e034B5d2a0Ab6Ef`

**2026-11-05: D10 certificates, validator (step 1)** (`contracts/test/WinterlockCertificates.t.sol`, `bench/bundlers/run.sh`)

The validator now installs master trees and stores per-chain operation trees certified by them. The tests cover:
- enrolment on the first operation
- rejection when there is no tree, a certificate from another chain or for another account, or a foreign master tree
- the start and master-index bounds
- rotation, and rollback to an old tree
- a direct call storing only valid certificates

| D6, height-3 operation tree, master height 6 | Validation gas |
|---|---|
| Steady state (tree enrolled) | 66,623 |
| With certificate (first operation on a chain) | 167,202 |
| Dummy carrying the real certificate | 169,978 |

- **A certificate is 1,379 bytes** and adds about 100k validation gas: one master verification (~57k) and two new storage slots (~44k).
- **Measured end to end on Kernel with Rundler (local),** the first D6 operation on a chain costs about 130k gas more than later ones, after subtracting what any first operation costs. That's validation plus about 55k preverification gas, because Rundler prices the 1.4 KB at the EIP-7623 floor. A 2-of-3 team pays it once per signing member: about 290k for two members.
- **The steady state is unchanged:** 210.8k gas per D6 transfer on Kernel, against 210.2k before D10.
- **Rundler accepts the storage write in validation** under full ERC-7562 checks: certificate operations were accepted and included, single and 2-of-3, with Rundler's own estimates.
- **Validation writes storage only for a valid certificate.** An account can call the validator outside the EntryPoint, from a batch or an executor. If an invalid certificate were stored, such a call could install an attacker's tree. So wallets put the real certificate into the dummy signature for gas estimation; the certificate doesn't depend on the operation.

**2026-11-05: D10 across chains (steps 2–4)** (`script/DeployValidator.s.sol`, `test/integration/KernelMultichain.t.sol`, `bench/bundlers/multichain.sh`)

- **Deterministic validator.** `DeployValidator.s.sol` deploys through the deterministic deployment proxy with a fixed salt, so the address depends only on the bytecode and the parameter set. D6 sits at `0xd2B64A501c37957EF154A5971BbEBE417726b535`, now deployed on Ethereum Sepolia and Arbitrum Sepolia with identical code. A change to the source or the compiler settings changes the address, so a release pins both.
- **Two chains in Foundry.** The Kernel tests run one deployment as two chains, from a state snapshot with different chain ids. They show:
  - the same account address on both chains, deployed on each by its first WOTS-signed operation
  - a separate operation tree on each chain, under master keys 0 and 1
  - one chain's certificate refused on the other
  - the other chain's tree refused, with or without its certificate
- **Live.** One account, `0x88edb7859e1986515e721ed42D954E1c7A181a65`, on Ethereum Sepolia and Arbitrum Sepolia, deployed on each chain by its first operation through Pimlico. Each first operation carried that chain's certificate, and each chain has its own tree.

| Live, Pimlico | Ethereum Sepolia | Arbitrum Sepolia |
|---|---|---|
| Deploy + certificate + transfer | 1,734,026 gas | 578,776 gas |
| Next transfer | 431,536 gas | 213,417 gas |
| Operation tree | master key 0 | master key 1 |

**Glamsterdam on Sepolia.** Sepolia has run Glamsterdam since 2026-10-06; `eth_config` lists the ePBS builder contracts. This is the first measurement of Winterlock under its repricing, which makes new state much more expensive (EIP-8037, part of EIP-8007):
- **Deploying the validator** took 14.8M gas on Sepolia, against 2.1M on Arbitrum Sepolia. That is close to the 16.7M transaction gas cap. Forge's local simulation still prices the old way and set too low a limit (the transaction ran out of gas), so I deployed with `cast send` to the proxy and an explicit gas limit.
- **Same chain, ECDSA against D6 on Kernel,** with each bundler's own estimates:

  | Sepolia (Glamsterdam) | Candide | Alchemy | vs ECDSA |
  |---|---|---|---|
  | ECDSA transfer | 241,703 | 238,581 | 1.00× |
  | D6 transfer | 325,160 | 322,063 | 1.35× |
  | D6 first transfer with certificate, over steady state | +299k | +300k | once per chain and member |
  | Counterfactual deploy, D6 against ECDSA | 1,510,003 vs 909,197 | rejected (CREATE2 rule) | +601k once |

- **D6 costs only 1.35× ECDSA under Glamsterdam,** against 1.62× on Arbitrum. State access got dearer for every account, and WOTS hashing did not.
- **New state is where Winterlock now pays:**
  - A certificate stores two new slots, about 300k gas once per chain.
  - The account's install data takes three slots (configuration and the master tree) against one for ECDSA.
  - Together, the first operation on a chain costs about 600k gas more than ECDSA's. A possible saving: pack the operation tree into one slot. For D6 that's root, start, master index and height in 32 bytes, with the tree's public seed derived from the master seed and index.
- **Preverification gas differs by bundler.** For D6's extra 1.6 KB, Pimlico charged about 110k on Sepolia, Candide and Alchemy about 26k (16 gas per byte).
- **Funding matters with Pimlico.** Pimlico simulates at its own gas price (about 1.2 gwei on Sepolia, where the base fee is about 1,000 wei). Test accounts funded with 0.001 ETH failed its estimation with AA21 (prefund). That was the cause of three Pimlico failures in this run; the 0.01 ETH-funded live run went through.

**2026-11-05: packed storage for D10** (`src/WinterlockValidator.sol`, `test/WinterlockCertificates.t.sol`)

Glamsterdam makes new storage slots the most expensive thing Winterlock does, so the validator now stores less:
- **Master tree: one slot** holding a commitment to its root, seed and height. The certificate carries the master seed and height (17 bytes), and the validator checks them against the commitment.
- **Operation tree: one slot** for hash sizes up to 24 bytes: root in the high bytes, then start (40 bits), master index (16 bits) and height (8 bits).
  - The tree's public seed is no longer stored. It is derived as `treeSeed(chain, validator, account, member, master index)`, which is unique per tree because a master key certifies only one tree.
  - 32-byte hashes keep a second slot.
- **New checks:** the certificate's root must be high-aligned and its start must fit in 40 bits. A mutation test confirms that without the alignment check a properly signed certificate would corrupt the packed fields.
- **New address:** the D6 validator moved to `0x05326803001b3FD4875005aACe351f3E3Ecc685E` (both testnets, identical code; deploying took 15.0M gas on Sepolia).

**Saving, measured on Sepolia (Glamsterdam) with the bundlers' own estimates, against the run before packing:**

| D6 on Kernel | Candide | Alchemy |
|---|---|---|
| First transfer with certificate | 722,405 → 610,991 (−111k) | 817,504 → 706,102 (−111k) |
| Later transfers | 325,160 → 323,660 (−1.5k) | 322,063 → 320,587 (−1.5k) |
| Counterfactual deploy + certificate | 1,510,003 → 1,290,634 (−219k) | rejected (CREATE2 rule) |

**Against ECDSA, same chain and run:**
- **Later transfers:** 1.34× with Candide and Alchemy, 1.63× with Pimlico, whose preverification gas charges more per signature byte.
- **A chain's first certificate:** about 189k gas over the steady state, against about 300k before packing.
- **First operation on a new chain:** +381k gas over ECDSA (Candide), against +601k before.
- **What's left of that first-operation surcharge:**
  - the certificate's master verification and calldata
  - two new slots: the master commitment and the tree
  - ECDSA's own install writes one new slot

In Foundry (old pricing), validation drops from 66.6k to 65.1k gas per operation, and from 167.2k to 143.7k with a certificate.

All three bundlers accepted every operation, Alchemy's Rundler included (full ERC-7562 checks), apart from the known CREATE2 rejection of counterfactual deploys at Alchemy.

**2026-11-05: D11, stateless key (steps 1–5)** (`src/vendor/sphincs-minus/`, `test/StatelessVerifier.t.sol`, `test/WinterlockStateless.t.sol`, `test/WinterlockMessages.t.sol`, `test/integration/`)

Each member now has a stateless leanSphincs key next to its master tree. It certifies operation trees, signs ERC-1271 messages, and recovers a signer that lost its state.

**The verifier.** leanSphincs over keccak256 (leanSphincs-keccak, see D12's naming note) is the `keccak` branch of Tom Wambsgans' leanSPHINCS proposal, in the implementation of Nicolas Consigny's SPHINCs- (`src/keccak/LeanSphincsAsm.sol`, commit `4c76aaf`, MIT). It is vendored unchanged, with its licence and a provenance header, in `src/vendor/sphincs-minus/`, and the upstream known answers sit in `test/fixtures/`. The parameters: one XMSS layer of height 26, FORS with 24 trees of 1,024 leaves, WOTS+C with 64 chains (w = 4, target sum 120), 16-byte hashes.

| Candidate (SPHINCs- figures, verify gas measured here for leanSphincs) | Signature | Verify gas | Signatures per key at 128 bits | Signing work per signature |
|---|---|---|---|---|
| **leanSphincs** | 5,684 B | 52.8k | 210k / 22M / 1.15B (Light / Standard / Full signer), proved in Lean | 70–92k hashes: 13 s at the rate of Ledger's SPHINCS+ benchmark, but about 1.5–2.5 min with keccak on a Ledger Nano S+ (see Open questions); under 1 ms on a CPU |
| leanSphincs-s | 4,164 B | ~39k | 20k / 2.1M / 67M, estimated | 155–178k hashes |
| C7 (WOTS+C, FORS+C) | 3,704 B | ~96k | 2^20 | 4.3M hashes: 12 min at the same benchmark rate |
| C13 | 3,688 B | ~105k | 2^20 | ~10M hashes |
| C12, JARDÍN's SPX | 6,512–6,592 B | 204–276k | 2^14; 109 bits at 2^18, 95 at 2^20 | ~37k hashes |
| SLH-DSA-SHA2-128-24 (FIPS 205) | 3,856 B | ~142k | 2^24 | ~1B hashes |

- **Why leanSphincs:**
  - It covers the 2^14–2^20 signatures one key needs across all chains and messages, in every signer tier. That includes the 16 KiB Light tier for hardware wallets; leanSphincs-s's Light tier stops at 20k signatures.
  - Its signature budget is proved, not estimated.
  - It verifies for less gas than one D6 WOTS signature (57k). C7 and C13 cost twice as much, the SPX family four to five times.
  - What it costs against leanSphincs-s: 1.5 KB more calldata and 14k more gas per verification.
- **Licences:** SPHINCs- has an MIT licence file. JARDÍN has none, although its sources carry MIT headers. Its registration verifier is the same code as SPHINCs-' C12, so nothing needs vendoring from JARDÍN.
- **Compiler:** the vendored file compiles with via-IR (`foundry.toml`, `compilation_restrictions`), as upstream measures it: 52,750–52,896 gas in its own frame over the known answers, and 57.1k when called from a contract (the 5.7 KB copied into the call). Our default legacy pipeline would cost 58.0k.
  - Nothing imports the source: the validator and the tests use `IStatelessVerifier` and deploy from the artifact, so it is compiled once.
  - After changing compiler restrictions, run `forge clean`: Forge kept a stale artifact.
- **Test signer:** `test/utils/StatelessSigner.sol`, plain Solidity written from the upstream spec. It reproduces byte for byte the two b = 10 vectors of the upstream fixture and the known answer of the upstream crate, so signer and verifier cross-check each other.
  - No FFI.
  - Test keys keep a subtree of height 10: keygen takes about 0.1 s in Forge, a signature about 0.2 s.
  - WOTS-only tests get a placeholder stateless public key that nobody can sign for, so they skip the keygen.

**Install data and storage.**
- **Install data:** each member gains `statelessKey`, the 32-byte leanSphincs public key (root ‖ public parameter). The install data still has no chain-specific field.
- **Storage:** still one slot per member, now `memberCommitment(masterCommitment(root, seed, height), statelessKey)`.
- **What each certificate carries:** a master certificate carries the stateless key (32 more bytes, one more hash); a stateless certificate carries the master commitment.
- **New install checks:** both halves of a stateless key must be nonzero, and no two members may share one.

**Stateless certificates.** Flag bit 6 marks one, carried as `[root][height][start][master commitment][stateless key][signature]`, 5,789 bytes.
- **Bindings:** the digest has its own domain and binds the chain, the validator, the account, the member, the root, the height and the start. A certificate for another chain, validator, account or member is refused (tested one by one).
- **Tree seed:** the tree's public seed is derived from its start: `statelessTreeSeed`.
- **Packed tree:** the root, then start (40 bits), next master index (17), a stateless flag (1) and height (6).
- **Rotation:** start sequences only grow. Every certificate on a chain, of either kind, must start after the stored tree. Master certificates keep D10's master-index rule as well, and a stateless certificate keeps the master floor, so spent master keys stay spent.
  - This tightens D10. Before, a master certificate only needed a higher master index. Under the old rule, a stateless certificate replaced by a master certificate with an earlier start could have been replayed.
- **Storage writes:** only valid certificates are stored, also on direct calls.
- **Gas estimation:** a wallet's dummy signature must carry the real certificate. The verifier stops early on an inadmissible WOTS+C counter (about 100 fewer hashes), so a garbage stateless signature in the dummy would underestimate.

| D6, height-3 operation tree, validator and verifier cold (Foundry, old pricing) | Validation gas | Certificate |
|---|---|---|
| Steady state | 65,335 (was 65.1k) | — |
| With master certificate | 144,434 (was 143.7k) | 1,412 B |
| With stateless certificate | 147,758 | 5,789 B |
| Dummy carrying the real stateless certificate | 150,534 | |

- **Validation costs about the same for both kinds:** one leanSphincs verification (52.8k plus 4k to pass 5.7 KB) against one WOTS master verification (57k), and one new slot either way.
- **The difference is calldata:** 4.4 KB more, about 70k gas at 16 gas per byte, up to 175k where a bundler prices preverification at the EIP-7623 floor.

**ERC-1271.** `isValidSignatureWithSender` was hard-coded to refuse. It now checks members' stateless signatures of an EIP-712 wrap: domain "Winterlock", version 1, the chain id and the validator, message `WinterlockMessage(address account, bytes32 hash)`.
- **Signature format:** one entry per signing member, in increasing member order: `[member index][master commitment][stateless key][signature]`, 5,749 bytes. Teams need `threshold` entries, and one invalid entry fails the whole signature.
- **Bindings:** a signature counts for one account, on one chain, under one validator (tested). It doesn't rely on the account's own wrap, so it also holds on accounts that pass the raw hash.
- **Messages and certificates can't stand in for each other:** a message signature is over the wrap, never over a raw hash, and the two digests have different preimage formats (tested both ways).
- **Kernel v3.3:** Kernel hands its root validator its own EIP-712 wrap, `Kernel(bytes32 hash)` over the account's domain, and the member signs Winterlock's wrap of that. In Kernel's replayable mode, Kernel's wrap drops the chain id, but Winterlock's keeps it, so the signature still counts on one chain only (tested).

| ERC-1271 check, validator and verifier cold | Gas | Signature |
|---|---|---|
| Validator, 1-of-1 | 69,052 | 5,749 B |
| Validator, 2-of-3 | 127,900 | 11,498 B |
| `Kernel.isValidSignature`, 1-of-1 (Kernel's frame) | 81,642 | 5,750 B |

**Recovery** (`test_recoveryAfterStateLoss`, on Kernel).
- **The scenario:** an account runs on master key 0's tree for nonces 0–2, then the signer loses its state. From its seeds and the chain alone, it certifies a fresh tree with the stateless key from the current nonce, 3. Operations continue without certificates.
- **The old tree is revoked:** it is refused with and without its certificate, although it still had unused keys for that nonce. Master key 0 stays spent.
- **No direct stateless-signed UserOperation path is needed.** A stateless certificate plus a WOTS signature from a freshly generated small tree costs about 148k validation gas once, then 65k per operation. A direct path would cost 5.7 KB and about 60k gas on every operation, and add a second signature shape for gas estimation. A signer that can sign leanSphincs can also generate a WOTS tree of height 3–10.
- **Caveats:**
  - A signer that loses its state again before its recovery operation lands, and derives tree secrets from the chain, account and start alone, would rebuild the same tree. It must follow D4's rule for pending nonces, or mix fresh randomness into the tree secrets.
  - Uninstalling and reinstalling the module resets the rotation state, as it does for master certificates.

**Deployment.**
- **Constructor:** the validator takes the verifier's address.
- **Deterministic deployment:** `ValidatorDeployment` now deploys the verifier first, at its own deterministic address, shared by every parameter set.
- **New addresses:** the bytecode changed, so the validator's address changed too. Nothing was redeployed: the addresses above, and `bench/bundlers/multichain.py`, still name the old validator.

**2026-11-05: D12, the stateless key signs every certificate; Kernel's enable mode locked** (`src/WinterlockValidator.sol`, `test/WinterlockCertificates.t.sol`, `test/WinterlockMessages.t.sol`, `test/integration/`)

The master tree is gone. A member is its stateless leanSphincs key and nothing else.

**What changed.**
- **Install data:** `abi.encode(nonceKey, threshold, bytes32[] keys)`, each member's 32-byte stateless public key (root ‖ P). Both halves must be nonzero, and no two members may share a key. Still nothing chain-specific, so the address is the same on every chain.
- **Storage:** a member's slot holds the key itself, no commitment. An operation tree is still one slot (D6): the root, then start (40 bits) and height (8 bits).
- **Certificate:** flag bit 7 marks one; any flag bit other than the slot and bit 7 makes the entry malformed. It carries `[root][height][start][stateless signature]`, 5,725 bytes; the validator takes the key from storage. That is 64 bytes less than D11's stateless certificate and 4.3 KB more than a master certificate (1,412 bytes).
- **ERC-1271 entries:** `[member index][stateless signature]`, 5,685 bytes.
- **Removed:** master trees, master commitments, master indices and their bits in the packed tree, the master certificate's domain and tree seed, the master height limit, the stateless flag bit.

**Tests.** `WinterlockStateless.t.sol` is merged into `WinterlockCertificates.t.sol`. Tests that only made sense for master trees are gone (master index bounds and order, master seed and commitment checks, mixed kinds). The properties they protected are kept on the stateless certificate:
- binding to the chain, the validator, the account and the member, one by one; another key's signature is refused
- start sequences strictly increase on a chain: no rollback, no skipped start used later, no second tree for one start
- the start isn't in the future and fits in 40 bits (the largest start that fits is accepted)
- the root is high-aligned
- only valid certificates are stored, also on direct calls to `validateUserOp`
- a dummy carrying the real certificate costs at least as much gas as the real signature
- the tree seed is derived from the chain, the validator, the account, the member and the start (checked against the formula)

Every member now needs a real stateless key, so tests keep it in storage after one keygen (about 0.25 s in Forge).

**Gas and size** (D6, height-3 operation tree, validator and verifier cold, Foundry, old pricing). "Before" is the previous commit, measured again with the same Foundry; it is 10–20 gas above the D11 tables.

| Measurement | Before (D11) | After (D12) |
|---|---|---|
| Validation, steady state | 65,335 | 65,170 |
| Validation, first operation with certificate | 147,768 | 146,701 |
| Its dummy, carrying the real certificate | 150,544 | 149,477 |
| Certificate | 5,789 B | 5,725 B |
| ERC-1271 at the validator, 1-of-1 | 69,062 (5,749 B) | 68,137 (5,685 B) |
| ERC-1271 at the validator, 2-of-3 | 127,920 (11,498 B) | 126,038 (11,370 B) |
| `Kernel.isValidSignature`, 1-of-1 (Kernel's frame) | 81,652 (5,750 B) | 80,699 (5,686 B) |
| `Kernel.isValidSignature`, 2-of-3 (Kernel's frame) | not measured | 139,787 (11,371 B) |
| Validator runtime code | 12,577 B | 9,933 B |

- **Slightly cheaper everywhere.** The key comes from storage, so the validator no longer hashes a commitment or copies 64 more bytes per entry. The simpler tree slot saves 165 gas per operation.
- **Against the master certificate it replaces:** 2.3k more validation gas (146.7k against 144.4k) and 4.3 KB more calldata. That's about 69k gas at 16 gas per byte, or up to 173k where a bundler prices preverification at the EIP-7623 floor. It's paid once per chain, per rotation and per signing member.
- **The validator is a fifth smaller,** so it also costs less to deploy.

**Kernel's enable mode is refused by design.**
- **The risk:** Kernel v3.3's enable mode installs a validator inside a UserOperation once the root validator approves Kernel's EIP-712 "Enable" digest through `isValidSignatureWithSender`. Kernel asks with the account itself as the sender (`ValidationManager._verifyEnableSig`). The new validator then validates the rest of the operation. Members' message signatures involve no WOTS key, so a quorum of them could install a module and act through it: a phished "sign this message" would become a takeover.
- **The lock:** `isValidSignatureWithSender` fails when `sender == msg.sender`, that is, when the account asks on its own behalf. Apps are unaffected, since `Kernel.isValidSignature` names the app that asks.
- **Test** (`test_enableModeRefused`, on Kernel v3.3): a 2-of-3 team account and a real enable-mode operation. The nonce is in Kernel's enable mode and names Kernel's ECDSA validator, to be installed with an attacker's key and the `execute` selector. Two members sign Kernel's enable digest through Winterlock's message wrap, and the ECDSA key signs the rest: a 5 ETH transfer. The validator accepts the same quorum signature when an app asks. The operation is refused (AA23, `EnableNotApproved`), nothing is installed and no funds move.
- **Mutation check:** with the lock removed, the same test fails. Kernel installs the ECDSA validator with the attacker's key, it validates the operation, and the 5 ETH leave the account. With the lock restored, the test passes.
- **Message signing for apps still works:** through `Kernel.isValidSignature`, 1-of-1 and 2-of-3 (tested). A unit test refuses the account as the sender for both.

**Bundlers** (`bench/bundlers/run.sh`, local Rundler v0.11.0 with full ERC-7562 checks, the bundler's own estimates).
- **Rundler accepts stateless certificates.** Every first operation, which carries the certificates, was accepted and included, single and 2-of-3, for all five parameter sets. The call to the verifier and the storage write pass its tracing.
- **Counterfactual deploys:** rejected by the CREATE2 rule, for ECDSA too (unchanged, see stage 1).
- **w = 256** passed this time; it hit the tracer timeout in stage 1, which depends on local resources.
- **Signing:** the test signer needs about 50M gas for a stateless keygen and 55M per signature. So geth now runs without an eth_call time limit, and the driver calls the signer helper with a 2-billion gas limit.

| Rundler (local), gas used | First transfer, with certificate | Second transfer | Difference |
|---|---|---|---|
| ECDSA (control) | 192,925 | 124,690 | 68k: what any first operation costs |
| D6 | 566,712 (7,383 B signature) | 209,356 (1,658 B) | 357k |
| D6 2-of-3 | 1,009,285 (14,766 B) | 339,017 (3,316 B) | 670k |

- **A chain's first D6 operation costs about 289k gas more than the next,** after subtracting the 68k any first operation costs. With master certificates it was about 130k (D10, step 1). Most of the difference is calldata: Rundler prices preverification at the EIP-7623 floor, 40 gas per byte, so the 5.7 KB certificate costs about 229k of preverification gas. A 2-of-3 team pays it per signing member: about 600k for two.
- **The steady state is as before:** 209.4k gas per D6 transfer, with Rundler's verification estimate at 180k (271k for 2-of-3).

**Deployment.**
- **New addresses:** the bytecode changed, and builds are now reproducible (next point). The deterministic D6 validator moves to `0xE8bE004Eae7A744a0e626b4bdeDD8b506547ACE0`, and the stateless verifier to `0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254`. Neither is deployed anywhere yet. `bench/bundlers/multichain.py` names the validator, so the live multichain run needs a deployment first.
- **Fixed: the address depended on the checkout's path.**
  - Forge passes the compiler remappings for nested libraries with absolute paths. They ended up in the contract metadata, whose hash was part of the bytecode, so building the same commit from another directory gave other addresses, for the verifier too.
  - `foundry.toml` now sets `bytecode_hash = "none"`.
  - Checked: a copy of the repository built at another path predicts the same two addresses.

**2026-11-05: Safe owner spike** (`src/safe/WinterlockOwner.sol`, `script/DeploySafeOwner.s.sol`, `test/WinterlockOwner.t.sol`, `test/integration/SafeWinterlockOwner.t.sol`)

The question: can Winterlock be a Safe owner, an EIP-1271 contract owner checked by Safe's ordinary multisig path, so that teams keep their Safe, Safe's app and the Transaction Service? For transactions, yes, at about 90k gas per owner signature. Messages work on-chain but don't fit the Transaction Service.

**Setup.**
- **Safe's contracts** are submodules at tags v1.4.1 (`bf943f8`) and v1.5.0 (`dc437e8`). `setup.sh` builds them with their release settings (solc 0.7.6, optimizer off, EVM istanbul, as each release's CHANGELOG states), and the tests deploy them from those artifacts and run against both releases.
  - The bytecode is not byte-identical to the canonical deployments: the code hashes listed in safe-deployments differ. Not investigated; the metadata is the likely cause.
  - Remappings `safe-v1.4.1/` and `safe-v1.5.0/`; the tests drive both releases through v1.5.0's `ISafe`, since the calls they make have the same ABI in both.
- **Safe's app deploys v1.4.1 by default:** `LATEST_SAFE_VERSION` defaults to `'1.4.1'` in the wallet's `packages/utils/src/config/constants.ts`. The hosted app can override it through its environment.
- **The Transaction Service's behaviour** below is read from its source and from safe-eth-py, the library it checks signatures with (both as of 2026-11-05).

**Question 1: what Safe passes to a contract owner (v = 0).**
- **v1.4.1** calls the legacy `isValidSignature(bytes data, bytes signature)` and wants `0x20c13b0b` (`Safe.sol:315`, `ISignatureValidator.sol:6`).
  - `data` is the EIP-712 preimage of the hash, `0x1901 ‖ domainSeparator ‖ SafeTx struct hash`, 66 bytes (`encodeTransactionData`, `Safe.sol:410`).
  - Safe first checks `keccak256(data) == dataHash` (GS027, `Safe.sol:287`).
- **v1.5.0** calls `isValidSignature(bytes32 dataHash, bytes signature)` and wants `0x1626ba7e` (`checkContractSignature`, `Safe.sol:270`; `ISignatureValidator.sol:7`). The legacy `checkSignatures(bytes32, bytes, bytes)` and `checkNSignatures` overloads remain but ignore `data` (`Safe.sol:355`, `:372`).
- **Where the data sits:** each signer has a 65-byte static part, in increasing owner order: r = the owner contract's address, s = the offset of its data in the signatures blob, v = 0. The data follows all static parts, as `[length: 32][bytes]`. Safe checks:
  - s ≥ threshold × 65 (GS021)
  - s + 32 ≤ blob length (GS022)
  - s + 32 + data length ≤ blob length (GS023)
  - (v1.4.1 `Safe.sol:295–306`; v1.5.0 `Safe.sol:316`, `:248`, `:258`)
- **Size limits:** none on-chain apart from gas. The Transaction Service caps a confirmation and a message signature at 5,000 bytes (`SIGNATURE_LENGTH`, `utils/constants.py`), counting the whole entry: 65 + 32 + the data. The proposer's signature in a new transaction proposal has no cap in its serializer.

**Question 2: the Safe's nonce, before and during execution.**
- **Safe increments its nonce before it checks signatures,** in both releases: v1.4.1 runs `nonce++` (`Safe.sol:170`) and then `checkSignatures` (`:172`); v1.5.0 passes `nonce++` to `getTransactionHash` (`:145`) and then calls `checkSignatures` (`:147`). During execution an owner that reads the Safe's nonce sees the signed nonce + 1, with the Safe as msg.sender (tested with a probe owner on both releases).
- **The Transaction Service checks each confirmation with an eth_call straight to the owner contract** (safe-eth-py, `SafeSignatureContract.is_valid`):
  - first `isValidSignature(bytes32 safeTxHash, data)`
  - then, because the service passes no Safe version, the legacy entry point with the preimage
  - msg.sender is not the Safe, and the Safe's nonce is the signed nonce (the next transaction) or lower (a queued one).
- **So an owner can rely on neither the Safe's nonce nor msg.sender. The binding:**
  - A transaction signature carries the Safe's address and the ten SafeTx words. The owner recomputes Safe's EIP-712 hash from them (domain: this chain's id and the Safe) and refuses the signature unless it is the hash being checked.
  - The key index then comes from the SafeTx's own nonce: keyIndex = (nonce − start) × 2 + slot.
  - The answer doesn't depend on who asks or when. Tested: an eth_call from address 0 before execution, a queued transaction, both entry points, then execution.
- **Each WOTS key verifies only for a SafeTx of one Safe, on one chain, at one nonce.** The signer keeps D4's rule: slot 0 signs, slot 1 replaces or cancels.

**Question 3: messages.**
- **Apps ask the Safe `isValidSignature(bytes32 h, sig)`.** The Safe has no such function, so its fallback handler answers. CompatibilityFallbackHandler wraps h in `SafeMessage(bytes message)` with message = `abi.encode(h)`, in the Safe's EIP-712 domain, and has the Safe check its owners:
  - **v1.4.1:** the handler (`:77–81`) calls the Safe's legacy `isValidSignature(abi.encode(h), sig)`, which comes back through the fallback to `:28–39`. That builds the 66-byte preimage of the SafeMessage hash (`:31`, `:56–59`) and calls `checkSignatures(messageHash, messageData, sig)` (`:36`). The owner gets `isValidSignature(messageData, data)`.
  - **v1.5.0:** the handler (`:73–86`) builds the same message and calls `checkSignatures(address(0), messageHash, sig)` (`:83`). The owner gets `isValidSignature(messageHash, data)`. The legacy entry point is gone from the handler.
- **An owner can't tell a message from a transaction by the hash alone:** both are an EIP-712 hash in the Safe's domain. WinterlockOwner's message signature carries keccak256(message). The owner recomputes the SafeMessage hash for the named Safe on this chain, then checks the stateless key's signature of `messageDigest(safe, hash)`.
- **A message signature can't approve a transaction.** If a member is phished into signing a SafeTx hash as a "message", the owner refuses the result, because that hash is not a SafeMessage hash (tested, with a mutation check).
- **Nested Safes:** if a team's Safe owns another Safe, the parent's transactions reach the team's Safe as SafeMessages. Members approve them with their stateless keys, so they get no WOTS nonce binding.

**Design: `WinterlockOwner`, one contract per member.**
- **Keys:** the member's leanSphincs key is its only long-term key (`KEY`, immutable). The contract reuses WotsVerifier and the stateless verifier (D1).
- **Signatures:**
  - transaction: `[slot][safe: 20][SafeTx: 10 × 32][WOTS signature][path]`
  - message: `[0x02][safe: 20][keccak256(message): 32][stateless signature: 5,684]`
  - Both EIP-1271 entry points answer: bytes32 with `0x1626ba7e`, legacy with `0x20c13b0b`. Malformed input gets `0xffffffff` and never reverts.
- **Enrolment:** `enroll(safe, root, height, start, signature)` is permissionless. The owner check is a view call (STATICCALL), so it can't store a certificate the way validateUserOp does; a certificate (5.7 KB) wouldn't fit a confirmation anyway. D12's properties hold:
  - the certificate binds the chain, the owner contract, the Safe, the root, the height and the start
  - start nonces only grow
  - only valid certificates are stored
  - one slot per Safe (root, start in 40 bits, height in 8 bits); the tree seed is derived from the chain, the owner, the Safe and the start
  - Anyone may send it: a relayer, the member, or the Safe itself in a MultiSend next to `swapOwner` (tested in the upgrade below).
- **Address:** CREATE2 through the deterministic deployment proxy, with KEY as the salt; the init code holds the code, the parameter set, the verifier's address and KEY. The owner's address is the same on every chain, and so is a Safe that Safe's factory creates with those owners (tested under two chain ids).
- **No outbound calls** other than to the verifier: an owner contract can't call `approveHash` or anything else.

**Tests.** 8 unit tests, and 15 integration tests run on each release. The full suite passes: 330 tests; the 12 skipped are in WotsVerifier's checksum suites.
- a 2-of-3 Safe of three owners: enrolment, an ETH and an ERC-20 transfer; one signature short; the same owner twice
- the Safe's nonce during execution (probe), and the same answer before and during execution
- a replacement at the same nonce with slot 1 (a cancellation, as Safe's app builds it), after which the original is refused
- a key used for another nonce is refused, including SafeTx fields that lie to match the key
- a signature or a certificate for another Safe or another chain is refused
- messages through the fallback handler; refused for another Safe, message or chain, and across kinds; a phished SafeTx hash is refused
- **upgrade in place:** a 2-of-3 ECDSA Safe swaps one owner per transaction, each swap in a MultiSend with the new owner's `enroll`. The swaps are signed by two ECDSA owners, then by a WinterlockOwner and an ECDSA owner, then by two WinterlockOwners. The Safe keeps its address, and at the end the ECDSA keys are refused (GS026).
- the same owner and Safe addresses under another chain id
- enrolment rules: bindings, start order, field bounds; malformed signatures; the deterministic address
- **Mutation checks:** a test fails without each of the SafeTx hash check, the SafeMessage check, the start rule, the root alignment, and the chain or the Safe in the certificate digest.

**Gas and sizes** (D6, operation trees of height 10: 512 nonces × 2 slots). Transaction gas as Forge measures it (below), Prague pricing, steady state: nonce ≥ 1, recipient balances nonzero.

| `execTransaction` | v1.4.1 | v1.5.0 |
|---|---|---|
| ETH transfer, 2-of-3 ECDSA owners | 65,794 | 65,302 |
| ETH transfer, 2-of-3 WinterlockOwners | 247,250 (3.76×) | 244,861 (3.75×) |
| ERC-20 transfer, 2-of-3 ECDSA owners | 72,586 | 72,067 |
| ERC-20 transfer, 2-of-3 WinterlockOwners | 253,933 (3.50×) | 251,604 (3.49×) |

- **About 90k gas per WinterlockOwner signature.** Calldata is about 24k of it: the ERC-20 transaction carries 4,196 bytes against 644, which costs 53.7k gas against 4.8k at 4 and 16 gas per byte. Execution is the other ~65k: about 55k for the WOTS verification, and about 10k for calling the owner (a cold account and slot, 1.8 KB copied into the call) and recomputing the SafeTx hash.
- **Compared with Kernel 2-of-3** (+160k over Kernel with ECDSA, 2.12×): the absolute premium is similar, +180k. The ratio is higher because an ECDSA Safe transaction is cheap, with no 4337 overhead.
- **Sizes:**

  | Per owner | Data | As a confirmation (65 + 32 + data) | Transaction Service cap |
  |---|---|---|---|
  | Transaction, height 10 | 1,757 B | 1,854 B | fits (5,000 B) |
  | Transaction, height 20 | 1,997 B | 2,094 B | fits |
  | Message (stateless) | 5,737 B | 5,834 B | **too large** |

- **Messages on-chain:** the 2-of-3 signature an app receives is 11,668 bytes. Checking it costs 190.9k gas for the call on v1.5.0 and 233.5k on v1.4.1, whose handler goes through the Safe twice; the app's calldata comes on top.
- **One-time costs per member and chain:** deploying the owner takes 1.60M gas (7,114 bytes of runtime code); `enroll` takes 251k gas (5,892 bytes of calldata, one new slot), and the same again for each rotation.
- **How the gas was measured.** This Forge (1.8.3) runs with `isolate = true` by default: every call a test makes at the top level is its own transaction, with intrinsic gas, the EIP-7623 floor, fresh access lists and committed storage. `vm.lastCallGas()` reports that transaction's gas. For a plain storage write it matched an anvil receipt exactly (26,413). Refunds are not subtracted; none of the transactions above earns one. The figures move by a few dozen gas whenever the owner's code changes, since its address, and with it the signatures' bytes, change too.

**Problems and risks.**
- **Messages don't fit the Transaction Service:** 5,834 bytes against its 5,000-byte cap, on both its message endpoints. Options:
  - leanSphincs-s for the stateless key: its 4,164-byte signature makes a 4,314-byte entry. D12 chose leanSphincs for its Light-tier signature budget.
  - approving messages on-chain, with SignMessageLib in a WOTS-signed transaction; the handler then accepts an empty signature
  - collecting message signatures outside the service
  - Even then, apps receive 11.7 KB for 2-of-3 and pay 190–230k gas per check. Some off-chain consumers may cap signature sizes.
- **Enrolment comes first.** Each member needs an `enroll` transaction per Safe and chain (251k gas, 5.9 KB) before the Transaction Service accepts that member's confirmations, because it checks them against chain state. A rotation invalidates confirmations already collected under the old tree.
- **Deployment is costly:** 1.6M gas per member per chain for a full contract. Under Glamsterdam's state pricing, which made the validator's deployment cost seven times more on Sepolia than on Arbitrum Sepolia, that could reach about 11M on L1. An ERC-1167 clone carrying KEY as an immutable argument would cost under 0.1M gas (estimate) and up to about 3k more per transaction (a delegatecall to the shared implementation, warm after the first owner). Not built.
- **Who executes:** a WinterlockOwner has no EOA. Once a transaction has its signatures, anyone with gas can execute it: a relayer, or any member's wallet. **Checked live on 2026-11-06:** Safe's app shows the Winterlock owners' confirmations. An ordinary MetaMask account that isn't an owner executed a transaction there that the two proxy owners had confirmed through the signer (2-of-2 test Safe on Sepolia, nonce 6, 293,777 gas, the same as executing from the signer). So a team can sign with the signer and execute from Safe's familiar UI with any funded wallet.
- **No delegates:** the Transaction Service registers a proposer (delegate) with an owner's EIP-1271 signature over an EIP-712 `Delegate` hash, which WinterlockOwner refuses by design. A proposal must therefore carry a WinterlockOwner's own signature, with that owner as sender.
- **Typed data of modules gets no answer:** WinterlockOwner signs only SafeTx and SafeMessage. A module that asks the Safe to check its own typed data, such as Safe's 4337 module with its SafeOp, needs its type added, with its own nonce binding.
- **The lock-down is more than the owners:** the constraint "no ECDSA path left over" applies to modules, the guard and the fallback handler too. The upgrade test checks the owners only.
- **Safes before v1.3.0** use an EIP-712 domain without a chain id. Not supported.
- **Forge's incremental build is stale for the owner:** after an edit to `WinterlockOwner.sol`, Forge recompiled that file alone ("Compiling 1 files"), and the tests, which embed its creation code through `SafeOwnerDeployment`, kept the old bytecode. A mutant then passed every test, while the same mutant, recompiled together with the tests, failed its test. A first mutation run was fooled this way. After changing the owner, run `forge build --force`.

**2026-11-05: Safe owner, live on Sepolia** (`bench/safe/live.py`, `bench/safe/SafeSignerHelper.sol`; results in the git-ignored `bench/safe/results-sepolia.json`)

The question: does the spike's design work with a real Safe and Safe's hosted Transaction Service (version 6.14.0)? For transactions, yes, unchanged: the service accepts proposals and confirmations from WinterlockOwners, shows them as contract signatures, and indexes their execution. Messages and delegates are refused, as the spike predicted.

**Setup.**
- **Safe v1.4.1 with the SafeL2 singleton** (`0x29fcB43b46531BcA003ddC8FCB67FFE91900C762`), created through the canonical factory (`0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67`), threshold 2, CompatibilityFallbackHandler `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99`. Why SafeL2:
  - Where the app's multi-chain creation feature is on, it creates a v1.4.1 Safe with the L1 singleton plus `SafeToL2Setup.setupToL2`, which switches the Safe to SafeL2 on every chain but mainnet (`createNewUndeployedSafeWithoutSalt` in the wallet's create logic). Elsewhere it takes SafeL2 when the chain is marked L2. Sepolia's flags come from Safe's config service and weren't checked.
  - Starting from SafeL2 gives the same singleton without the setup call, and SafeL2's events let the service index it whether it traces calls or reads events. It reports the Safe as `1.4.1+L2`.
- **Members:** parameter set D6; operation trees of height 10 whose first 16 keys are real, built like the integration tests' trees; leanSphincs stateless keys.
  - The keys derive from a new secret seed in `bench/bundlers/.env`.
  - Signing runs in Solidity on a local anvil that the driver starts and stops.
  - The driver records each (member, nonce, slot) it signs with and refuses to sign a second SafeTx with the same key (D4).
- **Rehearsal first:** the whole run went through on a local anvil fork of Sepolia without service calls. Its gas figures, under pre-Glamsterdam rules, are the second column below.
- **Addresses** (all deterministic):
  - Safe `0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2`
  - owners `0x7141F0c30ABcF3Dc35d9409FFc3383009235c47d` (member 1), `0x2D3C9197237D1F1e1165b1EEE748BC9e1c3f1123` (member 2), `0xfaF53A0b16E45252a2F142B1C10Eecab4fE1Fa14` (member 3, not enrolled)
  - stateless verifier `0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254`, now deployed on Sepolia at its predicted address

**On-chain steps** (gas used from receipts; all sent by the throwaway deployer, which is not an owner):

| Step | Sepolia (Glamsterdam) | Pre-Glamsterdam (fork rehearsal) |
|---|---|---|
| Deploy the stateless verifier | 6,513,514 | 928,746 (7.0×) |
| Deploy an owner (each of the three) | 11,225,240 | 1,604,182 (7.0×) |
| Create the Safe | 1,483,393 | 305,847 (4.9×) |
| Fund it with 0.001 ETH | 27,729 | 27,329 |
| Enrol a member (members 1 and 2) | 392,088 | 251,460 |
| `execTransaction`, 1 wei to the deployer, nonce 0 | 392,632 | 306,900 |
| `execTransaction`, the replacement at nonce 1 | 287,593 | 284,909 |

- **Transactions:**
  - verifier `0x9847c894d13a911a51134c182377f152a2adadc7549e3b82546dddaa46190215`
  - owners `0x842a4128d239a85fbf083fb9f9b0ea39322611c034e785a553071d73e0531e66`, `0xf08482c82dd5bd14fbfb164be2f8c5369586ffd4c177c2499fcc9f5c3ad67267`, `0xd5b36e4b6286df9688f858483cf1a0aab1218da9c7822078b72cf4fc5661c1eb`
  - Safe `0x61139a01295c242e2df0f2e81f62153e4c47237a413e6f8b8e0588fd8b263c66`, funding `0xf6b4063e462c0df37d68e91823a14527e52c7dc768aa68b1fd174325dc7a7ca0`
  - enrolments `0xff85dd254175fef440c5f68cbe543cf818a70144e22af633eca2cfd7cd418a4b`, `0xd149a39aba40ee7f6e7417c296df4b543b6068d171442539d530326bbd01333e`
  - executions `0x7b70e656f865340c101f26cec8fd7558eb9ec68a02c7d044c891c4cfff1bbc4d` (nonce 0), `0x33b36753f78881530dfe8d08056ead5f8e2a396d5060b8baeec89d2f5fd63c2f` (nonce 1)
- **Glamsterdam's surcharge falls on new state:**
  - deployments cost seven times more, as predicted (about 11M per owner)
  - the Safe's creation costs five times more; that applies to any Safe
  - enrolment costs 141k more, and the first execution 86k more; each writes a new storage slot (the owner's tree, the Safe's nonce)
  - the later execution costs only 2.7k more
- **SafeL2 logs the signatures.** Its `SafeMultiSigTransaction` event carries all of `execTransaction`'s parameters: 4,256 bytes here, 3,708 of them the two owners' signatures. That's about 35k gas per execution, about 15k per WinterlockOwner signature, which the spike's 247k (L1 singleton, Forge) doesn't include. A 2-of-3 execution on this SafeL2 at a nonce above 0 cost 288k gas (a call without value), and 285k under the old rules.
- **Spent:** 0.00142 ETH, including the 0.001 ETH in the Safe. Of the 0.00042 ETH of fees, 0.00029 is the last execution: `cast` picked a 1 gwei priority fee there, against 24 wei to 5 Mwei per gas for the rest.

**Transaction Service calls**, in order (one call per step, except where noted):

| Step | Call | Status | What the service returned |
|---|---|---|---|
| a | `GET /v1/safes/{safe}/` | 200 | already indexed at the first poll, 42 s after the creation block: three owners, threshold 2, nonce 0, master copy SafeL2, `1.4.1+L2` |
| b | `POST /v2/safes/{safe}/multisig-transactions/` | 201 | proposal from member 1's owner as `sender`, with its 1,854-byte contract signature (slot 0) |
| c | `POST /v1/multisig-transactions/{safeTxHash}/confirmations/` | 201 | member 2's 1,854-byte contract signature, echoed back |
| d | `GET /v2/multisig-transactions/{safeTxHash}/` | 200 | two confirmations, both `CONTRACT_SIGNATURE`, `confirmationsRequired` 2, proposer member 1's owner, `trusted` true |
| e | `GET` the same, about 75 s after execution | 200 | `isExecuted` and `isSuccessful` true; executor is the deployer; transaction hash, block, `gasUsed` 392,632 and fee filled in; the 3,708-byte signatures blob |
| f | 2 proposals, 2 confirmations, 2 × `GET …/multisig-transactions/?nonce=1` | 201 × 4, 200 × 2 | both versions at nonce 1, each with two confirmations; after the replacement executed, it is `isExecuted` true and the original stays `isExecuted` false |
| g | `POST /v1/safes/{safe}/messages/` | 400 | `{"signature": ["Ensure this field has no more than 5000 hexadecimal chars (not counting 0x)."]}` |
| h | `POST /v2/delegates/` | 400 | `{"nonFieldErrors": ["No valid signature found for signer=0x7141F0c30ABcF3Dc35d9409FFc3383009235c47d"]}` |

- **Transactions work unchanged.** The service checked each signature with an eth_call to the owner contract and stored it. The execution was built from the signatures as the service returned them; they matched the driver's own byte for byte.
- **The replacement (D4) works.** The original sends 2 wei to the deployer, signed with slot 0. The replacement is an on-chain rejection as Safe's app builds one (a call to the Safe itself, no value, no data), signed with slot 1 by the same two members. The service accepts two proposals at one nonce and lists both. It knows nothing of slots, so it can't warn about a slot used twice; D8 puts that warning in Winterlock's own service.
- **Messages:** refused by the field check, before any signature check. The 5,834-byte entry is over the cap.
  - The error text says hexadecimal characters, but the field counts bytes (safe-eth-py `HexadecimalField` measures the decoded bytes, as its `min_length` of 65 shows), so the cap is 5,000 bytes as the spike assumed.
  - On-chain the same message works: an eth_call of the Safe's `isValidSignature(EIP-191 hash, 2-of-3 signature)` returns `0x1626ba7e` for the 11,668-byte signature, through the fallback handler.
- **Delegates are refused by the owner.** Member 1's owner can't approve the service's `Delegate` hash. The service checks a contract signature with an eth_call of the owner's `isValidSignature`; the same eth_call from the driver returned `0xffffffff`.
  - The request carried a contract signature whose data names the hash without a stateless signature: no data the owner accepts exists, and a full stateless signature would exceed the cap.
  - Proposals therefore have to come from a member's own owner contract, as in b and f.
- **Member 3 isn't enrolled.** By design its owner refuses every transaction signature, so the service would too, until it enrols.
- **Safe's app (app.safe.global), checked by hand after the run:** the Safe opens read-only with no changes on Safe's side.
  - **History:** nonce 0 shows as sent, and nonce 1 as rejected, because the app recognises the slot-1 replacement as its own on-chain rejection. The unexecuted original at nonce 1 isn't shown, and the queue is empty.
  - **Each entry:** two confirmations, from member 1's and member 2's owner contracts. The proposer is member 1's owner; the executor is the deployer, a plain account that isn't an owner.
  - **Owners:** shown as plain addresses, like any owner without a name. Adding the Safe offers to put each signer in the address book, so a team can name its Winterlock owners there.
- **So for transactions, the Safe route needs no change to Safe's contracts, its Transaction Service or its app.** Winterlock's own pieces are the owner contracts and a signer that posts proposals and confirmations through the service API. Not checked yet: whether the app lets a connected account that isn't an owner press "Execute". A Winterlock relayer or signer can always execute directly, as here.

**2026-11-05: proxy owners for the Safe route** (`src/safe/WinterlockOwner.sol`, `src/safe/WinterlockOwnerFactory.sol`, `script/DeploySafeOwner.s.sol`)

- **The design:** a member's owner is a 77-byte proxy, Solady's ERC-1167 clone with immutable arguments, that carries the member's stateless key.
  - It delegates to one WinterlockOwner implementation per chain and parameter set, made by a factory with CREATE2 and the key as the salt.
  - The proxy reads the key from its own code, never from calldata.
  - Digests, tree seeds and trees stay bound to the proxy's address and storage.
  - The implementation, factory and stateless verifier come from the deterministic deployment proxy with fixed salts, so an owner's address depends only on their code and the key: the same on every chain (tested, and a mutant that puts the chain id into the salt is caught).
- **The bare implementation is harmless:** its key reads as zero, so no certificate or message verifies there, no tree can be stored, and every transaction signature is refused. Proxies with a zero key or none are refused the same way.
- **Factory:** `deployAndEnroll` creates an owner and enrols its first tree in one transaction; the certificate is signed for the predicted address.
- **Gas, old pricing:** a member's owner costs 74k to deploy (was 1.6M), or 255k together with its first tree. Each owner check costs about 3k more the first time in a transaction (a cold account), 0.5k after. A 2-of-3 `execTransaction` costs about 3.5k more.
- **Gas under Glamsterdam pricing:** estimated with EIP-8037's state charges, calibrated against the Sepolia receipts to within 6k and cross-checked with read-only `eth_estimateGas` on Sepolia.
  - A member's owner: about 0.34M (was 11.2M).
  - Owner plus first tree: about 0.61M.
  - Once per chain for all teams: about 11.6M for the implementation and 2.7M for the factory.
- **Deploying on Glamsterdam chains:** use `--broadcast --skip-simulation --slow`. Otherwise Forge sets gas limits from its own old-price simulation, and the transactions run out of gas.
- **Tests:** 7 mutants caught. One survives by design: removing the zero-key check in signature verification, which the verifier already refuses.
- **A test bug fixed:** in `test_constructorChecks`, Forge 1.8.3 turns `new` in test files into its `deployCode` cheatcode, and an expected revert from that cheatcode ended the test as passed. So only its first check had ever run. It now deploys with plain CREATE, and a mutation run confirms every check executes.
- **Out of date:** `bench/safe/live.py` still builds owners with the old full-contract constructor; the signer (below) replaces it.

**2026-11-05: Safe messages within the Transaction Service's cap** (`docs/notes/safe-messages.md`, `test/integration/SafeMessages.t.sol`, `test/StatelessVerifierS.t.sol`)

Three options, measured. The full comparison is in the note.
- **A. leanSphincs-s as the stateless key:**
  - Fits the cap: 4,314 bytes per owner. Verifies for 38.9k gas (42.6k without via-IR), against 52.8k.
  - Its signature budget is estimated, not proved: 20k / 2.1M / 67M per signer tier, against leanSphincs' proved 210k / 22M / 1.15B. Hardware signing takes twice as long.
  - Switching needs new seeds, owners, verifier and Kernel validator for every member.
  - A later 24-byte version would no longer fit the cap.
- **B. On-chain approval through Safe's SignMessageLib:**
  - The members' WOTS keys approve the message in a Safe transaction: 265–267k gas, against 85–86k with ECDSA owners. An app's check then costs 19–22k, with an empty signature.
  - Works with Permit2 and the `siwe` library. Doesn't work with viem: its ERC-6492 validator reverts on signatures under 32 bytes, and an ERC-6492 wrap then fails Permit2.
  - Safe's Transaction Service ignores these approvals, and nothing in Safe can revoke one; a custom delegatecall library can (tested).
  - One member alone can't approve, and a phished stateless signature of the approval's hash is refused.
- **C. Stateless signatures collected outside Safe's service:** the 2-of-3 signature (11.7 KB) already verifies on-chain through the Safe. Winterlock's collection service (D8) would store and serve it.
- **Every option:** EIP-2612 permits with OpenZeppelin's `ERC20Permit` accept only ECDSA, so no smart account works with them.
- **Safe's app:** its "always use on-chain signatures" setting answers apps too early or not at all (read from its source). So both B and C need a Winterlock signer that answers apps itself, over WalletConnect.
- **Decided as D14:** keep leanSphincs (D12 stands). Use B for messages that apps check on-chain, such as permits, and C for messages checked off-chain, such as sign-in.
- **Proposed, not built:**
  - a WinterlockOwner signature kind that defers to the Safe's own approval, so a wallet can return a short signature viem accepts
  - building SignMessageLib with the release settings in `setup.sh`

**2026-11-05: minimal signer** (`signer/`)

A Python command-line signer for the Safe route.
- **Crypto:** WOTS (D6) and leanSphincs implemented natively (C-backed keccak).
- **Checked against the Solidity signers byte for byte:** leaves, signatures, trees, keys and the owner formats. All upstream leanSphincs known answers match.
- **Checked against the real contracts on a local chain:** both owner entry points, the verifier, `enroll`, and a Safe v1.4.1 SafeL2 execution.
- **Safety rails:**
  - One seed file. Operation trees mix in randomness kept only in the key log, so a signer that lost its log can't rebuild an old tree, and a restore always certifies a fresh one.
  - An append-only, checksummed key log, written and fsynced before a signature leaves the signer.
  - One hash per key. Slot 0 first, slot 1 for a replacement, a third version refused.
  - It builds the SafeTx itself and compares the hash with the Safe's.
  - It checks the owner, the nonce and the enrolled tree before signing, and verifies each signature with the owner contract before posting.
  - It refuses to sign if the service shows a signature from its current tree that its log doesn't know.
- **Commands:** init (and restore), address, enroll (deploy, rotate), propose (and cancel), confirm, queue, execute, status, plus an offline file mode for peer-to-peer use.
- **Tests:** 43, including an end-to-end run of a 2-of-3 Safe against a mock Transaction Service.
- **Speed, on 12 cores:**
  - a WOTS signature in 4 ms
  - a leanSphincs signature in 0.24 s and its key in 0.13 s
  - a height-10 tree in 0.3 s, height 12 in 1.2 s
- **Live on Sepolia:** a 2-of-2 Safe `0x60361563278E85da267C1198f8fBdc2cf43e38ED` with new seeds. The owners were full contracts, from before the proxy change.
  - Proposal and confirmation through the hosted service: 201 and 201.
  - Execution: `0x88de9dfee61300fa0ffe4b441cc52ee130a02992f6e7652b1ed032708e9f5313`, 384,803 gas.
  - The service shows both confirmations as contract signatures.
- **Gaps before real use:** a hardware signer, a hard stop at the stateless key's budget, and an audit. Since built: a recovery phrase, an encrypted seed, moves between devices, and WalletConnect with message signing (below).

**2026-11-05: proxy owners, live on Sepolia** (`signer/`, `signer/tools/live_check.py`)

The question: do proxy owners work end to end with a real Safe and Safe's hosted Transaction Service, driven by the signer alone? Yes, as the full-contract owners did, for 0.60M gas per member instead of 11.6M.

- **Setup:** two new signers with new seeds; a new 2-of-2 Safe v1.4.1 on the SafeL2 singleton through Safe's canonical factory, owned by the members' predicted proxy owners and funded with 0.00001 ETH. Rehearsed first on a local anvil fork of Sepolia with a mock service.
- **Order:** the Safe first, since its owners need not exist yet. Then member 1's `enroll --deploy`: the implementation, the factory, and member 1's owner with its first tree in one `deployAndEnroll`. Then member 2's plain `enroll`, which made its owner the same way.
- **Addresses**, all as the signer predicted offline:
  - implementation `0xC4Aa38F766020e66136cd6cb1c547CeCAd175f2e`, factory `0x13D4cB5F9A9D076dB123CE8Eb5f404e2FA01fEa5`; the verifier `0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254` was already there
  - owners `0x9Ba62FC5AfeF50566446c6b91C32A9C9451aEA24` (member 1) and `0xe331785F6E7690FC9f9e6C109b7a89D6aca9d3aE` (member 2): 77 bytes of code each, the proxy and the key
  - Safe `0x68f64486FC720D1dB14507bC7Fa64896bE6Bef07`

| Step (Sepolia, Glamsterdam) | Gas used | Node's estimate | Expected (proxy owners, above) |
|---|---|---|---|
| Implementation, once per chain | 11,412,369 | 11,595,854 | about 11.6M |
| Factory, once per chain | 2,618,037 | 2,661,929 | about 2.7M |
| `deployAndEnroll`, member 1 | 604,507 | 610,472 | about 0.61M |
| `deployAndEnroll`, member 2 | 604,477 | 610,442 | about 0.61M |
| Create the Safe | 1,371,909 | 1,396,021 | |
| `execTransaction`, 1e11 wei to the deployer, nonce 0 | 388,733 | 397,239 | |

- **Gas limits:** the node's estimate times 1.2. The largest, the implementation's, was 13.9M, under the 16.7M cap.
- **Against the full-contract owners** (the minimal signer's live run, same chain):
  - a member's owner and first tree: 0.60M instead of 11.6M (11.2M to deploy, 0.39M to enrol)
  - the execution: 3.9k more (388,733 against 384,803), the two owners' DELEGATECALLs; 3.5k more in the old-pricing rehearsal (302,577 against 299,035)
- **Transaction Service:**

  | Call | Status | What it returned |
  |---|---|---|
  | `GET /v1/safes/{safe}/` | 200 | indexed at the first poll: both owners, threshold 2, `1.4.1+L2` |
  | `POST /v2/safes/{safe}/multisig-transactions/` | 201 | member 1's proposal, slot 0 |
  | `POST /v1/multisig-transactions/{safeTxHash}/confirmations/` | 201 | member 2's confirmation, slot 0 |
  | `GET /v2/multisig-transactions/{safeTxHash}/`, 90 s after execution | 200 | `isExecuted` and `isSuccessful` true, both confirmations `CONTRACT_SIGNATURE` (1,758 bytes each), the deployer as executor |

- **Transactions:**
  - implementation `0x8ff033b3bff27042cc16298607c3eb70f479de83313614daeb5f86399883c50c`, factory `0x788e7a89129ef12fb9f07167afc7ce745141e20bfc72b8a5353f33be6c987bdd`
  - Safe `0x72551f94187d12c6e15b5ab8588e2579f00c65fd42f21ca1d51162e9f1938bc9`, funding `0x3a7e8c64530d9688db236dd35da3c112142402a9b23af84dc860360b13a6b2bb`
  - `deployAndEnroll` `0xd2b7d2fd1b7b28084f9a169b8eb03fdaebe1b34f5af0f460bcf8da0f0fa8a26e` (member 1), `0x685bd141792dbb426c9389b0153f2279915d03f145ac8e8244465b7d6c38117d` (member 2)
  - execution `0x0f0040b8ba88605ad5591847244b8e19c95e21c33623871dc272875c2ed6ff46` (SafeTx `0xc9d8851cfb3fbb0fb97d8ed551bbc74e9e1bee06faff88f4cf0a7aa1bb8c1be2`)
- **Spent:** 0.0000099 ETH, nearly all of it left in the Safe; fees were 3.9e-10 ETH at 23 wei per gas.
- **Nothing differed from the local run** apart from the gas pricing.

**2026-11-05: signer recovery and device moves** (`signer/`, `docs/notes/signer-recovery.md`)

- **Recovery phrase:** 24 BIP-39 words that encode the signer's 32-byte seed directly. Existing seeds get a phrase without their owner address changing, and there is no second secret.
  - `init` shows the phrase once and asks for three random words before saving anything. `backup --check` repeats that later, and `status` reminds after 90 days.
- **Seed at rest:** encrypted with scrypt and ChaCha20-Poly1305. Only commands that sign, certify or export ask for the passphrase.
- **Moving to a new device** (the old one still works): the new device shows a one-time move code, the old device exports an encrypted bundle (the key log, no secret keys), then locks itself and deletes its seed. The new device checks the bundle against the chain and Safe's service, and keeps the same trees, with no fee.
  - Tested failure modes: the same bundle on two devices, exporting twice, a changed or truncated bundle, an interrupted move, a stale bundle.
- **Lost device:** restoring from the phrase certifies fresh trees, one `enroll` per Safe and network. The signer lists which pending approvals stop counting.
- **Copied or rolled-back key logs** are detected offline (device identity, the log's file identity, a record counter) and sign nothing until their trees are retired or the copy is adopted.
- **Not protected:**
  - a whole-machine rollback (a VM snapshot from before a move)
  - anyone holding the phrase
  - malware on an unlocked device
  - deliberate tampering with the tracking files
- **Tests:** 38 new signer tests.

**2026-11-05: WalletConnect bridge** (`signer/`, `docs/notes/walletconnect.md`)

The signer answers dapps over WalletConnect v2 as the team's Safe. It implements the needed part of the protocol itself: no suitable Python library exists (GPL or unmaintained), and Reown has no Python SDK. The crypto and relay login match WalletConnect's own test values, and dapps built on the official JS SDK work with it through a stand-in relay.

| Request | What happens | What the dapp gets |
|---|---|---|
| Transactions, batches | Decoded, signed by this member, proposed through Safe's service | The SafeTx hash, as Safe's own app answers |
| Sign-in and other messages checked off-chain | Stateless signatures from k members, collected peer to peer or by a small endpoint, checked through the Safe | The combined signature (11.7 KB for 2 of 3) |
| Permits and other messages checked on-chain | Approved in a Safe transaction through SignMessageLib | `0x` after execution |
| Bare hashes, `eth_sign`, another site's sign-in, the Safe's own typed data, Kernel's Enable data, risky self-calls | Refused with the reason | An error |

- **Locked devices refuse dapps too:** message signing goes through the same check as transactions, so a moved or locked device signs nothing.
- **Open:**
  - viem refuses `0x`, so on-chain approvals need the owner signature kind in D14's to-do list
  - one dapp session at a time
  - the dapp's name and URL aren't verified, so the sign-in check compares only what the dapp claims
- **Tests:** 42 new signer tests; together with the recovery work, 126 pass.

**2026-11-06: WalletConnect, live on Sepolia** (`signer/tools/live_walletconnect.py`, `live_dapp.js`)

A scripted dapp on the official SDK (`@walletconnect/sign-client` 2.26.0) paired through Reown's relay with member 1's `connect`, for the 2-of-2 test Safe of proxy owners (`0x68f6…ef07`). The script played member 2 and the gas account, and the dapp checked every answer against Sepolia with viem 2.57.16. Two runs; numbers from the second.

| Step | What the dapp got | Checked by the dapp |
|---|---|---|
| Pairing | a session in 1.0 s, with the Safe as its account | — |
| Sign-in (`personal_sign`) | the Safe's combined signature, 11,668 bytes, 7.2 s after asking (both members sign in about 1 s each) | viem's `verifyMessage`: valid; for a changed message: invalid. The Safe's `isValidSignature`: the magic value |
| Transfer (`eth_sendTransaction`) | the SafeTx hash at once; after member 2 confirmed and the gas account executed (290,889 gas), the receipt of the SafeTx hash from the wallet | the receipt matches the chain's |
| Permit2 (`eth_signTypedData_v4`) | `0x` once the SignMessageLib approval executed (400,441 gas), 26 s after asking | `isValidSignature(hash, 0x)`: the magic value. viem's `verifyTypedData`: invalid, as expected |

- **Reown's relay accepts the wallet's approval through `irn_publish`,** although SDK 2.26.0 dapps propose through `wc_proposeSession`. This was the open question in the bridge's notes.
- **The relay carries the 11.7 KB answer** without trouble.
- **The SDK refuses a dapp's own `eth_chainId` request** because it isn't a session method. Dapps read the chain and account from the session, so the wallet needs no change.
- **Cost:** about 11.8M wei in fees for the two executions, at Sepolia's base fee of about 30 wei.

**2026-11-06: a real dapp, and Safe's app**

A member ran the signer on their own computer, from a small kit: the signer and both members of the 2-of-2 test Safe (`0x68f6…ef07`), taken over with `device adopt`. The dapp was Reown's AppKit lab (lab.reown.com, the wagmi demo), reached over WalletConnect, on a public Sepolia RPC endpoint.

| Request | Path | Result |
|---|---|---|
| Send transaction | Proposed to Safe's service (nonce 5); member 2 confirmed and executed it with the signer | Executed, 293,681 gas |
| Send transaction, executed in Safe's app | Proposed and confirmed by the two members (nonce 6); executed in Safe's app by a MetaMask account that isn't an owner | Executed, 293,777 gas |
| Sign message (`personal_sign`) | Off-chain: both members' stateless signatures, combined into the Safe's | The lab got the Safe's signature |
| Sign typed data (the lab's example names a verifying contract) | On-chain: a SignMessageLib approval (nonce 7) | Executed, 400,565 gas; the lab got `0x` |

- **Safe's app works as the team's dashboard:** it shows the Winterlock owners' confirmations, and anyone can execute from it once they're in.
- **Found and fixed:** `--wait-for-execution` failed on the public endpoint. It balances across nodes, and one a block behind refused the log query's range. The bridge now looks back 64 blocks and treats a refused query as "not executed yet".
- **The lab doesn't verify signatures:** it only shows that the wallet answered, so `0x` passes there. Dapps that verify with viem would refuse it (D14's to-do).
- **Usability snags:**
  - finding the WalletConnect link in AppKit's dialog (Connect Wallet → WalletConnect → copy link)
  - `confirm` wanting `--safe-tx-hash` instead of taking the hash as a plain argument

**2026-11-06: Owner v2, contracts** (`src/safe/WinterlockOwner.sol`, `src/safe/WinterlockOwnerFactory.sol`, `src/SharedWotsVerifier.sol`, `script/DeploySafeOwner.s.sol`, `test/WinterlockOwner.t.sol`, `test/integration/SafeWinterlockOwner.t.sol`, `test/integration/SafeMessages.t.sol`)

Phase 1 of [notes/owner-v2.md](notes/owner-v2.md): the contracts, their tests and the deployment script. **Built, not deployed** (deployed on Sepolia later the same day: "Owner v2, live on Sepolia"). `WinterlockOwner.sol` is now v2; v1 stays in git history, and its Sepolia deployment keeps working. The signer still builds v1 owners from its pinned bytecode until its own phase.

**What's built**, as the note proposes:
- **Devices:** device 0 is the member key in the proxy's code. Devices 1–3 hold leanSphincs-keccak device keys, checked by the same stateless verifier. Per device, two words: the key, and the generation with an active flag.
  - `certifyDevice(device, generation, key, signature)`: the member key signs; the generation must be the stored one plus one; devices 1–3 only; both halves of the key set. It replaces an active device's key.
  - `revokeDevice(device, generation, signature)`: the member key signs; the device must be active at that generation; it turns inactive and keeps its generation.
  - Anyone may send either. Events `DeviceCertified` and `DeviceRevoked`.
- **Trees per Safe and device:** `enroll(safe, device, root, height, start, signature)`, signed by the device's key (the member key for device 0) while the device is active. One word: root ‖ generation (16 bits) ‖ start (40) ‖ height (8). Within a generation, start nonces only grow per Safe and device; a tree of an earlier generation sets no bound. A tree verifies only while its device is active at the tree's generation.
- **Signatures** (one byte more than v1 for transactions and messages):

  | Kind | Layout | Size per owner |
  |---|---|---|
  | Transaction, slot 0 or 1 | `[slot][device][safe: 20][SafeTx: 320][WOTS: 1,176][path: 24 × height]` | 1,758 B at height 10; 1,855 B as a confirmation |
  | Message | `[0x02][device][safe: 20][keccak(message): 32][stateless: 5,684]` | 5,738 B; 5,835 B as a confirmation (over the service's cap, as in v1) |
  | Approved | `[0x03][safe: 20][keccak(message): 32]` | 53 B; 150 B in Safe's encoding |

  - The approved kind is valid when the hash is that Safe's SafeMessage hash and a staticcall to `signedMessages(hash)` answers nonzero. An account without code, a revert, and an answer shorter than a word count as not approved. The hash is checked first, so a Safe is only asked about its own SafeMessages.
- **Digests,** with `v2` domains, all naming the chain and the owner: device certificate (device, generation, key), revocation (device, generation), tree certificate (Safe, device, generation, root, height, start), message (Safe, device, generation, SafeMessage hash), tree seed (Safe, device, generation, start). Public views: `deviceDigest`, `revocationDigest`, `certificateDigest`, `messageDigest`, `treeSeed`, `devices(device)` and `tree(safe, device)`.
- **Factory:** the same model; `deployAndEnroll` enrols device 0. The salts name v2 (`Winterlock.safe-owner.implementation.v2`, `….factory.v2`).

**One change from the note: WOTS verification moved into a shared contract,** as the note's fallback foresaw.
- **v2 with WOTS inline came to 10,301 bytes,** against the budget of about 8,500. Removing one feature at a time showed where the 3 KB went: certify and revoke 1.05 KB, the device and digest views 0.68 KB, the approved kind 0.54 KB (its call written in Solidity), the public constants 0.40 KB. Even without the optional parts it stayed near 9.5 KB.
- **`SharedWotsVerifier`** (2,484 bytes) is WotsVerifier behind one external function, for every parameter set. It has no state and no constructor arguments, and goes through the deterministic deployment proxy (salt `Winterlock.wots-verifier.v1`), like the stateless verifier. The implementation takes its address as a third constructor argument.
- **The approved kind's call** is written in assembly like the verifier calls, which took the implementation from 8,472 to 8,144 bytes.

**Sizes and deployment.** Forge, Prague pricing.

| Contract | Runtime bytes | Deploy gas (Prague) | Glamsterdam (Sepolia) |
|---|---|---|---|
| Implementation v1 | 7,236 | 1,629,027 | 11,412,369 (measured) |
| **Implementation v2** | **8,144** | 1,829,675 | about 13.0M (estimate) |
| **SharedWotsVerifier** (new) | 2,484 | 589,027 | about 4.1M (estimate) |
| Factory v2 (v1: 1,551) | 1,563 | 399,428 | about 2.7M |
| A member's owner (proxy) | 77 | 74,228 | about 0.33M |

- **The estimate:** EIP-8037's state gas, (120 + runtime bytes) × 1,530, plus the 0.36M that v1's node estimate had on top of its state gas. For the implementation that is 12.64M + 0.36M.
- **Within the cap at 120%:** 13.0M × 1.2 is about 15.6M, under 16,777,216. At Forge's default of 130% it would be about 16.9M, over the cap. So the script's instructions now pass `--gas-estimate-multiplier 120`.
- **Once per chain on Sepolia,** about 4.1M for the WOTS verifier, 13.0M for the implementation and 2.7M for the factory; the stateless verifier is already there.

**Gas.** Forge, Prague pricing, as in the spike: each call its own transaction, steady state, D6 trees of height 10. v1 was re-measured today with the same Forge.

| `execTransaction`, 2-of-3 | v1.4.1 | v1.5.0 |
|---|---|---|
| ETH transfer, v1 owners | 250,864 | 248,365 |
| ETH transfer, v2, signed by device 0 | 257,760 (+6,896) | 255,415 (+7,050) |
| ETH transfer, v2, signed by device keys | 262,128 (+11,264) | 259,783 (+11,418) |
| ERC-20 transfer, v1 owners | 257,475 | 255,072 |
| ERC-20 transfer, v2, device 0 | 264,491 (+7,016) | 262,062 (+6,990) |
| ERC-20 transfer, v2, device keys | 4,312 more than device 0 | 4,372 more |

- **The shared WOTS verifier costs about 4.4k for the first signature in a transaction and 1.7k for each one after** (`test_gas_sharedWotsVerifier`). WOTS verification linked in costs 53,876 gas; through the verifier, 58,227 cold and 55,562 warm. Cold includes the verifier's account (2.6k); warm is the call and copying the signature into it. End to end, one owner's check of a SafeTx went from 66,242 to 71,005 (first in a transaction) and from 63,554 to 65,817 (second). The rest of the difference is v2's longer seed and the device checks.
- **Device keys add a storage read each,** the device's state: about 2.2k per signature, 4.3–4.4k for two.
- **Messages:** an app's 2-of-3 stateless check costs 197,908 gas on v1.5.0 and 240,564 on v1.4.1 (v1: 196,424 and 238,887).

| Device keys and trees | Gas | Calldata |
|---|---|---|
| `certifyDevice` | 250,570 | 5,860 B |
| `revokeDevice` | 249,350 | 5,828 B |
| `enroll`, a first tree, device 0 | 251,390–251,630 | 5,924 B |
| `enroll`, a first tree, a device key | 251,630–251,780 | 5,924 B |

- **All four sit exactly at EIP-7623's calldata floor** (21,000 + 10 gas per calldata token; the test logs both). The 5.7 KB stateless signature puts the floor above their execution, so under Prague neither the device key's two storage reads in `enroll` nor `certifyDevice`'s two new storage slots show in the totals. v1's 251k enrolment was floor-bound too.
- **Under Glamsterdam,** new storage costs more and execution may rise above the floor. Not measured: the note's estimate of about 0.5M for `certifyDevice` on Sepolia (two new slots) stays an estimate.

| The approved kind, each call cold | v1.4.1 | v1.5.0 |
|---|---|---|
| An app's check, the empty signature | 21,811 | 18,828 |
| An app's check, 2 approved signatures (300 B) | 51,164 | 44,370 |
| One owner's check on its own | 17,929 | 17,920 |

- **About 13–15k per owner through the Safe,** against the note's 3k. Each owner's check calls the owner's proxy, the implementation (cold for the first owner), recomputes the SafeMessage hash and calls back into the Safe for `signedMessages`. The app's check with two approved signatures still costs less than a quarter of the stateless 2-of-3 check (198k on v1.5.0, 241k on v1.4.1).

**Tests.** 87 in the owner's suites, all passing: 21 unit tests (`test/WinterlockOwner.t.sol`, 10 of them new) and, on each Safe release, 20 in `SafeWinterlockOwner.t.sol` (4 new) and 13 in `SafeMessages.t.sol` (4 new). The full suite: 385 pass, 12 skipped (WotsVerifier's checksum suites, as before), none fail.
- **Devices:** certify, revoke and certify again across generations. Old certificates and revocations can't be replayed. Refused: the wrong signer (the device key itself, another key), another chain, owner, device, generation or key, a key with a zero half, device 0, and devices above 3.
- **Trees per device:** a device key enrols only its own device's trees, and only while active. Two devices of one member sign at the same nonce with different one-time keys; neither signature passes under the other's device number, and the Safe counts the member once.
- **Start rules:** start nonces grow within a generation; a new generation may start below the old tree; a generation-1 certificate signed before a revoke can't be used after it.
- **Revoked or replaced devices:** their trees and messages stop verifying, including a confirmation collected before the revoke (GS024 on execution). The member key and other devices keep signing, and a new device key signs once it has enrolled.
- **The approved kind:** refused before a SignMessageLib approval and accepted after, through the fallback handlers of v1.4.1 and v1.5.0, from any two owners, and by Permit2. Refused again once the approval is withdrawn.
  - It can't approve a SafeTx, even with `signedMessages` set for the SafeTx hash itself by a test library.
  - Stand-in Safes: a reverting one, one with a short answer, an account without code and a precompile are all refused.
- **Every kind** is refused for a mismatching Safe or hash: a twin Safe with the same owners, with trees and the approval there too.
- **Unchanged and passing on v2:** transactions, the replacement with slot 1, nonce binding, the bindings to Safe and chain, messages through the fallback handler, the upgrade in place (`swapOwner` in a MultiSend with `enroll`), deterministic addresses, and option A's leanSphincs-s comparison. Option A's test-only owner is a copy of v1 and keeps v1's formats.
- **Mutation checks:** 12 mutants of the owner, each built with `forge test --force`, all caught by the unit tests: dropping the device-state check on transactions, or its generation; signing with an inactive device's key; bounding starts across generations; accepting any later generation in `certifyDevice`; dropping `revokeDevice`'s state check; dropping the approved kind's SafeMessage check or its code check; leaving the generation out of the message or device digest, or the device out of the tree certificate; dropping the device range check.

**Open issues and risks.**
- **The signer's pinned bytecode is v1.** `signer/tests/test_safe.py`'s check that the pinned code matches `contracts/out` now fails, as it should, until the signer phase re-pins. The signer still computes v1 addresses and formats.
- **Deploying v2 needs the 120% multiplier,** or a lower one. The signer's `enroll --deploy` must deploy the WOTS verifier as a fourth shared contract.
- **Revocations are per chain,** like device certificates (decision 3). A device certified on two chains and revoked on one still signs on the other, so the signer must revoke on every chain where it certified.
- **A revoked device's trees stay in storage.** `tree(safe, device)` still returns them; whether a tree verifies depends on `devices(device)`. The signer must check both.
- **Anyone can build an approved signature,** as designed. The owner answers it for any contract that reports its own SafeMessage approved, the implementation included. Only someone who trusts that contract is affected.
- **Generations are 16 bits,** so a device can be certified at most 65,535 times.
- **The views revert for a device above 3** (an out-of-range index), while signatures naming one are simply invalid.

**2026-11-06: Owner v2, signer** (`signer/`, `docs/notes/signer-recovery.md`, `docs/notes/walletconnect.md`)

Phase 2 of [notes/owner-v2.md](notes/owner-v2.md): the signer for v2. **Built and tested on local chains, not deployed;** phase 3 deploys v2 on Sepolia and swaps the test Safes' owners (deployed and run live later the same day, with a new test Safe instead of the swap: "Owner v2, live on Sepolia"). The signer on this branch is for v2 only: v1 owners keep v1's signer (main, `a7a175f`), and a v1 signer home opened here says so and how to restore its phrase into a v2 home.

**What's built:**
- **Formats** (`owner.py`): re-pinned from the phase 1 build, now with SharedWotsVerifier as the fourth shared contract and the implementation's third constructor argument. v2's digests, tree seeds and signature kinds (the device byte; the approved kind `0x03`); the views `devices(d)` and `tree(safe, d)`. A tree counts as usable only while its device is active at the tree's generation.
  - **Checked against the compiled contract** on anvil (`tests/test_owner_v2.py`): every digest and tree seed against the owner's own views, for devices 0–3 and generations up to 65,535; the domains, constants and addresses; and every encoding by acceptance and refusal (another device byte, a revoked device, an earlier generation, an unapproved message).
- **Two kinds of signer home** (`member.py`). The member key's home is device 0, as before. A device home (`device new`) holds a random device seed, encrypted like the phrase's, the member's owner address, its device number and its own key log, and no recovery phrase. Both sign the same way: `enroll`, `propose`, `confirm`, `execute`, `queue`, `status`, `connect` and `message` read the home's device from the contract on each chain and refuse, saying why, if it is revoked, replaced or not certified there.
- **Pairing** (`cli_devices.py`): `device new` shows the device key and a **check code**, five BIP-39 words from keccak(owner ‖ device ‖ key). `device certify` on the member key's home shows the code for what it is about to sign and certifies only once the member confirms it (or gives it with `--check-code`); on one or more chains, creating the owner first where it doesn't exist yet. `device revoke` revokes on every chain the key log certified the device on, plus any named, and reports per chain; a chain without an RPC is reported as NOT REVOKED and the command fails. `device list` shows the table per chain.
- **One owner counts once:** `confirm` on another of the member's homes sees the valid signature of device N at the service and doesn't spend a one-time key on it.
- **Approved answers for permits** (`bridge.py`, `messages.py`): once a SignMessageLib approval has executed, the dapp gets k approved signatures of v2 owners (150 bytes each, 300 for 2 of 3), checked with the Safe's `isValidSignature` first. With fewer than k v2 owners, it gets `0x` and the member a warning.
- **Moves and restores:** unchanged for the member key's home, the enroll guard included. A device home doesn't move (its key never leaves it): pair a new device and revoke the old one. A lost device home is revoked.

| Local measurements (anvil, Prague pricing) | Gas |
|---|---|
| `certifyDevice`, first certificate of a device | 250,690–250,840 |
| `revokeDevice` | 249,260–249,350 |
| `enroll`, a device key's first tree (height 6) | 251,600 |
| creating an owner through the factory (`device certify` on a new chain) | 74,228 |

- **Sizes:** a v2 message signature is one byte longer, 5,835 bytes as a Safe confirmation, so a 2-of-3 combined signature is 11,670 bytes (v1: 11,668). A transaction signature at height 10 is 1,758 bytes (1,855 as a confirmation).
- **The viem check** (`tests/test_e2e_walletconnect.py`, `tests/viem_verify.js`): a 2-of-3 Safe v1.4.1 of v2 owners on anvil approves a Permit2 PermitSingle through SignMessageLib, driven over WalletConnect. **viem 2.57.16's `verifyTypedData` accepts the 300-byte approved answer and refuses `0x`,** and refuses the approved answer for a permit the Safe hasn't approved. The test runs when `WINTERLOCK_NODE_MODULES` or `NODE_PATH` names a `node_modules` with viem, and skips otherwise.
- **Tests:** 152, none failing. With both optional `node_modules` given (viem, and the JS SDK dapp's `WINTERLOCK_WC_JS`), all 152 pass; with neither, 150 pass and those 2 skip. Before: 131, 1 skipped, with the pinned-bytecode check failing as phase 1 expected; it now covers all four pinned contracts and passes. New: 21.
  - `test_owner_v2.py` (6): the cross-check above.
  - `test_e2e_devices.py` (7), on two anvils (chains 31337 and 31338): pairing with a wrong and a right check code, certified on both chains; a device home enrols and proposes, a member key's home confirms, a third member executes (2 of 3); the member's other home doesn't sign again; a device message signature; a revoke with one RPC reports one chain revoked and the other not (the device still active there), the device's pending confirmation and message stop counting and its commands refuse; both chains revoked; the same key certified again (generation 2), its old tree void until `enroll`; a new device home replaces device 1 and the old one says REPLACED; a device home has no phrase, doesn't move and certifies nothing.
  - `test_device.py` (5 new): device homes offline: derivation, records, refusals, the check code, `device new` with a passphrase, and a v1 home's message.
  - `test_bridge.py` (1 new): the approved answer, its fallback to `0x`, and both checked before release.
  - `test_e2e_walletconnect.py` (1 new): the viem check; the permit step now expects the approved answer.
  - `test_safe.py` (1 new): amounts shown exactly (below).
  - Updated to v2: the anvil end-to-end tests (enrolment deploys four shared contracts), the vectors (deployment addresses from Forge's prediction of the v2 script; v1's helper still signs the WOTS part, which v2 extends by its device byte).
- **Fixed on the way:** the signer showed 0.1 ETH as `0.100000000000000006 ETH` (a float in `safe.fmt_eth`); amounts are now exact.

**Deviations from the note:**
- **The `device` command keeps `adopt` and `fresh-trees`** next to `new`, `certify`, `revoke` and `list`, with the help text saying which home runs which. Binding states moved from "device ACTIVE" to "key log ACTIVE on this machine", so "device" means a device number everywhere.
- **`device certify` can create the owner** on a chain where it doesn't exist yet (the factory's `deploy`), so a device can be paired before the member key's home has enrolled there.
- **Re-certifying a revoked key** is allowed with a warning, since the contract allows it; a lost or stolen device should be replaced by a new one instead.

**Open issues and risks:**
- **Revocation needs an RPC per chain,** and covers only chains the key log knows of. A member key's home restored from the phrase has an empty log: the member names the chains (`--chain`). Nothing on-chain lists the chains a device was certified on.
- **v1 homes don't open here.** Phase 3's owner swap is signed with v1's signer; afterwards each member restores the phrase into a v2 home (fresh trees, one `enroll` per Safe and chain).
- **The hosted Transaction Service with two devices of one member** is not checked: the stand-in replaces an owner's confirmation with the later one. The signer avoids a second confirmation when one already counts, but after a revoke the member's other home confirms again, and whether the hosted service accepts that replacement is unverified.
  - **Checked live on 2026-11-06: it doesn't.** It answers 201 and keeps the first confirmation; the signer now writes a proposal file for `execute --file` (see "Owner v2, live on Sepolia").
- **Deploying v2's implementation** through `enroll --deploy` uses the node's estimate × 1.2, within the cap by the phase 1 estimate (about 15.6M), not measured on Sepolia.
  - **Deployed on Sepolia on 2026-11-06** (separately, not through `enroll --deploy`): 12,821,325 gas, with a gas limit of 15,632,608.

**2026-11-06: Owner v2, live on Sepolia** (`signer/tools/live_devices.py`, `live_walletconnect.py`, `live_dapp.js`; results in the run directory's `results.json` and `walletconnect-*.json`, not in the repository)

The question: does owner v2 work end to end on Sepolia, with a member signing through a paired device key, a device revoked while a transaction is pending, Safe's hosted Transaction Service, and a dapp that verifies with viem? Yes. Two things needed fixing in the signer, both now fixed with tests: Safe's service keeps an owner's first confirmation, so confirming again after a revoke needed a way around it; and the bridge's receipt lookup failed on Alchemy's free tier.

**Deployment** (done before the run, separately; the addresses match the signer's pinned ones):

| Contract | Address | Gas used | Gas limit |
|---|---|---|---|
| SharedWotsVerifier | `0x272138c7D3b508bd510bE5166fbE2461561e410D` | 4,050,815 | 4,940,940 |
| WinterlockOwner v2 implementation | `0x114caAB223BaccD9BcA92C28ABBCf1edC0C3bCdf` | 12,821,325 | 15,632,608 |
| WinterlockOwnerFactory v2 | `0x90835a46Fb205B7f038B0EE46e798ead45a6fA7F` | 2,636,612 | 3,216,958 |
| stateless verifier (shared with v1) | `0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254` | already there | |

- **Transactions:** `0x1328a995911af90a2d95a3090ce4cd238002733402fc17150b0455b84f14afab`, `0x3f0b3755e6e6b9396403fd8c0b8aa46019aa8b1ae08b6659e3230763ec1567f3`, `0xbe5eb9ce09bcffbe3e77f0f1fba3a3d76765265ebfc6ab7b894cea7f74ce850b`.
- **Against the estimates** (Owner v2, contracts): the implementation 12.82M against about 13.0M, the WOTS verifier 4.05M against 4.1M, the factory 2.64M against 2.7M. The implementation's gas limit, 15,632,608, stayed under the 16,777,216 cap with 1.1M to spare.
- **Fees:** 0.00325 ETH. The base fee was 18 wei, but these transactions paid a priority fee of about 0.17 gwei. The run's own transactions tip at most 1 Mwei.

**Setup.**
- **Three signer homes,** new seeds, throwaway testnet keys: member 1's home with the member key (device 0), member 1's device home (device 1, no phrase), member 2's home.
- **The Safe:** v1.4.1 on the SafeL2 singleton through the canonical factory with the CompatibilityFallbackHandler, as in the earlier live runs; 2 of 2, funded with 0.001 ETH.
- **Key trees** of height 6 (32 nonces).
- **Addresses:**
  - member 1's owner `0x6162296cE4026c40eDe20C8867f4a6041c969800`, also the owner of device 1's key (`0xc9714bd8…30a6`, check code "among cheese scale climb bright")
  - member 2's owner `0x5b15B68d65a4dEbFd0B130D3e8a8B432e60B93cd`
  - Safe `0x6c315c5c9aDbFE50217B976a70BA54Cd11EC04EA`
- **The gas account** is the throwaway deployer `0x2B3e…3eAe`, not an owner. It sent every transaction and received the transfers.

**On-chain steps** (Sepolia, Glamsterdam pricing, gas used from receipts):

| Step | Gas used | Transaction |
|---|---|---|
| 1. Member 1's owner, created by `device certify` through the factory's `deploy` | 334,756 | `0x09b1fb11f1f4167103aa21dfdfb5dea7e4d7418c519794c9acca3af1632ebe79` |
| 1. `certifyDevice`, device 1, generation 1 | 391,760 | `0xdcf67e32be783231edac5ac7478a26d3a90af4f2368cd91c0ffc4c0785dfb067` |
| 2. Create the Safe | 1,371,897 | `0x081c13c4b7d5a3c1e8867070f455ff2ffafb2754e878f3a27b6997979860f6f1` |
| 2. Fund it with 0.001 ETH | 27,729 | `0x9399a47db001fce74b8fcecd8f007a8946c45e1b631daf79350f232e726db237` |
| 3. `enroll`, member 1's device 1 | 394,136 | `0x71b7fe8d7326b013addbf77e4827fca73186d70f22c315da72b62d7cf3f8710f` |
| 3. `enroll`, member 1's device 0 | 394,136 | `0xc831638b180bd1f92f0a0ba5c475b789ef7a57909718d33e9fb3195a91811963` |
| 3. `deployAndEnroll`, member 2 | 606,065 | `0x41075e50e4dcf6dd056e4c5406618f7b98291528cfb720ff7d9110fbca156d07` |
| 4. `execTransaction`, nonce 0, 1e11 wei to the gas account: device 1 and member 2 | 398,111 | `0x77b6a173246be34c9325c10a29846272c80c622997aef5a131df30d11ae2f5cc` |
| 5. `revokeDevice`, device 1, while nonce 1 was pending | 387,992 | `0x76f251a0a618a32c1c67c512108f89ec303fa926047702b46de53abfd6d9a118` |
| 5. `execTransaction`, nonce 1, 2e11 wei: device 0 (from the proposal file) and member 2 | 298,093 | `0xb2bed2af01872c1030bca9b0945b6ee972a9bbdd6b24a53db146584118f9834e` |
| 6. `execTransaction`, nonce 2, the dapp's transfer (1e11 wei), first dapp run: member 1's member key and member 2 | 298,081 | `0x17789fabfdf2d2559095120e357115ceb23acbe34b2203debeafed7728199b12` |
| 6. `execTransaction`, nonce 3, the Permit2 approval through SignMessageLib, first run | 407,769 | `0xdfa088d02f22920aee6ab8051a5a98060f8735acd25a28f7694f57fef15bf4fb` |
| 6. `execTransaction`, nonce 4, the transfer, second run | 298,093 | `0x8e4c98bde3c519e79f1c425a123d9d5097171b0e883aba694d0dd9010cd665fb` |
| 6. `execTransaction`, nonce 5, the Permit2 approval, second run | 407,769 | `0xa203202cdf3041e1b38af92ed66bd9f6eae7697d0fa2ba699ac296dd68dd2ac6` |
| 7. `certifyDevice`, device 1 with the same key, generation 2 | 390,040 | `0x2da0c6ad40ee9a5be1601e579d78467db65c7074a224c8ea15955c872e9efe49` |
| 7. `enroll`, device 1, generation 2 (nonces 6–37) | 394,136 | `0xe1419ae5c870386015bad6b487d302c5537508ebcabb41fd08a4c130333ca8a3` |
| 7. `execTransaction`, nonce 6, 3e11 wei: device 1 and member 2 | 300,247 | `0x00d26f2654272b53e2406be4d160b6c0627f34564020480c5a4db417c4ef19ae` |

- **Against the estimates and v1:**
  - `certifyDevice` 391,760 and `revokeDevice` 387,992, against 250,570 and 249,350 under Prague and the note's guess of about 0.5M on Sepolia: about 0.14M more than under Prague, as for enrolments, and less than the guess.
  - `enroll` 394,136 for a device key and for the member key alike, against v1's 392,088 on Sepolia; `deployAndEnroll` 606,065 against v1's 604,477–604,507; an owner alone 334,756 (estimate about 0.33M).
  - The first execution, 398,111, against v1's 388,733 at nonce 0 (proxy owners): 9.4k more, with a device key's signature among the two.
  - Later transfers with two member keys: 298,081–298,093 (nonces 1, 2 and 4), against v1's 290,889–293,777 on the kit Safe: about 7k more, as Forge measured for device 0 (+6.9k). With device 1's key at nonce 6: 300,247, another 2,154, the device record's storage read (about 2.2k under Prague).
  - The Permit2 approval through SignMessageLib: 407,769, against v1's 400,441 (+7.3k).
  - Enrolments cost 394,136 each, whether the device's tree slot was new (device 0, device 1's first tree) or held an earlier generation's tree (device 1 at generation 2); the certificates 391,760 (new device words) and 390,040 (generation 2). So Sepolia's extra 0.14M over Prague for these 5.8–5.9 KB transactions isn't new storage, as the 2026-11-05 live section read it. Not investigated further.
- **Sizes:** a transaction signature at height 6 is 1,662 bytes of owner data, 1,759 bytes as a confirmation (v1: 1,758); two of them make a 3,518-byte signatures blob.

**Step 1, pairing.** `device new` on the device home showed the key and its check code; `device certify --check-code` on member 1's home showed the same five words and certified. Member 1's owner didn't exist yet, so `device certify` created it first.

**Steps 3 and 4: the device signs.** The device home enrolled its own tree (generation 1) and proposed the transfer; member 2 confirmed. The service listed both confirmations as `CONTRACT_SIGNATURE`, 1,759 bytes each, member 1's with device byte 1, and indexed the execution within 20 s.

**Step 5: revoking while a transaction is pending.** The device home proposed a second transfer (nonce 1) and member 2 confirmed it. Then member 1's home revoked device 1.
- **The device's confirmation stopped counting at once:** the owner's `isValidSignature(SafeTx hash, its data)` answers `0xffffffff` (it answered the magic value before). `devices(1)` reads the same key at generation 1, inactive.
- **The device home refuses, in words:** `confirm` and `propose` answer "REFUSED: this device (device 1) was REVOKED on Sepolia (chain 11155111) at generation 1: it signs nothing there…"; `status` shows device 1 revoked ("<- this home") and its tree VOID.
- **`execute`** (any home) skips the device's signature as refused by its owner contract and stops: 1 valid of 2.
- **Member 1's home confirmed the same transaction through the hosted service.** What the service did:

| Call (in order) | Status | What the service holds afterwards |
|---|---|---|
| `GET /v2/multisig-transactions/{hash}/` after the revoke | 200 | both confirmations, unchanged: nothing marks device 1's as void, `confirmationsRequired` 2 |
| `POST /v1/multisig-transactions/{hash}/confirmations/`, member 1's device 0 signature (1,759 bytes) | 201 | |
| `GET` the same | 200 | unchanged: member 1's confirmation is still device 1's, with its original submission date |
| `POST /v2/safes/{safe}/multisig-transactions/`, the same transaction proposed again from member 1's home (same SafeTx hash, same key, so the same signature) | 201 | |
| `GET` the same | 200 | unchanged |
| `GET` after the execution (below) | 200 | executed; member 1's confirmation now holds device 0's signature, the one that executed, still with device 1's submission date |

- **Why** (the service's source, `history/serializers.py` and `indexers/tx_processor.py`, as of 2026-11-05):
  - Both endpoints store confirmations with `get_or_create` keyed by SafeTx hash and owner. A second confirmation by the same owner validates, is answered 201, and is dropped.
  - Deleting needs the proposer's signature over a `DeleteRequest`, and the service accepts only EOA signatures for it ("Only EOA and ETH_SIGN signatures are supported"), so no WinterlockOwner can delete a transaction there. No endpoint removes one confirmation.
  - When it indexes an execution, the service overwrites each owner's confirmation with the signature that executed. So history ends up right; only the pending queue is wrong.
- **So any re-confirmation of a pending transaction through the hosted service is silently lost:** after a device's revoke, after a restore from the phrase, and after `enroll --rotate`. The stand-in service in the tests replaced the confirmation instead, so the tests didn't see it, and the signer printed "Confirmed". Safe's app would show the transaction as fully confirmed and build its execution from the void signature (not checked in the app).
- **The way through, chosen:** the confirming home keeps its signature in a proposal file, and the executor combines the file with the service. Nothing is deleted, no extra one-time key is spent, and the service's other confirmations still count. Fixed in the signer (below) and used here: member 1's home confirmed again (the same key, so the same signature), the service again kept device 1's, and `confirm` wrote the file with member 2's confirmation and its own. The gas account ran `execute --file`, which counted each owner once and executed nonce 1.
- **The alternatives:**
  - a replacement at the same nonce (a cancel, signed with each member's second key) and the transfer proposed again at the next nonce, which works with the service and Safe's app but costs two executions and the second keys;
  - deleting the transaction at the service, which no WinterlockOwner can do.

**Signer fixed** (`cli.py`, with tests):
- **`confirm` and `propose` check what the service holds** after posting. If it kept another confirmation of this owner that no longer counts, they say so and write a proposal file (`--out`, or `safetx-HASH.json`) with the new signature and the other members' confirmations that count, and print how to execute with it. `confirm` warns before signing when it sees such a confirmation.
- **`execute --file`** adds the service's confirmations for the same hash to the file's, and counts each owner once, from its first signature that counts. When it lacks signatures and one was refused, it points to the proposal file.
- **`queue`** marks each confirmation that no longer counts, and tells the member when theirs is one.
- **The advice after `init --restore --lost` and `enroll --rotate`** mentions the proposal file.
- **Tests:** the stand-in service now keeps an owner's first confirmation, as the hosted one does. With that change and the old signer, the revoke and restore end-to-end tests failed at execution, as the live run would have. They now confirm again, get the proposal file, see `execute` without it fail and with it succeed, and check `queue` and a repeated `propose`.

**Step 6: a dapp over WalletConnect** (`live_walletconnect.py` and `live_dapp.js`; sign-client 2.26.0, viem 2.57.16, Reown's relay). The dapp paired with `connect` on member 1's member-key home; the script played member 2 and the gas account. Two runs: the first found a bridge bug (below), the second ran after the fix.

| Step | What the dapp got (second run; the first in brackets) | Checked by the dapp |
|---|---|---|
| Pairing | a session in 0.95 s (1.1 s), with the Safe as its account | — |
| Sign-in (`personal_sign`) | the Safe's combined signature, 11,670 bytes, 7.0 s after asking (4.8 s) | viem's `verifyMessage`: valid; for a changed message: invalid. The Safe's `isValidSignature`: the magic value |
| Transfer (`eth_sendTransaction`) | the SafeTx hash at once; after member 2 confirmed and the gas account executed, the execution's receipt for the SafeTx hash on its second poll, 15.9 s after the proposal (first run: none in 10 minutes, below) | the receipt matches the chain's (298,093 gas) |
| Permit2 (`eth_signTypedData_v4`) | the owners' approved signatures, 300 bytes, 26.3 s after asking (11.0 s), once the SignMessageLib approval had executed | **viem's `verifyTypedData`: valid** (both runs); with `0x`: invalid. The Safe's `isValidSignature`: the magic value for both |

- **viem accepts the on-chain path now.** The v1 run got `0x`, which viem refused (D14). The answer is two of Safe's contract signatures (r = owner, v = 0), lower owner first, each carrying the 53-byte approved kind `[0x03][safe][keccak(message)]`; no key signed them.
- **Against the v1 run:** sign-in 7.0 s (v1: 7.2 s), Permit2 26 s (v1: 26 s).

**Signer fixed, second: receipts for dapps on Alchemy** (`bridge.py`, with tests).
- **The bug:** in the first run the transfer executed at nonce 2, but the bridge answered `null` to each of the dapp's `eth_getTransactionReceipt` polls for 10 minutes, and the dapp gave up. Alchemy refused every `eth_getLogs` with HTTP 400: "Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range". The bridge asked from the proposal's block minus 64 to the latest. The 64-block look-back was added after the real-dapp run (2026-11-06, "a real dapp"), so the v1 live run, which asked from the proposal's block, didn't meet it.
- **The fix:** no log query until the Safe's nonce has passed the transaction's. Then the scan goes forward in windows, narrowed to 10 blocks (and then fewer) when a node refuses, and resumes where it stopped. It scans the last 4 blocks again, for nodes of a load-balanced endpoint that lag. `wallet_getCallsStatus` reports a replacement (400) only once that scan has settled past the block where the nonce was first seen passed.
- **Tests** (`test_bridge.py`, 3 new, failing on the old bridge): a node that refuses ranges over 10 blocks with Alchemy's message, where the execution is found in 10-block windows and remembered; nothing asked before the nonce passes, and a later lookup resuming where the last stopped; a replacement reported only once the logs are settled. The lagging-node test is updated for the nonce gate. 155 tests pass.

**Step 7: the same device again, generation 2.** Member 1's home certified device 1's key once more, after warning that the key had been revoked. The device home's `status` then read "ACTIVE at generation 2" and called its old tree VOID ("from generation 1; the device is at 2 now: `enroll`"). `enroll` certified a fresh tree from nonce 6 (the old one, from generation 1, set no bound), and the device proposed a transfer that member 2 confirmed and the gas account executed. The service listed the device's confirmation with device byte 1.

**Spent:** 0.000999200133 ETH from the gas account, of which 0.0009992 ETH is still in the test Safe (the 0.001 ETH funding less the 8e11 wei of transfers back). Fees were 133,223,611 wei (1.3e-10 ETH) for 17 transactions and 7.10M gas, about 19 wei per gas. Before the run, the deployment above cost 0.00325 ETH. The gas account holds 0.0379 ETH.

**Not checked:** Safe's app with this Safe (it would list the void confirmation as one of two), and a third-party dapp that verifies with viem (the scripted dapp verifies with viem itself).

**2026-11-07: Rust core** (`core/`, `signer/tools/core_vectors.py`, `hardware/esp32-core-check/`)

Step 2 of [notes/signer-app.md](notes/signer-app.md), "Order". The question: does a `no_std` Rust port of the Python signer's cryptography and key rules give the same bytes as Python, natively, in WebAssembly and on the ESP32? Yes natively, under Node and in Espressif's QEMU. The chip itself runs it on Monday.

**What's built:**
- **`winterlock-core`** (`core/`), `no_std` with `alloc`, no floating point, no randomness inside (seeds, salts and phrase entropy are parameters):
  - keccak256: the crate's own sponge over the Keccak-f of `tiny-keccak` (default) or RustCrypto (`sha3` feature: the `keccak` crate under `sha3`). With both features the backend is picked at run time, so one image can time both.
  - the phrase (24 words ↔ seed, the forgiving parser with Python's Unicode sets, named errors) and the pairing check code
  - leanSphincs-keccak: pruned keys, leaves over any range (for two cores), a key from cached leaves, sign, verify
  - WOTS D6: leaves over any range, trees, paths, the Python cache format, `verify_root`
  - derivations: member key, device key, tree secret seed
  - owner v2: key indices, all five digests, the three layouts with parsers, owner addresses from the pinned v2 contracts, signing a transaction, message, device certificate or revocation (each checked before it is returned)
  - SafeTx (fields in: 320-byte words, EIP-712 hash), SafeMessage, EIP-191; amounts shown exactly
  - **the key log's rules** (`pick_slot`, `record_sign`) over a two-method storage trait the platform implements: find a key's use, append a use durably. A WOTS key signs only from the `Recorded` value that the append returns, so a signature can't exist without its record.
- **Fewer permutations than Python, same outputs:** a WOTS randomizer's first block and the leanSphincs WOTS+C prefix are absorbed once per signature, not per try (2 permutations per WOTS try instead of 3; 1 per WOTS+C try instead of 6). Key and tree counts equal Python's: 238,624 for a key (b = 10), 848,895 for a height-10 tree.
- **Size:** 2,640 lines of Rust in the crate, plus 340 lines of generated tables (the word list, Python's whitespace and digit sets); 980 lines of tests and the timing example.

**Vectors** (`core/tests/vectors/`, 380 KB of JSON from `core_vectors.py`; only that script is new on the Python side):
- phrase: the word list and Unicode sets, 5 round trips, 13 typed variants (case, numbering, commas, abbreviations, Unicode spaces, Arabic-Indic numbering, hex), 10 errors, 20 single words, 6 backup-check answers, 9 check codes
- keys: 4 seeds' member and device keys (b = 10) with their leaves' hash, owner addresses, 4 tree secret seeds
- leanSphincs: 4 signatures whose grinds took 243 to 251,953 tries, and a b = 6 key
- WOTS: trees of height 6 and 10 (roots, leaves, cache), 8 signatures with paths for both slots and the last key, the signer and test PRFs, a partial test tree
- owner v2: 15 sets of all five digests (devices 0–3, generations 0, 1, 65,535, starts up to 2^40 − 1), 11 key indices with errors, 5 addresses with their init code and runtime, the three layouts with real signatures, the domains, the pinned addresses
- Safe: 5 SafeTx (empty, a value, ERC-20 data, a delegatecall with 768 bytes of data, every field set with a nonce above 2^64) on 4 chains, 3 SafeMessages, 4 EIP-191 messages, 8 amounts, 10 checksummed addresses
- key log: 4 scenarios (first, second, third version; explicit slots and reuse; nonces outside the tree; separate trees, Safes and chains) with the records left
- also checked: the 6 upstream leanSphincs-keccak known answers and the upstream crate's, and the 4 pinned addresses derived from `contracts.json`'s creation code

**Three targets** (`core/check.sh`):

| Target | Result |
|---|---|
| native (x86-64) | 29 tests pass with tiny-keccak, with RustCrypto, and with both switched at run time |
| WebAssembly (`wasm32-unknown-unknown`) | the same 29 pass under Node 24 (wasm-bindgen-test 0.3.80) |
| ESP32 (`xtensa-esp32-none-elf`, `no_std`) | builds with each backend and with both |

**Native timings,** the inputs of `signer/tools/bench.py`, one process or thread, Ryzen 5 2600. The machine was busy (load average 8 to 10 on 12 threads), so these are the best of three runs and only the ratios are worth much:

| Operation | Python (C keccak) | Rust | Ratio |
|---|---|---|---|
| stateless key, b = 10 | 0.38 s | 0.10 s | 3.7× |
| stateless signature, median of 10 | 0.18 s | 60 ms | 3× |
| stateless verification | 1.2 ms | 0.14 ms | 8× |
| WOTS tree, height 10 | 1.04 s | 0.37 s | 2.8× |
| WOTS signature with its check against the tree, median of 20 | 3.8 ms | 0.9 ms | 4× |

Two threads saved less than half (a height-10 tree in 0.29–0.33 s) on the busy machine.

**The board's firmware** (`hardware/esp32-core-check/`, image `winterlock-esp32-core-check.bin`, 395,072 bytes, SHA-256 `c3558a0b03955655516ce34f3bd3070f33fb97275fcd3d9e0d61c92861a62cab`):
- **Checks** a compact subset of the vectors built into the image (phrase to seed, member key, owner address, check code, device certificate digest, two SafeTx hashes, a key log scenario, stateless and WOTS verification, both backends' keccak), then **times** the member key (one core, both), four stateless signatures, WOTS trees of height 6 and 10 (one core, both) and eight WOTS signatures through the key log, with each backend, checking every result byte for byte: 54 checks.
- **In QEMU** (v0.0 and v3.0 chips): all 54 pass; heap peak 82,144 of 180,224 bytes; the first core's stack peaked at 9,868 of 73,992 bytes, the second's at 1,644 of 32,768 over 6 jobs. With `scripted-boot`, BOOT starts the run and turns the summary pages. QEMU's times say nothing about the chip.

**Unverified until Monday:**
- that the chip computes the same bytes (QEMU emulates the Xtensa core, not the silicon)
- every timing, and which backend is faster on the chip: the image times both, then the board's firmware builds with the faster feature
- the second core restarted for each job, and the heap in memory reclaimed from the bootloader, on silicon
- the OLED (QEMU has none) and the BOOT button
- chips older than v3.0 on real silicon

**Python, read while porting** (matched in Rust, not changed):
- `phrase.matches(words, 0, answer)` compares with the last word (`words[position - 1]`); position 25 raises IndexError. Callers only pass 1 to 24.
- `owner.key_index` takes any height, including heights above 40 that no certificate allows; height 0 fails with Python's "negative shift count".
- `owner.tx_signature_data` doesn't check the slot: slot 2 gives data the contract refuses.
- `wots.tweak` doesn't range-check its fields, so `verify_root` with a path of more than 255 levels would spill the level into the chain byte (Rust keeps one byte). Paths are 40 levels at most in practice.
- `phrase.to_seed` takes a hex seed with `0x` but not `0X`, while `abi.h2b` takes both.
- `wots.Tree` allows real leaves up to height 40; the signer refuses above 20 (`member.new_tree`). The core refuses above 20 in `Tree` itself: a tree of 2^40 leaves can't be held in memory.

## Integration notes: Kernel v3.3

These come from `contracts/test/integration/KernelWinterlock.t.sol`, which has 13 tests.

- **Root validator, including counterfactual deployment.** The first operation deploys the account through the factory and is signed with WOTS. There's no ECDSA step anywhere.
- **Nonce lanes.** Kernel's nonce key is mode (1 byte), type (1), validator (20) and a parallel key (2). Kernel accepts any parallel key for the root validator. Winterlock accepts only its configured lane, so sequence numbers can't repeat across lanes (tested).
- **Replayable signatures.** If a signature starts with Kernel's magic value, Kernel hands the validator a hash without the chain ID, so one signature is valid on every chain. That conflicts with keeping key trees separate per chain. For ERC-1271 it no longer matters: Winterlock's own wrap binds the chain id (D11, tested).
- **ERC-1271 works with the stateless keys (D11), for apps.** `Kernel.isValidSignature` names the app that asks as the sender; 1-of-1 and 2-of-3 are tested.
- **Kernel's "enable mode" is refused by design.** It installs a validator inside a UserOperation once the root validator approves an "Enable" digest through ERC-1271, and Kernel asks with the account itself as the sender. Winterlock refuses that sender, so members' message signatures can't install a module and act through it. Modules are installed only by a WOTS-signed `installModule` (tested, with a mutation check: see 2026-11-05, D12).
- **Each installed module is a second way in.** A Winterlock-signed operation can install an ECDSA validator, and from then on that ECDSA key can move funds on its own nonce lane (tested). The signer and the wallet have to show module installs clearly and require explicit confirmation.
- **Threshold accounts work on Kernel.** A 2-of-3 team account is deployed by its first operation, signed by two members. One member alone is refused (tested).
- **Kernel's EIP-7702 mode.** Validation type 0x00 falls back to ECDSA over the account's own address. That is only reachable for EIP-7702-delegated EOAs, not for accounts deployed as contracts.

## Open questions

**Cryptography**
- Hash function on hardware signers: D9 keeps keccak. If a hardware signer can't hash keccak fast enough for key generation and target-sum retries, weigh SHA-256 (+50k gas per signature) against it.
- **Hardware signing time, measured elsewhere (noted 2026-11-06).** JARDÍN's README reports keccak on a Ledger Nano S+ (ST33K1M5) at about 1.5 ms per hash: 31.5k hashes in 47.3 s. That is about eight times slower than the rate behind the "13 s" above, which came from Ledger's SPHINCS+ benchmark. At 1.5 ms per hash (my estimates, not measured on a device):
  - **A leanSphincs signature** (70–92k hashes): about 1.5–2.5 minutes. Acceptable for certificates and recovery, slow for messages.
  - **A D6 transaction signature:** about 945 digest tries plus 431 chain steps, so about 2 seconds, if the device keeps the tree's leaves (64 × 24 bytes at height 6) instead of recomputing them.
  - **Generating a D6 tree:** about 720 hashes per key, so about 70 seconds at height 6 (64 keys) and about 18 minutes at height 10 (1,024 keys).
  - **So, on hardware:** small trees (height 6 or less, rotated more often), leaves kept on the device, and SHA-256 weighed again where the secure element accelerates it.
  - **Next:** measure on a real device before promising hardware support.
- Key generation on a device: tree height is nearly free on-chain, but whoever computes the root must generate every key. 2^20 keys with D6 is roughly 750 million hashes, which is minutes on a laptop and likely too slow for a hardware wallet. D10 makes small operation trees with rotation possible: a height-14 tree is about 12 million hashes. Open: the tree size the signer should default to, and when it should rotate.
- An independent reference implementation and test vectors, in Python or Rust. So far the tests only cross-check against a Solidity signer.
- **A stateless key for EIP-8288 (noted 2026-11-06).** EIP-8288 (draft, Buterin and Coratger, 2026-06-03) would let EIP-8141 frame transactions declare a leanSPHINCS signature as a dependency that mempool nodes aggregate into one recursive STARK, at 3,000 gas per signature instead of about 53k. Its public key has our layout (16-byte root ‖ 16-byte public parameter), but it names the Lean Ethereum verifier, whose hash is chosen to be cheap to prove. A keccak key such as ours would first have to be wrapped in a STARK by the signer (Consigny, ethresear.ch topic 25165). That rides as EIP-8288's other dependency kind, a STARK (scheme `0x11`, still reserved), at 30,000 gas. For scale, ERC-8403's author proved a small key-set program on leanVM: a 162–235 KiB proof in 0.1–0.3 s on 12 cores (topic 26147). Proving a keccak signature would take far more work, since keccak is costly to prove.
  - **The idea:** when EIP-8288 settles its hash, derive a second stateless key with it from the same recovery phrase, under its own label next to `winterlock.signer.stateless.v1` (member.py), and certify it with the leanSphincs-keccak key. Members keep their phrase, and the certificate shows that the new key is theirs, so moving to an EIP-8288 account needs no new backup and no new trust.
  - **What it needs:** a native signer for that hash (the field arithmetic of Poseidon-style hashes, not keccak), and an owner or account that accepts the second key. On-chain verification of the new key is only cheap through EIP-8288, so the keccak key stays the path on chains without it.
  - **When:** nothing to build until EIP-8288 fixes its hash and a fork or an L2 schedules it. Any phrase made today can derive the key later.
  - **With device keys (notes/owner-v2.md):** in an EIP-8141 account, the EIP-8288 key needn't come from the phrase. It becomes a device key certified by the member key, and daily signatures then cost 3,000 gas with no key trees.

**Accounts and chains**
- One address on every chain, and tree rotation: decided in D10, built and shown live on two testnets (above). D12 removed the log of used master keys. Still open: deploying on chains without Cancun opcodes, or with a different deterministic deployer; and bytecode that doesn't depend on the build directory (see 2026-11-05, D12, "Deployment").
- **Several devices per member (noted 2026-11-06, after JARDÍN, where each device registers its own key slot).** Today an owner holds one active tree per Safe, so a member signs from one device at a time, and a backup is either a cold copy of the phrase (promoted by a restore) or a separate owner.
  - **The idea:** the owner holds a few trees per Safe (2–4), one per device, each tagged with a device number and certified by the stateless key. The tree's keys derive from the device number too, so two active devices never share a key, even at the same nonce.
  - **What it adds:** an explicit revoke for a lost device's tree, signed by the stateless key or by the quorum. JARDÍN's slots can't be revoked.
  - **Costs:** a storage slot and a certificate (about 190k gas) per device, Safe and chain. The signer changes, and the enroll guard against an old device undoing a restore becomes "revoke the lost device" instead.
  - **When:** it changes WinterlockOwner's code, and so every owner's address, as does the deferring signature kind for viem (D14). Doing both in one new owner version pays that cost once.
- **The next owner version, built once (noted 2026-11-06).** Three changes each move every owner's address, so they belong in one version:
  - **The signature kind for viem (D14).**
  - **Several devices per member, as a root over authority leaves,** in the shape of ERC-8403 (Daniil Ankushin, Nethermind; ethresear.ch topic 26147): the owner stores one root per Safe over leaves of the form `keccak(id ‖ predicate)`, one per device tree, and a signature carries a membership proof next to its WOTS signature. Adding, rotating and revoking a device is one root write, signed by the stateless key or the quorum. The revoke reads the current root, ERC-8403's tier 2, so it works from the next block. Rules to keep: a fixed, small number of devices per member; only the stateless key or the quorum adds a device, never another device; a revoke removes a device whatever state its tree is in. The leaves also suit a future EIP-8141 account, which ERC-8403 targets.
  - **Alignment with a LeanSPHINCS standard.** A draft ERC, "LeanSPHINCS" (Antonio Sanso, with Matteo Vicari and Alessandro Baiocchi of RivaLabs in a fork; created 2026-07-28, not yet a pull request to ethereum/ERCs), sets out to fix one parameter set, the public-key and signature encodings, message domains and verification rules, and adds FORS+C as an optional stateful mode. It fixes none of them yet. The owner's address follows from the stateless key, so if the ERC settles an encoding or domain that differs from leanSphincs-keccak's, the owner version that follows it should adopt it. Until then, follow the draft and compare before freezing the next owner.
  - **Then:** reprice the version with the device proof (about 32 bytes per level) and the root write, and keep certified WOTS trees under the leaves; benchmarking FORS+C against them is a separate question.
  - **Design note (proposal, 2026-11-06):** [notes/owner-v2.md](notes/owner-v2.md). Working it through, it proposes device keys that don't hold the recovery phrase (otherwise revoking a device is pointless), a small table of devices instead of an ERC-8403 root, and the approved signature kind for viem. Decisions 1–3, 5 and 6 approved on 2026-11-06; the verifier per device dropped. **Phase 1 built on 2026-11-06** (the contracts and their tests, not deployed): see Measurements, "2026-11-06: Owner v2, contracts". **Phase 2, the signer, built the same day** (local chains only, with the viem check): "2026-11-06: Owner v2, signer". **Deployed on Sepolia and run live the same day:** "2026-11-06: Owner v2, live on Sepolia".
- **A signer without a terminal (noted 2026-11-06).** The Python signer needs a terminal; the first users outside the project sign on laptops and phones. Design note (proposal): [notes/signer-app.md](notes/signer-app.md). One Rust core (`no_std`) for the browser and an ESP32 board, a TypeScript app around it, Arbitrum One with play money. Python stays the reference, and its test vectors become the normative spec's.
- A recovery key: D11's stateless key is the recovery path, built and tested (above). Open: social or time-delayed recovery on top, as a separate module.
- Managing threshold accounts: changing members or the threshold currently means uninstalling and reinstalling the module. Open: a rotation function signed by the current quorum.
- Validator upgrades: the validator is immutable. Moving to a fixed version means installing the new module through an operation signed with the old one, then uninstalling the old one.
- Off-chain messages (ERC-1271 through `isValidSignatureWithSender`): built with the stateless key and an EIP-712 wrap (D11, above). Open: full ERC-7739 nested typed data, and on-chain pre-approval for high-value permits.
- 7579 details: Kernel v3.3 is done (see the integration notes). Still to do: Nexus and Safe7579, including whether they have an enable path like Kernel's and whether it asks with the account as the sender, so the same lock covers it; whether to refuse or support Kernel's replayable signatures for UserOperations; and the signer's confirmation flow for installing modules (Kernel's enable mode is refused by design). On Safe7579, an operation whose nonce doesn't name an installed validator falls back to the Safe's owners, so lock-down must replace the owners too.
- Classic Safes: a Safe-owner (EIP-1271) adapter from D1 is prototyped and tested on Safe v1.4.1 and v1.5.0 (see 2026-11-05, Safe owner spike), and works live on Sepolia with Safe's Transaction Service for transactions (see 2026-11-05, Safe owner, live on Sepolia). Safe's app shows such a Safe with no change (checked by hand). Members' owners are now cheap proxies (above). Messages follow D14, and the signer answers dapps over WalletConnect, live on Sepolia (2026-11-06). The owner signature kind for viem (D14) is built in owner v2 and the signer answers with it; viem accepts it live on Sepolia (2026-11-06, "Owner v2, live on Sepolia").

**Infrastructure**
- Bundler acceptance: answered for the hosted bundlers. Pimlico, Candide and Alchemy accept and include WOTS operations from a production Kernel on Arbitrum Sepolia (stage 2, above). Still open:
  - the shared (P2P) mempool
  - mainnet configurations, which may differ from testnet ones
  - Kernel's first operation on Alchemy (the CREATE2 rule): report it to ZeroDev or Alchemy, or deploy the account by an ordinary transaction
- The collection service (D8): its API, who may post proposals (spam), how private pending proposals are, and whether to reuse code from Safe's transaction service.
- Limits and abuse policy for the rescue bundler, how to fund it, and a legal check on sanctions screening (EU/Germany).
- The signer: software first, key derivation from a seed, tracking used slots. Hardware comes later.
- Calldata repricing: EIP-7976 is analysed above. Glamsterdam is live on Sepolia (measured above). Re-run `bench.sh` against its final pricing once Foundry's EVM supports it, since local benchmarks still use the old prices.

**Before real funds**
- An independent cryptographic review of the construction (tweaks, randomizer, target sum, nonce binding) and a security audit of the validator.
