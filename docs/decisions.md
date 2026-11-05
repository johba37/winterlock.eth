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
- **Certificates:** a master key signs a certificate for one operation tree on one chain. The certificate binds the chain id, the validator, the account, the member, the tree's root, seed and height, and the first sequence number it signs for.
- **Enrolment:** the first operation a member signs on a chain carries the certificate. The validator checks it and stores the tree in the account's storage on that chain. Later operations are verified against the stored tree and cost the same as before.
- **Rotation:** the same mechanism replaces an exhausted tree. Each certificate on a chain must use a higher master index than the one before, so old certificates can't be replayed to roll a tree back.
- **What the signer must guarantee:** a master key certifies at most one tree, across all chains and accounts. Certificates are rare and recorded on-chain, so the log is small and can be rebuilt.
- **The same structure as LMS/HSS and XMSS^MT** (NIST SP 800-208).

It replaces the single key tree of D2, keeps D2's binding of keys to nonces, and resolves the open questions about one address per chain and about tree exhaustion. Per-chain trees can be small and are generated when a chain is first used, which also eases key generation on devices.

## Constraints that every design must respect

- **One key tree per chain and per account.** Nonces repeat across chains and accounts. If two of them share a tree, the same one-time key ends up signing two different messages. In a threshold account this applies per member: each member needs a separate tree for every account they sign for. One master seed can derive them all. Under D10 the master tree is shared by all chains of one account, but each master key signs only one certificate.
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

## Integration notes: Kernel v3.3

These come from `contracts/test/integration/KernelWinterlock.t.sol`, which has 7 tests.

- **Root validator, including counterfactual deployment.** The first operation deploys the account through the factory and is signed with WOTS. There's no ECDSA step anywhere.
- **Nonce lanes.** Kernel's nonce key is mode (1 byte), type (1), validator (20) and a parallel key (2). Kernel accepts any parallel key for the root validator. Winterlock accepts only its configured lane, so sequence numbers can't repeat across lanes (tested).
- **Replayable signatures.** If a signature starts with Kernel's magic value, Kernel hands the validator a hash without the chain ID, so one signature is valid on every chain. That conflicts with keeping key trees separate per chain (open question).
- **ERC-1271 is refused.** That also disables Kernel's "enable mode", where a validator is installed inside a UserOperation on the strength of a root ERC-1271 signature. New modules can only arrive through an ordinary Winterlock-signed operation calling `installModule`.
- **Each installed module is a second way in.** A Winterlock-signed operation can install an ECDSA validator, and from then on that ECDSA key can move funds on its own nonce lane (tested). The signer and the wallet have to show module installs clearly and require explicit confirmation.
- **Threshold accounts work on Kernel.** A 2-of-3 team account is deployed by its first operation, signed by two members. One member alone is refused (tested).
- **Kernel's EIP-7702 mode.** Validation type 0x00 falls back to ECDSA over the account's own address. That is only reachable for EIP-7702-delegated EOAs, not for accounts deployed as contracts.

## Open questions

**Cryptography**
- Hash function on hardware signers: D9 keeps keccak. If a hardware signer can't hash keccak fast enough for key generation and target-sum retries, weigh SHA-256 (+50k gas per signature) against it.
- Key generation on a device: tree height is nearly free on-chain, but whoever computes the root must generate every key. 2^20 keys with D6 is roughly 750 million hashes, which is minutes on a laptop and likely too slow for a hardware wallet. D10 makes small operation trees with rotation possible: a height-14 tree is about 12 million hashes. Open: the tree size the signer should default to, and when it should rotate.
- An independent reference implementation and test vectors, in Python or Rust. So far the tests only cross-check against a Solidity signer.

**Accounts and chains**
- One address on every chain, and tree rotation: decided in D10. The validator is done (step 1, measured above). Still to do:
  - deploy the validator at the same address on every chain
  - Kernel tests across two chain ids (same address, separate trees)
  - the same account live on Ethereum Sepolia and Arbitrum Sepolia
  - the signer's log of used master keys: where it lives and how it is backed up
- A recovery key: SPHINCS+, a cold WOTS tree, or none.
- Managing threshold accounts: changing members or the threshold currently means uninstalling and reinstalling the module. Open: a rotation function signed by the current quorum.
- Validator upgrades: the validator is immutable. Moving to a fixed version means installing the new module through an operation signed with the old one, then uninstalling the old one.
- Off-chain messages (ERC-1271 through `isValidSignatureWithSender`): support them with dedicated key slots, or refuse them.
- 7579 details: Kernel v3.3 is done (see the integration notes). Still to do: Nexus and Safe7579; whether to refuse or support Kernel's replayable signatures; and the signer's confirmation flow for installing modules. On Safe7579, an operation whose nonce doesn't name an installed validator falls back to the Safe's owners, so lock-down must replace the owners too.
- Classic Safes: whether to build the Safe-owner (EIP-1271) adapter from D1, for teams that don't use 4337.

**Infrastructure**
- Bundler acceptance: answered for the hosted bundlers. Pimlico, Candide and Alchemy accept and include WOTS operations from a production Kernel on Arbitrum Sepolia (stage 2, above). Still open:
  - the shared (P2P) mempool
  - mainnet configurations, which may differ from testnet ones
  - Kernel's first operation on Alchemy (the CREATE2 rule): report it to ZeroDev or Alchemy, or deploy the account by an ordinary transaction
- The collection service (D8): its API, who may post proposals (spam), how private pending proposals are, and whether to reuse code from Safe's transaction service.
- Limits and abuse policy for the rescue bundler, how to fund it, and a legal check on sanctions screening (EU/Germany).
- The signer: software first, key derivation from a seed, tracking used slots. Hardware comes later.
- Calldata repricing: EIP-7976 is analysed above. Re-run `bench.sh` if the final Glamsterdam pricing differs.

**Before real funds**
- An independent cryptographic review of the construction (tweaks, randomizer, target sum, nonce binding) and a security audit of the validator.
