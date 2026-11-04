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

## Constraints that every design must respect

- **One key tree per chain and per account.** Nonces repeat across chains and accounts. If two of them share a tree, the same one-time key ends up signing two different messages. In a threshold account this applies per member: each member needs a separate tree for every account they sign for. One master seed can derive them all.
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
- Key generation on a device: tree height is nearly free on-chain, but whoever computes the root must generate every key. 2^20 keys with D6 is roughly 750 million hashes, which is minutes on a laptop and likely too slow for a hardware wallet. Options: a smaller tree with rotation, or a hypertree whose top tree signs subtree roots.
- An independent reference implementation and test vectors, in Python or Rust. So far the tests only cross-check against a Solidity signer.

**Accounts and chains**
- How to keep one address on every chain while using different keys on each. One option: a single root over per-chain subtrees, with the validator checking that the subtree matches `block.chainid`.
- What happens when a tree runs out of keys: how to rotate to a new root, and what signs the rotation.
- A recovery key: SPHINCS+, a cold WOTS tree, or none.
- Managing threshold accounts: changing members or the threshold currently means uninstalling and reinstalling the module. Open: a rotation function signed by the current quorum.
- Validator upgrades: the validator is immutable. Moving to a fixed version means installing the new module through an operation signed with the old one, then uninstalling the old one.
- Off-chain messages (ERC-1271 through `isValidSignatureWithSender`): support them with dedicated key slots, or refuse them.
- 7579 details: Kernel v3.3 is done (see the integration notes). Still to do: Nexus and Safe7579; whether to refuse or support Kernel's replayable signatures; and the signer's confirmation flow for installing modules. On Safe7579, an operation whose nonce doesn't name an installed validator falls back to the Safe's owners, so lock-down must replace the owners too.
- Classic Safes: whether to build the Safe-owner (EIP-1271) adapter from D1, for teams that don't use 4337.

**Infrastructure**
- Whether Rundler, Alto and the shared mempool accept these signatures (1.7 KB per signer with D6) and the verification gas measured above.
- The collection service (D8): its API, who may post proposals (spam), how private pending proposals are, and whether to reuse code from Safe's transaction service.
- Limits and abuse policy for the rescue bundler, how to fund it, and a legal check on sanctions screening (EU/Germany).
- The signer: software first, key derivation from a seed, tracking used slots. Hardware comes later.
- Calldata repricing: EIP-7976 is analysed above. Re-run `bench.sh` if the final Glamsterdam pricing differs.

**Before real funds**
- An independent cryptographic review of the construction (tweaks, randomizer, target sum, nonce binding) and a security audit of the validator.
