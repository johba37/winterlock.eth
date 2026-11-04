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

## Constraints that every design must respect

- **One key tree per chain and per account.** Nonces repeat across chains and accounts. If two of them share a tree, the same one-time key ends up signing two different messages.
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

## Integration notes: Kernel v3.3

These come from `contracts/test/integration/KernelWinterlock.t.sol`, which has 7 tests.

- **Root validator, including counterfactual deployment.** The first operation deploys the account through the factory and is signed with WOTS. There's no ECDSA step anywhere.
- **Nonce lanes.** Kernel's nonce key is mode (1 byte), type (1), validator (20) and a parallel key (2). Kernel accepts any parallel key for the root validator. Winterlock accepts only its configured lane, so sequence numbers can't repeat across lanes (tested).
- **Replayable signatures.** If a signature starts with Kernel's magic value, Kernel hands the validator a hash without the chain ID, so one signature is valid on every chain. That conflicts with keeping key trees separate per chain (open question).
- **ERC-1271 is refused.** That also disables Kernel's "enable mode", where a validator is installed inside a UserOperation on the strength of a root ERC-1271 signature. New modules can only arrive through an ordinary Winterlock-signed operation calling `installModule`.
- **Each installed module is a second way in.** A Winterlock-signed operation can install an ECDSA validator, and from then on that ECDSA key can move funds on its own nonce lane (tested). The signer and the wallet have to show module installs clearly and require explicit confirmation.
- **Kernel's EIP-7702 mode.** Validation type 0x00 falls back to ECDSA over the account's own address. That is only reachable for EIP-7702-delegated EOAs, not for accounts deployed as contracts.

## Open questions

**Cryptography**
- Within D6: Winternitz `w` (16 now), and the hash function (keccak now; SHA-256 is faster on hardware wallets, which matters for target-sum retries on the device).
- An independent reference implementation and test vectors, in Python or Rust. So far the tests only cross-check against a Solidity signer.

**Accounts and chains**
- How to keep one address on every chain while using different keys on each. One option: a single root over per-chain subtrees, with the validator checking that the subtree matches `block.chainid`.
- What happens when a tree runs out of keys: how to rotate to a new root, and what signs the rotation.
- A recovery key: SPHINCS+, a cold WOTS tree, or none.
- Off-chain messages (ERC-1271 through `isValidSignatureWithSender`): support them with dedicated key slots, or refuse them.
- 7579 details: Kernel v3.3 is done (see the integration notes). Still to do: Nexus and Safe7579; whether to refuse or support Kernel's replayable signatures; and the signer's confirmation flow for installing modules.

**Infrastructure**
- Whether Rundler, Alto and the shared mempool accept 2.5–3 KB signatures and the verification gas measured below.
- Limits and abuse policy for the rescue bundler, how to fund it, and a legal check on sanctions screening (EU/Germany).
- The signer: software first, key derivation from a seed, tracking used slots. Hardware comes later.
- How future repricing of calldata gas would change the numbers above.
