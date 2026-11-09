# SLH-DSA on the EVM: a gas benchmark

What does it cost to verify a NIST-standard hash-based signature, SLH-DSA (FIPS 205), on Ethereum today? This directory
holds a verifier for **SLH-DSA-SHA2-128s**, checked against independent known answers, and the measurements. It also
covers **SLH-DSA-SHA2-128-24, a DRAFT parameter set** from the initial public draft of NIST SP 800-230, whose known
answers come from this benchmark's own reference.

It's a benchmark: nothing in `contracts/src`, the owner contracts, the validator, the signer or the app uses it.

## Results

Prague rules (as `contracts/bench.sh`); Osaka gives the same figures. Mean over the signatures measured, range in
brackets. Signatures are over 32-byte hashes with an empty context, as an ERC-1271 check passes them.

| | SLH-DSA-SHA2-128s | SLH-DSA-SHA2-128-24 (DRAFT) |
|---|---|---|
| Signature, public key | 7,856 B, 32 B | 3,856 B, 32 B |
| SHA-256 precompile calls per verification | 2,137 (2,010–2,295) over 18 signatures; modelled 2,125, p1–p99 1,950–2,310 | 285 (281–287); modelled 279 (257–299) |
| Verification gas, from a contract, verifier cold | **623k** (591k–662k), 18 signatures | **106k** (105k–107k), 3 |
| Same, verifier warm | 620k (588k–659k) | 103k (102k–104k) |
| Transaction calling `verify` (anvil receipt) | **766k** (735k–806k) | 187k (186k–187k) |
| of which 21,000 + calldata + execution | 21,000 + 127k (8,132 B) + 618k | 21,000 + 63k (4,132 B) + 102k |
| EIP-7623 floor | 339k: doesn't apply | 180k: doesn't apply |
| With EIP-7976, as decisions.md models it (64 gas per calldata byte) | 766k: the floor (541k) doesn't apply | **285k: the floor applies** |
| Minimal owner's `isValidSignature`, owner and verifier cold | **629k** (596k–667k), 16 signatures | 111k, 1 |
| Runtime code | 4,360 B | 6,455 B |
| Deployment (Prague, measured) | 0.99M gas | 1.44M gas |
| Deployment under Glamsterdam (decisions.md's EIP-8037 model, estimate) | about 7.0M | about 10.2M |

- **Gas per precompile call:** a verification costs 97.0k + 246.2 gas per SHA-256 call (128s, 18 signatures, every
  residual under 710 gas). F and H are 102- and 118-byte inputs, four words each: 60 + 12 × 4 = 108 gas for the
  precompile plus 100 for the warm STATICCALL. The remaining 38 gas per call is the verifier's own work (setting the
  next hash address, the call's arguments). T_len costs 312 + 100, T_k 180 + 100, H_msg's two calls 96 + 100 each.
- **The spread:** the number of hash calls depends on the WOTS+ digits, so the gas does too, by about ±40k for 128s
  (p1–p99, modelled from 200,000 random digests with tools/fips205.py). A 4337 bundler or a Safe relayer must estimate
  with the real signature. The theoretical extremes (every digit 15, every digit 0) are 570 and 3,825 calls, about
  0.24M and 1.04M gas by the model.
- **Call counts are checked twice:** the Python reference counts them, and a Forge trace of one verification shows the
  same 2,040 calls (2,030 F/H at 108 gas, seven T_35 at 312, one T_14 at 180, two H_msg at 96).

### Against Winterlock's keys

Per signature, the owner's or validator's check and the signature's calldata at 16 gas per byte (most bytes are
nonzero). The WOTS, leanSphincs-keccak and ECDSA rows are decisions.md's figures, not re-measured.

| Signature | Check (cold) | Calldata | Together | Against leanSphincs-keccak |
|---|---|---|---|---|
| **SLH-DSA-SHA2-128s**, minimal owner | 629k | 7,856 B, about 126k | **about 755k** | 4.7× |
| SLH-DSA-SHA2-128-24 (DRAFT), minimal owner | 111k | 3,856 B, about 62k | about 173k | 1.1× |
| leanSphincs-keccak, validator's ERC-1271 1-of-1 | 69,052 | 5,749 B, about 92k | about 161k | 1 |
| WOTS (D6), owner v2's check of a SafeTx, first in a transaction | 71,005 | 1,758 B, about 28k | about 99k | 0.6× |
| ECDSA | about 6k | 65 B | about 7k | 0.04× |

- **The check alone:** 128s is 9.1× leanSphincs-keccak's 69k and about 100× ECDSA.
- **A Safe 2-of-3 transfer with all-SLH-DSA owners** would cost about 1.5–1.6M gas, against 257,760 for owner v2 with
  WOTS (v1.4.1). Estimate: replace v2's two WOTS checks and their calldata with two SLH-DSA checks and theirs. Not
  measured end to end.
- **The minimal owner** (`src/SlhDsaOwner.sol`) calls a shared verifier with the key in its code, as WinterlockOwner v2
  calls its stateless verifier. It binds the hash to no Safe, chain or owner; WinterlockOwner's message digest would add
  a few hundred gas.

### Signing time for SLH-DSA-SHA2-128s

| Where | Time per signature | Status |
|---|---|---|
| RustCrypto slh-dsa 0.2.0-rc.5, native, one thread (Ryzen 5 2600, SHA-NI) | **217 ms** median, 179 ms best (n = 15); key 32 ms; verify 0.37 ms | measured |
| The same crate compiled to wasm32, under Node 24 | **1.28 s** median, 1.06 s best (n = 9); key 0.19 s | measured |
| noble post-quantum 0.7.1, under Node 24 | 4.0 s median, 3.0 s best (n = 7); key 0.64 s | measured |
| ESP32 (240 MHz), SHA-256 hardware accelerator | **about 10 s** or more | estimate |
| ESP32, software SHA-256, one core | about 65 s or more | estimate |

- **The machine was busy** (load average 11 to 14 on 12 threads), as on 2026-11-07. Medians and best runs are given;
  the ratios matter more than the absolute times.
- **The work:** 2,185,898 hash calls per signature: FIPS 205 rebuilds 14 FORS trees of 4,096 leaves and seven XMSS
  trees of 512 leaves. That is 2,218,149 SHA-256 compressions if the signer keeps PK.seed's midstate (RustCrypto
  does), 4,404,044 if it doesn't. Counted by tools/fips205.py for a 32-byte message. For scale, a leanSphincs-keccak
  signature takes 141,974 Keccak-f permutations on average (`hardware/esp32-bench/README.md`).
- **The ESP32 estimate** multiplies those counts by Oryx Embedded's ESP32 figures (CycloneCRYPTO 2.5.0, GCC -O3,
  240 MHz): 27.777 MB/s with the SHA accelerator, 2.173 MB/s in software, so 2.30 µs and 29.5 µs per 64-byte block.
  - With the accelerator, 4.40M blocks give about 10 s. ESP-IDF's driver for the classic ESP32 can read a digest state
    out but falls back to software to continue one, which suggests the engine can't start from a saved midstate, so
    each F is two blocks. With a midstate it would be about 5 s.
  - In software with a midstate, 2.22M blocks give about 65 s on one core; much of it splits across both.
  - Both are lower bounds: bulk throughput leaves out each hash's own start and read-out. The board hasn't run it.
- **The draft set** needs about 1.45 billion hashes for a key and its first signature (a 2^22-leaf XMSS tree, six FORS
  trees of 2^24 leaves), 302 million per further signature if the signer keeps the tree (128 MB). tools/draft.py took
  196 s for the key and 62–71 s per signature on 12 processes here. No library signs it; at RustCrypto's native rate
  (about 82 ns per hash) one signature would take about 25 s with the tree kept and 2 minutes without (estimate).
  Unusable in a browser or on a board.

## How the verifier works

`src/SlhDsaSha2_128s.sol` and `src/SlhDsaSha2_128_24_DRAFT.sol` are rendered from one template,
`tools/SlhDsaSha2Verifier.sol.in`, by `tools/gen.py`. The parameter block at the top of each is the only difference
that matters; gen.py computes it with FIPS 205's formulas (`tools/fips205.py`, `Params`).

- **Interface:** `verify(pk, message, signature)` is FIPS 205's Algorithm 24 (pure SLH-DSA) with an empty context,
  M' = 0x00 ‖ 0x00 ‖ M. `verifyWithContext(pk, ctx, message, signature)` takes a context of up to 255 bytes, and
  `verifyInternal(pk, M', signature)` is Algorithm 20 (for ACVP's internal-interface vectors). Wrong lengths and long
  contexts return false.
- **Hashes:** F, H and T_l are SHA-256 over PK.seed padded to a 64-byte block, the 22-byte compressed address ADRSc and
  the input (section 11.2.1); H_msg is MGF1-SHA-256 over R ‖ PK.seed ‖ SHA-256(R ‖ PK.seed ‖ PK.root ‖ M'). Every
  hash is a STATICCALL to precompile 0x02.
- **Memory:** two fixed buffers hold PK.seed's block and ADRSc. Each precompile call writes its output where the next
  call reads it: the next chain step's input, the free half of the next H, or the slot in T_len's input. Only a layer's
  root is read back onto the stack. ADRSc changes with one MSTORE8 per chain step, and an H step writes the address and
  the authentication node with one or two MSTOREs.
- **Unrolled:** each WOTS+ chain runs as straight-line blocks of 8, 4, 2 and 1 steps, chosen by the bits of its
  length, and the FORS and XMSS authentication paths are unrolled. That took 128s from 705k to 632k; via-IR (as the
  repository compiles its vendored stateless verifier) another 1.4%, to 623k. The draft set went from 131k to 106k.
- **Precompile calls aren't checked for success.** SHA-256 fails only by running out of gas. A call gets all but
  1/64 of the remaining gas, so a failing call leaves at most about 1/63 of its own price: 4 gas after F, H or a 128s
  T_l (at most 312), 7 after the draft's T_68 (504). The code after any call needs more than that to reach RETURN.
  H_msg's first call grows with the message, but whatever it leaves is far below the 100k the rest of the verification
  needs. `test_outOfGasNeverAnswers` sweeps every gas limit in the 1,500 below the least a valid signature needs: each
  one reverts. Checking every call would cost 16 gas per call, 34k per verification.
- **The midstate idea doesn't pay.** The precompile can't resume from PK.seed's midstate, so every call hashes that
  block again. One SHA-256 compression in EVM code (straightforward Yul, `test/utils/Sha256Evm.sol`) costs 50,174 gas,
  against 208 for the precompile's whole two-block F call. An unrolled implementation might be several times cheaper
  and would still lose by two orders of magnitude.

## Correctness

| Source | 128s cases | Valid | Invalid |
|---|---|---|---|
| NIST ACVP, `SLH-DSA-sigVer-FIPS205`: every SHA2-128s case of the external/pure interface (with contexts) and the internal interface | 28 | 4 | 24: modified R, SIG_FORS, SIG_HT and message, signatures too long and too short |
| NIST ACVP, `SLH-DSA-sigGen-FIPS205`: the same groups' signatures, deterministic and randomized | 28 | 28 | |
| noble post-quantum 0.7.1: fresh keys; hedged and deterministic; contexts of 0, 10 and 255 bytes; empty and 1,000-byte messages; the internal interface | 10 | 5 | 5: another message, context, key; no context; a pure signature checked as internal |
| RustCrypto slh-dsa 0.2.0-rc.5: the same kinds, a 16-byte context, a flipped bit | 9 | 5 | 4 |
| noble, for the gas benchmark: 16 hedged signatures over 32-byte hashes | 16 | 16 | |

- **Every verdict agrees,** and for each pure-interface case the three entry points agree (`test_acvp`, `test_noble`,
  `test_rustcrypto`).
- **Mutations:** in each of the 42 valid ACVP, noble and RustCrypto signatures, one bit flipped in R (two places),
  every FORS tree's secret and one of its authentication nodes, every hypertree layer's WOTS+ signature and one of its
  authentication nodes, and the last byte; the message changed and lengthened; PK.seed and PK.root changed; the
  context changed, added or dropped; the pure signature checked as internal. All 2,145 variants are refused
  (`test_mutations`).
- **Malformed input:** a signature one byte short, one byte long or empty, a key of 31, 33 or 0 bytes, another key,
  another key's signature and a 256-byte context are all false, not reverts (`test_malformed`).
- **The Python reference** (`tools/fips205.py`, written from FIPS 205 for this benchmark) agrees with all 56 ACVP
  verdicts, re-signs ACVP's, noble's and RustCrypto's signatures byte for byte, and recomputes noble's and
  RustCrypto's public keys from their seeds (`tools/check_reference.py`).

**The DRAFT set, SLH-DSA-SHA2-128-24.** ACVP, noble 0.7.1 and RustCrypto slh-dsa cover only FIPS 205's twelve sets, so
there is no independent known answer.
- **Internal consistency only:** `fixtures/draft-sha2-128-24.json` holds a key and three signatures from the Python
  reference (empty and 255-byte contexts, deterministic and randomized). The verifier accepts them; that shows the two
  read FIPS 205 alike at the draft's parameters, not that either is right. The reference's code paths are the ones
  checked on 128s; the draft adds lg w = 2, len2 = 4, a checksum shift of 0, d = 1 and key-pair addresses above 2^16.
- **Another implementation, not a standard source:** SPHINCs- (Nicolas Consigny) signs this set with adaptations of
  the sphincsplus C reference, of noble and of a GPU signer. Its two known answers verify here, and the Python reference
  re-creates their public key from the seeds and both signatures byte for byte (`python3 tools/draft.py
  sphincs-minus`). SPHINCs-' own verifier also accepts this reference's signature.
- **Mutations and malformed input** as for 128s: 121 variants of 5 signatures refused, 9 malformed inputs false.
- **The parameters, checked with FIPS 205's formulas** (`python3 tools/fips205.py params`): len1 = 8n / lg w = 64,
  len2 = ⌊log2(len1 (w − 1)) / lg w⌋ + 1 = ⌊log2 192 / 2⌋ + 1 = 4, len = 68; m = ⌈k a / 8⌉ + ⌈(h − h') / 8⌉ +
  ⌈h' / 8⌉ = 18 + 0 + 3 = 21; signature = (1 + k (1 + a) + h + d len) n = (1 + 150 + 22 + 68) × 16 = 3,856 bytes.
  All match the draft's stated values.

## Prior art

Searched on GitHub and the web on 2026-11-09. Measured here: the same signatures, the same compiler settings as this
verifier (solc 0.8.28, via-IR, 1,000,000 optimizer runs) unless noted, verifier cold, called from a contract.

| Project | Licence | Sets | Interface | Hashes | Claimed | Measured here |
|---|---|---|---|---|---|---|
| [skalenetwork/slhdsa-solidity](https://github.com/skalenetwork/slhdsa-solidity) (`30b9d8b`, 2026-10-08) | MIT | the six SHA2 sets | FIPS 205 final: pure with contexts, and internal; its README reports every ACVP case passing | SHA-256 precompile; SHA-512 in EVM code for categories 3 and 5 | 2.0M (128s) | 128s: 1.83M (1.75M–1.93M, 16 signatures); 1.98M with its own optimizer setting (200 runs, solc 0.8.28 instead of its 0.8.37) |
| [SHLOK333/Kyvanta](https://github.com/SHLOK333/Kyvanta) (`f360909`, 2026-07-27) | "MIT OR Apache-2.0" in its README and SPDX header, no licence file | 128s | FIPS 205's internal interface over a `bytes32` (no M', no context) | SHA-256 precompile, "deliberately not optimised" | 2,156,760 execution | 2.13M–2.19M (two internal-interface signatures) |
| [nconsigny/SPHINCS-](https://github.com/nconsigny/SPHINCS-) `src/sha/SLH-DSA-SHA2-128-24verifier.sol` (`4c76aaf`) | MIT | SLH-DSA-SHA2-128-24 (draft) only | FIPS 205 pure, empty context, `bytes32` message | SHA-256 precompile | about 142k | 141k–143k (three signatures); this verifier: 105k–107k |
| [blocq-inc/sphincsplus-verify-sol](https://github.com/blocq-inc/sphincsplus-verify-sol) (2024-09) | none | SPHINCS+ (ported from a Go round-3 implementation) | pre-FIPS 205 | SHA-256 | none; its README says the tests fail on gas | not measured |
| ZKNox (48 public repositories) | | | | | | no SLH-DSA verifier; its EVM verifiers are ML-DSA (ETHDILITHIUM) and Falcon (ETHFALCON) |
| poqeth (Kysil, Seres, Kutas, Kelecsényi, ePrint 2025/091) | | SPHINCS+ among four schemes | | | no figures in the abstract | not examined |

- **Skale's is the only other FIPS 205 verifier for 128s with a compatible licence and the external interface.**
  Measured on the same 16 signatures it costs 2.9 times as much as this one (1.83M against 623k), so this benchmark
  uses its own. It makes the same hash calls; the difference is the Solidity around each one (function calls, a
  memory struct, the address rebuilt and compressed for every hash).
- **The paper estimate** of about 2,100 SHA-256 calls and 0.7–0.9M gas was right about the calls (2,125 on average)
  and high on the gas: 623k for the verification. A whole transaction calling the verifier costs 766k.

## Running it

```sh
cd contracts/bench/slh-dsa
forge test -vv                   # correctness and gas; a Foundry project of its own (foundry.toml)
./gas.sh                         # whole transactions on anvil (HARDFORK=osaka ./gas.sh for Osaka)
python3 tools/check_reference.py # the Python reference against ACVP, noble and RustCrypto (about a minute)
python3 tools/gen.py --check     # src/ matches the template
```

Regenerating the known answers and the timings:

```sh
python3 -I tools/acvp.py <sigVer internalProjection.json> <sigGen internalProjection.json> \
  > fixtures/acvp-sha2-128s.json
(cd tools/noble && npm ci --ignore-scripts && npm run vectors && npm run gas-vectors && npm run bench)
(cd tools/rust && cargo run --release -- vectors > ../../fixtures/rustcrypto-sha2-128s.json \
  && cargo run --release -- bench 15)
(cd tools/rust && cargo build --release --lib --target wasm32-unknown-unknown \
  && wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/slh_dsa_bench.wasm \
  && node wasm-bench.mjs 9)
python3 tools/draft.py > fixtures/draft-sha2-128-24.json   # about 1.5 billion hashes, minutes on all cores
python3 tools/draft.py sphincs-minus                        # re-creates SPHINCs-' known answers, about 7 minutes
```

The ACVP files are `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json` and
`SLH-DSA-sigGen-FIPS205/internalProjection.json` of usnistgov/ACVP-Server at `975de31` (SHA-256 `a013fc21…` and
`62b42e7c…`). Fresh noble and RustCrypto runs make new random keys, so their fixtures change; the committed ones are
what the tests check.

## Files

| Path | What it is |
|---|---|
| `src/SlhDsaSha2_128s.sol`, `src/SlhDsaSha2_128_24_DRAFT.sol` | the verifiers, generated |
| `src/ISlhDsaVerifier.sol` | their entry points |
| `src/SlhDsaOwner.sol` | the minimal ERC-1271 owner |
| `test/SlhDsaSha2_128s.t.sol`, `test/SlhDsaSha2_128_24_DRAFT.t.sol`, `test/SlhDsaTest.sol` | known answers, mutations, malformed input |
| `test/SlhDsaGas.t.sol` | gas, code size, the out-of-gas sweep |
| `test/Sha256Midstate.t.sol`, `test/utils/Sha256Evm.sol` | one SHA-256 compression in EVM code |
| `gas.sh`, `tools/txgas.py` | whole transactions on anvil |
| `tools/SlhDsaSha2Verifier.sol.in`, `tools/gen.py` | the template and its renderer |
| `tools/fips205.py` | the Python reference (FIPS 205, SHA2 at category 1) |
| `tools/check_reference.py` | the reference against the independent sources |
| `tools/acvp.py`, `tools/draft.py` | the ACVP extract; the draft set's key and signatures |
| `tools/noble/`, `tools/rust/` | known answers and signing times from noble and RustCrypto, each with its lock file |
| `fixtures/` | the known answers (below) |

## Sources and licences

- **FIPS 205** (SLH-DSA, August 2024) and **NIST SP 800-230** (initial public draft): the specifications.
- **NIST ACVP-Server** (`fixtures/acvp-sha2-128s.json`): test vectors published by NIST, a US government work.
- **noble post-quantum** 0.7.1 (Paul Miller, MIT): `fixtures/noble-sha2-128s*.json`, generated by `tools/noble/`.
- **RustCrypto slh-dsa** 0.2.0-rc.5 (Apache-2.0 OR MIT): `fixtures/rustcrypto-sha2-128s.json`, generated by
  `tools/rust/`.
- **SPHINCs-** (Nicolas Consigny, MIT) at `4c76aaf`: the two SLH-DSA-SHA2-128-24 known answers in
  `fixtures/sphincs-minus-sha2-128-24.json`, copied from `test/SLH-DSA-SHA2-128-24-KAT.t.sol` and
  `signers/slhvk-sha2-128-24/kat-counter0.json`.
- **Oryx Embedded**, crypto benchmark on the ESP32 (CycloneCRYPTO 2.5.0): the SHA-256 throughputs behind the ESP32
  estimate.
- The prior-art verifiers were compiled and run in a scratch directory, not copied here.
