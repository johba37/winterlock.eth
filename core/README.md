# winterlock-core

The Python signer's cryptography and key rules in Rust, `no_std` with `alloc`, for the browser (WebAssembly), the ESP32 board and native tests. Python (`signer/winterlock_signer`) stays the reference: the tests read vectors that it writes and match them byte for byte. Design: `docs/notes/signer-app.md`, "The core".

## What's in

| Module | What | Python |
|---|---|---|
| `keccak` | keccak256: a small sponge over Keccak-f[1600] from `tiny-keccak` (default) or RustCrypto (`sha3` feature: the `keccak` crate that `sha3` is built on). With both features, `set_backend` picks one at run time. `count` counts permutations. | `keccak.py` |
| `phrase` | 24 BIP-39 words ↔ the 32-byte seed (entropy, SHA-256 checksum), the forgiving parser and its named errors, the pairing check code | `phrase.py`, `member.check_code` |
| `leansphincs` | pruned keys (b = 10 for members and devices), leaves over any range, a key from leaves, sign, verify | `leansphincs.py` |
| `wots` | D6: leaves over any range, trees and paths, the cache format, `verify_root`, signing only from a key log record | `wots.py` |
| `derive` | the member key, device keys, tree secret seeds | `member.py` |
| `owner` | v2: key indices, every digest, the three signature layouts and their parsers, owner addresses (pinned v2 contracts), signing a transaction, message, device certificate or revocation | `owner.py`, `messages.signature_data` |
| `safe` | SafeTx (fields in, 320-byte words, EIP-712 hash), SafeMessage, EIP-191 | `safe.py`, `messages.py`, `eip712.personal_hash` |
| `keylog` | the one-time key rules over a storage trait, and `MemoryLog`, a model of it | `keylog.py` (`pick_slot`, `record_sign`) |
| `u256`, `hex`, `abi` | amounts shown exactly, EIP-55 addresses, words, the labelled PRF, CREATE2 | `abi.py`, `safe.fmt_eth` |

Nothing inside is random, reads a clock or does I/O: seeds, tree salts and phrase entropy are parameters.

**Out:** RPC, Safe's Transaction Service, WalletConnect, EIP-712 typed data in general, screens, encryption at rest, the rest of the key log (identity, trees, certificates, device records, moves). These differ between the browser and the board.

## The key log's storage contract

The platform implements `keylog::KeyLogStore`: look up the hash that one-time key `k` of a tree (chain, Safe, root) signed, and append a use.

- `append_use` returns `Ok` only once the use is **durable**: written and flushed (an fsync, a committed IndexedDB transaction, a flash write read back).
- `keylog::record` (or `pick_slot`, then `record_sign`) checks the rules and appends. It returns a `Recorded`, and only a `Recorded` signs a one-time key (`wots::sign_recorded`, `owner::sign_transaction`). So the record exists before the signature does; a crash can lose a signature, never its record.
- The rules: a key signs one hash only; the same hash again returns the slot that signed it, without appending. Slot 0 first, slot 1 for a second, different hash at the nonce, then refused (`ThirdVersion`). A key that signed another hash is refused (`KeyReused`). A failing store refuses (`Store`).
- Stateless signatures have no one-time key. They count against the key's budget, so a platform records them before signing too, as the Python signer does.

## Testing

```sh
./check.sh          # all three targets
cargo test          # native only
```

`check.sh` runs the tests natively with each keccak backend, in WebAssembly under Node (`wasm32-unknown-unknown` and wasm-bindgen-cli 0.2.130 for `wasm-bindgen-test-runner`), and builds the crate for `xtensa-esp32-none-elf` (espup's toolchain, `cargo +esp`).

The vectors in `tests/vectors/` come from `signer/tools/core_vectors.py` (run it with the signer's virtualenv). The tests also check the upstream leanSphincs-keccak known answers (`contracts/test/fixtures/leansphincs-keccak-kat.json`) and derive the pinned contract addresses from `signer/winterlock_signer/contracts.json`.

`cargo run --release --example speed` times the operations natively, with the inputs of `signer/tools/bench.py`.

## Differences from Python

- **Fewer permutations, same outputs.** A WOTS randomizer and the leanSphincs WOTS+C counter absorb their constant first blocks once per signature, not once per try: 2 permutations per WOTS try instead of 3, 1 per WOTS+C try instead of 6.
- **Tree heights.** A tree with real leaves above height 20 is refused (the Python signer refuses those too, in `member.new_tree`, but `wots.Tree` allows 40).
- **Chain ids** are u64.
