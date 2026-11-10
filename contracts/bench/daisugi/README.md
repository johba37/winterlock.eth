# Winterlock on Daisugi (EIP-8141)

[Daisugi](https://daisugi.fyi) (chain 1337) is a public test network for post-quantum accounts. It runs Nethermind's EIP-8141 prototype (branch `daisugi/devnet-handoff`), and its RPC accepts frame transactions (type 0x06) only.

This folder sends frame transactions from native accounts that Winterlock keys guard:
- **v0** (`frame/WinterlockFrameAccount.yul`): the member key signs every transaction.
- **v1** (`frame/WinterlockFrameAccountV1.yul`): the member key enrols a tree of one-time WOTS keys, bound to the nonce, and those sign the transactions.
- **v2** (`frame/WinterlockFrameAccountV2.yul`): device keys, as in owner v2. The member key adds and revokes devices 1–3, and each device enrols and signs from its own tree (`devices.py`).

Results: decisions.md, the 2026-11-08 entries on Daisugi.

Test network only. The contracts are not audited.

```sh
cd contracts
forge build                                   # the verifiers
frame/build.sh --check                        # the frame accounts' pinned creation code matches the Yul sources
PY="../signer/.venv/bin/python -I"
$PY bench/daisugi/daisugi.py vector           # the encoder against Daisugi transactions (vectors.json); offline
export DAISUGI_DIR=/some/scratch/dir          # throwaway phrase, tree secrets, key log: keep it out of the repository
$PY bench/daisugi/daisugi.py deploy           # both verifiers and v0–v2 (CREATE2; skips what exists)
$PY bench/daisugi/daisugi.py member           # make the throwaway member, print its v1 account and tree
$PY bench/daisugi/daisugi.py fund             # 1 test ETH from the faucet, to the account's address
$PY bench/daisugi/daisugi.py enroll           # a tree of height 10 (512 nonces); deploys the account too
$PY bench/daisugi/daisugi.py send             # a one-time key while the tree covers the nonce, else the member key
$PY bench/daisugi/daisugi.py attacks          # signatures the account must refuse
$PY bench/daisugi/daisugi.py replace          # slot 1 for a replacement; the key log refuses a third version
$PY bench/daisugi/devices.py demo             # v2: add devices, enrol, sign, same nonce, revoke, re-add (checked)
$PY bench/daisugi/devices.py status           # v2: devices, generations, trees
$PY bench/daisugi/devices.py send --as 2      # v2: a transfer signed by device 2
```

- **`--account v0`** runs `member`, `fund` and `send` against the v0 account. `devices.py` works on the v2 account. Each device has a home in `$DAISUGI_DIR/device-N/` with its own seed (no phrase), trees and key log.
- **`send --member`** forces the member key.
- **`deploy`** signs with `DAISUGI_DEPLOYER_KEY` from `bench/bundlers/.env`. That's an ordinary key, whose frame transactions pass through EIP-8141's default code with a SECP256K1 signature entry. The faucet funds it.
- **The tool reuses the signer's Python** for the member key (`member.stateless_key`), leanSphincs, WOTS (`wots.Tree`, `wots.sign`) and secp256k1.
- **The key log** (`$DAISUGI_DIR/keylog.json`) records each one-time key, and syncs it to disk, before the key signs.
- **Reading the stored tree:** Daisugi's public RPC has neither `eth_getStorageAt` nor state overrides. The tool reads the latest `Enrolled` event from the first enrolment block it recorded (`enrolments.json`).
- **Fees:** 1 gwei priority, as Daisugi's own transactions pay; the base fee is a few wei.

## The encoding

Checked against Daisugi's transactions (`vector`):

```text
payload   = [chain_id, nonce, sender, frames, signatures,
             [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas], blob_versioned_hashes]
frame     = [mode, flags, target, [execution_gas, state_gas], value, data]
signature = [scheme, signer (address or empty), msg (empty or 32 bytes), signature]
tx hash   = keccak(0x06 ‖ rlp(payload))
sig hash  = the same, with the signature bytes of every empty-msg entry replaced by empty bytes
```

Two things differ from the EIP's text: the fees are per gas, and the signature hash drops the elided bytes instead of committing to their length.

## Limits the node enforces

- **State gas:** frames up to and including VERIFY may reserve at most 500,000 state gas (`MAX_VERIFY_STATE_GAS`). A deployment frame asks for 450,000.
- **Execution gas:** the EIP's public mempool also caps that prefix at 100,000 execution gas, counting the signatures' intrinsic cost. Daisugi doesn't enforce this one. Our VERIFY frames reserve 75,100.
- **`eth_getLogs`:** at most 10,000 blocks per request.
