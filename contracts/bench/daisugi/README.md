# Winterlock on Daisugi (EIP-8141)

[Daisugi](https://daisugi.fyi) (chain 1337) is a public test network for post-quantum accounts. It runs Nethermind's EIP-8141 prototype (branch `daisugi/devnet-handoff`), and its RPC accepts frame transactions (type 0x06) only. This folder sends frame transactions from a native account that a Winterlock member key guards (`src/frame/WinterlockFrameAccount.yul`). Results: decisions.md, "2026-11-08: a member key guards a native frame-transaction account on Daisugi".

Test network only. The contracts are not audited.

```sh
cd contracts
forge build
PY="../signer/.venv/bin/python -I"
$PY bench/daisugi/daisugi.py vector          # the encoder against Daisugi transactions (vectors.json); offline
export DAISUGI_DIR=/some/scratch/dir         # a throwaway phrase goes here: keep it out of the repository
$PY bench/daisugi/daisugi.py deploy          # stateless verifier + account implementation (CREATE2; skips what exists)
$PY bench/daisugi/daisugi.py member          # make the throwaway member, print its account
$PY bench/daisugi/daisugi.py fund            # 1 test ETH from the faucet, to the account's address
$PY bench/daisugi/daisugi.py send            # deploy the account if needed, VERIFY with the member key, send 0.01 ETH to 0x…dEaD
```

- `deploy` signs with `DAISUGI_DEPLOYER_KEY` from `bench/bundlers/.env`: an ordinary key, whose frame transactions pass through EIP-8141's default code (a SECP256K1 signature entry). The faucet funds it.
- The tool uses the signer's Python for the member key (`member.stateless_key`), leanSphincs signing and secp256k1.
- Fees: 1 gwei priority, as Daisugi's own transactions pay; the base fee is a few wei.

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

- **State gas:** frames up to and including VERIFY may reserve at most 500,000 state gas (`MAX_VERIFY_STATE_GAS`). The first transaction's deployment frame asks for 450,000.
- **Execution gas:** the EIP's public mempool also caps that prefix at 100,000 execution gas, counting the signatures' intrinsic cost. Daisugi doesn't enforce this one. A later transaction from the account reserves 75,100.
