#!/usr/bin/env python3
"""Known answers from the Python signer for the board signer's flows (hardware/board-signer/logic), which must match
them byte for byte: the seed from both sides' randomness, its words, member key, owner and gas key; the PIN's check
value; a key tree enrolled from a known salt and its certificate; and confirmations of an ETH transfer, a second version
at the same nonce (a USDC transfer), an approveHash of a parent Safe's transaction, and a call that isn't decoded.

The keys follow ERC-8499 as the signer app derives them (erc8499.py; decisions.md, D15): the root of the seed's words,
the member key, the tree's secret seed and the gas key. The board's own labels (the seed, the PIN) are computed here with
the signer's abi.encode helper, so the Python side states them too. Every input is a fixed public test value.

usage: signer/.venv/bin/python -I hardware/board-signer/tools/board_vectors.py [OUT]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, os.path.join(ROOT, "signer"))

from winterlock_signer import erc8499, leansphincs, member, owner, phrase, safe, wots  # noqa: E402
from winterlock_signer.abi import b2h, checksum  # noqa: E402
from winterlock_signer.keccak import keccak256  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(HERE), "logic", "tests", "vectors",
                                                         "board_flows.json")

SEED_LABEL = b"winterlock.board.seed.v1"
PIN_LABEL = b"winterlock.board.pin.v1"
CHAIN = 42161
USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"  # Circle's USDC on Arbitrum One (the board's token list)


def k(label: str) -> bytes:
    return keccak256(label.encode())


def addr(label: str) -> str:
    return checksum(k(label)[12:])


def safetx_json(t):
    return {"to": t.to, "value": str(t.value), "data": b2h(t.data), "operation": t.operation,
            "safe_tx_gas": str(t.safe_tx_gas), "base_gas": str(t.base_gas), "gas_price": str(t.gas_price),
            "gas_token": t.gas_token, "refund_receiver": t.refund_receiver, "nonce": str(t.nonce)}


def main():
    board_random, app_random = k("board vectors: board randomness"), k("board vectors: app randomness")
    seed = member._abi_label(SEED_LABEL, board_random, app_random)
    words = phrase.to_phrase(seed)
    root = erc8499.phrase_root(seed)
    key = erc8499.stateless_key(root)
    owner_addr = owner.owner_address(key.public_key)
    pin = [2, 0, 2, 6]
    pin_salt = k("board vectors: PIN salt")
    pin_check = member._abi_label(PIN_LABEL, pin_salt, bytes([len(pin)] + pin + [0] * (31 - len(pin))))

    safe_addr = addr("board vectors: Safe")
    parent_addr = addr("board vectors: parent Safe")
    bob = addr("board vectors: recipient")
    start = 7
    tree_salt = k("board vectors: tree salt")
    rec = {"chain": CHAIN, "owner": owner_addr, "safe": safe_addr, "device": 0, "gen": 0, "start": start,
           "salt": b2h(tree_salt)}
    sk = erc8499.tree_secret_seed(root, rec, 10)
    tseed = owner.tree_seed(CHAIN, owner_addr, safe_addr, 0, 0, start)
    tree = wots.Tree.create(tseed, sk, 10, workers=1)
    digest = owner.certificate_digest(CHAIN, owner_addr, safe_addr, 0, 0, tree.root, 10, start)
    cert = key.sign(digest)
    assert leansphincs.verify(key.public_key, digest, cert)

    parent = safe.SafeTx(to=bob, value=2 * 10**18, nonce=3)
    transfer = bytes.fromhex("a9059cbb") + bytes(12) + bytes.fromhex(bob[2:]) + (12_500_000).to_bytes(32, "big")
    cases = [
        ("eth", safe.SafeTx(to=bob, value=15 * 10**17, nonce=start), None),
        ("usdc, a second version at the same nonce", safe.SafeTx(to=USDC, data=transfer, nonce=start), None),
        ("approveHash of a parent's transfer",
         safe.SafeTx(to=parent_addr, data=bytes.fromhex("d4d9bdcd") + parent.hash(CHAIN, parent_addr), nonce=start + 1),
         parent),
        ("not decoded", safe.SafeTx(to=addr("board vectors: contract"), value=5, data=bytes.fromhex("12345678000102"),
                                    nonce=start + 2), None),
    ]
    used = {}
    txs = []
    for name, st, par in cases:
        h = st.hash(CHAIN, safe_addr)
        slot = used.get(st.nonce, 0)
        used[st.nonce] = slot + 1
        ki = owner.key_index(st.nonce, start, slot, 10)
        sig = wots.sign(tseed, sk, ki, h, wots.Prf.SIGNER)
        path = tree.path(ki)
        assert wots.verify_root(tseed, ki, h, sig, path) == tree.root
        txs.append({"name": name, "tx": safetx_json(st), "parent": safetx_json(par) if par else None,
                    "hash": b2h(h), "slot": slot, "key_index": ki,
                    "data": b2h(owner.tx_signature_data(slot, 0, safe_addr, st.words(), sig, path))})

    out = {
        "board_random": b2h(board_random), "app_random": b2h(app_random), "seed": b2h(seed),
        "words": " ".join(words), "member_key": b2h(key.public_key), "owner": owner_addr,
        "root": b2h(root), "gas_key": b2h(erc8499.gas_key(root)),
        "pin": pin, "pin_salt": b2h(pin_salt), "pin_check": b2h(pin_check),
        "chain": CHAIN, "safe": safe_addr, "start": start, "tree_salt": b2h(tree_salt), "tree_root": b2h(tree.root),
        "tree_sk_seed": b2h(sk),
        "certificate_digest": b2h(digest), "certificate": b2h(cert), "transactions": txs,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{OUT}: {os.path.getsize(OUT):,} bytes")


if __name__ == "__main__":
    main()
