#!/usr/bin/env python3
"""Checks the Python reference (fips205.py) against the independent sources, before it signs anything for the draft set.

    python3 tools/check_reference.py          # add --all to re-sign every ACVP sigGen case (about 5 minutes)

1. NIST ACVP (fixtures/acvp-sha2-128s.json): every verdict, and ACVP's signatures re-signed byte for byte from their
   secret keys (deterministic and with ACVP's additional randomness).
2. noble and RustCrypto (fixtures/noble-sha2-128s.json, fixtures/rustcrypto-sha2-128s.json): every verdict, every
   public key recomputed from its seeds, and their deterministic signatures re-signed byte for byte.
3. The fast tree walk that signs the draft set's large trees: the same roots, auth paths and leaves as FIPS 205's
   Algorithms 9 and 15, on SLH-DSA-SHA2-128s's trees and on leaves of the draft set.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fips205 as f  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "fixtures")


def h(s):
    return bytes.fromhex(s[2:])


def check_fixture(name, resign_all):
    path = os.path.join(FIX, name)
    if not os.path.exists(path):
        print(f"{name}: missing, skipped")
        return
    vs = json.load(open(path))["vectors"]
    resign = keys = 0
    for v in vs:
        p = f.SHA2_128S
        m, ctx, sig, pk = h(v["message"]), h(v["context"]), h(v["signature"]), h(v["pk"])
        got = f.verify_internal(p, m, sig, pk) if v["internal"] else f.verify(p, m, sig, ctx, pk)
        assert got == v["valid"], (v["source"], v.get("reason"))
        if "seed" in v:  # noble and RustCrypto record the key's seeds: SK.seed | SK.prf | PK.seed
            sd = h(v["seed"])
            sk, again_pk = f.keygen_internal(p, sd[:16], sd[16:32], sd[32:])
            assert again_pk == pk, ("keygen", v["source"])
            keys += 1
        else:
            sk = h(v["sk"])
        # ACVP's signatures with their randomness, the others' deterministic ones
        reproducible = "addrnd" in v or "deterministic" in v["reason"]
        if v["valid"] and reproducible and (resign_all or resign < 2 or "seed" in v):
            addrnd = h(v.get("addrnd", "0x")) or None
            again = f.sign_internal(p, m, sk, addrnd) if v["internal"] else f.sign(p, m, ctx, sk, addrnd)
            assert again == sig, ("re-signed", v["source"])
            resign += 1
    print(f"{name}: {len(vs)} verdicts agree ({sum(v['valid'] for v in vs)} valid), {resign} signatures re-signed "
          f"byte for byte" + (f", {keys} public keys recomputed from seeds" if keys else ""))


def check_tree_walk():
    p = f.SHA2_128S
    pk_seed, sk_seed = bytes(range(16)), bytes(range(16, 32))
    hs = f.Hashes(p, pk_seed)
    # an XMSS tree of the hypertree (layer 3, tree 5): root and auth path of leaf 300
    adrs = f.Adrs()
    adrs.set_layer(3)
    adrs.set_tree(5)
    root, auth = f.parallel_tree(hs, sk_seed, adrs.copy(), "xmss", p.hp, 300, split=3)
    assert root == f.xmss_node(hs, sk_seed, 0, p.hp, adrs.copy())
    assert auth == [f.xmss_node(hs, sk_seed, (300 >> j) ^ 1, j, adrs.copy()) for j in range(p.hp)]
    # FORS tree 9 of key pair 77 in hypertree tree 1234: root and auth path of leaf 1000
    adrs = f.Adrs()
    adrs.set_tree(1234)
    adrs.set_type_and_clear(f.FORS_TREE)
    adrs.set_key_pair(77)
    root, auth = f.parallel_tree(hs, sk_seed, adrs.copy(), "fors", p.a, 1000, offset=9 << p.a, split=4)
    assert root == f.fors_node(hs, sk_seed, 9, p.a, adrs.copy())
    assert auth == [f.fors_node(hs, sk_seed, ((9 << p.a) + 1000 >> j) ^ 1, j, adrs.copy()) for j in range(p.a)]
    # the draft set's leaves, which use other types, key pairs above 2^16 and w = 4
    d = f.SHA2_128_24_DRAFT
    hs = f.Hashes(d, pk_seed)
    adrs = f.Adrs()
    leaves, *_ = f._leaves(d, pk_seed, sk_seed, bytes(adrs.b), "xmss", (1 << 22) - 3, 3)
    assert leaves == [f.xmss_leaf(hs, sk_seed, (1 << 22) - 3 + j, adrs.copy()) for j in range(3)]
    adrs.set_type_and_clear(f.FORS_TREE)
    adrs.set_key_pair((1 << 22) - 1)
    leaves, *_ = f._leaves(d, pk_seed, sk_seed, bytes(adrs.b), "fors", (5 << 24) + 7, 3)
    assert leaves == [f.fors_leaf(hs, sk_seed, (5 << 24) + 7 + j, adrs.copy()) for j in range(3)]
    print("tree walk: the same roots, auth paths and leaves as Algorithms 6, 9, 14 and 15")


if __name__ == "__main__":
    resign_all = "--all" in sys.argv
    check_tree_walk()
    for name in ("acvp-sha2-128s.json", "noble-sha2-128s.json", "rustcrypto-sha2-128s.json"):
        check_fixture(name, resign_all)
