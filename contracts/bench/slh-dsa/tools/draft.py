#!/usr/bin/env python3
"""Keys and signatures for the DRAFT parameter set SLH-DSA-SHA2-128-24 (NIST SP 800-230 ipd), from the Python
reference fips205.py: fixtures/draft-sha2-128-24.json.

    python3 tools/draft.py > fixtures/draft-sha2-128-24.json    # about 1.5 billion hashes; JOBS=<n> sets the workers
    python3 tools/draft.py sphincs-minus                        # re-create SPHINCs-' known answers (below)

NOT INDEPENDENT. No independent implementation of this draft set exists to compare with (noble 0.7.1, RustCrypto
slh-dsa and ACVP cover FIPS 205's twelve sets only), so these vectors only show that the Solidity verifier and this
Python reference read FIPS 205 the same way at the draft's parameters. The reference itself is checked against ACVP,
noble and RustCrypto on SLH-DSA-SHA2-128s (check_reference.py).

The key's single XMSS tree (2^22 leaves) is computed once and kept, so each signature only recomputes its six FORS
trees (2^24 leaves each). Every signature is checked with the reference's verifier before it is written.

`sphincs-minus` recomputes the public key of fixtures/sphincs-minus-sha2-128-24.json from its seeds and re-signs its
two messages: Nicolas Consigny's signers for this draft set (adaptations of the sphincsplus C reference and of noble)
against this reference, byte for byte. Another implementation, not an independent standard source.
"""
import hashlib
import json
import os
import sys
import time
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fips205 as f  # noqa: E402

P = f.SHA2_128_24_DRAFT
CHUNK = 14  # 2^14 leaves per task


def seed(label):
    return hashlib.sha256(f"winterlock/bench/slh-dsa/draft-128-24/{label}".encode()).digest()[: P.n]


def _chunk(args):
    pk_seed, sk_seed, first = args
    leaves, *_ = f._leaves(P, pk_seed, sk_seed, bytes(f.Adrs().b), "xmss", first, 1 << CHUNK)
    return b"".join(leaves)


def xmss_levels(pk_seed, sk_seed):
    """Every level of the key's XMSS tree (layer 0, tree 0), each as one byte string."""
    tasks = [(pk_seed, sk_seed, c << CHUNK) for c in range(1 << (P.hp - CHUNK))]
    with Pool(int(os.environ.get("JOBS", os.cpu_count()))) as pool:
        level = b"".join(pool.map(_chunk, tasks))
    blk = hashlib.sha256(pk_seed + bytes(64 - P.n))
    pre = bytes(9) + bytes([f.TREE]) + bytes(4)
    levels = [level]
    for z in range(1, P.hp + 1):
        nxt = bytearray()
        for i in range(len(level) // 32):
            s = blk.copy()
            s.update(pre + z.to_bytes(4, "big") + i.to_bytes(4, "big") + level[32 * i:32 * i + 32])
            nxt += s.digest()[: P.n]
        level = bytes(nxt)
        levels.append(level)
    return levels


def sign(m_prime, sk, levels, addrnd=None):
    """Algorithm 19, with Algorithm 12 for d = 1: one XMSS signature whose auth path is read from the kept tree."""
    n = P.n
    sk_seed, sk_prf, pk_seed, pk_root = sk[:n], sk[n:2 * n], sk[2 * n:3 * n], sk[3 * n:]
    hs = f.Hashes(P, pk_seed)
    r = f.prf_msg(P, sk_prf, pk_seed if addrnd is None else addrnd, m_prime)
    md, idx_tree, idx_leaf = f.split_digest(P, f.h_msg(P, r, pk_seed, pk_root, m_prime))
    assert idx_tree == 0
    adrs = f.Adrs()
    adrs.set_type_and_clear(f.FORS_TREE)
    adrs.set_key_pair(idx_leaf)
    sig_fors = f.fors_sign(hs, md, sk_seed, adrs)
    pk_fors = f.fors_pk_from_sig(hs, sig_fors, md, adrs)
    adrs = f.Adrs()
    adrs.set_type_and_clear(f.WOTS_HASH)
    adrs.set_key_pair(idx_leaf)
    auth = b"".join(levels[j][16 * ((idx_leaf >> j) ^ 1):16 * ((idx_leaf >> j) ^ 1) + 16] for j in range(P.hp))
    return r + sig_fors + f.wots_sign(hs, pk_fors, sk_seed, adrs) + auth, idx_leaf


def main():
    t0 = time.time()
    sk_seed, sk_prf, pk_seed = seed("sk-seed"), seed("sk-prf"), seed("pk-seed")
    levels = xmss_levels(pk_seed, sk_seed)
    root = levels[-1]
    pk, sk = pk_seed + root, sk_seed + sk_prf + pk_seed + root
    print(f"key: {time.time() - t0:.0f} s", file=sys.stderr)
    cases = [
        ("a 32-byte hash, empty context, deterministic", hashlib.sha256(b"draft 1").digest(), b"", None),
        ("a 100-byte message, a context, deterministic", hashlib.sha256(b"draft 2").digest() * 3 + b"tail",
         b"winterlock", None),
        ("an empty message, a 255-byte context, randomized", b"", bytes(range(255)), seed("addrnd")),
    ]
    vectors = []
    for reason, m, ctx, addrnd in cases:
        t = time.time()
        for key in f.COUNT:
            f.COUNT[key] = 0
        sig, idx_leaf = sign(f.wrap(m, ctx), sk, levels, addrnd)
        counts = dict(f.COUNT)
        assert len(sig) == P.sig_bytes
        assert f.verify(P, m, sig, ctx, pk), reason
        assert not f.verify(P, m + b"x", sig, ctx, pk)
        print(f"{reason}: {time.time() - t:.0f} s, leaf {idx_leaf}, {counts}", file=sys.stderr)
        vectors.append({
            "source": "tools/fips205.py (own reference, NOT independent)",
            "internal": False,
            "pk": "0x" + pk.hex(),
            "message": "0x" + m.hex(),
            "context": "0x" + ctx.hex(),
            "signature": "0x" + sig.hex(),
            "valid": True,
            "reason": reason,
        })
    json.dump({
        "source": "tools/draft.py: the Python reference written from FIPS 205; internal consistency only, NOT an "
                  "independent known answer",
        "parameterSet": "SLH-DSA-SHA2-128-24, DRAFT (NIST SP 800-230 ipd): n=16 h=22 d=1 h'=22 a=24 k=6 lg w=2 m=21",
        "seeds": "SHA-256(\"winterlock/bench/slh-dsa/draft-128-24/\" + label)[:16], labels sk-seed, sk-prf, pk-seed",
        "vectors": vectors,
    }, sys.stdout, indent=1)
    print()


def sphincs_minus():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "sphincs-minus-sha2-128-24.json")
    vs = json.load(open(path))["vectors"]
    h = lambda x: bytes.fromhex(x[2:])  # noqa: E731
    sd = h(vs[0]["seed"])
    t = time.time()
    levels = xmss_levels(sd[32:], sd[:16])
    pk = sd[32:] + levels[-1]
    assert all(h(v["pk"]) == pk for v in vs), "public key"
    print(f"public key recomputed from the seeds ({time.time() - t:.0f} s)")
    for v in vs:
        t = time.time()
        sig, _ = sign(f.wrap(h(v["message"]), h(v["context"])), sd + levels[-1], levels, h(v["addrnd"]))
        assert sig == h(v["signature"]), v["reason"]
        assert f.verify(P, h(v["message"]), sig, h(v["context"]), pk)
        print(f"re-signed byte for byte ({time.time() - t:.0f} s): {v['reason']}")


if __name__ == "__main__":
    if sys.argv[1:] == ["sphincs-minus"]:
        sphincs_minus()
    else:
        main()
