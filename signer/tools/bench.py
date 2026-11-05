#!/usr/bin/env python3
"""Signing speed of the native signer: WOTS (D6) and leanSphincs signatures, operation tree and stateless key
generation. usage: signer/.venv/bin/python signer/tools/bench.py [--workers N]"""
import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from winterlock_signer import keccak, leansphincs, wots  # noqa: E402


def timed(f, *a, **kw):
    t0 = time.perf_counter()
    r = f(*a, **kw)
    return r, time.perf_counter() - t0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--workers", type=int, default=os.cpu_count())
    a = p.parse_args()
    print(f"keccak backend {keccak.BACKEND}, {a.workers} worker processes for key generation ({os.cpu_count()} CPUs)")
    seed, sk = 0x1234, keccak.keccak256(b"bench")
    _, t = timed(wots.leaf, seed, sk, 0, wots.Prf.SIGNER)
    print(f"WOTS one-time key (leaf): {t * 1e3:.1f} ms")
    ts = [timed(wots.sign, seed, sk, i, keccak.keccak256(b"%d" % i), wots.Prf.SIGNER)[1] for i in range(20)]
    print(f"WOTS signature: median {statistics.median(ts) * 1e3:.1f} ms, max {max(ts) * 1e3:.1f} ms (20 signatures)")
    for h in (6, 10, 12):
        _, t1 = timed(wots.Tree.create, seed, sk, h, workers=a.workers)
        print(f"operation tree height {h} ({1 << (h - 1):,} nonces, {1 << h:,} keys): {t1:.2f} s"
              + (f"; one process {timed(wots.Tree.create, seed, sk, h, workers=1)[1]:.2f} s" if h <= 10 else ""))
    key, t = timed(leansphincs.Key, keccak.keccak256(b"stateless"), 10, workers=a.workers)
    print(f"leanSphincs keygen, kept subtree 10: {t:.2f} s; one process "
          f"{timed(leansphincs.Key, keccak.keccak256(b'stateless'), 10, workers=1)[1]:.2f} s")
    ts = [timed(key.sign, keccak.keccak256(b"m%d" % i))[1] for i in range(10)]
    print(f"leanSphincs signature: median {statistics.median(ts):.2f} s, min {min(ts):.2f}, max {max(ts):.2f} "
          f"(10 signatures; the randomizer grind varies)")
    sig = key.sign(keccak.keccak256(b"v"))
    _, t = timed(leansphincs.verify, key.public_key, keccak.keccak256(b"v"), sig)
    print(f"leanSphincs verification (the signer's own check): {t * 1e3:.1f} ms")


if __name__ == "__main__":
    main()
