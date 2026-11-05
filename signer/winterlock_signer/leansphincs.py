"""leanSphincs over keccak256: the member's stateless key (decisions D11, D12).

Parameters: n = 16, one XMSS layer of height 26, FORS with k = 24 trees of height a = 10 (no tree roots: the two
level-9 tops of each tree), WOTS+C with 64 chains of w = 4 (2-bit digits) and target sum 120; 5,684-byte signatures.
The construction is Tom Wambsgans' leanSphincs (keccak branch), as implemented in Nicolas Consigny's SPHINCs-
(MIT): its verifier is vendored in contracts/src/vendor/sphincs-minus/LeanSphincsAsm.sol, whose header documents
the spec. This file is a port of contracts/test/utils/StatelessSigner.sol, which was written from that spec, and
reproduces the upstream known answers (contracts/test/fixtures/leansphincs-keccak-kat.json) byte for byte.

Pruned keys: the signer keeps a subtree of height b of the 2^26 one-time leaves; the siblings above it are
pseudo-random surrogates, and a signature grinds the randomizer until its leaf index falls in the kept subtree
(about 2^(26 - b) digests). The verifier can't tell a pruned key from a full one. The kept-subtree height is part of
the key: the same seed with another b gives another public key.

Hash: Th(P, address, M) = keccak256(P ‖ address ‖ M)[0:16]. Address (16 bytes): lo as u32 little endian, hi as u24
little endian, t | step << 5, eight zero bytes.
"""

import os

from .keccak import keccak256 as _k

H = 26
K = 24
A = 10
V = 64
TARGET = 120
NB = 16
SIG_BYTES = 5684
DEFAULT_B = 10  # the Light tier (16 KiB of leaves): about 210k signatures at 128 bits (docs/decisions.md, D11)

PRF, CHAIN, LEAF, NODE, ENC, PARAMETER, RANDOMIZER = 0, 1, 2, 3, 4, 5, 7
FTS_PRF, FTS_LEAF, FTS_NODE, MSG, SURROGATE = 8, 9, 10, 12, 13

_Z8 = bytes(8)
_DIGIT_SUM = [(b & 3) + ((b >> 2) & 3) + ((b >> 4) & 3) + (b >> 6) for b in range(256)]


def addr(t: int, step: int, hi: int, lo: int) -> bytes:
    if not (t < 32 and step < 8 and hi < 1 << 24 and lo < 1 << 32):
        raise ValueError("address field out of range")
    return lo.to_bytes(4, "little") + hi.to_bytes(3, "little") + bytes([t | (step << 5)]) + _Z8


def th(p: bytes, a: bytes, payload: bytes) -> bytes:
    return _k(p + a + payload)[:NB]


def _node(p: bytes, level: int, j: int, left: bytes, right: bytes) -> bytes:
    return _k(p + addr(NODE, 0, level, j) + left + right)[:NB]


def _wots_leaf(p: bytes, seed: bytes, e: int) -> bytes:
    """The WOTS+C one-time public key at leaf e: 32 PRF calls give 64 chain secrets, each walked 3 steps"""
    k = _k
    lo = e.to_bytes(4, "little")
    ends = []
    for t in range(32):
        d = k(p + lo + bytes([t, 0, 0, PRF]) + _Z8 + seed)
        for half in (0, 1):
            i = 2 * t + half
            x = d[16 * half: 16 * half + 16]
            hi = bytes([i, 0, 0])
            for step in range(3):
                x = k(p + lo + hi + bytes([CHAIN | (step << 5)]) + _Z8 + x)[:NB]
            ends.append(x)
    return k(p + lo + bytes([0, 0, 0, LEAF]) + _Z8 + b"".join(ends))[:NB]


def _wots_leaves(args):
    p, seed, lo, hi = args
    return [_wots_leaf(p, seed, e) for e in range(lo, hi)]


class Key:
    """A leanSphincs key with a kept subtree of height b. Holds the secret seed."""

    def __init__(self, seed: bytes, b: int = DEFAULT_B, workers=None, kept_leaves=None):
        if len(seed) != 32 or not 0 <= b <= H:
            raise ValueError("seed must be 32 bytes and 0 <= b <= 26")
        self.seed, self.b = seed, b
        self.p = th(bytes(16), addr(PARAMETER, 0, 0, 0), seed)
        self.s = (int.from_bytes(self.p[:8], "little") & ((1 << (H - b)) - 1)) if b < H else 0
        first = self.s << b
        if kept_leaves is None:
            kept_leaves = _leaves(self.p, seed, first, 1 << b, workers)
        elif len(kept_leaves) != 1 << b:
            raise ValueError("kept leaves")
        self.levels = [list(kept_leaves)]
        for lvl in range(1, b + 1):
            below = self.levels[-1]
            off = self.s << (b - lvl)
            self.levels.append([_node(self.p, lvl, off + j, below[2 * j], below[2 * j + 1])
                                for j in range(len(below) // 2)])
        self.surrogates = []
        v = self.levels[b][0]
        for t in range(H - b):
            sib = th(self.p, addr(SURROGATE, 0, b + t, 0), seed)
            self.surrogates.append(sib)
            j = self.s >> t
            v = _node(self.p, b + t + 1, j >> 1, sib, v) if j & 1 else _node(self.p, b + t + 1, j >> 1, v, sib)
        self.root = v

    @property
    def public_key(self) -> bytes:
        """root ‖ P (32 bytes): WinterlockOwner's KEY"""
        return self.root + self.p

    def kept_leaves_bytes(self) -> bytes:
        return b"".join(self.levels[0])

    def sign(self, m: bytes) -> bytes:
        """Signs a 32-byte message; returns the 5,684-byte signature"""
        if len(m) != 32:
            raise ValueError("message must be 32 bytes")
        p, seed = self.p, self.seed
        rho, idx = self._grind(m)
        u = fors_indices(p, m, rho)
        out = [rho]
        lo = idx.to_bytes(4, "little")
        tops = []
        for kappa in range(K):
            sk, path, top0, top1 = self._fors_tree(lo, kappa, u[kappa])
            out.append(sk)
            out.extend(path)
            tops.append(top0 + top1)
        tops = b"".join(tops)
        c, x = _encode(p, lo, tops)
        out.append(c.to_bytes(4, "little"))
        k = _k
        for t in range(32):
            d = k(p + lo + bytes([t, 0, 0, PRF]) + _Z8 + seed)
            for half in (0, 1):
                i = 2 * t + half
                v = d[16 * half: 16 * half + 16]
                hi = bytes([i, 0, 0])
                for step in range(_digit(x, i)):
                    v = k(p + lo + hi + bytes([CHAIN | (step << 5)]) + _Z8 + v)[:NB]
                out.append(v)
        if idx >> self.b != self.s:
            raise AssertionError("leaf outside the kept subtree")
        local = idx - (self.s << self.b)
        for lvl in range(H):
            out.append(self.levels[lvl][(local >> lvl) ^ 1] if lvl < self.b else self.surrogates[lvl - self.b])
        sig = b"".join(out)
        assert len(sig) == SIG_BYTES
        return sig

    def _grind(self, m: bytes):
        """ρ = R_0 + i (u128 little endian) for the least i whose digest leaf index lies in the kept subtree"""
        r0 = th(self.p, addr(RANDOMIZER, 0, 0, 0), self.seed + m)
        r = int.from_bytes(r0, "little")
        prefix = self.p + addr(MSG, 0, 0, 0) + m
        b, s, k = self.b, self.s, _k
        mask = (1 << 128) - 1
        while True:
            rho = r.to_bytes(16, "little")
            d = k(prefix + rho)
            idx = d[16] | (d[17] << 8) | (d[18] << 16) | ((d[19] & 3) << 24)
            if idx >> b == s:
                return rho, idx
            r = (r + 1) & mask

    def _fors_tree(self, lo: bytes, kappa: int, uk: int):
        """FORS tree κ of the instance at leaf lo: the opened secret, its path (10 siblings) and the two tops"""
        p, seed, k = self.p, self.seed, _k
        nodes = []
        sk_open = None
        for t in range(512):
            d = k(p + lo + _hi_type(FTS_PRF, kappa + (t << 9)) + seed)
            for j, sk in ((2 * t, d[:16]), (2 * t + 1, d[16:])):
                if j == uk:
                    sk_open = sk
                nodes.append(k(p + lo + _hi_type(FTS_LEAF, kappa + (j << 9)) + sk)[:NB])
        path = []
        for lvl in range(A):
            path.append(nodes[(uk >> lvl) ^ 1])
            if lvl + 1 == A:
                break
            nodes = [k(p + lo + _hi_type(FTS_NODE, kappa + ((lvl + 1) << 5) + (j << 9)) + nodes[2 * j] + nodes[2 * j + 1])
                     [:NB] for j in range(len(nodes) // 2)]
        return sk_open, path, nodes[0], nodes[1]


def _hi_type(t: int, hi: int) -> bytes:
    """address bytes 4..15 for lo already written: hi (u24 LE), the type byte, eight zero bytes"""
    return hi.to_bytes(3, "little") + bytes([t]) + _Z8


def _leaves(p, seed, first, count, workers):
    workers = workers if workers is not None else (os.cpu_count() or 1)
    if workers <= 1 or count < 64:
        return _wots_leaves((p, seed, first, first + count))
    import multiprocessing
    chunk = max(16, count // (workers * 4))
    jobs = [(p, seed, first + lo, first + min(count, lo + chunk)) for lo in range(0, count, chunk)]
    with multiprocessing.get_context("fork").Pool(min(workers, len(jobs))) as pool:
        parts = pool.map(_wots_leaves, jobs)
    return [x for part in parts for x in part]


def _digit(x: bytes, i: int) -> int:
    return (x[i >> 2] >> (2 * (i & 3))) & 3


def _encode(p: bytes, lo: bytes, tops: bytes):
    """WOTS+C: the least counter whose encoding of the tops has digit sum 120; returns (counter, codeword)"""
    prefix = p + lo + bytes([0, 0, 0, ENC]) + _Z8 + tops
    c = 0
    while True:
        x = _k(prefix + c.to_bytes(4, "little"))[:NB]
        if sum(map(_DIGIT_SUM.__getitem__, x)) == TARGET:
            return c, x
        c += 1


def _word(d: bytes, w: int) -> int:
    return int.from_bytes(d[8 * w: 8 * w + 8], "little")


def fors_indices(p: bytes, m: bytes, rho: bytes) -> list:
    """The 24 FORS indices: tree κ in digest call κ / 12, word (κ mod 12) / 6, bits 10 (κ mod 6)"""
    d = [_k(p + addr(MSG, 0, c, 0) + m + rho) for c in (0, 1)]
    u = []
    for kappa in range(K):
        r = kappa % 12
        u.append((_word(d[kappa // 12], r // 6) >> (A * (r % 6))) & 0x3FF)
    return u


def verify(public_key: bytes, m: bytes, sig: bytes) -> bool:
    """Verifies a signature against root ‖ P, as LeanSphincsAsm.verify does"""
    if len(public_key) != 32 or len(m) != 32 or len(sig) != SIG_BYTES:
        return False
    root, p = public_key[:16], public_key[16:]
    k = _k
    rho = sig[:16]
    d0 = k(p + addr(MSG, 0, 0, 0) + m + rho)
    idx = d0[16] | (d0[17] << 8) | (d0[18] << 16) | ((d0[19] & 3) << 24)
    u = fors_indices(p, m, rho)
    lo = idx.to_bytes(4, "little")
    tops = []
    for kappa in range(K):
        off = 16 + 176 * kappa
        sk = sig[off: off + 16]
        path = [sig[off + 16 + 16 * lvl: off + 32 + 16 * lvl] for lvl in range(A)]
        uk = u[kappa]
        v = k(p + lo + _hi_type(FTS_LEAF, kappa + (uk << 9)) + sk)[:NB]
        for lvl in range(A - 1):
            j = uk >> (lvl + 1)
            pair = path[lvl] + v if (uk >> lvl) & 1 else v + path[lvl]
            v = k(p + lo + _hi_type(FTS_NODE, kappa + ((lvl + 1) << 5) + (j << 9)) + pair)[:NB]
        tops.append(path[A - 1] + v if (uk >> (A - 1)) & 1 else v + path[A - 1])
    c = sig[4240:4244]
    x = k(p + lo + bytes([0, 0, 0, ENC]) + _Z8 + b"".join(tops) + c)[:NB]
    if sum(map(_DIGIT_SUM.__getitem__, x)) != TARGET:
        return False
    ends = []
    for i in range(V):
        v = sig[4244 + 16 * i: 4260 + 16 * i]
        hi = bytes([i, 0, 0])
        for step in range(_digit(x, i), 3):
            v = k(p + lo + hi + bytes([CHAIN | (step << 5)]) + _Z8 + v)[:NB]
        ends.append(v)
    v = k(p + lo + bytes([0, 0, 0, LEAF]) + _Z8 + b"".join(ends))[:NB]
    j = idx
    for lvl in range(H):
        sib = sig[5268 + 16 * lvl: 5284 + 16 * lvl]
        v = _node(p, lvl + 1, j >> 1, sib, v) if j & 1 else _node(p, lvl + 1, j >> 1, v, sib)
        j >>= 1
    return v == root
