"""WOTS one-time signatures and their operation trees, parameter set D6 (docs/decisions.md): n = 24 bytes, w = 16,
48 message chains whose digits add up to 431, no checksum chains, keccak256 truncated to 24 bytes.

A port of contracts/test/utils/WotsSigner.sol (WotsSigner, WotsTree), checked byte for byte against it
(signer/tests), and of the verifier contracts/src/WotsVerifier.sol (verify_root), used to check every signature
before it is released.

Hash inputs start with a 32-byte tweak (WotsVerifier.sol):
    bits 255..128  public seed (128 bits, per tree)       byte  0..15
    bits 127..120  type: 0 chain, 1 pk compression,       byte 16
                   2 tree node, 3 message digest
    bits 119..56   key index (or parent node index)       bytes 17..24
    bits  55..48   chain index                            byte 25
    bits  47..40   chain step or tree level               byte 26
Values are n bytes, hashed as 32-byte words with the low bytes zero. Internally they are kept as such words.

Secrets and randomizers come from a PRF of the tree's secret seed. The Solidity test signer's PRF is
keccak256(abi.encode(label, skSeed, ...)) with labels "winterlock.test.sk", "winterlock.test.R" and, for the fixed
upper siblings of partly real test trees, "winterlock.test.sibling". The signer uses the same construction with its
own labels (Prf.SIGNER); the verifier never sees them.
"""

import os
from dataclasses import dataclass

from .keccak import keccak256 as _k

N = 24
LOG_W = 4
W = 16
WM1 = 15
TARGET_SUM = 431
CHAINS = 48  # 8 * N / LOG_W
SIG_BYTES = N * (1 + CHAINS)  # 1,176
HASH_KECCAK = 0
PARAMS = N | (LOG_W << 8) | (HASH_KECCAK << 16) | (TARGET_SUM << 32)  # WotsVerifier.encodeParams(24, 4, 0, 431)
MAX_TRIES = 1_000_000

_Z8 = bytes(8)
_TYPE_CHAIN, _TYPE_PK, _TYPE_NODE, _TYPE_DIGEST = 0, 1, 2, 3
_STEP = [bytes([j]) + bytes(5) for j in range(256)]
# nibble sum of each byte value: the digit sum of a digest is the sum over its bytes
_NIBBLES = [(b >> 4) + (b & 15) for b in range(256)]


def _w(v24: bytes) -> bytes:
    return v24 + _Z8


def _abi_label(label: bytes, *words: bytes) -> bytes:
    """keccak256(abi.encode(string label, bytes32 / uint256 words...))"""
    head = (32 * (len(words) + 1)).to_bytes(32, "big") + b"".join(words)
    tail = len(label).to_bytes(32, "big") + label + bytes((-len(label)) % 32)
    return _k(head + tail)


def _u(v: int) -> bytes:
    return v.to_bytes(32, "big")


@dataclass(frozen=True)
class Prf:
    """Labels of the secret-key PRF (keccak256 of abi.encode(label, ...))"""
    sk: bytes
    r: bytes
    sibling: bytes = b"winterlock.test.sibling"

    def secret(self, sk_seed: bytes, key_index: int, i: int) -> bytes:
        return _abi_label(self.sk, sk_seed, _u(key_index), _u(i))[:N] + _Z8

    def randomizer(self, sk_seed: bytes, key_index: int, message: bytes, counter: int) -> bytes:
        return _abi_label(self.r, sk_seed, _u(key_index), message, _u(counter))[:N] + _Z8

    def upper_sibling(self, sk_seed: bytes, level: int) -> bytes:
        return _abi_label(self.sibling, sk_seed, _u(level))[:N] + _Z8


Prf.TEST = Prf(b"winterlock.test.sk", b"winterlock.test.R")
Prf.SIGNER = Prf(b"winterlock.signer.wots.sk.v1", b"winterlock.signer.wots.R.v1", b"winterlock.signer.wots.sibling.v1")


def tweak(seed: int, typ: int, index: int, chain: int, step: int) -> bytes:
    return ((seed << 128) | (typ << 120) | (index << 56) | (chain << 48) | (step << 40)).to_bytes(32, "big")


def _seed16(seed: int) -> bytes:
    if not 0 <= seed < 1 << 128:
        raise ValueError("tree seed must be 128 bits")
    return seed.to_bytes(16, "big")


def _chain(prefix: bytes, x: bytes, frm: int, to: int) -> bytes:
    """Chain steps frm..to-1 on 32-byte value x; prefix = seed ‖ type 0 ‖ key index ‖ chain index (26 bytes)"""
    k = _k
    for j in range(frm, to):
        x = k(prefix + _STEP[j] + x)[:N] + _Z8
    return x


def _prefix(seed16: bytes, typ: int, key_index: int, chain: int) -> bytes:
    return seed16 + bytes([typ]) + key_index.to_bytes(8, "big") + bytes([chain])


def digest(seed: int, key_index: int, r: bytes, message: bytes) -> bytes:
    """trunc(H(tweak(seed, 3, keyIndex) ‖ R ‖ message)) as a 32-byte word; r is a 32-byte word"""
    return _k(tweak(seed, _TYPE_DIGEST, key_index, 0, 0) + r + message)[:N] + _Z8


def digit_sum(d: bytes) -> int:
    return sum(map(_NIBBLES.__getitem__, d[:N]))


def digits(d: bytes) -> list:
    """The 48 message digits of a digest, most significant first"""
    out = []
    for b in d[:N]:
        out.append(b >> 4)
        out.append(b & 15)
    return out


def encode(seed: int, sk_seed: bytes, key_index: int, message: bytes, prf: Prf):
    """Retries the randomizer until the digits hit the target sum; returns (digits, R word, tries)"""
    for c in range(MAX_TRIES):
        r = prf.randomizer(sk_seed, key_index, message, c)
        d = digest(seed, key_index, r, message)
        if digit_sum(d) == TARGET_SUM:
            return digits(d), r, c + 1
    raise RuntimeError("target sum not reached")


def _leaf_from_ends(seed16: bytes, key_index: int, ends) -> bytes:
    return _k(seed16 + bytes([_TYPE_PK]) + key_index.to_bytes(8, "big") + bytes(7) + b"".join(ends))[:N] + _Z8


def leaf(seed: int, sk_seed: bytes, key_index: int, prf: Prf) -> bytes:
    """The one-time public key of key_index, compressed: a 32-byte word"""
    s16 = _seed16(seed)
    ends = []
    for i in range(CHAINS):
        x = prf.secret(sk_seed, key_index, i)
        ends.append(_chain(_prefix(s16, _TYPE_CHAIN, key_index, i), x, 0, WM1))
    return _leaf_from_ends(s16, key_index, ends)


def sign(seed: int, sk_seed: bytes, key_index: int, message: bytes, prf: Prf) -> bytes:
    """[R][x_0]...[x_47], n bytes each (1,176 bytes)"""
    if len(message) != 32:
        raise ValueError("message must be 32 bytes")
    a, r, _ = encode(seed, sk_seed, key_index, message, prf)
    s16 = _seed16(seed)
    out = [r[:N]]
    for i in range(CHAINS):
        x = prf.secret(sk_seed, key_index, i)
        out.append(_chain(_prefix(s16, _TYPE_CHAIN, key_index, i), x, 0, a[i])[:N])
    return b"".join(out)


def node(seed: int, level: int, index: int, left: bytes, right: bytes) -> bytes:
    return _k(tweak(seed, _TYPE_NODE, index, 0, level) + left + right)[:N] + _Z8


def verify_root(seed: int, key_index: int, message: bytes, sig: bytes, path: bytes):
    """WotsVerifier.computeRoot: the root that a signature and path imply, or None if the digits miss the target"""
    if len(sig) != SIG_BYTES or len(path) % N or not 0 <= key_index < 1 << 64 or len(message) != 32:
        return None
    s16 = _seed16(seed)
    d = digest(seed, key_index, _w(sig[:N]), message)
    if digit_sum(d) != TARGET_SUM:
        return None
    a = digits(d)
    ends = []
    for i in range(CHAINS):
        x = _w(sig[N * (i + 1): N * (i + 2)])
        ends.append(_chain(_prefix(s16, _TYPE_CHAIN, key_index, i), x, a[i], WM1))
    v = _leaf_from_ends(s16, key_index, ends)
    idx = key_index
    for lvl in range(len(path) // N):
        sib = _w(path[N * lvl: N * (lvl + 1)])
        bit = idx & 1
        idx >>= 1
        v = node(seed, lvl + 1, idx, sib, v) if bit else node(seed, lvl + 1, idx, v, sib)
    return v[:N]


# --- trees ---

def _leaves(args):
    seed, sk_seed, lo, hi, prf = args
    return [leaf(seed, sk_seed, i, prf) for i in range(lo, hi)]


def leaves(seed: int, sk_seed: bytes, count: int, prf: Prf, workers=None) -> list:
    """Leaves 0..count-1, in parallel processes when there are many"""
    workers = workers if workers is not None else (os.cpu_count() or 1)
    if workers <= 1 or count < 64:
        return _leaves((seed, sk_seed, 0, count, prf))
    import multiprocessing
    chunk = max(16, count // (workers * 4))
    jobs = [(seed, sk_seed, lo, min(count, lo + chunk), prf) for lo in range(0, count, chunk)]
    with multiprocessing.get_context("fork").Pool(min(workers, len(jobs))) as pool:
        parts = pool.map(_leaves, jobs)
    return [x for part in parts for x in part]


class Tree:
    """A tree of WOTS keys (WotsTree in WotsSigner.sol). Leaves [0, 2^k) are real; levels above k, if any, use fixed
    pseudo-random siblings (test trees only: the signer's trees have k = height). Holds only public values."""

    def __init__(self, seed: int, height: int, k: int, leaves_: list, upper: list):
        if len(leaves_) != 1 << k or len(upper) != height - k:
            raise ValueError("tree shape")
        self.seed, self.height, self.k = seed, height, k
        self.levels = [list(leaves_)]
        for lvl in range(1, k + 1):
            below = self.levels[-1]
            self.levels.append([node(seed, lvl, i, below[2 * i], below[2 * i + 1]) for i in range(len(below) // 2)])
        self.upper = list(upper)
        v = self.levels[k][0]
        for lvl in range(k, height):
            v = node(seed, lvl + 1, 0, v, self.upper[lvl - k])
        self.root = v[:N]

    @classmethod
    def create(cls, seed: int, sk_seed: bytes, height: int, k: int = None, prf: Prf = Prf.SIGNER, workers=None):
        k = height if k is None else k
        if not 0 <= k <= height <= 40:
            raise ValueError("bad tree height")
        upper = [prf.upper_sibling(sk_seed, lvl) for lvl in range(k, height)]
        return cls(seed, height, k, leaves(seed, sk_seed, 1 << k, prf, workers), upper)

    def path(self, index: int) -> bytes:
        if not 0 <= index < 1 << self.k:
            raise ValueError("index outside the real subtree")
        out = [self.levels[lvl][(index >> lvl) ^ 1][:N] for lvl in range(self.k)]
        out += [u[:N] for u in self.upper]
        return b"".join(out)

    # cache: public values only (the leaves and the upper siblings)
    def to_bytes(self) -> bytes:
        return (bytes([self.height, self.k]) + self.seed.to_bytes(16, "big")
                + b"".join(x[:N] for x in self.levels[0]) + b"".join(u[:N] for u in self.upper))

    @classmethod
    def from_bytes(cls, b: bytes):
        height, k = b[0], b[1]
        seed = int.from_bytes(b[2:18], "big")
        body = b[18:]
        if len(body) != N * ((1 << k) + height - k):
            raise ValueError("tree cache has the wrong size")
        xs = [_w(body[N * i: N * (i + 1)]) for i in range(len(body) // N)]
        return cls(seed, height, k, xs[: 1 << k], xs[1 << k:])
