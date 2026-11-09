#!/usr/bin/env python3
"""FIPS 205 SLH-DSA, SHA2 instantiation for security category 1 (n = 16, section 11.2.1).

A reference written from the standard for this benchmark, standard library only. It serves two purposes:
- a second reading of FIPS 205 next to the Solidity verifier, checked against NIST's ACVP vectors and noble's and
  RustCrypto's signatures for SLH-DSA-SHA2-128s (check_reference.py);
- the only source of keys and signatures for the DRAFT parameter set SLH-DSA-SHA2-128-24 of NIST SP 800-230 (initial
  public draft), which no independent implementation offers. Signatures for it check internal consistency only.

Algorithm numbers are FIPS 205's. Hash calls and SHA-256 compressions are counted in COUNT.

    python3 fips205.py params        # FIPS 205's formulas for both sets
"""
import hashlib
import hmac
import os
import struct
import sys
from multiprocessing import Pool


class Params:
    """One parameter set (FIPS 205 Table 2 and section 11.2.1). Derived values follow FIPS 205's formulas."""

    def __init__(self, name, n, h, d, hp, a, k, lgw, m, draft=False):
        self.name, self.n, self.h, self.d, self.hp, self.a, self.k, self.lgw, self.m = name, n, h, d, hp, a, k, lgw, m
        self.draft = draft
        assert n == 16, "category 1 only: F, H, T and H_msg over SHA-256"
        assert h == d * hp
        self.w = 1 << lgw
        # section 5: len1 = ceil(8n / lg w), len2 = floor(log2(len1 (w - 1)) / lg w) + 1
        self.len1 = -(-8 * n // lgw)
        self.len2 = (self.len1 * (self.w - 1)).bit_length() - 1
        self.len2 = self.len2 // lgw + 1
        self.len = self.len1 + self.len2
        # Algorithm 19: m = ceil(k a / 8) + ceil((h - h') / 8) + ceil(h' / 8)
        self.md_bytes = -(-k * a // 8)
        self.tree_bytes = -(-(h - hp) // 8)
        self.leaf_bytes = -(-hp // 8)
        assert m == self.md_bytes + self.tree_bytes + self.leaf_bytes, "m from FIPS 205's formula"
        # section 9: SIG = R (n) + SIG_FORS (k (1 + a) n) + SIG_HT ((h + d len) n)
        self.sig_bytes = (1 + k * (1 + a) + h + d * self.len) * n
        self.pk_bytes = 2 * n


SHA2_128S = Params("SLH-DSA-SHA2-128s", n=16, h=63, d=7, hp=9, a=12, k=14, lgw=4, m=30)
# NIST SP 800-230 ipd (initial public draft). DRAFT: the parameters may still change.
SHA2_128_24_DRAFT = Params("SLH-DSA-SHA2-128-24 (DRAFT, SP 800-230 ipd)", n=16, h=22, d=1, hp=22, a=24, k=6, lgw=2,
                           m=21, draft=True)

# ADRS types, FIPS 205 section 4.2
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)


class Adrs:
    """The 32-byte address of section 4.2: layer (4) | tree (12) | type (4) | three 4-byte words."""

    def __init__(self, b=None):
        self.b = bytearray(32) if b is None else bytearray(b)

    def copy(self):
        return Adrs(self.b)

    def _set(self, off, length, v):
        self.b[off:off + length] = v.to_bytes(length, "big")

    def set_layer(self, l):
        self._set(0, 4, l)

    def set_tree(self, t):
        self._set(4, 12, t)

    def set_type_and_clear(self, y):
        self._set(16, 4, y)
        self.b[20:32] = bytes(12)

    def set_key_pair(self, i):
        self._set(20, 4, i)

    def get_key_pair(self):
        return int.from_bytes(self.b[20:24], "big")

    def set_chain(self, i):  # also setTreeHeight
        self._set(24, 4, i)

    set_tree_height = set_chain

    def set_hash(self, i):  # also setTreeIndex
        self._set(28, 4, i)

    set_tree_index = set_hash

    def get_tree_index(self):
        return int.from_bytes(self.b[28:32], "big")

    def compressed(self):
        """ADRSc, section 11.2: ADRS[3] | ADRS[8:16] | ADRS[19] | ADRS[20:32], 22 bytes."""
        b = self.b
        return bytes(b[3:4] + b[8:16] + b[19:20] + b[20:32])


COUNT = {"calls": 0, "compressions": 0, "compressions_midstate": 0}


def _blocks(nbytes):
    return (nbytes + 9 + 63) // 64


class Hashes:
    """Section 11.2.1: PRF, F, H and T_l hash PK.seed padded to a 64-byte block, then ADRSc and the input."""

    def __init__(self, p, pk_seed):
        self.p = p
        self.pk_seed = pk_seed
        self.block = hashlib.sha256(pk_seed + bytes(64 - p.n))  # the midstate after the PK.seed block

    def _t(self, adrs, data):
        COUNT["calls"] += 1
        COUNT["compressions"] += _blocks(64 + 22 + len(data))
        COUNT["compressions_midstate"] += _blocks(64 + 22 + len(data)) - 1
        s = self.block.copy()
        s.update(adrs.compressed() + data)
        return s.digest()[: self.p.n]

    F = H = T = PRF = _t


def h_msg(p, r, pk_seed, pk_root, m):
    """H_msg = MGF1-SHA-256(R | PK.seed | SHA-256(R | PK.seed | PK.root | M), m)."""
    COUNT["calls"] += 1
    COUNT["compressions"] += _blocks(3 * p.n + len(m))
    COUNT["compressions_midstate"] += _blocks(3 * p.n + len(m))
    seed = r + pk_seed + hashlib.sha256(r + pk_seed + pk_root + m).digest()
    out = b""
    for c in range(-(-p.m // 32)):
        COUNT["calls"] += 1
        COUNT["compressions"] += _blocks(len(seed) + 4)
        COUNT["compressions_midstate"] += _blocks(len(seed) + 4)
        out += hashlib.sha256(seed + c.to_bytes(4, "big")).digest()
    return out[: p.m]


def prf_msg(p, sk_prf, opt_rand, m):
    """PRF_msg = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand | M))."""
    COUNT["calls"] += 1
    return hmac.new(sk_prf, opt_rand + m, hashlib.sha256).digest()[: p.n]


def base_2b(x, b, out_len):
    """Algorithm 4."""
    i, bits, total, out = 0, 0, 0, []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + x[i]
            i += 1
            bits += 8
        bits -= b
        out.append((total >> bits) & ((1 << b) - 1))
    return out


# --- WOTS+, section 5 ---


def chain(hs, x, i, s, adrs):
    """Algorithm 5."""
    for j in range(i, i + s):
        adrs.set_hash(j)
        x = hs.F(adrs, x)
    return x


def wots_digits(p, m):
    """Algorithm 7 lines 1-7 / Algorithm 8 lines 1-7: the len base-w digits of message and checksum."""
    msg = base_2b(m, p.lgw, p.len1)
    csum = sum(p.w - 1 - v for v in msg)
    csum <<= (8 - ((p.len2 * p.lgw) % 8)) % 8
    return msg + base_2b(csum.to_bytes(-(-p.len2 * p.lgw // 8), "big"), p.lgw, p.len2)


def wots_pkgen(hs, sk_seed, adrs):
    """Algorithm 6."""
    p = hs.p
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())
    tmp = b""
    for i in range(p.len):
        sk_adrs.set_chain(i)
        sk = hs.PRF(sk_adrs, sk_seed)
        adrs.set_chain(i)
        tmp += chain(hs, sk, 0, p.w - 1, adrs)
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(WOTS_PK)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    return hs.T(pk_adrs, tmp)


def wots_sign(hs, m, sk_seed, adrs):
    """Algorithm 7."""
    p = hs.p
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())
    sig = b""
    for i, v in enumerate(wots_digits(p, m)):
        sk_adrs.set_chain(i)
        sk = hs.PRF(sk_adrs, sk_seed)
        adrs.set_chain(i)
        sig += chain(hs, sk, 0, v, adrs)
    return sig


def wots_pk_from_sig(hs, sig, m, adrs):
    """Algorithm 8."""
    p, n = hs.p, hs.p.n
    tmp = b""
    for i, v in enumerate(wots_digits(p, m)):
        adrs.set_chain(i)
        tmp += chain(hs, sig[i * n:(i + 1) * n], v, p.w - 1 - v, adrs)
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(WOTS_PK)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    return hs.T(pk_adrs, tmp)


# --- XMSS, section 6 ---


def xmss_leaf(hs, sk_seed, i, adrs):
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair(i)
    return wots_pkgen(hs, sk_seed, adrs)


def xmss_node(hs, sk_seed, i, z, adrs):
    """Algorithm 9."""
    if z == 0:
        return xmss_leaf(hs, sk_seed, i, adrs)
    l = xmss_node(hs, sk_seed, 2 * i, z - 1, adrs)
    r = xmss_node(hs, sk_seed, 2 * i + 1, z - 1, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return hs.H(adrs, l + r)


def xmss_sign(hs, m, sk_seed, idx, adrs):
    """Algorithm 10. Large trees (h' > 12) go through the parallel tree walk."""
    p = hs.p
    if p.hp > 12:
        _, auth = parallel_tree(hs, sk_seed, adrs, "xmss", p.hp, idx)
    else:
        auth = [xmss_node(hs, sk_seed, (idx >> j) ^ 1, j, adrs) for j in range(p.hp)]
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair(idx)
    return wots_sign(hs, m, sk_seed, adrs) + b"".join(auth)


def xmss_pk_from_sig(hs, idx, sig, m, adrs):
    """Algorithm 11."""
    p, n = hs.p, hs.p.n
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair(idx)
    node = wots_pk_from_sig(hs, sig[: p.len * n], m, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_index(idx)
    for k in range(p.hp):
        auth = sig[(p.len + k) * n:(p.len + k + 1) * n]
        adrs.set_tree_height(k + 1)
        if (idx >> k) & 1 == 0:
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            node = hs.H(adrs, node + auth)
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node = hs.H(adrs, auth + node)
    return node


# --- the hypertree, section 7 ---


def ht_sign(hs, m, sk_seed, idx_tree, idx_leaf):
    """Algorithm 12."""
    p = hs.p
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    sig = xmss_sign(hs, m, sk_seed, idx_leaf, adrs)
    out = sig
    root = xmss_pk_from_sig(hs, idx_leaf, sig, m, adrs)
    for j in range(1, p.d):
        idx_leaf = idx_tree % (1 << p.hp)
        idx_tree >>= p.hp
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        sig = xmss_sign(hs, root, sk_seed, idx_leaf, adrs)
        out += sig
        if j < p.d - 1:
            root = xmss_pk_from_sig(hs, idx_leaf, sig, root, adrs)
    return out


def ht_verify(hs, m, sig_ht, idx_tree, idx_leaf, pk_root):
    """Algorithm 13."""
    p, n = hs.p, hs.p.n
    xl = (p.len + p.hp) * n
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    node = xmss_pk_from_sig(hs, idx_leaf, sig_ht[:xl], m, adrs)
    for j in range(1, p.d):
        idx_leaf = idx_tree % (1 << p.hp)
        idx_tree >>= p.hp
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        node = xmss_pk_from_sig(hs, idx_leaf, sig_ht[j * xl:(j + 1) * xl], node, adrs)
    return node == pk_root


# --- FORS, section 8 ---


def fors_sk(hs, sk_seed, adrs, idx):
    """Algorithm 14."""
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(FORS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())
    sk_adrs.set_tree_index(idx)
    return hs.PRF(sk_adrs, sk_seed)


def fors_leaf(hs, sk_seed, i, adrs):
    sk = fors_sk(hs, sk_seed, adrs, i)
    adrs.set_tree_height(0)
    adrs.set_tree_index(i)
    return hs.F(adrs, sk)


def fors_node(hs, sk_seed, i, z, adrs):
    """Algorithm 15."""
    if z == 0:
        return fors_leaf(hs, sk_seed, i, adrs)
    l = fors_node(hs, sk_seed, 2 * i, z - 1, adrs)
    r = fors_node(hs, sk_seed, 2 * i + 1, z - 1, adrs)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return hs.H(adrs, l + r)


def fors_sign(hs, md, sk_seed, adrs):
    """Algorithm 16. Large trees (a > 12) go through the parallel tree walk."""
    p = hs.p
    out = b""
    for i, idx in enumerate(base_2b(md, p.a, p.k)):
        out += fors_sk(hs, sk_seed, adrs, (i << p.a) + idx)
        if p.a > 12:
            _, auth = parallel_tree(hs, sk_seed, adrs, "fors", p.a, idx, offset=i << p.a)
            out += b"".join(auth)
        else:
            for j in range(p.a):
                s = (idx >> j) ^ 1
                out += fors_node(hs, sk_seed, (i << (p.a - j)) + s, j, adrs)
    return out


def fors_pk_from_sig(hs, sig_fors, md, adrs):
    """Algorithm 17."""
    p, n = hs.p, hs.p.n
    roots = b""
    for i, idx in enumerate(base_2b(md, p.a, p.k)):
        at = i * (p.a + 1) * n
        adrs.set_tree_height(0)
        adrs.set_tree_index((i << p.a) + idx)
        node = hs.F(adrs, sig_fors[at:at + n])
        for j in range(p.a):
            auth = sig_fors[at + (j + 1) * n:at + (j + 2) * n]
            adrs.set_tree_height(j + 1)
            if (idx >> j) & 1 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node = hs.H(adrs, node + auth)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = hs.H(adrs, auth + node)
        roots += node
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(FORS_ROOTS)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    return hs.T(pk_adrs, roots)


# --- SLH-DSA, sections 9 and 10 ---


def split_digest(p, digest):
    """Algorithm 19 lines 7-11 / Algorithm 20 lines 7-11."""
    md = digest[: p.md_bytes]
    t = digest[p.md_bytes:p.md_bytes + p.tree_bytes]
    l = digest[p.md_bytes + p.tree_bytes:p.md_bytes + p.tree_bytes + p.leaf_bytes]
    idx_tree = int.from_bytes(t, "big") % (1 << (p.h - p.hp)) if t else 0
    idx_leaf = int.from_bytes(l, "big") % (1 << p.hp)
    return md, idx_tree, idx_leaf


def keygen_internal(p, sk_seed, sk_prf, pk_seed):
    """Algorithm 18. Returns (sk, pk)."""
    hs = Hashes(p, pk_seed)
    adrs = Adrs()
    adrs.set_layer(p.d - 1)
    if p.hp > 12:
        root, _ = parallel_tree(hs, sk_seed, adrs, "xmss", p.hp, 0)
    else:
        root = xmss_node(hs, sk_seed, 0, p.hp, adrs)
    return sk_seed + sk_prf + pk_seed + root, pk_seed + root


def sign_internal(p, m, sk, addrnd=None):
    """Algorithm 19. addrnd None is the deterministic variant (opt_rand = PK.seed)."""
    n = p.n
    sk_seed, sk_prf, pk_seed, pk_root = sk[:n], sk[n:2 * n], sk[2 * n:3 * n], sk[3 * n:]
    hs = Hashes(p, pk_seed)
    r = prf_msg(p, sk_prf, pk_seed if addrnd is None else addrnd, m)
    md, idx_tree, idx_leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, m))
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair(idx_leaf)
    sig_fors = fors_sign(hs, md, sk_seed, adrs)
    pk_fors = fors_pk_from_sig(hs, sig_fors, md, adrs)
    return r + sig_fors + ht_sign(hs, pk_fors, sk_seed, idx_tree, idx_leaf)


def verify_internal(p, m, sig, pk):
    """Algorithm 20."""
    n = p.n
    if len(sig) != p.sig_bytes or len(pk) != 2 * n:
        return False
    pk_seed, pk_root = pk[:n], pk[n:]
    hs = Hashes(p, pk_seed)
    r = sig[:n]
    sig_fors = sig[n:n + p.k * (1 + p.a) * n]
    sig_ht = sig[n + p.k * (1 + p.a) * n:]
    md, idx_tree, idx_leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, m))
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair(idx_leaf)
    pk_fors = fors_pk_from_sig(hs, sig_fors, md, adrs)
    return ht_verify(hs, pk_fors, sig_ht, idx_tree, idx_leaf, pk_root)


def wrap(m, ctx):
    """Algorithms 22 and 24 (pure SLH-DSA): M' = toByte(0, 1) | toByte(|ctx|, 1) | ctx | M."""
    assert len(ctx) <= 255
    return bytes([0, len(ctx)]) + ctx + m


def sign(p, m, ctx, sk, addrnd=None):
    """Algorithm 22, slh_sign (pure)."""
    return sign_internal(p, wrap(m, ctx), sk, addrnd)


def verify(p, m, sig, ctx, pk):
    """Algorithm 24, slh_verify (pure)."""
    if len(ctx) > 255:
        return False
    return verify_internal(p, wrap(m, ctx), sig, pk)


# --- a parallel tree walk for the draft set's large trees (2^22 XMSS leaves, FORS trees of 2^24 leaves) ---
#
# The same values as Algorithms 6, 9, 14 and 15, computed from precomputed ADRSc prefixes, in 2^split subtrees on all
# cores. check_reference.py compares it with the algorithms above on SLH-DSA-SHA2-128s's trees.

SPLIT = 8
Z4 = bytes(4)


def _prefixes(adrs_b, kind):
    """ADRSc up to the key pair: layer (1) | tree (8), then the type byte and key pair (4) per use."""
    a = Adrs(adrs_b).compressed()
    lt, kp = a[:9], a[10:14]
    if kind == "xmss":
        return lt, None, lt + bytes([TREE]) + Z4
    return lt, kp, lt + bytes([FORS_TREE]) + kp


def _leaves(p, pk_seed, sk_seed, adrs_b, kind, first, count):
    """Leaves first .. first + count - 1 of the tree; with the number of hash calls and compressions."""
    blk = hashlib.sha256(pk_seed + bytes(64 - p.n))
    lt, kp, _ = _prefixes(adrs_b, kind)
    n = p.n
    out = []
    if kind == "xmss":
        chains = [i.to_bytes(4, "big") for i in range(p.len)]
        steps = [j.to_bytes(4, "big") for j in range(p.w - 1)]
        for leaf in range(first, first + count):
            kpl = leaf.to_bytes(4, "big")
            prf, f = lt + bytes([WOTS_PRF]) + kpl, lt + bytes([WOTS_HASH]) + kpl
            tmp = []
            for c in chains:
                s = blk.copy()
                s.update(prf + c + Z4 + sk_seed)
                x = s.digest()[:n]
                fc = f + c
                for j in steps:
                    s = blk.copy()
                    s.update(fc + j + x)
                    x = s.digest()[:n]
                tmp.append(x)
            s = blk.copy()
            s.update(lt + bytes([WOTS_PK]) + kpl + bytes(8) + b"".join(tmp))
            out.append(s.digest()[:n])
        t_blocks = _blocks(64 + 22 + p.len * n)
        calls = count * (p.len * p.w + 1)
        comps = count * (2 * p.len * p.w + t_blocks)
        comps_mid = count * (p.len * p.w + t_blocks - 1)
    else:
        prf, f = lt + bytes([FORS_PRF]) + kp + Z4, lt + bytes([FORS_TREE]) + kp + Z4
        for i in range(first, first + count):
            ib = i.to_bytes(4, "big")
            s = blk.copy()
            s.update(prf + ib + sk_seed)
            sk = s.digest()[:n]
            s = blk.copy()
            s.update(f + ib + sk)
            out.append(s.digest()[:n])
        calls, comps, comps_mid = 2 * count, 4 * count, 2 * count
    return out, calls, comps, comps_mid


def _climb(blk, node_pre, level, first, z0, z1, idx, auth, n):
    """Hash `level` (nodes at height z0, the leftmost at index first >> z0) up to height z1, collecting idx's auth
    path. Returns the top level and the number of H calls."""
    calls = 0
    for z in range(z0 + 1, z1 + 1):
        if idx is not None:
            auth.append(level[((idx - first) >> (z - 1)) ^ 1])
        nxt = []
        for j in range(len(level) // 2):
            s = blk.copy()
            s.update(node_pre + z.to_bytes(4, "big") + ((first >> z) + j).to_bytes(4, "big") + level[2 * j]
                     + level[2 * j + 1])
            nxt.append(s.digest()[:n])
        calls += len(nxt)
        level = nxt
    return level, calls


def _subtree(args):
    """Root of the subtree of height zs whose leftmost leaf is `first`, and the auth path inside it for leaf idx."""
    p_name, pk_seed, sk_seed, adrs_b, kind, zs, first, idx = args
    p = PARAMS[p_name]
    level, calls, comps, comps_mid = _leaves(p, pk_seed, sk_seed, adrs_b, kind, first, 1 << zs)
    auth = []
    blk = hashlib.sha256(pk_seed + bytes(64 - p.n))
    level, h_calls = _climb(blk, _prefixes(adrs_b, kind)[2], level, first, 0, zs, idx, auth, p.n)
    return level[0], auth, (calls + h_calls, comps + 2 * h_calls, comps_mid + h_calls)


def parallel_tree(hs, sk_seed, adrs, kind, z, idx, offset=0, split=SPLIT):
    """Root and auth path of leaf idx in the XMSS tree (kind "xmss", ADRS with layer and tree set) or the FORS tree
    (kind "fors", ADRS of type FORS_TREE with its key pair; leaves start at `offset`) of height z."""
    p = hs.p
    zs = z - split
    tasks = []
    for c in range(1 << split):
        first = offset + (c << zs)
        tasks.append((p.name, hs.pk_seed, sk_seed, bytes(adrs.b), kind, zs, first,
                      idx + offset if (idx >> zs) == c else None))
    with Pool(int(os.environ.get("JOBS", os.cpu_count()))) as pool:
        results = pool.map(_subtree, tasks)
    for _, _, (calls, comps, comps_mid) in results:
        COUNT["calls"] += calls
        COUNT["compressions"] += comps
        COUNT["compressions_midstate"] += comps_mid
    auth = results[idx >> zs][1]
    level, calls = _climb(hs.block, _prefixes(bytes(adrs.b), kind)[2], [r[0] for r in results], offset, zs, z,
                          idx + offset, auth, p.n)
    COUNT["calls"] += calls
    COUNT["compressions"] += 2 * calls
    COUNT["compressions_midstate"] += calls
    return level[0], auth


PARAMS = {SHA2_128S.name: SHA2_128S, SHA2_128_24_DRAFT.name: SHA2_128_24_DRAFT}


def _print_params():
    for p in PARAMS.values():
        print(f"{p.name}: n={p.n} h={p.h} d={p.d} h'={p.hp} a={p.a} k={p.k} lg w={p.lgw} w={p.w}")
        print(f"  len1={p.len1} len2={p.len2} len={p.len}  m={p.m} = {p.md_bytes} + {p.tree_bytes} + {p.leaf_bytes}"
              f"  signature={p.sig_bytes} B  public key={p.pk_bytes} B")


if __name__ == "__main__":
    if sys.argv[1:] == ["params"]:
        _print_params()
    else:
        print(__doc__)
