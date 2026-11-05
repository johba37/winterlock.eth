"""EIP-1559 transactions from the gas-paying account (secp256k1, RFC 6979, RLP), in plain Python.

The gas account only pays for `enroll`, owner deployment and `execTransaction`; it holds no Safe funds and is not a
Safe owner. Its key comes from an environment variable and is never printed or written.
"""

import hashlib
import hmac

from .abi import checksum, h2b
from .keccak import keccak256

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


# --- secp256k1 in Jacobian coordinates ---

def _jdouble(p):
    x, y, z = p
    if y == 0 or z == 0:
        return (0, 1, 0)
    s = 4 * x * y * y % P
    m = 3 * x * x % P
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * y**4) % P
    return (nx, ny, 2 * y * z % P)


def _jadd(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1s, z2s = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2s % P, x2 * z1s % P
    s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
    if u1 == u2:
        return _jdouble(p) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    nx = (r * r - h3 - 2 * u1h2) % P
    ny = (r * (u1h2 - nx) - s1 * h3) % P
    return (nx, ny, h * z1 * z2 % P)


def _mul(k: int, pt=G):
    acc = (0, 1, 0)
    q = (pt[0], pt[1], 1)
    while k:
        if k & 1:
            acc = _jadd(acc, q)
        q = _jdouble(q)
        k >>= 1
    x, y, z = acc
    if z == 0:
        raise ValueError("point at infinity")
    zi = pow(z, -1, P)
    return (x * zi * zi % P, y * zi * zi * zi % P)


def _k_rfc6979(d: int, h: bytes) -> int:
    x = d.to_bytes(32, "big")
    hb = (int.from_bytes(h, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        c = int.from_bytes(v, "big")
        if 1 <= c < N:
            return c
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_hash(d: int, h: bytes):
    """(y parity, r, s) with low s"""
    z = int.from_bytes(h, "big")
    k = _k_rfc6979(d, h)
    rx, ry = _mul(k)
    r = rx % N
    s = pow(k, -1, N) * (z + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("bad signature nonce")
    parity = ry & 1
    if s > N // 2:
        s = N - s
        parity ^= 1
    return parity, r, s


class Account:
    def __init__(self, private_key_hex: str):
        d = int.from_bytes(h2b(private_key_hex.strip()), "big")
        if not 1 <= d < N:
            raise ValueError("invalid private key")
        self._d = d
        x, y = _mul(d)
        self.address = checksum(keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:])

    def __repr__(self):
        return f"Account({self.address})"

    def sign_1559(self, chain_id, nonce, max_priority_fee, max_fee, gas, to, value, data: bytes) -> bytes:
        fields = [chain_id, nonce, max_priority_fee, max_fee, gas, h2b(to) if to else b"", value, data, []]
        h = keccak256(b"\x02" + rlp(fields))
        parity, r, s = sign_hash(self._d, h)
        return b"\x02" + rlp(fields + [parity, r, s])


# --- RLP ---

def _int_bytes(v: int) -> bytes:
    return v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b""


def _len_prefix(n: int, short: int) -> bytes:
    if n <= 55:
        return bytes([short + n])
    nb = _int_bytes(n)
    return bytes([short + 55 + len(nb)]) + nb


def rlp(x) -> bytes:
    if isinstance(x, int):
        x = _int_bytes(x)
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        if len(x) == 1 and x[0] < 0x80:
            return x
        return _len_prefix(len(x), 0x80) + x
    payload = b"".join(rlp(i) for i in x)
    return _len_prefix(len(payload), 0xC0) + payload


def send(rpc, account: Account, to, data: bytes, value=0, gas=None, gas_margin=1.2, max_fee=None,
         priority_fee=None, max_gas=16_777_216, wait=True, log=print):
    """Signs and sends a transaction from `account`; returns the receipt (or the hash if wait is False)"""
    chain_id = rpc.chain_id()
    if gas is None:
        gas = min(int(rpc.estimate_gas(account.address, to, data, value) * gas_margin), max_gas)
    base = rpc.base_fee()
    tip = priority_fee if priority_fee is not None else min(rpc.priority_fee(), max(base, 10**6))
    fee_cap = max_fee if max_fee is not None else 2 * base + tip
    raw = account.sign_1559(chain_id, rpc.nonce(account.address), tip, fee_cap, gas, to, value, data)
    tx_hash = rpc.send_raw(raw)
    log(f"  sent {tx_hash} (gas limit {gas:,}, fee cap {fee_cap:,} wei/gas, tip {tip:,})")
    if not wait:
        return tx_hash
    r = rpc.receipt(tx_hash)
    if int(r["status"], 16) != 1:
        raise RuntimeError(f"transaction reverted: {tx_hash}")
    return r
