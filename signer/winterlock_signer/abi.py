"""Minimal ABI encoding and decoding: the static types the signer uses, plus `bytes` and `address[]`."""

from .keccak import keccak256


def read_file(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def h2b(x) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    x = x[2:] if x.startswith(("0x", "0X")) else x
    return bytes.fromhex(x)


def b2h(b: bytes) -> str:
    return "0x" + bytes(b).hex()


def checksum(addr) -> str:
    """EIP-55 checksummed address"""
    a = (addr.hex() if isinstance(addr, (bytes, bytearray)) else addr.lower().replace("0x", "")).rjust(40, "0")
    if len(a) != 40:
        raise ValueError(f"not an address: {addr}")
    int(a, 16)
    hh = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(hh[i], 16) >= 8 else c for i, c in enumerate(a))


def is_address(s) -> bool:
    try:
        return isinstance(s, str) and len(h2b(s)) == 20
    except ValueError:
        return False


def address(s) -> str:
    """Parses and checksums an address; refuses a mixed-case address with a wrong checksum"""
    if not is_address(s):
        raise ValueError(f"not an address: {s}")
    c = checksum(s)
    body = s[2:] if s.startswith(("0x", "0X")) else s
    if body != body.lower() and body != body.upper() and "0x" + body != c:
        raise ValueError(f"bad address checksum: {s}")
    return c


def word(v) -> bytes:
    """One 32-byte word: an int (uint), an address string (left-padded), or bytes (bytes32 if 32 long, else
    left-padded like an address)"""
    if isinstance(v, bool):
        return int(v).to_bytes(32, "big")
    if isinstance(v, int):
        if v < 0:
            v += 1 << 256
        return v.to_bytes(32, "big")
    if isinstance(v, str):
        return h2b(v).rjust(32, b"\x00")
    v = bytes(v)
    if len(v) > 32:
        raise ValueError("word longer than 32 bytes")
    return v if len(v) == 32 else v.rjust(32, b"\x00")


def selector(sig: str) -> bytes:
    return keccak256(sig.encode())[:4]


def _pad(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 32)


def encode(types, values) -> bytes:
    """abi.encode for uint*, int*, address, bool, bytes32, bytes, string, address[], bytes32[N]"""
    heads, tails = [], []
    head_len = 0
    for t in types:
        if t.startswith("bytes32[") and t.endswith("]"):
            head_len += 32 * int(t[8:-1])
        else:
            head_len += 32
    for t, v in zip(types, values):
        if t in ("bytes", "string"):
            data = v.encode() if isinstance(v, str) and t == "string" else h2b(v) if isinstance(v, str) else bytes(v)
            heads.append(("off", len(b"".join(tails))))
            tails.append(word(len(data)) + _pad(data))
        elif t == "address[]":
            heads.append(("off", len(b"".join(tails))))
            tails.append(word(len(v)) + b"".join(word(a) for a in v))
        elif t.startswith("bytes32[") and t.endswith("]"):
            heads.append(("raw", b"".join(word(x) for x in v)))
        elif t == "bytes32":
            b = h2b(v) if isinstance(v, str) else bytes(v)
            if len(b) != 32:
                raise ValueError("bytes32 must be 32 bytes")
            heads.append(("raw", b))
        else:
            heads.append(("raw", word(v)))
    out = b""
    for kind, x in heads:
        out += word(head_len + x) if kind == "off" else x
    return out + b"".join(tails)


def calldata(sig: str, types=(), values=()) -> bytes:
    return selector(sig) + encode(list(types), list(values))


def dec_word(ret: bytes, index=0) -> bytes:
    if len(ret) < 32 * index + 32:
        raise ValueError("return data too short")
    return ret[32 * index: 32 * index + 32]


def dec_uint(ret: bytes, index=0) -> int:
    return int.from_bytes(dec_word(ret, index), "big")


def dec_addr(ret: bytes, index=0) -> str:
    return checksum(dec_word(ret, index)[12:])


def dec_bytes(ret: bytes, index=0) -> bytes:
    off = dec_uint(ret, index)
    n = int.from_bytes(ret[off: off + 32], "big")
    if off + 32 + n > len(ret):
        raise ValueError("bytes out of range")
    return ret[off + 32: off + 32 + n]


def dec_addresses(ret: bytes, index=0) -> list:
    off = dec_uint(ret, index)
    n = int.from_bytes(ret[off: off + 32], "big")
    return [checksum(ret[off + 32 + 32 * i + 12: off + 64 + 32 * i]) for i in range(n)]


def dec_args(data: bytes, types) -> list:
    """Decodes call arguments (after the selector) of static types, `bytes` and `address[]`"""
    out = []
    for i, t in enumerate(types):
        if t == "address":
            out.append(dec_addr(data, i))
        elif t == "bytes":
            out.append(dec_bytes(data, i))
        elif t == "address[]":
            out.append(dec_addresses(data, i))
        elif t == "bytes32":
            out.append(dec_word(data, i))
        elif t == "bool":
            out.append(dec_uint(data, i) != 0)
        else:
            out.append(dec_uint(data, i))
    return out
