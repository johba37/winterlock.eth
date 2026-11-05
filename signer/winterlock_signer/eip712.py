"""EIP-712 typed data (eth_signTypedData_v4) and EIP-191 personal messages: the hashes an app checks with the Safe's
isValidSignature, computed here from what the app sent, never taken from it.

Typed data as eth_signTypedData_v4 takes it (MetaMask's eth-sig-util, viem): nested structs, arrays (dynamic and
fixed, nested), bytes and string hashed, atomic types as 32-byte words. A missing EIP712Domain type is inferred from
the domain's fields, as viem does. Anything that doesn't fit its declared type is refused with ValueError.
"""

import json
import re

from .abi import checksum, h2b
from .keccak import keccak256

DOMAIN_FIELDS = [("name", "string"), ("version", "string"), ("chainId", "uint256"), ("verifyingContract", "address"),
                 ("salt", "bytes32")]
_IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_ARRAY = re.compile(r"^(.*)\[(\d*)\]$")


def personal_hash(message: bytes) -> bytes:
    """EIP-191 version 0x45: what personal_sign signs and an app checks"""
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)


class TypedData:
    def __init__(self, data):
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                raise ValueError("typed data is not JSON") from None
        if not isinstance(data, dict):
            raise ValueError("typed data is not an object")
        self.raw = data
        types = data.get("types")
        self.primary = data.get("primaryType")
        self.domain = data.get("domain") or {}
        self.message = data.get("message")
        if not isinstance(types, dict) or not isinstance(self.primary, str) or not isinstance(self.domain, dict):
            raise ValueError("typed data needs types, primaryType and domain")
        self.types = {}
        for name, fields in types.items():
            if not _IDENT.match(name) or not isinstance(fields, list):
                raise ValueError(f"bad type name {name!r}")
            seen = set()
            out = []
            for f in fields:
                if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not isinstance(f.get("type"), str):
                    raise ValueError(f"bad field in {name}")
                if f["name"] in seen:
                    raise ValueError(f"field {f['name']} twice in {name}")
                seen.add(f["name"])
                out.append((f["name"], f["type"]))
            self.types[name] = out
        if "EIP712Domain" not in self.types:
            self.types["EIP712Domain"] = [(n, t) for n, t in DOMAIN_FIELDS if n in self.domain]
        if self.primary not in self.types:
            raise ValueError(f"primaryType {self.primary} has no type definition")
        if self.primary != "EIP712Domain" and not isinstance(self.message, dict):
            raise ValueError("typed data has no message")
        for name in self.types:
            self._deps(name)  # every referenced type exists

    # --- EIP-712 ---

    def _base(self, t: str) -> str:
        m = _ARRAY.match(t)
        return self._base(m[1]) if m else t

    def _deps(self, name, found=None):
        found = set() if found is None else found
        if name in found:
            return found
        found.add(name)
        for _, t in self.types[name]:
            b = self._base(t)
            if b in self.types:
                self._deps(b, found)
            elif not _atomic_ok(b):
                raise ValueError(f"unknown type {b} in {name}")
        return found

    def encode_type(self, name) -> str:
        deps = sorted(self._deps(name) - {name})
        return "".join(f"{n}({','.join(f'{t} {f}' for f, t in self.types[n])})" for n in [name] + deps)

    def type_hash(self, name) -> bytes:
        return keccak256(self.encode_type(name).encode())

    def hash_struct(self, name, value) -> bytes:
        if not isinstance(value, dict):
            raise ValueError(f"{name}: expected an object")
        extra = set(value) - {f for f, _ in self.types[name]}
        if extra:
            raise ValueError(f"{name}: fields not in its type: {', '.join(sorted(extra))}")
        enc = self.type_hash(name)
        for f, t in self.types[name]:
            if f not in value:
                raise ValueError(f"{name}.{f} is missing")
            enc += self._encode_value(t, value[f], f"{name}.{f}")
        return keccak256(enc)

    def _encode_value(self, t, v, where) -> bytes:
        m = _ARRAY.match(t)
        if m:
            if not isinstance(v, list):
                raise ValueError(f"{where}: expected an array")
            if m[2] and len(v) != int(m[2]):
                raise ValueError(f"{where}: expected {m[2]} elements")
            return keccak256(b"".join(self._encode_value(m[1], x, f"{where}[{i}]") for i, x in enumerate(v)))
        if t in self.types:
            return self.hash_struct(t, v)
        return encode_atomic(t, v, where)

    def domain_separator(self) -> bytes:
        return self.hash_struct("EIP712Domain", self.domain)

    def hash(self) -> bytes:
        if self.primary == "EIP712Domain":
            return keccak256(b"\x19\x01" + self.domain_separator())
        return keccak256(b"\x19\x01" + self.domain_separator() + self.hash_struct(self.primary, self.message))

    # --- for display ---

    def chain_id(self):
        v = self.domain.get("chainId")
        return None if v is None else _int(v, "domain.chainId")

    def verifying_contract(self):
        v = self.domain.get("verifyingContract")
        return None if v is None else checksum(v)

    def lines(self, value=None, name=None, depth=1, limit=200) -> list:
        """The message, field by field, typed values formatted, for the user to read"""
        name = name or self.primary
        value = self.message if value is None else value
        out = []
        for f, t in self.types[name]:
            v = value.get(f)
            pad = "  " * depth
            base = self._base(t)
            if base in self.types and not _ARRAY.match(t):
                out.append(f"{pad}{f} ({t}):")
                out += self.lines(v, t, depth + 1, limit)
            elif _ARRAY.match(t) and base in self.types:
                out.append(f"{pad}{f} ({t}, {len(v)} entries):")
                for i, x in enumerate(v):
                    out.append(f"{pad}  [{i}]")
                    out += self.lines(x, base, depth + 2, limit)
            else:
                out.append(f"{pad}{f} ({t}): {_show(v, limit)}")
        return out


def _atomic_ok(t: str) -> bool:
    if t in ("address", "bool", "string", "bytes"):
        return True
    m = re.fullmatch(r"(u?int)(\d*)", t)
    if m:
        n = int(m[2] or 256)
        return n % 8 == 0 and 8 <= n <= 256
    m = re.fullmatch(r"bytes(\d+)", t)
    return bool(m) and 1 <= int(m[1]) <= 32


def _int(v, where) -> int:
    if isinstance(v, bool):
        raise ValueError(f"{where}: expected a number")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        try:
            return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s, 10)
        except ValueError:
            pass
    raise ValueError(f"{where}: expected a number, got {str(v)[:40]!r}")


def encode_atomic(t: str, v, where="value") -> bytes:
    if not _atomic_ok(t):
        raise ValueError(f"{where}: unknown type {t}")
    if t == "string":
        if not isinstance(v, str):
            raise ValueError(f"{where}: expected a string")
        return keccak256(v.encode())
    if t == "bytes":
        try:
            return keccak256(h2b(v) if isinstance(v, str) else bytes(v))
        except (ValueError, TypeError):
            raise ValueError(f"{where}: expected hex bytes") from None
    if t == "bool":
        if not isinstance(v, bool):
            if v in ("true", "false"):
                v = v == "true"
            else:
                raise ValueError(f"{where}: expected true or false")
        return int(v).to_bytes(32, "big")
    if t == "address":
        try:
            b = h2b(v)
        except (ValueError, AttributeError, TypeError):
            raise ValueError(f"{where}: expected an address") from None
        if len(b) != 20:
            raise ValueError(f"{where}: expected a 20-byte address")
        return b.rjust(32, b"\x00")
    m = re.fullmatch(r"bytes(\d+)", t)
    if m:
        try:
            b = h2b(v)
        except (ValueError, AttributeError, TypeError):
            raise ValueError(f"{where}: expected hex") from None
        if len(b) != int(m[1]):
            raise ValueError(f"{where}: expected {m[1]} bytes")
        return b.ljust(32, b"\x00")
    m = re.fullmatch(r"(u?int)(\d*)", t)
    n = int(m[2] or 256)
    x = _int(v, where)
    if m[1] == "uint":
        if not 0 <= x < 1 << n:
            raise ValueError(f"{where}: out of range for {t}")
        return x.to_bytes(32, "big")
    if not -(1 << (n - 1)) <= x < 1 << (n - 1):
        raise ValueError(f"{where}: out of range for {t}")
    return (x % (1 << 256)).to_bytes(32, "big")


def _show(v, limit):
    s = json.dumps(v) if not isinstance(v, str) else v
    s = s.encode("unicode_escape").decode() if not s.isprintable() else s
    return s if len(s) <= limit else s[:limit] + f"… ({len(s)} characters)"
