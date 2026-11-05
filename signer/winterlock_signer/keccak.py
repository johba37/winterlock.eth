"""keccak256 as Ethereum uses it (original Keccak padding 0x01, not SHA3-256), from a C-backed library.

Backends, fastest first (pip install -r signer/requirements.txt):
  safe-pysha3   sha3.keccak_256, about 1 microsecond per short hash
  pycryptodome  Crypto.Hash.keccak, about 7 microseconds per short hash (call overhead)
There is no pure-Python fallback: tree generation would take minutes.
"""

try:
    from sha3 import keccak_256 as _k

    def keccak256(data: bytes) -> bytes:
        return _k(data).digest()

    BACKEND = "safe-pysha3"
except ImportError:  # pragma: no cover - depends on the environment
    try:
        from Crypto.Hash import keccak as _keccak

        _new = _keccak.new

        def keccak256(data: bytes) -> bytes:
            return _new(digest_bits=256, data=data).digest()

        BACKEND = "pycryptodome"
    except ImportError:
        raise ImportError("no C-backed keccak256: pip install -r signer/requirements.txt "
                          "(safe-pysha3, or pycryptodome)") from None

assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "not Keccak-256"
