"""The seed at rest: the file `seed` in the signer's directory, mode 600.

Encrypted (the default), one JSON object:
  {"v": 1, "kdf": "scrypt", "n": 262144, "r": 8, "p": 1, "salt": 16 bytes hex,
   "aead": "chacha20-poly1305", "nonce": 12 bytes hex, "ct": 48 bytes hex}
  key = scrypt(passphrase, salt, n, r, p, 32 bytes): hashlib's (OpenSSL). n = 2^18, r = 8, p = 1 is the Ethereum
        keystore's "standard" setting: 256 MiB and about a second per unlock, so each guess at a stolen file costs as
        much. The passphrase is NFKC-normalised first, as BIP-39 does, so the same characters typed on another system
        give the same key.
  ct  = ChaCha20-Poly1305(key, nonce) over the 32-byte seed, tag appended (pycryptodome). The associated data is the
        header (every field but ct, canonical JSON), so a changed parameter fails the tag like a wrong passphrase.
  Each write draws a fresh salt and nonce, so a key and nonce never meet twice.
Plaintext: the seed as 64 hex digits and a newline, the format before passphrases. It is what `init
--insecure-plaintext-seed` writes (tests only) and what older signers have; `passphrase` encrypts it.
"""

import hashlib
import json
import os
import secrets
import unicodedata

from Crypto.Cipher import ChaCha20_Poly1305

SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 18, 8, 1
MIN_PASSPHRASE = 8


class WrongPassphrase(Exception):
    pass


class SeedFileError(Exception):
    pass


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not (n >= 2 and n & (n - 1) == 0 and n <= 1 << 22 and 1 <= r <= 32 and 1 <= p <= 16):
        raise SeedFileError("unusual scrypt parameters in the seed file: refusing")
    pw = unicodedata.normalize("NFKC", passphrase).encode()
    return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=256 * r * n + (1 << 24), dklen=32)


def encrypt(seed: bytes, passphrase: str, n: int = SCRYPT_N) -> str:
    if len(seed) != 32:
        raise ValueError("a seed is 32 bytes")
    head = {"v": 1, "kdf": "scrypt", "n": n, "r": SCRYPT_R, "p": SCRYPT_P, "salt": secrets.token_hex(16),
            "aead": "chacha20-poly1305", "nonce": secrets.token_hex(12)}
    c = ChaCha20_Poly1305.new(key=_key(passphrase, bytes.fromhex(head["salt"]), n, SCRYPT_R, SCRYPT_P),
                              nonce=bytes.fromhex(head["nonce"]))
    c.update(_canonical(head))
    ct, tag = c.encrypt_and_digest(seed)
    return json.dumps(dict(head, ct=(ct + tag).hex()), sort_keys=True) + "\n"


def decrypt(text: str, passphrase: str) -> bytes:
    try:
        doc = json.loads(text)
        head = {k: v for k, v in doc.items() if k != "ct"}
        if head.get("v") != 1 or head.get("kdf") != "scrypt" or head.get("aead") != "chacha20-poly1305":
            raise SeedFileError("unknown seed file format")
        blob = bytes.fromhex(doc["ct"])
        salt, nonce = bytes.fromhex(head["salt"]), bytes.fromhex(head["nonce"])
        n, r, p = int(head["n"]), int(head["r"]), int(head["p"])
    except (ValueError, KeyError, TypeError, AttributeError):
        raise SeedFileError("the seed file is damaged") from None
    c = ChaCha20_Poly1305.new(key=_key(passphrase, salt, n, r, p), nonce=nonce)
    c.update(_canonical(head))
    try:
        seed = c.decrypt_and_verify(blob[:-16], blob[-16:])
    except ValueError:
        raise WrongPassphrase("wrong passphrase (or a changed seed file)") from None
    if len(seed) != 32:
        raise SeedFileError("the seed file holds no 32-byte seed")
    return seed


def kind(path: str) -> str:
    """"encrypted", "plaintext" or "missing", without decrypting"""
    if not os.path.exists(path):
        return "missing"
    with open(path) as f:
        head = f.read(1)
    return "encrypted" if head == "{" else "plaintext"


def describe(path: str) -> str:
    k = kind(path)
    if k == "encrypted":
        with open(path) as f:
            d = json.load(f)
        return f"encrypted with a passphrase (scrypt n=2^{int(d['n']).bit_length() - 1}, r={d['r']}, p={d['p']}; " \
               f"{d['aead']})"
    if k == "plaintext":
        return "NOT encrypted (plain hex): run `passphrase` to encrypt it"
    return "not on this device"


def read(path: str, passphrase_fn) -> bytes:
    """The seed; passphrase_fn() is called only for an encrypted file"""
    with open(path) as f:
        text = f.read()
    if text.startswith("{"):
        return decrypt(text, passphrase_fn())
    try:
        seed = bytes.fromhex(text.strip().removeprefix("0x"))
    except ValueError:
        raise SeedFileError("the seed file is damaged") from None
    if len(seed) != 32:
        raise SeedFileError("seed file must hold 32 bytes of hex")
    return seed


def _fsync_dir(d: str):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path: str, seed: bytes, passphrase: str = None, n: int = SCRYPT_N, replace: bool = False):
    """Writes the seed, encrypted unless passphrase is None, through a temporary file and a rename (fsynced), so a
    crash leaves the old file or the new one, never half of one"""
    if passphrase is not None and len(passphrase) < MIN_PASSPHRASE:
        raise ValueError(f"a passphrase needs at least {MIN_PASSPHRASE} characters")
    text = encrypt(seed, passphrase, n) if passphrase is not None else seed.hex() + "\n"
    if not replace and os.path.exists(path):
        raise FileExistsError(path)
    tmp = path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(os.path.abspath(path)))


def wipe(path: str):
    """Overwrites the file with zeros, then removes it. On SSDs and copy-on-write file systems old blocks may survive:
    this is a courtesy on top of the encryption, not a guarantee."""
    if not os.path.exists(path):
        return
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(b"\0" * size)
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)
    _fsync_dir(os.path.dirname(os.path.abspath(path)))
