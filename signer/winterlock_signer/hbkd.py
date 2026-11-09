"""Hash-Based Key Derivation from BIP-39 (HBKD, a draft ERC): the secret seeds of hash-based keys from a BIP-39 phrase,
through HMAC-SHA512 only (BIP-39's PBKDF2, then HKDF-SHA512), never BIP-32 or any elliptic-curve step.

    M     = the mnemonic's words as they appear in the BIP-39 wordlist, joined by single spaces
    S     = BIP-39 seed: PBKDF2-HMAC-SHA512(NFKD(M), "mnemonic" + NFKD(passphrase), 2048), 64 bytes
    R     = HKDF-Extract(salt = "HBKD/v1", IKM)        the root, 64 bytes; IKM is S, or at least 32 random bytes
    value = HKDF-Expand(R, info, L)                    32 <= L <= 16320 (255 blocks of SHA-512)
    info  = purpose || be32(account) || be16(L) || len8(name) || name || tail

    stateless key:      purpose 0x01, name = ascii(key type), tail empty
    stateful key:       purpose 0x02, name = ascii(key type), tail = context || instance (32 bytes each)
    application secret: purpose 0x03, name = utf8(label), tail empty

`bip39_seed` takes the words and refuses a word outside the English list, a count other than 12, 15, 18, 21 or 24, or
a failed checksum, as the ERC requires; what a member types is made canonical first (phrase.parse does that for
Winterlock's 24-word phrases). `bip39_seed_unchecked` is the PBKDF2 step alone, for tests and vectors.

A key type is 1 to 255 bytes of printable ASCII other than the space (0x21 to 0x7e) naming the scheme, its parameters,
its seed length L and its key generation; an account is 0 to 2^32 - 1. A label is 1 to 255 bytes of UTF-8 as given,
without Unicode normalisation (the ERC says labels SHOULD be ASCII). A stateful instance's `instance` is 32 random bytes
that the caller generates and stores with the instance's state; nothing here is random.

SLH-DSA (FIPS 205): the twelve parameter set names are key types of their own, stateless only, with L = 3n; the seed
is SK.seed || SK.prf || PK.seed, the inputs of slh_keygen_internal (`slh_dsa_seeds`). Key generation itself is not
here.

Every refusal is a ValueError. Byte inputs may be bytes or bytearray.

Library code only: nothing in the signer derives keys this way. Winterlock's own keys (member.py: the member key,
device keys, tree secret seeds, the gas key) come from the phrase's entropy and are unrelated to these.
`winterlock_root` is the bridge: Winterlock's seed is a 24-word phrase's BIP-39 entropy (phrase.py), so the same
words also have an HBKD root.
"""

import hashlib
import hmac
import unicodedata

from . import phrase

SALT = b"HBKD/v1"  # HKDF-Extract's salt: the ERC's name and version
STATELESS, STATEFUL, APPLICATION = 1, 2, 3  # the purpose byte of info
HASH_LEN = 64  # SHA-512
MIN_LENGTH, MAX_LENGTH = 32, 255 * HASH_LEN  # L: the ERC's floor, and RFC 5869's ceiling of 16320
MIN_IKM = 32  # random input key material: at least 32 bytes
PBKDF2_ROUNDS = 2048  # BIP-39's
WORD_COUNTS = (12, 15, 18, 21, 24)  # BIP-39's mnemonic lengths
# the hash length n of each SLH-DSA parameter set, by its name in FIPS 205; its seed is L = 3n bytes
SLH_DSA_N = {f"SLH-DSA-{h}-{bits}{v}": bits // 8 for h in ("SHA2", "SHAKE") for bits in (128, 192, 256) for v in "sf"}


def _bytes(v, what: str) -> bytes:
    if not isinstance(v, (bytes, bytearray)):
        raise ValueError(f"{what} is bytes")
    return bytes(v)


def _fixed(v, n: int, what: str) -> bytes:
    v = _bytes(v, what)
    if len(v) != n:
        raise ValueError(f"{what} is {n} bytes")
    return v


def _int(v, lo: int, hi: int, what: str) -> int:
    if type(v) is not int or not lo <= v <= hi:  # type(): not a bool, as the ERC's reference has it
        raise ValueError(f"{what} is an integer from {lo} to {hi}")
    return v


# --- HKDF-SHA512 (RFC 5869) ---

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, IKM) = HMAC-SHA512(key = salt, message = IKM), 64 bytes. An empty salt is HMAC's empty key,
    the same as RFC 5869's default of 64 zero bytes."""
    return hmac.new(_bytes(salt, "a salt"), _bytes(ikm, "input key material"), hashlib.sha512).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand(PRK, info, L): T(1) || T(2) || ... cut to L bytes, T(i) = HMAC-SHA512(PRK, T(i-1) || info || i).
    L is 0 to 255 * 64 = 16320 (RFC 5869's limit); HBKD's own values are at least 32 bytes."""
    prk, info = _bytes(prk, "a pseudorandom key"), _bytes(info, "info")
    length = _int(length, 0, MAX_LENGTH, "an HKDF output length")
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        out += block
        counter += 1
    return out[:length]


# --- BIP-39 ---

def bip39_seed(words, passphrase: str = "") -> bytes:
    """BIP-39's 64-byte seed of a mnemonic, given as its words exactly as they appear in the English wordlist (a list
    or tuple), and a passphrase ("" for none). Refused (ValueError) unless the count is 12, 15, 18, 21 or 24, every word
    is in the list and the BIP-39 checksum holds: the draft ERC makes wallets reject a mnemonic that fails, since a
    mistyped word that passed would restore other keys. Typed text (other case, spacing, abbreviations) must be made
    canonical first."""
    if not isinstance(words, (list, tuple)) or not all(isinstance(w, str) for w in words):
        raise ValueError("a mnemonic is a list of words")
    if len(words) not in WORD_COUNTS:
        raise ValueError(f"a mnemonic has 12, 15, 18, 21 or 24 words; this has {len(words)}")
    for n, w in enumerate(words, 1):
        if w not in phrase._INDEX:
            raise ValueError(f"word {n} ({w!r}) isn't a word of the BIP-39 English list as it appears there")
    sentence = " ".join(words)
    if not phrase._M.check(sentence):
        raise ValueError("the words don't match their BIP-39 checksum")
    return bip39_seed_unchecked(sentence, passphrase)


def bip39_seed_unchecked(sentence: str, passphrase: str = "") -> bytes:
    """The PBKDF2 step alone: BIP-39's seed of any sentence, both inputs NFKD-normalised, with no word list and no
    checksum. Not conforming on its own (the ERC requires canonical words and a valid checksum): use bip39_seed."""
    if not isinstance(sentence, str) or not isinstance(passphrase, str):
        raise ValueError("a mnemonic sentence and a passphrase are strings")
    m = unicodedata.normalize("NFKD", sentence).encode("utf-8")
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", m, salt, PBKDF2_ROUNDS)


# --- the root and the derived values ---

def root(ikm: bytes) -> bytes:
    """The root R = HKDF-Extract("HBKD/v1", IKM), 64 bytes. IKM is a BIP-39 seed (bip39_seed), or at least 32 bytes
    from a cryptographically secure random number generator for a key holder without a phrase. No upper bound: IKM is
    HMAC's message."""
    ikm = _bytes(ikm, "input key material")
    if len(ikm) < MIN_IKM:
        raise ValueError(f"input key material is at least {MIN_IKM} bytes; this is {len(ikm)}")
    return hkdf_extract(SALT, ikm)


def is_key_type(key_type) -> bool:
    """Whether `key_type` is a key type: 1 to 255 characters of printable ASCII other than the space, 0x21 to 0x7e"""
    return isinstance(key_type, str) and 1 <= len(key_type) <= 255 and all("!" <= c <= "~" for c in key_type)


def _key_type(key_type) -> bytes:
    if not is_key_type(key_type):
        raise ValueError("a key type is 1 to 255 characters of printable ASCII other than the space (0x21 to 0x7e)")
    return key_type.encode("ascii")


def _label(label) -> bytes:
    if not isinstance(label, str):
        raise ValueError("a label is a string")
    try:
        b = label.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("a label is UTF-8 (this has a lone surrogate)") from None
    if not 1 <= len(b) <= 255:
        raise ValueError(f"a label is 1 to 255 bytes of UTF-8; this is {len(b)}")
    return b


def info(purpose: int, account: int, length: int, name: bytes, tail: bytes = b"") -> bytes:
    """purpose || be32(account) || be16(L) || len8(name) || name || tail: HKDF-Expand's info for one derived value.
    Checks the layout only (purpose, account, L, a name of 1 to 255 bytes, a 64-byte tail exactly when stateful);
    stateless_seed, stateful_seed and app_secret also check the key type or label."""
    if type(purpose) is not int or purpose not in (STATELESS, STATEFUL, APPLICATION):
        raise ValueError("a purpose is 1 (stateless), 2 (stateful) or 3 (application)")
    account = _int(account, 0, (1 << 32) - 1, "an account")
    length = _int(length, MIN_LENGTH, MAX_LENGTH, "a length")
    name, tail = _bytes(name, "a key type or label"), _bytes(tail, "a tail")
    if not 1 <= len(name) <= 255:
        raise ValueError(f"a key type or label is 1 to 255 bytes; this is {len(name)}")
    if len(tail) != (64 if purpose == STATEFUL else 0):
        raise ValueError("the tail is context || instance (64 bytes) for a stateful key, and empty otherwise")
    return bytes([purpose]) + account.to_bytes(4, "big") + length.to_bytes(2, "big") + bytes([len(name)]) + name + tail


def _root(value) -> bytes:
    return _fixed(value, 64, "a root")


def stateless_seed(root: bytes, key_type: str, length: int, account: int = 0) -> bytes:
    """The `length`-byte seed of the stateless key of `key_type` for `account`: the same root always gives the same
    key. The key type defines `length`; an SLH-DSA key type's is 3n (SLH_DSA_N)."""
    root, kt = _root(root), _key_type(key_type)
    if key_type in SLH_DSA_N and length != 3 * SLH_DSA_N[key_type]:
        raise ValueError(f"{key_type}'s seed is {3 * SLH_DSA_N[key_type]} bytes (3n)")
    return hkdf_expand(root, info(STATELESS, account, length, kt), length)


def stateful_seed(root: bytes, key_type: str, length: int, context: bytes, instance: bytes, account: int = 0) -> bytes:
    """The `length`-byte seed of one instance of a stateful key. `context` is 32 bytes the application defines;
    `instance` is 32 random bytes, made when the instance is created and stored with its state: never derive it.
    SLH-DSA key types are stateless and refused here."""
    root, kt = _root(root), _key_type(key_type)
    if key_type in SLH_DSA_N:
        raise ValueError(f"{key_type} is a stateless key type")
    tail = _fixed(context, 32, "a context") + _fixed(instance, 32, "an instance")
    return hkdf_expand(root, info(STATEFUL, account, length, kt, tail), length)


def app_secret(root: bytes, label: str, length: int = 32, account: int = 0) -> bytes:
    """An application's `length`-byte secret under its label: 1 to 255 bytes of UTF-8 as given, without Unicode
    normalisation (labels SHOULD be ASCII, and namespaced). Not a key type's seed; it may be other key material, such
    as an ECDSA gas key."""
    root, lb = _root(root), _label(label)
    return hkdf_expand(root, info(APPLICATION, account, length, lb), length)


def slh_dsa_seeds(root: bytes, key_type: str, account: int = 0) -> tuple:
    """(SK.seed, SK.prf, PK.seed), n bytes each: the inputs of slh_keygen_internal (FIPS 205, Algorithm 18) for an
    SLH-DSA key type, cut from its 3n-byte stateless seed in that order. The public key is PK.seed || PK.root."""
    if not isinstance(key_type, str) or key_type not in SLH_DSA_N:
        raise ValueError("an SLH-DSA key type is a FIPS 205 parameter set's name, such as SLH-DSA-SHA2-128s")
    n = SLH_DSA_N[key_type]
    seed = stateless_seed(root, key_type, 3 * n, account)
    return seed[:n], seed[n:2 * n], seed[2 * n:]


def winterlock_root(seed: bytes, passphrase: str = "") -> bytes:
    """The 64-byte HBKD root of a Winterlock seed: its 24-word phrase (phrase.to_phrase; the seed is the phrase's BIP-39
    entropy, so the words are canonical and their checksum holds), through bip39_seed with `passphrase`, then root. For
    a phrase as a member typed it: winterlock_root(phrase.to_seed(text))."""
    return root(bip39_seed(phrase.to_phrase(seed), passphrase))
