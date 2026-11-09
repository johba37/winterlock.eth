"""Hash-Based Key Derivation from BIP-39 (HBKD, a draft ERC): the secret seeds of hash-based keys from a BIP-39 phrase,
through PBKDF2-HMAC-SHA512 and keccak256 only, never BIP-32 or any elliptic-curve step.

    M         = the mnemonic's words as they appear in the BIP-39 wordlist, joined by single spaces
    S         = BIP-39 seed: PBKDF2-HMAC-SHA512(NFKD(M), "mnemonic" + NFKD(passphrase), 2048), 64 bytes
    R         = TH("HBKD/root/v1", S)                                      the root, 32 bytes (or 32 random bytes)
    stateless = TH("HBKD/stateless/v1", R || be32(account) || kt)
    stateful  = TH("HBKD/stateful/v1", R || be32(account) || kt || context || instance)
    app       = TH("HBKD/app/v1", R || be32(account) || keccak256(utf8(label)))

    TH(tag, data) = keccak256(keccak256(ascii(tag)) || data),  kt = keccak256(ascii(key type))

`bip39_seed` takes the words and refuses a word outside the English list, a count other than 12, 15, 18, 21 or 24, or
a failed checksum, as the ERC requires; what a member types is made canonical first (phrase.parse does that for
Winterlock's 24-word phrases). `bip39_seed_unchecked` is the PBKDF2 step alone, for tests and vectors.

A key type is a non-empty string of printable ASCII other than the space (0x21 to 0x7e) naming the scheme, its
parameters and its key generation; an account is 0 to 2^32 - 1. Labels are UTF-8 as given, without Unicode
normalisation (the ERC says they SHOULD be ASCII). A stateful instance's `instance` is 32 random bytes that the
caller generates and stores with the instance's state; nothing here is random.

Library code only: nothing in the signer derives keys this way. Winterlock's own keys (member.py: the member key,
device keys, tree secret seeds, the gas key) come from the phrase's entropy and are unrelated to these.
`winterlock_root` is the bridge: Winterlock's seed is a 24-word phrase's BIP-39 entropy (phrase.py), so the same
words also have an HBKD root.
"""

import hashlib
import unicodedata

from . import phrase
from .keccak import keccak256

ROOT_TAG = "HBKD/root/v1"
STATELESS_TAG = "HBKD/stateless/v1"
STATEFUL_TAG = "HBKD/stateful/v1"
APP_TAG = "HBKD/app/v1"
PBKDF2_ROUNDS = 2048  # BIP-39's


def tagged_hash(tag: str, data: bytes) -> bytes:
    """TH(tag, data) = keccak256(keccak256(ascii(tag)) || data)"""
    return keccak256(keccak256(tag.encode("ascii")) + data)


WORD_COUNTS = (12, 15, 18, 21, 24)  # BIP-39's mnemonic lengths


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


def _bytes(v, n: int, what: str) -> bytes:
    if not isinstance(v, (bytes, bytearray)) or len(v) != n:
        raise ValueError(f"{what} is {n} bytes")
    return bytes(v)


def _account(account) -> bytes:
    if not isinstance(account, int) or isinstance(account, bool) or not 0 <= account < 1 << 32:
        raise ValueError("an account is an integer from 0 to 2^32 - 1")
    return account.to_bytes(4, "big")


def is_key_type(key_type) -> bool:
    """Whether `key_type` is a key type: a non-empty string of printable ASCII other than the space, 0x21 to 0x7e"""
    return isinstance(key_type, str) and bool(key_type) and all("!" <= c <= "~" for c in key_type)


def _kt(key_type) -> bytes:
    if not is_key_type(key_type):
        raise ValueError("a key type is a non-empty string of printable ASCII other than the space (0x21 to 0x7e)")
    return keccak256(key_type.encode("ascii"))


def root_from_seed(seed: bytes) -> bytes:
    """The root R of a 64-byte BIP-39 seed"""
    return tagged_hash(ROOT_TAG, _bytes(seed, 64, "a BIP-39 seed"))


def stateless_seed(root: bytes, key_type: str, account: int = 0) -> bytes:
    """The seed of the stateless key of `key_type` for `account`: the same root always gives the same key"""
    return tagged_hash(STATELESS_TAG, _bytes(root, 32, "a root") + _account(account) + _kt(key_type))


def stateful_seed(root: bytes, key_type: str, context: bytes, instance: bytes, account: int = 0) -> bytes:
    """The seed of one instance of a stateful key. `instance` is 32 random bytes, made when the instance is created and
    stored with its state; never derive it."""
    return tagged_hash(STATEFUL_TAG, _bytes(root, 32, "a root") + _account(account) + _kt(key_type)
                       + _bytes(context, 32, "a context") + _bytes(instance, 32, "an instance"))


def app_secret(root: bytes, label: str, account: int = 0) -> bytes:
    """An application's secret under its label: any string, its UTF-8 bytes as given, without Unicode normalisation
    (labels SHOULD be ASCII). Not a key type's seed; it may be other key material, such as an ECDSA gas key."""
    if not isinstance(label, str):
        raise ValueError("a label is a string")
    return tagged_hash(APP_TAG, _bytes(root, 32, "a root") + _account(account) + keccak256(label.encode("utf-8")))


def winterlock_root(seed: bytes, passphrase: str = "") -> bytes:
    """The HBKD root of a Winterlock seed: its 24-word phrase (phrase.to_phrase; the seed is the phrase's BIP-39
    entropy, so the words are canonical and their checksum holds), through bip39_seed with `passphrase`, then
    root_from_seed. For a phrase as a member typed it: winterlock_root(phrase.to_seed(text))."""
    return root_from_seed(bip39_seed(phrase.to_phrase(seed), passphrase))
