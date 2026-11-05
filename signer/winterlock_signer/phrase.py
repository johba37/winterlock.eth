"""The recovery phrase: 24 BIP-39 English words that encode the signer's 32-byte seed itself.

Derivation: the phrase's BIP-39 *entropy* is the seed (`Mnemonic.to_entropy`), 256 bits plus BIP-39's 8-bit SHA-256
checksum. It is not BIP-39's PBKDF2 "seed" (`to_seed`), and there is no BIP-39 passphrase. Why:
  - The signer's only secret is 32 bytes (member.py). 24 words carry exactly those bits, so the phrase and the seed are
    two spellings of one value: a restore decodes, it doesn't derive.
  - Signers set up with a hex seed (before phrases) have a phrase too, with the same owner address and stateless key.
  - No BIP-39 passphrase: it would be a second secret to back up, and a typo in it gives another valid identity
    rather than an error. The passphrase on the seed file (seedfile.py) protects the copy on the device instead.
  - The phrase is for this signer only. Deriving from the entropy has precedents (Cardano's Icarus scheme,
    substrate-bip39); a wallet that imports these words derives unrelated keys through PBKDF2 and BIP-32, but must
    never be given them, since whoever holds the words holds the seed.
Encoding and checksum come from `mnemonic`, the reference implementation that BIP-39 cites; the tests check it
against BIP-39's published vectors.
"""

import re
import secrets

from mnemonic import Mnemonic

WORDS = 24
CHECK_WORDS = 3  # words asked in a backup check
_M = Mnemonic("english")
_INDEX = {w: i for i, w in enumerate(_M.wordlist)}


class PhraseError(ValueError):
    pass


def to_phrase(seed: bytes) -> list:
    if len(seed) != 32:
        raise ValueError("a seed is 32 bytes")
    return _M.to_mnemonic(bytes(seed)).split()


def word(token: str) -> str:
    """A word of the list from what a member typed: the word itself, or its first four letters (unique in the English
    list); None if neither"""
    t = token.strip().lower()
    if t in _INDEX:
        return t
    if len(t) >= 4:
        hits = [w for w in _M.wordlist if w.startswith(t)]
        if len(hits) == 1:
            return hits[0]
    return None


def parse(text: str) -> list:
    """The 24 words of a phrase as typed: any case and spacing, commas, numbering ("1." "2)") and four-letter
    abbreviations accepted. Raises PhraseError naming the first problem."""
    tokens = [t for t in re.split(r"[\s,;]+", text.strip()) if t and not re.fullmatch(r"\d+[.):]?", t)]
    if len(tokens) != WORDS:
        raise PhraseError(f"a recovery phrase has {WORDS} words; this has {len(tokens)}")
    words = []
    for n, t in enumerate(tokens, 1):
        w = word(t)
        if w is None:
            raise PhraseError(f"word {n} ({t!r}) isn't a word of the BIP-39 English list")
        words.append(w)
    return words


def to_seed(text: str) -> bytes:
    """The seed a phrase encodes. Also accepts a legacy seed backup: 64 hex digits."""
    raw = text.strip()
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", raw):
        return bytes.fromhex(raw[-64:])
    words = parse(raw)
    try:
        seed = bytes(_M.to_entropy(words))
    except ValueError:
        raise PhraseError("the words don't match their checksum: one of them is wrong, or two are swapped") from None
    if len(seed) != 32:
        raise PhraseError("not a 24-word phrase")
    return seed


def check_positions(k: int = CHECK_WORDS) -> list:
    """k distinct word positions (1-based, ascending) for a backup check, chosen at random"""
    return sorted(secrets.SystemRandom().sample(range(1, WORDS + 1), k))


def matches(words: list, position: int, answer: str) -> bool:
    return word(answer or "") == words[position - 1]


def columns(words: list, cols: int = 4) -> list:
    """The phrase as numbered lines, in columns read top to bottom"""
    rows = (len(words) + cols - 1) // cols
    lines = []
    for r in range(rows):
        cells = [f"{c * rows + r + 1:2}. {words[c * rows + r]:<9}" for c in range(cols) if c * rows + r < len(words)]
        lines.append("   ".join(cells).rstrip())
    return lines
