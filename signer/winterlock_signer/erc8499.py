"""Winterlock's keys under ERC-8499 (Hash-Based Key Derivation from BIP-39, hbkd.py), as the signer app derives them
since 2026-11-14. The Rust core does the same (core/src/derive.rs, module erc8499); this is its reference.

    phrase root   R = HKDF-Extract("HBKD/v1", BIP-39 seed of the phrase's 24 words, no passphrase)
    device root   R = HKDF-Extract("HBKD/v1", 32 random bytes): a random root; the device has no phrase

    member key    stateless, phrase root, key type KEY_TYPE, L = 32, account 0
    device key    stateless, device root, key type KEY_TYPE, L = 32, account 0
    tree secret   stateful, the root of the device that holds the tree, key type tree_key_type(height), L = 32,
                  account 0; context = owner.tree_place_digest(chain, owner, safe, device, generation, start),
                  instance = the tree's salt (32 random bytes made with the tree and kept with it)
    gas key       application secret, phrase root, label GAS_LABEL, L = 32, account 0; refused unless 1 <= key < n

KEY_TYPE names leanSPHINCS over Keccak-256 at the parameters of leansphincs.py, with the top tree pruned to keep a
subtree of height 10 (STATELESS_B); its 32-byte seed is leansphincs.Key's seed. The ERC uses the same string in its
test cases. A tree's key type names Winterlock's WOTS parameter set D6 (wots.py) and the tree's height, both of which
change its root; the place goes into the context. One phrase is one member, so every value uses account 0.

The command-line signer (member.py) keeps the earlier derivation, from the phrase's entropy under Keccak labels, for the
homes it already has. Keys of the two derivations are unrelated: the same words give another member key and owner.
"""
from . import hbkd, leansphincs, owner

KEY_TYPE = "leanSphincs-keccak/wambsgans-keccak/b10"
TREE_KEY_TYPE = "winterlock-wots-d6-keccak/tree-h"  # + the height in decimal
GAS_LABEL = "winterlock.eth/gas"
ACCOUNT = 0
STATELESS_B = 10
SEED_LEN = 32

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

assert leansphincs.DEFAULT_B == STATELESS_B


def phrase_root(seed: bytes) -> bytes:
    """The root of a recovery phrase, from its seed (the phrase's BIP-39 entropy): PBKDF2 over the 24 words, no
    passphrase, then HKDF-Extract"""
    return hbkd.winterlock_root(seed, "")


def device_root(random_bytes: bytes) -> bytes:
    """A device's random root from the 32 random bytes it keeps"""
    if len(random_bytes) != 32:
        raise ValueError("a device's random input is 32 bytes")
    return hbkd.root(random_bytes)


def stateless_key_seed(root: bytes) -> bytes:
    """The leanSphincs seed of the root's stateless key: the member key of a phrase root, the device key of a device
    root"""
    return hbkd.stateless_seed(root, KEY_TYPE, SEED_LEN, ACCOUNT)


def stateless_key(root: bytes) -> leansphincs.Key:
    return leansphincs.Key(stateless_key_seed(root), STATELESS_B)


def identity_of(seed: bytes):
    """(member key, owner address) of a recovery phrase's seed"""
    key = stateless_key(phrase_root(seed)).public_key
    return key, owner.owner_address(key)


def tree_key_type(height: int) -> str:
    if not isinstance(height, int) or not 1 <= height <= owner.MAX_HEIGHT:
        raise ValueError(f"a tree is 1 to {owner.MAX_HEIGHT} high")
    return f"{TREE_KEY_TYPE}{height}"


def tree_context(chain: int, owner_addr: str, safe: str, device: int, generation: int, start: int) -> bytes:
    return owner.tree_place_digest(chain, owner_addr, safe, device, generation, start)


def tree_secret_seed(root: bytes, rec: dict, height: int) -> bytes:
    """The secret seed (wots.Prf's skSeed) of a tree: `rec` has chain, owner, safe, device, gen, start and salt, as
    the key log keeps them"""
    context = tree_context(rec["chain"], rec["owner"], rec["safe"], rec["device"], rec["gen"], rec["start"])
    salt = bytes.fromhex(rec["salt"][2:] if rec["salt"].startswith("0x") else rec["salt"])
    return hbkd.stateful_seed(root, tree_key_type(height), SEED_LEN, context, salt, ACCOUNT)


def gas_key(root: bytes) -> bytes:
    """The gas account's private key of a phrase root"""
    key = hbkd.app_secret(root, GAS_LABEL, SEED_LEN, ACCOUNT)
    if not 1 <= int.from_bytes(key, "big") < _SECP256K1_N:
        raise ValueError("the gas key isn't a secp256k1 private key")
    return key
