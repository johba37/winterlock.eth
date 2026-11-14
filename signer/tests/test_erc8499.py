"""Winterlock's keys under ERC-8499 (erc8499.py): the ERC's own test values where they meet Winterlock's, each value
from the ERC's primitives by hand, and the separation from the earlier derivation."""
import os
import unittest

from winterlock_signer import erc8499, hbkd, member, owner, phrase
from winterlock_signer.abi import checksum
from winterlock_signer.ethtx import Account
from winterlock_signer.keccak import keccak256

from .test_hbkd import ABANDON, ERC, KEY_TYPE, h

SEED = keccak256(b"winterlock erc8499 test seed")
PLACE = {"chain": 11155111, "owner": checksum(keccak256(b"owner")[12:]), "safe": checksum(keccak256(b"safe")[12:]),
         "device": 2, "gen": 3, "start": 77, "salt": "0x" + keccak256(b"salt").hex()}


class TheErcsValues(unittest.TestCase):
    def test_the_member_key_type_is_the_ercs_example(self):
        self.assertEqual(erc8499.KEY_TYPE, KEY_TYPE)

    def test_zero_seed(self):
        """The all-zero seed is the ERC's first phrase ("abandon" 23 times, "art"), so its member key's seed is the
        ERC's stateless seed of account 0"""
        self.assertEqual(" ".join(phrase.to_phrase(bytes(32))), ABANDON)
        root = erc8499.phrase_root(bytes(32))
        self.assertEqual(root, h(ERC[0][3]))
        self.assertEqual(erc8499.stateless_key_seed(root), h(ERC[0][4]))


class ByHand(unittest.TestCase):
    def test_phrase_root(self):
        words = phrase.to_phrase(SEED)
        self.assertEqual(erc8499.phrase_root(SEED), hbkd.root(hbkd.bip39_seed(words, "")))

    def test_device_root(self):
        r = os.urandom(32)
        self.assertEqual(erc8499.device_root(r), hbkd.hkdf_extract(b"HBKD/v1", r))
        for n in (0, 31, 33, 64):
            with self.assertRaises(ValueError):
                erc8499.device_root(bytes(n))

    def test_stateless_key(self):
        root = erc8499.phrase_root(SEED)
        info = bytes([1]) + bytes(4) + (32).to_bytes(2, "big") + bytes([len(KEY_TYPE)]) + KEY_TYPE.encode()
        self.assertEqual(erc8499.stateless_key_seed(root), hbkd.hkdf_expand(root, info, 32))
        key = erc8499.stateless_key(root)
        self.assertEqual(key.seed, erc8499.stateless_key_seed(root))
        self.assertEqual(key.b, 10)
        mk, owner_addr = erc8499.identity_of(SEED)
        self.assertEqual(mk, key.public_key)
        self.assertEqual(owner_addr, owner.owner_address(mk))

    def test_tree_secret(self):
        root = erc8499.device_root(keccak256(b"device"))
        p = PLACE
        context = keccak256(owner.TREE_SEED_DOMAIN + b"".join(
            v.to_bytes(32, "big") for v in (p["chain"], int(p["owner"], 16), int(p["safe"], 16), p["device"], p["gen"],
                                             p["start"])))
        self.assertEqual(erc8499.tree_context(p["chain"], p["owner"], p["safe"], p["device"], p["gen"], p["start"]),
                         context)
        # the tree's public seed is the context's first 16 bytes
        self.assertEqual(owner.tree_seed(p["chain"], p["owner"], p["safe"], p["device"], p["gen"], p["start"]),
                         int.from_bytes(context[:16], "big"))
        kt = b"winterlock-wots-d6-keccak/tree-h10"
        info = bytes([2]) + bytes(4) + (32).to_bytes(2, "big") + bytes([len(kt)]) + kt + context + h(p["salt"][2:])
        self.assertEqual(erc8499.tree_secret_seed(root, p, 10), hbkd.hkdf_expand(root, info, 32))
        # the height, the salt and every part of the place change it
        base = erc8499.tree_secret_seed(root, p, 10)
        self.assertNotEqual(erc8499.tree_secret_seed(root, p, 11), base)
        for k, v in (("chain", 1), ("device", 1), ("gen", 4), ("start", 78), ("salt", "0x" + "00" * 32),
                     ("safe", PLACE["owner"]), ("owner", PLACE["safe"])):
            self.assertNotEqual(erc8499.tree_secret_seed(root, {**p, k: v}, 10), base, k)

    def test_tree_key_types(self):
        self.assertEqual(erc8499.tree_key_type(1), "winterlock-wots-d6-keccak/tree-h1")
        self.assertEqual(erc8499.tree_key_type(40), "winterlock-wots-d6-keccak/tree-h40")
        for bad in (0, 41, -1, 10.0, "10", None):
            with self.assertRaises(ValueError):
                erc8499.tree_key_type(bad)
        for height in range(1, 41):
            self.assertTrue(hbkd.is_key_type(erc8499.tree_key_type(height)))

    def test_gas_key(self):
        root = erc8499.phrase_root(SEED)
        label = b"winterlock.eth/gas"
        info = bytes([3]) + bytes(4) + (32).to_bytes(2, "big") + bytes([len(label)]) + label
        key = erc8499.gas_key(root)
        self.assertEqual(key, hbkd.hkdf_expand(root, info, 32))
        Account(key.hex())  # a secp256k1 private key


class NotTheEarlierKeys(unittest.TestCase):
    def test_every_value_differs(self):
        root = erc8499.phrase_root(SEED)
        self.assertNotEqual(erc8499.stateless_key_seed(root), member._abi_label(member.MEMBER_KEY_LABEL, SEED))
        self.assertNotEqual(erc8499.stateless_key_seed(erc8499.device_root(SEED)),
                            member._abi_label(member.DEVICE_KEY_LABEL, SEED))
        self.assertNotEqual(erc8499.identity_of(SEED)[1], member.identity_of(SEED)[1])

    def test_member_and_device_keys_of_one_input_differ(self):
        """The same 32 bytes as a phrase's seed and as a device's random input give two roots"""
        self.assertNotEqual(erc8499.phrase_root(SEED), erc8499.device_root(SEED))


if __name__ == "__main__":
    unittest.main()
