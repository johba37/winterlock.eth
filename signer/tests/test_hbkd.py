"""Hash-Based Key Derivation from BIP-39 (draft ERC): the ERC's test vectors, BIP-39's own, and the input checks."""
import hashlib
import os
import unicodedata
import unittest

from mnemonic import Mnemonic

from winterlock_signer import hbkd, leansphincs, phrase
from winterlock_signer.keccak import keccak256

# The ERC's Test Cases (draft, commit 6a5dbdca): shared inputs, then per phrase and passphrase S, R, the stateless
# seeds of accounts 0 and 1, the stateful seed of account 0 and the application secret.
KEY_TYPE = "leanSphincs-keccak/wambsgans-keccak/b10"
CONTEXT = bytes(range(32))
INSTANCE = bytes([0xA5] * 32)
LABEL = "example.app.gas"
ABANDON = "abandon " * 23 + "art"
LEGAL = "legal winner thank year wave sausage worth useful legal winner thank yellow"
ERC = [
    (ABANDON, "",
     "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"
     "5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
     "3e6cf3c3a1af758759e9337eed8a7d4723e23a378c1e471a28baf4db10569e01",
     "373d01c6fca9738080cf1f4186fd517ad450d134d31bcb3aecb3bb4dd340d419",
     "8fc21bcff345bc88b412b2d4a3a8c2a0637d3ea05e187969d3ce0aa195ca2e7b",
     "e8e1e2bc45a1a0785011021d34b601833c4e1f0fcfabb19daa53d0ffd1a47939",
     "fcec37951685415d996fb166633bce4891ffb650ef121354129c1fe8b6d850c7"),
    (ABANDON, "TREZOR",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
     "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
     "04ed2bcdefde1aad10dc37dd64ef968d3229c9b468a8407d76b1f969a2d6b335",
     "d4438a8e081bd7cf04b632dc763fcff549eeb1f1fbea78e759d22041aa0ef295",
     "44a8d35e0d3010c16f5256426c2c0c6b267f5a121928adcb21e6f934de5711b7",
     "9e65891f41a97f6235a55233a3117095a86fc831b3bfc72eb429ba5c77e2160e",
     "1da8fa73176e364da9784eeff604937153bf9565acff932d558e678c9aca6eff"),
    (LEGAL, "TREZOR",
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
     "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
     "fed41ed04e47cf6b7cebabb5fce9f214fc6a5e5b8ddddb38c50cbc7feaa7dee4",
     "55b86642971ca5d137f1ce48ad68d0c79310aff96ae70b5b061dc696e5a7dd03",
     "3347fbb9f4f0adaf77a518ccd4ff34d47247120a8b32ecf7d13b5b5575170d7e",
     "37306d29c12f6f5490989ce516eada140d00038ec48979584aaec7a42c00b37a",
     "85c53633bb07dddb69b8cabe0f883410574b5db9bf90775b93b45620120227b4"),
]
# Informative: the public key (root || public parameter) of the first case's account-0 stateless key under KEY_TYPE
ERC_PUBLIC_KEY = "14ea1515b0bb93f5bf7151fbad2800ca37389f2020209a2d0e55ed7fd6b2977e"

# BIP-39's published seeds for these two phrases with passphrase "TREZOR" (trezor/python-mnemonic, vectors.json), which
# the ERC says its two TREZOR values of S are
BIP39_TREZOR = {
    ABANDON: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
             "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    LEGAL: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
           "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
}


def h(x: str) -> bytes:
    return bytes.fromhex(x)


class ErcVectors(unittest.TestCase):
    def test_every_value(self):
        for m, p, s, r, sl0, sl1, sf0, app in ERC:
            with self.subTest(mnemonic=m[:20], passphrase=p):
                self.assertEqual(hbkd.bip39_seed(m, p), h(s))
                self.assertEqual(hbkd.root_from_seed(h(s)), h(r))
                self.assertEqual(hbkd.stateless_seed(h(r), KEY_TYPE), h(sl0))
                self.assertEqual(hbkd.stateless_seed(h(r), KEY_TYPE, 0), h(sl0))
                self.assertEqual(hbkd.stateless_seed(h(r), KEY_TYPE, 1), h(sl1))
                self.assertEqual(hbkd.stateful_seed(h(r), KEY_TYPE, CONTEXT, INSTANCE), h(sf0))
                self.assertEqual(hbkd.stateful_seed(h(r), KEY_TYPE, CONTEXT, INSTANCE, 0), h(sf0))
                self.assertEqual(hbkd.app_secret(h(r), LABEL), h(app))
                self.assertEqual(hbkd.app_secret(h(r), LABEL, 0), h(app))

    def test_shared_inputs(self):
        # "context is the bytes 0x00 to 0x1f, and instance is 32 bytes of 0xa5"
        self.assertEqual(CONTEXT.hex(), "".join(f"{i:02x}" for i in range(0x20)))
        self.assertEqual(INSTANCE.hex(), "a5" * 32)
        self.assertEqual(len(ABANDON.split()), 24)
        self.assertEqual(len(LEGAL.split()), 12)

    def test_b10_public_key(self):
        """The account-0 stateless seed through Winterlock's leanSphincs key at b = 10: its public key is root || P,
        16 bytes each, the layout the ERC states"""
        key = leansphincs.Key(h(ERC[0][4]), 10)
        self.assertEqual(key.public_key, h(ERC_PUBLIC_KEY))
        self.assertEqual(key.public_key, key.root + key.p)
        self.assertEqual(key.b, leansphincs.DEFAULT_B)

    def test_tags_and_tagged_hash(self):
        self.assertEqual(hbkd.tagged_hash("t", b"d"), keccak256(keccak256(b"t") + b"d"))
        for tag in (hbkd.ROOT_TAG, hbkd.STATELESS_TAG, hbkd.STATEFUL_TAG, hbkd.APP_TAG):
            self.assertTrue(tag.startswith("HBKD/") and tag.endswith("/v1"))


class Bip39(unittest.TestCase):
    def test_trezor_seeds_are_bip39s(self):
        for m, want in BIP39_TREZOR.items():
            self.assertEqual(Mnemonic.to_seed(m, "TREZOR"), h(want))
            self.assertEqual(hbkd.bip39_seed(m, "TREZOR"), h(want))
        self.assertEqual({(m, s) for m, p, s, *_ in ERC if p == "TREZOR"}, set(BIP39_TREZOR.items()))
        self.assertEqual(hbkd.bip39_seed(ABANDON), Mnemonic.to_seed(ABANDON, ""))

    def test_pbkdf2_by_hand(self):
        # one 64-byte block: U1 xor ... xor U2048, U1 = HMAC(m, salt || be32(1))
        import hmac
        m, salt = LEGAL.encode(), b"mnemonicTREZOR"
        u = hmac.new(m, salt + (1).to_bytes(4, "big"), hashlib.sha512).digest()
        t = bytearray(u)
        for _ in range(2047):
            u = hmac.new(m, u, hashlib.sha512).digest()
            t = bytearray(a ^ b for a, b in zip(t, u))
        self.assertEqual(bytes(t), hbkd.bip39_seed(LEGAL, "TREZOR"))

    def test_nfkd(self):
        """Python normalises (NFKD) as BIP-39 says; the Rust core refuses anything but ASCII
        (core/tests/vectors/hbkd.json, "non_ascii")"""
        composed, decomposed = "pässphräse", "pässphräse"
        self.assertNotEqual(composed, decomposed)
        s = hbkd.bip39_seed(ABANDON, composed)
        self.assertEqual(s, hbkd.bip39_seed(ABANDON, decomposed))
        self.assertEqual(s, Mnemonic.to_seed(ABANDON, composed))
        self.assertEqual(s, hashlib.pbkdf2_hmac("sha512", ABANDON.encode(), ("mnemonic" + decomposed).encode(), 2048))
        self.assertNotEqual(s, hbkd.bip39_seed(ABANDON, "passphrase"))
        # an ideographic space (BIP-39's Japanese separator) and a no-break space are a space after NFKD
        self.assertEqual(hbkd.bip39_seed(ABANDON.replace(" ", "　")), hbkd.bip39_seed(ABANDON))
        self.assertEqual(hbkd.bip39_seed(ABANDON.replace(" ", " ")), hbkd.bip39_seed(ABANDON))

    def test_sentence_as_given(self):
        """No word list and no checksum: the seed is of the sentence as given, so a typed phrase is another seed until
        it is made canonical"""
        bad = "abandon " * 24  # 24 words, checksum wrong
        self.assertEqual(hbkd.bip39_seed(bad.strip()), Mnemonic.to_seed(bad.strip(), ""))
        self.assertNotEqual(hbkd.bip39_seed(ABANDON.upper()), hbkd.bip39_seed(ABANDON))
        self.assertNotEqual(hbkd.bip39_seed(ABANDON + " "), hbkd.bip39_seed(ABANDON))


class WinterlockRoot(unittest.TestCase):
    def test_zero_seed_is_the_ercs_first_phrase(self):
        self.assertEqual(" ".join(phrase.to_phrase(bytes(32))), ABANDON)
        self.assertEqual(hbkd.winterlock_root(bytes(32)), h(ERC[0][3]))
        self.assertEqual(hbkd.winterlock_root(bytes(32), ""), h(ERC[0][3]))
        self.assertEqual(hbkd.winterlock_root(bytes(32), "TREZOR"), h(ERC[1][3]))
        self.assertEqual(hbkd.stateless_seed(hbkd.winterlock_root(bytes(32)), KEY_TYPE), h(ERC[0][4]))

    def test_any_seed(self):
        seed = os.urandom(32)
        words = phrase.to_phrase(seed)
        self.assertEqual(hbkd.winterlock_root(seed, "x"), hbkd.root_from_seed(Mnemonic.to_seed(" ".join(words), "x")))
        # the phrase as a member may type it decodes to the same seed, so to the same root
        typed = ", ".join(f"{i}. {w[:4].upper()}" for i, w in enumerate(words, 1))
        self.assertEqual(hbkd.winterlock_root(phrase.to_seed(typed)), hbkd.winterlock_root(seed))
        with self.assertRaises(ValueError):
            hbkd.winterlock_root(bytes(31))


class InputChecks(unittest.TestCase):
    R = h(ERC[0][3])

    def test_accounts(self):
        top = (1 << 32) - 1
        self.assertNotEqual(hbkd.stateless_seed(self.R, KEY_TYPE, top), hbkd.stateless_seed(self.R, KEY_TYPE, 0))
        hbkd.stateful_seed(self.R, KEY_TYPE, CONTEXT, INSTANCE, top)
        hbkd.app_secret(self.R, LABEL, top)
        for bad in (-1, 1 << 32, 1 << 64, True, False, 1.0, "0", None):
            with self.subTest(account=bad):
                with self.assertRaises(ValueError):
                    hbkd.stateless_seed(self.R, KEY_TYPE, bad)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, KEY_TYPE, CONTEXT, INSTANCE, bad)
                with self.assertRaises(ValueError):
                    hbkd.app_secret(self.R, LABEL, bad)

    def test_key_types(self):
        punctuated = "a key type, with spaces & punctuation: !\"#$%'()*+-./;<=>?@[\\]^_`{|}~"
        for good in (" ", "~", "x", punctuated, "k" * 300):
            with self.subTest(key_type=good):
                self.assertTrue(hbkd.is_key_type(good))
                self.assertEqual(hbkd.stateless_seed(self.R, good),
                                 hbkd.tagged_hash("HBKD/stateless/v1", self.R + bytes(4) + keccak256(good.encode())))
        for bad in ("", "\n", "a\tb", "\x00", "\x1f", "\x7f", "é", " ", "　", "ḱ", b"x", None, 1):
            with self.subTest(key_type=bad):
                self.assertFalse(hbkd.is_key_type(bad))
                with self.assertRaises(ValueError):
                    hbkd.stateless_seed(self.R, bad)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, bad, CONTEXT, INSTANCE)

    def test_key_types_match_the_reference_predicate(self):
        """The ERC's reference code: key_type and key_type.isascii() and key_type.isprintable()"""
        for c in map(chr, range(0x3000)):
            self.assertEqual(hbkd.is_key_type(c), c.isascii() and c.isprintable(), hex(ord(c)))

    def test_lengths(self):
        for bad in (bytes(31), bytes(33), b"", "00" * 32, None):
            with self.subTest(value=bad):
                for f in (lambda v: hbkd.stateless_seed(v, KEY_TYPE),
                          lambda v: hbkd.stateful_seed(v, KEY_TYPE, CONTEXT, INSTANCE),
                          lambda v: hbkd.stateful_seed(self.R, KEY_TYPE, v, INSTANCE),
                          lambda v: hbkd.stateful_seed(self.R, KEY_TYPE, CONTEXT, v),
                          lambda v: hbkd.app_secret(v, LABEL)):
                    with self.assertRaises(ValueError):
                        f(bad)
        for bad in (bytes(32), bytes(63), bytes(65), "00" * 64, None):
            with self.assertRaises(ValueError):
                hbkd.root_from_seed(bad)
        # bytearray is bytes
        self.assertEqual(hbkd.stateless_seed(bytearray(self.R), KEY_TYPE), h(ERC[0][4]))
        self.assertEqual(hbkd.root_from_seed(bytearray(h(ERC[0][2]))), self.R)

    def test_labels_and_phrases(self):
        self.assertNotEqual(hbkd.app_secret(self.R, ""), hbkd.app_secret(self.R, LABEL))
        self.assertEqual(hbkd.app_secret(self.R, "é"), hbkd.tagged_hash(
            "HBKD/app/v1", self.R + bytes(4) + keccak256("é".encode())))
        # labels are UTF-8 as given, not normalised
        self.assertNotEqual(hbkd.app_secret(self.R, "é"), hbkd.app_secret(self.R, unicodedata.normalize("NFD", "é")))
        for bad in (b"label", None, "\ud800"):  # bytes, nothing, a lone surrogate (not UTF-8)
            with self.assertRaises(ValueError):
                hbkd.app_secret(self.R, bad)
        for m, p in ((b"abandon", ""), (ABANDON, b"x"), (None, "")):
            with self.assertRaises(ValueError):
                hbkd.bip39_seed(m, p)

    def test_inputs_separate(self):
        r = self.R
        seeds = {
            hbkd.stateless_seed(r, KEY_TYPE), hbkd.stateless_seed(r, KEY_TYPE, 1),
            hbkd.stateless_seed(r, KEY_TYPE + " "), hbkd.stateless_seed(h(ERC[1][3]), KEY_TYPE),
            hbkd.stateful_seed(r, KEY_TYPE, CONTEXT, INSTANCE), hbkd.stateful_seed(r, KEY_TYPE, INSTANCE, CONTEXT),
            hbkd.stateful_seed(r, KEY_TYPE, CONTEXT, bytes(32)),
            hbkd.app_secret(r, LABEL), hbkd.app_secret(r, KEY_TYPE),
        }
        self.assertEqual(len(seeds), 9)


if __name__ == "__main__":
    unittest.main()
