"""The recovery phrase (BIP-39 entropy = the seed) and the encrypted seed file."""
import json
import os
import stat
import tempfile
import time
import unittest
from unittest import mock

from winterlock_signer import phrase, seedfile
from winterlock_signer.abi import read_file
from winterlock_signer.keylog import Refused
from winterlock_signer.member import Member, identity_of

# BIP-39's published vectors for 256-bit entropy (trezor/python-mnemonic vectors.json, English)
VECTORS = [
    ("00" * 32, "abandon " * 23 + "art"),
    ("7f" * 32, "legal winner thank year wave sausage worth useful " * 2 + "legal winner thank year wave sausage worth "
                "title"),
    ("80" * 32, "letter advice cage absurd amount doctor acoustic avoid " * 2 + "letter advice cage absurd amount "
                "doctor acoustic bless"),
    ("ff" * 32, "zoo " * 23 + "vote"),
    ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
     "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis "
     "maple dilemma loan word shrug inflict delay length"),
]


class Phrase(unittest.TestCase):
    def test_bip39_vectors(self):
        for entropy, words in VECTORS:
            self.assertEqual(phrase.to_phrase(bytes.fromhex(entropy)), words.split())
            self.assertEqual(phrase.to_seed(words), bytes.fromhex(entropy))

    def test_round_trip_and_the_same_signer(self):
        seed = os.urandom(32)
        words = phrase.to_phrase(seed)
        self.assertEqual(len(words), 24)
        self.assertEqual(phrase.to_seed(" ".join(words)), seed)
        self.assertEqual(identity_of(phrase.to_seed(" ".join(words))), identity_of(seed))

    def test_forgiving_input(self):
        seed = bytes.fromhex(VECTORS[4][0])
        words = VECTORS[4][1].split()
        numbered = "\n".join(f"{i}. {w.upper()}," for i, w in enumerate(words, 1))
        self.assertEqual(phrase.to_seed(numbered), seed)
        self.assertEqual(phrase.to_seed(" ".join(w[:4] for w in words)), seed)  # four-letter abbreviations
        self.assertEqual(phrase.to_seed("0x" + seed.hex()), seed)  # a legacy hex seed backup
        self.assertEqual(phrase.to_seed(seed.hex().upper()), seed)

    def test_mistakes_are_named(self):
        words = VECTORS[4][1].split()
        with self.assertRaisesRegex(phrase.PhraseError, "has 24 words; this has 23"):
            phrase.to_seed(" ".join(words[:23]))
        with self.assertRaisesRegex(phrase.PhraseError, r"word 5 \('cuase'\)"):
            phrase.to_seed(" ".join(words[:4] + ["cuase"] + words[5:]))
        swapped = words[:]
        swapped[0], swapped[1] = swapped[1], swapped[0]
        with self.assertRaisesRegex(phrase.PhraseError, "checksum"):
            phrase.to_seed(" ".join(swapped))
        with self.assertRaises(phrase.PhraseError):
            phrase.to_seed(" ".join(words[:23] + ["abandon"]))  # another last word: the checksum fails

    def test_backup_check_helpers(self):
        words = VECTORS[4][1].split()
        for _ in range(20):
            pos = phrase.check_positions()
            self.assertEqual(len(set(pos)), phrase.CHECK_WORDS)
            self.assertEqual(pos, sorted(pos))
            self.assertTrue(all(1 <= p <= 24 for p in pos))
        self.assertTrue(phrase.matches(words, 1, "Hamster"))
        self.assertTrue(phrase.matches(words, 1, "hams"))
        self.assertFalse(phrase.matches(words, 1, "diagram"))
        self.assertFalse(phrase.matches(words, 1, ""))
        lines = phrase.columns(words)
        self.assertEqual(len(lines), 6)
        self.assertTrue(lines[0].startswith(" 1. hamster"))
        self.assertIn("7. private", lines[0])


class SeedFile(unittest.TestCase):
    N = 1 << 10

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "seed")
        self.seed = os.urandom(32)

    def tearDown(self):
        self.dir.cleanup()

    def test_encrypted_round_trip(self):
        seedfile.write(self.path, self.seed, "a long passphrase", n=self.N)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(seedfile.kind(self.path), "encrypted")
        text = read_file(self.path)
        self.assertNotIn(self.seed.hex(), text)
        doc = json.loads(text)
        self.assertEqual((doc["kdf"], doc["aead"], doc["n"], doc["r"], doc["p"]), ("scrypt", "chacha20-poly1305",
                                                                                     self.N, 8, 1))
        self.assertEqual(seedfile.read(self.path, lambda: "a long passphrase"), self.seed)
        with self.assertRaises(seedfile.WrongPassphrase):
            seedfile.read(self.path, lambda: "a long passphrasf")
        with self.assertRaises(FileExistsError):
            seedfile.write(self.path, self.seed, "a long passphrase", n=self.N)
        # each write draws a new salt and nonce
        seedfile.write(self.path, self.seed, "a long passphrase", n=self.N, replace=True)
        doc2 = json.loads(read_file(self.path))
        self.assertNotEqual((doc["salt"], doc["nonce"], doc["ct"]), (doc2["salt"], doc2["nonce"], doc2["ct"]))

    def test_changes_are_detected(self):
        seedfile.write(self.path, self.seed, "a long passphrase", n=self.N)
        doc = json.loads(read_file(self.path))
        for field, value in (("ct", ("00" if doc["ct"][:2] != "00" else "01") + doc["ct"][2:]),
                             ("nonce", "00" * 12), ("salt", "11" * 16), ("n", self.N * 2)):
            bad = dict(doc, **{field: value})
            with self.assertRaises(seedfile.WrongPassphrase, msg=field):
                seedfile.decrypt(json.dumps(bad), "a long passphrase")
        with self.assertRaises(seedfile.SeedFileError):
            seedfile.decrypt(json.dumps(dict(doc, n=3)), "a long passphrase")  # not a power of two
        with self.assertRaises(seedfile.SeedFileError):
            seedfile.decrypt("{}", "a long passphrase")

    def test_passphrase_rules(self):
        with self.assertRaises(ValueError):
            seedfile.write(self.path, self.seed, "short", n=self.N)
        # the same characters, composed or not, unlock the same file (NFKC, as BIP-39 normalises)
        seedfile.write(self.path, self.seed, "café au lait", n=self.N)
        self.assertEqual(seedfile.read(self.path, lambda: "café au lait"), self.seed)

    def test_plaintext_and_wipe(self):
        seedfile.write(self.path, self.seed)
        self.assertEqual(read_file(self.path), self.seed.hex() + "\n")
        self.assertEqual(seedfile.kind(self.path), "plaintext")
        self.assertIn("NOT encrypted", seedfile.describe(self.path))
        self.assertEqual(seedfile.read(self.path, lambda: self.fail("no passphrase for a plain file")), self.seed)
        seedfile.wipe(self.path)
        self.assertEqual(seedfile.kind(self.path), "missing")

    def test_default_cost(self):
        """The signer's own setting: scrypt n = 2^18, r = 8, p = 1 (the Ethereum keystore's standard)"""
        self.assertEqual((seedfile.SCRYPT_N, seedfile.SCRYPT_R, seedfile.SCRYPT_P), (1 << 18, 8, 1))
        t0 = time.time()
        seedfile.write(self.path, self.seed, "a long passphrase")
        self.assertIn("n=2^18, r=8, p=1", seedfile.describe(self.path))
        self.assertGreater(time.time() - t0, 0.05)  # memory-hard work, not a fast hash


class MemberUnlock(unittest.TestCase):
    """A member with an encrypted seed: read-only commands need no passphrase; signing unlocks once"""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.home = os.path.join(cls.dir.name, "m")
        m = Member.init(cls.home, passphrase="first passphrase", scrypt_n=1 << 10)
        cls.owner = m.owner
        m.close()

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_read_only_needs_no_passphrase(self):
        with mock.patch("winterlock_signer.member.ask_passphrase", lambda p: self.fail("asked for a passphrase")):
            m = Member(self.home, lock=False)
            self.assertEqual(m.owner, self.owner)
            m.close()

    def test_unlock(self):
        m = Member(self.home, passphrase="first passphrase")
        m.stateless_sign(b"\x01" * 32)
        m.close()
        with mock.patch.dict(os.environ, {"WINTERLOCK_PASSPHRASE": "first passphrase"}):
            m = Member(self.home)
            m.stateless_sign(b"\x02" * 32)
            m.close()
        asked = []
        with mock.patch("winterlock_signer.member.ask_passphrase", lambda p: asked.append(p) or "wrong passphrase"):
            m = Member(self.home)
            with self.assertRaisesRegex(Refused, "wrong passphrase"):
                m.seed()
            m.close()
        self.assertEqual(len(asked), 3)  # three tries at a prompt
        with mock.patch.dict(os.environ, {"WINTERLOCK_PASSPHRASE": "wrong passphrase"}):
            m = Member(self.home)
            with self.assertRaisesRegex(Refused, "wrong passphrase"):
                m.seed()
            m.close()
        with mock.patch("winterlock_signer.member.ask_passphrase", None):
            m = Member(self.home)
            with self.assertRaisesRegex(Refused, "WINTERLOCK_PASSPHRASE"):
                m.seed()
            m.close()

    def test_change_passphrase(self):
        home = os.path.join(self.dir.name, "change")
        m = Member.init(home, passphrase="old passphrase", scrypt_n=1 << 10)
        seed = m.seed()
        m.set_passphrase("new passphrase", scrypt_n=1 << 10)
        m.close()
        self.assertEqual(seedfile.read(os.path.join(home, "seed"), lambda: "new passphrase"), seed)
        with self.assertRaises(seedfile.WrongPassphrase):
            seedfile.read(os.path.join(home, "seed"), lambda: "old passphrase")
        # a plain (legacy) seed file gets encrypted the same way
        plain = os.path.join(self.dir.name, "plain")
        m = Member.init(plain)
        m.set_passphrase("now encrypted", scrypt_n=1 << 10)
        m.close()
        self.assertEqual(seedfile.kind(os.path.join(plain, "seed")), "encrypted")


if __name__ == "__main__":
    unittest.main()
