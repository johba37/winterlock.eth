"""Native crypto: leanSphincs against the upstream known answers, WOTS sign and verify, trees, both keccak
backends."""
import json
import os
import unittest

from winterlock_signer import keccak, leansphincs, wots
from winterlock_signer.abi import h2b

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KAT = os.path.join(ROOT, "contracts", "test", "fixtures", "leansphincs-keccak-kat.json")


class LeanSphincsKnownAnswers(unittest.TestCase):
    def test_upstream_fixture(self):
        """The six vectors of SPHINCs- (Rust signer, b = 6, 10, 12): keys, signatures, indices, counters"""
        with open(KAT) as f:
            vs = json.load(f)["vectors"]
        self.assertEqual(len(vs), 6)
        for v in vs:
            k = leansphincs.Key(h2b(v["seed"]), v["b"])
            self.assertEqual(k.p + bytes(16), h2b(v["pkSeed"]), v["label"])
            self.assertEqual(k.root + bytes(16), h2b(v["pkRoot"]), v["label"])
            m = h2b(v["message"])
            sig = k.sign(m)
            self.assertEqual(sig, h2b(v["sig"]), v["label"])
            self.assertEqual(sig[:16], h2b(v["randomizer"]))
            self.assertEqual(int.from_bytes(sig[4240:4244], "little"), v["counter"])
            self.assertEqual(leansphincs.fors_indices(k.p, m, sig[:16]), v["fors_indices"])
            self.assertTrue(leansphincs.verify(k.public_key, m, sig))

    def test_upstream_crate(self):
        """The upstream crate's known answer (key_gen(seed(1), 11), seed(x)[i] = 31x + i, m[i] = 7i), as quoted in
        contracts/test/StatelessVerifier.t.sol"""
        seed = bytes((31 + i) % 256 for i in range(32))
        m = bytes((7 * i) % 256 for i in range(32))
        k = leansphincs.Key(seed, 11)
        self.assertEqual(k.public_key.hex(), "63b118353523319f8f74f387824956482e582128e480149accc2ed4f19edcd00")
        sig = k.sign(m)
        self.assertEqual(keccak.keccak256(sig).hex(), "9a21b6bc61d6ba500b4d67809912c1424be1f58486eda144e4ef70afd01cf94d")
        self.assertEqual(int.from_bytes(sig[4240:4244], "little"), 1176)

    def test_verify_refuses(self):
        with open(KAT) as f:
            v = json.load(f)["vectors"][2]
        pk = h2b(v["pkRoot"])[:16] + h2b(v["pkSeed"])[:16]
        m, sig = h2b(v["message"]), h2b(v["sig"])
        self.assertTrue(leansphincs.verify(pk, m, sig))
        self.assertFalse(leansphincs.verify(pk, bytes(31) + b"\x01", sig))
        for pos in (0, 20, 3000, 4241, 4300, 5683):
            bad = bytearray(sig)
            bad[pos] ^= 1
            self.assertFalse(leansphincs.verify(pk, m, bytes(bad)), pos)
        self.assertFalse(leansphincs.verify(pk, m, sig[:-1]))


class Wots(unittest.TestCase):
    seed = 0x0123456789ABCDEF0123456789ABCDEF
    sk = keccak.keccak256(b"unit test tree")

    def test_sign_verify_tree(self):
        t = wots.Tree.create(self.seed, self.sk, 5)
        self.assertEqual(len(t.root), 24)
        for k in (0, 1, 17, 31):
            m = keccak.keccak256(b"m%d" % k)
            sig = wots.sign(self.seed, self.sk, k, m, wots.Prf.SIGNER)
            self.assertEqual(wots.verify_root(self.seed, k, m, sig, t.path(k)), t.root)
            # another message, key index, seed or path doesn't verify to the root
            self.assertNotEqual(wots.verify_root(self.seed, k, keccak.keccak256(b"other"), sig, t.path(k)), t.root)
            self.assertNotEqual(wots.verify_root(self.seed, k ^ 1, m, sig, t.path(k)), t.root)
            self.assertNotEqual(wots.verify_root(self.seed ^ 1, k, m, sig, t.path(k)), t.root)
            bad = bytearray(sig)
            bad[30] ^= 1
            self.assertNotEqual(wots.verify_root(self.seed, k, m, bytes(bad), t.path(k)), t.root)

    def test_signature_is_deterministic_and_hits_target(self):
        m = keccak.keccak256(b"x")
        a = wots.sign(self.seed, self.sk, 3, m, wots.Prf.SIGNER)
        self.assertEqual(a, wots.sign(self.seed, self.sk, 3, m, wots.Prf.SIGNER))
        d = wots.digest(self.seed, 3, a[:24] + bytes(8), m)
        self.assertEqual(wots.digit_sum(d), wots.TARGET_SUM)

    def test_parallel_tree_equals_serial(self):
        a = wots.Tree.create(self.seed, self.sk, 7, workers=1)
        b = wots.Tree.create(self.seed, self.sk, 7, workers=4)
        self.assertEqual(a.root, b.root)
        self.assertEqual(a.levels[0], b.levels[0])

    def test_cache_roundtrip(self):
        t = wots.Tree.create(self.seed, self.sk, 6, 4, wots.Prf.TEST)
        u = wots.Tree.from_bytes(t.to_bytes())
        self.assertEqual((u.root, u.height, u.k, u.seed), (t.root, t.height, t.k, t.seed))
        self.assertEqual(u.path(9), t.path(9))

    def test_signer_and_test_prf_differ(self):
        m = keccak.keccak256(b"y")
        self.assertNotEqual(wots.sign(self.seed, self.sk, 0, m, wots.Prf.SIGNER),
                            wots.sign(self.seed, self.sk, 0, m, wots.Prf.TEST))


class Backends(unittest.TestCase):
    def test_backends_agree(self):
        try:
            from Crypto.Hash import keccak as ck
            import sha3
        except ImportError:
            self.skipTest("both backends needed")
        for n in (0, 1, 31, 32, 64, 135, 136, 137, 804, 1056, 5000):
            data = bytes((i * 7) % 256 for i in range(n))
            self.assertEqual(sha3.keccak_256(data).digest(), ck.new(digest_bits=256, data=data).digest())


if __name__ == "__main__":
    unittest.main()
