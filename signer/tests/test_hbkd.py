"""Hash-Based Key Derivation from BIP-39 (draft ERC): the ERC's test vectors, BIP-39's own, HKDF-SHA512 against
pycryptodome and Wycheproof, and the input checks."""
import hashlib
import hmac
import os
import unicodedata
import unittest

from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF
from mnemonic import Mnemonic

from winterlock_signer import hbkd, leansphincs, phrase

# The ERC's Test Cases (draft, commit 14708d88): shared inputs, then per phrase and passphrase S, R, the stateless
# seeds of accounts 0 and 1, the stateful seed of account 0 and the application secret, all of L = 32; the first
# phrase's stateless seed of L = 48; a random input's R and its values at account 2^32 - 1; the info bytes of the first
# stateless seed; three SLH-DSA key types; and the inputs an implementation must reject.
KEY_TYPE = "leanSphincs-keccak/wambsgans-keccak/b10"
CONTEXT = bytes(range(32))
INSTANCE = bytes([0xA5] * 32)
LABEL = "example.app.gas"
ABANDON = "abandon " * 23 + "art"
LEGAL = "legal winner thank year wave sausage worth useful legal winner thank yellow"
TOP = (1 << 32) - 1
ERC = [
    (ABANDON, "",
     "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"
     "5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
     "31a48aa502c800ed2e98d6ea19e8121861876ac755601b53f3772c4c910cc292"
     "e8f1650268f6df3f7b7f030536b6b4e55a13b0d673b24e7e6a8fdecb9c5854ed",
     "fe1de5038bcc56fc434f8cba07eb53ab972de18ec0779c7465fd0d789a966879",
     "dae839ce92eb35bdd99718114d73d0b1ef6a2c66ad0bdd41b1fc7e99ee36ff82",
     "675a2390347bd7f57af7086cd3596929701d22f554100304555a946403542c9f",
     "4a50286a3a17be26017002484f0e99f10b6a19bc6202fbc3f079760fd9b1c000"),
    (ABANDON, "TREZOR",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
     "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
     "36115dbd5c9909f705901905fdfcd5b59af8a03773b107a4cbc01de190810425"
     "edabf87db6ceaebf3684dbfaf5ea46ec34d2b91a0d7661310b03b4ec1b5202bf",
     "3d5ad9f82a782c1578db5b40443cfba75c151167312a133d4c90457f6a98179d",
     "e5fa8baf57d6a7fecf5cdd9b7e1d1714cfbbdd4c86e7de882d4494d02fe65433",
     "20023fe84a406e7f050108053e586d5741db708b721554c6a9e1e1cb16bd6b6b",
     "63cf757802534428b39551535e5560831be70a5996f1eab6240d399a0798c151"),
    (LEGAL, "TREZOR",
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
     "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
     "c9f92a198541dcb5caf89f801827ef3baa8aafadcd3cee67d973ddbced8edad2"
     "30dd8e77b5d30e60650c5d6ac22328a701b0e87ef959ea6a78c7e170354c3fbf",
     "601ae30e33d5058eed33e0cc0ec25cb5bf8659481104a7bd0f10c0ebdd30b967",
     "7d3b358bf3d671dc6eb66dcfc58f7d91e6bb06bfe4cf92da9c19051a44516943",
     "52f7f43010563686fa971066e92e0e389d1caddf2c14a1dbb27f589a5f90dfee",
     "27ed4acb2aed9f052692619b763f96da377a3f96f2b242d8d636d19e1d06a3be"),
]
ERC_STATELESS_48 = ("da22b68be432f40bc516b7f4633ac9238970b93fe22e198438f32750cb42c45a"
                    "7eaa9c32c1bc6a3fb120d9d3e3cd9d51")
ERC_RANDOM_IKM = bytes(range(0x20, 0x40))  # R, then the stateless and stateful seeds and app secret at account TOP
ERC_RANDOM = ("719bbea6f6e3bec595afff3dccc8558972a4aa4893a654ce6b793616eab6f3d5"
              "c18887c81e3a4009c5488c1070b86a65e6bb32279473b8d8a21548e8d02fc07a",
              "6a0989ffde23947e80f0dfe22f5c9f7df46b79403db776b90fdd127b84f76ceb",
              "0faee1dc2f4f8cdb4cd3fb634429c53d2305644fcc3903f5507ce05a64c6f5e8",
              "dadb75da4b8194cfac6575b65705b93e5343172e4c2ed271e2e3627ffadfa950")
ERC_INFO = "01 00000000 0020 27 6c65616e537068696e63732d6b656363616b2f77616d627367616e732d6b656363616b2f623130"
ERC_SLH_DSA = [  # (key type, seed, public key) for the first phrase, account 0
    ("SLH-DSA-SHA2-128s",
     "9a4f5ec07d81f8f9b5ad67afe96d81793158212491f532a49a3139ac24e97105"
     "9feb56347e8b95e5c18e1879d3ecf3bd",
     "9feb56347e8b95e5c18e1879d3ecf3bd8aa1a5ce8e63e5240b7521b3648b8298"),
    ("SLH-DSA-SHA2-192s",
     "dd0257c7e6c82971da01e82c2e100827025e587bf4beb0837771faee59e9da38"
     "3041f5ef899c5c7af8527461fb5922b0b2ee3215b5859539d83576885c3ec291"
     "35f3878148585575",
     "b2ee3215b5859539d83576885c3ec29135f387814858557560f7ac4140534ed3"
     "55a93fffba557aeb7a425407ff4bdd96"),
    ("SLH-DSA-SHAKE-256s",
     "0771852b79bc31a74ed79f000965b5c36263e098f19def34204fdcefad597187"
     "e11fbe0ccf0aa665307ab0becd1d7183af5c2a3f8c136e6976161b6d6fe9e4ac"
     "be4e3fe70e626bafe1538ed6c50cdffe7918192469ce47798357d6ca901f3d78",
     "be4e3fe70e626bafe1538ed6c50cdffe7918192469ce47798357d6ca901f3d78"
     "7a7fd9278d47cc69476b93a1b22fe671b4c1c102e5dddaf05870138189dc068e"),
]
# A Winterlock regression value, not the ERC's: root || public parameter of Winterlock's leanSphincs key at b = 10
# from the first phrase's account-0 stateless seed (L = 32). The Rust core checks the same value (hbkd.rs).
WINTERLOCK_B10_PUBLIC_KEY = "3262892101810781d0692ec03d73ae03d1c6b5a62c97cd145ec18f9979111bb2"

# BIP-39's published seeds for these two phrases with passphrase "TREZOR" (trezor/python-mnemonic, vectors.json), which
# the ERC says its two TREZOR values of S are
BIP39_TREZOR = {
    ABANDON: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
             "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    LEGAL: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
           "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
}

# HKDF-SHA512 from Wycheproof (C2SP/wycheproof, testvectors_v1/hkdf_sha512_test.json): (tcId, IKM, salt, info, OKM).
# Empty salts, a salt longer than 64 bytes, info longer than a block, output over two blocks; the Rust core has the same.
WYCHEPROOF = [
    (1, "24aeff2645e3e0f5494a9a102778c43a", "", "", "dd2599840b09699c6200b5cba79002b3aa75c61b"),
    (8, "be0df9811ad0bf3b08358a3dc4a05981", "c98618bfeb59295f8bf1dd3804b1bf2c", "",
     "c5cc73041ea99289bfbc39aaf64595129b461651c69d3de5297d66f844b4d59257be9a82bddf228630c8"),
    (19, "df27ab960ad87bfe2e173a4659e3546b",
     "1e7ec49981fd4b0b7c20dd4dd5bdfbf2195e707f4d0354611b4893b8a86f61467aca2cf726ccc3ef0b0b4f3240d945ce"
     "506197e2be00322b17b48209c312ef9f", "",
     "a1cca923d8f07cf98d658b425425a146a6cfea8910dbfee9a28962d0b1a1f40716ebfd19d094a1bba684"),
    (23, "d04f44faa4542b34f958d8a863801f2c", "",
     "ff6b5b655cbf2421a66d2f28408395a2ce57264f76bd60befd51cbfd9474faa47a97a9aa0f0e4338635633023cb36da1"
     "2a3051f1f369355b687304e74c5218b315",
     "76ebb3133cbf07afb653393bea4e4ecdab9d8e8fcc5e79e67d5346312ce9e46e937b3393170b811e25f7621923f74e51"
     "9b604ae2b9884fe2d7202782ee9e20100f95341d8b6ff1f39db23bab7b7edcd6"),
    (75, "ddba77f227f237c791c07ee7e1ce9d933ecad3614212cc98d4f12afc90a3b21f4c7c3b4c54f44ad7d1e8ce45cd36aad5"
         "cb0bbf84e90cb054a1e7dc558690c5fa",
     "bd37d35e915d6a3431e8ab0fe1f1a3d129d9b6dfcdcb627ae7eb6d15068145cff05fa37e6bca0721e9ae696281759f6f"
     "1f6784db7c8d30c4b75342ec6d6a1cc2af",
     "6b478027231379b6bbed6c61732aad5636b5aab2", "54b3b9a5d7f1713194b8e0621d8d33c6f2034b5005d47bbc90e5883d6af9bc42"),
]
# tcId 21: the maximal output, 16320 bytes (its first 16 bytes and SHA-256 here); tcId 22: one byte more, invalid
WYCHEPROOF_MAX = ("83c6fa101a922bf4e0ab38c1853b82f8",
                  "7ea9bd3ed65fdbec456e4859209d0e87336b0a04bd342fccede6fa4cb12331789a9af13d3c96e955a74550883aa5a80e"
                  "055ad7682a26c8b2343088d05f15f80d",
                  "c893d162bf0036e4", "c80c2cce5fc294e1e680e665bbd7aac8",
                  "f1d2571780c8a83db38dd812b9cab70a8c2e66bfaf1a2fb3632a154ce63a524a")


def h(x: str) -> bytes:
    return bytes.fromhex(x)


class ErcVectors(unittest.TestCase):
    def test_every_value(self):
        for m, p, s, r, sl0, sl1, sf0, app in ERC:
            with self.subTest(mnemonic=m[:20], passphrase=p):
                self.assertEqual(hbkd.bip39_seed(m.split(" "), p), h(s))
                self.assertEqual(hbkd.root(h(s)), h(r))
                self.assertEqual(hbkd.stateless_seed(h(r), KEY_TYPE, 32), h(sl0))
                self.assertEqual(hbkd.stateless_seed(h(r), KEY_TYPE, 32, 0), h(sl0))
                self.assertEqual(hbkd.stateless_seed(h(r), KEY_TYPE, 32, 1), h(sl1))
                self.assertEqual(hbkd.stateful_seed(h(r), KEY_TYPE, 32, CONTEXT, INSTANCE), h(sf0))
                self.assertEqual(hbkd.stateful_seed(h(r), KEY_TYPE, 32, CONTEXT, INSTANCE, 0), h(sf0))
                self.assertEqual(hbkd.app_secret(h(r), LABEL), h(app))
                self.assertEqual(hbkd.app_secret(h(r), LABEL, 32, 0), h(app))

    def test_stateless_48(self):
        """"The line with L = 48 shows that a longer seed does not start with the shorter one." HKDF alone would make
        it a prefix: L in info is what separates them."""
        r, sl0 = h(ERC[0][3]), h(ERC[0][4])
        s48 = hbkd.stateless_seed(r, KEY_TYPE, 48)
        self.assertEqual(s48, h(ERC_STATELESS_48))
        self.assertNotEqual(s48[:32], sl0)
        self.assertEqual(hbkd.hkdf_expand(r, hbkd.info(hbkd.STATELESS, 0, 32, KEY_TYPE.encode()), 48)[:32], sl0)

    def test_random_input_at_the_top_account(self):
        self.assertEqual(ERC_RANDOM_IKM.hex(), "".join(f"{i:02x}" for i in range(0x20, 0x40)))
        r, sl, sf, app = map(h, ERC_RANDOM)
        self.assertEqual(hbkd.root(ERC_RANDOM_IKM), r)
        self.assertEqual(hbkd.stateless_seed(r, KEY_TYPE, 32, TOP), sl)
        self.assertEqual(hbkd.stateful_seed(r, KEY_TYPE, 32, CONTEXT, INSTANCE, TOP), sf)
        self.assertEqual(hbkd.app_secret(r, LABEL, 32, TOP), app)

    def test_info_bytes(self):
        want = h(ERC_INFO.replace(" ", ""))
        self.assertEqual(len(want), 47)
        self.assertEqual(hbkd.info(hbkd.STATELESS, 0, 32, KEY_TYPE.encode()), want)
        r = h(ERC[0][3])
        self.assertEqual(hbkd.hkdf_expand(r, want, 32), h(ERC[0][4]))
        # the other two purposes, from the same layout
        sf = hbkd.info(hbkd.STATEFUL, 0, 32, KEY_TYPE.encode(), CONTEXT + INSTANCE)
        self.assertEqual(sf, b"\x02" + want[1:] + CONTEXT + INSTANCE)
        self.assertEqual(hbkd.hkdf_expand(r, sf, 32), h(ERC[0][6]))
        app = hbkd.info(hbkd.APPLICATION, 0, 32, LABEL.encode())
        self.assertEqual(app, bytes([3, 0, 0, 0, 0, 0, 32, 15]) + LABEL.encode())
        self.assertEqual(hbkd.hkdf_expand(r, app, 32), h(ERC[0][7]))

    def test_slh_dsa(self):
        r = h(ERC[0][3])
        for kt, seed, pk in ERC_SLH_DSA:
            with self.subTest(kt):
                n = hbkd.SLH_DSA_N[kt]
                seed, pk = h(seed), h(pk)
                self.assertEqual((len(seed), len(pk)), (3 * n, 2 * n))
                self.assertEqual(hbkd.stateless_seed(r, kt, 3 * n), seed)
                sk_seed, sk_prf, pk_seed = hbkd.slh_dsa_seeds(r, kt)
                self.assertEqual((sk_seed, sk_prf, pk_seed), (seed[:n], seed[n:2 * n], seed[2 * n:]))
                self.assertEqual(hbkd.slh_dsa_seeds(r, kt, 0), (sk_seed, sk_prf, pk_seed))
                self.assertEqual(pk[:n], pk_seed)  # the public key is PK.seed || PK.root

    def test_rejections(self):
        """"An implementation rejects each of these inputs": 24 x abandon, the key types "" and "leanSphincs keccak",
        a key type of 256 bytes, account 2^32, the lengths 31 and 16321, and SLH-DSA-SHA2-128s at a length other than
        48 or as a stateful key"""
        r = hbkd.root(ERC_RANDOM_IKM)
        with self.assertRaises(ValueError):
            hbkd.bip39_seed(["abandon"] * 24)
        for bad in ("", "leanSphincs keccak", "k" * 256):
            with self.subTest(key_type=bad[:20]):
                with self.assertRaises(ValueError):
                    hbkd.stateless_seed(r, bad, 32)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(r, bad, 32, CONTEXT, INSTANCE)
        for f in (lambda: hbkd.stateless_seed(r, KEY_TYPE, 32, 1 << 32),
                  lambda: hbkd.stateful_seed(r, KEY_TYPE, 32, CONTEXT, INSTANCE, 1 << 32),
                  lambda: hbkd.app_secret(r, LABEL, 32, 1 << 32),
                  lambda: hbkd.slh_dsa_seeds(r, "SLH-DSA-SHA2-128s", 1 << 32)):
            with self.assertRaises(ValueError):
                f()
        for bad in (31, 16321):
            with self.subTest(length=bad):
                for f in (lambda: hbkd.stateless_seed(r, KEY_TYPE, bad),
                          lambda: hbkd.stateful_seed(r, KEY_TYPE, bad, CONTEXT, INSTANCE),
                          lambda: hbkd.app_secret(r, LABEL, bad),
                          lambda: hbkd.info(hbkd.STATELESS, 0, bad, b"x")):
                    with self.assertRaises(ValueError):
                        f()
        for bad in (32, 47, 49, 64, 72, 96):
            with self.assertRaises(ValueError):
                hbkd.stateless_seed(r, "SLH-DSA-SHA2-128s", bad)
        self.assertEqual(len(hbkd.stateless_seed(r, "SLH-DSA-SHA2-128s", 48)), 48)
        for length in (32, 48):
            with self.assertRaises(ValueError):
                hbkd.stateful_seed(r, "SLH-DSA-SHA2-128s", length, CONTEXT, INSTANCE)

    def test_shared_inputs(self):
        # "context is the bytes 0x00 to 0x1f, instance is 32 bytes of 0xa5"
        self.assertEqual(CONTEXT.hex(), "".join(f"{i:02x}" for i in range(0x20)))
        self.assertEqual(INSTANCE.hex(), "a5" * 32)
        self.assertEqual(len(ABANDON.split()), 24)
        self.assertEqual(len(LEGAL.split()), 12)
        self.assertEqual(len(KEY_TYPE), 0x27)


class SlhDsa(unittest.TestCase):
    R = h(ERC[0][3])

    def test_names(self):
        """FIPS 205's twelve parameter set names, with n = 16, 24, 32 for 128, 192, 256 bits"""
        want = {f"SLH-DSA-{f}-{bits}{v}": bits // 8 for f in ("SHA2", "SHAKE") for bits in (128, 192, 256) for v in "sf"}
        self.assertEqual(hbkd.SLH_DSA_N, want)
        self.assertEqual(len(want), 12)
        self.assertEqual(list(hbkd.SLH_DSA_N)[:2], ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"])

    def test_every_name(self):
        for kt, n in hbkd.SLH_DSA_N.items():
            with self.subTest(kt):
                self.assertTrue(hbkd.is_key_type(kt))
                parts = hbkd.slh_dsa_seeds(self.R, kt, 7)
                self.assertEqual([len(p) for p in parts], [n] * 3)
                self.assertEqual(b"".join(parts), hbkd.stateless_seed(self.R, kt, 3 * n, 7))
                for bad in (32, 3 * n - 1, 3 * n + 1, 2 * n, 4 * n):
                    with self.assertRaises(ValueError):
                        hbkd.stateless_seed(self.R, kt, bad)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, kt, 3 * n, CONTEXT, INSTANCE)

    def test_other_key_types(self):
        """Only the exact names are SLH-DSA's: a near miss is an ordinary key type"""
        for other in (KEY_TYPE, "slh-dsa-sha2-128s", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128", "SLH-DSA-SHA2-128s/x"):
            with self.subTest(other):
                self.assertNotIn(other, hbkd.SLH_DSA_N)
                with self.assertRaises(ValueError):
                    hbkd.slh_dsa_seeds(self.R, other)
                self.assertEqual(len(hbkd.stateless_seed(self.R, other, 32)), 32)
        for bad in (None, b"SLH-DSA-SHA2-128s", ["SLH-DSA-SHA2-128s"]):
            with self.assertRaises(ValueError):
                hbkd.slh_dsa_seeds(self.R, bad)


class Hkdf(unittest.TestCase):
    def test_against_pycryptodome(self):
        """pycryptodome's HKDF (extract and expand in one) gives every derived value from IKM, salt "HBKD/v1" and the
        info bytes"""
        ikms = [h(ERC[0][2]), h(ERC[2][2]), ERC_RANDOM_IKM, bytes(range(100)), os.urandom(64)]
        for ikm in ikms:
            r = hbkd.root(ikm)
            for length in (32, 48, 64, 65, 1000, 16320):
                for account in (0, 1, 1 << 31, TOP):
                    cases = [(hbkd.stateless_seed(r, KEY_TYPE, length, account),
                              hbkd.info(hbkd.STATELESS, account, length, KEY_TYPE.encode())),
                             (hbkd.stateful_seed(r, "x", length, CONTEXT, INSTANCE, account),
                              hbkd.info(hbkd.STATEFUL, account, length, b"x", CONTEXT + INSTANCE)),
                             (hbkd.app_secret(r, "\xe9", length, account),
                              hbkd.info(hbkd.APPLICATION, account, length, "\xe9".encode()))]
                    for got, info in cases:
                        self.assertEqual(got, HKDF(ikm, length, b"HBKD/v1", SHA512, context=info))
        for kt, n in hbkd.SLH_DSA_N.items():
            ikm = h(ERC[0][2])
            want = HKDF(ikm, 3 * n, b"HBKD/v1", SHA512, context=hbkd.info(1, 0, 3 * n, kt.encode()))
            self.assertEqual(b"".join(hbkd.slh_dsa_seeds(hbkd.root(ikm), kt)), want)
        # the helpers on their own, with other salts and lengths below HBKD's floor
        for _ in range(50):
            ikm, salt, info = os.urandom(os.urandom(1)[0]), os.urandom(os.urandom(1)[0]), os.urandom(os.urandom(1)[0])
            length = int.from_bytes(os.urandom(2), "big") % 16321
            prk = hbkd.hkdf_extract(salt, ikm)
            want = HKDF(ikm, length, salt, SHA512, context=info) if length else b""  # pycryptodome refuses 0
            self.assertEqual(hbkd.hkdf_expand(prk, info, length), want)

    def test_wycheproof(self):
        for tc, ikm, salt, info, okm in WYCHEPROOF:
            with self.subTest(tcId=tc):
                prk = hbkd.hkdf_extract(h(salt), h(ikm))
                self.assertEqual(hbkd.hkdf_expand(prk, h(info), len(h(okm))), h(okm))
        ikm, salt, info, head, digest = WYCHEPROOF_MAX
        prk = hbkd.hkdf_extract(h(salt), h(ikm))
        okm = hbkd.hkdf_expand(prk, h(info), 16320)
        self.assertEqual(okm[:16], h(head))
        self.assertEqual(hashlib.sha256(okm).digest(), h(digest))
        with self.assertRaises(ValueError):  # tcId 22
            hbkd.hkdf_expand(h("00" * 64), h("b0aaceb3b0b8c885"), 16321)

    def test_by_hand(self):
        """RFC 5869: PRK = HMAC(salt, IKM); T(1) = HMAC(PRK, info || 1), T(2) = HMAC(PRK, T(1) || info || 2)"""
        ikm, info = ERC_RANDOM_IKM, b"info"
        prk = hmac.new(b"HBKD/v1", ikm, hashlib.sha512).digest()
        self.assertEqual(hbkd.root(ikm), prk)
        self.assertEqual(hbkd.hkdf_extract(b"HBKD/v1", ikm), prk)
        t1 = hmac.new(prk, info + b"\x01", hashlib.sha512).digest()
        t2 = hmac.new(prk, t1 + info + b"\x02", hashlib.sha512).digest()
        self.assertEqual(hbkd.hkdf_expand(prk, info, 100), (t1 + t2)[:100])
        self.assertEqual(hbkd.hkdf_expand(prk, info, 0), b"")
        # an empty salt is the RFC's default of 64 zero bytes
        self.assertEqual(hbkd.hkdf_extract(b"", ikm), hbkd.hkdf_extract(bytes(64), ikm))
        for bad in (-1, 16321, True, 32.0, "32", None):
            with self.assertRaises(ValueError):
                hbkd.hkdf_expand(prk, info, bad)
        for bad in ("00", None, [0]):
            with self.assertRaises(ValueError):
                hbkd.hkdf_expand(bad, info, 32)
            with self.assertRaises(ValueError):
                hbkd.hkdf_expand(prk, bad, 32)
            with self.assertRaises(ValueError):
                hbkd.hkdf_extract(bad, ikm)
            with self.assertRaises(ValueError):
                hbkd.hkdf_extract(b"", bad)


class Bip39(unittest.TestCase):
    def test_trezor_seeds_are_bip39s(self):
        for m, want in BIP39_TREZOR.items():
            self.assertEqual(Mnemonic.to_seed(m, "TREZOR"), h(want))
            self.assertEqual(hbkd.bip39_seed(m.split(), "TREZOR"), h(want))
            self.assertEqual(hbkd.bip39_seed(tuple(m.split()), "TREZOR"), h(want))
        self.assertEqual({(m, s) for m, p, s, *_ in ERC if p == "TREZOR"}, set(BIP39_TREZOR.items()))
        self.assertEqual(hbkd.bip39_seed(ABANDON.split()), Mnemonic.to_seed(ABANDON, ""))

    def test_every_length(self):
        """12 to 24 words, each with a checksum that holds, give BIP-39's seed"""
        m = Mnemonic("english")
        for n in hbkd.WORD_COUNTS:
            for entropy in (bytes(n * 4 // 3), bytes([0xFF] * (n * 4 // 3)), bytes(range(n * 4 // 3))):
                words = m.to_mnemonic(entropy).split()
                self.assertEqual(len(words), n)
                self.assertEqual(hbkd.bip39_seed(words, "x"), Mnemonic.to_seed(" ".join(words), "x"))

    def test_mnemonic_refusals(self):
        """The ERC: a word outside the wordlist, a failed checksum (BIP-39 asks only for a warning), or a phrase not in
        canonical form is refused, never hashed as given"""
        words = ABANDON.split()
        bad = {
            "24 x abandon (checksum)": ["abandon"] * 24,
            "a word swapped (checksum)": words[:22] + ["art", "abandon"],
            "11 words": words[:11], "13 words": LEGAL.split() + ["abandon"], "25 words": words + ["abandon"],
            "no words": [],
            "uppercase": [w.upper() for w in words], "capitalised": ["Abandon"] + words[1:],
            "abbreviated": ["aban"] + words[1:], "a trailing space": words[:-1] + ["art "],
            "two words in one": ["abandon abandon"] + words[2:], "an empty word": words[:-1] + [""],
            "an accent": words[:-1] + ["\xe1rt"], "not English": ["\u3042\u3044\u3053\u304f\u3057\u3093"] * 24,
        }
        for what, ws in bad.items():
            with self.subTest(what):
                with self.assertRaises(ValueError):
                    hbkd.bip39_seed(ws)
        for not_a_list in (ABANDON, ABANDON.encode(), None, [b"abandon"] * 24, iter(words)):
            with self.assertRaises(ValueError):
                hbkd.bip39_seed(not_a_list)

    def test_pbkdf2_by_hand(self):
        # one 64-byte block: U1 xor ... xor U2048, U1 = HMAC(m, salt || be32(1))
        m, salt = LEGAL.encode(), b"mnemonicTREZOR"
        u = hmac.new(m, salt + (1).to_bytes(4, "big"), hashlib.sha512).digest()
        t = bytearray(u)
        for _ in range(2047):
            u = hmac.new(m, u, hashlib.sha512).digest()
            t = bytearray(a ^ b for a, b in zip(t, u))
        self.assertEqual(bytes(t), hbkd.bip39_seed(LEGAL.split(), "TREZOR"))
        self.assertEqual(bytes(t), hbkd.bip39_seed_unchecked(LEGAL, "TREZOR"))

    def test_nfkd(self):
        """Python normalises (NFKD) as BIP-39 says; the Rust core refuses anything but ASCII
        (core/tests/vectors/hbkd.json, "non_ascii")"""
        composed, decomposed = "p\xe4ssphr\xe4se", "pa\u0308ssphra\u0308se"
        self.assertNotEqual(composed, decomposed)
        s = hbkd.bip39_seed(ABANDON.split(), composed)
        self.assertEqual(s, hbkd.bip39_seed(ABANDON.split(), decomposed))
        self.assertEqual(s, Mnemonic.to_seed(ABANDON, composed))
        self.assertEqual(s, hashlib.pbkdf2_hmac("sha512", ABANDON.encode(), ("mnemonic" + decomposed).encode(), 2048))
        self.assertNotEqual(s, hbkd.bip39_seed(ABANDON.split(), "passphrase"))
        # the unchecked step normalises the sentence too: an ideographic space (BIP-39's Japanese separator) and a
        # no-break space are a space after NFKD
        self.assertEqual(hbkd.bip39_seed_unchecked(ABANDON.replace(" ", "\u3000")), hbkd.bip39_seed(ABANDON.split()))
        self.assertEqual(hbkd.bip39_seed_unchecked(ABANDON.replace(" ", "\xa0")), hbkd.bip39_seed(ABANDON.split()))

    def test_unchecked_sentence_as_given(self):
        """bip39_seed_unchecked has no word list and no checksum: the seed is of the sentence as given, which is why
        the conforming entry point is bip39_seed"""
        bad = " ".join(["abandon"] * 24)  # checksum wrong
        self.assertEqual(hbkd.bip39_seed_unchecked(bad), Mnemonic.to_seed(bad, ""))
        self.assertNotEqual(hbkd.bip39_seed_unchecked(ABANDON.upper()), hbkd.bip39_seed_unchecked(ABANDON))
        self.assertNotEqual(hbkd.bip39_seed_unchecked(ABANDON + " "), hbkd.bip39_seed_unchecked(ABANDON))


class WinterlockRoot(unittest.TestCase):
    def test_zero_seed_is_the_ercs_first_phrase(self):
        self.assertEqual(" ".join(phrase.to_phrase(bytes(32))), ABANDON)
        self.assertEqual(hbkd.winterlock_root(bytes(32)), h(ERC[0][3]))
        self.assertEqual(len(hbkd.winterlock_root(bytes(32))), 64)
        self.assertEqual(hbkd.winterlock_root(bytes(32), ""), h(ERC[0][3]))
        self.assertEqual(hbkd.winterlock_root(bytes(32), "TREZOR"), h(ERC[1][3]))
        self.assertEqual(hbkd.stateless_seed(hbkd.winterlock_root(bytes(32)), KEY_TYPE, 32), h(ERC[0][4]))

    def test_any_seed(self):
        seed = os.urandom(32)
        words = phrase.to_phrase(seed)
        self.assertEqual(hbkd.winterlock_root(seed, "x"), hbkd.root(Mnemonic.to_seed(" ".join(words), "x")))
        self.assertEqual(hbkd.winterlock_root(seed, "x"), hbkd.root(hbkd.bip39_seed(words, "x")))
        # the phrase as a member may type it decodes to the same seed, so to the same root
        typed = ", ".join(f"{i}. {w[:4].upper()}" for i, w in enumerate(words, 1))
        self.assertEqual(hbkd.winterlock_root(phrase.to_seed(typed)), hbkd.winterlock_root(seed))
        with self.assertRaises(ValueError):
            hbkd.winterlock_root(bytes(31))

    def test_b10_regression(self):
        """Winterlock only, not the ERC's: the first phrase's account-0 stateless seed through Winterlock's leanSphincs
        key at b = 10. Its public key is root || P, 16 bytes each, EIP-8288's layout"""
        key = leansphincs.Key(h(ERC[0][4]), 10)
        self.assertEqual(key.public_key, h(WINTERLOCK_B10_PUBLIC_KEY))
        self.assertEqual(key.public_key, key.root + key.p)
        self.assertEqual(key.b, leansphincs.DEFAULT_B)


class InputChecks(unittest.TestCase):
    R = h(ERC[0][3])

    def test_root(self):
        """IKM: at least 32 bytes, no upper bound; R: 64 bytes"""
        for bad in (b"", bytes(31), "00" * 32, None, list(range(32))):
            with self.assertRaises(ValueError):
                hbkd.root(bad)
        self.assertEqual(hbkd.root(bytes(32)), hbkd.hkdf_extract(b"HBKD/v1", bytes(32)))
        self.assertEqual(len(hbkd.root(bytes(1 << 20))), 64)
        self.assertEqual(hbkd.root(bytearray(h(ERC[0][2]))), self.R)  # bytearray is bytes

    def test_accounts(self):
        self.assertNotEqual(hbkd.stateless_seed(self.R, KEY_TYPE, 32, TOP), hbkd.stateless_seed(self.R, KEY_TYPE, 32))
        hbkd.stateful_seed(self.R, KEY_TYPE, 32, CONTEXT, INSTANCE, TOP)
        hbkd.app_secret(self.R, LABEL, 32, TOP)
        for bad in (-1, 1 << 32, 1 << 64, True, False, 1.0, "0", None):
            with self.subTest(account=bad):
                with self.assertRaises(ValueError):
                    hbkd.stateless_seed(self.R, KEY_TYPE, 32, bad)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, KEY_TYPE, 32, CONTEXT, INSTANCE, bad)
                with self.assertRaises(ValueError):
                    hbkd.app_secret(self.R, LABEL, 32, bad)

    def test_lengths(self):
        """L: 32 to 16320, an int"""
        for good in (32, 33, 64, 65, 16320):
            self.assertEqual(len(hbkd.stateless_seed(self.R, KEY_TYPE, good)), good)
            self.assertEqual(len(hbkd.stateful_seed(self.R, KEY_TYPE, good, CONTEXT, INSTANCE)), good)
            self.assertEqual(len(hbkd.app_secret(self.R, LABEL, good)), good)
        for bad in (0, 31, 16321, 1 << 16, -32, True, 32.0, "32", None):
            with self.subTest(length=bad):
                with self.assertRaises(ValueError):
                    hbkd.stateless_seed(self.R, KEY_TYPE, bad)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, KEY_TYPE, bad, CONTEXT, INSTANCE)
                with self.assertRaises(ValueError):
                    hbkd.app_secret(self.R, LABEL, bad)

    def test_key_types(self):
        punctuated = "a-key-type,with_punctuation:!\"#$%&'()*+-./;<=>?@[\\]^_`{|}~"
        longest = "".join(chr(0x21 + i % 94) for i in range(255))
        for good in ("!", "~", "x", punctuated, longest):
            with self.subTest(key_type=good[:20]):
                self.assertTrue(hbkd.is_key_type(good))
                self.assertEqual(hbkd.stateless_seed(self.R, good, 32),
                                 hbkd.hkdf_expand(self.R, bytes([1, 0, 0, 0, 0, 0, 32, len(good)]) + good.encode(), 32))
                hbkd.stateful_seed(self.R, good, 32, CONTEXT, INSTANCE)
        for bad in ("", " ", "leanSphincs keccak", KEY_TYPE + " ", " " + KEY_TYPE, "\n", "a\tb", "\x00", "\x1f", "\x7f",
                    "\xe9", "\xa0", "\u3000", "k\u0301", longest + "!", "k" * 300, b"x", None, 1):
            with self.subTest(key_type=bad):
                self.assertFalse(hbkd.is_key_type(bad))
                with self.assertRaises(ValueError):
                    hbkd.stateless_seed(self.R, bad, 32)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, bad, 32, CONTEXT, INSTANCE)

    def test_key_types_match_the_reference_predicate(self):
        """The ERC's reference code: all("!" <= c <= "~" for c in key_type), 1 to 255 bytes: printable ASCII without
        the space"""
        for c in map(chr, range(0x3000)):
            self.assertEqual(hbkd.is_key_type(c), c.isascii() and c.isprintable() and c != " ", hex(ord(c)))

    def test_fixed_lengths(self):
        """a 64-byte root, a 32-byte context and instance"""
        for bad in (bytes(32), bytes(63), bytes(65), b"", "00" * 64, None):
            with self.subTest(root=bad):
                for f in (lambda v: hbkd.stateless_seed(v, KEY_TYPE, 32),
                          lambda v: hbkd.stateful_seed(v, KEY_TYPE, 32, CONTEXT, INSTANCE),
                          lambda v: hbkd.app_secret(v, LABEL),
                          lambda v: hbkd.slh_dsa_seeds(v, "SLH-DSA-SHA2-128s")):
                    with self.assertRaises(ValueError):
                        f(bad)
        for bad in (bytes(31), bytes(33), bytes(64), b"", "00" * 32, None):
            with self.subTest(context_or_instance=bad):
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, KEY_TYPE, 32, bad, INSTANCE)
                with self.assertRaises(ValueError):
                    hbkd.stateful_seed(self.R, KEY_TYPE, 32, CONTEXT, bad)
        # bytearray is bytes
        self.assertEqual(hbkd.stateless_seed(bytearray(self.R), KEY_TYPE, 32), h(ERC[0][4]))
        self.assertEqual(hbkd.stateful_seed(self.R, KEY_TYPE, 32, bytearray(CONTEXT), bytearray(INSTANCE)), h(ERC[0][6]))

    def test_labels(self):
        """1 to 255 bytes of UTF-8 as given, counted in bytes, not normalised"""
        for good in ("a", "l" * 255, "\xe9" * 127 + "a", "\u4f8b" * 85, "\U0001f511" * 63 + "abc"):
            with self.subTest(label=good[:10]):
                self.assertEqual(len(good.encode()), 1 if good == "a" else 255)
                self.assertEqual(hbkd.app_secret(self.R, good),
                                 hbkd.hkdf_expand(self.R, hbkd.info(3, 0, 32, good.encode()), 32))
        for bad in ("", "l" * 256, "\xe9" * 128, "\u4f8b" * 85 + "a", b"label", None, "\ud800"):
            with self.subTest(label=bad if not isinstance(bad, str) else bad[:10]):
                with self.assertRaises(ValueError):
                    hbkd.app_secret(self.R, bad)
        self.assertNotEqual(hbkd.app_secret(self.R, "\xe9"), hbkd.app_secret(self.R, unicodedata.normalize("NFD", "\xe9")))
        # an app secret under a key type's name is not that key type's seed
        self.assertNotEqual(hbkd.app_secret(self.R, KEY_TYPE), hbkd.stateless_seed(self.R, KEY_TYPE, 32))

    def test_info_checks(self):
        for bad in ((0, 0, 32, b"x"), (4, 0, 32, b"x"), (True, 0, 32, b"x"), (hbkd.STATEFUL, 0, 32, b"x"),
                    (hbkd.STATELESS, 0, 32, b"x", bytes(64)), (hbkd.STATEFUL, 0, 32, b"x", bytes(63)),
                    (1, 0, 32, b""), (1, 0, 32, bytes(256)), (1, 0, 32, "x"), (1, 1 << 32, 32, b"x"), (1, 0, 31, b"x")):
            with self.subTest(args=bad[:4]):
                with self.assertRaises(ValueError):
                    hbkd.info(*bad)
        self.assertEqual(hbkd.info(3, 1 << 31, 16320, b"a"), bytes([3, 0x80, 0, 0, 0, 0x3F, 0xC0, 1]) + b"a")
        self.assertEqual(hbkd.info(1, TOP, 65, KEY_TYPE.encode())[:8], bytes([1, 255, 255, 255, 255, 0, 65, 39]))

    def test_inputs_separate(self):
        r = self.R
        seeds = {
            hbkd.stateless_seed(r, KEY_TYPE, 32), hbkd.stateless_seed(r, KEY_TYPE, 32, 1),
            hbkd.stateless_seed(r, KEY_TYPE + "!", 32), hbkd.stateless_seed(h(ERC[1][3]), KEY_TYPE, 32),
            hbkd.stateless_seed(r, KEY_TYPE, 33)[:32],
            hbkd.stateful_seed(r, KEY_TYPE, 32, CONTEXT, INSTANCE), hbkd.stateful_seed(r, KEY_TYPE, 32, INSTANCE, CONTEXT),
            hbkd.stateful_seed(r, KEY_TYPE, 32, CONTEXT, bytes(32)),
            hbkd.app_secret(r, LABEL), hbkd.app_secret(r, KEY_TYPE),
        }
        self.assertEqual(len(seeds), 10)


if __name__ == "__main__":
    unittest.main()
