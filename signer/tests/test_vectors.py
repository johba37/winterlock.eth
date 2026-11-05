"""Byte-for-byte agreement with the Solidity reference signers (tests/vectors/solidity.json, from
tools/gen_vectors.py): WotsSigner and WotsTree, StatelessSigner, and the live test's owner-format helper."""
import json
import os
import unittest

from winterlock_signer import leansphincs, owner, wots
from winterlock_signer.abi import h2b
from winterlock_signer.member import _abi_label
from winterlock_signer.safe import SafeTx

with open(os.path.join(os.path.dirname(__file__), "vectors", "solidity.json")) as _f:
    V = json.load(_f)
TEST = wots.Prf.TEST


class WotsAgainstSolidity(unittest.TestCase):
    def test_leaves(self):
        for x in V["wots"]["leaf"]:
            self.assertEqual(wots.leaf(int(x["seed"], 16), h2b(x["skSeed"]), x["keyIndex"], TEST)[:24],
                             h2b(x["leaf"])[:24])

    def test_signatures(self):
        for x in V["wots"]["sign"]:
            sig = wots.sign(int(x["seed"], 16), h2b(x["skSeed"]), x["keyIndex"], h2b(x["message"]), TEST)
            self.assertEqual(sig, h2b(x["sig"]))
            self.assertEqual(len(sig), wots.SIG_BYTES)

    def test_trees_and_paths(self):
        for x in V["wots"]["tree"]:
            t = wots.Tree.create(int(x["seed"], 16), h2b(x["skSeed"]), x["height"], x["k"], TEST, workers=1)
            self.assertEqual(t.root, h2b(x["root"])[:24])
            self.assertEqual(t.path(x["index"]), h2b(x["path"]))


class StatelessAgainstSolidity(unittest.TestCase):
    def test_keys_and_signatures(self):
        for x in V["stateless"]:
            k = leansphincs.Key(h2b(x["seed"]), x["b"])
            self.assertEqual(k.public_key, h2b(x["publicKey"]))
            for s in x["signatures"]:
                self.assertEqual(k.sign(h2b(s["message"])), h2b(s["sig"]))


class DeploymentAgainstSolidity(unittest.TestCase):
    """The deterministic addresses, offline, against SafeOwnerDeployment's predictions (DeploySafeOwner.s.sol)"""

    def test_predicted_addresses(self):
        self.assertEqual(len(V["deployment"]), 2)
        for d in V["deployment"]:
            self.assertEqual(owner.verifier_address(), d["verifier"])
            self.assertEqual(owner.implementation_address(), d["implementation"])
            self.assertEqual(owner.factory_address(), d["factory"])
            self.assertEqual(owner.owner_address(h2b(d["key"])), d["owner"])

    def test_proxy_code(self):
        key = h2b(V["deployment"][0]["key"])
        impl = owner.implementation_address()
        code = owner.proxy_runtime(impl, key)
        self.assertEqual(len(code), owner.OWNER_CODE_BYTES)
        self.assertEqual(code[0x2D:], key)  # where WinterlockOwner._key reads it (KEY_OFFSET)
        init = owner.proxy_init_code(impl, key)
        self.assertEqual(init[-(77 - 10):], code[10:])  # the init code returns the runtime code after its header
        with self.assertRaises(ValueError):
            owner.proxy_init_code(impl, bytes(16) + key[16:])


class OwnerFormatsAgainstSolidity(unittest.TestCase):
    """bench/safe/SafeSignerHelper.sol, which signed the live Sepolia run: its derivations, rebuilt here"""

    def setUp(self):
        self.h = V["helper"]
        self.sk = leansphincs.Key(_abi_label(b"winterlock.safe-live.stateless", h2b(self.h["tag"]), self.h["member"]))

    def test_public_key_and_owner_address(self):
        self.assertEqual(self.sk.public_key, h2b(self.h["publicKey"]))
        # the proxy owner as SafeOwnerDeployment predicts it; the tree seed and digests bind it
        self.assertEqual(owner.owner_address(self.sk.public_key), self.h["owner"])

    def test_transaction_signatures(self):
        h = self.h
        seed = owner.tree_seed(h["chainId"], h["owner"], h["safe"], h["start"])
        self.assertEqual(hex(seed), h["treeSeed"])
        sks = _abi_label(b"winterlock.safe-live.ops", h2b(h["tag"]), h["member"], h["chainId"], h["safe"], h["start"])
        tree = wots.Tree.create(seed, sks, 10, 4, TEST)
        self.assertEqual(tree.root, h2b(h["root"])[:24])
        for x in h["tx"]:
            t = SafeTx.from_json(x["safeTx"])
            sh = t.hash(h["chainId"], h["safe"])
            self.assertEqual(sh, h2b(x["hash"]))
            k = owner.key_index(t.nonce, h["start"], x["slot"], 10)
            data = owner.tx_signature_data(x["slot"], h["safe"], t.words(), wots.sign(seed, sks, k, sh, TEST),
                                           tree.path(k))
            self.assertEqual(data, h2b(x["data"]))
            self.assertEqual(len(data), 1757)  # the spike's figure for height 10
            slot, safe, words, sig, path = owner.parse_tx_signature_data(data)
            self.assertEqual((slot, safe, words), (x["slot"], h["safe"], t.words()))

    def test_certificate(self):
        c = self.h["certificate"]
        self.assertEqual(self.sk.sign(h2b(c["digest"])), h2b(c["sig"]))


if __name__ == "__main__":
    unittest.main()
