"""owner.py against the compiled WinterlockOwner v2 on a local anvil: every digest, tree seed, constant and address the
signer computes offline, compared with the contract's own views; and every signature encoding the signer builds
(device certificates and revocations, tree certificates, transaction, message and approved signatures), accepted by
the contract, and refused where it must be (another device byte, a revoked device, an earlier generation, a Safe that
hasn't approved). The four shared contracts are deployed from the signer's pinned bytecode through the deterministic
deployment proxy, as `enroll --deploy` does. Needs Foundry's anvil.
"""
import os
import shutil
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNER = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(SIGNER, "tools"))

import devchain  # noqa: E402
from winterlock_signer import abi, leansphincs, messages, owner, wots  # noqa: E402
from winterlock_signer.abi import b2h, h2b  # noqa: E402
from winterlock_signer.ethtx import send  # noqa: E402
from winterlock_signer.keccak import keccak256  # noqa: E402
from winterlock_signer.rpc import Reverted  # noqa: E402
from winterlock_signer.safe import SafeTx, pack  # noqa: E402

HAVE_ANVIL = bool(shutil.which("anvil") or os.path.exists(os.path.join(devchain.FOUNDRY_BIN, "anvil")))
SAFE = "0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2"  # no code needed: the owner computes Safe's hashes itself
TO = "0x000000000000000000000000000000000000dEaD"
# a stand-in Safe for the approved kind: signedMessages(anything) returns 1 (PUSH1 1 PUSH1 0 MSTORE PUSH1 32 PUSH1 0
# RETURN), or 0 when STUB_NO
STUB_YES, STUB_NO = "0x600160005260206000f3", "0x600060005260206000f3"
APPROVING = "0x00000000000000000000000000000000000A99e0"
CHAIN = 31337


def quiet(*a):
    pass


@unittest.skipUnless(HAVE_ANVIL, "needs Foundry's anvil")
class OwnerV2OnAnvil(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = devchain.Anvil()
        cls.rpc = cls.chain.rpc
        cls.acct = cls.chain.account
        for salt, init in ((owner.VERIFIER_SALT, owner.VERIFIER_CREATION),
                           (owner.WOTS_VERIFIER_SALT, owner.WOTS_VERIFIER_CREATION),
                           (owner.IMPLEMENTATION_SALT, owner.implementation_init_code()),
                           (owner.FACTORY_SALT, owner.factory_init_code())):
            send(cls.rpc, cls.acct, owner.PROXY, salt + init, gas=30_000_000, log=quiet)
            assert cls.rpc.code(owner.create2(salt, init)), "shared contract not deployed"
        cls.member = leansphincs.Key(keccak256(b"owner v2 test: member key"))
        cls.dev = leansphincs.Key(keccak256(b"owner v2 test: device key"))
        cls.dev2 = leansphincs.Key(keccak256(b"owner v2 test: another device key"))
        cls.own = owner.owner_address(cls.member.public_key)
        send(cls.rpc, cls.acct, owner.factory_address(),
             abi.calldata("deploy(bytes32)", ["bytes32"], [cls.member.public_key]), log=quiet)
        cls.rpc.call("anvil_setCode", [APPROVING, STUB_YES])

    @classmethod
    def tearDownClass(cls):
        cls.chain.close()

    def view(self, sig, types=(), values=(), to=None):
        return self.rpc.eth_call(to or self.own, abi.calldata(sig, list(types), list(values)))

    def tx(self, cd):
        return send(self.rpc, self.acct, self.own, cd, log=quiet)

    def certify(self, device, gen, key):
        sig = self.member.sign(owner.device_digest(CHAIN, self.own, device, gen, key))
        self.tx(owner.certify_device_calldata(device, gen, key, sig))

    def enroll(self, sk, device, gen, start, height=4, label=b"tree"):
        seed = owner.tree_seed(CHAIN, self.own, SAFE, device, gen, start)
        tree = wots.Tree.create(seed, keccak256(label + bytes([device, gen]) + start.to_bytes(8, "big")), height,
                                workers=1)
        cert = sk.sign(owner.certificate_digest(CHAIN, self.own, SAFE, device, gen, tree.root, height, start))
        self.tx(owner.enroll_calldata(SAFE, device, tree.root, height, start, cert))
        return tree, keccak256(label + bytes([device, gen]) + start.to_bytes(8, "big"))

    def tx_sig(self, tree, sk_seed, device, start, t: SafeTx, slot=0):
        h = t.hash(CHAIN, SAFE)
        k = owner.key_index(t.nonce, start, slot, tree.height)
        return h, owner.tx_signature_data(slot, device, SAFE, t.words(), wots.sign(tree.seed, sk_seed, k, h, wots.Prf.SIGNER),
                                          tree.path(k))

    def valid(self, h, data, who=None):
        return owner.is_valid_signature(self.rpc, who or self.own, h, data)

    def message_sig(self, sk, device, gen, app_hash, safe=SAFE):
        smh = messages.safe_message_hash(CHAIN, safe, app_hash)
        sig = sk.sign(owner.message_digest(CHAIN, self.own, safe, device, gen, smh))
        return smh, owner.message_signature_data(device, safe, messages.message_hash(app_hash), sig)

    # --- addresses, constants and views ---

    def test_1_addresses_and_constants(self):
        impl = owner.implementation_address()
        self.assertEqual(abi.dec_addr(self.view("predict(bytes32)", ["bytes32"], [self.member.public_key],
                                                to=owner.factory_address())), self.own)
        self.assertEqual(abi.dec_addr(self.view("IMPLEMENTATION()", to=owner.factory_address())), impl)
        self.assertEqual(self.rpc.code(self.own), owner.proxy_runtime(impl, self.member.public_key))
        self.assertEqual(owner.member_key_of(self.own, self.rpc.code(self.own)), self.member.public_key)
        self.assertTrue(owner.is_v2_owner(self.rpc, self.own))
        self.assertFalse(owner.is_v2_owner(self.rpc, impl))  # the implementation itself is no owner
        self.assertFalse(owner.is_v2_owner(self.rpc, APPROVING))
        self.assertIsNone(owner.member_key_of(TO, self.rpc.code(self.own)))  # the right code at another address
        self.assertEqual(abi.dec_word(self.view("KEY()")), self.member.public_key)
        for name, value in (("DEVICE_DOMAIN", owner.DEVICE_DOMAIN), ("REVOCATION_DOMAIN", owner.REVOCATION_DOMAIN),
                            ("CERTIFICATE_DOMAIN", owner.CERTIFICATE_DOMAIN), ("MESSAGE_DOMAIN", owner.MESSAGE_DOMAIN),
                            ("TREE_SEED_DOMAIN", owner.TREE_SEED_DOMAIN)):
            self.assertEqual(abi.dec_word(self.view(f"{name}()")), value, name)
        for name, value in (("SLOTS", owner.SLOTS), ("MAX_HEIGHT", owner.MAX_HEIGHT), ("MAX_START", owner.MAX_START),
                            ("MAX_DEVICE", owner.MAX_DEVICE), ("STATELESS_SIG_LEN", owner.STATELESS_SIG_LEN),
                            ("PARAMS", wots.PARAMS), ("N", wots.N)):
            self.assertEqual(abi.dec_uint(self.view(f"{name}()")), value, name)
        self.assertEqual(abi.dec_addr(self.view("STATELESS_VERIFIER()")), owner.verifier_address())
        self.assertEqual(abi.dec_addr(self.view("WOTS_VERIFIER()")), owner.wots_verifier_address())

    def test_2_digests_and_seeds(self):
        key = self.dev.public_key
        root = bytes(range(1, 25))
        smh = keccak256(b"a SafeMessage hash")
        for device in range(owner.MAX_DEVICE + 1):
            for gen in (0, 1, 7, owner.MAX_GENERATION):
                self.assertEqual(abi.dec_word(self.view("deviceDigest(uint8,uint16,bytes32)",
                                                        ["uint256", "uint256", "bytes32"], [device, gen, key])),
                                 owner.device_digest(CHAIN, self.own, device, gen, key))
                self.assertEqual(abi.dec_word(self.view("revocationDigest(uint8,uint16)", ["uint256", "uint256"],
                                                        [device, gen])),
                                 owner.revocation_digest(CHAIN, self.own, device, gen))
                for start, height in ((0, 1), (12345, 10), (owner.MAX_START, owner.MAX_HEIGHT)):
                    self.assertEqual(abi.dec_word(self.view(
                        "certificateDigest(address,uint8,uint16,bytes32,uint8,uint64)",
                        ["address", "uint256", "uint256", "bytes32", "uint256", "uint256"],
                        [SAFE, device, gen, owner.root_word(root), height, start])),
                        owner.certificate_digest(CHAIN, self.own, SAFE, device, gen, root, height, start))
                    self.assertEqual(abi.dec_uint(self.view(
                        "treeSeed(address,uint8,uint16,uint64)", ["address", "uint256", "uint256", "uint256"],
                        [SAFE, device, gen, start])), owner.tree_seed(CHAIN, self.own, SAFE, device, gen, start))
                self.assertEqual(abi.dec_word(self.view(
                    "messageDigest(address,uint8,uint16,bytes32)", ["address", "uint256", "uint256", "bytes32"],
                    [SAFE, device, gen, smh])), owner.message_digest(CHAIN, self.own, SAFE, device, gen, smh))
        # an empty device and an empty tree, as the signer reads them
        self.assertEqual(owner.read_device(self.rpc, self.own, 3), (bytes(32), 0, False))
        self.assertEqual(owner.read_tree(self.rpc, self.own, TO, 2), (None, 0, 0, 0, 0))
        self.assertEqual(owner.read_device(self.rpc, self.own, 0), (self.member.public_key, 0, True))

    # --- encodings, accepted and refused ---

    def test_3_device_lifecycle(self):
        key = self.dev.public_key
        # certifyDevice from the signer's calldata and the member key's signature of its digest
        self.certify(1, 1, key)
        self.assertEqual(owner.read_device(self.rpc, self.own, 1), (key, 1, True))
        # a certificate for another generation, or signed by the device key itself, is refused
        bad = self.dev.sign(owner.device_digest(CHAIN, self.own, 2, 1, key))
        with self.assertRaises(Reverted):
            self.rpc.eth_call(self.own, owner.certify_device_calldata(2, 1, key, bad))
        # the device key enrols its own tree, at its generation; the stored tree reads back with its seed
        tree, sk_seed = self.enroll(self.dev, 1, 1, 5)
        got = owner.read_tree(self.rpc, self.own, SAFE, 1)
        self.assertEqual(got, (tree.root, tree.seed, 4, 5, 1))
        self.assertTrue(owner.tree_usable(got, owner.read_device(self.rpc, self.own, 1)))
        # a transaction signature with device byte 1: valid through both EIP-1271 entry points
        t = SafeTx(to=TO, value=7, nonce=6)
        h, data = self.tx_sig(tree, sk_seed, 1, 5, t)
        self.assertEqual(len(data), owner.TX_HEADER + wots.SIG_BYTES + wots.N * 4)
        self.assertEqual(owner.parse_tx_signature_data(data)[:4], (0, 1, SAFE, t.words()))
        self.assertTrue(self.valid(h, data))
        legacy = self.view("isValidSignature(bytes,bytes)", ["bytes", "bytes"], [t.preimage(CHAIN, SAFE), data])
        self.assertEqual(legacy[:4], owner.LEGACY_MAGIC)
        # the same signature under another device byte is refused
        self.assertFalse(self.valid(h, data[:1] + b"\x02" + data[2:]))
        self.assertFalse(self.valid(h, data[:1] + b"\x00" + data[2:]))
        # a message signature by the device key at its generation
        app = keccak256(b"an app's hash")
        smh, mdata = self.message_sig(self.dev, 1, 1, app)
        self.assertEqual(len(mdata), owner.MESSAGE_LEN)
        self.assertTrue(self.valid(smh, mdata))
        self.assertFalse(self.valid(smh, self.message_sig(self.dev, 1, 0, app)[1]))  # another generation
        # revokeDevice: both stop verifying, and the tree stays in storage
        self.tx(owner.revoke_device_calldata(1, 1, self.member.sign(owner.revocation_digest(CHAIN, self.own, 1, 1))))
        self.assertEqual(owner.read_device(self.rpc, self.own, 1), (key, 1, False))
        self.assertEqual(owner.read_tree(self.rpc, self.own, SAFE, 1)[0], tree.root)
        self.assertFalse(owner.tree_usable(owner.read_tree(self.rpc, self.own, SAFE, 1),
                                           owner.read_device(self.rpc, self.own, 1)))
        self.assertFalse(self.valid(h, data))
        self.assertFalse(self.valid(smh, mdata))
        # certified again (generation 2, another key): the generation-1 tree stays void; a new one verifies
        self.certify(1, 2, self.dev2.public_key)
        self.assertFalse(self.valid(h, data))
        self.assertFalse(owner.tree_usable(owner.read_tree(self.rpc, self.own, SAFE, 1),
                                           owner.read_device(self.rpc, self.own, 1)))
        tree2, sk2 = self.enroll(self.dev2, 1, 2, 3)  # a new generation may start below the old tree
        self.assertEqual(owner.read_tree(self.rpc, self.own, SAFE, 1)[2:], (4, 3, 2))
        h2, data2 = self.tx_sig(tree2, sk2, 1, 3, SafeTx(to=TO, value=8, nonce=4))
        self.assertTrue(self.valid(h2, data2))
        self.assertTrue(self.valid(*self.message_sig(self.dev2, 1, 2, app)))
        self.assertFalse(self.valid(*self.message_sig(self.dev, 1, 2, app)))  # the replaced key

    def test_4_member_key_is_device_0(self):
        tree, sk_seed = self.enroll(self.member, 0, 0, 0, label=b"member tree")
        self.assertEqual(owner.read_tree(self.rpc, self.own, SAFE, 0)[4], 0)
        h, data = self.tx_sig(tree, sk_seed, 0, 0, SafeTx(to=TO, value=1, nonce=1), slot=1)
        self.assertTrue(self.valid(h, data))
        self.assertTrue(self.valid(*self.message_sig(self.member, 0, 0, keccak256(b"member message"))))
        # device 0 can't be certified or revoked
        with self.assertRaises(Reverted):
            self.rpc.eth_call(self.own, owner.revoke_device_calldata(
                0, 0, self.member.sign(owner.revocation_digest(CHAIN, self.own, 0, 0))))
        with self.assertRaises(ValueError):
            owner.tx_signature_data(0, 4, SAFE, [bytes(32)] * 10, b"", b"")

    def test_5_approved_kind(self):
        app = keccak256(b"a permit's hash")
        smh = messages.safe_message_hash(CHAIN, APPROVING, app)
        data = owner.approved_signature_data(APPROVING, messages.message_hash(app))
        self.assertEqual(len(data), owner.APPROVED_LEN)
        self.assertTrue(self.valid(smh, data))
        self.assertFalse(self.valid(messages.safe_message_hash(CHAIN, APPROVING, keccak256(b"other")), data))
        self.assertFalse(self.valid(messages.safe_message_hash(CHAIN, SAFE, app),
                                    owner.approved_signature_data(SAFE, messages.message_hash(app))))  # no code
        # in Safe's encoding: 150 bytes per owner, sorted, r = owner, s = offset, v = 0, then length and data
        other = "0x0000000000000000000000000000000000000001"
        blob = pack([(self.own, data, True), (other, data, True)])
        self.assertEqual(len(blob), 2 * 150)
        first = min(self.own, other, key=lambda o: int(o, 16))
        self.assertEqual(blob[12:32], h2b(first))
        self.assertEqual((int.from_bytes(blob[32:64], "big"), blob[64]), (130, 0))
        self.assertEqual(int.from_bytes(blob[130:162], "big"), 53)
        self.rpc.call("anvil_setCode", [APPROVING, STUB_NO])
        self.assertFalse(self.valid(smh, data))
        self.rpc.call("anvil_setCode", [APPROVING, STUB_YES])

    def test_6_signer_side_checks(self):
        with self.assertRaises(ValueError):
            owner.check_key(bytes(16) + b"\x01" * 16)
        with self.assertRaises(ValueError):
            owner.read_device(self.rpc, self.own, 4)
        self.assertIsNone(owner.parse_tx_signature_data(b"\x00\x04" + bytes(owner.TX_HEADER + wots.SIG_BYTES)))
        self.assertEqual(b2h(owner.enroll_calldata(SAFE, 2, b"\x01" * 24, 4, 9, b"")[:4]),
                         b2h(abi.selector("enroll(address,uint8,bytes32,uint8,uint64,bytes)")))


if __name__ == "__main__":
    unittest.main()
