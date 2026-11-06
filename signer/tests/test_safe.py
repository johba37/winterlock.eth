"""Safe transactions and signature blobs, ABI helpers, owner digests, and the gas account's transactions."""
import unittest

from winterlock_signer import abi, ethtx, owner
from winterlock_signer.keccak import keccak256
from winterlock_signer.safe import SafeTx, contract_signature, decode, pack, parse_signature

SAFE = "0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2"
A, B = "0x00000000000000000000000000000000000000AA", "0x00000000000000000000000000000000000000BB"


class Encoding(unittest.TestCase):
    def test_checksum(self):
        self.assertEqual(abi.checksum("0x5b81d3ce1ca48be48f154d8ad060cf9f883e86b2"), SAFE)
        with self.assertRaises(ValueError):
            abi.address("0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86b2".replace("B81", "b81"))

    def test_abi_encode_dynamic(self):
        enc = abi.encode(["uint256", "bytes", "address[]"], [7, b"\x01\x02", [A, B]])
        self.assertEqual(abi.dec_uint(enc, 0), 7)
        self.assertEqual(abi.dec_bytes(enc, 1), b"\x01\x02")
        self.assertEqual(abi.dec_addresses(enc, 2), [abi.checksum(A), abi.checksum(B)])

    def test_owner_constants(self):
        self.assertEqual(owner.verifier_address(), "0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254")  # docs/decisions.md
        self.assertEqual(owner.TX_HEADER, 342)  # v2: [slot][device][safe][SafeTx]
        self.assertEqual((owner.MESSAGE_LEN, owner.APPROVED_LEN), (5738, 53))
        cd = owner.deploy_and_enroll_calldata(b"\x11" * 32, A, b"\x22" * 24, 6, 3, b"\x33" * 5684)
        self.assertEqual(cd[:4], abi.selector("deployAndEnroll(bytes32,address,bytes32,uint8,uint64,bytes)"))
        self.assertEqual(abi.dec_word(cd[4:], 2), b"\x22" * 24 + bytes(8))  # root high-aligned
        self.assertEqual(owner.capacity(10), 512)
        self.assertEqual(owner.key_index(9, 5, 1, 4), 9)


class Signatures(unittest.TestCase):
    def test_pack_orders_owners(self):
        da, db = b"\xaa" * 3, b"\xbb" * 5
        blob = pack([(B, db, True), (A, da, True)])
        self.assertEqual(blob[12:32], abi.h2b(A))  # lowest owner first
        self.assertEqual(int.from_bytes(blob[32:64], "big"), 130)
        self.assertEqual(blob[64], 0)
        self.assertEqual(blob[130:162], abi.word(3))
        with self.assertRaises(ValueError):
            pack([(A, da, True), (A, db, True)])

    def test_standalone_roundtrip(self):
        s = contract_signature(A, b"\x01" * 40)
        self.assertEqual(parse_signature(s), (abi.checksum(A), b"\x01" * 40, True))
        self.assertEqual(parse_signature(b"\x02" * 65), (None, b"\x02" * 65, False))

    def test_safe_tx_json_roundtrip(self):
        t = SafeTx(to=A, value=5, data=b"\x12\x34", nonce=9)
        self.assertEqual(SafeTx.from_json(t.to_json()), t)
        self.assertEqual(t.hash(1, SAFE), keccak256(t.preimage(1, SAFE)))
        self.assertNotEqual(t.hash(1, SAFE), t.hash(11155111, SAFE))


class Decoding(unittest.TestCase):
    def test_amounts_are_exact(self):
        from winterlock_signer.safe import fmt_eth
        self.assertEqual(fmt_eth(10**17), "0.1 ETH (100,000,000,000,000,000 wei)")  # a float gives 0.100000000000000006
        self.assertEqual(fmt_eth(0), "0 ETH (0 wei)")
        self.assertEqual(fmt_eth(3 * 10**18 + 1), "3.000000000000000001 ETH (3,000,000,000,000,000,001 wei)")

    def test_kinds(self):
        lines, warn = decode(SafeTx(to=A, value=10**15), SAFE)
        self.assertIn("0.001 ETH", lines[0])
        lines, _ = decode(SafeTx(to=SAFE, nonce=4), SAFE)
        self.assertIn("Cancel", lines[0])
        data = abi.calldata("transfer(address,uint256)", ["address", "uint256"], [B, 12345])
        lines, _ = decode(SafeTx(to=A, data=data), SAFE)
        self.assertIn("ERC-20 transfer", lines[0])
        self.assertIn("12,345", lines[0])
        data = abi.calldata("enableModule(address)", ["address"], [B])
        _, warn = decode(SafeTx(to=SAFE, data=data), SAFE)
        self.assertTrue(any("controls this Safe" in w for w in warn))
        _, warn = decode(SafeTx(to=A, data=b"\x01\x02\x03\x04", operation=1), SAFE)
        self.assertTrue(any("DELEGATECALL" in w for w in warn))
        inner = bytes([0]) + abi.h2b(A) + abi.word(1) + abi.word(0)
        ms = abi.calldata("multiSend(bytes)", ["bytes"], [inner + inner])
        lines, _ = decode(SafeTx(to=B, data=ms, operation=1), SAFE)
        self.assertEqual(sum(x.strip().startswith("Send") for x in lines), 2)


class GasAccount(unittest.TestCase):
    def test_known_address(self):
        # anvil's first default account
        acct = ethtx.Account("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        self.assertEqual(acct.address, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        self.assertNotIn("ac0974", repr(acct))

    def test_rlp(self):
        self.assertEqual(ethtx.rlp(b""), b"\x80")
        self.assertEqual(ethtx.rlp(0), b"\x80")
        self.assertEqual(ethtx.rlp(127), b"\x7f")
        self.assertEqual(ethtx.rlp(1024), b"\x82\x04\x00")
        self.assertEqual(ethtx.rlp([]), b"\xc0")
        self.assertEqual(ethtx.rlp(b"\x00" * 56)[:2], b"\xb8\x38")

    def test_low_s(self):
        for i in range(5):
            _, r, s = ethtx.sign_hash(12345 + i, keccak256(bytes([i])))
            self.assertLessEqual(s, ethtx.N // 2)


if __name__ == "__main__":
    unittest.main()


class PinnedBytecode(unittest.TestCase):
    """The signer computes and deploys owners from winterlock_signer/contracts.json; it must be the repository's
    build, or every member's owner address silently differs from the contracts' tests and scripts"""

    def test_matches_build(self):
        import json
        import os
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        pinned_by_name = {"WinterlockOwner": owner.IMPLEMENTATION_CREATION,
                          "WinterlockOwnerFactory": owner.FACTORY_CREATION, "LeanSphincsAsm": owner.VERIFIER_CREATION,
                          "SharedWotsVerifier": owner.WOTS_VERIFIER_CREATION}
        for name, pinned in pinned_by_name.items():
            sol = f"{name}.sol"
            path = os.path.join(root, "contracts", "out", sol, f"{name}.json")
            if not os.path.exists(path):
                self.skipTest("contracts/ not built")
            with open(path) as f:
                built = abi.h2b(json.load(f)["bytecode"]["object"])
            self.assertEqual(keccak256(pinned), keccak256(built),
                             f"{name} changed: re-run signer/tools/pin_contracts.py (owner addresses change)")
