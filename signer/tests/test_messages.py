"""Messages for dapps (messages.py, eip712.py, safelibs.py): typed-data and personal-message hashes against ethers,
D14's decision rules (which requests go off-chain, on-chain, or are refused), the message files members exchange, and
the pinned Safe libraries a delegatecall may target."""
import copy
import json
import os
import unittest

from winterlock_signer import messages, safelibs
from winterlock_signer.abi import b2h, checksum
from winterlock_signer.eip712 import TypedData, encode_atomic, personal_hash
from winterlock_signer.keccak import keccak256
from winterlock_signer.safe import pack

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
with open(os.path.join(HERE, "vectors", "eip712.json")) as f:
    V = json.load(f)
SAFE = "0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2"
OWNER = "0x7141F0c30ABcF3Dc35d9409FFc3383009235c47d"
CHAIN = 11155111
NOW = 1793900000  # 2026-11-05


def hx(s: str) -> str:
    return b2h(s.encode())


def siwe(address=SAFE, domain="app.example", chain=CHAIN, extra=""):
    return (f"{domain} wants you to sign in with your Ethereum account:\n{address}\n\nSign in.\n\n"
            f"URI: https://{domain}/login\nVersion: 1\nChain ID: {chain}\nNonce: 1234abcd\n"
            f"Issued At: 2026-11-05T12:00:00Z{extra}")


def typed(primary, types, message, domain):
    return json.dumps({"types": types, "primaryType": primary, "domain": domain, "message": message})


PERMIT = {"Permit": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
                     {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"},
                     {"name": "deadline", "type": "uint256"}]}


class Hashes(unittest.TestCase):
    def test_typed_data_matches_ethers(self):
        for case in V["typed"]:
            self.assertEqual(b2h(TypedData(case["data"]).hash()), case["hash"], case["name"])
            self.assertEqual(b2h(TypedData(json.dumps(case["data"])).hash()), case["hash"])

    def test_personal_matches_ethers(self):
        for case in V["personal"]:
            self.assertEqual(b2h(personal_hash(case["message"].encode())), case["hash"])

    def test_domain_type_inferred_as_viem_does(self):
        data = copy.deepcopy(V["typed"][0]["data"])  # ethers omits EIP712Domain; it is inferred from the domain
        self.assertNotIn("EIP712Domain", data["types"])
        self.assertEqual(TypedData(data).encode_type("EIP712Domain"),
                         "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

    def test_values_must_fit_their_types(self):
        with self.assertRaises(ValueError):
            encode_atomic("uint8", 256)
        with self.assertRaises(ValueError):
            encode_atomic("int8", -129)
        self.assertEqual(encode_atomic("int8", -1), b"\xff" * 32)
        with self.assertRaises(ValueError):
            encode_atomic("bytes4", "0x0102")
        with self.assertRaises(ValueError):
            encode_atomic("address", "0x1234")
        with self.assertRaises(ValueError):
            encode_atomic("bool", 1)
        with self.assertRaises(ValueError):
            encode_atomic("uint7", 1)
        data = copy.deepcopy(V["typed"][0]["data"])
        data["message"]["extra"] = 1
        with self.assertRaises(ValueError):
            TypedData(data).hash()  # a field its type doesn't declare
        data = copy.deepcopy(V["typed"][0]["data"])
        del data["message"]["contents"]
        with self.assertRaises(ValueError):
            TypedData(data).hash()
        data = copy.deepcopy(V["typed"][0]["data"])
        data["types"]["Mail"].append({"name": "x", "type": "Unknown"})
        with self.assertRaises(ValueError):
            TypedData(data)


class Decisions(unittest.TestCase):
    def decide(self, method, params, url="https://app.example", owners=(OWNER,)):
        return messages.decide(method, params, SAFE, CHAIN, url, owners, now=NOW)

    def assertPath(self, d, path, needle=None):
        self.assertEqual(d.path, path, d.reason)
        if needle:
            self.assertIn(needle, d.reason + " " + d.kind + " " + " ".join(d.warnings))

    def test_sign_in(self):
        d = self.decide("personal_sign", [hx(siwe()), SAFE])
        self.assertPath(d, messages.OFFCHAIN, "sign-in")
        self.assertEqual(d.app_hash, personal_hash(siwe().encode()))
        self.assertPath(self.decide("personal_sign", [SAFE, hx(siwe())]), messages.OFFCHAIN)  # reversed order
        self.assertPath(self.decide("personal_sign", [siwe(), SAFE]), messages.OFFCHAIN)  # plain text, not hex
        self.assertPath(self.decide("personal_sign", [hx(siwe(domain="sub.app.example")), SAFE]), messages.OFFCHAIN)
        self.assertPath(self.decide("personal_sign", [hx(siwe(address=OWNER)), SAFE]), messages.REFUSE, "not this Safe")
        self.assertPath(self.decide("personal_sign", [hx(siwe(chain=1)), SAFE]), messages.REFUSE, "chain 1")
        self.assertPath(self.decide("personal_sign", [hx(siwe(domain="evil.example")), SAFE]), messages.REFUSE,
                        "somewhere else")
        expired = siwe(extra="\nExpiration Time: 2026-01-01T00:00:00Z")
        self.assertPath(self.decide("personal_sign", [hx(expired), SAFE]), messages.REFUSE, "expired")
        # a member signing from a file has no app URL to compare: allowed, with a warning naming the domain
        self.assertPath(self.decide("personal_sign", [hx(siwe()), SAFE], url=None), messages.OFFCHAIN,
                        "check that you are signing in to app.example")

    def test_text_and_refusals(self):
        self.assertPath(self.decide("personal_sign", [hx("Welcome! Sign to accept the terms."), SAFE]),
                        messages.OFFCHAIN, "text message")
        self.assertPath(self.decide("personal_sign", ["0x" + "ab" * 32, SAFE]), messages.REFUSE, "bare 32-byte hash")
        self.assertPath(self.decide("personal_sign", ["0x" + "ff" * 20, SAFE]), messages.REFUSE, "binary")
        self.assertPath(self.decide("personal_sign", [hx("pay ‮evil"), SAFE]), messages.REFUSE, "U+202E")
        self.assertPath(self.decide("personal_sign", [hx("zero​width"), SAFE]), messages.REFUSE, "invisible")
        self.assertPath(self.decide("personal_sign", ["0x", SAFE]), messages.REFUSE, "empty")
        self.assertPath(self.decide("personal_sign", [hx("hi"), OWNER]), messages.REFUSE, "not by this Safe")
        self.assertPath(self.decide("personal_sign", [hx("hi")]), messages.REFUSE, "two parameters")
        self.assertPath(self.decide("eth_sign", [SAFE, "0x" + "ab" * 32]), messages.REFUSE, "bare hash")

    def test_typed_data(self):
        p2 = V["typed"][2]["data"]
        p2 = dict(p2, domain=dict(p2["domain"], chainId=CHAIN))
        d = self.decide("eth_signTypedData_v4", [SAFE, json.dumps(p2)])
        self.assertPath(d, messages.ONCHAIN, "unlimited Permit2 allowance")
        self.assertEqual(d.app_hash, TypedData(p2).hash())
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, p2]), messages.ONCHAIN)  # an object, not a string
        self.assertPath(self.decide("eth_signTypedData_v4", [json.dumps(p2), SAFE]), messages.ONCHAIN)  # reversed
        # EIP-2612: on-chain, with the ECDSA-only warning; another owner is refused
        dom = {"name": "USD Coin", "version": "2", "chainId": CHAIN, "verifyingContract": OWNER.replace("7", "8")}
        msg = {"owner": SAFE, "spender": OWNER, "value": str(2**256 - 1), "nonce": 0, "deadline": NOW + 3600}
        d = self.decide("eth_signTypedData_v4", [SAFE, typed("Permit", PERMIT, msg, dom)])
        self.assertPath(d, messages.ONCHAIN, "ECDSA")
        self.assertTrue(any("unlimited" in w for w in d.warnings))
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Permit", PERMIT, dict(msg, owner=OWNER),
                                                                         dom)]), messages.REFUSE, "permit's owner")
        d = self.decide("eth_signTypedData_v4", [SAFE, typed("Permit", PERMIT, dict(msg, deadline=NOW - 10), dom)])
        self.assertTrue(any("in the past" in w for w in d.warnings))
        # DAI's permit: ecrecover only
        dai = {"Permit": [{"name": "holder", "type": "address"}, {"name": "spender", "type": "address"},
                          {"name": "nonce", "type": "uint256"}, {"name": "expiry", "type": "uint256"},
                          {"name": "allowed", "type": "bool"}]}
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Permit", dai, {
            "holder": SAFE, "spender": OWNER, "nonce": 0, "expiry": 0, "allowed": True}, dom)]), messages.REFUSE,
            "ecrecover")
        # an order a contract settles: on-chain; typed data with no contract: off-chain
        order = {"Order": [{"name": "maker", "type": "address"}, {"name": "amount", "type": "uint256"}]}
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Order", order, {"maker": SAFE, "amount": 5},
                                                                         dom)]), messages.ONCHAIN, "verifying contract")
        login = {"Login": [{"name": "user", "type": "address"}, {"name": "nonce", "type": "string"}]}
        d = self.decide("eth_signTypedData_v4", [SAFE, typed("Login", login, {"user": SAFE, "nonce": "x"},
                                                             {"name": "Example", "chainId": CHAIN})])
        self.assertPath(d, messages.OFFCHAIN, "no verifying contract")

    def test_typed_data_refusals(self):
        dom = {"chainId": CHAIN, "verifyingContract": SAFE}
        safetx = {"SafeTx": [{"name": "to", "type": "address"}, {"name": "nonce", "type": "uint256"}]}
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("SafeTx", safetx, {"to": OWNER, "nonce": 1},
                                                                         dom)]), messages.REFUSE, "the Safe itself")
        other = {"Thing": [{"name": "x", "type": "uint256"}]}
        for vc in (SAFE, OWNER):  # any type, addressed to the Safe or one of its owners
            self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Thing", other, {"x": 1}, dict(
                dom, verifyingContract=vc))]), messages.REFUSE, "the Safe itself")
        enable = {"Enable": [{"name": "validationId", "type": "bytes21"}, {"name": "nonce", "type": "uint32"}]}
        kernel = {"name": "Kernel", "version": "0.3.3", "chainId": CHAIN, "verifyingContract": OWNER.replace("7", "9")}
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Enable", enable, {
            "validationId": "0x" + "01" * 21, "nonce": 1}, kernel)]), messages.REFUSE, "validator")
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Thing", other, {"x": 1}, dict(
            kernel, name="Winterlock"))]), messages.REFUSE, "validator")
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Thing", other, {"x": 1}, {
            "chainId": 1})]), messages.REFUSE, "chain 1")
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("EIP712Domain", {}, {}, {
            "name": "x", "chainId": CHAIN})]), messages.REFUSE, "bare domain")
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, "{not json"]), messages.REFUSE, "doesn't decode")
        self.assertPath(self.decide("eth_signTypedData_v4", [SAFE, typed("Thing", other, {"x": "abc"}, {
            "chainId": CHAIN})]), messages.REFUSE, "doesn't decode")
        self.assertPath(self.decide("eth_signTypedData_v4", [OWNER, typed("Thing", other, {"x": 1}, {
            "chainId": CHAIN})]), messages.REFUSE, "not by this Safe")


class Files(unittest.TestCase):
    def test_doc_roundtrip_and_tampering(self):
        params = [hx(siwe()), SAFE]
        d = messages.decide("personal_sign", params, SAFE, CHAIN, "https://app.example", (), NOW)
        doc = messages.new_doc(CHAIN, SAFE, "personal_sign", params, d, {"name": "App", "url": "https://app.example",
                                                                           "icons": ["x"]})
        self.assertEqual(doc["dapp"], {"name": "App", "url": "https://app.example"})
        d2 = messages.check_doc(json.loads(json.dumps(doc)), CHAIN, now=NOW)
        self.assertEqual((d2.path, d2.app_hash), (messages.OFFCHAIN, d.app_hash))
        bad = dict(doc, appHash=b2h(b"\x01" * 32))
        with self.assertRaises(ValueError):
            messages.check_doc(bad, CHAIN, now=NOW)
        bad = dict(doc, request={"method": "personal_sign", "params": [hx("another text"), SAFE]})
        with self.assertRaises(ValueError):
            messages.check_doc(bad, CHAIN, now=NOW)  # another message under the same hashes
        with self.assertRaises(ValueError):
            messages.check_doc(doc, 1, now=NOW)
        # a file whose app URL doesn't match the sign-in's domain is refused by every member, not only the first
        self.assertEqual(messages.check_doc(dict(doc, dapp={"url": "https://evil.example"}), CHAIN, now=NOW).path,
                         messages.REFUSE)

    def test_merge_and_combine(self):
        d = messages.decide("personal_sign", [hx("hello"), SAFE], SAFE, CHAIN, None, (), NOW)
        a = messages.new_doc(CHAIN, SAFE, "personal_sign", [hx("hello"), SAFE], d)
        b = copy.deepcopy(a)
        messages.add_signature(a, OWNER, "0x01")
        messages.add_signature(b, SAFE, "0x02")
        self.assertEqual(messages.merge(a, b), 1)
        self.assertEqual(messages.merge(a, b), 0)
        other = messages.new_doc(CHAIN, SAFE, "personal_sign", [hx("other"), SAFE], messages.decide(
            "personal_sign", [hx("other"), SAFE], SAFE, CHAIN, None, (), NOW))
        messages.add_signature(other, checksum("0x" + "33" * 20), "0x03")
        self.assertEqual(messages.merge(a, other), 0)  # another message
        sigs = [(checksum("0x" + "22" * 20), b"\x02" * 3, True), (checksum("0x" + "11" * 20), b"\x01" * 3, True),
                (checksum("0x" + "33" * 20), b"\x03" * 3, True)]
        blob = messages.combine(sigs, 2)
        self.assertEqual(blob, pack(sigs[:2]))
        self.assertEqual(blob[12:32], bytes.fromhex("11" * 20))  # increasing owner order
        with self.assertRaises(ValueError):
            messages.combine(sigs[:1], 2)

    def test_safe_message_hash(self):
        """Safe's CompatibilityFallbackHandler.getMessageHashForSafe(safe, abi.encode(h)), recomputed: the SafeMessage
        struct over keccak256(abi.encode(h)) in the Safe's EIP-712 domain"""
        h = keccak256(b"app hash")
        domain = keccak256(keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)")
                           + CHAIN.to_bytes(32, "big") + bytes(12) + bytes.fromhex(SAFE[2:]))
        struct = keccak256(keccak256(b"SafeMessage(bytes message)") + keccak256(h))
        self.assertEqual(messages.safe_message_hash(CHAIN, SAFE, h), keccak256(b"\x19\x01" + domain + struct))
        self.assertEqual(messages.sign_message_calldata(h)[:4], bytes.fromhex("85a5affe"))


class FakeRpc:
    def __init__(self, code):
        self._code = code

    def code(self, addr):
        return self._code


class Libraries(unittest.TestCase):
    def test_canonical_code_and_local_build_pass(self):
        with open(os.path.join(HERE, "vectors", "safe_libs_canonical.json")) as f:
            canonical = json.load(f)
        for name in (safelibs.SIGN_MESSAGE_LIB, safelibs.MULTISEND):
            code = bytes.fromhex(canonical[name][2:])
            self.assertEqual(safelibs.check(FakeRpc(code), name), safelibs.default_address(name))
            other_metadata = code[:-20] + b"\x00" * 18 + code[-2:]
            self.assertEqual(safelibs.check(FakeRpc(other_metadata), name), safelibs.default_address(name))
            changed = bytearray(code)
            changed[40] ^= 1
            for bad in (bytes(changed), b"", code[:-60] + code[-2:]):
                with self.assertRaises(safelibs.UnknownLibrary):
                    safelibs.check(FakeRpc(bad), name)

    @unittest.skipUnless(os.path.exists(os.path.join(ROOT, "contracts/lib/safe-smart-account-v1.4.1/build/forge-out/"
                                                           "SignMessageLib.sol/SignMessageLib.json")),
                         "Safe v1.4.1's release build is missing (contracts/setup.sh)")
    def test_pin_matches_build(self):
        for name in (safelibs.SIGN_MESSAGE_LIB, safelibs.MULTISEND):
            path = os.path.join(ROOT, f"contracts/lib/safe-smart-account-v1.4.1/build/forge-out/{name}.sol/{name}.json")
            with open(path) as f:
                code = bytes.fromhex(json.load(f)["deployedBytecode"]["object"][2:])
            self.assertEqual("0x" + keccak256(safelibs.strip_metadata(code)).hex(),
                             safelibs.PINNED[name]["codeWithoutMetadataHash"], f"re-run tools/pin_safe_libs.py ({name})")


if __name__ == "__main__":
    unittest.main()
