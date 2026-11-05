"""The WalletConnect bridge's request handling (bridge.py), without a chain: what it answers by itself, what it
refuses before anything is signed, and how it maps the dapp's methods. The paths that sign and propose run end to end
in test_e2e_walletconnect.py."""
import builtins
import tempfile
import unittest

from winterlock_signer import abi, owner
from winterlock_signer.bridge import Bridge, RpcFail, Ui

SAFE = "0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2"
OWNERS = ["0x7141F0c30ABcF3Dc35d9409FFc3383009235c47d", "0x2D3C9197237D1F1e1165b1EEE748BC9e1c3f1123"]
OTHER = "0x000000000000000000000000000000000000cafE"
CHAIN = 11155111


class FakeRpc:
    """The Safe's views, and a record of what is passed through"""

    def __init__(self):
        self.calls = []

    def eth_call(self, to, data, **kw):
        if data == abi.calldata("nonce()"):
            return abi.encode(["uint256"], [7])
        if data == abi.calldata("getThreshold()"):
            return abi.encode(["uint256"], [2])
        if data == abi.calldata("getOwners()"):
            return abi.encode(["address[]"], [OWNERS])
        raise AssertionError(f"unexpected eth_call {data[:4].hex()}")

    def code(self, addr):
        if addr == Member.owner:  # the member's proxy owner
            return owner.proxy_runtime(owner.implementation_address(), Member.key)
        return b"\x60\x80"

    def call(self, method, params=()):
        self.calls.append((method, params))
        return {"eth_getBalance": "0x10", "eth_blockNumber": "0x5", "eth_getLogs": []}.get(method)


class Ctx:
    def __init__(self):
        self.rpc = FakeRpc()
        self.chain = CHAIN
        self.service = None


class Member:
    owner = OWNERS[0]
    key = bytes(range(1, 33))


class Handling(unittest.TestCase):
    def setUp(self):
        self.shown = []
        self.ctx = Ctx()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bridge = Bridge(Member(), self.ctx, SAFE, Ui(yes=False, out=self.shown.append), self.tmp.name, dapp={
            "name": "App", "url": "https://app.example"})

    def handle(self, method, params, chain=f"eip155:{CHAIN}"):
        return self.bridge.handle(method, params, chain)

    def fails(self, method, params, code, needle, chain=f"eip155:{CHAIN}"):
        with self.assertRaises(RpcFail) as e:
            self.handle(method, params, chain)
        self.assertEqual(e.exception.code, code, e.exception.message)
        self.assertIn(needle, e.exception.message)

    def test_answers_itself(self):
        self.assertEqual(self.handle("eth_accounts", []), [SAFE])
        self.assertEqual(self.handle("eth_requestAccounts", []), [SAFE])
        self.assertEqual(self.handle("eth_chainId", []), hex(CHAIN))
        self.assertEqual(self.handle("net_version", []), str(CHAIN))
        self.assertIsNone(self.handle("wallet_switchEthereumChain", [{"chainId": hex(CHAIN)}]))
        caps = self.handle("wallet_getCapabilities", [SAFE])
        self.assertEqual(caps[hex(CHAIN)]["atomic"], {"status": "supported"})
        self.assertEqual(self.handle("wallet_getCapabilities", [OTHER]), {})
        self.assertEqual(self.handle("eth_getBalance", [SAFE, "latest"]), "0x10")  # reads pass through
        self.assertEqual(self.ctx.rpc.calls, [("eth_getBalance", [SAFE, "latest"])])

    def test_refused_before_signing(self):
        self.fails("eth_accounts", [], 5100, "not eip155:1", chain="eip155:1")
        self.fails("wallet_switchEthereumChain", [{"chainId": "0x1"}], 4902, "chain 1")
        self.fails("eth_signTransaction", [{}], 4200, "raw transactions")
        self.fails("eth_sendRawTransaction", ["0x00"], 4200, "raw transactions")
        self.fails("wallet_addEthereumChain", [{}], 4200, "not supported")
        self.fails("eth_sendTransaction", [{"from": OTHER, "to": OTHER}], -32602, "not this Safe")
        self.fails("eth_sendTransaction", [{"from": SAFE, "data": "0x6080"}], 4200, "creates a contract")
        self.fails("eth_sendTransaction", [{"to": "0x1234"}], -32602, "not an address")
        self.fails("eth_sendTransaction", [{"to": OTHER, "chainId": "0x1"}], 5100, "chain 0x1")
        self.fails("eth_sendTransaction", [{"to": OTHER, "value": "lots"}], -32602, "not a number")
        for sig, args in (("addOwnerWithThreshold(address,uint256)", [OTHER, 1]), ("enableModule(address)", [OTHER]),
                          ("setGuard(address)", [OTHER]), ("changeThreshold(uint256)", [1]),
                          ("setFallbackHandler(address)", [OTHER])):
            types = ["address", "uint256"][:len(args)] if "Owner" in sig else (["uint256"] if "Threshold" in sig
                                                                                else ["address"])
            data = abi.b2h(abi.calldata(sig, types, args))
            self.fails("eth_sendTransaction", [{"to": SAFE, "data": data}], 4001, "owners, threshold, modules")
            self.fails("wallet_sendCalls", [{"calls": [{"to": OTHER}, {"to": SAFE, "data": data}]}], 4001,
                       "owners, threshold, modules")
        self.fails("wallet_sendCalls", [{"calls": []}], -32602, "needs a bundle")
        self.fails("wallet_sendCalls", [{"chainId": "0x1", "calls": [{"to": OTHER}]}], 5100, "chain")
        self.fails("wallet_sendCalls", [{"from": OTHER, "calls": [{"to": OTHER}]}], -32602, "not this Safe")
        self.fails("wallet_sendCalls", [{"calls": [{"to": OTHER}], "capabilities": {
            "paymasterService": {"url": "x", "optional": False}}}], 5700, "paymasterService")
        self.fails("wallet_getCallsStatus", ["0x" + "11" * 32], 5730, "unknown bundle id")
        self.assertEqual(self.shown, [])  # nothing was decoded for signing, so nothing was shown

    def test_messages_refused_with_reason(self):
        self.fails("personal_sign", ["0x" + "ab" * 32, SAFE], 4001, "bare 32-byte hash")
        self.fails("eth_sign", [SAFE, "0x" + "ab" * 32], 4001, "eth_sign")
        self.fails("personal_sign", ["0x68656c6c6f", OTHER], 4001, "not by this Safe")
        self.assertTrue(any("REFUSED" in line for line in self.shown))

    def test_member_says_no(self):
        """A message the rules allow is still signed only if the member agrees"""
        asked = []
        orig = builtins.input
        builtins.input = lambda q: asked.append(q) or "n"
        try:
            self.fails("personal_sign", ["0x68656c6c6f", SAFE], 4001, "the member rejected the message")
        finally:
            builtins.input = orig
        self.assertEqual(asked, ["Sign this message with your stateless key? [y/N] "])
        self.assertTrue(any("OFF-CHAIN" in line for line in self.shown))

    def test_unknown_hash_lookups_pass_through(self):
        self.assertIsNone(self.handle("eth_getTransactionReceipt", ["0x" + "22" * 32]))
        self.assertEqual(self.ctx.rpc.calls[-1][0], "eth_getTransactionReceipt")


if __name__ == "__main__":
    unittest.main()
