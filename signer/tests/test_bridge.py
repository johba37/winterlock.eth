"""The WalletConnect bridge's request handling (bridge.py), without a chain: what it answers by itself, what it
refuses before anything is signed, and how it maps the dapp's methods. The paths that sign and propose run end to end
in test_e2e_walletconnect.py."""
import builtins
import tempfile
import unittest

from winterlock_signer import abi, owner
from winterlock_signer.bridge import Bridge, RpcFail, Ui

SAFE = "0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2"
KEY = bytes(range(1, 33))  # the member key of the member at the keyboard
KEYS = [KEY, bytes(range(101, 133))]
OWNERS = [owner.owner_address(k) for k in KEYS]
PERMIT2 = {"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"},
                                      {"name": "verifyingContract", "type": "address"}],
                     "PermitSingle": [{"name": "details", "type": "PermitDetails"},
                                      {"name": "spender", "type": "address"}, {"name": "sigDeadline", "type": "uint256"}],
                     "PermitDetails": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"},
                                       {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}]},
           "primaryType": "PermitSingle",
           "domain": {"name": "Permit2", "chainId": 11155111,
                      "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
           "message": {"details": {"token": "0x1111111111111111111111111111111111111111", "amount": "1000000",
                                   "expiration": 4102444800, "nonce": 0},
                       "spender": "0x2222222222222222222222222222222222222222", "sigDeadline": "4102444800"}}
OTHER = "0x000000000000000000000000000000000000cafE"
CHAIN = 11155111


class FakeRpc:
    """The Safe's views, and a record of what is passed through. The Safe has approved every message on-chain
    (signedMessages), and its isValidSignature accepts the empty signature and whatever `accepts` allows."""

    def __init__(self):
        self.calls = []
        self.v2_owners = {OWNERS[0]}
        self.accepts = lambda sig: True
        self.checked = []

    def eth_call(self, to, data, **kw):
        if data[:4] == abi.selector("signedMessages(bytes32)"):
            return abi.encode(["uint256"], [1])
        if data[:4] == abi.selector("isValidSignature(bytes32,bytes)"):
            sig = abi.dec_bytes(data[4:], 1)
            self.checked.append(sig)
            ok = sig == b"" or self.accepts(sig)
            return (owner.MAGIC if ok else b"\xff" * 4).ljust(32, b"\x00")
        if data == abi.calldata("nonce()"):
            return abi.encode(["uint256"], [7])
        if data == abi.calldata("getThreshold()"):
            return abi.encode(["uint256"], [2])
        if data == abi.calldata("getOwners()"):
            return abi.encode(["address[]"], [OWNERS])
        raise AssertionError(f"unexpected eth_call {data[:4].hex()}")

    def code(self, addr):
        if addr in self.v2_owners:  # a member's proxy owner
            key = KEYS[OWNERS.index(addr)]
            return owner.proxy_runtime(owner.implementation_address(), key)
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
    key = KEY
    device_no = 0
    is_device = False


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
        self.assertEqual(asked, ["Sign this message with your member key? [y/N] "])
        self.assertTrue(any("OFF-CHAIN" in line for line in self.shown))

    def test_approved_answers(self):
        """A message the Safe has approved on-chain is answered with k approved signatures of v2 owners, checked with
        the Safe's isValidSignature; with fewer than k v2 owners, or if the Safe refuses them, with 0x and a warning"""
        import json
        from winterlock_signer import messages
        from winterlock_signer.eip712 import TypedData
        params = [SAFE, json.dumps(PERMIT2)]
        app_hash = TypedData(PERMIT2).hash()
        rpc = self.ctx.rpc
        # one of the two owners is a v2 owner, the threshold is 2: 0x, with the reason
        self.assertEqual(self.handle("eth_signTypedData_v4", params), "0x")
        self.assertTrue(any("WARNING: only 1 of the Safe's 2 owners are v2 Winterlock owners, fewer than its "
                            "threshold of 2" in line for line in self.shown), self.shown)
        self.assertEqual(rpc.checked[-1], b"")  # the empty signature was checked too before it was released
        # both are: two approved signatures, 150 bytes each, sorted by owner, checked by the Safe before release
        rpc.v2_owners = set(OWNERS)
        answer = abi.h2b(self.handle("eth_signTypedData_v4", params))
        self.assertEqual(answer, messages.approved_signatures(SAFE, app_hash, OWNERS))
        self.assertEqual(len(answer), 300)
        first, second = sorted(OWNERS, key=lambda o: int(o, 16))
        self.assertEqual((abi.checksum(answer[12:32]), abi.checksum(answer[77:97])), (first, second))
        self.assertEqual([int.from_bytes(answer[32:64], "big"), int.from_bytes(answer[97:129], "big")], [130, 215])
        self.assertEqual(answer[130:162], abi.word(53))
        self.assertEqual(answer[162:215], b"\x03" + abi.h2b(SAFE) + messages.message_hash(app_hash))
        self.assertEqual(rpc.checked[-1], answer)
        # the Safe refuses them (it shouldn't): 0x instead, with a warning
        rpc.accepts = lambda sig: False
        self.assertEqual(self.handle("eth_signTypedData_v4", params), "0x")
        self.assertTrue(any("refuses the approved signatures" in line for line in self.shown))

    def test_execution_watch_survives_a_lagging_node(self):
        """A node behind the one that gave the proposal's block refuses the log range: not executed yet, no error"""
        from winterlock_signer.rpc import RpcError
        h = "0x" + "33" * 32
        self.bridge.submitted[h] = {"nonce": 6, "block": 1000, "calls": 1}  # the Safe is at nonce 7: passed
        seen = []

        def call(method, params=()):
            if method == "eth_getLogs":
                seen.append(params[0]["fromBlock"])
                raise RpcError("eth_getLogs: invalid block range params")
            return hex(1010) if method == "eth_blockNumber" else None
        self.ctx.rpc.call = call
        self.assertIsNone(self.bridge.execution(h))
        self.assertEqual(seen[0], hex(1000 - 64))  # looks back a little, too
        self.assertTrue(any("the node refused the log query" in line for line in self.shown))
        self.assertIsNone(self.handle("eth_getTransactionReceipt", [h]))

    def chain_with_logs(self, executed_at, h, limit=None):
        """eth_getLogs over blocks up to self.head, with the Safe's ExecutionSuccess for `h` at `executed_at`, from a
        node that refuses ranges over `limit` blocks as Alchemy's free tier does (its message, 2026-11-06)"""
        from winterlock_signer.bridge import SUCCESS_TOPIC
        from winterlock_signer.rpc import RpcError
        self.queries = []

        def call(method, params=()):
            if method == "eth_blockNumber":
                return hex(self.head)
            if method == "eth_getLogs":
                f = params[0]
                lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
                self.queries.append((lo, hi))
                if limit and hi - lo + 1 > limit:
                    raise RpcError("eth_getLogs at https://eth-sepolia.g.alchemy.com: Under the Free tier plan, you "
                                   "can make eth_getLogs requests with up to a 10 block range.")
                self.assertEqual(f["address"], SAFE)
                return [{"topics": [SUCCESS_TOPIC, h], "data": "0x" + "00" * 32, "transactionHash": "0x" + "ee" * 32}
                        ] if lo <= executed_at <= hi <= self.head else []
            raise AssertionError(method)
        self.ctx.rpc.call = call

    def test_execution_found_under_a_ten_block_limit(self):
        """Live on Sepolia (2026-11-06), Alchemy refused the bridge's log query (the proposal's block minus 64 to the
        latest) on every poll, so the dapp never got its receipt"""
        h = "0x" + "44" * 32
        self.bridge.submitted[h] = {"nonce": 6, "block": 1000, "calls": 1}
        self.head = 1100
        self.chain_with_logs(1050, h, limit=10)
        self.assertEqual(self.bridge.execution(h), ("0x" + "ee" * 32, True))
        self.assertEqual(self.queries[0], (936, 1100))  # refused, then 10 blocks at a time from 936
        self.assertEqual(self.queries[1:3], [(936, 945), (946, 955)])
        self.assertTrue(all(hi - lo + 1 <= 10 for lo, hi in self.queries[1:]))
        self.assertEqual(self.queries[-1], (1046, 1055))
        n = len(self.queries)
        self.assertEqual(self.bridge.execution(h), ("0x" + "ee" * 32, True))  # remembered: no more queries
        self.assertEqual(len(self.queries), n)

    def test_execution_waits_for_the_nonce_and_resumes(self):
        h = "0x" + "55" * 32
        self.bridge.submitted[h] = {"nonce": 7, "block": 1000, "calls": 1}  # the Safe is at nonce 7: not yet
        self.head = 1020
        self.chain_with_logs(1030, h)
        self.assertIsNone(self.bridge.execution(h))
        self.assertEqual(self.queries, [])  # nothing to look for before the Safe's nonce passes
        self.bridge.submitted[h]["nonce"] = 6
        self.assertIsNone(self.bridge.execution(h))  # passed, but the execution isn't in these blocks
        self.assertEqual(self.queries, [(936, 1020)])
        self.assertEqual(self.bridge.submitted[h]["scanned"], 1020 - 4 + 1)  # the last 4 blocks are scanned again
        self.assertEqual(self.bridge.calls_status(h)["status"], 100)  # not "replaced" yet: maybe a lagging node
        self.head = 1040
        self.assertEqual(self.bridge.execution(h), ("0x" + "ee" * 32, True))
        self.assertEqual(self.queries[-1], (1017, 1040))

    def test_replaced_once_the_logs_are_settled(self):
        h = "0x" + "66" * 32
        self.bridge.submitted[h] = {"nonce": 6, "block": 1000, "calls": 1}
        self.head = 1020
        self.chain_with_logs(10**9, h)  # never executed: another transaction took nonce 6
        self.assertEqual(self.bridge.calls_status(h)["status"], 100)
        self.head = 1030
        self.assertEqual(self.bridge.calls_status(h)["status"], 400)

    def test_unknown_hash_lookups_pass_through(self):
        self.assertIsNone(self.handle("eth_getTransactionReceipt", ["0x" + "22" * 32]))
        self.assertEqual(self.ctx.rpc.calls[-1][0], "eth_getTransactionReceipt")


if __name__ == "__main__":
    unittest.main()
