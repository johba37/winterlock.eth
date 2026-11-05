"""End to end over WalletConnect on a local anvil: a dapp connects to member 1's signer (`connect`, run as its own
process) through a stand-in relay (tests/mock_relay.py), as a scripted dapp (tests/mock_dapp.py), and sees the team's
2-of-3 Safe of WinterlockOwner proxies as its account. Members 2 and 3 use the signer's other commands.

  a transaction   eth_sendTransaction -> a SafeTx proposed to the stand-in Transaction Service, signed by member 1;
                  the dapp gets its SafeTx hash; member 2 confirms, member 3 executes; the dapp's receipt lookup of the
                  SafeTx hash returns the execution. A two-call batch (wallet_sendCalls) through MultiSendCallOnly.
  sign-in         personal_sign of a sign-in with Ethereum message: member 1 signs with its stateless key and writes
                  a message file, member 2 signs the file (`message`), and the dapp gets the combined 2-of-3 signature
                  (11,668 bytes), which the Safe's isValidSignature accepts on-chain.
  permit          eth_signTypedData_v4 of a Permit2 PermitSingle: an approval through SignMessageLib is proposed,
                  confirmed and executed; the dapp gets 0x, and the Safe's isValidSignature accepts the empty signature.
  refusals        a bare hash, eth_sign, a validator's enable data, the Safe's own typed data, a self-call that adds an
                  owner, a sign-in for another site, a request for another chain.
Needs Foundry's anvil and Safe v1.4.1's release build (contracts/setup.sh).
"""
import contextlib
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNER = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(SIGNER, "tools"))

import devchain  # noqa: E402
from tests.mock_dapp import MockDapp, DappError  # noqa: E402
from tests.mock_relay import Relay as MockRelay  # noqa: E402
from winterlock_signer import abi, cli, collect, messages, owner  # noqa: E402
from winterlock_signer.abi import b2h, h2b  # noqa: E402
from winterlock_signer.eip712 import TypedData, personal_hash  # noqa: E402
from winterlock_signer.ethtx import send  # noqa: E402
from winterlock_signer.member import Member  # noqa: E402
from winterlock_signer.service import Service  # noqa: E402

RECIPIENT = "0x000000000000000000000000000000000000bEEF"
OTHER = "0x000000000000000000000000000000000000cafE"
HAVE_TOOLS = os.path.exists(os.path.join(devchain.SAFE_141, "SignMessageLib.sol", "SignMessageLib.json")) and bool(
    shutil.which("anvil") or os.path.exists(os.path.join(devchain.FOUNDRY_BIN, "anvil")))
CHAIN = 31337


def siwe(safe, domain="app.example", chain=CHAIN):
    return (f"{domain} wants you to sign in with your Ethereum account:\n{safe}\n\nSign in to the app.\n\n"
            f"URI: https://{domain}\nVersion: 1\nChain ID: {chain}\nNonce: 32891756\n"
            "Issued At: 2026-11-05T12:00:00Z")


def permit2_single(safe_unused=None, nonce=0):
    return {"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"},
                                       {"name": "verifyingContract", "type": "address"}],
                      "PermitSingle": [{"name": "details", "type": "PermitDetails"},
                                       {"name": "spender", "type": "address"},
                                       {"name": "sigDeadline", "type": "uint256"}],
                      "PermitDetails": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"},
                                        {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}]},
            "primaryType": "PermitSingle",
            "domain": {"name": "Permit2", "chainId": CHAIN, "verifyingContract": messages.PERMIT2},
            "message": {"details": {"token": "0x1111111111111111111111111111111111111111", "amount": "1000000",
                                    "expiration": 4102444800, "nonce": nonce},
                        "spender": "0x2222222222222222222222222222222222222222", "sigDeadline": "4102444800"}}


@unittest.skipUnless(HAVE_TOOLS, "needs anvil and Safe v1.4.1's build with SignMessageLib (contracts/setup.sh)")
class WalletConnectEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.chain = devchain.Anvil()
        cls.rpc = cls.chain.rpc
        cls.deployer = cls.chain.account
        os.environ["WINTERLOCK_GAS_KEY"] = devchain.ANVIL_KEY  # anvil's public test key
        cls.release = devchain.safe_release(cls.rpc, cls.deployer)
        cls.libs = devchain.safe_libraries(cls.rpc)
        cls.homes = {n: os.path.join(cls.tmp.name, n) for n in ("m1", "m2", "m3")}
        cls.owners = {}
        for n, h in cls.homes.items():
            cls.run_cli(["--home", h, "init", "--insecure-plaintext-seed"])
            m = Member(h, lock=False)
            cls.owners[n] = m.owner
            m.close()
        cls.safe, _ = devchain.create_safe(cls.rpc, cls.deployer, cls.release, list(cls.owners.values()), 2)
        send(cls.rpc, cls.deployer, cls.safe, b"", value=10**18, log=lambda *a: None)
        port = devchain.free_port()
        cls.service_proc = subprocess.Popen([sys.executable, "-m", "tests.mock_service", "--rpc", cls.chain.url,
                                             "--port", str(port)], cwd=SIGNER)
        cls.service = f"http://127.0.0.1:{port}/api"
        for i, n in enumerate(("m1", "m2", "m3")):
            code, text = cls.run_cli(["--home", cls.homes[n], "--yes", "enroll", "--chain", str(CHAIN), "--rpc",
                                      cls.chain.url, "--safe", cls.safe, "--height", "6"] + (["--deploy"] if i == 0
                                                                                             else []))
            assert code == 0, text
        cls.relay = MockRelay().start()
        cls.collector, cls.collect_url = collect.serve(cls.chain.url)
        cls.exchange = os.path.join(cls.tmp.name, "exchange")
        os.makedirs(cls.exchange)
        cls.dapp = MockDapp(cls.relay.url)
        uri = cls.dapp.uri()
        cls.log_path = os.path.join(cls.tmp.name, "connect.log")
        cls.log = open(cls.log_path, "w")
        env = dict(os.environ, PYTHONPATH=SIGNER)
        cls.connect = subprocess.Popen(
            [sys.executable, "-m", "winterlock_signer", "--home", cls.homes["m1"], "--yes", "connect", "--chain",
             str(CHAIN), "--rpc", cls.chain.url, "--service", cls.service, "--safe", cls.safe, "--relay", cls.relay.url,
             "--exchange-dir", cls.exchange, "--collect", cls.collect_url, "--poll", "0.3", uri], cwd=SIGNER,
            stdout=cls.log, stderr=subprocess.STDOUT,
            env=env)
        cls.namespaces = cls.dapp.propose(optional={"eip155": {
            "chains": [f"eip155:{CHAIN}"], "events": ["chainChanged", "accountsChanged"],
            "methods": ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "wallet_sendCalls",
                        "wallet_getCallsStatus", "eth_getTransactionReceipt"]}}, timeout=60)

    @classmethod
    def tearDownClass(cls):
        cls.connect.terminate()
        cls.connect.wait()
        cls.log.close()
        if os.environ.get("WINTERLOCK_CONNECT_LOG"):  # keep the connected signer's output, to read it
            shutil.copy(cls.log_path, os.environ["WINTERLOCK_CONNECT_LOG"])
        cls.dapp.close()
        cls.relay.close()
        cls.collector.shutdown()
        cls.collector.server_close()
        cls.service_proc.terminate()
        cls.service_proc.wait()
        cls.chain.close()
        cls.tmp.cleanup()
        os.environ.pop("WINTERLOCK_GAS_KEY", None)

    @staticmethod
    def run_cli(argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def cmd(self, member, *argv, expect=0):
        argv = ["--home", self.homes[member], "--yes", argv[0], "--chain", str(CHAIN), "--rpc", self.chain.url,
                *([] if argv[0] in ("message", "status") else ["--service", self.service]), *argv[1:]]
        code, text = self.run_cli(argv)
        self.assertEqual(code, expect, f"{' '.join(argv[3:5])} exited {code}:\n{text}")
        return text

    def request(self, method, params, chain=CHAIN, timeout=120):
        return self.dapp.request(method, params, f"eip155:{chain}", timeout=timeout)

    def in_background(self, method, params):
        box = {}

        def run():
            try:
                box["result"] = self.request(method, params)
            except DappError as e:
                box["error"] = e
        t = threading.Thread(target=run)
        t.start()
        return t, box

    def connect_log(self):
        with open(self.log_path) as f:
            return f.read()

    def nonce(self):
        return abi.dec_uint(self.rpc.eth_call(self.safe, abi.calldata("nonce()")))

    def wait_for(self, cond, what, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            got = cond()
            if got:
                return got
            time.sleep(0.2)
        self.fail(f"timed out waiting for {what}\n--- connect log ---\n{self.connect_log()[-3000:]}")

    def is_valid(self, app_hash, sig):
        return messages.safe_accepts(self.rpc, self.safe, app_hash, sig)

    # --- steps, in order ---

    def test_1_session(self):
        ns = self.namespaces["eip155"]
        self.assertEqual(ns["accounts"], [f"eip155:{CHAIN}:{self.safe}"])
        for m in ("eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "wallet_sendCalls"):
            self.assertIn(m, ns["methods"])
        self.assertEqual(self.request("eth_accounts", []), [self.safe])
        self.assertEqual(self.request("eth_chainId", []), hex(CHAIN))
        self.assertTrue(self.dapp.ping())
        self.assertIn("Connected", self.connect_log())

    def test_2_transaction(self):
        before = self.rpc.balance(RECIPIENT)
        h = self.request("eth_sendTransaction", [{"from": self.safe, "to": RECIPIENT, "value": hex(25 * 10**16)}])
        rec = Service(self.service).transaction(h)
        self.assertEqual(rec["nonce"], 0)
        self.assertEqual([c["owner"] for c in rec["confirmations"]], [self.owners["m1"]])
        log = self.connect_log()
        self.assertIn("Send 0.25 ETH", log)
        self.assertIn(f"Proposed {h}", log)
        self.assertIsNone(self.request("eth_getTransactionReceipt", [h]))  # not executed yet
        self.cmd("m2", "confirm", "--safe-tx-hash", h)
        self.assertIn("Executed nonce 0", self.cmd("m3", "execute", "--safe-tx-hash", h))
        self.assertEqual(self.rpc.balance(RECIPIENT) - before, 25 * 10**16)
        receipt = self.request("eth_getTransactionReceipt", [h])
        self.assertEqual(receipt["status"], "0x1")
        self.assertEqual(receipt["to"].lower(), self.safe.lower())

    def test_3_batch(self):
        before = (self.rpc.balance(RECIPIENT), self.rpc.balance(OTHER))
        res = self.request("wallet_sendCalls", [{"version": "2.0.0", "chainId": hex(CHAIN), "from": self.safe,
                                                 "atomicRequired": True,
                                                 "calls": [{"to": RECIPIENT, "value": hex(1000)},
                                                           {"to": OTHER, "value": hex(2000), "data": "0x"}]}])
        h = res["id"]
        self.assertEqual(self.request("wallet_getCallsStatus", [h])["status"], 100)
        self.assertIn("MultiSend batch through", self.connect_log())
        self.cmd("m2", "confirm", "--safe-tx-hash", h)
        self.cmd("m3", "execute", "--safe-tx-hash", h)
        status = self.request("wallet_getCallsStatus", [h])
        self.assertEqual(status["status"], 200)
        self.assertEqual(status["receipts"][0]["status"], "0x1")
        self.assertEqual((self.rpc.balance(RECIPIENT) - before[0], self.rpc.balance(OTHER) - before[1]), (1000, 2000))

    def test_4_sign_in(self):
        text = siwe(self.safe)
        app_hash = personal_hash(text.encode())
        t, box = self.in_background("personal_sign", [b2h(text.encode()), self.safe])
        files = self.wait_for(lambda: glob.glob(os.path.join(self.exchange, "safe-message-*.json")),
                              "member 1's message file")
        # member 2 gets a copy, signs it, and sends it back
        copy = os.path.join(self.tmp.name, "m2-message.json")
        shutil.copy(files[0], copy)
        out = self.cmd("m2", "message", "--file", copy)
        self.assertIn("sign-in with Ethereum to app.example", out)
        self.assertIn("Signed (2 of 2)", out)
        shutil.copy(copy, os.path.join(self.exchange, "returned-by-m2.json"))
        t.join(120)
        self.assertNotIn("error", box, str(box.get("error")))
        sig = h2b(box["result"])
        self.assertEqual(len(sig), 2 * (65 + 32 + 1 + 20 + 32 + owner.STATELESS_SIG_LEN))  # 11,668 bytes
        self.assertTrue(self.is_valid(app_hash, sig))
        self.assertFalse(self.is_valid(personal_hash(b"another message"), sig))
        signers = sorted(abi.checksum(sig[i * 65 + 12: i * 65 + 32]) for i in range(2))
        self.assertEqual(signers, sorted([self.owners["m1"], self.owners["m2"]]))
        # the same request again is answered from the collected signatures, without signing again
        self.assertEqual(self.request("personal_sign", [b2h(text.encode()), self.safe]), box["result"])
        self.assertIn("stateless signatures", self.cmd("m2", "status").replace("\n", " "))
        m2 = Member(self.homes["m2"], lock=False)
        self.assertEqual(sum(1 for r in m2.log.records if r["t"] == "msg"), 1)
        m2.close()

    def test_4b_collection_endpoint(self):
        """A text message, with member 3's signature through the collection endpoint instead of a file"""
        text = "Welcome to app.example. Sign to accept the terms of service (version 3)."
        app_hash = personal_hash(text.encode())
        smh = b2h(messages.safe_message_hash(CHAIN, self.safe, app_hash))
        t, box = self.in_background("personal_sign", [b2h(text.encode()), self.safe])

        def posted():
            try:
                return collect.get(self.collect_url, smh)
            except collect.CollectError:
                return None
        self.assertEqual([s["owner"] for s in self.wait_for(posted, "member 1's post")["signatures"]],
                         [self.owners["m1"]])
        out = self.cmd("m3", "message", "--collect", self.collect_url, "--hash", smh)
        self.assertIn("text message", out)
        self.assertIn("Signed and posted: the endpoint holds 2 of 2", out)
        t.join(120)
        self.assertNotIn("error", box, str(box.get("error")))
        self.assertTrue(self.is_valid(app_hash, h2b(box["result"])))
        self.assertIn(f"--collect {self.collect_url} --hash {smh}", self.connect_log())
        # the endpoint stores only what checks out: a signature for another message, or a forged one, is dropped
        doc = collect.get(self.collect_url, smh)
        forged = dict(doc["signatures"][1])
        forged["signature"] = forged["signature"][:-4] + ("00" if forged["signature"][-2:] != "00" else "11") + \
            forged["signature"][-2:]
        stored = collect.post_signature(self.collect_url, smh, forged["owner"], forged["signature"])
        self.assertEqual(stored["signatures"], doc["signatures"])
        with self.assertRaises(collect.CollectError):  # an on-chain message is not collected
            bad = messages.new_doc(CHAIN, self.safe, "eth_signTypedData_v4", [self.safe, permit2_single()],
                                   messages.decide("eth_signTypedData_v4", [self.safe, permit2_single()], self.safe,
                                                   CHAIN))
            collect.put(self.collect_url, bad)

    def test_5_permit_onchain(self):
        typed = permit2_single()
        app_hash = TypedData(typed).hash()
        self.assertFalse(self.is_valid(app_hash, b""))
        nonce = self.nonce()
        t, box = self.in_background("eth_signTypedData_v4", [self.safe, json.dumps(typed)])
        pending = self.wait_for(lambda: Service(self.service).pending(self.safe, nonce), "the approval's proposal")
        h = pending[0]["safeTxHash"]
        self.assertEqual(pending[0]["operation"], 1)
        self.assertEqual(pending[0]["to"], self.libs["SignMessageLib"])
        self.assertEqual(h2b(pending[0]["data"]), messages.sign_message_calldata(app_hash))
        self.cmd("m2", "confirm", "--safe-tx-hash", h)
        self.cmd("m3", "execute", "--safe-tx-hash", h)
        t.join(60)
        self.assertNotIn("error", box, str(box.get("error")))
        self.assertEqual(box["result"], "0x")
        self.assertTrue(self.is_valid(app_hash, b""))
        log = self.connect_log()
        self.assertIn("Permit2 PermitSingle", log)
        self.assertIn("viem refuse 0x", log)
        # asked again: answered at once from the Safe's approval
        self.assertEqual(self.request("eth_signTypedData_v4", [self.safe, json.dumps(typed)]), "0x")

    def test_6_refusals(self):
        def refused(method, params, needle, chain=CHAIN, code=4001):
            with self.assertRaises(DappError) as e:
                self.request(method, params, chain=chain)
            self.assertEqual(e.exception.code, code, e.exception.message)
            self.assertIn(needle, e.exception.message)

        refused("personal_sign", ["0x" + "ab" * 32, self.safe], "bare 32-byte hash")
        refused("eth_sign", [self.safe, "0x" + "ab" * 32], "eth_sign")
        enable = {"types": {"Enable": [{"name": "validationId", "type": "bytes21"}, {"name": "nonce", "type": "uint32"}]},
                  "primaryType": "Enable", "domain": {"name": "Kernel", "version": "0.3.3", "chainId": CHAIN,
                                                      "verifyingContract": OTHER},
                  "message": {"validationId": "0x" + "01" * 21, "nonce": 1}}
        refused("eth_signTypedData_v4", [self.safe, json.dumps(enable)], "enables a validator")
        safetx = {"types": {"SafeTx": [{"name": "to", "type": "address"}, {"name": "nonce", "type": "uint256"}]},
                  "primaryType": "SafeTx", "domain": {"chainId": CHAIN, "verifyingContract": self.safe},
                  "message": {"to": OTHER, "nonce": 9}}
        refused("eth_signTypedData_v4", [self.safe, json.dumps(safetx)], "the Safe itself")
        add_owner = abi.calldata("addOwnerWithThreshold(address,uint256)", ["address", "uint256"], [OTHER, 1])
        refused("eth_sendTransaction", [{"from": self.safe, "to": self.safe, "data": b2h(add_owner)}], "owners")
        refused("personal_sign", [b2h(siwe(self.safe, domain="evil.example").encode()), self.safe],
                "signing you in somewhere else")
        refused("eth_accounts", [], "not eip155:1", chain=1, code=5100)
        refused("eth_signTransaction", [{"to": OTHER}], "raw", code=4200)
        self.assertEqual(self.nonce(), 3)  # nothing was proposed or executed
        self.assertEqual(glob.glob(os.path.join(self.exchange, "safetx-*.json")), [])

    def test_7_disconnect(self):
        self.dapp.disconnect()
        self.connect.wait(30)
        self.assertEqual(self.connect.returncode, 0, self.connect_log()[-2000:])
        log = self.connect_log()
        self.assertIn("The app disconnected", log)
        for secret_hint in ("symKey", os.path.join(self.homes["m1"], "seed")):
            self.assertNotIn(secret_hint, log)


if __name__ == "__main__":
    unittest.main()
