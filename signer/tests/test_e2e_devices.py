"""Device keys end to end (owner v2), on two local anvils (chains 31337 and 31338), driven through the signer's
commands: a 2-of-3 Safe v1.4.1 on chain 31337 whose owners are three members' v2 owners, a stand-in Transaction
Service, and member 1's device home (device 1) next to member 1's own home (the member key, device 0).

  pairing      `device new` on the new device shows its key and check code; the member key's home refuses a wrong
               check code, then certifies the key on both chains (`device certify`, creating the owner on 31338)
  signing      the device home enrols its own key tree and proposes a transfer; member 2 confirms from the member
               key's home and member 3 executes. The Safe counts member 1 once: the member key's home doesn't sign
               what device 1 has signed. The device signs a message file.
  revoking     `device revoke` with an RPC for 31337 only reports 31337 revoked and 31338 not (the device still
               active there); the device's pending confirmation and its message signature stop counting; its commands
               refuse, naming the revocation. Revoking again with both RPCs reports both chains.
  generations  the member key certifies the same key again (generation 2): the old tree is void, `enroll` certifies
               a fresh one, and the device signs again. A new device home replaces device 1 (generation 3): the old
               home says it was replaced.
  limits       a device home has no phrase (`backup`, `passphrase --forgot`), doesn't move, and can't certify devices.
Needs Foundry's anvil and Safe v1.4.1's release build (contracts/setup.sh).
"""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNER = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(SIGNER, "tools"))

import devchain  # noqa: E402
from winterlock_signer import abi, cli, messages, owner  # noqa: E402
from winterlock_signer.abi import b2h, h2b  # noqa: E402
from winterlock_signer.eip712 import personal_hash  # noqa: E402
from winterlock_signer.ethtx import send  # noqa: E402
from winterlock_signer.member import Member, check_code  # noqa: E402
from winterlock_signer.safe import parse_signature  # noqa: E402
from winterlock_signer.service import Service  # noqa: E402

RECIPIENT = "0x000000000000000000000000000000000000bEEF"
HAVE_TOOLS = os.path.exists(os.path.join(devchain.SAFE_141, "SafeL2.sol", "SafeL2.json")) and bool(
    shutil.which("anvil") or os.path.exists(os.path.join(devchain.FOUNDRY_BIN, "anvil")))
A, B = 31337, 31338


def deploy_shared(rpc, acct):
    """The four shared contracts from the signer's pinned code, through the deterministic deployment proxy"""
    for salt, init in ((owner.VERIFIER_SALT, owner.VERIFIER_CREATION),
                       (owner.WOTS_VERIFIER_SALT, owner.WOTS_VERIFIER_CREATION),
                       (owner.IMPLEMENTATION_SALT, owner.implementation_init_code()),
                       (owner.FACTORY_SALT, owner.factory_init_code())):
        send(rpc, acct, owner.PROXY, salt + init, gas=30_000_000, log=lambda *a: None)


@unittest.skipUnless(HAVE_TOOLS, "needs anvil and Safe v1.4.1's build (contracts/setup.sh)")
class Devices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = mock.patch.dict(os.environ, {"WINTERLOCK_GAS_KEY": devchain.ANVIL_KEY})  # anvil's public test key
        cls.env.start()
        for k in [k for k in os.environ if k.startswith("WINTERLOCK_RPC")]:
            del os.environ[k]
        cls.tmp = tempfile.TemporaryDirectory()
        cls.a, cls.b = devchain.Anvil(), devchain.Anvil(chain_id=B)
        cls.rpc = cls.a.rpc
        cls.release = devchain.safe_release(cls.rpc, cls.a.account)
        deploy_shared(cls.b.rpc, cls.b.account)  # chain 31338 has the contracts, but no owner of member 1 yet
        cls.homes = {n: os.path.join(cls.tmp.name, n) for n in ("m1", "m2", "m3", "d1", "d1b")}
        cls.owners = {}
        for n in ("m1", "m2", "m3"):
            cls.run_cli(["--home", cls.homes[n], "init", "--insecure-plaintext-seed"])
            m = Member(cls.homes[n], lock=False)
            cls.owners[n] = m.owner
            m.close()
        cls.safe, _ = devchain.create_safe(cls.rpc, cls.a.account, cls.release, list(cls.owners.values()), 2)
        send(cls.rpc, cls.a.account, cls.safe, b"", value=10**18, log=lambda *a: None)
        port = devchain.free_port()
        cls.service_proc = subprocess.Popen([sys.executable, "-m", "tests.mock_service", "--rpc", cls.a.url,
                                             "--port", str(port)], cwd=SIGNER)
        cls.service = f"http://127.0.0.1:{port}/api"
        time.sleep(0.5)
        for i, n in enumerate(("m1", "m2", "m3")):
            code, text = cls.run_cli(["--home", cls.homes[n], "--yes", "enroll", "--chain", str(A), "--rpc", cls.a.url,
                                      "--safe", cls.safe, "--height", "6"] + (["--deploy"] if i == 0 else []))
            assert code == 0, text
        cls.key = cls.code = None

    @classmethod
    def tearDownClass(cls):
        cls.service_proc.terminate()
        cls.service_proc.wait()
        cls.a.close()
        cls.b.close()
        cls.tmp.cleanup()
        cls.env.stop()

    @staticmethod
    def run_cli(argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def cmd(self, home, *argv, expect=0, chain=True, service=True):
        """A command in `home` on chain 31337 (with the service, for the commands that take one)"""
        extra = []
        if chain:
            extra = ["--chain", str(A), "--rpc", self.a.url]
            if service and argv[0] in ("propose", "confirm", "queue", "execute"):
                extra += ["--service", self.service]
        argv = ["--home", self.homes[home], "--yes", *argv[:1], *extra, *argv[1:]]
        code, text = self.run_cli(argv)
        self.assertEqual(code, expect, f"{' '.join(argv[3:6])} exited {code}:\n{text}")
        return text

    def device(self, home, *argv, expect=0):
        """A `device` action, with its own --chain/--rpc pairs"""
        code, text = self.run_cli(["--home", self.homes[home], "--yes", "device", *argv])
        self.assertEqual(code, expect, f"device {' '.join(argv[:3])} exited {code}:\n{text}")
        return text

    def both(self):
        return ["--chain", str(A), "--rpc", self.a.url, "--chain", str(B), "--rpc", self.b.url]

    def nonce(self):
        return abi.dec_uint(self.rpc.eth_call(self.safe, abi.calldata("nonce()")))

    def hash_from(self, text):
        return re.search(r"SafeTx hash (0x[0-9a-f]{64})", text)[1]

    def service_tx(self, h):
        return Service(self.service).transaction(h)

    def confirmation(self, h, who="m1"):
        c = next(c for c in self.service_tx(h)["confirmations"] if c["owner"] == self.owners[who])
        return parse_signature(h2b(c["signature"]))[1]

    def dev(self, chain_rpc=None):
        return owner.read_device(chain_rpc or self.rpc, self.owners["m1"], 1)

    # --- steps, in order ---

    def test_1_pairing(self):
        own = self.owners["m1"]
        text = self.device("d1", "new", "--owner", own, "--device", "1", "--insecure-plaintext-seed")
        key = h2b(re.search(r"device key +(0x[0-9a-f]{64})", text)[1])
        code = re.search(r"check code +([a-z ]+)\n", text)[1].strip()
        self.assertEqual(code, check_code(own, 1, key))
        self.assertEqual(len(code.split()), 5)
        self.assertNotEqual(code, check_code(own, 2, key))  # the device number is in it, and the owner
        self.assertNotEqual(code, check_code(self.owners["m2"], 1, key))
        self.assertIn(f"device certify --device 1 --key {b2h(key)}", text)
        self.assertIn("no recovery phrase", text.replace("holds no", "no"))
        type(self).key, type(self).code = key, code
        self.assertIn(code, self.cmd("d1", "address", chain=False))
        self.assertIn("already has a signer", self.device("d1", "new", "--owner", own, "--device", "1",
                                                          "--insecure-plaintext-seed", expect=2))
        self.assertIn("--device is 1, 2 or 3", self.device("d1b", "new", "--owner", own, "--device", "0", expect=1))
        # not certified yet: the device home says what to run where
        text = self.cmd("d1", "enroll", "--safe", self.safe, expect=2)
        self.assertIn("this device isn't certified on local anvil (chain 31337) yet", text)
        self.assertIn(f"device certify --device 1 --key {b2h(key)}", text)
        # a wrong check code: refused before anything is signed
        text = self.device("m1", "certify", "--device", "1", "--key", b2h(key), "--check-code",
                           "abandon ability able about above", *self.both(), expect=2)
        self.assertIn("isn't this key's", text)
        m = Member(self.homes["m1"], lock=False)
        self.assertFalse([r for r in m.log.records if r["t"] == "device-cert"])
        m.close()
        self.assertEqual(self.dev(), (bytes(32), 0, False))
        # the right one, on both chains: on 31338 the owner is created first
        text = self.device("m1", "certify", "--device", "1", "--key", b2h(key), "--check-code", code.upper(),
                           *self.both())
        self.assertIn("the check code you gave matches", text)
        self.assertIn(f"your owner {own} doesn't exist on chain {B} yet: the factory creates it first", text)
        self.assertIn("local anvil (chain 31337): CERTIFIED as device 1, generation 1", text)
        self.assertIn(f"chain {B}: CERTIFIED as device 1, generation 1", text)
        self.assertEqual(self.dev(), (key, 1, True))
        self.assertEqual(self.dev(self.b.rpc), (key, 1, True))
        text = self.device("m1", "list", *self.both())
        self.assertEqual(text.count("1  ACTIVE at generation 1"), 2)
        self.assertIn("0  the member key", text)
        # certifying again changes nothing
        self.assertIn("already certified", self.device("m1", "certify", "--device", "1", "--key", b2h(key),
                                                       "--check-code", code, "--chain", str(A), "--rpc", self.a.url))

    def test_2_device_signs_a_transfer(self):
        text = self.cmd("d1", "enroll", "--safe", self.safe, "--height", "6")
        self.assertIn("Key tree enrolled for device 1 (generation 1): none", text)
        self.assertIn("your device key (device 1) signed", text)
        d = Member(self.homes["d1"], lock=False)
        root, seed, _, start, gen = owner.read_tree(self.rpc, self.owners["m1"], self.safe, 1)
        self.assertEqual((b2h(root), gen), (d.active_tree(A, self.safe)["root"], 1))
        self.assertEqual(seed, owner.tree_seed(A, self.owners["m1"], self.safe, 1, 1, start))
        d.close()
        # member 1's device 1 and member 2's member key sign a 2-of-3 transfer; member 3 executes it
        before = self.rpc.balance(RECIPIENT)
        text = self.cmd("d1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.1")
        self.assertIn("device 1's key tree", text)
        h = self.hash_from(text)
        self.cmd("m2", "confirm", h)
        self.assertEqual(self.confirmation(h)[:2], b"\x00\x01")  # slot 0, device 1
        self.assertEqual(self.confirmation(h, "m2")[:2], b"\x00\x00")  # slot 0, device 0
        self.assertIn("Executed nonce 0", self.cmd("m3", "execute", h))
        self.assertEqual(self.rpc.balance(RECIPIENT) - before, 10**17)
        text = self.cmd("d1", "status", "--safe", self.safe)
        self.assertIn("This device: ACTIVE at generation 1, with this home's key", text)
        self.assertIn("ENROLLED", text)
        self.assertIn("1  ACTIVE at generation 1, key", text)

    def test_3_one_owner_counts_once(self):
        text = self.cmd("m2", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01")
        h = self.hash_from(text)
        type(self).pending = h
        self.cmd("d1", "confirm", h)
        text = self.cmd("m1", "confirm", h)  # member 1's own home: device 1 has signed for this owner already
        self.assertIn("Your owner has already confirmed it: device 1's signature counts", text)
        self.assertEqual(self.confirmation(h)[1], 1)
        self.assertIn("you: signed (device 1)", self.cmd("m1", "queue", "--safe", self.safe))
        # a message file, signed by the device key
        text_msg = "Welcome to app.example. Sign to accept the terms (version 3)."
        params = [b2h(text_msg.encode()), self.safe]
        d = messages.decide("personal_sign", params, self.safe, A, "")
        doc = messages.new_doc(A, self.safe, "personal_sign", params, d, {"name": "App", "url": "https://app.example"})
        path = os.path.join(self.tmp.name, "message.json")
        with open(path, "w") as f:
            json.dump(doc, f)
        self.assertIn("Signed (1 of 2)", self.cmd("d1", "message", "--file", path))
        with open(path) as f:
            sig = json.load(f)["signatures"][0]
        data = parse_signature(h2b(sig["signature"]))[1]
        self.assertEqual(data[:2], b"\x02\x01")  # message kind, device 1
        smh = messages.safe_message_hash(A, self.safe, personal_hash(text_msg.encode()))
        self.assertTrue(owner.is_valid_signature(self.rpc, self.owners["m1"], smh, data))
        type(self).message = (path, smh, data)
        self.assertIn("Your owner has signed this message already", self.cmd("m1", "message", "--file", path))

    def test_4_revoke_per_chain(self):
        h, (path, smh, mdata) = self.pending, self.message
        pending_sig = self.confirmation(h)
        self.assertTrue(owner.is_valid_signature(self.rpc, self.owners["m1"], h2b(h), pending_sig))
        # the key log knows both chains; only 31337 has an RPC here
        text = self.device("m1", "revoke", "--device", "1", "--chain", str(A), "--rpc", self.a.url, expect=1)
        self.assertIn("local anvil (chain 31337): REVOKED (generation 1)", text)
        self.assertIn(f"chain {B}: NOT REVOKED: no RPC for this chain, so device 1 may still sign here", text)
        self.assertIn(f"device 1 may still sign on chain {B}", text)
        self.assertEqual(self.dev(), (self.key, 1, False))
        self.assertEqual(self.dev(self.b.rpc), (self.key, 1, True))  # revocation is per chain
        # what the device signed stops counting: its pending confirmation and its message signature
        self.assertFalse(owner.is_valid_signature(self.rpc, self.owners["m1"], h2b(h), pending_sig))
        self.assertFalse(owner.is_valid_signature(self.rpc, self.owners["m1"], smh, mdata))
        self.assertIn("not enough valid signatures", self.cmd("m3", "execute", h, expect=1))
        # and its commands refuse, saying why
        why = "this device (device 1) was REVOKED on local anvil (chain 31337) at generation 1"
        for argv in (("propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01"), ("confirm", h),
                     ("enroll", "--safe", self.safe), ("message", "--file", path)):
            self.assertIn(why, self.cmd("d1", *argv, expect=2))
        self.assertIn(f"This device: {why}", self.cmd("d1", "status"))
        self.assertIn("VOID (this device was revoked or replaced on this chain)", self.cmd("d1", "status"))
        # both RPCs: both chains reported, 31338 revoked now
        text = self.device("m1", "revoke", "--device", "1", *self.both())
        self.assertIn("local anvil (chain 31337): already revoked (generation 1)", text)
        self.assertIn(f"chain {B}: REVOKED (generation 1)", text)
        self.assertEqual(self.dev(self.b.rpc), (self.key, 1, False))
        self.assertIn(f"{self.owners['m1']} (no longer counts)", self.cmd("m3", "queue", "--safe", self.safe))
        self.assertIn("your owner's confirmation no longer counts", self.cmd("m1", "queue", "--safe", self.safe))
        # member 1 approves from the member key's home instead. The service keeps device 1's confirmation (as the
        # hosted one does: the first per owner), so the signature goes into a proposal file
        path = os.path.join(self.tmp.name, "pending-m1.json")
        text = self.cmd("m1", "confirm", h, "--out", path)
        self.assertIn("Note: the service holds your owner's earlier confirmation (device 1's), which no longer counts",
                      text)
        self.assertIn("HTTP 201", text)
        self.assertIn("still holds your owner's earlier confirmation (device 1's), which no longer counts, and kept it",
                      text)
        self.assertIn(f"Your signature is in {path}, with the other members' confirmations that count (2 in all)", text)
        self.assertIn("your signature is in the proposal file, not in the service", text)
        self.assertEqual(self.confirmation(h)[:2], b"\x00\x01")  # still device 1's at the service
        with open(path) as f:
            doc = json.load(f)
        self.assertEqual(doc["safeTxHash"], h)
        self.assertEqual({s["owner"] for s in doc["signatures"]}, {self.owners["m1"], self.owners["m2"]})
        mine = next(s for s in doc["signatures"] if s["owner"] == self.owners["m1"])
        self.assertTrue(owner.is_valid_signature(self.rpc, self.owners["m1"], h2b(h),
                                                 parse_signature(h2b(mine["signature"]))[1]))
        # proposing the same transaction again (the same key, so the same signature) meets the same service
        nonce = int(self.service_tx(h)["nonce"])
        path2 = os.path.join(self.tmp.name, "pending-m1-proposed.json")
        text = self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01", "--nonce",
                        str(nonce), "--out", path2)
        self.assertIn("you already signed this exact transaction with it", text)
        self.assertIn("your signature is in the proposal file, not in the service", text)
        # the service's confirmations alone don't execute; the file does, with the service's added
        text = self.cmd("m3", "execute", h, expect=1)
        self.assertIn("execute with `--file` and that file", text)
        text = self.cmd("m3", "execute", h, "--file", path)
        self.assertIn(f"2 signatures in {path}, 2 confirmations at the service", text)
        self.assertNotIn("refused by its owner contract", text)  # member 1 counted once, from the file
        self.assertIn("Signatures: 2 valid of 2 needed", text)
        self.assertIn(f"Executed nonce {nonce}", text)

    def test_5_certified_again(self):
        text = self.device("m1", "certify", "--device", "1", "--key", b2h(self.key), "--check-code", self.code,
                           "--chain", str(A), "--rpc", self.a.url)
        self.assertIn("this key was revoked on this chain (generation 1)", text)
        self.assertIn("CERTIFIED as device 1, generation 2", text)
        self.assertEqual(self.dev(), (self.key, 2, True))
        self.assertIn("VOID (from generation 1; the device is at 2 now", self.cmd("d1", "status", "--safe", self.safe))
        text = self.cmd("d1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01", expect=2)
        self.assertIn("is from generation 1, before the device was certified again (now generation 2)", text)
        text = self.cmd("d1", "enroll", "--safe", self.safe, "--height", "6")
        self.assertIn("from generation 1: void", text)
        self.assertEqual(owner.read_tree(self.rpc, self.owners["m1"], self.safe, 1)[4], 2)
        h = self.hash_from(self.cmd("d1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01"))
        self.cmd("m2", "confirm", h)
        n = self.nonce()
        self.cmd("m3", "execute", h)
        self.assertEqual(self.nonce(), n + 1)

    def test_6_replaced(self):
        own = self.owners["m1"]
        text = self.device("d1b", "new", "--owner", own, "--device", "1", "--insecure-plaintext-seed")
        key = h2b(re.search(r"device key +(0x[0-9a-f]{64})", text)[1])
        # not paired yet, while device 1 holds the other home's key: not "replaced", just not certified
        self.assertIn("this device isn't certified on local anvil (chain 31337) with this home's key: device 1 there "
                      "holds another key (generation 2, active)", self.cmd("d1b", "status"))
        text = self.device("m1", "certify", "--device", "1", "--key", b2h(key), "--check-code",
                           check_code(own, 1, key), "--chain", str(A), "--rpc", self.a.url)
        self.assertIn("device 1 is active with another key", text)
        self.assertIn("CERTIFIED as device 1, generation 3", text)
        why = "device 1 on local anvil (chain 31337) holds another key now (generation 3, active): this device was " \
              "REPLACED"
        self.assertIn(why, self.cmd("d1", "status"))
        self.assertIn(why, self.cmd("d1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01",
                                    expect=2))
        self.assertIn("This device: ACTIVE at generation 3", self.cmd("d1b", "status"))

    def test_7_what_a_device_home_doesnt_do(self):
        for argv in (("backup",), ("passphrase", "--forgot"), ("move", "export", "--code", "AAAA-BBBB-CCCC-DDDD",
                                                                 "--out", os.path.join(self.tmp.name, "x.json"))):
            text = self.cmd("d1b", *argv, expect=2, chain=False)
            self.assertTrue("no recovery phrase" in text or "doesn't move" in text, text)
        self.assertIn("only the member key does that", self.device(
            "d1b", "certify", "--device", "2", "--key", b2h(self.key), "--chain", str(A), "--rpc", self.a.url,
            expect=2))
        self.assertIn("device 0, the member key, can't be revoked",
                      self.device("m1", "revoke", "--device", "0", "--chain", str(A), "--rpc", self.a.url, expect=1))
        text = self.cmd("m1", "status")
        self.assertIn("member key: ", text)
        self.assertIn("device certificates and revocations", text)


if __name__ == "__main__":
    unittest.main()
