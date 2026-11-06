"""End to end on a local anvil: a 2-of-3 Safe v1.4.1 (SafeL2, from the repository's release build) whose owners are
three members' proxy owners (WinterlockOwnerFactory clones of one WinterlockOwner v2 implementation), each signing with
the member key's home (device 0), driven only through the signer's commands, with a stand-in Transaction Service (tests/mock_service.py) that checks every signature with an
eth_call to the owner, as the hosted one does.

Steps: init, address; enroll, which deploys the two verifiers, the implementation and the factory once (--deploy) and
creates each member's owner with its first tree (deployAndEnroll); a transfer (propose, confirm, execute); a same-nonce replacement
with each member's second key and a refused third version; a restore that certifies a fresh tree with a plain enroll
and voids the old device's approval; a stale key log caught by the service check; the bare implementation refused as an
owner; a move to a new device checked against the chain and the service, and a rolled-back device caught by those
checks.
Needs Foundry's anvil and contracts/ built (./setup.sh, forge build).
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

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNER = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(SIGNER, "tools"))

import devchain  # noqa: E402
from winterlock_signer import abi, cli, device, leansphincs, move, owner, phrase  # noqa: E402
from winterlock_signer.abi import h2b  # noqa: E402
from winterlock_signer.ethtx import send  # noqa: E402
from winterlock_signer.rpc import Reverted  # noqa: E402
from winterlock_signer.member import Member  # noqa: E402
from winterlock_signer.safe import SafeTx, contract_signature, pack, parse_signature  # noqa: E402

RECIPIENT = "0x000000000000000000000000000000000000bEEF"
HAVE_TOOLS = os.path.exists(os.path.join(devchain.SAFE_141, "SafeL2.sol", "SafeL2.json")) and bool(
    shutil.which("anvil") or os.path.exists(os.path.join(devchain.FOUNDRY_BIN, "anvil")))


@unittest.skipUnless(HAVE_TOOLS, "needs anvil and Safe v1.4.1's build (contracts/setup.sh)")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.chain = devchain.Anvil()
        cls.rpc = cls.chain.rpc
        cls.deployer = cls.chain.account
        os.environ["WINTERLOCK_GAS_KEY"] = devchain.ANVIL_KEY  # anvil's public test key
        cls.release = devchain.safe_release(cls.rpc, cls.deployer)
        cls.homes = {n: os.path.join(cls.tmp.name, n) for n in ("m1", "m2", "m3")}
        for h in cls.homes.values():
            cls.run_cli(["--home", h, "init", "--insecure-plaintext-seed"])
        cls.owners = {}
        for n, h in cls.homes.items():
            m = Member(h, lock=False)
            cls.owners[n] = m.owner
            m.close()
        cls.safe, _ = devchain.create_safe(cls.rpc, cls.deployer, cls.release, list(cls.owners.values()), 2)
        send(cls.rpc, cls.deployer, cls.safe, b"", value=10**18, log=lambda *a: None)
        port = devchain.free_port()
        cls.service_proc = subprocess.Popen([sys.executable, "-m", "tests.mock_service", "--rpc", cls.chain.url,
                                             "--port", str(port)], cwd=SIGNER)
        cls.service = f"http://127.0.0.1:{port}/api"
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
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

    def cmd(self, member, *argv, expect=0, home=None):
        argv = ["--home", home or self.homes[member], "--yes", argv[0], "--chain", "31337", "--rpc", self.chain.url,
                *([] if argv[0] in ("enroll", "status", "address") else ["--service", self.service]), *argv[1:]]
        code, text = self.run_cli(argv)
        self.assertEqual(code, expect, f"{' '.join(argv[3:5])} exited {code}:\n{text}")
        return text

    def nonce(self):
        return abi.dec_uint(self.rpc.eth_call(self.safe, abi.calldata("nonce()")))

    def hash_from(self, text):
        for line in text.splitlines():
            if "SafeTx hash" in line:
                return line.split("SafeTx hash ")[1].split()[0]
        self.fail("no SafeTx hash in output")

    def service_tx(self, h):
        from winterlock_signer.service import Service
        return Service(self.service).transaction(h)

    # --- steps, in order ---

    def test_1_identity_and_enrolment(self):
        text = self.cmd("m1", "address")
        self.assertIn(self.owners["m1"], text)
        self.assertIn("your owner not deployed", text)
        self.assertIn("owner factory not deployed", text)
        # a fresh chain: the shared contracts need --deploy, once
        text = self.cmd("m1", "enroll", "--safe", self.safe, expect=1)
        self.assertIn("not on this chain yet: stateless verifier, WOTS verifier, WinterlockOwner implementation, owner "
                      "factory", text)
        text = self.cmd("m1", "enroll", "--safe", self.safe, "--deploy", "--height", "6")
        for name in ("WOTS verifier: deployed", "WinterlockOwner implementation: deployed", "owner factory: deployed",
                     "deployAndEnroll", "Enrolled (owner created)"):
            self.assertIn(name, text)
        for m in ("m2", "m3"):  # the shared contracts exist now: no --deploy needed
            text = self.cmd(m, "enroll", "--safe", self.safe, "--height", "6")
            self.assertIn("Enrolled (owner created)", text)
            self.assertNotIn("implementation: deploying", text)
        impl = owner.implementation_address()
        for name in ("m1", "m2", "m3"):
            mem = Member(self.homes[name], lock=False)
            own = self.owners[name]
            # the owner is the factory's prediction, a 77-byte proxy of the implementation carrying the member's key
            self.assertEqual(abi.dec_addr(self.rpc.eth_call(owner.factory_address(), abi.calldata(
                "predict(bytes32)", ["bytes32"], [mem.key]))), own)
            self.assertEqual(self.rpc.code(own), owner.proxy_runtime(impl, mem.key))
            self.assertEqual(len(self.rpc.code(own)), 77)
            self.assertEqual(abi.dec_word(self.rpc.eth_call(own, abi.calldata("KEY()"))), mem.key)
            self.assertEqual(abi.dec_addr(self.rpc.eth_call(own, abi.calldata("IMPLEMENTATION()"))), impl)
            # the tree the signer derived offline, for the predicted address, is the one the proxy stores
            root, seed, height, start, gen = owner.read_tree(self.rpc, own, self.safe)
            self.assertEqual((abi.b2h(root), height, start, gen), (mem.active_tree(31337, self.safe)["root"], 6, 0, 0))
            self.assertEqual(seed, owner.tree_seed(31337, own, self.safe, 0, 0, 0))
            self.assertEqual(owner.read_device(self.rpc, own, 0), (mem.key, 0, True))  # the member key, device 0
            mem.close()
        own = self.owners["m1"]
        mem = Member(self.homes["m1"], lock=False)
        # the stateless verifier accepts the member's signature, and refuses a changed one
        digest = h2b("0x" + "5a" * 32)
        sig = mem.stateless_sign(digest)
        verify = "verify(bytes32,bytes32,bytes32,bytes)"
        args = [mem.key[16:] + bytes(16), mem.key[:16] + bytes(16), digest, sig]
        types = ["bytes32", "bytes32", "bytes32", "bytes"]
        self.assertEqual(abi.dec_uint(self.rpc.eth_call(owner.verifier_address(), abi.calldata(verify, types, args))), 1)
        bad = bytearray(sig)
        bad[100] ^= 1
        args[3] = bytes(bad)
        self.assertEqual(abi.dec_uint(self.rpc.eth_call(owner.verifier_address(), abi.calldata(verify, types, args))), 0)
        self.assertTrue(leansphincs.verify(mem.key, digest, sig))
        mem.close()
        self.assertIn("Already enrolled", self.cmd("m1", "enroll", "--safe", self.safe))

    def test_2_transfer(self):
        before = self.rpc.balance(RECIPIENT)
        text = self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.25")
        self.assertIn("Send 0.25 ETH", text)
        self.assertIn("one-time key 0: your first of two keys for nonce 0 (slot 0)", text)
        self.assertIn("HTTP 201", text)
        h = self.hash_from(text)
        text = self.cmd("m2", "confirm", h)  # the hash after the command, as `queue` and Safe's app show it
        self.assertIn("Send 0.25 ETH", text)
        self.assertIn("HTTP 201", text)
        # both EIP-1271 entry points of the owner accept the stored confirmation: bytes32 (Safe v1.5.0, the
        # service) and the legacy one with the 66-byte preimage (Safe v1.4.1)
        rec = self.service_tx(h)
        t = SafeTx.from_json(rec)
        o, data, _ = parse_signature(h2b(rec["confirmations"][1]["signature"]))
        self.assertTrue(owner.is_valid_signature(self.rpc, o, h2b(h), data))
        legacy = self.rpc.eth_call(o, abi.calldata("isValidSignature(bytes,bytes)", ["bytes", "bytes"],
                                                   [t.preimage(31337, self.safe), data]))
        self.assertEqual(legacy[:4], owner.LEGACY_MAGIC)
        text = self.cmd("m3", "queue", "--safe", self.safe)
        self.assertIn("signatures 2 of 2", text)
        self.assertIn("you: not signed", text)
        text = self.cmd("m3", "execute", h, "--safe-tx-hash", h)  # both ways at once: fine if they agree
        self.assertIn("Executed nonce 0", text)
        self.assertEqual(self.rpc.balance(RECIPIENT) - before, 25 * 10**16)
        self.assertEqual(self.nonce(), 1)

    def test_3_replacement_and_refused_reuse(self):
        before = self.rpc.balance(RECIPIENT)
        a = self.hash_from(self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.1"))
        self.cmd("m2", "confirm", "--safe-tx-hash", a)
        # the replacement: Safe's on-chain rejection at the same nonce, signed with each member's second key
        text = self.cmd("m1", "propose", "--safe", self.safe, "--cancel", "--nonce", "1")
        self.assertIn("Cancel", text)
        self.assertIn("one-time key 3: your second and last key for nonce 1 (slot 1)", text)
        self.assertIn(f"also at nonce 1: {a} (2 signatures); only one of them can execute", text)
        b = self.hash_from(text)
        self.assertIn("your second and last key for nonce 1 (slot 1)", self.cmd("m2", "confirm", "--safe-tx-hash", b))
        # a third version at nonce 1 is refused: both of each member's keys for it are used
        text = self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.2", "--nonce", "1",
                        expect=2)
        self.assertIn("REFUSED: both keys for nonce 1 are used", text)
        self.cmd("m2", "confirm", "--safe-tx-hash", a)  # the same transaction again: allowed, same signature
        # forcing a used key onto another transaction is refused by the key log itself
        mem = Member(self.homes["m2"])
        rec = mem.active_tree(31337, self.safe)
        from winterlock_signer.keylog import Refused
        with self.assertRaises(Refused):
            mem.sign_safe_tx(31337, self.safe, rec, SafeTx(to=RECIPIENT, value=3, nonce=1), slot=0)
        mem.close()
        text = self.cmd("m3", "queue", "--safe", self.safe)
        self.assertIn("you: not signed; your two keys for this nonce: first unused, second unused", text)
        self.cmd("m3", "execute", "--safe-tx-hash", b)
        self.assertEqual(self.nonce(), 2)
        self.assertTrue(self.service_tx(b)["isExecuted"])
        self.assertFalse(self.service_tx(a)["isExecuted"])
        self.assertEqual(self.rpc.balance(RECIPIENT), before)  # the cancelled transfer never happened
        text = self.cmd("m3", "execute", "--safe-tx-hash", a, expect=1)
        self.assertIn("this transaction has nonce 1", text)

    def test_4_restore_starts_a_fresh_tree(self):
        c = self.hash_from(self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.05"))
        self.cmd("m2", "confirm", "--safe-tx-hash", c)  # the old device approves, then is lost
        backup = os.path.join(self.tmp.name, "m2-phrase")  # the recovery phrase, as written down
        with open(backup, "w") as f:
            f.write(" ".join(phrase.to_phrase(h2b(abi.read_file(os.path.join(self.homes["m2"], "seed")).strip()))))
        new_home = os.path.join(self.tmp.name, "m2-restored")
        code, text = self.run_cli(["--home", new_home, "init", "--restore", backup, "--lost",
                                   "--insecure-plaintext-seed", "--chain", "31337", "--rpc", self.chain.url,
                                   "--service", self.service])
        self.assertEqual(code, 0, text)
        self.assertIn(self.owners["m2"], text)  # same owner address
        # the report: the Safe found through the service, the old device's tree, the approval that stops counting
        self.assertIn(f"Safe {self.safe} on local anvil (chain 31337): 2 of 3, next nonce 2", text)
        self.assertIn("the enrolled key tree is the old device's (nonces 0–31)", text)
        self.assertIn(f"nonce 2 {c}: approved by your old device; stops counting once your fresh key tree is enrolled",
                      text)
        # the restored signer has no log for the enrolled tree, so it won't sign with it
        text = self.cmd("m2", "confirm", "--safe-tx-hash", c, home=new_home, expect=2)
        self.assertIn("isn't in this signer's key log", text)
        old_root = abi.b2h(owner.read_tree(self.rpc, self.owners["m2"], self.safe)[0])
        text = self.cmd("m2", "enroll", "--safe", self.safe, home=new_home)
        self.assertIn("nonces 2–", text)
        root, _, _, start, _ = owner.read_tree(self.rpc, self.owners["m2"], self.safe)
        self.assertNotEqual(abi.b2h(root), old_root)
        self.assertEqual(start, 2)
        # the old device's approval no longer counts
        old = [x for x in self.service_tx(c)["confirmations"] if x["owner"] == self.owners["m2"]][0]
        _, data, _ = parse_signature(h2b(old["signature"]))
        self.assertFalse(owner.is_valid_signature(self.rpc, self.owners["m2"], h2b(c), data))
        text = self.cmd("m3", "execute", "--safe-tx-hash", c, expect=1)
        self.assertIn("not enough valid signatures", text)
        # the restored home confirms again; the service keeps the old device's confirmation (the first per owner,
        # as the hosted service does), so the new signature goes into a proposal file that executes
        path = os.path.join(self.tmp.name, "restored-confirmation.json")
        text = self.cmd("m2", "confirm", "--safe-tx-hash", c, "--out", path, home=new_home)
        self.assertIn("your first of two keys for nonce 2 (slot 0)", text)  # the fresh key tree's
        self.assertIn("Note: the service holds your owner's earlier confirmation (device 0's)", text)
        self.assertIn("your signature is in the proposal file, not in the service", text)
        self.assertIn("execute with `--file`", self.cmd("m3", "execute", "--safe-tx-hash", c, expect=1))
        self.cmd("m3", "execute", "--safe-tx-hash", c, "--file", path)
        self.assertEqual(self.nonce(), 3)
        # the old device turns up again: it sees that it was replaced and won't undo the restore
        old_home, restored_root = self.homes["m2"], owner.read_tree(self.rpc, self.owners["m2"], self.safe)[0]
        text = self.cmd("m2", "status", "--safe", self.safe, home=old_home)
        self.assertIn("REPLACED (another device enrolled a newer key tree)", text)
        self.assertIn("another device has taken over this owner on this Safe", text)
        text = self.cmd("m2", "enroll", "--safe", self.safe, home=old_home, expect=2)
        self.assertIn("another device has taken over", text)
        self.assertIn("`enroll --take-over`", text)
        self.assertIn("another device has taken over", self.cmd(
            "m2", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01", home=old_home, expect=2))
        self.assertEqual(owner.read_tree(self.rpc, self.owners["m2"], self.safe)[0], restored_root)  # untouched
        # --take-over, both ways: each fresh tree starts after the one it replaces, so no key is ever shared
        _, _, _, restored_start, _ = owner.read_tree(self.rpc, self.owners["m2"], self.safe)
        self.assertIn("WARNING: another device has taken over",
                      self.cmd("m2", "enroll", "--safe", self.safe, "--take-over", home=old_home))
        _, _, _, old_again, _ = owner.read_tree(self.rpc, self.owners["m2"], self.safe)
        self.assertGreater(old_again, restored_start)
        self.assertIn("REPLACED", self.cmd("m2", "status", "--safe", self.safe, home=new_home))
        self.cmd("m2", "enroll", "--safe", self.safe, "--take-over", home=new_home)
        self.assertGreater(owner.read_tree(self.rpc, self.owners["m2"], self.safe)[3], old_again)
        self.homes["m2"] = new_home

    def test_5_stale_key_log_is_caught(self):
        stale = os.path.join(self.tmp.name, "m1-stale-copy")
        shutil.copytree(self.homes["m1"], stale)
        os.chmod(os.path.join(stale, "seed"), 0o600)
        self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.01")
        # the copy's log misses that signature: it would pick the same key for another transaction
        text = self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.02", "--nonce", "3",
                        home=stale, expect=2)
        self.assertIn("the key log is stale", text)

    def test_7_implementation_is_no_owner(self):
        """The bare implementation, called directly, has no key: it accepts no signature, stores no tree, and a Safe
        that names it as an owner can't execute"""
        impl = owner.implementation_address()
        self.assertEqual(abi.dec_word(self.rpc.eth_call(impl, abi.calldata("KEY()"))), bytes(32))
        # a confirmation that the member's proxy accepts, presented to the implementation
        own = self.owners["m1"]
        txs = [x for x in self.service_txs() if x["confirmations"]]
        rec = next(x for x in txs if any(c["owner"] == own for c in x["confirmations"]))
        h = h2b(rec["safeTxHash"])
        c = next(c for c in rec["confirmations"] if c["owner"] == own)
        _, data, _ = parse_signature(h2b(c["signature"]))
        t = SafeTx.from_json(rec)
        if self.nonce() <= t.nonce:  # still pending: the proxy accepts it
            self.assertTrue(owner.is_valid_signature(self.rpc, own, h, data))
        self.assertFalse(owner.is_valid_signature(self.rpc, impl, h, data))
        legacy = self.rpc.eth_call(impl, abi.calldata("isValidSignature(bytes,bytes)", ["bytes", "bytes"],
                                                      [t.preimage(31337, self.safe), data]))
        self.assertNotEqual(legacy[:4], owner.LEGACY_MAGIC)
        # a certificate the member's key signed for the implementation's address doesn't enrol a tree there
        mem = Member(self.homes["m1"])
        root = b"\x5a" * 24
        cert = mem.stateless_sign(owner.certificate_digest(31337, impl, self.safe, 0, 0, root, 4, 100))
        mem.close()
        with self.assertRaises(Reverted):
            self.rpc.eth_call(impl, owner.enroll_calldata(self.safe, 0, root, 4, 100, cert))
        # a 1-of-1 Safe whose owner is the implementation: its contract signature is refused (GS024)
        lone, _ = devchain.create_safe(self.rpc, self.deployer, self.release, [impl], 1, salt_nonce=7)
        t2 = SafeTx(to=RECIPIENT, nonce=0)
        blob = pack([(impl, data, True)])
        with self.assertRaises(Reverted) as e:
            self.rpc.eth_call(lone, t2.exec_calldata(blob), sender=self.deployer.address)
        self.assertIn("GS024", str(e.exception) + str(e.exception.data))
        # and the signer's execute skips it as a signature its owner contract refuses
        path = os.path.join(self.tmp.name, "lone.json")
        with open(path, "w") as f:
            json.dump({"chain": 31337, "safe": lone, "safeTx": t2.to_json(),
                       "safeTxHash": abi.b2h(t2.hash(31337, lone)),
                       "signatures": [{"owner": impl, "signature": abi.b2h(contract_signature(impl, data))}]}, f)
        text = self.cmd("m1", "execute", "--file", path, "--offline", expect=1)
        self.assertIn("signature refused by its owner contract", text)
        self.assertIn("not enough valid signatures", text)

    def test_8_move_to_a_new_device(self):
        """m3 moves to a new device while the old one works: both ends check the key log against the chain and the
        service, the new device signs with the same enrolled tree (no enroll, no fee) and the old one refuses. Then a
        whole-machine rollback of the new device (key log and anchor as they were, which no offline check can see)
        is caught by the online checks of the next move."""
        old, new = self.homes["m3"], os.path.join(self.tmp.name, "m3-new")
        online = ["--chain", "31337", "--rpc", self.chain.url, "--service", self.service]
        pfile = os.path.join(self.tmp.name, "m3-phrase")
        with open(pfile, "w") as f:
            f.write(" ".join(phrase.to_phrase(h2b(abi.read_file(os.path.join(old, "seed")).strip()))))
        # m1's pending proposal from step 5, approved by m3 on the old device
        pending = [x for x in self.service_txs() if x["nonce"] == self.nonce() and not x["isExecuted"]]
        h = pending[0]["safeTxHash"]
        self.cmd("m3", "confirm", "--safe-tx-hash", h)
        tree_before = owner.read_tree(self.rpc, self.owners["m3"], self.safe)

        def code_in(text):
            return re.search(r"\b([A-Z2-7]{4}(?:-[A-Z2-7]{4}){3})\b", text)[1]

        def run(argv, expect=0):
            code, text = self.run_cli(argv)
            self.assertEqual(code, expect, text)
            return text

        mc = code_in(run(["--home", new, "move", "start", "--phrase", pfile, "--insecure-plaintext-seed"]))
        bundle = os.path.join(self.tmp.name, "m3-move.json")
        text = run(["--home", old, "--yes", "move", "export", "--code", mc, "--out", bundle, *online])
        self.assertIn("the enrolled key tree is in the log, with 1 approval(s) at pending nonces", text)
        self.assertIn("the service holds no signature by this tree that the log lacks", text)
        text = run(["--home", new, "move", "import", bundle, *online])
        self.assertIn("the service holds no signature by this tree that the log lacks", text)
        self.assertIn("Moved in", text)
        self.assertEqual(owner.read_tree(self.rpc, self.owners["m3"], self.safe), tree_before)  # no new tree
        self.assertIn("moved its keys to another device", self.cmd("m3", "confirm", "--safe-tx-hash", h, expect=2))
        text = self.cmd("m3", "confirm", "--safe-tx-hash", h, home=new)  # the log knows the old device's approval
        self.assertIn("your first of two keys for nonce", text)
        self.assertIn("already signed this exact transaction", text)
        n = self.nonce()
        self.cmd("m3", "execute", "--safe-tx-hash", h)
        self.assertEqual(self.nonce(), n + 1)
        self.homes["m3"] = new

        # the new device's state (key log and anchor) before its next approval, as a VM snapshot would keep it
        m = Member(new, lock=False)
        anchor_path = os.path.join(device.anchor_dir(), m.device()["id"] + ".json")
        m.close()
        log_path = os.path.join(new, "keylog.jsonl")
        snapshot = abi.read_file(log_path, "rb"), abi.read_file(anchor_path, "rb")
        h2 = self.hash_from(self.cmd("m1", "propose", "--safe", self.safe, "--to", RECIPIENT, "--value", "0.02"))
        self.cmd("m3", "confirm", "--safe-tx-hash", h2, home=new)
        for path, data in zip((log_path, anchor_path), snapshot):  # rolled back in place: same files, same inode
            with open(path, "r+b") as f:
                f.write(data)
                f.truncate()
        self.assertIn("key log ACTIVE", self.cmd("m3", "status", home=new))  # offline it looks fine
        newer = os.path.join(self.tmp.name, "m3-newer")
        mc2 = code_in(run(["--home", newer, "move", "start", "--phrase", pfile, "--insecure-plaintext-seed"]))
        bundle2 = os.path.join(self.tmp.name, "m3-move-2.json")
        text = run(["--home", new, "--yes", "move", "export", "--code", mc2, "--out", bundle2, *online], expect=2)
        self.assertIn("not exported", text)
        self.assertIn("the key log is stale", text)
        m = Member(new, lock=False)
        self.assertEqual(m.state()[0], "active")  # refused before anything was locked
        m.close()
        run(["--home", new, "--yes", "move", "export", "--code", mc2, "--out", bundle2])  # without the check
        text = run(["--home", newer, "move", "import", bundle2, *online], expect=2)
        self.assertIn("not imported", text)
        self.assertIn("the key log is stale", text)
        self.assertTrue(move.pending(newer))  # nothing installed: it still waits
        self.assertFalse(os.path.exists(os.path.join(newer, "keylog.jsonl")))

    def service_txs(self):
        from winterlock_signer.service import Service
        return Service(self.service).get(f"/v2/safes/{self.safe}/multisig-transactions/").get("results", [])

    def test_6_status(self):
        text = self.cmd("m1", "status", "--safe", self.safe)
        self.assertIn("ENROLLED", text)
        self.assertIn("one-time keys used (1 for a replacement or cancellation), last at nonce", text)
        self.assertIn("of 32 nonces left", text)
        text = self.cmd("m2", "status")
        self.assertIn("restored from the recovery phrase", text)


if __name__ == "__main__":
    unittest.main()
