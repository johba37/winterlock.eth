"""The command line's arguments, offline: a SafeTx hash after the command or with --safe-tx-hash, and the messages for a
missing chain, RPC, hash or file (the flows themselves run on anvil: test_e2e_anvil.py)."""
import json
import os
import tempfile
import unittest
from unittest import mock

from tests.term import run
from winterlock_signer import cli
from winterlock_signer.member import Member

H = "0x" + "f7ef" * 16
OTHER = "0x" + "12ab" * 16


class FakeRpc:
    """A node that only answers eth_chainId, as anvil (31337) or Sepolia"""
    chain = 31337

    def __init__(self, url, timeout=None):
        self.url = url

    def chain_id(self):
        return self.chain


class Arguments(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.dir.name, "m")
        Member.init(self.home).close()
        env = mock.patch.dict(os.environ)  # restored after each test
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("WINTERLOCK_RPC", None)

    def tearDown(self):
        self.dir.cleanup()

    def cli(self, *argv, expect=1):
        code, text = run(["--home", self.home, *argv])
        self.assertEqual(code, expect, text)
        return text

    def test_hash_after_the_command(self):
        parse = cli.build_parser().parse_args
        for cmd in ("confirm", "execute"):
            args = parse([cmd, H, "--chain", "sepolia"])
            self.assertEqual((args.hash, args.safe_tx_hash), (H, None))
            self.assertEqual(cli.safe_tx_hash_arg(args), bytes.fromhex(H[2:]))
            args = parse([cmd, "--chain", "sepolia", "--safe-tx-hash", H])  # the option still works
            self.assertEqual(cli.safe_tx_hash_arg(args), bytes.fromhex(H[2:]))
            args = parse([cmd, H.upper().replace("0X", "0x"), "--safe-tx-hash", H])  # both, the same hash
            self.assertEqual(cli.safe_tx_hash_arg(args), bytes.fromhex(H[2:]))
            # both, different: refused before anything else, the chain included
            text = self.cli(cmd, H, "--safe-tx-hash", OTHER)
            self.assertIn("two different SafeTx hashes", text)
            self.assertIn("isn't a whole SafeTx hash", self.cli(cmd, "0xf7ef", "--chain", "sepolia"))
            self.assertIn("isn't a whole SafeTx hash", self.cli(cmd, "f7ef…", "--chain", "sepolia"))
            self.assertIn("which proposal?", self.cli(cmd, "--chain", "sepolia"))
            self.assertIn("which chain is the Safe on?", self.cli(cmd, H))

    def test_a_hash_and_a_file_must_agree(self):
        path = os.path.join(self.dir.name, "p.json")
        with open(path, "w") as f:
            json.dump({"chain": 31337, "safe": "0x" + "00" * 19 + "e5", "safeTxHash": H, "safeTx": {}}, f)
        with mock.patch.object(cli, "Rpc", FakeRpc):
            text = self.cli("confirm", OTHER, "--file", path, "--chain", "anvil", "--rpc", "http://node", "--offline")
            self.assertIn(f"holds the proposal {H}, not {OTHER}", text)
            text = self.cli("execute", "--file", path, "--chain", "sepolia", "--rpc", "http://node", "--offline")
            self.assertIn("is local anvil (chain 31337), not Sepolia (chain 11155111)", text)  # the RPC's chain
            text = self.cli("confirm", "--file", os.path.join(self.dir.name, "nope.json"), "--chain", "anvil",
                            "--rpc", "http://node", "--offline")
            self.assertIn("error: No such file or directory", text)  # a message, not a traceback

    def test_missing_chain_and_rpc(self):
        safe = "0x" + "00" * 19 + "e5"
        for argv in (["enroll", "--safe", safe], ["propose", "--safe", safe, "--to", safe], ["queue", "--safe", safe],
                     ["confirm", H], ["execute", H], ["message", "--file", "m.json"]):
            text = self.cli(*argv)
            self.assertIn("which chain is the Safe on? Add --chain", text)
            self.assertIn("sepolia", text)
            self.assertNotIn("Traceback", text)
        self.assertIn("no RPC for Sepolia (chain 11155111): add --rpc URL, or set WINTERLOCK_RPC",
                      self.cli("queue", "--safe", safe, "--chain", "sepolia"))
        # with an RPC but no --chain, the RPC's chain is named, not chosen
        with mock.patch.object(cli, "Rpc", type("SepoliaRpc", (FakeRpc,), {"chain": 11155111})), \
                mock.patch.dict(os.environ, {"WINTERLOCK_RPC": "https://rpc.example/secret-key"}):
            text = self.cli("confirm", H)
        self.assertIn("Your RPC (https://rpc.example) is Sepolia (chain 11155111): --chain sepolia.", text)
        self.assertNotIn("secret-key", text)


if __name__ == "__main__":
    unittest.main()
