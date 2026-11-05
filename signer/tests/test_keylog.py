"""The key log and the member's safety rails, without a chain."""
import json
import os
import stat
import tempfile
import unittest

from winterlock_signer import owner, wots
from winterlock_signer.abi import h2b, read_file
from winterlock_signer.keylog import KeyLog, LogCorrupt, Refused
from winterlock_signer.member import Member
from winterlock_signer.safe import SafeTx

CHAIN = 31337
SAFE = "0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2"
TO = "0x000000000000000000000000000000000000dEaD"


class KeyLogBasics(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "keylog.jsonl")
        self.tree = {"t": "tree", "chain": CHAIN, "safe": SAFE, "root": "0x" + "ab" * 24, "start": 5, "height": 4}

    def tearDown(self):
        self.dir.cleanup()

    def test_persists_and_reloads(self):
        log = KeyLog(self.path)
        log.append(self.tree)
        log.record_sign(CHAIN, SAFE, self.tree, 6, 0, "0x" + "11" * 32)
        log.close()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        log = KeyLog(self.path)
        self.assertEqual(log.used(CHAIN, SAFE, self.tree["root"], 2)["hash"], "0x" + "11" * 32)
        log.close()

    def test_one_hash_per_key(self):
        log = KeyLog(self.path)
        log.record_sign(CHAIN, SAFE, self.tree, 6, 0, "0x" + "11" * 32)
        log.record_sign(CHAIN, SAFE, self.tree, 6, 0, "0x" + "11" * 32)  # the same hash again: allowed
        with self.assertRaises(Refused):
            log.record_sign(CHAIN, SAFE, self.tree, 6, 0, "0x" + "22" * 32)
        self.assertEqual(len(log.signs()), 1)
        log.close()

    def test_slots(self):
        log = KeyLog(self.path)
        h1, h2, h3 = ("0x" + c * 32 for c in ("11", "22", "33"))
        self.assertEqual(log.pick_slot(CHAIN, SAFE, self.tree, 6, h1), (0, False))
        log.record_sign(CHAIN, SAFE, self.tree, 6, 0, h1)
        self.assertEqual(log.pick_slot(CHAIN, SAFE, self.tree, 6, h1), (0, True))
        self.assertEqual(log.pick_slot(CHAIN, SAFE, self.tree, 6, h2), (1, False))
        log.record_sign(CHAIN, SAFE, self.tree, 6, 1, h2)
        self.assertEqual(log.pick_slot(CHAIN, SAFE, self.tree, 6, h2), (1, True))
        with self.assertRaises(Refused):
            log.pick_slot(CHAIN, SAFE, self.tree, 6, h3)
        # other nonces, trees, Safes and chains are independent
        self.assertEqual(log.pick_slot(CHAIN, SAFE, self.tree, 7, h3), (0, False))
        self.assertEqual(log.pick_slot(CHAIN, SAFE, dict(self.tree, root="0x" + "cd" * 24), 6, h3), (0, False))
        self.assertEqual(log.pick_slot(1, SAFE, self.tree, 6, h3), (0, False))
        with self.assertRaises(ValueError):
            log.pick_slot(CHAIN, SAFE, self.tree, 4, h3)  # before the tree's start
        with self.assertRaises(ValueError):
            log.pick_slot(CHAIN, SAFE, self.tree, 13, h3)  # past its 8 nonces
        log.close()

    def test_torn_tail_is_cut(self):
        log = KeyLog(self.path)
        log.record_sign(CHAIN, SAFE, self.tree, 6, 0, "0x" + "11" * 32)
        log.close()
        with open(self.path, "ab") as f:
            f.write(b'{"t":"sign","chain":')
        log = KeyLog(self.path)
        self.assertEqual(len(log.records), 1)
        self.assertTrue(log.warnings)
        log.record_sign(CHAIN, SAFE, self.tree, 7, 0, "0x" + "22" * 32)
        log.close()
        self.assertEqual(len(KeyLog(self.path).records), 2)

    def test_corruption_refuses(self):
        log = KeyLog(self.path)
        log.record_sign(CHAIN, SAFE, self.tree, 6, 0, "0x" + "11" * 32)
        log.close()
        rec = json.loads(read_file(self.path))
        rec["hash"] = "0x" + "22" * 32  # edited: the checksum no longer matches
        with open(self.path, "w") as f:
            f.write(json.dumps(rec) + "\n")
        with self.assertRaises(LogCorrupt):
            KeyLog(self.path)

    def test_lock(self):
        a = KeyLog(self.path)
        with self.assertRaises(Refused):
            KeyLog(self.path)
        a.close()
        KeyLog(self.path).close()


class MemberRails(unittest.TestCase):
    """A member's signer, offline: identity, fresh trees, signing through the log, restore"""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.home = os.path.join(cls.dir.name, "m")
        Member.init(cls.home).close()

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_files_are_private(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.home).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.home, "seed")).st_mode), 0o600)

    def test_identity_is_deterministic_and_init_refuses_twice(self):
        m = Member(self.home)
        key, own = m.key, m.owner
        seed = h2b(read_file(os.path.join(self.home, "seed")).strip())
        m.close()
        self.assertEqual(own, owner.owner_address(key))
        with self.assertRaises(Refused):
            Member.init(self.home)
        other = os.path.join(self.dir.name, "restored")
        r = Member.init(other, restore_seed=seed)
        self.assertEqual((r.key, r.owner), (key, own))
        self.assertEqual(r.log.identity()["t"], "restore")
        self.assertEqual(r.log.all_trees(), [])
        r.close()

    def test_sign_through_the_log(self):
        m = Member(self.home)
        safe = "0x00000000000000000000000000000000000000A1"
        rec = m.new_tree(CHAIN, safe, 0, 4)
        tree = m.tree(rec)
        t1 = SafeTx(to=TO, value=1, nonce=2)
        data, slot, k, h = m.sign_safe_tx(CHAIN, safe, rec, t1)
        self.assertEqual((slot, k), (0, 4))
        s = owner.parse_tx_signature_data(data)
        self.assertEqual(wots.verify_root(tree.seed, k, h, s[3], s[4]), tree.root)
        # the same transaction again: the same signature, no new record
        n = len(m.log.records)
        self.assertEqual(m.sign_safe_tx(CHAIN, safe, rec, t1)[0], data)
        self.assertEqual(len(m.log.records), n)
        # a replacement takes slot 1; a third version is refused; a forced slot can't reuse a key
        t2 = SafeTx(to=safe, nonce=2)
        self.assertEqual(m.sign_safe_tx(CHAIN, safe, rec, t2)[1], 1)
        with self.assertRaises(Refused):
            m.sign_safe_tx(CHAIN, safe, rec, SafeTx(to=TO, value=2, nonce=2))
        with self.assertRaises(Refused):
            m.sign_safe_tx(CHAIN, safe, rec, SafeTx(to=TO, value=2, nonce=2), slot=0)
        # a new tree must start later; the log survives a reload
        with self.assertRaises(Refused):
            m.new_tree(CHAIN, safe, 0, 4)
        m.close()
        m = Member(self.home)
        self.assertEqual(len(m.log.signs(CHAIN, safe)), 2)
        m.close()

    def test_trees_are_fresh(self):
        """Two trees for the same Safe and start (two restores of one seed) never share keys"""
        a = Member(self.home)
        safe = "0x00000000000000000000000000000000000000B2"
        ra = a.new_tree(CHAIN, safe, 3, 3)
        seed = h2b(read_file(os.path.join(self.home, "seed")).strip())
        a.close()
        b = Member.init(os.path.join(self.dir.name, "again"), restore_seed=seed)
        rb = b.new_tree(CHAIN, safe, 3, 3)
        self.assertNotEqual(ra["root"], rb["root"])
        self.assertNotEqual(ra["salt"], rb["salt"])
        b.close()


if __name__ == "__main__":
    unittest.main()
