"""Device binding (device.py): copies, rollbacks, adoption, fresh trees, and key logs from before device records."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from winterlock_signer import device, owner, seedfile
from winterlock_signer.abi import b2h
from winterlock_signer.keylog import KeyLog, Refused
from winterlock_signer.member import Member, identity_of
from winterlock_signer.safe import SafeTx

CHAIN = 31337
SAFE = "0x00000000000000000000000000000000000000C3"
TO = "0x000000000000000000000000000000000000dEaD"


def kinds(m):
    return [k for k, _ in m.problems]


class Copies(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.dir.name, "m")
        m = Member.init(self.home)
        self.rec = m.new_tree(CHAIN, SAFE, 0, 3)
        m.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=1, nonce=0))
        m.close()

    def tearDown(self):
        self.dir.cleanup()

    def copy(self, name="copy"):
        path = os.path.join(self.dir.name, name)
        shutil.copytree(self.home, path)
        return path

    def test_bound_and_counting(self):
        m = Member(self.home)
        self.assertEqual(m.state(), ("active", ""))
        dev = m.device()
        self.assertEqual((dev["how"], dev["gen"]), ("init", 0))
        a = device.load(dev["id"])
        self.assertEqual((a["count"], a["last"]), (len(m.log.records), m.log.records[-1]["chk"]))
        self.assertEqual(a["machine"], device.machine())
        m.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=2, nonce=1))
        self.assertEqual(device.load(dev["id"])["count"], len(m.log.records))  # advanced with every record
        m.close()

    def test_a_copied_directory_signs_nothing(self):
        copy = self.copy()
        c = Member(copy)
        st, why = c.state()
        self.assertEqual(st, "locked")
        self.assertIn("looks like a copy", why)
        self.assertIn("move export", why)  # and what to do instead
        self.assertEqual(kinds(c), ["inode"])
        n = len(c.log.records)
        for attempt in (lambda: c.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=2, nonce=1)),
                        lambda: c.stateless_sign(b"\x01" * 32), lambda: c.new_tree(CHAIN, SAFE, 4, 3)):
            with self.assertRaisesRegex(Refused, "looks like a copy"):
                attempt()
        self.assertEqual(len(c.log.records), n)
        c.close()
        reread = KeyLog(os.path.join(copy, "keylog.jsonl"), lock=False)
        self.assertEqual(len(reread.records), n)  # nothing written
        reread.close()
        o = Member(self.home)  # the original is unaffected
        self.assertEqual(o.state()[0], "active")
        o.close()

    def test_adopting_a_copy_makes_it_a_device_of_its_own(self):
        copy = self.copy()
        c = Member(copy)
        old_id = c.device()["id"]
        rec = c.add_device("adopt")
        self.assertNotEqual(rec["id"], old_id)
        self.assertEqual((rec["gen"], c.state()[0]), (1, "active"))
        c.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=2, nonce=1))
        c.close()
        # the original keeps its own anchor: now two copies sign, which is what `device adopt` warns about, and what
        # the Transaction Service check catches when one of them posts
        o = Member(self.home)
        self.assertEqual(o.state()[0], "active")
        o.close()
        c = Member(copy)
        self.assertEqual(c.state()[0], "active")
        c.close()

    def test_a_rollback_is_caught_and_only_fresh_trees_help(self):
        log_path = os.path.join(self.home, "keylog.jsonl")
        with open(log_path, "rb") as f:
            backup = f.read()
        m = Member(self.home)
        m.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=2, nonce=1))
        m.close()
        with open(log_path, "r+b") as f:  # the older log restored in place: the same file, the same inode
            f.write(backup)
            f.truncate()
        m = Member(self.home)
        self.assertEqual(kinds(m), [device.ROLLBACK])
        self.assertIn("rolled back", m.state()[1])
        # this log would give slot 0 at nonce 1 to another transaction: refused before any key is touched
        with self.assertRaisesRegex(Refused, "rolled back"):
            m.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=3, nonce=1))
        m.add_device("fresh-trees", retire=True)
        self.assertEqual(m.state()[0], "active")
        old = m.log.all_trees()[0]
        self.assertTrue(m.log.retired(old))
        self.assertEqual(m.log.trees(CHAIN, SAFE), [])
        self.assertIsNone(m.log.tree_by_root(CHAIN, SAFE, old["root"]))
        with self.assertRaisesRegex(Refused, "retired"):
            m.sign_safe_tx(CHAIN, SAFE, old, SafeTx(to=TO, value=3, nonce=1))
        fresh = m.new_tree(CHAIN, SAFE, 1, 3)
        self.assertNotEqual(fresh["root"], old["root"])
        self.assertFalse(m.log.retired(fresh))
        self.assertEqual(m.sign_safe_tx(CHAIN, SAFE, fresh, SafeTx(to=TO, value=3, nonce=1))[1], 0)
        m.close()

    def test_no_anchor_or_another_machine(self):
        m = Member(self.home)
        dev_id = m.device()["id"]
        m.close()
        device.forget(dev_id)
        m = Member(self.home)
        self.assertEqual(kinds(m), ["no-anchor"])
        m.add_device("adopt")
        m.close()
        with mock.patch.object(device, "_machine", "0" * 16):
            m = Member(self.home)
            self.assertIn("machine", kinds(m))
            m.close()

    def test_a_log_from_before_device_records_is_bound_on_first_use(self):
        home = os.path.join(self.dir.name, "legacy")
        os.makedirs(home, mode=0o700)
        seed = os.urandom(32)
        seedfile.write(os.path.join(home, "seed"), seed)
        key, own = identity_of(seed)
        log = KeyLog(os.path.join(home, "keylog.jsonl"))
        log.append({"t": "init", "owner": own, "key": b2h(key), "params": "D6", "stateless_b": 10,
                    "owner_code": owner.PINNED_COMMIT})
        log.close()
        m = Member(home, lock=False)  # read-only: no binding, no problem
        self.assertIsNone(m.device())
        self.assertEqual(m.state()[0], "active")
        m.close()
        m = Member(home)
        self.assertEqual(m.device()["how"], "upgrade")
        self.assertTrue(any("now bound" in w for w in m.log.warnings))
        m.close()
        m = Member(home)
        self.assertEqual((m.device()["how"], m.problems), ("upgrade", []))
        m.close()

    def test_a_frozen_log_takes_only_device_records(self):
        log = KeyLog(os.path.join(self.dir.name, "frozen.jsonl"))
        log.frozen = "locked for a test"
        with self.assertRaisesRegex(Refused, "locked for a test"):
            log.append({"t": "sign"})
        log.append({"t": "device", "id": "00", "how": "adopt", "gen": 0})
        log.close()


if __name__ == "__main__":
    unittest.main()
