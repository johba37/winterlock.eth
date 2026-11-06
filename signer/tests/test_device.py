"""Device binding (device.py): copies, rollbacks, adoption, fresh trees, and key logs from before device records. And
device homes (owner v2's device keys, member.py), offline: creation, the check code, what they record and refuse."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tests.term import PASSPHRASE, Terminal, run
from winterlock_signer import device, leansphincs, owner, phrase, seedfile, wots
from winterlock_signer.abi import b2h, h2b, read_file
from winterlock_signer.keylog import KeyLog, Refused
from winterlock_signer.member import Member, check_code, device_key_of, identity_of
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


class DeviceHomes(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.member_home = os.path.join(self.dir.name, "m")
        m = Member.init(self.member_home)
        self.owner = m.owner
        m.close()

    def tearDown(self):
        self.dir.cleanup()

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def test_a_device_home(self):
        home = self.path("d")
        d = Member.init_device(home, self.owner.lower(), 2)
        seed = h2b(read_file(os.path.join(home, "seed")).strip())
        self.assertEqual((d.owner, d.device_no, d.is_device), (self.owner, 2, True))
        self.assertEqual(d.key, device_key_of(seed))
        self.assertNotEqual(d.key, identity_of(seed)[0])  # not a member key: another derivation
        ident = d.log.identity()
        self.assertEqual((ident["t"], ident["device"], ident["implementation"], ident["version"]),
                         ("device-new", 2, owner.implementation_address(), 2))
        self.assertEqual((d.device()["how"], d.state()[0]), ("device-new", "active"))
        d.close()
        d = Member(home)  # reopened: the same identity, from the log
        self.assertEqual((d.owner, d.device_no, d.key), (self.owner, 2, device_key_of(seed)))
        # its trees carry its device number and the generation they were made under
        rec = d.new_tree(31337, SAFE, 4, 3, generation=5)
        self.assertEqual((rec["device"], rec["gen"]), (2, 5))
        self.assertEqual(d.tree(rec).seed, owner.tree_seed(31337, self.owner, SAFE, 2, 5, 4))
        data, slot, k, h = d.sign_safe_tx(31337, SAFE, rec, SafeTx(to=TO, value=1, nonce=5))
        parsed = owner.parse_tx_signature_data(data)
        self.assertEqual(parsed[:3], (0, 2, SAFE))
        self.assertEqual(wots.verify_root(d.tree(rec).seed, k, h, parsed[4], parsed[5]), h2b(rec["root"]))
        cert = d.certificate(rec)
        digest = owner.certificate_digest(31337, self.owner, SAFE, 2, 5, h2b(rec["root"]), 3, 4)
        self.assertEqual(d.log.last("cert")["digest"], b2h(digest))
        self.assertTrue(leansphincs.verify(d.key, digest, cert))
        # what only the member key does
        for attempt in (lambda: d.device_certificate(31337, 1, 1, b"\x01" * 32), lambda: d.revocation(31337, 1, 1),
                        lambda: d.use_seed(seed)):
            with self.assertRaisesRegex(Refused, "only the member key does that"):
                attempt()
        self.assertEqual(d.stateless_signatures(), 1)
        d.close()
        with self.assertRaises(Refused):
            Member.init_device(home, self.owner, 2)  # never over an existing home
        with self.assertRaises(Refused):
            Member.init_device(self.path("e"), self.owner, 0)  # device 0 is the member key

    def test_the_check_code(self):
        key = bytes(range(1, 33))
        code = check_code(self.owner, 1, key)
        words = code.split()
        self.assertEqual(len(words), 5)
        self.assertTrue(all(phrase.word(w) == w for w in words))  # BIP-39 English words
        self.assertEqual(code, check_code(self.owner.lower(), 1, key))  # the address, not its spelling
        for other in (check_code(self.owner, 2, key), check_code(TO, 1, key),
                      check_code(self.owner, 1, key[:-1] + b"\x00")):
            self.assertNotEqual(code, other)

    def test_the_member_key_certifies_and_records(self):
        m = Member(self.member_home)
        self.assertFalse(m.is_device)
        key = Member.init_device(self.path("d"), self.owner, 1).key
        sig = m.device_certificate(31337, 1, 1, key)
        self.assertTrue(leansphincs.verify(m.key, owner.device_digest(31337, self.owner, 1, 1, key), sig))
        m.device_certificate(11155111, 1, 1, key)
        m.revocation(31337, 1, 1)
        self.assertEqual(m.certified_chains(1), [31337, 11155111])
        self.assertEqual(m.certified_chains(2), [])
        self.assertEqual([r["t"] for r in m.log.records[-3:]], ["device-cert", "device-cert", "device-revoke"])
        self.assertEqual(m.stateless_signatures(), 3)
        with self.assertRaises(Refused):
            m.device_certificate(31337, 0, 1, key)  # devices 1 to 3 only
        with self.assertRaises(Refused):
            m.new_tree(31337, SAFE, 0, 3, generation=1)  # the member key is at generation 0 for good
        m.close()

    def test_a_v1_home_says_what_to_do(self):
        home = self.path("v1")
        os.makedirs(home, mode=0o700)
        seed = os.urandom(32)
        seedfile.write(os.path.join(home, "seed"), seed)
        key, _ = identity_of(seed)
        log = KeyLog(os.path.join(home, "keylog.jsonl"))
        log.append({"t": "init", "owner": "0x00000000000000000000000000000000000000F1", "key": b2h(key),
                    "params": "D6", "stateless_b": 10, "owner_code": "357c25f"})
        log.close()
        with self.assertRaisesRegex(Refused, "set up for WinterlockOwner v1.*init --restore"):
            Member(home)

    def test_device_new_on_the_command_line(self):
        home = self.path("d")
        code, text = run(["--home", home, "device", "new", "--owner", self.owner, "--device", "3"], Terminal())
        self.assertEqual(code, 0, text)
        d = Member(home, lock=False)
        self.assertEqual(seedfile.kind(d.seed_path), "encrypted")
        self.assertEqual(device_key_of(seedfile.read(d.seed_path, lambda: PASSPHRASE)), d.key)
        self.assertEqual(d.device_no, 3)
        self.assertIn(f"check code   {d.check_code()}", text)
        self.assertIn(f"device certify --device 3 --key {b2h(d.key)} --chain CHAIN", text)
        d.close()
        code, text = run(["--home", home, "status"])
        self.assertEqual(code, 0, text)
        for s in ("a device home, device 3", "no recovery phrase", "key log ACTIVE", "check code"):
            self.assertIn(s, text)
        self.assertNotIn("NEVER CHECKED", text)
        code, text = run(["--home", home, "address"])
        self.assertIn("this home        device 3", text)
        code, text = run(["--home", home, "backup"])
        self.assertEqual(code, 2, text)
        self.assertIn("a device home has no recovery phrase", text)
        code, text = run(["--home", self.path("x"), "device", "new", "--owner", "0x1234", "--device", "1"])
        self.assertEqual(code, 1, text)
        self.assertIn("--owner: not an address", text)


if __name__ == "__main__":
    unittest.main()
