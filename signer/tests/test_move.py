"""Moving a signer to a new device (move.py), offline: the protocol and its failure modes."""
import base64
import json
import os
import shutil
import tempfile
import unittest

from winterlock_signer import move
from winterlock_signer.abi import h2b, read_file
from winterlock_signer.keylog import Refused
from winterlock_signer.member import REQUEST, Member
from winterlock_signer.move import MoveError
from winterlock_signer.safe import SafeTx

CHAIN = 31337
SAFE = "0x00000000000000000000000000000000000000D4"
TO = "0x000000000000000000000000000000000000dEaD"
OLD_PW, NEW_PW = "old device passphrase", "new device passphrase"
N = 1 << 10  # a cheap scrypt for tests


class Move(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.old = os.path.join(self.dir.name, "old")
        self.new = os.path.join(self.dir.name, "new")
        self.bundle = os.path.join(self.dir.name, "bundle.json")
        m = Member.init(self.old, passphrase=OLD_PW, scrypt_n=N)
        self.seed, self.owner = m.seed(), m.owner
        self.rec = m.new_tree(CHAIN, SAFE, 0, 3)
        self.tx0 = SafeTx(to=TO, value=1, nonce=0)
        m.sign_safe_tx(CHAIN, SAFE, self.rec, self.tx0)
        m.close()

    def tearDown(self):
        self.dir.cleanup()

    def start(self, home=None):
        return move.start(home or self.new, self.seed, NEW_PW, scrypt_n=N)

    def export(self, code, path=None, **kw):
        m = Member(self.old, passphrase=OLD_PW)
        try:
            return move.export(m, code, path or self.bundle, **kw)
        finally:
            m.close()

    def doc(self, path=None):
        return json.loads(read_file(path or self.bundle))

    def import_(self, home=None, path=None):
        home = home or self.new
        seed, payload, records = move.open_bundle(home, self.doc(path), passphrase=NEW_PW)
        return move.install(home, seed, payload, records, passphrase=NEW_PW)

    def test_a_move_keeps_the_trees(self):
        req = self.start()
        self.assertEqual(req["owner"], self.owner)
        with self.assertRaisesRegex(Refused, "waiting for a move"):
            Member(self.new)
        payload = self.export(req["request"])
        # the old device: locked for good, its seed file gone
        old = Member(self.old)
        self.assertEqual(old.state()[0], "moved")
        self.assertFalse(os.path.exists(os.path.join(self.old, "seed")))
        for attempt in (lambda: old.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=2, nonce=1)),
                        lambda: old.stateless_sign(b"\x01" * 32), lambda: old.new_tree(CHAIN, SAFE, 4, 3),
                        old.seed):
            with self.assertRaisesRegex(Refused, "moved its keys to another device"):
                attempt()
        old.close()
        self.assertNotIn(self.seed.hex(), read_file(self.bundle))  # encrypted, and it carries no seed anyway
        new = self.import_()
        self.assertEqual((new.state()[0], new.owner), ("active", self.owner))
        dev = new.device()
        self.assertEqual((dev["how"], dev["move"], dev["gen"]), ("move-in", payload["move"], 1))
        self.assertFalse(os.path.exists(os.path.join(self.new, REQUEST)))
        self.assertEqual(new.log.last("backup")["how"], "move-in")
        # the same tree, rebuilt from the phrase and the salt in the log: no new certificate, no fee
        rec = new.active_tree(CHAIN, SAFE)
        self.assertEqual(rec["root"], self.rec["root"])
        self.assertEqual(new.tree(rec).root, h2b(self.rec["root"]))
        # and the log's memory: slot 0 at nonce 0 is used, so a replacement takes slot 1 and a third is refused
        self.assertEqual(new.sign_safe_tx(CHAIN, SAFE, rec, self.tx0)[1], 0)
        self.assertEqual(new.sign_safe_tx(CHAIN, SAFE, rec, SafeTx(to=SAFE, nonce=0))[1], 1)
        with self.assertRaises(Refused):
            new.sign_safe_tx(CHAIN, SAFE, rec, SafeTx(to=TO, value=9, nonce=0))
        new.close()
        new = Member(self.new, passphrase=NEW_PW)  # reopened: bound to this device
        self.assertEqual((new.state()[0], new.problems), ("active", []))
        new.close()

    def test_one_bundle_two_devices(self):
        """A bundle opens only on the device whose request it answers, and only once"""
        req = self.start()
        self.export(req["request"])
        other = os.path.join(self.dir.name, "other")
        self.start(other)
        with self.assertRaisesRegex(MoveError, "made for move request"):
            move.open_bundle(other, self.doc(), passphrase=NEW_PW)
        self.import_().close()
        with self.assertRaisesRegex(MoveError, "isn't waiting for a move"):
            move.open_bundle(self.new, self.doc(), passphrase=NEW_PW)

    def test_a_copied_request_is_refused(self):
        req = self.start()
        twin = os.path.join(self.dir.name, "twin")
        shutil.copytree(self.new, twin)
        self.export(req["request"])
        with self.assertRaisesRegex(MoveError, "isn't where it was made"):
            move.open_bundle(twin, self.doc(), passphrase=NEW_PW)
        self.import_().close()

    def test_exporting_twice(self):
        req = self.start()
        first = self.export(req["request"])
        m = Member(self.old)
        with self.assertRaisesRegex(Refused, "moved its keys"):
            m.seed()
        with self.assertRaisesRegex(Refused, "another signer"):
            m.use_seed(os.urandom(32))
        m.use_seed(self.seed)  # the phrase stands in for the removed seed file
        again = move.export(m, req["request"], self.bundle + "2")
        self.assertEqual(again, first)  # the same request: the same log, the same move
        self.assertNotEqual(self.doc(), self.doc(self.bundle + "2"))  # (a fresh salt and nonce)
        with self.assertRaisesRegex(MoveError, "already handed its keys over"):
            move.export(m, move.new_code(), self.bundle + "3")
        m.close()

    def test_replacing_a_request_that_never_finished(self):
        req1 = self.start()
        self.export(req1["request"])
        move.cancel(self.new)  # that new device gave up before importing
        req2 = self.start()
        m = Member(self.old)
        m.use_seed(self.seed)
        payload = move.export(m, req2["request"], self.bundle, replace_request=True)
        m.close()
        recs = [json.loads(line) for line in payload["log"]]
        self.assertEqual([r["t"] for r in recs[-2:]], ["move-out", "move-out"])
        self.assertEqual(recs[-1]["replaces"], req1["request"])
        self.import_().close()

    def test_changed_bundles_are_refused(self):
        req = self.start()
        self.export(req["request"])
        doc = self.doc()
        blob = bytearray(base64.b64decode(doc["ct"]))
        blob[10] ^= 1
        for changed in (dict(doc, ct=base64.b64encode(bytes(blob)).decode()),
                        dict(doc, exported="2020-01-01T00:00:00Z"), dict(doc, salt="00" * 16)):
            with self.assertRaisesRegex(MoveError, "doesn't open"):
                move.open_bundle(self.new, changed, passphrase=NEW_PW)
        payload = move.unseal(self.seed, doc, req["request"])
        # sealed with another signer's phrase
        with self.assertRaisesRegex(MoveError, "doesn't open"):
            move.open_bundle(self.new, move.seal(os.urandom(32), payload), passphrase=NEW_PW)
        # sealed correctly, but a record dropped from the log (a faulty exporter): the move-out's commitment fails
        dropped = dict(payload, log=[line for line in payload["log"] if '"t":"sign"' not in line])
        with self.assertRaisesRegex(MoveError, "commits to"):
            move.open_bundle(self.new, move.seal(self.seed, dropped), passphrase=NEW_PW)
        edited = dict(payload, log=[line.replace('"slot":0', '"slot":1') for line in payload["log"]])
        with self.assertRaisesRegex(MoveError, "checksum"):
            move.open_bundle(self.new, move.seal(self.seed, edited), passphrase=NEW_PW)
        self.assertFalse(os.path.exists(os.path.join(self.new, "keylog.jsonl")))  # nothing installed
        self.import_().close()

    def test_an_interrupted_export(self):
        req = self.start()
        m = Member(self.old, passphrase=OLD_PW)
        move.lock_for(m, req["request"])  # the lock is saved, then the export stops
        m.close()
        m = Member(self.old, passphrase=OLD_PW)
        st, why = m.state()
        self.assertEqual(st, "locked")
        self.assertIn(f"move export --code {req['request']}", why)
        with self.assertRaisesRegex(Refused, "signs nothing more"):
            m.sign_safe_tx(CHAIN, SAFE, self.rec, SafeTx(to=TO, value=2, nonce=1))
        move.export(m, req["request"], self.bundle)  # running it again finishes it
        self.assertEqual(m.state()[0], "moved")
        m.close()
        self.import_().close()

    def test_an_interrupted_import(self):
        req = self.start()
        self.export(req["request"])
        seed, payload, records = move.open_bundle(self.new, self.doc(), passphrase=NEW_PW)
        # stopped after the key log was renamed into place, before the device record
        move.stage(self.new, records).close()
        os.replace(os.path.join(self.new, move.STAGED), os.path.join(self.new, "keylog.jsonl"))
        with self.assertRaisesRegex(Refused, "waiting for a move"):
            Member(self.new)
        m = self.import_()
        n = len(m.log.records)
        m.close()
        # stopped after the device record, before the request was removed: finishing again adds nothing
        with open(os.path.join(self.new, REQUEST), "w") as f:
            json.dump(req, f)
        m = move.install(self.new, seed, payload, records, passphrase=NEW_PW)
        self.assertEqual(len(m.log.records), n)
        self.assertEqual(sum(1 for r in m.log.records if r["t"] == "device" and r["how"] == "move-in"), 1)
        m.close()

    def test_a_suspected_copy_cannot_move(self):
        copy = os.path.join(self.dir.name, "copy")
        shutil.copytree(self.old, copy)
        req = self.start()
        c = Member(copy, passphrase=OLD_PW)
        with self.assertRaisesRegex(Refused, "looks like a copy"):
            move.export(c, req["request"], self.bundle)
        self.assertIsNone(c.move_out())
        c.close()

    def test_cancel_and_codes(self):
        self.start()
        with self.assertRaisesRegex(MoveError, "already waits"):
            self.start()
        move.cancel(self.new)
        self.assertIsNone(move.pending(self.new))
        self.assertFalse(os.path.exists(os.path.join(self.new, "seed")))
        with self.assertRaises(MoveError):
            move.cancel(self.new)
        Member.init(self.new, restore_seed=self.seed).close()  # the directory is free again
        with self.assertRaisesRegex(MoveError, "already has a signer"):
            self.start()
        code = move.new_code()
        self.assertRegex(code, r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$")
        self.assertEqual(move.normalize_code(code.lower().replace("-", " ")), code)
        with self.assertRaises(MoveError):
            move.normalize_code("ABCD-EFGH")


if __name__ == "__main__":
    unittest.main()
