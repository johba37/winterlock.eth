"""The command line for backup, recovery and devices, with a scripted member at the keyboard (tests/term.py)."""
import os
import re
import shutil
import tempfile
import unittest

from tests.term import PASSPHRASE, Terminal, run
from winterlock_signer import move, phrase, seedfile
from winterlock_signer.keylog import KeyLog
from winterlock_signer.member import Member, identity_of
from winterlock_signer.safe import SafeTx

CHAIN = 31337
SAFE = "0x00000000000000000000000000000000000000E5"
TO = "0x000000000000000000000000000000000000dEaD"


class Cli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def ok(self, argv, term=None, expect=0):
        code, text = run(argv, term)
        self.assertEqual(code, expect, text)
        return text

    def new_signer(self, name="m"):
        """(home, the 24 words) of a signer made through `init`"""
        t = Terminal()
        self.ok(["--home", self.path(name), "init"], t)
        return self.path(name), t.shown_phrase()

    def phrase_file(self, words, name="phrase.txt"):
        with open(self.path(name), "w") as f:
            f.write(" ".join(words) + "\n")
        return self.path(name)

    def test_init_shows_the_phrase_once_and_checks_it(self):
        t = Terminal()
        text = self.ok(["--home", self.path("m"), "init"], t)
        words = t.shown_phrase()
        self.assertEqual(sum(1 for p in t.prompts if "word #" in p), 3)
        self.assertIn("Never type it into a website", text)
        self.assertEqual(text.count(" 1. "), 1)  # shown once
        m = Member(self.path("m"), lock=False)
        self.assertEqual(seedfile.kind(m.seed_path), "encrypted")
        self.assertEqual(m.log.last("backup")["how"], "init")
        self.assertEqual(identity_of(phrase.to_seed(" ".join(words)))[1], m.owner)  # the phrase is the backup
        self.assertEqual(seedfile.read(m.seed_path, lambda: PASSPHRASE), phrase.to_seed(" ".join(words)))
        m.close()
        text = self.ok(["--home", self.path("m"), "status"])
        for s in ("device ACTIVE", "created here", "seed file encrypted with a passphrase", "recovery phrase checked"):
            self.assertIn(s, text)
        self.ok(["--home", self.path("m"), "init"], Terminal(), expect=2)  # never over an existing signer

    def test_the_backup_check_cant_be_skipped(self):
        text = self.ok(["--home", self.path("m"), "init"], Terminal(wrong_rounds=5), expect=1)
        self.assertIn("nothing was saved", text)
        self.assertFalse(os.path.exists(self.path("m")) and os.listdir(self.path("m")))
        t = Terminal(wrong_rounds=1)
        text = self.ok(["--home", self.path("m"), "init"], t)
        self.assertIn("doesn't match", text)
        self.assertEqual(sum(1 for p in t.prompts if "word #" in p), 6)

    def test_test_mode(self):
        t = Terminal()
        text = self.ok(["--home", self.path("m"), "init", "--insecure-plaintext-seed"], t)
        self.assertIn("TEST MODE", text)
        self.assertEqual(t.prompts, [])
        text = self.ok(["--home", self.path("m"), "status"])
        self.assertIn("NOT encrypted", text)
        self.assertIn("NEVER CHECKED", text)

    def test_backup_and_passphrase(self):
        home, words = self.new_signer()
        text = self.ok(["--home", home, "backup", "--check"], Terminal(words=words))
        self.assertNotIn(" 1. ", text)  # --check doesn't show the phrase
        self.assertIn("recovery phrase checked", self.ok(["--home", home, "status"]))
        m = Member(home, lock=False)
        self.assertEqual(m.log.last("backup")["how"], "check")
        m.close()
        self.ok(["--home", home, "backup"], Terminal())  # shows it, then checks it
        # a new passphrase: unlock with the old one, then the new one twice
        self.ok(["--home", home, "passphrase"], Terminal(passphrase=[PASSPHRASE, "second passphrase",
                                                                      "second passphrase"]))
        seed = seedfile.read(os.path.join(home, "seed"), lambda: "second passphrase")
        self.ok(["--home", home, "passphrase"], Terminal(passphrase="not the passphrase"), expect=2)
        # forgotten: the phrase sets a new one, and the key log stays
        self.ok(["--home", home, "passphrase", "--forgot", "--phrase", self.phrase_file(words)],
                Terminal(passphrase="third passphrase"))
        self.assertEqual(seedfile.read(os.path.join(home, "seed"), lambda: "third passphrase"), seed)
        other = phrase.to_phrase(os.urandom(32))
        text = self.ok(["--home", home, "passphrase", "--forgot", "--phrase", self.phrase_file(other, "other.txt")],
                       Terminal(), expect=2)
        self.assertIn("belongs to another signer", text)

    def test_restore_asks_what_happened(self):
        home, words = self.new_signer()
        owner_addr = identity_of(phrase.to_seed(" ".join(words)))[1]
        pfile = self.phrase_file(words)
        # someone else may have the phrase: no restore, guidance instead
        text = self.ok(["--home", self.path("r"), "init", "--restore", pfile], Terminal(situation="3"), expect=1)
        self.assertIn("swapOwner", text)
        self.assertFalse(os.path.exists(os.path.join(self.path("r"), "seed")))
        # lost: fresh trees, the cost, and what to tell the team
        text = self.ok(["--home", self.path("r"), "init", "--restore", pfile], Terminal(situation="2"))
        for s in (owner_addr, "never uses the trees of the old device", "0.25M gas", "stops counting",
                  "Tell your team"):
            self.assertIn(s, text)
        m = Member(self.path("r"), lock=False)
        self.assertEqual((m.log.identity()["t"], m.log.last("backup")["how"], m.device()["how"]),
                         ("restore", "restore", "restore"))
        self.assertEqual(m.log.all_trees(), [])
        m.close()
        # typed at the prompt, with a typo first; then a move
        t = Terminal(phrase=" ".join(words), situation="1")
        text = self.ok(["--home", self.path("n"), "init", "--restore"], t)
        self.assertIn("Move code", text)
        self.assertTrue(move.pending(self.path("n")))
        bad = Terminal(phrase=" ".join(words[:23] + ["zoo"]))
        text = self.ok(["--home", self.path("x"), "init", "--restore", "--lost"], bad, expect=1)
        self.assertIn("checksum", text)
        self.assertIn("no valid recovery phrase", text)

    def test_move_on_the_command_line(self):
        old, words = self.new_signer("old")
        m = Member(old, passphrase=PASSPHRASE)
        rec = m.new_tree(CHAIN, SAFE, 0, 3)
        m.sign_safe_tx(CHAIN, SAFE, rec, SafeTx(to=TO, value=1, nonce=0))
        m.close()
        pfile = self.phrase_file(words)
        new, bundle = self.path("new"), self.path("bundle.json")
        text = self.ok(["--home", new, "move", "start", "--phrase", pfile])
        code = re.search(r"\b([A-Z2-7]{4}(?:-[A-Z2-7]{4}){3})\b", text)[1]
        self.assertIn(f"move export --code {code}", text)
        text = self.ok(["--home", old, "move", "export", "--code", code, "--out", bundle])  # confirmed: y
        self.assertIn("locked for good", text)
        text = self.ok(["--home", old, "status"])
        self.assertIn("device MOVED", text)
        self.assertIn("seed file not on this device", text)
        self.assertIn("moved its keys to another device", self.ok(["--home", old, "backup"], expect=2))
        self.assertIn("moved its keys", self.ok(["--home", old, "passphrase"], expect=2))
        self.assertIn("moved its keys", self.ok(["--home", old, "device", "adopt"], expect=2))
        # the same bundle again, from the phrase (say the file was lost on the way)
        text = self.ok(["--home", old, "move", "export", "--code", code, "--out", bundle, "--phrase", pfile])
        self.assertIn("writing the same bundle again", text)
        text = self.ok(["--home", new, "move", "import", bundle])
        self.assertIn("Moved in", text)
        self.assertIn("Not checked online", text)
        self.assertFalse(os.path.exists(bundle))  # consumed
        text = self.ok(["--home", new, "status"])
        for s in ("device ACTIVE", "moved in from another device", rec["root"][:18], "1 keys used",
                  "recovery phrase checked"):
            self.assertIn(s, text)
        # cancel only applies to a pending move
        self.assertIn("no pending move", self.ok(["--home", new, "move", "cancel"], expect=2))

    def test_a_copy_and_the_device_commands(self):
        home, _ = self.new_signer()
        m = Member(home, passphrase=PASSPHRASE)
        rec = m.new_tree(CHAIN, SAFE, 0, 3)
        m.sign_safe_tx(CHAIN, SAFE, rec, SafeTx(to=TO, value=1, nonce=0))
        m.close()
        copy = self.path("copy")
        shutil.copytree(home, copy)
        text = self.ok(["--home", copy, "status"])
        self.assertIn("device LOCKED", text)
        self.assertIn("WARNING: the key log is another file", text)
        self.assertIn("looks like a copy", self.ok(["--home", copy, "move", "export", "--code", move.new_code(),
                                                     "--out", self.path("b.json")], expect=2))
        text = self.ok(["--home", copy, "device", "adopt"])
        self.assertIn("Adopted", text)
        self.assertIn("device ACTIVE", self.ok(["--home", copy, "status"]))
        self.assertIn("nothing to adopt", self.ok(["--home", copy, "device", "adopt"]))
        # a rollback in place: adopt is refused, fresh trees retire everything
        log_path = os.path.join(home, "keylog.jsonl")
        with open(log_path, "rb") as f:
            before = f.read()
        m = Member(home, passphrase=PASSPHRASE)
        m.sign_safe_tx(CHAIN, SAFE, rec, SafeTx(to=TO, value=2, nonce=1))
        m.close()
        with open(log_path, "r+b") as f:
            f.write(before)
            f.truncate()
        self.assertIn("rolled back", self.ok(["--home", home, "device", "adopt"], expect=2))
        text = self.ok(["--home", home, "device", "fresh-trees"])
        self.assertIn("Retired the trees", text)
        text = self.ok(["--home", home, "status"])
        self.assertIn("RETIRED HERE", text)
        self.assertIn("fresh trees after a suspected copy", text)
        log = KeyLog(log_path, lock=False)
        self.assertEqual(log.trees(CHAIN, SAFE), [])
        log.close()


if __name__ == "__main__":
    unittest.main()
