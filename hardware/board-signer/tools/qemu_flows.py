#!/usr/bin/env python3
"""The board signer's firmware in QEMU, driven over its serial port by the Python client (board_client.py) and checked
with the Python signer: setup, a restart and unlock, enrolment, an ETH transfer, an approveHash with the parent's
fields, a call that isn't decoded, a refused delegate call, QEMU killed in the middle of a key log write (twice: after
the record's header, and after the whole record) and started again from the same flash image, three wrong PINs that
erase the board, and a recovery from the words. The release image is booted too: it starts, and refuses the test
hooks' message types.

Needs Espressif's QEMU (QEMU=...) and the test image (firmware built with --features test-hooks, merged and padded
to 4 MB with the partition table); the Python signer's virtualenv for the checks.

usage: signer/.venv/bin/python -I hardware/board-signer/tools/qemu_flows.py TEST_IMAGE [RELEASE_IMAGE] [OUT_DIR]
"""
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, os.path.join(ROOT, "signer"))
sys.path.insert(0, HERE)

from board_client import (TEST_BUTTONS, Board, BoardError, TcpLink, encode_tx)  # noqa: E402
from winterlock_signer import leansphincs, member, owner, phrase, safe as safemod, wots  # noqa: E402
from winterlock_signer.abi import b2h, checksum  # noqa: E402
from winterlock_signer.keccak import keccak256  # noqa: E402

QEMU = os.environ.get("QEMU", "qemu-system-xtensa")
PIN = [2, 0, 2, 6]
CHAIN = 11155111
SAFE = keccak256(b"qemu flows: Safe")[12:]
PARENT = keccak256(b"qemu flows: parent Safe")[12:]
BOB = keccak256(b"qemu flows: recipient")[12:]
GAS_LABEL = b"winterlock.app.gas.v1"


def key_line(*a):
    print("KEY", *a, flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Qemu:
    def __init__(self, image, out, name):
        self.port = free_port()
        self.serial = open(os.path.join(out, f"{name}.serial.log"), "ab")
        self.stderr = open(os.path.join(out, f"{name}.qemu.log"), "ab")
        self.proc = subprocess.Popen(
            [QEMU, "-nographic", "-machine", "esp32", "-drive", f"file={image},if=mtd,format=raw",
             "-serial", f"tcp:127.0.0.1:{self.port},server=on,wait=on", "-monitor", "none"],
            stdout=self.stderr, stderr=self.stderr)
        self.text = bytearray()
        self.board = Board(TcpLink("127.0.0.1", self.port), log=self._noise)

    def _noise(self, b):
        self.text += b
        self.serial.write(b)
        self.serial.flush()

    def wait_text(self, s, timeout=120):
        end = time.time() + timeout
        while s.encode() not in self.text:
            if time.time() > end:
                raise TimeoutError(f"no {s!r} on the serial port")
            self.board._pump(0.2)

    def kill(self):
        self.proc.kill()
        self.proc.wait()
        self.board.close()
        self.serial.close()
        self.stderr.close()


def pin_keys(digits):
    return "".join("R" * d + "B" for d in digits) + "LB"


def setup(q: Qemu, app_random: bytes):
    b = q.board
    rid = b.setup(app_random)
    words = []
    s = b.press("R")
    for _ in range(6):
        assert s[0].startswith("Your words"), s
        words += [line.split()[1] for line in s[1:5]]
        s = b.press("R")
    assert s[0] == "All written?", s
    s = b.press("B")
    for _ in range(3):
        pos = int(s[0].split()[1].rstrip("?"))
        choices = [line[2:] for line in s[1:5]]
        s = b.press("R" * choices.index(words[pos - 1]) + "B")
    assert s[0] == "Choose a PIN", s
    s = b.press("R" + pin_keys(PIN) + pin_keys(PIN))
    ident = b.parse_identity(b.wait(rid, 600))
    return words, ident, s


def recover(q: Qemu, words):
    b = q.board
    rid = b.recover()
    s = b.press("R")
    wl = phrase._M.wordlist
    for i, w in enumerate(words):
        assert s[0].startswith(f"Word {i + 1}"), s
        keys, typed = "", ""
        while True:
            cands = [x for x in wl if x.startswith(typed)]
            if len(cands) == 1 and typed:
                break
            letters = []
            for x in cands:
                if len(x) > len(typed) and x[len(typed)] not in letters:
                    letters.append(x[len(typed)])
            if typed == w:
                keys += "R" * len(letters) + "B"  # the prefix as a word
                break
            keys += "R" * letters.index(w[len(typed)]) + "B"
            typed += w[len(typed)]
        s = b.press(keys)
        assert s[-1].endswith("both: ok") and s[2] == w, (w, s)
        s = b.press("B")
    assert s[0] == "Choose a PIN", s
    s = b.press("R" + pin_keys(PIN) + pin_keys(PIN))
    return b.parse_identity(b.wait(rid, 600)), s


def confirm(b: Board, rid, first_screen_needed=True):
    """Steps through a request's pages and holds both on the last (and the second confirmation)."""
    s = b.screen()
    pages = [s]
    while not s[-1].endswith("hold both: sign") and not s[-1].endswith("hold both: enrol"):
        s = b.press("R")
        pages.append(s)
    s = b.press("B")
    if s[0] == "Not decoded":
        pages.append(s)
        s = b.press("B")
    return pages, s


def parse_tx_sig(data):
    slot, device, safe = data[0], data[1], data[2:22]
    words = [data[22 + 32 * i:54 + 32 * i] for i in range(10)]
    sig = data[342:342 + wots.SIG_BYTES]
    path = data[342 + wots.SIG_BYTES:]
    return slot, device, safe, words, sig, path


def check_signature(ident, tree, st: safemod.SafeTx, signed, ledger):
    """What the owner contract checks, in Python: the SafeTx words hash to the Safe's hash, and the WOTS signature
    and path lead to the enrolled root."""
    owner_addr = checksum(ident["owner"])
    safe_addr = checksum(SAFE)
    slot, device, safe, words, sig, path = parse_tx_sig(signed["data"])
    assert (device, safe) == (0, SAFE)
    assert words == st.words(), "the SafeTx words"
    h = st.hash(CHAIN, safe_addr)
    assert h == signed["hash"] == safemod.SafeTx.hash(st, CHAIN, safe_addr)
    k = owner.key_index(st.nonce, tree["start"], slot, tree["height"])
    assert k == signed["key_index"]
    tseed = owner.tree_seed(CHAIN, owner_addr, safe_addr, 0, 0, tree["start"])
    assert wots.verify_root(tseed, k, h, sig, path) == tree["root"], "the signature leads to the enrolled root"
    prior = ledger.setdefault((tree["root"], k), h)
    assert prior == h, f"one-time key {k} signed two hashes"
    return k


def main():
    test_image = sys.argv[1]
    release_image = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "-" else None
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(test_image), "qemu-run")
    os.makedirs(out, exist_ok=True)
    flash = os.path.join(out, "flash.bin")
    shutil.copyfile(test_image, flash)
    ledger = {}
    t0 = time.time()

    # --- setup ---
    q = Qemu(flash, out, "1-setup")
    st = q.board.wait_booted(120)
    key_line("booted:", st["version"], "state", st["state"], "test hooks", st["test_hooks"],
             f"storage {st['storage_used']}/{st['storage_size']}")
    words, ident, s = setup(q, os.urandom(32))
    seed = phrase.to_seed(" ".join(words))
    mk = member.stateless_key(seed).public_key
    assert ident["member_key"] == mk, "the member key is the Python signer's for these words"
    owner_addr = owner.owner_address(mk)
    assert checksum(ident["owner"]) == owner_addr
    key_line("setup: 24 words shown, 3 checked; member key", b2h(mk)[:18] + "...", "owner", owner_addr,
             "(Python signer agrees)")
    key_line("setup screen after:", s[0], "/", s[1].strip())
    s = q.board.press("RR")
    assert s[0] == "Winterlock", s
    gas = q.board.gas_key()
    assert gas == member._abi_label(GAS_LABEL, seed)
    key_line("gas key: matches the Python signer's for the seed")
    mem = q.board.memory()
    key_line("memory after setup:", mem)
    q.kill()

    # --- a restart: locked; unlock; enrol; sign ---
    q = Qemu(flash, out, "2-sign")
    st = q.board.wait_booted(120)
    assert st["state"] == "locked", st
    key_line("restart: state", st["state"], "owner", checksum(st["owner"]))
    try:
        q.board.gas_key()
        raise AssertionError("a locked board answered")
    except BoardError as err:
        key_line("a request while locked:", err)
    s = q.board.press(pin_keys(PIN))
    assert s[0] == "Winterlock", s
    rid = q.board.enrol(CHAIN, SAFE, 0)
    t = time.time()
    pages, s = confirm(q.board, rid)
    e = q.board.parse_enrolled(q.board.wait(rid, 900))
    digest = owner.certificate_digest(CHAIN, owner_addr, checksum(SAFE), 0, 0, e["root"], e["height"], e["start"])
    assert leansphincs.verify(mk, digest, e["signature"]), "the certificate verifies in Python"
    key_line(f"enrol: tree root {b2h(e['root'])}, height {e['height']}, start {e['start']}; certificate "
             f"({len(e['signature'])} bytes) verifies in Python; {time.time() - t:.1f} s in QEMU, pages included")
    q.board.press("R")
    tree = {"root": e["root"], "start": e["start"], "height": e["height"]}

    # an ETH transfer
    eth = safemod.SafeTx(to=checksum(BOB), value=15 * 10**16, nonce=0)
    rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=eth.value, nonce=0))
    pages, s = confirm(q.board, rid)
    sg = q.board.parse_signed(q.board.wait(rid, 120))
    k = check_signature(ident, tree, eth, sg, ledger)
    key_line(f"ETH transfer: pages {[p[0] for p in pages]}; '{pages[0][2].strip()}'; key {k} slot {sg['slot']}; "
             "verifies to the root in Python")
    q.board.press("R")

    # approveHash on a parent Safe, with the parent's fields
    parent = safemod.SafeTx(to=checksum(BOB), value=2 * 10**18, nonce=5)
    ph = parent.hash(CHAIN, checksum(PARENT))
    approve = safemod.SafeTx(to=checksum(PARENT), data=bytes.fromhex("d4d9bdcd") + ph, nonce=1)
    rid = q.board.sign(CHAIN, SAFE, encode_tx(PARENT, data=approve.data, nonce=1),
                       parent=encode_tx(BOB, value=parent.value, nonce=5))
    pages, s = confirm(q.board, rid)
    sg = q.board.parse_signed(q.board.wait(rid, 120))
    k = check_signature(ident, tree, approve, sg, ledger)
    key_line(f"approveHash: pages {[p[0] for p in pages]}; parent page '{pages[1][0]}: {pages[1][2].strip()}'; "
             f"key {k}; verifies")
    q.board.press("R")

    # a call that isn't decoded: a second confirmation
    raw = safemod.SafeTx(to=checksum(PARENT), value=7, data=bytes.fromhex("095ea7b3") + bytes(64), nonce=2)
    rid = q.board.sign(CHAIN, SAFE, encode_tx(PARENT, value=7, data=raw.data, nonce=2))
    pages, s = confirm(q.board, rid)
    sg = q.board.parse_signed(q.board.wait(rid, 120))
    k = check_signature(ident, tree, raw, sg, ledger)
    key_line(f"not decoded: pages {[p[0] for p in pages]}; '{pages[0][2].strip()}'; second confirmation "
             f"'{pages[-1][0]}'; key {k}; verifies")
    q.board.press("R")

    # a delegate call: refused
    rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, operation=1, nonce=3))
    try:
        q.board.wait(rid, 60)
        raise AssertionError("a delegate call was signed")
    except BoardError as err:
        key_line("delegate call:", err, "| screen:", " / ".join(x.strip() for x in q.board.screen()[:3]))
    q.board.press("R")

    # --- QEMU killed in the middle of a key log write ---
    def killed_sign(q, st_tx, enc, after_writes, name):
        q.board.stall(after_writes)
        rid = q.board.sign(CHAIN, SAFE, enc)
        s = q.board.screen()
        while not s[-1].endswith("hold both: sign"):
            s = q.board.press("R")
        q.board.send(TEST_BUTTONS, bytes([3]))  # both: the firmware records, and stops mid-way
        q.wait_text("STALLED", 60)
        answered = any(f.id == rid for f in q.board.frames)
        q.kill()
        key_line(f"{name}: firmware stopped after flash write {after_writes} of the key use record; QEMU killed; "
                 f"signature sent before the kill: {answered}")
        return answered

    used_before = None
    for after, name in ((1, "kill after the record's header"), (2, "kill after the whole record")):
        nonce = 3 + after
        txk = safemod.SafeTx(to=checksum(BOB), value=100 + after, nonce=nonce)
        q2 = q
        trees = q2.board.trees()
        used_before = trees[0]["used"]
        answered = killed_sign(q2, txk, encode_tx(BOB, value=txk.value, nonce=nonce), after, name)
        assert not answered
        q = Qemu(flash, out, f"3-after-kill-{after}")
        st = q.board.wait_booted(120)
        q.board.press(pin_keys(PIN))
        used_after = q.board.trees()[0]["used"]
        survived = used_after == used_before + 1
        key_line(f"  restarted from the same flash: state {st['state']}, keys used {used_before} -> {used_after}: "
                 f"the record {'survived' if survived else 'was torn and skipped'}")
        assert survived == (after == 2), "a whole record survives, a header alone doesn't"
        # the same transaction again: the key the record names, or the first free one
        rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=txk.value, nonce=nonce))
        confirm(q.board, rid)
        sg = q.board.parse_signed(q.board.wait(rid, 120))
        k = check_signature(ident, tree, txk, sg, ledger)
        q.board.press("R")
        # another transaction at the same nonce: the other key
        tx2 = safemod.SafeTx(to=checksum(BOB), value=999, nonce=nonce)
        rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=999, nonce=nonce))
        confirm(q.board, rid)
        sg2 = q.board.parse_signed(q.board.wait(rid, 120))
        k2 = check_signature(ident, tree, tx2, sg2, ledger)
        q.board.press("R")
        key_line(f"  then the same tx signs with key {k} (slot {sg['slot']}), another tx at nonce {nonce} with key "
                 f"{k2} (slot {sg2['slot']}): no key signed two hashes")
        assert k != k2
    mem = q.board.memory()
    key_line("memory after enrol and signing:", mem)
    q.kill()

    # --- three wrong PINs erase the board ---
    q = Qemu(flash, out, "4-wrong-pins")
    q.board.wait_booted(120)
    for i in range(3):
        s = q.board.press(pin_keys([9, 9, 9, 9]))
        key_line(f"wrong PIN {i + 1}:", s[0], "/", " ".join(x.strip() for x in s[1:4]))
        if i < 2:
            q.board.press("R")
    st = q.board.status()
    assert st["state"] == "blank", st
    q.kill()
    image = open(flash, "rb").read()
    assert seed not in image and e["root"] not in image, "the seed and the key log are gone from the flash"
    key_line("after 3 wrong PINs: state blank; the seed and the tree's root are no longer in the flash image")

    # --- recovery ---
    q = Qemu(flash, out, "5-recover")
    q.board.wait_booted(120)
    rident, s = recover(q, words)
    assert rident["member_key"] == mk and rident["owner"] == ident["owner"] and rident["recovered"]
    key_line("recovery: 24 words typed letter by letter; same member key and owner", owner_addr, "| screen:", s[0])
    s = q.board.press("R")
    key_line("  then:", s[0], "/", " ".join(x.strip() for x in s[1:5]))
    q.board.press("R")
    try:
        q.board.wait(q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=1, nonce=9)), 60)
        raise AssertionError("a recovered board signed without a tree")
    except BoardError as err:
        key_line("  signing before enrolling:", err)
    q.board.press("R")
    rid = q.board.enrol(CHAIN, SAFE, 9)
    confirm(q.board, rid)
    e2 = q.board.parse_enrolled(q.board.wait(rid, 900))
    d2 = owner.certificate_digest(CHAIN, owner_addr, checksum(SAFE), 0, 0, e2["root"], 10, 9)
    assert leansphincs.verify(mk, d2, e2["signature"])
    q.board.press("R")
    t9 = safemod.SafeTx(to=checksum(BOB), value=1, nonce=9)
    rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=1, nonce=9))
    confirm(q.board, rid)
    sg = q.board.parse_signed(q.board.wait(rid, 120))
    k = check_signature(ident, {"root": e2["root"], "start": 9, "height": 10}, t9, sg, ledger)
    key_line(f"  enrolled a new tree from nonce 9 (certificate verifies), then signed nonce 9 with key {k}")
    mem = q.board.memory()
    key_line("memory at the end:", mem)
    st = q.board.status()
    key_line(f"storage used: {st['storage_used']} of {st['storage_size']} bytes")
    q.kill()

    # --- the release image ---
    if release_image:
        rflash = os.path.join(out, "release-flash.bin")
        shutil.copyfile(release_image, rflash)
        q = Qemu(rflash, out, "6-release")
        st = q.board.wait_booted(120)
        try:
            q.board.press("B")
            raise AssertionError("the release image took a simulated button")
        except BoardError as err:
            key_line(f"release image: booted, version '{st['version']}', test hooks {st['test_hooks']}; "
                     f"a simulated button: {err}")
        st = q.board.status()
        text = bytes(q.text)
        q.kill()
        mark = b"Loaded app from partition at offset 0x10000"
        assert mark in text, "the bootloader's last line"
        after = text.split(mark, 1)[1].split(b"\n", 1)[1]
        assert after == b"", after[:200]
        key_line(f"release image: state {st['state']}; bytes on the serial port outside frames after the "
                 f"bootloader's last line: {len(after)}")
    key_line(f"all QEMU flows passed in {time.time() - t0:.0f} s")


if __name__ == "__main__":
    main()
