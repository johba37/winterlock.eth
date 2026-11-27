#!/usr/bin/env python3
"""A firmware update in QEMU: a board set up, enrolled and used with one firmware image keeps its seed, PIN, key
tree and key log when a newer image is written over the bootloader and the app, as `espflash write-bin 0x0` does
(the `signer` partition, from 0x110000, isn't touched). After the update the board is locked, unlocks with the same
PIN, reports the new version, holds the same tree with the same count of used keys, signs the transaction it signed
before with the same key and signature, and signs a new one.

With --other-keys, the newer image makes other keys from the same seed (0.1.3, whose key types start with
winterlock.eth/, over 0.1.2 or older): after the PIN it shows "Older firmware", reports damaged storage, erases when
asked, and the same 24 words recover it with the member key and owner that erc8499.py gives the seed; it then enrols a
tree and signs.

Both images are test images (built with --features test-hooks, merged and padded to 4 MB).

usage: signer/.venv/bin/python -I hardware/board-signer/tools/qemu_update.py OLD_TEST_IMAGE NEW_TEST_IMAGE [OUT_DIR]
       [--other-keys]
"""
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from qemu_flows import (BOB, CHAIN, PIN, SAFE, Qemu, check_signature, confirm, key_line, pin_keys,  # noqa: E402
                        recover, setup)
from board_client import encode_tx  # noqa: E402
from winterlock_signer import erc8499, phrase  # noqa: E402
from winterlock_signer import safe as safemod  # noqa: E402
from winterlock_signer.abi import b2h, checksum  # noqa: E402

# the `signer` partition's offset (firmware/partitions.csv): an update writes below it
SIGNER = 0x110000


def main():
    args = [a for a in sys.argv[1:] if a != "--other-keys"]
    other_keys = len(args) < len(sys.argv) - 1
    old_image, new_image = args[0], args[1]
    out = args[2] if len(args) > 2 else os.path.join(os.path.dirname(new_image), "qemu-update")
    os.makedirs(out, exist_ok=True)
    flash = os.path.join(out, "flash.bin")
    shutil.copyfile(old_image, flash)
    ledger = {}
    t0 = time.time()

    # --- the old firmware: set up, enrol, sign ---
    q = Qemu(flash, out, "1-old")
    st = q.board.wait_booted(120)
    old_version = st["version"]
    words, ident, s = setup(q, os.urandom(32))
    q.board.press("RR")
    rid = q.board.enrol(CHAIN, SAFE, 0)
    confirm(q.board, rid)
    e = q.board.parse_enrolled(q.board.wait(rid, 900))
    q.board.press("R")
    tree = {"root": e["root"], "start": e["start"], "height": e["height"]}
    eth = safemod.SafeTx(to=checksum(BOB), value=15 * 10**16, nonce=0)
    rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=eth.value, nonce=0))
    confirm(q.board, rid)
    before = q.board.parse_signed(q.board.wait(rid, 120))
    k = check_signature(ident, tree, eth, before, ledger)
    q.board.press("R")
    trees_before = q.board.trees()
    key_line(f"old firmware {old_version!r}: set up (owner {checksum(ident['owner'])}), a tree enrolled (root "
             f"{b2h(e['root'])}), one transfer signed with key {k}; keys used {trees_before[0]['used']}")
    q.kill()

    # --- the update: the new image over everything below the signer partition ---
    with open(flash, "rb") as f:
        signer_before = f.read()[SIGNER:]
    with open(new_image, "rb") as f:
        new = f.read()[:SIGNER]
    with open(flash, "r+b") as f:
        f.write(new)
    with open(flash, "rb") as f:
        assert f.read()[SIGNER:] == signer_before
    key_line(f"update: {len(new)} bytes written at 0x0; the signer partition ({len(signer_before)} bytes) untouched")

    # --- the new firmware on the old storage ---
    q = Qemu(flash, out, "2-new")
    st = q.board.wait_booted(120)
    assert st["state"] == "locked", st
    assert st["version"] != old_version, "the new image reports the old version"
    assert st["owner"] == ident["owner"], "the same owner"
    s = q.board.press(pin_keys(PIN))
    if other_keys:
        other(q, s, words, ident, ledger, st["version"], t0)
        return
    assert s[0] == "Winterlock", s
    trees_after = q.board.trees()
    assert trees_after == trees_before, (trees_before, trees_after)
    key_line(f"new firmware {st['version']!r}: locked, unlocked with the same PIN; the same owner, tree and count of "
             f"used keys ({trees_after[0]['used']})")
    # the transaction signed before: the same key and signature, no new key used
    rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=eth.value, nonce=0))
    confirm(q.board, rid)
    again = q.board.parse_signed(q.board.wait(rid, 120))
    assert (again["slot"], again["data"]) == (before["slot"], before["data"]), "the key log's record is kept"
    q.board.press("R")
    assert q.board.trees()[0]["used"] == trees_before[0]["used"]
    # a new transaction signs with the next key
    tx2 = safemod.SafeTx(to=checksum(BOB), value=1, nonce=1)
    rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=1, nonce=1))
    confirm(q.board, rid)
    sg = q.board.parse_signed(q.board.wait(rid, 120))
    k2 = check_signature(ident, tree, tx2, sg, ledger)
    q.board.press("R")
    key_line(f"  the earlier transfer signs again with the same key and signature (no key used); a new one with key "
             f"{k2}; verifies")
    q.kill()
    key_line(f"the update kept the board's storage; {time.time() - t0:.0f} s")


def other(q, s, words, ident, ledger, version, t0):
    """The newer firmware makes other keys from the seed: it says so, erases when asked, and the words recover it."""
    assert s[0] == "Older firmware", s
    assert s[1:5] == ["Made by firmware", "before 0.1.3, with", "other keys.", "It signs nothing."], s
    assert q.board.status()["state"] == "damaged"
    key_line(f"new firmware {version!r}: unlocked with the same PIN, then {s[0]!r}: {' '.join(s[1:5])}; "
             f"the app sees damaged storage")
    s = q.board.press("R")
    assert s[0] == "Older firmware", s
    s = q.board.press("B")
    assert s[0] == "Erase board?", s
    s = q.board.press("B")
    assert s[0] == "Erased", s
    s = q.board.press("R")
    assert q.board.status()["state"] == "blank"
    seed = phrase.to_seed(" ".join(words))
    mk, owner_addr = erc8499.identity_of(seed)
    rident, s = recover(q, words)
    assert rident["member_key"] == mk and checksum(rident["owner"]) == owner_addr and rident["recovered"], rident
    assert rident["member_key"] != ident["member_key"] and rident["owner"] != ident["owner"]
    key_line(f"  erased on the board; the same 24 words recovered it: member key {b2h(mk)}, owner {owner_addr} "
             f"(erc8499.py's for the seed; was {checksum(ident['owner'])})")
    q.board.press("RR")
    rid = q.board.enrol(CHAIN, SAFE, 0)
    confirm(q.board, rid)
    e = q.board.parse_enrolled(q.board.wait(rid, 900))
    q.board.press("R")
    tree = {"root": e["root"], "start": e["start"], "height": e["height"]}
    tx = safemod.SafeTx(to=checksum(BOB), value=1, nonce=0)
    rid = q.board.sign(CHAIN, SAFE, encode_tx(BOB, value=1, nonce=0))
    confirm(q.board, rid)
    sg = q.board.parse_signed(q.board.wait(rid, 120))
    k = check_signature(rident, tree, tx, sg, ledger)
    q.board.press("R")
    q.kill()
    key_line(f"  a new tree enrolled, a transfer signed with key {k}; verifies. {time.time() - t0:.0f} s")


if __name__ == "__main__":
    main()
