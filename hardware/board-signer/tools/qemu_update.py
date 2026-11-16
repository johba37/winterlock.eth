#!/usr/bin/env python3
"""A firmware update in QEMU: a board set up, enrolled and used with one firmware image keeps its seed, PIN, key
tree and key log when a newer image is written over the bootloader and the app, as `espflash write-bin 0x0` does
(the `signer` partition, from 0x110000, isn't touched). After the update the board is locked, unlocks with the same
PIN, reports the new version, holds the same tree with the same count of used keys, signs the transaction it signed
before with the same key and signature, and signs a new one.

Both images are test images (built with --features test-hooks, merged and padded to 4 MB).

usage: signer/.venv/bin/python -I hardware/board-signer/tools/qemu_update.py OLD_TEST_IMAGE NEW_TEST_IMAGE [OUT_DIR]
"""
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from qemu_flows import (BOB, CHAIN, PIN, SAFE, Qemu, check_signature, confirm, key_line, pin_keys,  # noqa: E402
                        setup)
from board_client import encode_tx  # noqa: E402
from winterlock_signer import safe as safemod  # noqa: E402
from winterlock_signer.abi import b2h, checksum  # noqa: E402

# the `signer` partition's offset (firmware/partitions.csv): an update writes below it
SIGNER = 0x110000


def main():
    old_image, new_image = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(new_image), "qemu-update")
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


if __name__ == "__main__":
    main()
