"""Which device a key log belongs to, and whether this copy of the log is the one that device has been writing.

A key log is safe only while one copy of it signs, and only if that copy holds every signature it ever made. A
restored backup, a copied signer directory or a rolled-back disk breaks both, silently. Two offline checks catch the
common cases:

  binding  The key log's latest `device` record names a random device id. An anchor file outside the signer's
           directory records, for that id, this machine (a hash of its machine id) and the key log's inode. A signer
           directory copied elsewhere, or restored from a backup, has another inode or machine, or no anchor at all.
  counter  The anchor also holds the key log's record count and its last record's checksum, updated after every
           write. A key log shorter than its anchor, or with another record at that position, was rolled back: it
           lacks records the device wrote, maybe signatures.

Anchors live in WINTERLOCK_ANCHOR_DIR, by default $XDG_STATE_HOME/winterlock-signer/anchors (~/.local/state/...).

Not caught: a rollback of the whole machine, anchors included (a VM snapshot, a full-disk image); and anything done on
purpose, since the anchor is an ordinary file. The online check (a signature at Safe's Transaction Service that the
key log doesn't know) is the second line. A home on a file system without stable inode numbers (FAT, some network
file systems) can look copied; `device adopt` rebinds it.
"""

import json
import os
import platform
import secrets
import subprocess

from .keccak import keccak256


def new_id() -> str:
    return secrets.token_hex(8)


def anchor_dir() -> str:
    d = os.environ.get("WINTERLOCK_ANCHOR_DIR")
    if d:
        return d
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(state, "winterlock-signer", "anchors")


_machine = None


def machine() -> str:
    """A hash of this machine's id (Linux machine-id, macOS platform UUID), or of its host name as a last resort"""
    global _machine
    if _machine is None:
        raw = None
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(p) as f:
                    raw = f.read().strip() or None
            except OSError:
                pass
            if raw:
                break
        if not raw and platform.system() == "Darwin":
            try:
                out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True,
                                     text=True, timeout=5).stdout
                raw = next((ln.split('"')[-2] for ln in out.splitlines() if "IOPlatformUUID" in ln), None)
            except (OSError, subprocess.SubprocessError, IndexError):
                pass
        raw = raw or ("host:" + platform.node())
        _machine = keccak256(b"winterlock.signer.machine.v1:" + raw.encode()).hex()[:16]
    return _machine


def _path(name: str) -> str:
    return os.path.join(anchor_dir(), f"{name}.json")


def load(name: str):
    try:
        with open(_path(name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _save(name: str, doc: dict):
    d = anchor_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = _path(name) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, _path(name))


def bind(name: str, file_path: str, count: int = 0, last: str = None):
    """Anchors `name` (a device id) to this machine and to the file at file_path, as it is now"""
    _save(name, {"machine": machine(), "inode": os.stat(file_path).st_ino, "count": count, "last": last,
                 "file": os.path.abspath(file_path)})


def advance(name: str, count: int, last: str):
    """After a write: the key log now has `count` records, the last with checksum `last`"""
    doc = load(name)
    if doc is None:
        return
    doc["count"], doc["last"] = count, last
    _save(name, doc)


def forget(name: str):
    try:
        os.remove(_path(name))
    except OSError:
        pass


ROLLBACK = "rollback"


def check(name: str, file_path: str, records: list = None) -> list:
    """Problems with this copy, as (kind, explanation); empty if it is the anchored one. `records`: the key log's
    records, for the counter check (each with its checksum "chk")"""
    a = load(name)
    if a is None:
        return [("no-anchor", "this machine has no anchor for this signer's device id: the signer directory was "
                              "copied or restored here, or the anchor directory was removed")]
    problems = []
    if a.get("machine") != machine():
        problems.append(("machine", "the anchor was written on another machine: the signer directory and its anchor "
                                    "were copied here"))
    try:
        ino = os.stat(file_path).st_ino
    except OSError:
        ino = None
    if a.get("inode") != ino:
        problems.append(("inode", "the key log is another file than the one this device has been writing: a copy, "
                                  "or a restore from a backup"))
    if records is not None and a.get("count"):
        n = a["count"]
        if n > len(records) or records[n - 1].get("chk") != a.get("last"):
            problems.append((ROLLBACK, f"the key log was rolled back: this device wrote {n} records, and this copy "
                                       f"has {len(records)}" + ("" if n > len(records) else
                                                                 f", with another record at {n}")
                             + ". It may be missing signatures it made."))
    return problems
