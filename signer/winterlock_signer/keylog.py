"""The key log: an append-only record of every one-time key the signer has used and every tree it has made.

One JSON object per line, each with a checksum. A record is written, flushed and fsynced (file and directory) before
the signature it covers leaves the signer, so a crash can lose a signature but never the record of one. A torn last
line (a crash during the write) is cut off when the log is opened: its signature was never released.

Records (field "t"):
  init / restore  the signer's identity (owner, KEY); restore marks a device set up again from the seed alone
  tree            an operation tree: chain, safe, root, height, start, and the random salt its secrets derive from.
                  The salt exists only here, so a signer that lost its log can't rebuild, and so can't reuse, an old
                  tree: it must certify a fresh one (D11, D12).
  cert            the stateless key certified a tree (enrolment)
  sign            a one-time key signed: chain, safe, tree root, nonce, slot, key index, and the SafeTx hash
Rules enforced here: a key signs one hash only (signing the same hash again is allowed: signatures are
deterministic); slots are picked by the signer, never the user: slot 0 first, slot 1 for a second, different SafeTx
at the same nonce (D4), and nothing after that.
"""

import fcntl
import json
import os
import time

from .keccak import keccak256


class Refused(Exception):
    """The signer won't sign: the message says why"""


class LogCorrupt(Exception):
    pass


def _chk(rec: dict) -> str:
    body = json.dumps({k: v for k, v in rec.items() if k != "chk"}, sort_keys=True, separators=(",", ":"))
    return keccak256(body.encode()).hex()[:16]


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class KeyLog:
    def __init__(self, path: str, lock=True):
        self.path = path
        self.records = []
        self.warnings = []
        new = not os.path.exists(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        self._f = os.fdopen(fd, "r+b", buffering=0)
        self.locked = lock
        if lock:
            try:
                fcntl.flock(self._f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self._f.close()
                raise Refused("another signer process holds the key log; wait for it to finish") from None
        if new:
            _fsync_dir(os.path.dirname(os.path.abspath(path)))
        self._load()

    def close(self):
        if self._f:
            self._f.close()
            self._f = None

    def _load(self):
        self._f.seek(0)
        raw = self._f.read()
        if raw and not raw.endswith(b"\n"):
            cut = raw.rfind(b"\n") + 1
            self.warnings.append(f"key log: a torn last record ({len(raw) - cut} bytes) left by an interrupted "
                                 "write; its signature was never released" + (", cut off" if self.locked else ""))
            if self.locked:
                os.ftruncate(self._f.fileno(), cut)
                os.fsync(self._f.fileno())
            raw = raw[:cut]
        for n, line in enumerate(raw.split(b"\n")[:-1], 1):
            try:
                rec = json.loads(line)
            except ValueError:
                raise LogCorrupt(f"key log line {n} is not JSON: refusing to sign until it is repaired") from None
            if rec.get("chk") != _chk(rec):
                raise LogCorrupt(f"key log line {n} fails its checksum: refusing to sign until it is repaired")
            self.records.append(rec)

    def append(self, rec: dict) -> dict:
        if not self.locked:
            raise Refused("the key log is open read-only")
        rec = dict(rec)
        rec.setdefault("at", _now())
        rec["chk"] = _chk(rec)
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        view = memoryview(line)
        while view:
            view = view[self._f.write(view):]
        os.fsync(self._f.fileno())
        self.records.append(rec)
        return rec

    # --- queries ---

    def identity(self):
        for r in self.records:
            if r["t"] in ("init", "restore"):
                return r
        return None

    def trees(self, chain: int, safe: str) -> list:
        return [r for r in self.records if r["t"] == "tree" and r["chain"] == chain
                and r["safe"].lower() == safe.lower()]

    def all_trees(self) -> list:
        return [r for r in self.records if r["t"] == "tree"]

    def tree_by_root(self, chain: int, safe: str, root_hex: str):
        for r in self.trees(chain, safe):
            if r["root"] == root_hex:
                return r
        return None

    def signs(self, chain=None, safe=None, root=None) -> list:
        return [r for r in self.records if r["t"] == "sign" and (chain is None or r["chain"] == chain)
                and (safe is None or r["safe"].lower() == safe.lower()) and (root is None or r["root"] == root)]

    def certs(self) -> list:
        return [r for r in self.records if r["t"] == "cert"]

    def used(self, chain: int, safe: str, root: str, key: int):
        for r in self.signs(chain, safe, root):
            if r["key"] == key:
                return r
        return None

    def pick_slot(self, chain: int, safe: str, tree: dict, nonce: int, hash_hex: str):
        """(slot, already_signed) for signing `hash_hex` at `nonce` with `tree`, or Refused"""
        from .owner import SLOTS, key_index
        by_slot = {}
        for slot in range(SLOTS):
            k = key_index(nonce, tree["start"], slot, tree["height"])
            r = self.used(chain, safe, tree["root"], k)
            if r:
                if r["hash"] == hash_hex:
                    return slot, True
                by_slot[slot] = r["hash"]
        for slot in range(SLOTS):
            if slot not in by_slot:
                return slot, False
        raise Refused(f"both keys for nonce {nonce} are used (slot 0 signed {by_slot[0]}, slot 1 signed "
                      f"{by_slot[1]}): this member can't sign a third version at nonce {nonce}")

    def record_sign(self, chain: int, safe: str, tree: dict, nonce: int, slot: int, hash_hex: str) -> dict:
        """Checks the key and records its use, fsynced, before the caller computes or releases the signature"""
        from .owner import key_index
        k = key_index(nonce, tree["start"], slot, tree["height"])
        prior = self.used(chain, safe, tree["root"], k)
        if prior:
            if prior["hash"] != hash_hex:
                raise Refused(f"key {k} (nonce {nonce}, slot {slot}) already signed {prior['hash']}; signing "
                              f"{hash_hex} with it would reuse a one-time key")
            return prior
        return self.append({"t": "sign", "chain": chain, "safe": safe, "root": tree["root"], "start": tree["start"],
                            "nonce": nonce, "slot": slot, "key": k, "hash": hash_hex})


def _fsync_dir(d: str):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
