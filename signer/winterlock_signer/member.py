"""A member's signer state: the secret seed, the key log, and everything derived from them.

Home directory (default ~/.winterlock-signer, or WINTERLOCK_HOME), mode 700:
  seed         32 random bytes, hex, mode 600: the only secret, and the only backup a member needs
  keylog.jsonl the key log (keylog.py), mode 600
  cache/       public values only, rebuilt when missing: the stateless key's kept leaves, operation tree leaves

Derivations (keccak256 of abi.encode(label, ...)):
  stateless seed   ("winterlock.signer.stateless.v1", seed) -> leanSphincs key, kept subtree of height 10.
                   Deterministic: a restored signer has the same KEY and the same owner address.
  tree secret seed ("winterlock.signer.ops.v1", seed, chain, owner, safe, start, salt), salt = 32 random bytes
                   recorded only in the key log. A lost log can't bring an old tree back; two restores never make
                   the same tree.
  WOTS secrets     wots.Prf.SIGNER over the tree secret seed
"""

import os
import secrets

from . import leansphincs, owner, wots
from .abi import b2h, h2b, read_file, word
from .keccak import keccak256
from .keylog import KeyLog, Refused, _fsync_dir

STATELESS_B = leansphincs.DEFAULT_B
DEFAULT_HEIGHT = 10


def default_home() -> str:
    return os.environ.get("WINTERLOCK_HOME") or os.path.expanduser("~/.winterlock-signer")


def _abi_label(label: bytes, *words) -> bytes:
    head = word(32 * (len(words) + 1)) + b"".join(word(w) for w in words)
    return keccak256(head + word(len(label)) + label + bytes((-len(label)) % 32))


def _write_secret(path: str, text: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


class Member:
    def __init__(self, home: str = None, lock=True):
        self.home = home or default_home()
        seed_path = os.path.join(self.home, "seed")
        if not os.path.exists(seed_path):
            raise Refused(f"no signer at {self.home}: run `init` first")
        st = os.stat(seed_path)
        if st.st_mode & 0o077:
            raise Refused(f"{seed_path} is readable by others (mode {oct(st.st_mode & 0o777)}): chmod 600 it")
        self._seed = h2b(read_file(seed_path).strip())
        if len(self._seed) != 32:
            raise Refused("seed file must hold 32 bytes of hex")
        self.log = KeyLog(os.path.join(self.home, "keylog.jsonl"), lock=lock)
        self._sk = None
        ident = self.log.identity()
        self.key = h2b(ident["key"]) if ident else self.stateless().public_key
        self.owner = owner.owner_address(self.key)
        if ident and ident["owner"] != self.owner:
            raise Refused(f"the owner address changed since init ({ident['owner']} -> {self.owner}): the pinned "
                          "owner contracts (implementation, factory or verifier) differ from the ones this signer was "
                          "set up with")

    # --- set-up ---

    @staticmethod
    def init(home: str = None, restore_seed: bytes = None):
        home = home or default_home()
        os.makedirs(home, mode=0o700, exist_ok=True)
        os.chmod(home, 0o700)
        if os.path.exists(os.path.join(home, "seed")):
            raise Refused(f"{home} already has a seed; refusing to overwrite it")
        if os.path.exists(os.path.join(home, "keylog.jsonl")):
            raise Refused(f"{home} has a key log but no seed; move it away first")
        seed = restore_seed if restore_seed is not None else secrets.token_bytes(32)
        if len(seed) != 32:
            raise Refused("a seed is 32 bytes")
        _write_secret(os.path.join(home, "seed"), seed.hex() + "\n")
        _fsync_dir(home)
        m = Member(home)
        m.log.append({"t": "restore" if restore_seed is not None else "init", "owner": m.owner,
                      "key": b2h(m.key), "params": "D6", "stateless_b": STATELESS_B,
                      "owner_code": owner.PINNED_COMMIT})
        return m

    def close(self):
        self.log.close()

    # --- stateless key ---

    def stateless(self) -> leansphincs.Key:
        if self._sk is None:
            seed = _abi_label(b"winterlock.signer.stateless.v1", self._seed)
            cache = os.path.join(self.home, "cache", f"stateless-b{STATELESS_B}.bin")
            kept = None
            if os.path.exists(cache):
                raw = read_file(cache, "rb")
                if len(raw) == 16 << STATELESS_B:
                    kept = [raw[16 * i: 16 * i + 16] for i in range(1 << STATELESS_B)]
            sk = leansphincs.Key(seed, STATELESS_B, kept_leaves=kept)
            ident = self.log.identity() if hasattr(self, "log") else None
            if kept is not None and ident and sk.public_key != h2b(ident["key"]):
                sk = leansphincs.Key(seed, STATELESS_B)  # stale cache
                kept = None
            if kept is None:
                os.makedirs(os.path.dirname(cache), mode=0o700, exist_ok=True)
                with open(cache, "wb") as f:
                    f.write(sk.kept_leaves_bytes())
            self._sk = sk
        return self._sk

    def stateless_sign(self, digest: bytes) -> bytes:
        sig = self.stateless().sign(digest)
        if not leansphincs.verify(self.key, digest, sig):
            raise RuntimeError("stateless signature failed its own verification: not released")
        return sig

    # --- operation trees ---

    def _tree_sk_seed(self, rec: dict) -> bytes:
        return _abi_label(b"winterlock.signer.ops.v1", self._seed, rec["chain"], rec["owner"], rec["safe"],
                          rec["start"], h2b(rec["salt"]))

    def active_tree(self, chain: int, safe: str):
        trees = self.log.trees(chain, safe)
        return trees[-1] if trees else None

    def new_tree(self, chain: int, safe: str, start: int, height: int = DEFAULT_HEIGHT) -> dict:
        """Generates a fresh tree (fresh random salt) and records it, fsynced, before it is certified"""
        if not 1 <= height <= owner.MAX_HEIGHT or not 0 <= start <= owner.MAX_START:
            raise Refused("bad tree height or start")
        if height > 20:
            raise Refused("trees above height 20 take too long to generate here")
        prior = self.log.trees(chain, safe)
        if prior and start <= max(t["start"] for t in prior):
            raise Refused(f"a new tree must start after nonce {max(t['start'] for t in prior)}")
        rec = {"t": "tree", "chain": chain, "safe": safe, "owner": self.owner, "start": start, "height": height,
               "salt": b2h(secrets.token_bytes(32))}
        seed = owner.tree_seed(chain, self.owner, safe, start)
        tree = wots.Tree.create(seed, self._tree_sk_seed(rec), height)
        rec["root"] = b2h(tree.root)
        self.log.append(rec)
        self._save_tree(rec, tree)
        return rec

    def _tree_cache(self, rec) -> str:
        return os.path.join(self.home, "cache", f"tree-{rec['chain']}-{rec['safe'].lower()}-{rec['root'][2:18]}.bin")

    def _save_tree(self, rec, tree):
        os.makedirs(os.path.join(self.home, "cache"), mode=0o700, exist_ok=True)
        with open(self._tree_cache(rec), "wb") as f:
            f.write(tree.to_bytes())

    def tree(self, rec: dict) -> wots.Tree:
        seed = owner.tree_seed(rec["chain"], rec["owner"], rec["safe"], rec["start"])
        path = self._tree_cache(rec)
        if os.path.exists(path):
            try:
                t = wots.Tree.from_bytes(read_file(path, "rb"))
                if t.root == h2b(rec["root"]) and t.seed == seed and t.height == rec["height"]:
                    return t
            except ValueError:
                pass
        t = wots.Tree.create(seed, self._tree_sk_seed(rec), rec["height"])
        if b2h(t.root) != rec["root"]:
            raise Refused("the tree rebuilt from the seed and the key log has another root: wrong seed?")
        self._save_tree(rec, t)
        return t

    def certificate(self, rec: dict) -> bytes:
        """The stateless key's signature of the tree's certificate digest; recorded before it is released"""
        digest = owner.certificate_digest(rec["chain"], rec["owner"], rec["safe"], h2b(rec["root"]), rec["height"],
                                          rec["start"])
        self.log.append({"t": "cert", "chain": rec["chain"], "safe": rec["safe"], "root": rec["root"],
                         "digest": b2h(digest)})
        return self.stateless_sign(digest)

    # --- transactions ---

    def sign_safe_tx(self, chain: int, safe: str, rec: dict, safe_tx, slot: int = None):
        """WinterlockOwner transaction signature data for `safe_tx` with tree `rec`. The slot is picked from the key
        log unless given; the key's use is recorded and fsynced before the signature is computed or released.
        Returns (data, slot, key index, SafeTx hash)."""
        h = safe_tx.hash(chain, safe)
        hx = b2h(h)
        nonce = safe_tx.nonce
        if slot is None:
            slot, _ = self.log.pick_slot(chain, safe, rec, nonce, hx)
        k = owner.key_index(nonce, rec["start"], slot, rec["height"])
        self.log.record_sign(chain, safe, rec, nonce, slot, hx)
        tree = self.tree(rec)
        sk_seed = self._tree_sk_seed(rec)
        sig = wots.sign(tree.seed, sk_seed, k, h, wots.Prf.SIGNER)
        path = tree.path(k)
        if wots.verify_root(tree.seed, k, h, sig, path) != tree.root:
            raise RuntimeError("WOTS signature failed its own verification: not released")
        return owner.tx_signature_data(slot, safe, safe_tx.words(), sig, path), slot, k, h
