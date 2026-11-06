"""A member's signer state: the secret seed, the key log, and everything derived from them.

Home directory (default ~/.winterlock-signer, or WINTERLOCK_HOME), mode 700:
  seed         the 32-byte secret, mode 600, encrypted with a passphrase (seedfile.py). Its backup is the recovery
               phrase: 24 BIP-39 words that encode these 32 bytes (phrase.py). Removed when the device moves away.
  keylog.jsonl the key log (keylog.py), mode 600
  cache/       public values only, rebuilt when missing: the stateless key's kept leaves, operation tree leaves
  move-request.json  only on a new device waiting for a move's bundle (move.py)

Derivations (keccak256 of abi.encode(label, ...)):
  stateless seed   ("winterlock.signer.stateless.v1", seed) -> leanSphincs key, kept subtree of height 10.
                   Deterministic: a restored signer has the same KEY and the same owner address.
  tree secret seed ("winterlock.signer.ops.v1", seed, chain, owner, safe, start, salt), salt = 32 random bytes
                   recorded only in the key log. A lost log can't bring an old tree back; two restores never make
                   the same tree.
  WOTS secrets     wots.Prf.SIGNER over the tree secret seed

Device states (state()): active; locked (a move was started and not finished, or this key log looks like a copy:
device.py); moved (the log was handed to another device, which now signs instead). Only an active signer signs.
"""

import os
import secrets

from . import device, leansphincs, owner, seedfile, wots
from .abi import b2h, h2b, read_file, word
from .keccak import keccak256
from .keylog import KeyLog, Refused, _fsync_dir

STATELESS_B = leansphincs.DEFAULT_B
DEFAULT_HEIGHT = 10
REQUEST = "move-request.json"
COPY_REMEDY = ("If the original signer still works, move from it instead (`move export` there, `move import` here). "
               "If it is gone for good, `device fresh-trees` makes this copy safe to use (fresh key trees: a fee per "
               "Safe and chain); `device adopt` trusts this copy as complete, which is only right if it was made after "
               "the original's last signature.")

# Asked for the seed's passphrase when neither the caller nor WINTERLOCK_PASSPHRASE gives one: f(prompt) -> str. The
# command line sets it to a terminal prompt.
ask_passphrase = None


def default_home() -> str:
    return os.environ.get("WINTERLOCK_HOME") or os.path.expanduser("~/.winterlock-signer")


def _abi_label(label: bytes, *words) -> bytes:
    head = word(32 * (len(words) + 1)) + b"".join(word(w) for w in words)
    return keccak256(head + word(len(label)) + label + bytes((-len(label)) % 32))


def stateless_key(seed: bytes) -> leansphincs.Key:
    return leansphincs.Key(_abi_label(b"winterlock.signer.stateless.v1", seed), STATELESS_B)


def identity_of(seed: bytes):
    """(stateless public key, owner address) that a seed gives, without a signer directory (about 0.1 s)"""
    key = stateless_key(seed).public_key
    return key, owner.owner_address(key)


class Member:
    def __init__(self, home: str = None, lock=True, passphrase: str = None, _seed: bytes = None,
                 _allow_request=False):
        self.home = home or default_home()
        self.seed_path = os.path.join(self.home, "seed")
        log_path = os.path.join(self.home, "keylog.jsonl")
        if os.path.exists(os.path.join(self.home, REQUEST)) and not _allow_request:
            raise Refused(f"{self.home} is waiting for a move from your old device: run `move import BUNDLE` with "
                          "the bundle it wrote, or `move cancel`")
        has_seed = os.path.exists(self.seed_path)
        if not has_seed and not os.path.exists(log_path):
            raise Refused(f"no signer at {self.home}: run `init` first")
        if has_seed:
            st = os.stat(self.seed_path)
            if st.st_mode & 0o077:
                raise Refused(f"{self.seed_path} is readable by others (mode {oct(st.st_mode & 0o777)}): chmod 600 it")
        self._passphrase = passphrase
        self._seed_value = _seed
        self._sk = None
        self.log = KeyLog(log_path, lock=lock)
        try:
            self._open(lock, has_seed)
        except BaseException:
            self.log.close()
            raise

    def _open(self, lock, has_seed):
        ident = self.log.identity()
        if ident is None and not has_seed:
            raise Refused(f"{self.home} has neither a seed nor an identity in its key log")
        self.key = h2b(ident["key"]) if ident else self.stateless().public_key
        self.owner = owner.owner_address(self.key)
        if ident and ident["owner"] != self.owner:
            raise Refused(f"the owner address changed since init ({ident['owner']} -> {self.owner}): the pinned "
                          "owner contracts (implementation, factory or verifier) differ from the ones this signer was "
                          "set up with")
        self.problems = []
        dev = self.log.last("device")
        if dev is None:
            if lock and ident and not self.move_out():  # a key log from before device records: bind it here
                self.add_device("upgrade")
                self.log.warnings.append("this key log is now bound to this device (it predates device checks)")
        else:
            self.problems = device.check(dev["id"], self.log.path, self.log.records)
            if lock and not self.problems:
                self.log.on_append = self._advance
        self._refreeze()

    # --- set-up ---

    @staticmethod
    def init(home: str = None, restore_seed: bytes = None, passphrase: str = None, backup: str = None,
             scrypt_n: int = None, new_seed: bytes = None):
        """A new signer (a new random seed), or one restored from a seed (its phrase) with an empty key log. The seed
        file is encrypted with `passphrase`; None writes it in plain hex (tests, and the command line's
        --insecure-plaintext-seed). `backup` records how the phrase was checked. `new_seed`: a new signer's seed, when
        the caller drew it (to show its phrase before anything is saved)."""
        home = home or default_home()
        os.makedirs(home, mode=0o700, exist_ok=True)
        os.chmod(home, 0o700)
        if os.path.exists(os.path.join(home, "seed")):
            raise Refused(f"{home} already has a seed; refusing to overwrite it")
        if os.path.exists(os.path.join(home, "keylog.jsonl")):
            raise Refused(f"{home} has a key log but no seed; move it away first")
        if os.path.exists(os.path.join(home, REQUEST)):
            raise Refused(f"{home} is waiting for a move: `move import` or `move cancel` first")
        seed = restore_seed if restore_seed is not None else new_seed or secrets.token_bytes(32)
        if len(seed) != 32:
            raise Refused("a seed is 32 bytes")
        seedfile.write(os.path.join(home, "seed"), seed, passphrase, n=scrypt_n)
        _fsync_dir(home)
        m = Member(home, passphrase=passphrase, _seed=seed)
        how = "restore" if restore_seed is not None else "init"
        m.log.append({"t": how, "owner": m.owner, "key": b2h(m.key), "params": "D6", "stateless_b": STATELESS_B,
                      "owner_code": owner.PINNED_COMMIT})
        m.add_device(how)
        if backup:
            m.log.append({"t": "backup", "how": backup})
        return m

    # --- the seed ---

    @property
    def _seed(self) -> bytes:
        if self._seed_value is None:
            self._seed_value = self._unlock()
        return self._seed_value

    def seed(self) -> bytes:
        """The secret seed, unlocked with the passphrase if needed"""
        return self._seed

    def use_seed(self, seed: bytes):
        """Takes the seed from the recovery phrase (on a device whose seed file is gone); refuses another signer's"""
        if stateless_key(seed).public_key != self.key:
            raise Refused("this recovery phrase belongs to another signer")
        self._seed_value = seed

    def _passphrase_for_unlock(self) -> str:
        if self._passphrase is not None:
            return self._passphrase
        env = os.environ.get("WINTERLOCK_PASSPHRASE")
        if env is not None:
            return env
        if ask_passphrase:
            return ask_passphrase(f"Passphrase for {self.home}: ")
        raise Refused("the seed is encrypted: run this in a terminal, or set WINTERLOCK_PASSPHRASE")

    def _unlock(self) -> bytes:
        if not os.path.exists(self.seed_path):
            st, why = self.state()
            raise Refused(why if st != "active" else f"{self.home} has no seed file")
        for attempt in range(3):
            try:
                return seedfile.read(self.seed_path, self._passphrase_for_unlock)
            except seedfile.WrongPassphrase:
                if self._passphrase is not None or os.environ.get("WINTERLOCK_PASSPHRASE") is not None or attempt == 2:
                    raise Refused("wrong passphrase for the seed file") from None
            except seedfile.SeedFileError as e:
                raise Refused(str(e)) from None

    def set_passphrase(self, passphrase: str, scrypt_n: int = None):
        """Re-encrypts the seed file under a new passphrase (or encrypts a plain one)"""
        seed = self._seed
        seedfile.write(self.seed_path, seed, passphrase, n=scrypt_n, replace=True)
        self._passphrase = passphrase

    # --- device ---

    def device(self):
        """The current device record, or None (a key log from before device records)"""
        return self.log.last("device")

    def move_out(self):
        """The move-out record that locks this device: one after its latest device record"""
        for r in reversed(self.log.records):
            if r["t"] == "device":
                return None
            if r["t"] == "move-out":
                return r
        return None

    def state(self):
        """("active" | "locked" | "moved", why)"""
        mo = self.move_out()
        if mo:
            if os.path.exists(self.seed_path):
                return "locked", (f"this device started a move to another device (request {mo['request']}) on "
                                  f"{mo['at']} and signs nothing more; run `move export --code {mo['request']}` "
                                  "again to write the bundle and finish it")
            return "moved", (f"this device moved its keys to another device on {mo['at']} (request "
                             f"{mo['request']}) and never signs again")
        if self.problems:
            return "locked", ("this key log looks like a copy: " + "; ".join(p[1] for p in self.problems) + ". "
                              + COPY_REMEDY)
        return "active", ""

    def require_active(self):
        st, why = self.state()
        if st != "active":
            raise Refused(why)

    def _refreeze(self):
        st, why = self.state()
        self.log.frozen = why if st != "active" else None

    def _advance(self, log):
        dev = log.last("device")
        if dev:
            try:
                device.advance(dev["id"], len(log.records), log.records[-1]["chk"])
            except OSError as e:
                log.warnings.append(f"device anchor not updated ({e}): the copy check can't see this record")

    def add_device(self, how: str, retire: bool = False, **extra) -> dict:
        """Binds the key log to this device under a new device id (device.py). With retire, every tree recorded so
        far is retired."""
        prev = self.log.last("device")
        rec = {"t": "device", "id": device.new_id(), "how": how, "gen": prev["gen"] + 1 if prev else 0, **extra}
        if retire:
            rec["retire"] = True
        self.log.on_append = None
        rec = self.log.append(rec)
        try:
            device.bind(rec["id"], self.log.path, len(self.log.records), rec["chk"])
        except OSError as e:
            self.log.warnings.append(f"device anchor not written ({e}): copies of this key log can't be detected")
        self.problems = []
        self.log.on_append = self._advance
        self._refreeze()
        return rec

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
        self.require_active()
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
        self.require_active()
        if not 1 <= height <= owner.MAX_HEIGHT or not 0 <= start <= owner.MAX_START:
            raise Refused("bad key tree height or start")
        if height > 20:
            raise Refused("key trees above height 20 take too long to generate here")
        prior = self.log.trees(chain, safe)
        if prior and start <= max(t["start"] for t in prior):
            raise Refused(f"a new key tree must start after nonce {max(t['start'] for t in prior)}")
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
            raise Refused("the key tree rebuilt from the seed and the key log has another root: wrong seed?")
        self._save_tree(rec, t)
        return t

    def certificate(self, rec: dict) -> bytes:
        """The stateless key's signature of the tree's certificate digest; recorded before it is released"""
        self.require_active()
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
        self.require_active()
        if self.log.retired(rec):
            raise Refused(f"key tree {rec['root']} is retired on this device: run `enroll` to certify a fresh one")
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
