"""Moving a signer to a new device while the old one still works: no fresh trees, no fee.

  1. new device   `move start`: the member types the recovery phrase and a passphrase for the new seed file. The
                  signer saves the seed and a move request, and shows the request's code (80 random bits).
  2. old device   `move export --code CODE --out FILE`: it appends a move-out record to its key log (fsynced; from here
                  on it signs nothing), writes the bundle, reads it back, and removes its seed file.
  3. new device   `move import FILE`: it opens the bundle with its seed and its pending request, checks the key log in
                  it, optionally against the chain and Safe's Transaction Service, installs it and binds it to itself.

The bundle (JSON):
  header  format, owner, request, move id, export time, salt, nonce: public, and the AEAD's associated data
  ct      ChaCha20-Poly1305 under HKDF-SHA256(seed, salt, "winterlock.signer.move-bundle.v1") over the payload: the
          key log up to and including its move-out record, one canonical line per record
Only someone with the seed (the phrase) can read or make a bundle. It carries no secret key: tree secrets need the
seed and the salts in the log together.

What the protocol prevents, and how:
  - the same bundle on two devices: it opens only with the request that one device made and keeps; that device
    consumes the request on import, and a request copied with its directory to another place fails its anchor check
  - exporting twice: the old device is locked by its first export. Exporting again for the same request rewrites the
    same log (an interrupted export finishes this way); another request is refused unless --replace-request (only for
    a new device that never finished and never will)
  - a changed, truncated or mixed-up bundle: the AEAD tag, each record's checksum, and the move-out record's count and
    hash of every record before it
  - an interrupted move: export locks before it writes and removes the seed only after the bundle reads back; import
    writes the log under a temporary name and renames it, and finishes an import that stopped half way
  - a stale bundle (a copy of the old log signed after the export, as after a VM rollback): with --chain and --rpc,
    import refuses if the Transaction Service holds a signature by the bundle's enrolled tree that the log lacks
Not prevented: a whole-machine rollback of the old device after the move (it comes back unlocked, with its seed);
copying the new device's directory before the import together with its anchors; anything done on purpose with the
phrase, which can always set up a signer.
"""

import base64
import json
import os
import secrets
import time

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from . import device, seedfile
from .abi import b2h
from .keylog import KeyLog, Refused, _chk, _fsync_dir, encode, head
from .member import REQUEST, Member, identity_of

FORMAT = "winterlock-move-v1"
KDF_INFO = b"winterlock.signer.move-bundle.v1"
STAGED = "keylog.import"


class MoveError(Refused):
    pass


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def new_code() -> str:
    raw = base64.b32encode(secrets.token_bytes(10)).decode()
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def normalize_code(code: str) -> str:
    raw = "".join(c for c in (code or "").upper() if c.isalnum())
    if len(raw) != 16:
        raise MoveError(f"a move code has 16 letters and digits, like {new_code()}")
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


# --- the bundle ---

def _bundle_key(seed: bytes, salt: bytes) -> bytes:
    return HKDF(seed, 32, salt, SHA256, context=KDF_INFO)


def seal(seed: bytes, payload: dict) -> dict:
    hdr = {"format": FORMAT, "owner": payload["owner"], "request": payload["request"], "move": payload["move"],
           "exported": payload["exported"], "kdf": "hkdf-sha256", "salt": secrets.token_hex(16),
           "aead": "chacha20-poly1305", "nonce": secrets.token_hex(12)}
    c = ChaCha20_Poly1305.new(key=_bundle_key(seed, bytes.fromhex(hdr["salt"])), nonce=bytes.fromhex(hdr["nonce"]))
    c.update(_canonical(hdr))
    ct, tag = c.encrypt_and_digest(_canonical(payload))
    return dict(hdr, ct=base64.b64encode(ct + tag).decode())


def unseal(seed: bytes, doc: dict, request: str) -> dict:
    """The payload of a bundle made for `request` with this seed, or MoveError"""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise MoveError("not a Winterlock move bundle")
    if normalize_code(doc.get("request", "")) != request:
        raise MoveError(f"this bundle was made for move request {doc.get('request')}, and this device waits for "
                        f"{request}: it belongs to another device's move")
    hdr = {k: v for k, v in doc.items() if k != "ct"}
    try:
        blob = base64.b64decode(doc["ct"], validate=True)
        c = ChaCha20_Poly1305.new(key=_bundle_key(seed, bytes.fromhex(hdr["salt"])), nonce=bytes.fromhex(hdr["nonce"]))
        c.update(_canonical(hdr))
        payload = json.loads(c.decrypt_and_verify(blob[:-16], blob[-16:]))
    except (KeyError, ValueError, TypeError):
        raise MoveError("the bundle doesn't open with this recovery phrase: it is another signer's, or it was changed "
                        "or damaged on the way") from None
    for k in ("owner", "request", "move", "exported"):
        if payload.get(k) != hdr.get(k):
            raise MoveError(f"the bundle's {k} differs inside and outside: refusing")
    if payload.get("format") != FORMAT:
        raise MoveError("unknown bundle payload")
    return payload


def records_of(payload: dict, key_hex: str) -> list:
    """The key log in a bundle, checked: canonical lines with valid checksums, the identity of this phrase, and a
    final move-out record for this move that commits to every record before it"""
    records = []
    for n, line in enumerate(payload.get("log") or [], 1):
        try:
            rec = json.loads(line)
        except ValueError:
            raise MoveError(f"record {n} in the bundle isn't JSON") from None
        if rec.get("chk") != _chk(rec) or encode(rec).decode() != line:
            raise MoveError(f"record {n} in the bundle fails its checksum")
        records.append(rec)
    ident = next((r for r in records if r["t"] in ("init", "restore")), None)
    if not ident or ident["key"] != key_hex or ident["owner"] != payload["owner"]:
        raise MoveError("the key log in the bundle belongs to another signer than this recovery phrase")
    last = records[-1]
    if last["t"] != "move-out" or last.get("move") != payload["move"] or last.get("request") != payload["request"]:
        raise MoveError("the bundle's key log doesn't end with the move-out record of this move")
    if last.get("count") != len(records) - 1 or last.get("head") != head(records[:-1]):
        raise MoveError("the bundle's key log isn't the one its move-out record commits to")
    return records


def _write_atomic(path: str, data: bytes):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(os.path.abspath(path)))


# --- old device ---

def lock_for(m: Member, request: str, replace_request=False) -> dict:
    """The move-out record for `request`: appended now (which locks the device) or the one already there"""
    mo = m.move_out()
    if mo is None:
        m.require_active()  # a suspected copy can't hand on a log that may be stale
        dev = m.device()
        return m.log.append({"t": "move-out", "move": secrets.token_hex(8), "request": request,
                             "device": dev["id"] if dev else None, "count": len(m.log.records),
                             "head": head(m.log.records)})
    if mo["request"] == request:
        return mo
    if not replace_request:
        raise MoveError(f"this device already handed its keys over for move request {mo['request']} on {mo['at']}. "
                        "A bundle for another request could put the same keys on two devices. If the device that "
                        f"asked with {mo['request']} never imported its bundle and never will (it was wiped), add "
                        "--replace-request.")
    frozen, m.log.frozen = m.log.frozen, None
    try:
        return m.log.append({"t": "move-out", "move": secrets.token_hex(8), "request": request,
                             "device": mo.get("device"), "count": len(m.log.records), "head": head(m.log.records),
                             "replaces": mo["request"]})
    finally:
        m.log.frozen = frozen


def export(m: Member, request: str, path: str, replace_request=False) -> dict:
    """Locks this device for `request` (if not already), writes the bundle to `path`, checks it reads back, then
    removes the seed file. The seed must be unlocked or given (m.use_seed) beforehand. Returns the payload."""
    request = normalize_code(request)
    seed = m.seed()
    mo = lock_for(m, request, replace_request)
    upto = next(i for i, r in enumerate(m.log.records) if r is mo)
    payload = {"format": FORMAT, "owner": m.owner, "key": b2h(m.key), "move": mo["move"], "request": request,
               "device": mo.get("device"), "exported": mo["at"],
               "log": [encode(r).decode() for r in m.log.records[:upto + 1]]}
    _write_atomic(path, json.dumps(seal(seed, payload), indent=1).encode() + b"\n")
    with open(path) as f:
        if unseal(seed, json.load(f), request) != payload:
            raise MoveError(f"{path} doesn't read back as written: the device stays locked; export again")
    seedfile.wipe(m.seed_path)
    m._refreeze()
    return payload


# --- new device ---

def pending(home: str):
    """The move request this directory waits with, or None"""
    try:
        with open(os.path.join(home, REQUEST)) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def start(home: str, seed: bytes, passphrase: str = None, scrypt_n: int = seedfile.SCRYPT_N) -> dict:
    """Saves the seed (encrypted unless passphrase is None) and a new move request in an empty signer directory"""
    os.makedirs(home, mode=0o700, exist_ok=True)
    os.chmod(home, 0o700)
    req = pending(home)
    if req:
        raise MoveError(f"{home} already waits for move request {req['request']}: finish it with `move import`, or "
                        "`move cancel` first")
    for name in ("seed", "keylog.jsonl"):
        if os.path.exists(os.path.join(home, name)):
            raise MoveError(f"{home} already has a signer ({name}): a move needs an empty directory (--home)")
    key, own = identity_of(seed)
    seedfile.write(os.path.join(home, "seed"), seed, passphrase, n=scrypt_n)
    req = {"request": new_code(), "owner": own, "key": b2h(key), "created": _now()}
    path = os.path.join(home, REQUEST)
    _write_atomic(path, json.dumps(req, indent=1).encode() + b"\n")
    try:
        device.bind("request-" + req["request"], path)
    except OSError:
        pass
    return req


def cancel(home: str):
    """Drops a pending move: the request and the seed saved with it (the phrase is still the backup)"""
    req = pending(home)
    if not req:
        raise MoveError(f"{home} has no pending move")
    if os.path.exists(os.path.join(home, "keylog.jsonl")):
        raise MoveError("the import already installed the key log here: run `move import` again to finish it")
    seedfile.wipe(os.path.join(home, "seed"))
    for name in (STAGED, REQUEST):
        try:
            os.remove(os.path.join(home, name))
        except FileNotFoundError:
            pass
    device.forget("request-" + req["request"])
    return req


def request_problems(home: str, req: dict) -> list:
    return [p[1] for p in device.check("request-" + req["request"], os.path.join(home, REQUEST))]


def open_bundle(home: str, doc: dict, passphrase: str = None):
    """(seed, payload, records) of a bundle for this directory's pending request, checked offline"""
    req = pending(home)
    if not req:
        raise MoveError(f"{home} isn't waiting for a move: run `move start` here first (it asks for your phrase and "
                        "shows the code to give `move export` on the old device)")
    problems = request_problems(home, req)
    if problems:
        raise MoveError("this move request isn't where it was made (" + "; ".join(problems) + "): a copied request "
                        "could import one bundle twice. Run `move cancel`, then `move start` again.")
    try:
        seed = seedfile.read(os.path.join(home, "seed"), lambda: _passphrase(home, passphrase))
    except seedfile.WrongPassphrase:
        raise MoveError("wrong passphrase for the seed file") from None
    payload = unseal(seed, doc, req["request"])
    if payload["key"] != req["key"]:
        raise MoveError("the bundle is for another signer than the phrase this move started with")
    return seed, payload, records_of(payload, req["key"])


def _passphrase(home, given):
    if given is not None:
        return given
    env = os.environ.get("WINTERLOCK_PASSPHRASE")
    if env is not None:
        return env
    from . import member
    if member.ask_passphrase:
        return member.ask_passphrase(f"Passphrase for {home}: ")
    raise Refused("the seed is encrypted: run this in a terminal, or set WINTERLOCK_PASSPHRASE")


def stage(home: str, records: list) -> KeyLog:
    """The bundle's key log under a temporary name, opened read-only for checks before it is installed"""
    path = os.path.join(home, STAGED)
    _write_atomic(path, b"".join(encode(r) + b"\n" for r in records))
    return KeyLog(path, lock=False)


def unstage(home: str):
    try:
        os.remove(os.path.join(home, STAGED))
    except FileNotFoundError:
        pass


def install(home: str, seed: bytes, payload: dict, records: list, passphrase: str = None) -> Member:
    """Installs the bundle's key log as this directory's, binds it to this device and drops the request. Finishes an
    import that stopped half way (the same log already installed)."""
    log_path = os.path.join(home, "keylog.jsonl")
    if os.path.exists(log_path):
        have = KeyLog(log_path, lock=False)
        same = have.records[:len(records)] == records
        have.close()
        if not same:
            raise MoveError(f"{home} already has another key log")
    else:
        staged = os.path.join(home, STAGED)
        if not os.path.exists(staged):
            stage(home, records).close()
        os.replace(staged, log_path)
        _fsync_dir(home)
    m = Member(home, passphrase=passphrase, _seed=seed, _allow_request=True)
    dev = m.device()
    if not (dev and dev.get("how") == "move-in" and dev.get("move") == payload["move"]
            and m.log.records.index(dev) > len(records) - 1):
        m.add_device("move-in", move=payload["move"], from_device=payload.get("device"))
        m.log.append({"t": "backup", "how": "move-in"})
    req = pending(home)
    os.remove(os.path.join(home, REQUEST))
    _fsync_dir(home)
    if req:
        device.forget("request-" + req["request"])
    return m
