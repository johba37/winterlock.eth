#!/usr/bin/env python3
"""Winterlock on Daisugi: EIP-8141 frame transactions from a member key and one-time keys.

Daisugi (https://daisugi.fyi, chain 1337) is a public test network for post-quantum accounts. It runs Nethermind's
EIP-8141 prototype (branch daisugi/devnet-handoff) and its public RPC accepts frame transactions (type 0x06) only.

  vector            reproduce Daisugi transactions' hashes and signature hashes from their fields (offline)
  deploy            deploy the verifiers and the frame account implementations (CREATE2, from the deployer key)
  member            make the throwaway member (phrase, member key) in $DAISUGI_DIR, print its account
  fund              ask Daisugi's faucet for 1 test ETH for the member's account
  enroll [--height H]
                    v1: make a tree of one-time keys and store its root with a member-key-signed transaction
                    (deploys the account too, if needed)
  send [--to A] [--value WEI] [--member] [--slot S]
                    a frame transaction from the account: VERIFY with a one-time key while the stored tree covers
                    the nonce (v1), else with the member key; then a SENDER frame; prints each frame's gas
  attacks           v1: signatures the account must refuse, then a one-time-key transaction that calls enroll
  replace           v1: sign nonce n with slot 0 and hold it back, send its replacement with slot 1, then show
                    the key log refusing a third version
  --account v0|v1   which implementation (default v1; v0 accepts the member key only)

Run with the signer's Python (it reuses the signer's key derivation, leanSphincs and secp256k1 code):
  DAISUGI_DIR=/scratch/dir ../signer/.venv/bin/python bench/daisugi/daisugi.py <command>
The deployer key is DAISUGI_DEPLOYER_KEY in bench/bundlers/.env (or the environment). $DAISUGI_DIR holds a
throwaway phrase, tree secrets and the key log; keep it out of the repository.

Encoding (checked against transactions on Daisugi, see `vector`):
  payload   = [chain_id, nonce, sender, frames, signatures,
               [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas], blob_versioned_hashes]
  frame     = [mode, flags, target, [execution_gas, state_gas], value, data]
  signature = [scheme, signer (address or empty), msg (empty or 32 bytes), signature]
  tx hash   = keccak(0x06 ‖ rlp(payload)); sig hash = the same with the signature bytes of every empty-msg entry
              replaced by empty bytes (the EIP commits to their length instead; Nethermind's prototype doesn't)
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONTRACTS = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(os.path.dirname(CONTRACTS), "signer"))

from winterlock_signer import leansphincs as wleansphincs  # noqa: E402
from winterlock_signer import member as wmember  # noqa: E402
from winterlock_signer import phrase as wphrase  # noqa: E402
from winterlock_signer import wots  # noqa: E402
from winterlock_signer.ethtx import Account, sign_hash  # noqa: E402
from winterlock_signer.keccak import keccak256  # noqa: E402

RPC = os.environ.get("DAISUGI_RPC", "https://daisugi.fyi/rpc")
FAUCET = "https://daisugi.fyi/api/faucet"
CHAIN_ID = 1337
CREATE2_DEPLOYER = bytes.fromhex("4e59b44847b379578588920cA78FbF26c0B4956C")
VERIFIER_SALT = keccak256(b"Winterlock.stateless-verifier.v1")
WOTS_VERIFIER_SALT = keccak256(b"Winterlock.wots-verifier.v1")
STATELESS_VERIFIER = bytes.fromhex("6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254")
WOTS_VERIFIER = bytes.fromhex("272138c7D3b508bd510bE5166fbE2461561e410D")
TREE_SEED_DOMAIN = keccak256(b"Winterlock.frame-account.tree-seed.v1")
ENROLL_SELECTOR = keccak256(b"enroll(bytes32,uint8,uint64)")[:4]
DEFAULT, VERIFY, SENDER = 0, 1, 2
ARBITRARY, SECP256K1 = 0, 1
SIG_LEN = 5684
PRIORITY_FEE = 10**9   # what Daisugi's own transactions pay; the base fee is a few wei
MAX_FEE = 2 * 10**9


# --- RLP ---------------------------------------------------------------------------------------------------------

def _len(n, off):
    if n < 56:
        return bytes([off + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(b)]) + b


def rlp(x) -> bytes:
    if isinstance(x, int):
        x = b"" if x == 0 else x.to_bytes((x.bit_length() + 7) // 8, "big")
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        return x if len(x) == 1 and x[0] < 0x80 else _len(len(x), 0x80) + x
    out = b"".join(rlp(i) for i in x)
    return _len(len(out), 0xc0) + out


def h2b(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def b2h(b: bytes) -> str:
    return "0x" + b.hex()


# --- frame transactions ------------------------------------------------------------------------------------------

def frame(mode, target, execution_gas, state_gas=0, value=0, data=b"", flags=0):
    return {"mode": mode, "flags": flags, "target": target, "exec": execution_gas, "state": state_gas,
            "value": value, "data": data}


def _payload(tx, elide):
    frames = [[f["mode"], f["flags"], f["target"] or b"", [f["exec"], f["state"]], f["value"], f["data"]]
              for f in tx["frames"]]
    sigs = [[s["scheme"], s.get("signer") or b"", s.get("msg") or b"",
             b"" if (elide and not s.get("msg")) else s["signature"]] for s in tx["signatures"]]
    return [tx["chain_id"], tx["nonce"], tx["sender"], frames, sigs,
            [tx["max_priority_fee"], tx["max_fee"], tx.get("max_blob_fee", 0)], tx.get("blob_hashes", [])]


def encode(tx) -> bytes:
    return b"\x06" + rlp(_payload(tx, False))


def tx_hash(tx) -> bytes:
    return keccak256(encode(tx))


def sig_hash(tx) -> bytes:
    """The canonical signature hash, as Daisugi's Nethermind computes it"""
    return keccak256(b"\x06" + rlp(_payload(tx, True)))


def from_rpc(t) -> dict:
    i = lambda s: int(s, 16)  # noqa: E731
    return {
        "chain_id": i(t["chainId"]), "nonce": i(t["nonce"]), "sender": h2b(t["from"]),
        "frames": [frame(i(f["mode"]), h2b(f["target"]) if f.get("target") else b"", i(f["executionGas"]),
                         i(f["stateGas"]), i(f["value"]), h2b(f["data"]), i(f["flags"])) for f in t["frames"]],
        "signatures": [{"scheme": i(s["scheme"]), "signer": h2b(s["signer"]) if s.get("signer") else b"",
                        "msg": h2b(s["msg"]), "signature": h2b(s["signature"])} for s in t["signatures"]],
        "max_priority_fee": i(t["maxPriorityFeePerGas"]), "max_fee": i(t["maxFeePerGas"]),
        "max_blob_fee": i(t.get("maxFeePerBlobGas") or "0x0"),
        "blob_hashes": [h2b(x) for x in t.get("blobVersionedHashes") or []],
    }


# --- RPC -----------------------------------------------------------------------------------------------------------

class RpcError(Exception):
    pass


def rpc(method, *params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": "winterlock-daisugi"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        d = json.loads(e.read() or b"{}")
    if "error" in d:
        raise RpcError(f"{method}: {d['error'].get('message')}")
    return d["result"]


def code_at(addr: bytes) -> bytes:
    return h2b(rpc("eth_getCode", b2h(addr), "latest"))


def balance(addr: bytes) -> int:
    return int(rpc("eth_getBalance", b2h(addr), "latest"), 16)


def nonce_of(addr: bytes) -> int:
    return int(rpc("eth_getTransactionCount", b2h(addr), "pending"), 16)


def submit(tx, label):
    raw = encode(tx)
    h = rpc("eth_sendRawTransaction", b2h(raw))
    assert h2b(h) == tx_hash(tx), "the node hashed the transaction differently"
    print(f"{label}: sent {h} ({len(raw):,} bytes)")
    for _ in range(90):
        r = rpc("eth_getTransactionReceipt", h)
        if r:
            return h, r
        time.sleep(2)
    raise RpcError(f"{label}: no receipt after 3 minutes")


def show_receipt(r, names):
    frames = r.get("frameReceipts") or r.get("frames") or []
    print(f"  block {int(r['blockNumber'], 16)}, gas used {int(r['gasUsed'], 16):,}"
          + (f", status {int(r['status'], 16)}" if r.get("status") else ""))
    for k, fr in enumerate(frames):
        gu = fr.get("gasUsed")
        if isinstance(gu, dict):
            ex, st = int(gu.get("execution", "0x0"), 16), int(gu.get("state", "0x0"), 16)
        elif isinstance(gu, list):
            ex, st = int(gu[0], 16), int(gu[1], 16)
        else:
            ex, st = int(fr.get("executionGasUsed", gu or "0x0"), 16), int(fr.get("stateGasUsed", "0x0"), 16)
        status = fr.get("status")
        print(f"  frame {k} {names[k] if k < len(names) else ''}: status {int(status, 16) if isinstance(status, str) else status}"
              f", execution gas {ex:,}, state gas {st:,}")
    return frames


# --- addresses and code ------------------------------------------------------------------------------------------

def create2(salt: bytes, init_code: bytes) -> bytes:
    return keccak256(b"\xff" + CREATE2_DEPLOYER + salt + keccak256(init_code))[12:]


def artifact(path, key="bytecode") -> bytes:
    with open(os.path.join(CONTRACTS, "out", path)) as f:
        return h2b(json.load(f)[key]["object"])


def account_init(version: str) -> bytes:
    """The frame account implementation's pinned creation code (frame/accounts.json, built by frame/build.sh)"""
    with open(os.path.join(CONTRACTS, "frame", "accounts.json")) as f:
        return h2b(json.load(f)[version]["creation_code"])


def account_salt(version: str) -> bytes:
    return keccak256(f"Winterlock.frame-account.{version}".encode())


def clone_init(impl: bytes, pk_seed: bytes, pk_root: bytes) -> bytes:
    """EIP-1167's runtime pointing at `impl`, then the 64-byte key; 109 bytes deployed"""
    runtime = (bytes.fromhex("363d3d373d3d3d363d73") + impl + bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
               + pk_seed + pk_root)
    assert len(runtime) == 109
    return bytes.fromhex("3d606d80600a3d3981f3") + runtime


def word(x) -> bytes:
    return (x if isinstance(x, bytes) else int(x).to_bytes(32, "big")).rjust(32, b"\x00")


def tree_seed(account: bytes, start: int) -> int:
    """v1: the first 16 bytes of keccak256(abi.encode(TREE_SEED_DOMAIN, chainid, account, start))"""
    return int.from_bytes(keccak256(TREE_SEED_DOMAIN + word(CHAIN_ID) + word(account) + word(start))[:16], "big")


ENROLLED_TOPIC = keccak256(b"Enrolled(bytes32,uint8,uint64)")


def stored_tree(account: bytes):
    """(root 24 B, start, height) that the account stores, or None. Daisugi's public RPC has no eth_getStorageAt
    and no state overrides, so this reads the latest Enrolled event (every write to slot 0 emits one), from the
    first enrolment this directory recorded, in the 10,000-block windows eth_getLogs allows."""
    first = _enrolments().get(b2h(account))
    if first is None:
        return None
    head = int(rpc("eth_blockNumber"), 16)
    last = None
    for lo in range(first, head + 1, 10_000):
        logs = rpc("eth_getLogs", {"address": b2h(account), "topics": [b2h(ENROLLED_TOPIC)],
                                   "fromBlock": hex(lo), "toBlock": hex(min(lo + 9_999, head))})
        if logs:
            last = logs[-1]
    if last is None:
        return None
    d = h2b(last["data"])
    return d[:24], int.from_bytes(d[64:96], "big"), int.from_bytes(d[32:64], "big")


def _enrolments() -> dict:
    path = os.path.join(member_dir(), "enrolments.json")
    return json.load(open(path)) if os.path.exists(path) else {}


def _note_enrolment(account: bytes, block: int):
    e = _enrolments()
    e.setdefault(b2h(account), block)
    _write_secret(os.path.join(member_dir(), "enrolments.json"), e)


# --- the deployer (an ordinary key, through EIP-8141's default code) -------------------------------------------------

def deployer() -> Account:
    key = os.environ.get("DAISUGI_DEPLOYER_KEY")
    if not key:
        env = os.path.join(CONTRACTS, "bench", "bundlers", ".env")
        for line in open(env):
            if line.startswith("DAISUGI_DEPLOYER_KEY="):
                key = line.split("=", 1)[1].strip()
    if not key:
        sys.exit("DAISUGI_DEPLOYER_KEY is not set")
    return Account(key)


def eoa_tx(acct: Account, frames_after_verify, label):
    """A frame transaction from a key: VERIFY by the default code with a SECP256K1 signature, then the frames"""
    sender = h2b(acct.address)
    tx = {"chain_id": CHAIN_ID, "nonce": nonce_of(sender), "sender": sender,
          "frames": [frame(VERIFY, sender, 100_000, flags=3)] + frames_after_verify,
          "signatures": [{"scheme": SECP256K1, "signer": sender, "msg": b"", "signature": bytes(65)}],
          "max_priority_fee": PRIORITY_FEE, "max_fee": MAX_FEE}
    parity, r, s = sign_hash(acct._d, sig_hash(tx))
    tx["signatures"][0]["signature"] = bytes([parity]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return submit(tx, label)


def cmd_deploy():
    acct = deployer()
    print(f"deployer {acct.address}, {balance(h2b(acct.address)) / 1e18:.4f} ETH")
    items = (
        ("stateless verifier", VERIFIER_SALT, artifact("LeanSphincsAsm.sol/LeanSphincsAsm.json"), 1_500_000),
        ("shared WOTS verifier", WOTS_VERIFIER_SALT, artifact("SharedWotsVerifier.sol/SharedWotsVerifier.json"),
         6_000_000),
        ("frame account v0", account_salt("v0"), account_init("v0"), 300_000),
        ("frame account v1", account_salt("v1"), account_init("v1"), 600_000),
    )
    for name, salt, init, gas in items:
        addr = create2(salt, init)
        if code_at(addr):
            print(f"{name}: at {b2h(addr)} already")
            continue
        _, r = eoa_tx(acct, [frame(SENDER, CREATE2_DEPLOYER, gas, gas, data=salt + init)], f"deploy {name}")
        show_receipt(r, ["VERIFY (default code)", "SENDER: CREATE2"])
        print(f"  {name} at {b2h(addr)}: {len(code_at(addr))} bytes")
    assert create2(VERIFIER_SALT, artifact("LeanSphincsAsm.sol/LeanSphincsAsm.json")) == STATELESS_VERIFIER
    assert create2(WOTS_VERIFIER_SALT, artifact("SharedWotsVerifier.sol/SharedWotsVerifier.json")) == WOTS_VERIFIER


# --- the member and its account ------------------------------------------------------------------------------------

def member_dir() -> str:
    d = os.environ.get("DAISUGI_DIR")
    if not d:
        sys.exit("set DAISUGI_DIR to a directory outside the repository")
    os.makedirs(d, exist_ok=True)
    return d


def _write_secret(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_member(version="v1"):
    """(member key, account address, clone init code); makes the throwaway phrase on first use"""
    d = member_dir()
    path = os.path.join(d, "member.json")
    if not os.path.exists(path):
        seed = os.urandom(32)
        t0 = time.time()
        key = wmember.stateless_key(seed)
        _write_secret(path, {"phrase": " ".join(wphrase.to_phrase(seed)), "note": "throwaway, Daisugi test only",
                             "kept_leaves": key.kept_leaves_bytes().hex()})
        print(f"made a throwaway member in {path} (member key in {time.time() - t0:.1f} s)")
    m = json.load(open(path))
    seed = wphrase.to_seed(m["phrase"])
    # the member key as member.stateless_key makes it, from the kept leaves instead of recomputing them
    leaves = bytes.fromhex(m["kept_leaves"])
    key = wleansphincs.Key(wmember._abi_label(wmember.MEMBER_KEY_LABEL, seed), wmember.STATELESS_B,
                           kept_leaves=[leaves[i:i + 16] for i in range(0, len(leaves), 16)])
    pk = key.public_key                    # root ‖ P
    pk_seed, pk_root = pk[16:] + bytes(16), pk[:16] + bytes(16)   # high-aligned words
    init = clone_init(create2(account_salt(version), account_init(version)), pk_seed, pk_root)
    return key, create2(bytes(32), init), init


def cmd_member(version):
    key, account, _ = load_member(version)
    print(f"member key (root ‖ P): {b2h(key.public_key)}")
    print(f"account {version}: {b2h(account)}  code {len(code_at(account))} bytes, nonce {nonce_of(account)}, "
          f"balance {balance(account) / 1e18:.4f} ETH")
    if version == "v1" and code_at(account):
        t = stored_tree(account)
        print("  tree: none" if not t else f"  tree: root {b2h(t[0])}, start {t[1]}, height {t[2]} "
                                            f"(nonces {t[1]}..{t[1] + (1 << (t[2] - 1)) - 1})")


def cmd_fund(version):
    _, account, _ = load_member(version)
    req = urllib.request.Request(FAUCET, data=json.dumps({"address": b2h(account), "amount": "1"}).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "winterlock-daisugi"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            print(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"faucet: HTTP {e.code} {e.read().decode()[:300]}")


# --- one-time keys: the tree and the key log -------------------------------------------------------------------------

def tree_path(account: bytes, start: int) -> str:
    return os.path.join(member_dir(), f"tree-{account.hex()}-{start}.json")


def load_tree(account: bytes):
    """(tree, sk_seed, start) of the tree the account stores; refuses if the local copy doesn't match it"""
    t = stored_tree(account)
    if not t:
        return None
    root, start, height = t
    path = tree_path(account, start)
    if not os.path.exists(path):
        sys.exit(f"the account stores a tree from nonce {start} that this directory doesn't hold")
    rec = json.load(open(path))
    tree = wots.Tree.from_bytes(bytes.fromhex(rec["cache"]))
    if tree.root != root or tree.height != height or tree.seed != tree_seed(account, start):
        sys.exit("the local tree doesn't match the one the account stores")
    return tree, bytes.fromhex(rec["sk_seed"]), start


class KeyLog:
    """Every one-time key this directory signs with, recorded (and fsync'd) before it signs: (account, start, nonce,
    slot) → the one sig hash it may sign. Re-signing the same hash with the same key gives the same signature."""

    def __init__(self):
        self.path = os.path.join(member_dir(), "keylog.json")
        self.entries = json.load(open(self.path)) if os.path.exists(self.path) else []

    def _used(self, account, start, nonce):
        return {e["slot"]: e["sig_hash"] for e in self.entries
                if e["account"] == b2h(account) and e["start"] == start and e["nonce"] == nonce}

    def pick(self, account, start, nonce, h, slot=None):
        used = self._used(account, start, nonce)
        for s, hh in used.items():
            if hh == b2h(h) and slot in (None, s):
                return s                      # the same message again: the same key, the same signature
        free = [s for s in (0, 1) if s not in used]
        if slot is not None:
            if slot in used:
                raise Refused(f"slot {slot} at nonce {nonce} already signed {used[slot]}")
            return slot
        if not free:
            raise Refused(f"both keys for nonce {nonce} are used: wait for one of those transactions")
        return free[0]

    def record(self, account, start, nonce, slot, h, note=""):
        if any(e["account"] == b2h(account) and e["start"] == start and e["nonce"] == nonce and e["slot"] == slot
               and e["sig_hash"] == b2h(h) for e in self.entries):
            return
        self.entries.append({"account": b2h(account), "start": start, "nonce": nonce, "slot": slot,
                             "sig_hash": b2h(h), "note": note, "t": int(time.time())})
        _write_secret(self.path, self.entries)


class Refused(Exception):
    pass


def wots_signature(account, tree, sk_seed, start, nonce, h, slot=None, note="") -> bytes:
    """[slot][WOTS signature][path] for the transaction with sig hash h at `nonce`, after recording the key"""
    log = KeyLog()
    slot = log.pick(account, start, nonce, h, slot)
    log.record(account, start, nonce, slot, h, note)
    k = 2 * (nonce - start) + slot
    sig = wots.sign(tree.seed, sk_seed, k, h, wots.Prf.SIGNER)
    path = tree.path(k)
    if wots.verify_root(tree.seed, k, h, sig, path) != tree.root:
        raise RuntimeError("the WOTS signature failed its own check: not released")
    return bytes([slot]) + sig + path


# --- transactions from the account -------------------------------------------------------------------------------------

def account_tx(account, frames, sig_len):
    return {"chain_id": CHAIN_ID, "nonce": nonce_of(account), "sender": account, "frames": frames,
            "signatures": [{"scheme": ARBITRARY, "signer": b"", "msg": b"", "signature": bytes(sig_len)}],
            "max_priority_fee": PRIORITY_FEE, "max_fee": MAX_FEE}


def deploy_frame(account, init, frames, names):
    if not code_at(account):
        frames.append(frame(DEFAULT, CREATE2_DEPLOYER, 60_000, 450_000, data=bytes(32) + init))
        names.append("DEFAULT: deploy the account")


def sign_member(tx, key):
    h = sig_hash(tx)
    t0 = time.time()
    tx["signatures"][0]["signature"] = key.sign(h)
    print(f"signed {b2h(h)} with the member key in {time.time() - t0:.1f} s (5,684 bytes)")


def report(tx, r, names, account):
    show_receipt(r, names)
    t = stored_tree(account) if code_at(account) else None
    print(f"  account {b2h(account)}: nonce {nonce_of(account)}, balance {balance(account) / 1e18:.6f} ETH"
          + (f", tree from nonce {t[1]}, height {t[2]}" if t else ""))


def cmd_send(version, to, value, member=False, slot=None):
    key, account, init = load_member(version)
    frames, names = [], []
    deploy_frame(account, init, frames, names)
    t = load_tree(account) if version == "v1" and code_at(account) and not member else None
    nonce = nonce_of(account)
    if t and not (t[2] <= nonce < t[2] + (1 << (t[0].height - 1))):
        print(f"nonce {nonce} is outside the tree: signing with the member key")
        t = None
    sig_len = 1 + wots.SIG_BYTES + wots.N * t[0].height if t else SIG_LEN
    frames.append(frame(VERIFY, account, 75_000, flags=3))
    names.append("VERIFY: one-time key" if t else "VERIFY: member key")
    frames.append(frame(SENDER, to, 100_000, 300_000, value=value))
    names.append("SENDER: the call")
    tx = account_tx(account, frames, sig_len)
    if t:
        tree, sk_seed, start = t
        t0 = time.time()
        tx["signatures"][0]["signature"] = wots_signature(account, tree, sk_seed, start, nonce, sig_hash(tx), slot,
                                                          "send")
        sig = tx["signatures"][0]["signature"]
        print(f"signed {b2h(sig_hash(tx))} with one-time key {2 * (nonce - start) + sig[0]} (nonce {nonce}, "
              f"slot {sig[0]}) in {time.time() - t0:.2f} s ({len(sig):,} bytes)")
    else:
        sign_member(tx, key)
    _, r = submit(tx, "frame transaction")
    report(tx, r, names, account)


def cmd_enroll(height):
    key, account, init = load_member("v1")
    deploying = not code_at(account)
    nonce = nonce_of(account)
    # the enrolment uses `nonce`; a counterfactual account also gets EIP-161's nonce 1 when it's deployed
    start = 2 if deploying and nonce == 0 else nonce + 1
    sk_seed = os.urandom(32)
    t0 = time.time()
    tree = wots.Tree.create(tree_seed(account, start), sk_seed, height, workers=os.cpu_count())
    print(f"made a tree of height {height} ({1 << height} keys, nonces {start}..{start + (1 << (height - 1)) - 1}) "
          f"in {time.time() - t0:.1f} s, root {b2h(tree.root)}")
    _write_secret(tree_path(account, start), {"sk_seed": sk_seed.hex(), "height": height, "start": start,
                                              "root": b2h(tree.root), "cache": tree.to_bytes().hex(),
                                              "note": "throwaway, Daisugi test only"})
    frames, names = [], []
    deploy_frame(account, init, frames, names)
    frames.append(frame(VERIFY, account, 75_000, flags=3))
    names.append("VERIFY: member key")
    data = ENROLL_SELECTOR + tree.root + bytes(8) + word(height) + word(start)
    frames.append(frame(SENDER, account, 60_000, 300_000, data=data))
    names.append("SENDER: enroll the tree")
    tx = account_tx(account, frames, SIG_LEN)
    sign_member(tx, key)
    _, r = submit(tx, "enrolment")
    _note_enrolment(account, int(r["blockNumber"], 16))
    report(tx, r, names, account)


def cmd_attacks():
    """Transactions the account must refuse, then a one-time-key transaction that tries to enroll a tree"""
    key, account, _ = load_member("v1")
    tree, sk_seed, start = load_tree(account)
    nonce = nonce_of(account)
    dead = b"\x00" * 18 + b"\xde\xad"
    sig_len = 1 + wots.SIG_BYTES + wots.N * tree.height

    def tx_to(frames_after):
        return account_tx(account, [frame(VERIFY, account, 75_000, flags=3)] + frames_after, sig_len)

    def try_send(label, tx):
        try:
            h = rpc("eth_sendRawTransaction", b2h(encode(tx)))
            print(f"{label}: ACCEPTED {h}  <-- should have been refused")
        except RpcError as e:
            print(f"{label}: refused ({e})")

    base = tx_to([frame(SENDER, dead, 100_000, 300_000, value=10**15)])
    h = sig_hash(base)
    # 1. the next nonce's key on this nonce's transaction (recorded, so the real transaction at nonce + 1 uses slot 1)
    tx = base | {"signatures": [dict(base["signatures"][0])]}   # same frames, own signature entry
    k_next = wots_signature(account, tree, sk_seed, start, nonce + 1, h, 0, "attack: next nonce's key")
    tx["signatures"][0]["signature"] = k_next
    try_send(f"key of nonce {nonce + 1} on nonce {nonce}", tx)
    # 2. this nonce's key, slot byte 2
    good = wots_signature(account, tree, sk_seed, start, nonce, h, None, "attack base (also sent below)")
    tx["signatures"][0]["signature"] = bytes([2]) + good[1:]
    try_send("slot byte 2", tx)
    # 3. a path node changed
    bad = bytearray(good)
    bad[-1] ^= 1
    tx["signatures"][0]["signature"] = bytes(bad)
    try_send("one path bit flipped", tx)
    # 4. the member-key length with garbage
    tx2 = account_tx(account, [frame(VERIFY, account, 75_000, flags=3), frame(SENDER, dead, 100_000, 300_000)],
                     SIG_LEN)
    tx2["signatures"][0]["signature"] = bytes(SIG_LEN)
    try_send("5,684 zero bytes as a member-key signature", tx2)
    # 5. the good signature, sent: it must be included
    tx["signatures"][0]["signature"] = good
    _, r = submit(tx, f"the valid one-time-key transaction at nonce {nonce}")
    show_receipt(r, ["VERIFY: one-time key", "SENDER"])
    # 6. replaying it
    try_send("the same transaction again", tx)
    # 7. a one-time-key transaction that tries to install its own tree
    before = stored_tree(account)
    n2 = nonce_of(account)
    evil_root = keccak256(b"not the member's tree")[:24]
    tx3 = tx_to([frame(SENDER, account, 60_000, 300_000,
                       data=ENROLL_SELECTOR + evil_root + bytes(8) + word(10) + word(n2 + 5))])
    tx3["signatures"][0]["signature"] = wots_signature(account, tree, sk_seed, start, n2, sig_hash(tx3), None,
                                                       "attack: enroll from a one-time key")
    _, r = submit(tx3, "a one-time-key transaction that calls enroll")
    show_receipt(r, ["VERIFY: one-time key", "SENDER: enroll"])
    print("  stored tree unchanged:", stored_tree(account) == before)


def cmd_replace():
    """Slot 1: a transaction at nonce n signed with slot 0 but never sent (as if stuck), then its replacement"""
    _, account, _ = load_member("v1")
    tree, sk_seed, start = load_tree(account)
    nonce = nonce_of(account)
    dead = b"\x00" * 18 + b"\xde\xad"
    sig_len = 1 + wots.SIG_BYTES + wots.N * tree.height
    stuck = account_tx(account, [frame(VERIFY, account, 75_000, flags=3),
                                 frame(SENDER, dead, 100_000, 300_000, value=10**15)], sig_len)
    stuck["max_priority_fee"] = 1     # a fee too low to matter: never sent
    wots_signature(account, tree, sk_seed, start, nonce, sig_hash(stuck), None, "replace: the stuck one")
    print(f"nonce {nonce}: signed a first version with slot 0 and kept it back")
    cmd_send("v1", dead, 10**15)
    try:
        third = account_tx(account, stuck["frames"], sig_len)
        third["nonce"] = nonce
        third["max_priority_fee"] = 3 * PRIORITY_FEE
        wots_signature(account, tree, sk_seed, start, nonce, sig_hash(third), None, "replace: a third version")
        print("a third version at the same nonce was signed  <-- the key log should refuse")
    except Refused as e:
        print(f"a third version at nonce {nonce}: refused by the key log ({e})")


def cmd_vector():
    fixture = os.path.join(HERE, "vectors.json")
    for v in json.load(open(fixture)):
        tx = from_rpc(v["tx"])
        ok_hash = tx_hash(tx) == h2b(v["tx"]["hash"])
        ok_sig = sig_hash(tx) == h2b(v["sig_hash"])
        print(f"{v['tx']['hash']}: tx hash {'ok' if ok_hash else 'WRONG'}, sig hash {'ok' if ok_sig else 'WRONG'}"
              f" ({v['why']})")
        if not (ok_hash and ok_sig):
            sys.exit(1)


def main(argv):
    if not argv:
        sys.exit(__doc__)
    c, rest = argv[0], argv[1:]

    def opt(name, default=None, cast=str):
        return cast(rest[rest.index(name) + 1]) if name in rest else default

    version = opt("--account", "v1")
    try:
        if c == "vector":
            cmd_vector()
        elif c == "deploy":
            cmd_deploy()
        elif c == "member":
            cmd_member(version)
        elif c == "fund":
            cmd_fund(version)
        elif c == "enroll":
            cmd_enroll(opt("--height", 10, int))
        elif c == "send":
            cmd_send(version, opt("--to", b"\x00" * 18 + b"\xde\xad", h2b), opt("--value", 10**16, int),
                     member="--member" in rest, slot=opt("--slot", None, int))
        elif c == "attacks":
            cmd_attacks()
        elif c == "replace":
            cmd_replace()
        else:
            sys.exit(__doc__)
    except Refused as e:
        sys.exit(f"refused: {e}")


if __name__ == "__main__":
    main(sys.argv[1:])
