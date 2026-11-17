#!/usr/bin/env python3
"""Device keys on Daisugi: the v2 frame account (frame/WinterlockFrameAccountV2.yul), and with `--account v3`
the v3 account (frame/WinterlockFrameAccountV3.yul), which checks each key's scope in VERIFY.

  status                          the account's devices and trees
  add N [--fresh]                 the member key adds device N (1–3); --fresh retires the device's home and makes a
                                  new key, as a re-added or replaced device would
  revoke N                        the member key revokes device N
  enroll --as N [--height H]      device N's key (N = 0: the member key) enrols its own tree of one-time keys
  send --as N [--stateless] [--to A] [--value WEI]
                                  a transfer signed by device N: a one-time key while its tree covers the nonce,
                                  else (or with --stateless) the device's key
  demo                            the scenario in decisions.md, with a check after each step
  --account v3                    work on the v3 account. There `add N [--own-tree]` gives device N the scope
                                  OWN_TREE (it may enrol its own tree) or none; `enroll --as 0 --for N` lets the
                                  member key enrol device N's tree; and:
  deploy                          v3: deploy the implementation, if it isn't there
  demo                            v3: the scenario of decisions.md's v3 entry: what each scope may send, and that
                                  VERIFY refuses the rest before inclusion; prints a gas table
  frames [--as N] [--stateless]   v3: transfers with 1, 8, 32 and 62 SENDER frames, for the cost of the frame walk

Each device has a home in $DAISUGI_DIR/device-N/: its own random seed (no phrase), its trees and its key log. Device
0 is the member key, from $DAISUGI_DIR/member.json (made by daisugi.py). Run with the signer's Python:
  DAISUGI_DIR=/scratch/dir ../signer/.venv/bin/python -I bench/daisugi/devices.py <command>
"""

import importlib.util
import json
import os
import sys
import time

_spec = importlib.util.spec_from_file_location("daisugi", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                         "daisugi.py"))
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)
wots, wmember, wleansphincs, keccak256 = d.wots, d.wmember, d.wleansphincs, d.keccak256

VERSION = sys.argv[sys.argv.index("--account") + 1] if "--account" in sys.argv else "v2"
if VERSION not in ("v2", "v3"):
    sys.exit("--account v2|v3")
TREE_SEED_DOMAIN = keccak256(b"Winterlock.frame-account.tree-seed.v2")      # v3 keeps v2's domain
SEL = {name: keccak256(sig.encode())[:4] for name, sig in (
    ("enroll", "enroll(uint8,bytes32,uint8,uint64)"),
    ("addDevice", "addDevice(uint8,bytes32,uint8)" if VERSION == "v3" else "addDevice(uint8,bytes32)"),
    ("revokeDevice", "revokeDevice(uint8)"), ("read", "read(uint256)"))}
ACTIVE = 1 << 16
OWN_TREE = 1 << 17      # v3: the device's key may enrol its own tree; without it, it may send the account nothing
STATELESS_LEN = 2 + 5684
DEAD = b"\x00" * 18 + b"\xde\xad"


# --- the account -------------------------------------------------------------------------------------------------

def account():
    key, acct, init = d.load_member(VERSION)
    return key, acct, init


def read(acct: bytes, slot: int) -> int:
    if not d.code_at(acct):
        return 0
    return int(d.rpc("eth_call", {"to": d.b2h(acct), "data": d.b2h(SEL["read"] + d.word(slot))}, "latest"), 16)


def device_state(acct, device):
    """(active, generation, key root ‖ P or None)"""
    if device == 0:
        return True, 0, None
    st = read(acct, 0x20 + device)
    return bool(st & ACTIVE), st & 0xffff, read(acct, 0x10 + device).to_bytes(32, "big")


def tree_word(acct, device):
    w = read(acct, device)
    if not w:
        return None
    return {"root": w.to_bytes(32, "big")[:24], "generation": (w >> 48) & 0xffff, "start": (w >> 8) & ((1 << 40) - 1),
            "height": w & 0xff}


def tree_seed(acct: bytes, device: int, generation: int, start: int) -> int:
    pre = TREE_SEED_DOMAIN + d.word(d.CHAIN_ID) + d.word(acct) + d.word(device) + d.word(generation) + d.word(start)
    return int.from_bytes(keccak256(pre)[:16], "big")


# --- devices: homes, keys, trees, key logs -------------------------------------------------------------------------

def home(device: int) -> str:
    h = os.path.join(d.member_dir(), f"device-{device}")
    os.makedirs(h, exist_ok=True)
    return h


def make_device(device: int, fresh=False) -> bytes:
    """Device N's key (root ‖ P), from the device's own random seed; makes it on first use"""
    path = os.path.join(home(device), "device.json")
    if fresh and os.path.exists(path):
        os.rename(home(device), home(device) + f".retired-{int(time.time())}")
        home(device)                                  # a new, empty home
    if not os.path.exists(path):
        seed = os.urandom(32)
        key = wmember.stateless_key(seed, wmember.DEVICE_KEY_LABEL)
        d._write_secret(path, {"seed": seed.hex(), "kept_leaves": key.kept_leaves_bytes().hex(),
                               "note": "throwaway device seed, Daisugi test only"})
    return signer_key(device).public_key


def signer_key(device: int):
    if device == 0:
        return account()[0]
    rec = json.load(open(os.path.join(home(device), "device.json")))
    leaves = bytes.fromhex(rec["kept_leaves"])
    return wleansphincs.Key(wmember._abi_label(wmember.DEVICE_KEY_LABEL, bytes.fromhex(rec["seed"])),
                            wmember.STATELESS_B, kept_leaves=[leaves[i:i + 16] for i in range(0, len(leaves), 16)])


def tree_file(device, acct, generation, start):
    return os.path.join(home(device), f"tree-{acct.hex()}-g{generation}-{start}.json")


def load_tree(device, acct):
    """(tree, sk_seed, stored word) for the device's stored tree, if this home holds it and it's usable"""
    w = tree_word(acct, device)
    if not w:
        return None
    path = tree_file(device, acct, w["generation"], w["start"])
    if not os.path.exists(path):
        return None
    rec = json.load(open(path))
    tree = wots.Tree.from_bytes(bytes.fromhex(rec["cache"]))
    if tree.root != w["root"] or tree.seed != tree_seed(acct, device, w["generation"], w["start"]):
        return None
    return tree, bytes.fromhex(rec["sk_seed"]), w


class KeyLog:
    """Per device home: every one-time key, recorded and synced before it signs; at most one message per key"""

    def __init__(self, device):
        self.path = os.path.join(home(device), "keylog.json")
        self.entries = json.load(open(self.path)) if os.path.exists(self.path) else []

    def take(self, where: dict, nonce: int, h: bytes, note: str) -> int:
        mine = [e for e in self.entries if all(e[k] == v for k, v in where.items()) and e["nonce"] == nonce]
        for e in mine:
            if e["sig_hash"] == d.b2h(h):
                return e["slot"]
        free = [s for s in (0, 1) if s not in {e["slot"] for e in mine}]
        if not free:
            raise d.Refused(f"both keys for nonce {nonce} are used")
        self.entries.append(where | {"nonce": nonce, "slot": free[0], "sig_hash": d.b2h(h), "note": note,
                                     "t": int(time.time())})
        d._write_secret(self.path, self.entries)
        return free[0]


def sign(device, acct, tx, stateless=False, note="", tree_override=None):
    """Fills in tx's signature as device `device`: [slot][device][WOTS][path] or [2][device][leanSphincs]"""
    t = tree_override or (None if stateless else load_tree(device, acct))
    if t:
        tree, sk_seed, w = t
        if not (w["start"] <= tx["nonce"] < w["start"] + (1 << (tree.height - 1))):
            t = None
    if t:
        tree, sk_seed, w = t
        tx["signatures"][0]["signature"] = bytes(2 + wots.SIG_BYTES + wots.N * tree.height)
        h = d.sig_hash(tx)
        where = {"account": d.b2h(acct), "device": device, "generation": w["generation"], "start": w["start"]}
        slot = KeyLog(device).take(where, tx["nonce"], h, note)
        k = 2 * (tx["nonce"] - w["start"]) + slot
        sig, path = wots.sign(tree.seed, sk_seed, k, h, wots.Prf.SIGNER), tree.path(k)
        if wots.verify_root(tree.seed, k, h, sig, path) != tree.root:
            raise RuntimeError("the WOTS signature failed its own check: not released")
        tx["signatures"][0]["signature"] = bytes([slot, device]) + sig + path
        return f"device {device}, one-time key {k} (nonce {tx['nonce']}, slot {slot})"
    tx["signatures"][0]["signature"] = bytes(STATELESS_LEN)
    h = d.sig_hash(tx)
    tx["signatures"][0]["signature"] = bytes([2, device]) + signer_key(device).sign(h)
    return f"device {device}'s key" if device else "the member key"


def build(acct, init, frames_after_verify, verify_gas=75_000):
    frames, names = [], []
    d.deploy_frame(acct, init, frames, names)
    frames.append(d.frame(d.VERIFY, acct, verify_gas, flags=3))
    names.append("VERIFY")
    for f, name in frames_after_verify:
        frames.append(f)
        names.append(name)
    return d.account_tx(acct, frames, STATELESS_LEN), names


def manage_frame(acct, data, name):
    return d.frame(d.SENDER, acct, 100_000, 300_000, data=data), name


GAS = []        # (label, gas used, VERIFY execution gas, transaction bytes), for the table at the end of a demo


def run(device, frames_after_verify, label, stateless=False, expect=True, verify_gas=75_000):
    """Builds, signs as `device`, sends; returns the receipt, or None if the node refused (printed either way)"""
    _, acct, init = account()
    tx, names = build(acct, init, frames_after_verify, verify_gas)
    who = sign(device, acct, tx, stateless, label)
    try:
        _, r = d.submit(tx, f"{label} [{who}]")
    except d.RpcError as e:
        print(f"{label} [{who}]: refused ({e})")
        check(not expect, f"{label}: refused" if not expect else f"{label}: expected inclusion")
        return None
    frames = d.show_receipt(r, names)
    gu = frames[names.index("VERIFY")].get("gasUsed")
    ex = gu.get("execution") if isinstance(gu, dict) else gu[0] if isinstance(gu, list) else gu
    GAS.append((f"{label} [{who}]", int(r["gasUsed"], 16), int(ex, 16), len(d.encode(tx))))
    if not expect:
        check(False, f"{label}: expected a refusal, got included")
    return r


RESULTS = []


def check(ok, what):
    RESULTS.append((ok, what))
    print(f"  {'PASS' if ok else 'FAIL'}: {what}")


def frame_status(r, i):
    fr = (r.get("frameReceipts") or r.get("frames"))[i]
    s = fr.get("status")
    return int(s, 16) if isinstance(s, str) else s


# --- commands ----------------------------------------------------------------------------------------------------------

def cmd_status():
    key, acct, _ = account()
    print(f"{VERSION} account {d.b2h(acct)}: code {len(d.code_at(acct))} bytes, nonce {d.nonce_of(acct)}, "
          f"balance {d.balance(acct) / 1e18:.4f} ETH")
    for dev in range(4):
        active, gen, k = device_state(acct, dev)
        w = tree_word(acct, dev)
        label = "member key" if dev == 0 else (f"key {d.b2h(k)[:18]}…" if k and int.from_bytes(k, 'big') else "no key")
        tree = (f"tree g{w['generation']} from nonce {w['start']}, height {w['height']}" if w else "no tree")
        own = ", OWN_TREE" if dev and read(acct, 0x20 + dev) & OWN_TREE else ""
        print(f"  device {dev}: {label}, generation {gen}, {'active' if active else 'inactive'}{own}; {tree}")


def add_frames(acct, devices, fresh=False, own_tree=()):
    """addDevice frames; v3 takes a scope: OWN_TREE for the devices in `own_tree`, nothing for the others"""
    out = []
    for n in devices:
        key = make_device(n, fresh)
        scope = d.word(1 if n in own_tree else 0) if VERSION == "v3" else b""
        out.append(manage_frame(acct, SEL["addDevice"] + d.word(n) + key + scope,
                                f"SENDER: addDevice({n}" + (", OWN_TREE)" if n in own_tree else ")")))
    return out


def small_transfers(n, to=DEAD):
    """n SENDER frames of 1 wei each to an account that exists, with small limits"""
    return [(d.frame(d.SENDER, to, 30_000, 0, value=1), f"SENDER: transfer {k + 1}/{n}") for k in range(n)]


def gas_table():
    if not GAS:
        return
    print(f"\n{'transaction':<78} {'gas used':>9} {'VERIFY':>7} {'bytes':>6}")
    for label, used, verify, size in GAS:
        print(f"{label[:78]:<78} {used:>9,} {verify:>7,} {size:>6,}")


def enroll_frames(device, acct, height):
    nonce = d.nonce_of(acct)
    _, gen, _ = device_state(acct, device)
    start = (2 if not d.code_at(acct) and nonce == 0 else nonce + 1)
    sk_seed = os.urandom(32)
    tree = wots.Tree.create(tree_seed(acct, device, gen, start), sk_seed, height, workers=os.cpu_count())
    d._write_secret(tree_file(device, acct, gen, start), {"sk_seed": sk_seed.hex(), "cache": tree.to_bytes().hex(),
                                                          "note": "throwaway, Daisugi test only"})
    data = SEL["enroll"] + d.word(device) + tree.root + bytes(8) + d.word(height) + d.word(start)
    return [manage_frame(acct, data, f"SENDER: enroll({device}), nonces {start}..{start + (1 << (height - 1)) - 1}")]


def transfer(value=10**15, to=DEAD):
    return [(d.frame(d.SENDER, to, 100_000, 300_000, value=value), "SENDER: transfer")]


def cmd_deploy():
    """The implementation of this account version, from the deployer key (CREATE2; skips what exists)"""
    acct = d.deployer()
    salt, init = d.account_salt(VERSION), d.account_init(VERSION)
    addr = d.create2(salt, init)
    print(f"deployer {acct.address}, {d.balance(d.h2b(acct.address)) / 1e18:.4f} ETH")
    if d.code_at(addr):
        print(f"frame account {VERSION}: at {d.b2h(addr)} already ({len(d.code_at(addr))} bytes)")
        return
    _, r = d.eoa_tx(acct, [d.frame(d.SENDER, d.CREATE2_DEPLOYER, 1_500_000, 1_500_000, data=salt + init)],
                    f"deploy frame account {VERSION}")
    d.show_receipt(r, ["VERIFY (default code)", "SENDER: CREATE2"])
    print(f"  frame account {VERSION} at {d.b2h(addr)}: {len(d.code_at(addr))} bytes")


def cmd_demo3():
    """v3: device 1 has OWN_TREE, device 2 has no scope; what VERIFY lets each send to the account"""
    key, acct, init = account()
    print(f"v3 account {d.b2h(acct)}")
    if d.balance(acct) < 10**17:
        d.cmd_fund(VERSION)
        time.sleep(8)

    def refused(device, frames, label, stateless=True):
        n = d.nonce_of(acct)
        run(device, frames, label, stateless=stateless, expect=False)
        check(d.nonce_of(acct) == n, f"{label}: the nonce didn't move")

    print("\n1. The member key adds device 1 with OWN_TREE and device 2 without (the transaction deploys the account)")
    r = run(0, add_frames(acct, [1, 2], own_tree=(1,)), "add devices 1 (OWN_TREE) and 2")
    s1, s2 = read(acct, 0x21), read(acct, 0x22)
    check(r and s1 == (1 | ACTIVE | OWN_TREE) and s2 == (1 | ACTIVE), "device 1 active with OWN_TREE, device 2 active without")

    print("\n2. Device 1 enrols its own tree with its own key; the member key enrols device 2's")
    r = run(1, enroll_frames(1, acct, 10), "device 1 enrols its own tree")
    check(r and frame_status(r, 1) == 1 and tree_word(acct, 1), "device 1's tree stored")
    refused(2, enroll_frames(2, acct, 4), "device 2 (no scope) enrols its own tree")
    r = run(0, enroll_frames(2, acct, 10), "the member key enrols device 2's tree")
    check(r and frame_status(r, 1) == 1 and tree_word(acct, 2), "device 2's tree stored")

    print("\n3. Transfers: each device's one-time key, each device's key, the member key")
    for dev in (1, 2):
        r = run(dev, transfer(), f"device {dev} sends, one-time key")
        check(r and frame_status(r, 1) == 1, f"device {dev}'s one-time key accepted")
    for dev in (1, 2):
        r = run(dev, transfer(), f"device {dev} sends, its key", stateless=True)
        check(r and frame_status(r, 1) == 1, f"device {dev}'s key accepted")
    r = run(0, transfer(), "the member key sends", stateless=True)
    check(r and frame_status(r, 1) == 1, "member key accepted")

    print("\n4. What v2 included and reverted, VERIFY now refuses: nothing is included, the nonce stays")
    revoke = lambda n: [manage_frame(acct, SEL["revokeDevice"] + d.word(n), f"SENDER: revokeDevice({n})")]
    refused(2, revoke(1), "device 2 revokes device 1")
    refused(1, revoke(2), "device 1 (OWN_TREE) revokes device 2")
    refused(1, [manage_frame(acct, SEL["addDevice"] + d.word(3) + keccak256(b"x") + d.word(1), "SENDER: addDevice(3)")],
            "device 1 adds device 3")
    evil = keccak256(b"not device 2's tree")[:24] + bytes(8)
    refused(1, [manage_frame(acct, SEL["enroll"] + d.word(2) + evil + d.word(10) + d.word(10**6), "SENDER: enroll(2)")],
            "device 1 enrols a tree for device 2")
    refused(1, transfer() + revoke(2), "device 1: a transfer, then revoke device 2, in one transaction")
    refused(1, enroll_frames(1, acct, 4), "device 1 enrols its own tree with a one-time key", stateless=False)
    refused(1, [(d.frame(d.SENDER, acct, 30_000, 0, value=1), "SENDER: 1 wei to the account itself")],
            "device 1 sends the account 1 wei")
    check(tree_word(acct, 2)["root"] != evil[:24] and read(acct, 0x22) & ACTIVE and not read(acct, 0x23),
          "nothing changed: device 2's tree and state, no device 3")

    print("\n5. In scope: device 1 enrols a new tree and sends a transfer in one transaction, with its key")
    before = tree_word(acct, 1)
    r = run(1, enroll_frames(1, acct, 4) + transfer(), "device 1: enroll its own tree, then a transfer", stateless=True)
    check(r and frame_status(r, 1) == 1 and frame_status(r, 2) == 1 and tree_word(acct, 1) != before,
          "both frames ran; device 1 has a new tree")

    print("\n6. The member key revokes device 1; its keys stop; device 2 and the member key go on")
    r = run(0, revoke(1), "revoke device 1")
    check(r and frame_status(r, 1) == 1 and read(acct, 0x21) == 1, "device 1 inactive, scope cleared, generation kept")
    run(1, transfer(), "device 1's one-time key after the revocation", stateless=False, expect=False)
    run(1, transfer(), "device 1's key after the revocation", stateless=True, expect=False)
    r = run(2, transfer(), "device 2 sends after device 1's revocation")
    check(r and frame_status(r, 1) == 1, "device 2 unaffected")

    print()
    cmd_status()
    gas_table()
    bad = [w for ok, w in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(bad)} of {len(RESULTS)} checks passed" + (f"; FAILED: {bad}" if bad else ""))
    sys.exit(1 if bad else 0)


def cmd_frames(device, stateless):
    """v3: the cost of VERIFY's walk over the frames, from transfers with more and more SENDER frames"""
    _, acct, _ = account()
    for n in (1, 8, 32, 62):
        r = run(device, small_transfers(n), f"{n} SENDER frame(s)", stateless=stateless, verify_gas=95_000)
        check(r and all(frame_status(r, k) == 1 for k in range(1, n + 1)), f"{n} transfer frame(s) ran")
    gas_table()


def cmd_demo(first=1):
    key, acct, init = account()
    print(f"v2 account {d.b2h(acct)}")
    if d.balance(acct) < 10**17:
        d.cmd_fund(VERSION)
        time.sleep(6)

    old_tree = load_tree(1, acct)       # device 1's generation-1 tree, for step 7
    if first <= 1:
        print("\n1. The member key adds devices 1 and 2 (the transaction also deploys the account)")
        r = run(0, add_frames(acct, [1, 2]), "add devices 1 and 2")
        check(r and device_state(acct, 1)[:2] == (True, 1) and device_state(acct, 2)[:2] == (True, 1),
              "devices 1 and 2 active at generation 1")

    if first <= 2:
        print("\n2. Each device enrols its own tree with its own key")
        for dev in (1, 2):
            r = run(dev, enroll_frames(dev, acct, 10), f"device {dev} enrols")
            check(r and frame_status(r, 1) == 1 and tree_word(acct, dev), f"device {dev}'s tree stored")

    if first <= 3:
        print("\n3. Each device signs a transfer with a one-time key")
        for dev in (1, 2):
            r = run(dev, transfer(), f"device {dev} sends")
            check(r and frame_status(r, 1) == 1, f"device {dev}'s one-time key accepted")

    if first <= 4:
        print("\n4. Both devices sign a different transaction at the same nonce")
        n = d.nonce_of(acct)
        txs = []
        for dev, value in ((1, 2 * 10**15), (2, 3 * 10**15)):
            tx, names = build(acct, init, transfer(value))
            txs.append((dev, tx, sign(dev, acct, tx, note="same-nonce race")))
        outcomes = []
        for dev, tx, who in txs:
            try:
                h = d.rpc("eth_sendRawTransaction", d.b2h(d.encode(tx)))
                outcomes.append((dev, "accepted", h))
            except d.RpcError as e:
                outcomes.append((dev, f"refused: {e}", None))
        for dev, what, _ in outcomes:
            print(f"  device {dev} at nonce {n}: {what}")
        included = []
        for _ in range(45):
            included = [dev for dev, _, h in outcomes if h and d.rpc("eth_getTransactionReceipt", h)]
            if included:
                break
            time.sleep(2)
        check(d.nonce_of(acct) == n + 1 and len(included) == 1,
              f"exactly one of the two included (device {included}); each device used its own tree's key")

    if first <= 5:
        print("\n5. Device 2 tries what only the member key or device 1 may do (signed with device 2's own key)")
        r = run(2, [manage_frame(acct, SEL["revokeDevice"] + d.word(1), "SENDER: revokeDevice(1)")], "device 2 revokes 1",
                stateless=True)
        check(r and frame_status(r, 1) == 0 and device_state(acct, 1)[0], "revoke by device 2 reverted; device 1 active")
        r = run(2, [manage_frame(acct, SEL["addDevice"] + d.word(3) + keccak256(b"x"), "SENDER: addDevice(3)")],
                "device 2 adds device 3", stateless=True)
        check(r and frame_status(r, 1) == 0 and not device_state(acct, 3)[0], "add by device 2 reverted")
        evil = keccak256(b"not device 1's tree")[:24] + bytes(8)
        r = run(2, [manage_frame(acct, SEL["enroll"] + d.word(1) + evil + d.word(10) + d.word(10**6),
                                 "SENDER: enroll(1)")], "device 2 enrols a tree for device 1", stateless=True)
        check(r and frame_status(r, 1) == 0 and tree_word(acct, 1)["root"] != evil[:24], "enroll for device 1 reverted")
        before = tree_word(acct, 2)
        r = run(2, enroll_frames(2, acct, 4), "device 2 enrols its own tree, signed with a one-time key")
        check(r and frame_status(r, 1) == 0 and tree_word(acct, 2) == before, "a one-time key can't enroll")

    if first <= 6:
        print("\n6. The member key revokes device 1")
        r = run(0, [manage_frame(acct, SEL["revokeDevice"] + d.word(1), "SENDER: revokeDevice(1)")], "revoke device 1")
        check(r and frame_status(r, 1) == 1 and not device_state(acct, 1)[0], "device 1 inactive")
        run(1, transfer(), "device 1's one-time key after the revocation", expect=False)
        run(1, transfer(), "device 1's key after the revocation", stateless=True, expect=False)
        r = run(2, transfer(), "device 2 after device 1's revocation")
        check(r and frame_status(r, 1) == 1, "device 2 unaffected")

    if first <= 7:
        print("\n7. The member key adds device 1 again, with a new key (generation 2)")
        old_key = signer_key(1)
        r = run(0, add_frames(acct, [1], fresh=True), "re-add device 1")
        check(r and device_state(acct, 1)[:2] == (True, 2), "device 1 active at generation 2")
        if old_tree:
            tree, sk_seed, w = old_tree
            tx, _ = build(acct, init, transfer())
            # generation 1's tree, still stored for device 1; its key is logged in the new home's key log
            try:
                sign(1, acct, tx, note="old generation's tree", tree_override=(tree, sk_seed, w))
                d.rpc("eth_sendRawTransaction", d.b2h(d.encode(tx)))
                check(False, "generation 1's tree after the re-add: expected a refusal")
            except d.RpcError as e:
                print(f"generation 1's tree after the re-add: refused ({e})")
                check(True, "generation 1's tree refused")
        tx, _ = build(acct, init, transfer())
        tx["signatures"][0]["signature"] = bytes(STATELESS_LEN)
        tx["signatures"][0]["signature"] = bytes([2, 1]) + old_key.sign(d.sig_hash(tx))
        try:
            d.rpc("eth_sendRawTransaction", d.b2h(d.encode(tx)))
            check(False, "device 1's old key after the re-add: expected a refusal")
        except d.RpcError as e:
            print(f"device 1's old key after the re-add: refused ({e})")
            check(True, "device 1's old key refused")
        r = run(1, enroll_frames(1, acct, 10), "the new device 1 enrols")
        check(r and frame_status(r, 1) == 1, "new device 1's tree stored")
        r = run(1, transfer(), "the new device 1 sends")
        check(r and frame_status(r, 1) == 1, "new device 1's one-time key accepted")

    if first <= 8:
        print("\n8. The member key still signs by itself")
        r = run(0, transfer(), "the member key sends", stateless=True)
        check(r and frame_status(r, 1) == 1, "member key accepted")

    print()
    cmd_status()
    gas_table()
    bad = [w for ok, w in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(bad)} of {len(RESULTS)} checks passed" + (f"; FAILED: {bad}" if bad else ""))
    sys.exit(1 if bad else 0)


def main(argv):
    if not argv:
        sys.exit(__doc__)
    c, rest = argv[0], argv[1:]

    def opt(name, default=None, cast=str):
        return cast(rest[rest.index(name) + 1]) if name in rest else default

    _, acct, _ = account()
    try:
        if c == "status":
            cmd_status()
        elif c == "deploy" and VERSION == "v3":
            cmd_deploy()
        elif c == "frames" and VERSION == "v3":
            cmd_frames(opt("--as", 1, int), "--stateless" in rest)
        elif c == "add":
            run(0, add_frames(acct, [int(rest[0])], fresh="--fresh" in rest,
                              own_tree=(int(rest[0]),) if "--own-tree" in rest else ()), f"add device {rest[0]}")
        elif c == "revoke":
            n = int(rest[0])
            run(0, [manage_frame(acct, SEL["revokeDevice"] + d.word(n), f"SENDER: revokeDevice({n})")],
                f"revoke device {n}")
        elif c == "enroll":
            n = opt("--as", 0, int)
            target = opt("--for", n, int)
            run(n, enroll_frames(target, acct, opt("--height", 10, int)), f"device {n} enrols device {target}'s tree")
        elif c == "send":
            run(opt("--as", 0, int), transfer(opt("--value", 10**15, int), opt("--to", DEAD, d.h2b)),
                "transfer", stateless="--stateless" in rest)
        elif c == "demo":
            cmd_demo3() if VERSION == "v3" else cmd_demo(opt("--from", 1, int))
        else:
            sys.exit(__doc__)
    except d.Refused as e:
        sys.exit(f"refused: {e}")


if __name__ == "__main__":
    main(sys.argv[1:])
