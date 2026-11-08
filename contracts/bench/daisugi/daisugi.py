#!/usr/bin/env python3
"""Winterlock on Daisugi: EIP-8141 frame transactions from a member's stateless key.

Daisugi (https://daisugi.fyi, chain 1337) is a public test network for post-quantum accounts. It runs Nethermind's
EIP-8141 prototype (branch daisugi/devnet-handoff) and its public RPC accepts frame transactions (type 0x06) only.

  vector            reproduce a Daisugi transaction's hash and signature hash from its fields (no network writes)
  deploy            deploy the stateless verifier and the frame account implementation (CREATE2, from the deployer)
  member            make the throwaway member (phrase, member key) in $DAISUGI_DIR, print its account address
  fund              ask Daisugi's faucet for 1 test ETH for the member's account
  send [--to A] [--value WEI]
                    a frame transaction from the member's account: deploy it if needed (DEFAULT frame), VERIFY with
                    the member key, then a SENDER frame; waits for the receipt and prints each frame's gas

Run with the signer's Python (it reuses the signer's key derivation, leanSphincs and secp256k1 code):
  DAISUGI_DIR=/scratch/dir ../signer/.venv/bin/python bench/daisugi/daisugi.py <command>
The deployer key is DAISUGI_DEPLOYER_KEY in bench/bundlers/.env (or the environment). $DAISUGI_DIR holds a
throwaway phrase; keep it out of the repository.

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
from winterlock_signer.ethtx import Account, sign_hash  # noqa: E402
from winterlock_signer.keccak import keccak256  # noqa: E402

RPC = os.environ.get("DAISUGI_RPC", "https://daisugi.fyi/rpc")
FAUCET = "https://daisugi.fyi/api/faucet"
CHAIN_ID = 1337
CREATE2_DEPLOYER = bytes.fromhex("4e59b44847b379578588920cA78FbF26c0B4956C")
VERIFIER_SALT = keccak256(b"Winterlock.stateless-verifier.v1")
ACCOUNT_SALT = keccak256(b"Winterlock.frame-account.v0")
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


def verifier_init() -> bytes:
    return artifact("LeanSphincsAsm.sol/LeanSphincsAsm.json")


def account_impl_init() -> bytes:
    return artifact("WinterlockFrameAccount.yul/WinterlockFrameAccount.json")


def clone_init(impl: bytes, pk_seed: bytes, pk_root: bytes) -> bytes:
    """EIP-1167's runtime pointing at `impl`, then the 64-byte key; 109 bytes deployed"""
    runtime = bytes.fromhex("363d3d373d3d3d363d73") + impl + bytes.fromhex("5af43d82803e903d91602b57fd5bf3") + pk_seed + pk_root
    assert len(runtime) == 109
    return bytes.fromhex("3d606d80600a3d3981f3") + runtime


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
    for name, salt, init, gas in (("stateless verifier", VERIFIER_SALT, verifier_init(), 1_500_000),
                                  ("frame account implementation", ACCOUNT_SALT, account_impl_init(), 300_000)):
        addr = create2(salt, init)
        if code_at(addr):
            print(f"{name}: at {b2h(addr)} already")
            continue
        _, r = eoa_tx(acct, [frame(SENDER, CREATE2_DEPLOYER, gas, gas, data=salt + init)], f"deploy {name}")
        show_receipt(r, ["VERIFY (default code)", "SENDER: CREATE2"])
        print(f"  {name} at {b2h(addr)}: {len(code_at(addr))} bytes")


# --- the member and its account ------------------------------------------------------------------------------------

def member_dir() -> str:
    d = os.environ.get("DAISUGI_DIR")
    if not d:
        sys.exit("set DAISUGI_DIR to a directory outside the repository")
    os.makedirs(d, exist_ok=True)
    return d


def load_member():
    """(key, pkSeed word, pkRoot word, account address, clone init code); makes the phrase on first use"""
    d = member_dir()
    path = os.path.join(d, "member.json")
    if not os.path.exists(path):
        seed = os.urandom(32)
        words = wphrase.to_phrase(seed)
        t0 = time.time()
        key = wmember.stateless_key(seed)
        with open(path, "w") as f:
            json.dump({"phrase": " ".join(words), "note": "throwaway, Daisugi test only",
                       "kept_leaves": key.kept_leaves_bytes().hex()}, f)
        os.chmod(path, 0o600)
        print(f"made a throwaway member in {path} (member key in {time.time() - t0:.1f} s)")
    m = json.load(open(path))
    seed = wphrase.to_seed(m["phrase"])
    # the member key as member.stateless_key makes it, from the kept leaves instead of recomputing them
    leaves = bytes.fromhex(m["kept_leaves"])
    key = wleansphincs.Key(wmember._abi_label(wmember.MEMBER_KEY_LABEL, seed), wmember.STATELESS_B,
                           kept_leaves=[leaves[i:i + 16] for i in range(0, len(leaves), 16)])
    pk = key.public_key                # root ‖ P
    pk_seed = pk[16:] + bytes(16)        # P, high-aligned
    pk_root = pk[:16] + bytes(16)        # root, high-aligned
    impl = create2(ACCOUNT_SALT, account_impl_init())
    init = clone_init(impl, pk_seed, pk_root)
    return key, pk_seed, pk_root, create2(bytes(32), init), init


def cmd_member():
    key, pk_seed, pk_root, account, _ = load_member()
    print(f"member key (root ‖ P): {b2h(key.public_key)}")
    print(f"account: {b2h(account)}  code {len(code_at(account))} bytes, balance {balance(account) / 1e18:.4f} ETH")


def cmd_fund():
    _, _, _, account, _ = load_member()
    req = urllib.request.Request(FAUCET, data=json.dumps({"address": b2h(account), "amount": "1"}).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "winterlock-daisugi"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            print(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"faucet: HTTP {e.code} {e.read().decode()[:300]}")


def cmd_send(to: bytes, value: int, data: bytes = b""):
    key, _, _, account, init = load_member()
    frames, names = [], []
    if not code_at(account):
        frames.append(frame(DEFAULT, CREATE2_DEPLOYER, 60_000, 450_000, data=bytes(32) + init))
        names.append("DEFAULT: deploy the account")
    frames.append(frame(VERIFY, account, 75_000, flags=3))
    names.append("VERIFY: member key")
    frames.append(frame(SENDER, to, 100_000, 300_000, value=value, data=data))
    names.append("SENDER: the call")
    tx = {"chain_id": CHAIN_ID, "nonce": nonce_of(account), "sender": account, "frames": frames,
          "signatures": [{"scheme": ARBITRARY, "signer": b"", "msg": b"", "signature": bytes(SIG_LEN)}],
          "max_priority_fee": PRIORITY_FEE, "max_fee": MAX_FEE}
    h = sig_hash(tx)
    t0 = time.time()
    sig = key.sign(h)
    print(f"signed the sig hash {b2h(h)} with the member key in {time.time() - t0:.1f} s ({len(sig):,} bytes)")
    tx["signatures"][0]["signature"] = sig
    _, r = submit(tx, "frame transaction")
    show_receipt(r, names)
    print(f"  account {b2h(account)}: code {len(code_at(account))} bytes, nonce {nonce_of(account)}, "
          f"balance {balance(account) / 1e18:.6f} ETH")


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
    if c == "vector":
        cmd_vector()
    elif c == "deploy":
        cmd_deploy()
    elif c == "member":
        cmd_member()
    elif c == "fund":
        cmd_fund()
    elif c == "send":
        to, value = b"\x00" * 18 + b"\xde\xad", 10**16
        if "--to" in rest:
            to = h2b(rest[rest.index("--to") + 1])
        if "--value" in rest:
            value = int(rest[rest.index("--value") + 1])
        cmd_send(to, value)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
