#!/usr/bin/env python3
"""Live test on Sepolia: a 2-of-3 Safe whose owners are WinterlockOwner contracts, driven through Safe's hosted
Transaction Service (see docs/decisions.md, "2026-11-05: Safe owner, live on Sepolia").

Keys: each member's stateless key and operation trees derive from the secret SAFE_SPIKE_TAG in
bench/bundlers/.env (git-ignored). Signing runs in Solidity (bench/safe/SafeSignerHelper.sol) on a LOCAL anvil that
this script starts and stops; the tag never leaves the machine. Deployer key, Alchemy key and Safe API key also come
from the environment and are never printed: every message from cast or a node is redacted first.

usage (from contracts/, after `forge build --force`, `forge build bench/safe/SafeSignerHelper.sol` and
`set -a; . bench/bundlers/.env; set +a`; the .env needs SAFE_SPIKE_TAG, 32 random bytes as hex):
  python3 bench/safe/live.py STEP [STEP ...]
steps, in order: keys deploy safe enrol index propose confirm show execute replace message delegate balance
State and results go to bench/safe/results-sepolia.json (git-ignored); each step records what it did, and a step
that already ran is skipped. Key use is recorded per (member, nonce, slot): signing a different SafeTx with a key
that already signed is refused (D4).
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keccak import keccak256  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # contracts/
RESULTS = os.environ.get("LIVE_RESULTS") or os.path.join(HERE, "results-sepolia.json")
# Rehearsal on a local fork: LIVE_RPC=http://127.0.0.1:PORT LIVE_DRYRUN=1 LIVE_RESULTS=/elsewhere.json
DRYRUN = os.environ.get("LIVE_DRYRUN") == "1"

CHAIN_ID = 11155111
PROXY = "0x4e59b44847b379578588920cA78FbF26c0B4956C"  # deterministic deployment proxy
VERIFIER_SALT = keccak256(b"Winterlock.stateless-verifier.v1")
D6 = 24 | (4 << 8) | (0 << 16) | (431 << 32)  # WotsVerifier.encodeParams(24, 4, 0, 431)
# Safe v1.4.1 canonical deployments (safe-deployments). The app creates Safes on Sepolia with the L1 singleton and
# SafeToL2Setup, which switches them to SafeL2 on any chain but mainnet; SafeL2 directly gives the same singleton.
SAFE_L2 = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"
SAFE_FACTORY = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"
FALLBACK_HANDLER = "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"
FALLBACK_HANDLER_SLOT = int.from_bytes(keccak256(b"fallback_manager.handler.address"), "big")
SERVICE = "https://api.safe.global/tx-service/sep/api"
ZERO = "0x" + "00" * 20
MAX_TX_GAS = 16_777_216  # EIP-7825 transaction gas cap
HELPER_GAS = 2_000_000_000
ANVIL_PORT = 8549
ANVIL_PK_ACCOUNT = None  # anvil's first unlocked account, found at start
STATELESS_SIG_LEN = 5684
MAGIC = "1626ba7e"
SAFE_MSG_TYPEHASH = keccak256(b"SafeMessage(bytes message)")
SAFE_DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)")
MESSAGE_TEXT = "Winterlock live test on Sepolia: a SafeMessage signed by a member's stateless key"


# --- environment and redaction ---

def env(name):
    v = os.environ.get(name)
    if not v:
        raise SystemExit(f"{name} missing: source bench/bundlers/.env first")
    return v


SECRETS = [os.environ.get(k) for k in ("DEPLOYER_PRIVATE_KEY", "ALCHEMY_API_KEY", "SAFE_API_KEY", "SAFE_SPIKE_TAG",
                                       "PIMLICO_API_KEY", "MULTICHAIN_TAG")]
SECRETS = [s for s in SECRETS if s and len(s) >= 8]


def redact(text):
    text = str(text)
    for s in SECRETS:
        text = text.replace(s, "<redacted>")
        if s.startswith("0x"):
            text = text.replace(s[2:], "<redacted>")
    return text


def log(*a):
    print(redact(" ".join(map(str, a))), flush=True)


# --- encoding ---

def h2b(x):
    return bytes.fromhex(x[2:] if x.startswith("0x") else x)


def b2h(b):
    return "0x" + b.hex()


def checksum(addr):
    a = addr.lower().replace("0x", "")
    hh = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(hh[i], 16) >= 8 else c for i, c in enumerate(a))


def word(v):
    if isinstance(v, bytes):
        assert len(v) <= 32
        return v.ljust(32, b"\x00") if len(v) == 32 else v.rjust(32, b"\x00")
    if isinstance(v, str):  # address or 0x-hex word
        b = h2b(v)
        return b.rjust(32, b"\x00")
    return int(v).to_bytes(32, "big")


def selector(sig):
    return keccak256(sig.encode())[:4]


def encode(types, values):
    """ABI encoding for the static types used here plus `bytes`"""
    head, tail = b"", b""
    n_head = 0
    for t in types:
        n_head += 32 * 10 if t == "bytes32[10]" else 32
    for t, v in zip(types, values):
        if t == "bytes":
            data = v if isinstance(v, bytes) else h2b(v)
            head += word(n_head + len(tail))
            tail += word(len(data)) + data + b"\x00" * ((-len(data)) % 32)
        elif t == "bytes32[10]":
            head += b"".join(word(x) for x in v)
        elif t == "bytes32":
            head += v if isinstance(v, bytes) else h2b(v)
        else:
            head += word(v)
    return head + tail


def calldata(sig, types, values):
    return selector(sig) + encode(types, values)


def dec_bytes(ret, index=0):
    off = int.from_bytes(ret[32 * index: 32 * index + 32], "big")
    n = int.from_bytes(ret[off: off + 32], "big")
    return ret[off + 32: off + 32 + n]


def dec_word(ret, index=0):
    return ret[32 * index: 32 * index + 32]


def dec_uint(ret, index=0):
    return int.from_bytes(dec_word(ret, index), "big")


def dec_addr(ret, index=0):
    return checksum(b2h(dec_word(ret, index)[12:]))


def create2(salt, init_code):
    return checksum(b2h(keccak256(b"\xff" + h2b(PROXY) + salt + keccak256(init_code))[12:]))


# --- JSON-RPC ---

class RpcError(Exception):
    pass


def rpc(url, method, params, timeout=180):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": "winterlock-bench"})
    for attempt in (0, 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                resp = json.load(r)
            break
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt:
                raise RpcError(redact(f"{method}: {e}"))
            time.sleep(3)
    if "error" in resp:
        raise RpcError(redact(f"{method}: {resp['error']}"))
    return resp["result"]


def sepolia():
    return os.environ.get("LIVE_RPC") or f"https://eth-sepolia.g.alchemy.com/v2/{env('ALCHEMY_API_KEY')}"


def eth_call(to, data, url=None, gas=None, sender=None):
    tx = {"to": to, "data": b2h(data)}
    if gas:
        tx["gas"] = hex(gas)
    if sender:
        tx["from"] = sender
    return h2b(rpc(url or sepolia(), "eth_call", [tx, "latest"], timeout=900))


def call(to, sig, types=(), values=(), **kw):
    return eth_call(to, calldata(sig, list(types), list(values)), **kw)


def code_size(addr):
    return (len(rpc(sepolia(), "eth_getCode", [addr, "latest"])) - 2) // 2


def balance(addr):
    return int(rpc(sepolia(), "eth_getBalance", [addr, "latest"]), 16)


def estimate(to, data, value=0):
    tx = {"from": env("DEPLOYER_ADDRESS"), "to": to, "data": b2h(data), "value": hex(value)}
    return int(rpc(sepolia(), "eth_estimateGas", [tx, "latest"]), 16)


def send(to, data, gas, value_wei=0):
    """A transaction from the deployer through `cast send` (it signs); returns the receipt. Output is redacted."""
    args = ["cast", "send", to] + ([b2h(data)] if data else []) + ["--gas-limit", str(gas), "--rpc-url", sepolia(),
            "--private-key", env("DEPLOYER_PRIVATE_KEY"), "--json", "--timeout", "600"]
    if value_wei:
        args += ["--value", str(value_wei)]
    out = subprocess.run(args, capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        raise RuntimeError(redact(f"cast send failed: {out.stderr.strip()[:800]}"))
    receipt = json.loads(out.stdout)
    if int(receipt["status"], 16) != 1:
        raise RuntimeError(f"transaction reverted: {receipt['transactionHash']}")
    return receipt


def receipt_row(receipt, **extra):
    gas = int(receipt["gasUsed"], 16)
    price = int(receipt.get("effectiveGasPrice", "0x0"), 16)
    row = dict(tx=receipt["transactionHash"], block=int(receipt["blockNumber"], 16), gas_used=gas,
               gas_price_wei=price, cost_wei=gas * price)
    row.update(extra)
    return row


# --- state ---

def load():
    if os.path.exists(RESULTS):
        return json.load(open(RESULTS))
    return {"network": "sepolia", "chain_id": CHAIN_ID, "onchain": {}, "service": [], "keys_used": {}}


def save(st):
    tmp = RESULTS + ".tmp"
    json.dump(st, open(tmp, "w"), indent=1)
    os.replace(tmp, RESULTS)


# --- local signer (anvil) ---

class Signer:
    """SafeOwnerSignerHelper on a local anvil. The tag is passed in eth_call data to 127.0.0.1 only."""

    def __init__(self):
        self.url = f"http://127.0.0.1:{ANVIL_PORT}"
        self.proc = subprocess.Popen(["anvil", "--port", str(ANVIL_PORT), "--disable-block-gas-limit",
                                      "--disable-code-size-limit", "--silent"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self._start()
        except BaseException:
            self.close()
            raise

    def _start(self):
        for _ in range(100):
            try:
                rpc(self.url, "eth_chainId", [], timeout=2)
                break
            except Exception:
                time.sleep(0.2)
        acct = rpc(self.url, "eth_accounts", [])[0]
        art = json.load(open(os.path.join(ROOT, "out/SafeSignerHelper.sol/SafeOwnerSignerHelper.json")))
        txh = rpc(self.url, "eth_sendTransaction", [{"from": acct, "data": art["bytecode"]["object"],
                                                     "gas": hex(30_000_000)}])
        receipt = None
        for _ in range(100):
            receipt = rpc(self.url, "eth_getTransactionReceipt", [txh])
            if receipt:
                break
            time.sleep(0.2)
        assert receipt and int(receipt["status"], 16) == 1, "signer helper deployment failed"
        self.helper = receipt["contractAddress"]
        self.tag = h2b(env("SAFE_SPIKE_TAG"))
        assert len(self.tag) == 32

    def close(self):
        self.proc.terminate()
        self.proc.wait()

    def _call(self, sig, types, values):
        return eth_call(self.helper, calldata(sig, ["bytes32"] + types, [self.tag] + values), url=self.url,
                        gas=HELPER_GAS)

    def public_key(self, member):
        return dec_word(self._call("publicKey(bytes32,uint256)", ["uint256"], [member]))

    def tree(self, member, safe, start, seed):
        ret = self._call("tree(bytes32,uint256,uint256,address,uint64,uint128)",
                         ["uint256", "uint256", "address", "uint256", "uint256"], [member, CHAIN_ID, safe, start, seed])
        return dec_word(ret, 0), dec_uint(ret, 1)

    def certificate(self, member, digest):
        return dec_bytes(self._call("certificate(bytes32,uint256,bytes32)", ["uint256", "bytes32"], [member, digest]))

    def tx_signature(self, member, safe, start, seed, slot, words):
        ret = self._call("txSignature(bytes32,uint256,uint256,address,uint64,uint128,uint256,bytes32[10])",
                         ["uint256", "uint256", "address", "uint256", "uint256", "uint256", "bytes32[10]"],
                         [member, CHAIN_ID, safe, start, seed, slot, words])
        return dec_bytes(ret, 0), dec_word(ret, 1)

    def message_signature(self, member, safe, msg_hash, digest):
        return dec_bytes(self._call("messageSignature(bytes32,uint256,address,bytes32,bytes32)",
                                    ["uint256", "address", "bytes32", "bytes32"], [member, safe, msg_hash, digest]))


_signer = None


def signer():
    global _signer
    if _signer is None:
        log("  starting the local signer (anvil)")
        _signer = Signer()
    return _signer


# --- Safe helpers ---

def safe_tx(to, value=0, data=b"", operation=0, nonce=0):
    return dict(to=checksum(to), value=value, data=b2h(data), operation=operation, safeTxGas=0, baseGas=0, gasPrice=0,
                gasToken=ZERO, refundReceiver=ZERO, nonce=nonce)


def tx_words(t):
    return [t["to"], t["value"], keccak256(h2b(t["data"])), t["operation"], t["safeTxGas"], t["baseGas"],
            t["gasPrice"], t["gasToken"], t["refundReceiver"], t["nonce"]]


def safe_tx_hash_onchain(safe, t):
    ret = call(safe, "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)",
               ["address", "uint256", "bytes", "uint256", "uint256", "uint256", "uint256", "address", "address",
                "uint256"],
               [t["to"], t["value"], h2b(t["data"]), t["operation"], t["safeTxGas"], t["baseGas"], t["gasPrice"],
                t["gasToken"], t["refundReceiver"], t["nonce"]])
    return dec_word(ret)


def contract_sig(owner, data):
    """One owner's standalone contract signature: r = owner, s = 65, v = 0, then [length][data]"""
    return word(owner) + word(65) + b"\x00" + word(len(data)) + data


def pack(sigs):
    """Safe's signatures blob for contract signatures [(owner, data)], in increasing owner order"""
    sigs = sorted(sigs, key=lambda s: int(s[0], 16))
    static, dynamic = b"", b""
    for owner, data in sigs:
        static += word(owner) + word(65 * len(sigs) + len(dynamic)) + b"\x00"
        dynamic += word(len(data)) + data
    return static + dynamic


def parse_standalone(sig_hex):
    b = h2b(sig_hex)
    owner = checksum(b2h(b[12:32]))
    s = int.from_bytes(b[32:64], "big")
    assert b[64] == 0 and s == 65, "not a standalone contract signature"
    n = int.from_bytes(b[65:97], "big")
    return owner, b[97:97 + n]


def sign_tx(st, member, t, slot):
    """Member's WinterlockOwner signature data for SafeTx t with `slot`, checked on Sepolia before it's used"""
    safe, owner = st["safe"]["address"], st["owners"][member]["address"]
    expected = safe_tx_hash_onchain(safe, t)
    key = f"m{member}:n{t['nonce']}:s{slot}"
    used = st["keys_used"].get(key)
    if used and used != b2h(expected):
        raise SystemExit(f"refused: key {key} already signed {used}; signing {b2h(expected)} would reuse it (D4)")
    st["keys_used"][key] = b2h(expected)
    save(st)
    seed = dec_uint(call(owner, "treeSeed(address,uint64)", ["address", "uint256"], [safe, 0]))
    data, hsh = signer().tx_signature(member, safe, 0, seed, slot, tx_words(t))
    assert hsh == expected, "helper's SafeTx hash differs from the Safe's"
    ok = call(owner, "isValidSignature(bytes32,bytes)", ["bytes32", "bytes"], [hsh, data])[:4].hex()
    assert ok == MAGIC, f"owner {member} refuses its own signature on Sepolia: {ok}"
    return data, hsh


# --- Transaction Service ---

def trim(v, keep=74):
    if isinstance(v, dict):
        return {k: trim(x, keep) for k, x in v.items()}
    if isinstance(v, list):
        return [trim(x, keep) for x in v]
    if isinstance(v, str) and len(v) > 200:
        return f"{v[:keep]}…({len(v)} chars)"
    return v


def service(st, step, method, path, body=None, record=True):
    if DRYRUN:
        log(f"  (dry run) {method} {path}" + (f" with a {len(h2b(body['signature']))}-byte signature"
                                              if body and "signature" in body else ""))
        return (200, {"dryrun": True}) if method == "GET" else (None, None)
    url = SERVICE + path
    headers = {"Authorization": f"Bearer {env('SAFE_API_KEY')}", "User-Agent": "winterlock-bench",
               "Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    for attempt in (0, 1):  # one retry on a network error only
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                status, raw = r.status, r.read()
            break
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
            break
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt:
                status, raw = None, redact(str(e)).encode()
            else:
                time.sleep(5)
    try:
        resp = json.loads(raw) if raw else None
    except ValueError:
        resp = raw.decode(errors="replace")[:2000]
    row = dict(step=step, method=method, path=path, status=status, response=trim(resp),
               at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if body is not None:
        row["request"] = trim(body)
        if "signature" in body:
            row["signature_bytes"] = len(h2b(body["signature"]))
    if record:
        st["service"].append(row)
        save(st)
    log(f"  {method} {path} -> {status}: {json.dumps(trim(resp, 120))[:600]}")
    return status, resp


def proposal_body(t, h, sender, signature):
    return {"to": t["to"], "value": str(t["value"]), "data": t["data"], "operation": t["operation"],
            "safeTxGas": str(t["safeTxGas"]), "baseGas": str(t["baseGas"]), "gasPrice": str(t["gasPrice"]),
            "gasToken": t["gasToken"], "refundReceiver": t["refundReceiver"], "nonce": t["nonce"],
            "contractTransactionHash": b2h(h), "sender": sender, "signature": b2h(signature), "origin": None}


def summarize_tx(resp):
    if not isinstance(resp, dict):
        return resp
    keys = ("safeTxHash", "nonce", "to", "value", "confirmationsRequired", "isExecuted", "isSuccessful",
            "transactionHash", "executor", "proposer", "proposedByDelegate", "trusted", "submissionDate",
            "executionDate", "blockNumber", "gasUsed", "fee", "safe", "signatures")
    out = {k: resp.get(k) for k in keys if k in resp}
    if isinstance(out.get("signatures"), str):
        out["signatures"] = f"{len(h2b(out['signatures']))} bytes"
    out["confirmations"] = [dict(owner=c.get("owner"), signatureType=c.get("signatureType"),
                                 signature_bytes=len(h2b(c["signature"])) if c.get("signature") else None,
                                 submissionDate=c.get("submissionDate"))
                            for c in resp.get("confirmations") or []]
    return out


# --- steps ---

def step_keys(st):
    s = signer()
    owner_art = json.load(open(os.path.join(ROOT, "out/WinterlockOwner.sol/WinterlockOwner.json")))
    verifier_art = json.load(open(os.path.join(ROOT, "out/LeanSphincsAsm.sol/LeanSphincsAsm.json")))
    verifier = create2(VERIFIER_SALT, h2b(verifier_art["bytecode"]["object"]))
    st["verifier"] = {"address": verifier}
    st["params"] = {"packed": hex(D6), "n": 24, "logW": 4, "targetSum": 431, "hash": "keccak256",
                    "tree_height": 10, "real_keys": 16, "stateless": "leanSphincs (kept subtree 10)"}
    st["owners"] = []
    for m in range(3):
        key = s.public_key(m)
        init = h2b(owner_art["bytecode"]["object"]) + encode(["uint256", "address", "bytes32"], [D6, verifier, key])
        st["owners"].append({"member": m + 1, "key": b2h(key), "address": create2(key, init),
                             "init_code_bytes": len(init)})
        log(f"  member {m + 1}: KEY {b2h(key)}  owner {st['owners'][-1]['address']}")
    log(f"  stateless verifier {verifier}")


def _deploy(st, name, salt, init):
    addr = create2(salt, init)
    if code_size(addr):
        log(f"  {name}: already deployed at {addr}")
        st["onchain"].setdefault(name, {"address": addr, "note": "already deployed"})
        return
    data = salt + init
    est = estimate(PROXY, data)
    gas = min(int(est * 1.05), MAX_TX_GAS)
    log(f"  {name}: estimate {est}, gas limit {gas}")
    r = send(PROXY, data, gas)
    assert code_size(addr), f"{name}: no code at {addr} after deployment"
    st["onchain"][name] = receipt_row(r, address=addr, estimate=est, runtime_bytes=code_size(addr))
    save(st)
    log(f"  {name}: deployed at {addr}, gas {st['onchain'][name]['gas_used']}, tx {r['transactionHash']}")


def step_deploy(st):
    owner_art = json.load(open(os.path.join(ROOT, "out/WinterlockOwner.sol/WinterlockOwner.json")))
    verifier_art = json.load(open(os.path.join(ROOT, "out/LeanSphincsAsm.sol/LeanSphincsAsm.json")))
    _deploy(st, "deploy_verifier", VERIFIER_SALT, h2b(verifier_art["bytecode"]["object"]))
    for o in st["owners"]:
        key = h2b(o["key"])
        init = h2b(owner_art["bytecode"]["object"]) + encode(["uint256", "address", "bytes32"],
                                                             [D6, st["verifier"]["address"], key])
        _deploy(st, f"deploy_owner{o['member']}", key, init)
        assert b2h(dec_word(call(o["address"], "KEY()"))) == o["key"]


def step_safe(st):
    owners = [o["address"] for o in st["owners"]]
    setup = selector("setup(address[],uint256,address,bytes,address,address,uint256,address)")
    # setup's owners array is dynamic: encode by hand (head of 8 words, then the array, then empty bytes)
    head = (word(32 * 8) + word(2) + word(ZERO) + word(32 * 8 + 32 + 32 * len(owners)) + word(FALLBACK_HANDLER)
            + word(ZERO) + word(0) + word(ZERO))
    tail = word(len(owners)) + b"".join(word(a) for a in owners) + word(0)
    initializer = setup + head + tail
    salt_nonce = st.get("safe", {}).get("salt_nonce") or int(time.time())
    cd = calldata("createProxyWithNonce(address,bytes,uint256)", ["address", "bytes", "uint256"],
                  [SAFE_L2, initializer, salt_nonce])
    predicted = dec_addr(eth_call(SAFE_FACTORY, cd, sender=env("DEPLOYER_ADDRESS")))
    st["safe"] = {"address": predicted, "salt_nonce": salt_nonce, "singleton": SAFE_L2, "version": "1.4.1 (SafeL2)",
                  "factory": SAFE_FACTORY, "fallback_handler": FALLBACK_HANDLER, "threshold": 2, "owners": owners}
    save(st)
    if not code_size(predicted):
        est = estimate(SAFE_FACTORY, cd)
        r = send(SAFE_FACTORY, cd, int(est * 1.2))
        st["onchain"]["create_safe"] = receipt_row(r, address=predicted, estimate=est)
        save(st)
        log(f"  Safe {predicted}: gas {st['onchain']['create_safe']['gas_used']}, tx {r['transactionHash']}")
    singleton = rpc(sepolia(), "eth_getStorageAt", [predicted, "0x0", "latest"])
    handler = rpc(sepolia(), "eth_getStorageAt", [predicted, hex(FALLBACK_HANDLER_SLOT), "latest"])
    threshold = dec_uint(call(predicted, "getThreshold()"))
    version = call(predicted, "VERSION()")
    st["safe"]["checked"] = {"singleton": checksum("0x" + singleton[-40:]), "fallback_handler":
                             checksum("0x" + handler[-40:]), "threshold": threshold,
                             "VERSION": dec_bytes(version).decode()}
    if "fund" not in st["onchain"]:
        value = 10**15  # 0.001 ETH
        est = estimate(predicted, b"", value)
        r = send(predicted, b"", int(est * 1.2), value)
        st["onchain"]["fund"] = receipt_row(r, value_wei=value, estimate=est)
        log(f"  funded with 0.001 ETH: gas {st['onchain']['fund']['gas_used']}, tx {r['transactionHash']}")
    log(f"  Safe {predicted}: {st['safe']['checked']}")


def step_enrol(st):
    safe = st["safe"]["address"]
    s = signer()
    for m in (0, 1):  # members 1 and 2; member 3 stays unenrolled
        name = f"enrol_member{m + 1}"
        owner = st["owners"][m]["address"]
        if name in st["onchain"]:
            continue
        seed = dec_uint(call(owner, "treeSeed(address,uint64)", ["address", "uint256"], [safe, 0]))
        root, height = s.tree(m, safe, 0, seed)
        digest = dec_word(call(owner, "certificateDigest(address,bytes32,uint8,uint64)",
                               ["address", "bytes32", "uint256", "uint256"], [safe, root, height, 0]))
        cert = s.certificate(m, digest)
        assert len(cert) == STATELESS_SIG_LEN
        cd = calldata("enroll(address,bytes32,uint8,uint64,bytes)", ["address", "bytes32", "uint256", "uint256",
                                                                     "bytes"], [safe, root, height, 0, cert])
        est = estimate(owner, cd)
        r = send(owner, cd, int(est * 1.2))
        stored = call(owner, "tree(address)", ["address"], [safe])
        assert dec_word(stored, 0) == root and dec_uint(stored, 2) == height
        st["onchain"][name] = receipt_row(r, owner=owner, root=b2h(root), height=height, start=0,
                                          calldata_bytes=len(cd), estimate=est)
        save(st)
        log(f"  member {m + 1} enrolled: gas {st['onchain'][name]['gas_used']}, calldata {len(cd)} B, "
            f"tx {r['transactionHash']}")


def step_index(st):
    safe = st["safe"]["address"]
    t0 = time.time()
    polls = 0
    while True:
        polls += 1
        status, resp = service(st, "a: index", "GET", f"/v1/safes/{safe}/", record=False)
        if polls == 1 or status == 200:
            st["service"].append(dict(step="a: index", method="GET", path=f"/v1/safes/{safe}/", status=status,
                                      response=trim(resp), poll=polls,
                                      at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
            save(st)
        if status == 200:
            break
        if time.time() - t0 > 15 * 60:
            raise SystemExit("not indexed after 15 minutes")
        time.sleep(15)
    st["indexed"] = {"polls": polls, "seconds_after_first_poll": round(time.time() - t0),
                     "safe_info": resp}
    if "create_safe" in st["onchain"]:
        blk = rpc(sepolia(), "eth_getBlockByNumber", [hex(st["onchain"]["create_safe"]["block"]), False])
        st["indexed"]["seconds_after_creation_block"] = round(time.time() - int(blk["timestamp"], 16))


def _tx(st, name):
    return st["txs"][name]


def step_propose(st):
    safe = st["safe"]["address"]
    st.setdefault("txs", {})
    t = safe_tx(env("DEPLOYER_ADDRESS"), 1, b"", 0, nonce=0)
    data, h = sign_tx(st, 0, t, 0)
    sender = st["owners"][0]["address"]
    sig = contract_sig(sender, data)
    st["txs"]["tx1"] = {"safe_tx": t, "safe_tx_hash": b2h(h), "slot": 0, "proposer": sender,
                        "member1_data_bytes": len(data), "member1_signature_bytes": len(sig)}
    save(st)
    service(st, "b: propose tx1 (member 1, slot 0)", "POST", f"/v2/safes/{safe}/multisig-transactions/",
            proposal_body(t, h, sender, sig))


def step_confirm(st):
    tx = _tx(st, "tx1")
    data, h = sign_tx(st, 1, tx["safe_tx"], 0)
    sig = contract_sig(st["owners"][1]["address"], data)
    tx["member2_signature_bytes"] = len(sig)
    service(st, "c: confirm tx1 (member 2, slot 0)", "POST",
            f"/v1/multisig-transactions/{tx['safe_tx_hash']}/confirmations/", {"signature": b2h(sig)})


def step_show(st):
    tx = _tx(st, "tx1")
    status, resp = service(st, "d: show tx1", "GET", f"/v2/multisig-transactions/{tx['safe_tx_hash']}/")
    tx["service_before_execution"] = summarize_tx(resp)
    if status == 200:
        tx["service_confirmations_raw"] = [c["signature"] for c in resp.get("confirmations") or []]


def _execute(st, name):
    """execTransaction from the deployer with the signatures as the service returned them"""
    safe = st["safe"]["address"]
    tx = _tx(st, name)
    t = tx["safe_tx"]
    raw = tx.get("service_confirmations_raw") or []
    sigs = [parse_standalone(s) for s in raw]
    tx["executed_with"] = "signatures as the service returned them" if len(sigs) >= 2 else "our own signatures"
    # the service's stored signature data must be ours, byte for byte (re-signing is deterministic)
    for owner, data in sigs:
        m = [o["address"] for o in st["owners"]].index(owner)
        mine, _ = sign_tx(st, m, t, tx["slot"])
        assert mine == data, f"service returned other signature data for {owner}"
    if len(sigs) < 2:
        sigs = [(st["owners"][m]["address"], sign_tx(st, m, t, tx["slot"])[0]) for m in (0, 1)]
    blob = pack(sigs)
    cd = calldata("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
                  ["address", "uint256", "bytes", "uint256", "uint256", "uint256", "uint256", "address", "address",
                   "bytes"],
                  [t["to"], t["value"], h2b(t["data"]), t["operation"], t["safeTxGas"], t["baseGas"], t["gasPrice"],
                   t["gasToken"], t["refundReceiver"], blob])
    est = estimate(safe, cd)
    r = send(safe, cd, int(est * 1.2))
    success_topic = b2h(keccak256(b"ExecutionSuccess(bytes32,uint256)"))
    ok = any(lg["topics"][0] == success_topic for lg in r["logs"] if lg["address"].lower() == safe.lower())
    st["onchain"][f"exec_{name}"] = receipt_row(r, signatures_bytes=len(blob), calldata_bytes=len(cd), estimate=est,
                                                execution_success=ok)
    save(st)
    log(f"  executed {name}: gas {st['onchain'][f'exec_{name}']['gas_used']}, success {ok}, tx {r['transactionHash']}")
    return r


def _executed(resp, safe_tx_hash):
    if not isinstance(resp, dict):
        return False
    if "results" in resp:
        return any(x.get("safeTxHash") == safe_tx_hash and x.get("isExecuted") for x in resp["results"])
    return bool(resp.get("isExecuted"))


def _wait_executed(st, step, name, path):
    """GET after the service has had time to index the execution: at most two calls"""
    for wait in (75, 90):
        time.sleep(0 if DRYRUN else wait)
        status, resp = service(st, step, "GET", path)
        if status == 200 and _executed(resp, _tx(st, name)["safe_tx_hash"]):
            break
    return status, resp


def step_execute(st):
    tx = _tx(st, "tx1")
    if "exec_tx1" not in st["onchain"]:
        _execute(st, "tx1")
    status, resp = _wait_executed(st, "e: show tx1 after execution", "tx1",
                                  f"/v2/multisig-transactions/{tx['safe_tx_hash']}/")
    tx["service_after_execution"] = summarize_tx(resp)


def step_replace(st):
    safe = st["safe"]["address"]
    o1, o2 = st["owners"][0]["address"], st["owners"][1]["address"]
    nonce = dec_uint(call(safe, "nonce()"))
    assert nonce == 1, f"Safe nonce is {nonce}, expected 1 (tx1 executed)"
    # the original: 2 wei to the deployer, slot 0
    t2 = safe_tx(env("DEPLOYER_ADDRESS"), 2, b"", 0, nonce=1)
    # its replacement as Safe's app builds an on-chain rejection: a call to the Safe itself with no value and no data,
    # at the same nonce, signed with slot 1 (D4)
    t3 = safe_tx(safe, 0, b"", 0, nonce=1)
    st["txs"]["tx2"] = {"safe_tx": t2, "slot": 0}
    st["txs"]["tx2_replacement"] = {"safe_tx": t3, "slot": 1}
    for name, t, slot in (("tx2", t2, 0), ("tx2_replacement", t3, 1)):
        d1, h = sign_tx(st, 0, t, slot)
        st["txs"][name]["safe_tx_hash"] = b2h(h)
        save(st)
        service(st, f"f: propose {name} (member 1, slot {slot})", "POST", f"/v2/safes/{safe}/multisig-transactions/",
                proposal_body(t, h, o1, contract_sig(o1, d1)))
        d2, _ = sign_tx(st, 1, t, slot)
        service(st, f"f: confirm {name} (member 2, slot {slot})", "POST",
                f"/v1/multisig-transactions/{b2h(h)}/confirmations/", {"signature": b2h(contract_sig(o2, d2))})
    status, resp = service(st, "f: list nonce 1", "GET", f"/v2/safes/{safe}/multisig-transactions/?nonce=1")
    st["replacement_queue"] = {"count": (resp or {}).get("count"),
                               "results": [summarize_tx(x) for x in (resp or {}).get("results", [])]}
    for x in (resp or {}).get("results", []):
        for name in ("tx2", "tx2_replacement"):
            if x["safeTxHash"] == st["txs"][name]["safe_tx_hash"]:
                st["txs"][name]["service_confirmations_raw"] = [c["signature"] for c in x.get("confirmations") or []]
    save(st)
    if "exec_tx2_replacement" not in st["onchain"]:
        _execute(st, "tx2_replacement")
    status, resp = _wait_executed(st, "f: list nonce 1 after executing the replacement", "tx2_replacement",
                                  f"/v2/safes/{safe}/multisig-transactions/?nonce=1")
    st["replacement_after_execution"] = {"count": (resp or {}).get("count"),
                                         "results": [summarize_tx(x) for x in (resp or {}).get("results", [])]}


def step_message(st):
    safe = st["safe"]["address"]
    owners = [o["address"] for o in st["owners"]]
    text = MESSAGE_TEXT.encode()
    app_hash = keccak256(b"\x19Ethereum Signed Message:\n" + str(len(text)).encode() + text)  # EIP-191
    msg_hash = keccak256(app_hash)  # keccak256(message), message = abi.encode(app_hash)
    domain = keccak256(SAFE_DOMAIN_TYPEHASH + word(CHAIN_ID) + word(safe))
    safe_msg_hash = keccak256(b"\x19\x01" + domain + keccak256(SAFE_MSG_TYPEHASH + msg_hash))
    handler = dec_word(call(FALLBACK_HANDLER, "getMessageHashForSafe(address,bytes)", ["address", "bytes"],
                            [safe, app_hash]))
    assert handler == safe_msg_hash, "SafeMessage hash differs from the fallback handler's"
    sigs = []
    for m in (0, 1):
        digest = dec_word(call(owners[m], "messageDigest(address,bytes32)", ["address", "bytes32"],
                               [safe, safe_msg_hash]))
        data = signer().message_signature(m, safe, msg_hash, digest)
        ok = call(owners[m], "isValidSignature(bytes32,bytes)", ["bytes32", "bytes"], [safe_msg_hash, data])[:4]
        assert ok.hex() == MAGIC, f"owner {m + 1} refuses its message signature"
        sigs.append((owners[m], data))
    # what an app sees on-chain: the Safe's fallback handler checks the 2-of-3 signature
    blob = pack(sigs)
    onchain = call(safe, "isValidSignature(bytes32,bytes)", ["bytes32", "bytes"], [app_hash, blob])[:4].hex()
    st["message"] = {"text": MESSAGE_TEXT, "eip191_hash": b2h(app_hash), "safe_message_hash": b2h(safe_msg_hash),
                     "member1_data_bytes": len(sigs[0][1]), "member1_signature_bytes": len(contract_sig(*sigs[0])),
                     "two_of_three_bytes": len(blob), "safe_isValidSignature_eth_call": "0x" + onchain}
    save(st)
    log(f"  on-chain check through the Safe (eth_call): 0x{onchain}, {len(blob)} bytes for 2-of-3")
    service(st, "g: post message (member 1, stateless key)", "POST", f"/v1/safes/{safe}/messages/",
            {"message": MESSAGE_TEXT, "safeAppId": None, "signature": b2h(contract_sig(*sigs[0]))})


def step_delegate(st):
    """A delegate registration needs the delegator's EIP-1271 approval of an EIP-712 Delegate hash. WinterlockOwner
    answers only for SafeTx and SafeMessage hashes, so no signature it accepts exists. The request carries a
    contract signature of member 1's owner whose data is a message header naming the Delegate hash, without a
    stateless signature (a full one would also exceed the service's 5,000-byte cap)."""
    safe = st["safe"]["address"]
    owner = st["owners"][0]["address"]
    delegate = checksum(env("DEPLOYER_ADDRESS"))
    totp = int(time.time()) // 3600
    domain_type = keccak256(b"EIP712Domain(string name,string version,uint256 chainId)")
    domain = keccak256(domain_type + keccak256(b"Safe Transaction Service") + keccak256(b"1.0") + word(CHAIN_ID))
    struct = keccak256(keccak256(b"Delegate(address delegateAddress,uint256 totp)") + word(delegate) + word(totp))
    delegate_hash = keccak256(b"\x19\x01" + domain + struct)
    data = b"\x02" + h2b(safe) + keccak256(delegate_hash)
    ok = call(owner, "isValidSignature(bytes32,bytes)", ["bytes32", "bytes"], [delegate_hash, data])[:4].hex()
    st["delegate"] = {"delegate": delegate, "delegator": owner, "totp": totp, "delegate_hash": b2h(delegate_hash),
                      "owner_isValidSignature_eth_call": "0x" + ok}
    save(st)
    service(st, "h: register a delegate for member 1", "POST", "/v2/delegates/",
            {"safe": safe, "delegate": delegate, "delegator": owner, "signature": b2h(contract_sig(owner, data)),
             "label": "winterlock live test"})


def step_balance(st):
    st["balances_wei"] = {"deployer": balance(env("DEPLOYER_ADDRESS")), "safe": balance(st["safe"]["address"])}
    st["safe"]["nonce_now"] = dec_uint(call(st["safe"]["address"], "nonce()"))
    spent = sum(v.get("cost_wei", 0) for v in st["onchain"].values()) + st["onchain"].get("fund", {}).get(
        "value_wei", 0)
    st["spent_wei_including_funding"] = spent
    log(f"  deployer {st['balances_wei']['deployer'] / 1e18:.6f} ETH, Safe {st['balances_wei']['safe']} wei, "
        f"Safe nonce {st['safe']['nonce_now']}, spent {spent / 1e18:.6f} ETH")


STEPS = {"keys": step_keys, "deploy": step_deploy, "safe": step_safe, "enrol": step_enrol, "index": step_index,
         "propose": step_propose, "confirm": step_confirm, "show": step_show, "execute": step_execute,
         "replace": step_replace, "message": step_message, "delegate": step_delegate, "balance": step_balance}
REPEATABLE = {"keys", "deploy", "safe", "enrol", "show", "balance"}


def main():
    names = sys.argv[1:] or list(STEPS)
    st = load()
    st.setdefault("steps_done", [])
    try:
        for name in names:
            if name in st["steps_done"] and name not in REPEATABLE:
                log(f"{name}: already done, skipped")
                continue
            log(f"{name}:")
            STEPS[name](st)
            if name not in st["steps_done"]:
                st["steps_done"].append(name)
            save(st)
    except Exception as e:  # never let a secret reach the terminal through a traceback message
        save(st)
        raise SystemExit(redact(f"{type(e).__name__}: {e}"))
    finally:
        if _signer:
            _signer.close()


if __name__ == "__main__":
    main()
