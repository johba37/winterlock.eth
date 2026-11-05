"""Messages an app asks the Safe to sign (personal_sign, eth_signTypedData_v4), and D14's two ways to answer them.

  off-chain  for messages apps check off-chain (sign-in with Ethereum, typed data a server verifies). Each member's
             stateless key signs the Safe's SafeMessage for the app's hash; k of these owner signatures, combined,
             are the Safe's EIP-1271 signature (11,668 bytes for 2 of 3), checked through the Safe's fallback handler.
             Nothing goes on-chain; the members exchange signatures peer to peer (a message file) or through a
             collection endpoint (collect.py).
  on-chain   for messages apps check on-chain (permits, Permit2, orders a contract settles). The team approves the
             message in an ordinary WOTS-signed Safe transaction that delegatecalls SignMessageLib.signMessage; after
             it executes, the Safe accepts an empty signature (0x) for that message.
  refused    what the signer can't decode, or what could be an attack: a bare 32-byte hash, binary data, hidden
             characters, a sign-in for another account, chain or site, the Safe's own typed data (SafeTx,
             SafeMessage, SafeOp), a validator's enable data (Kernel's Enable), permits that only accept ECDSA.

The app's hash is computed here from what the app sent (EIP-191 or EIP-712), never taken from it. Every member who
signs decides again from the original request.

SafeMessage (Safe's CompatibilityFallbackHandler, v1.3.0 to v1.5.0), for an app's isValidSignature(bytes32 h, sig):
  message = abi.encode(h); msgHash = keccak256(message)
  safeMessageHash = keccak256(0x1901 ‖ Safe's domain separator ‖ keccak256(abi.encode(SAFE_MSG_TYPEHASH, msgHash)))
Owner signature data (WinterlockOwner): [0x02][safe: 20][msgHash: 32][stateless signature of
  messageDigest(chain, owner, safe, safeMessageHash): 5,684]
"""

import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from . import abi, owner
from .abi import b2h, checksum, h2b, word
from .eip712 import TypedData, personal_hash
from .keccak import keccak256
from .safe import eip712, pack, parse_signature

SAFE_MSG_TYPEHASH = keccak256(b"SafeMessage(bytes message)")
KIND_MESSAGE = 2
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
MAX_UINT160 = (1 << 160) - 1
MAX_UINT256 = (1 << 256) - 1
# typed data that belongs to Safe itself or to account validators: never signed for a dapp
SAFE_TYPES = {"SafeTx", "SafeMessage", "SafeOp", "Delegate"}
ENABLE_TYPES = {"Enable", "WinterlockMessage"}
VALIDATOR_DOMAINS = {"kernel", "winterlock"}

OFFCHAIN, ONCHAIN, REFUSE = "off-chain", "on-chain", "refused"


@dataclass
class Decision:
    method: str
    kind: str
    path: str
    app_hash: bytes = None
    lines: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    reason: str = ""

    def show(self) -> list:
        out = [f"Message      {self.kind} ({self.method})"]
        out += [f"  {line}" for line in self.lines]
        if self.app_hash:
            out.append(f"  hash the app checks {b2h(self.app_hash)} (computed here)")
        for w in self.warnings:
            out.append(f"  WARNING: {w}")
        out.append(f"Path         {self.path.upper()}: {self.reason}")
        return out


def message_hash(app_hash: bytes) -> bytes:
    """keccak256(abi.encode(h)): the hash of the SafeMessage's message for an app's bytes32 hash"""
    return keccak256(app_hash)


def safe_message_hash(chain_id: int, safe: str, app_hash: bytes) -> bytes:
    return eip712(chain_id, safe, keccak256(SAFE_MSG_TYPEHASH + message_hash(app_hash)))


def signature_data(member, chain_id: int, safe: str, app_hash: bytes) -> bytes:
    """This member's owner signature data for the SafeMessage of `app_hash`, signed with the stateless key. The
    signature is recorded in the key log (it counts against the stateless key's budget) before it is made."""
    smh = safe_message_hash(chain_id, safe, app_hash)
    digest = owner.message_digest(chain_id, member.owner, safe, smh)
    member.log.append({"t": "msg", "chain": chain_id, "safe": safe, "hash": b2h(smh)})
    sig = member.stateless_sign(digest)
    return bytes([KIND_MESSAGE]) + h2b(safe) + message_hash(app_hash) + sig


# --- deciding ---

def _refuse(method, kind, reason, lines=()):
    return Decision(method, kind, REFUSE, None, list(lines), [], reason)


def _same(a, b) -> bool:
    try:
        return abi.is_address(a) and abi.is_address(b) and h2b(a) == h2b(b)
    except ValueError:
        return False


def _split_params(method, params, safe):
    """(address, payload) from personal_sign [message, address] or typed data [address, data], tolerating the
    reversed order some apps send"""
    if not isinstance(params, list) or len(params) < 2:
        raise ValueError(f"{method} needs two parameters")
    a, b = params[0], params[1]
    if method == "personal_sign":
        if isinstance(a, str) and abi.is_address(a) and _same(a, safe) and not (isinstance(b, str) and
                                                                               abi.is_address(b)):
            return a, b
        return b, a
    if isinstance(b, str) and abi.is_address(b) and not (isinstance(a, str) and abi.is_address(a)):
        return b, a
    return a, b


def _hidden(text: str):
    """Characters that can hide or reorder what the user reads"""
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "\n\t\r":
            continue
        if cat in ("Cc", "Cf", "Co", "Cs", "Cn") or ch in "  ":
            return f"U+{ord(ch):04X} ({unicodedata.name(ch, cat)})"
    return None


_SIWE_HEAD = re.compile(r"^(?:(?P<scheme>[a-zA-Z][a-zA-Z0-9+\-.]*)://)?(?P<domain>[^\s/?#]+) wants you to sign in with "
                        r"your Ethereum account:$")
_SIWE_FIELDS = ("URI", "Version", "Chain ID", "Nonce", "Issued At", "Expiration Time", "Not Before", "Request ID")


def parse_siwe(text: str):
    """EIP-4361 fields, or None if the text isn't a sign-in message"""
    lines = text.split("\n")
    m = _SIWE_HEAD.match(lines[0]) if lines else None
    if not m or len(lines) < 3:
        return None
    out = {"domain": m["domain"], "scheme": m["scheme"], "address": lines[1].strip(), "statement": None,
           "resources": []}
    i = 2
    rest = []
    while i < len(lines):
        line = lines[i]
        key, sep, val = line.partition(": ")
        if sep and key in _SIWE_FIELDS:
            out[key] = val
        elif line == "Resources:":
            out["resources"] = [x[2:] for x in lines[i + 1:] if x.startswith("- ")]
            break
        elif line.strip():
            rest.append(line)
        i += 1
    out["statement"] = "\n".join(rest) or None
    return out


def _iso(s):
    try:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except (ValueError, TypeError):
        return None


def _host(url):
    try:
        return (urllib.parse.urlsplit(url if "//" in url else "//" + url).hostname or "").lower()
    except ValueError:
        return ""


def _related(a: str, b: str) -> bool:
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def decide(method: str, params, safe: str, chain_id: int, dapp_url: str = None, owners=(), now=None) -> Decision:
    """Which path a message request takes, what it says, and why; refusals carry the reason"""
    now = time.time() if now is None else now
    safe = checksum(safe)
    if method == "eth_sign":
        return _refuse(method, "eth_sign", "eth_sign signs a bare hash the signer can't decode: refused")
    if method == "personal_sign":
        return _decide_personal(params, safe, chain_id, dapp_url, now)
    if method in ("eth_signTypedData", "eth_signTypedData_v3", "eth_signTypedData_v4"):
        return _decide_typed(method, params, safe, chain_id, owners, now)
    return _refuse(method, method, f"{method} is not a message method")


def _decide_personal(params, safe, chain_id, dapp_url, now) -> Decision:
    m = "personal_sign"
    try:
        addr, payload = _split_params(m, params, safe)
    except ValueError as e:
        return _refuse(m, "message", str(e))
    if not isinstance(addr, str) or not _same(addr, safe):
        return _refuse(m, "message", f"the app asks for a signature by {addr}, not by this Safe {safe}")
    if not isinstance(payload, str):
        return _refuse(m, "message", "the message is not a string")
    data = None
    if payload.startswith(("0x", "0X")):
        try:
            data = h2b(payload)
        except ValueError:
            data = None
    if data is None:
        data = payload.encode()
    if not data:
        return _refuse(m, "message", "the message is empty")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or (len(data) == 32 and _hidden(text)):
        if len(data) == 32:
            return _refuse(m, "bare hash", f"the message is a bare 32-byte hash ({b2h(data)}), which could be a "
                                           "transaction, a permit or another account's message: refused")
        return _refuse(m, "binary data", f"the message is {len(data)} bytes of binary data, not text: the signer "
                                         "can't show what it means")
    bad = _hidden(text)
    if bad:
        return _refuse(m, "message", f"the text holds an invisible or control character {bad}, which can hide what "
                                     "it says")
    h = personal_hash(data)
    lines = ["| " + line for line in text.split("\n")]
    siwe = parse_siwe(text)
    if not siwe:
        return Decision(m, "text message", OFFCHAIN, h, lines, [],
                        "a text message, which apps check off-chain: the members' stateless signatures, collected "
                        "peer to peer")
    warnings = []
    if not _same(siwe["address"], safe):
        return _refuse(m, "sign-in with Ethereum", f"the sign-in is for {siwe['address']}, not this Safe", lines)
    cid = siwe.get("Chain ID")
    if cid != str(chain_id):
        return _refuse(m, "sign-in with Ethereum", f"the sign-in names chain {cid}, but this Safe is connected on "
                                                   f"chain {chain_id}; the signature only verifies on {chain_id}",
                       lines)
    if siwe.get("Version") != "1":
        return _refuse(m, "sign-in with Ethereum", f"unknown sign-in version {siwe.get('Version')}", lines)
    exp = _iso(siwe.get("Expiration Time"))
    if siwe.get("Expiration Time") and (exp is None or exp < now):
        return _refuse(m, "sign-in with Ethereum", f"the sign-in expired at {siwe['Expiration Time']}", lines)
    nbf = _iso(siwe.get("Not Before"))
    if nbf and nbf > now:
        warnings.append(f"not valid before {siwe['Not Before']}")
    domain_host = _host(siwe["domain"])
    if dapp_url is not None:
        if not _related(domain_host, _host(dapp_url)):
            return _refuse(m, "sign-in with Ethereum", f"the sign-in is for {siwe['domain']}, but the connected app "
                                                       f"says it is {dapp_url}: a site may be signing you in "
                                                       "somewhere else", lines)
    else:
        warnings.append(f"check that you are signing in to {siwe['domain']}")
    if siwe.get("URI") and not _related(_host(siwe["URI"]), domain_host):
        warnings.append(f"the URI {siwe['URI']} is not on {siwe['domain']}")
    return Decision(m, f"sign-in with Ethereum to {siwe['domain']}", OFFCHAIN, h, lines, warnings,
                    "a sign-in, which the app checks off-chain: the members' stateless signatures, collected peer to "
                    "peer")


def _decide_typed(method, params, safe, chain_id, owners, now) -> Decision:
    try:
        addr, payload = _split_params(method, params, safe)
    except ValueError as e:
        return _refuse(method, "typed data", str(e))
    if not isinstance(addr, str) or not _same(addr, safe):
        return _refuse(method, "typed data", f"the app asks for a signature by {addr}, not by this Safe {safe}")
    try:
        td = TypedData(payload)
        h = td.hash()
        vc = td.verifying_contract()
        cid = td.chain_id()
        lines = [f"domain {_domain_line(td)}", f"{td.primary}:"]
        lines += td.lines() if td.primary != "EIP712Domain" else []
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        return _refuse(method, "typed data", f"the typed data doesn't decode: {e}")
    name = str(td.domain.get("name", ""))
    kind = f"typed data {td.primary}" + (f" for {name}" if name else "")
    if cid is not None and cid != chain_id:
        return _refuse(method, kind, f"the typed data names chain {cid}, not {chain_id}", lines)
    if td.primary == "EIP712Domain":
        return _refuse(method, kind, "the typed data is a bare domain, with no message", lines)
    if td.primary in SAFE_TYPES or (vc and (_same(vc, safe) or any(_same(vc, o) for o in owners))):
        return _refuse(method, kind, "the typed data is addressed to the Safe itself or one of its owners (a Safe "
                                     "transaction or message): it could move funds or approve something else", lines)
    if td.primary in ENABLE_TYPES or name.lower() in VALIDATOR_DOMAINS:
        return _refuse(method, kind, "the typed data enables a validator or module on an account: refused", lines)
    msg = td.message
    fields = {f for f, _ in td.types[td.primary]}
    warnings = []
    for f in ("deadline", "sigDeadline", "expiry", "expiration", "validTo", "endTime"):
        if f in msg:
            try:
                t = int(str(msg[f]), 0) if str(msg[f]).startswith("0x") else int(msg[f])
                if 0 < t < now:
                    warnings.append(f"{f} {t} is in the past")
            except (ValueError, TypeError):
                pass
    if td.primary == "Permit" and {"holder", "allowed"} <= fields:
        return _refuse(method, kind, "a DAI-style permit: the token checks it with ecrecover only, which no Safe can "
                                     "satisfy", lines)
    if td.primary == "Permit" and {"owner", "spender", "value"} <= fields:
        if not _same(str(msg.get("owner")), safe):
            return _refuse(method, kind, f"the permit's owner is {msg.get('owner')}, not this Safe", lines)
        if _uint(msg.get("value")) in (MAX_UINT256, MAX_UINT160):
            warnings.append(f"an unlimited allowance for {msg.get('spender')}")
        warnings.append("EIP-2612 tokens built on OpenZeppelin's ERC20Permit accept only ECDSA: the approval can "
                        "execute and the permit still fail; tokens that check EIP-1271 (such as USDC v2.2) accept it")
        return Decision(method, f"EIP-2612 permit for {name or vc}", ONCHAIN, h, lines, warnings,
                        "a permit, which the token checks on-chain: a Safe transaction approves it through "
                        "SignMessageLib; then the Safe accepts an empty signature")
    if (vc and _same(vc, PERMIT2)) or name == "Permit2":
        for d in _walk(msg):
            if isinstance(d, dict) and "amount" in d and _uint(d.get("amount")) in (MAX_UINT160, MAX_UINT256):
                warnings.append("an unlimited Permit2 allowance")
                break
        return Decision(method, f"Permit2 {td.primary}", ONCHAIN, h, lines, warnings,
                        "Permit2 checks the signature on-chain: a Safe transaction approves it through SignMessageLib; "
                        "then the Safe accepts an empty signature")
    if vc:
        return Decision(method, kind, ONCHAIN, h, lines, warnings,
                        f"it names a verifying contract ({vc}), which checks it on-chain: a Safe transaction approves "
                        "it through SignMessageLib; then the Safe accepts an empty signature")
    return Decision(method, kind, OFFCHAIN, h, lines, warnings,
                    "it names no verifying contract, so a server checks it off-chain: the members' stateless "
                    "signatures, collected peer to peer")


def _domain_line(td):
    return ", ".join(f"{k} {td.domain[k]}" for k, _ in td.types["EIP712Domain"] if k in td.domain)


def _uint(v):
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except (ValueError, TypeError):
        return None


def _walk(v):
    yield v
    if isinstance(v, dict):
        for x in v.values():
            yield from _walk(x)
    elif isinstance(v, list):
        for x in v:
            yield from _walk(x)


# --- message files: the request, and the members' signatures, exchanged peer to peer ---

DOC_KIND = "winterlock-safe-message"


def new_doc(chain_id: int, safe: str, method: str, params, d: Decision, dapp: dict = None) -> dict:
    return {"kind": DOC_KIND, "version": 1, "chain": chain_id, "safe": checksum(safe),
            "request": {"method": method, "params": params},
            "dapp": {k: (dapp or {}).get(k) for k in ("name", "url")},
            "appHash": b2h(d.app_hash), "safeMessageHash": b2h(safe_message_hash(chain_id, safe, d.app_hash)),
            "signatures": []}


def check_doc(doc: dict, chain_id: int, owners=(), now=None) -> Decision:
    """Decides again from the request the file carries; refuses a file whose hashes don't follow from it"""
    if doc.get("kind") != DOC_KIND or doc.get("version") != 1:
        raise ValueError("not a Winterlock message file")
    if doc.get("chain") != chain_id:
        raise ValueError(f"the message file is for chain {doc.get('chain')}, not {chain_id}")
    req = doc.get("request") or {}
    d = decide(req.get("method"), req.get("params"), doc["safe"], chain_id, (doc.get("dapp") or {}).get("url"),
               owners, now)
    if d.path == REFUSE:
        return d
    if b2h(d.app_hash) != doc.get("appHash") or \
            b2h(safe_message_hash(chain_id, doc["safe"], d.app_hash)) != doc.get("safeMessageHash"):
        raise ValueError("the file's hashes don't follow from its request: refusing")
    return d


def add_signature(doc: dict, owner_addr: str, signature_hex: str):
    doc["signatures"] = [s for s in doc.get("signatures", []) if s["owner"].lower() != owner_addr.lower()]
    doc["signatures"].append({"owner": checksum(owner_addr), "signature": signature_hex})


def merge(doc: dict, other: dict) -> int:
    """Adds `other`'s signatures for the same message to `doc`; returns how many were new"""
    if other.get("safeMessageHash") != doc.get("safeMessageHash") or other.get("chain") != doc.get("chain"):
        return 0
    have = {s["owner"].lower(): s["signature"] for s in doc.get("signatures", [])}
    n = 0
    for s in other.get("signatures", []):
        if have.get(s.get("owner", "").lower()) != s.get("signature"):
            add_signature(doc, s["owner"], s["signature"])
            n += 1
    return n


def valid_signatures(rpc, doc: dict, owners) -> list:
    """[(owner, data, True)] of the file's signatures that the owner contracts accept (eth_call), owners only"""
    smh = h2b(doc["safeMessageHash"])
    out = []
    for s in doc.get("signatures", []):
        try:
            o, data, is_contract = parse_signature(h2b(s["signature"]))
        except (ValueError, KeyError):
            continue
        if not is_contract or o.lower() not in [x.lower() for x in owners]:
            continue
        if owner.is_valid_signature(rpc, o, smh, data):
            out.append((o, data, True))
    return out


def combine(sigs: list, threshold: int) -> bytes:
    """The Safe's signature for the message: `threshold` owner signatures in increasing owner order"""
    if len(sigs) < threshold:
        raise ValueError(f"{len(sigs)} of {threshold} signatures")
    return pack(sorted(sigs, key=lambda s: int(s[0], 16))[:threshold])


def safe_accepts(rpc, safe: str, app_hash: bytes, signature: bytes) -> bool:
    """The Safe's own answer, as an app checks it: isValidSignature(bytes32, bytes) through its fallback handler"""
    try:
        ret = rpc.eth_call(safe, abi.calldata("isValidSignature(bytes32,bytes)", ["bytes32", "bytes"],
                                              [app_hash, signature]))
    except Exception:  # a revert counts as a refusal
        return False
    return ret[:4] == owner.MAGIC


def approved_onchain(rpc, safe: str, chain_id: int, app_hash: bytes) -> bool:
    """Whether the Safe has approved the message on-chain (SignMessageLib set signedMessages)"""
    smh = safe_message_hash(chain_id, safe, app_hash)
    return abi.dec_uint(rpc.eth_call(safe, abi.calldata("signedMessages(bytes32)", ["bytes32"], [smh]))) != 0


def sign_message_calldata(app_hash: bytes) -> bytes:
    """SignMessageLib.signMessage(abi.encode(h)), as Safe's app builds it for an app's bytes32 hash"""
    return abi.calldata("signMessage(bytes)", ["bytes"], [word(app_hash)])
