"""WalletConnect v2 (Sign API), the wallet's side: the subset the signer needs to answer dapps as the team's Safe.

No WalletConnect SDK exists for Python that is maintained and MIT-compatible, so the needed part of the protocol is
implemented here, from @walletconnect/sign-client, core, utils and relay-auth 2.21.0 (their sources), and checked
byte for byte against them (tests/test_walletconnect.py):

  pairing URI   wc:{topic}@2?relay-protocol=irn&symKey={hex}[&expiryTimestamp=...][&methods=...]
  keys          X25519 (RFC 7748, below), then HKDF-SHA256 (no salt, no info, 32 bytes): a session's symKey.
                A topic is sha256(symKey), hex.
  envelopes     type 0: base64([0x00][iv: 12][ChaCha20-Poly1305 ciphertext and tag]); type 1 adds the sender's
                X25519 key after the type byte (read, never sent)
  relay         JSON-RPC over a WebSocket: irn_subscribe, irn_publish, irn_unsubscribe; the relay pushes
                irn_subscription, acknowledged with `true`. The URL carries an EdDSA JWT (relay-auth: a random
                Ed25519 client key as did:key issuer) and, for Reown's relay, the project ID.
  sign protocol wc_sessionPropose (approved with wc_sessionSettle on the new session topic, then the answer
                {relay, responderPublicKey} on the pairing topic, in that order as sign-client does), wc_sessionRequest,
                wc_sessionPing, wc_pairingPing, wc_sessionDelete. Each with sign-client's relay tag and TTL.

Not implemented: one-click auth (wc_sessionAuthenticate: dapps that send it also send a session proposal, which is
answered), session updates and extensions from the wallet, link mode, the Verify API (so a dapp's metadata, its name
and URL, are what the dapp claims), and session persistence: keys live in memory only and a restart pairs again.
"""

import base64
import hashlib
import json
import os
import queue
import random
import threading
import time
import urllib.parse

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from . import ws

DEFAULT_RELAY = "wss://relay.walletconnect.org"
PROTOCOL = "irn"
SESSION_EXPIRY = 7 * 24 * 3600
UA = "wc-2/python-winterlock-0.1/signer"

# sign-client 2.21.0, ENGINE_RPC_OPTS: method -> (request ttl, request tag, response ttl, response tag)
RPC_OPTS = {
    "wc_sessionPropose": (300, 1100, 300, 1101),
    "wc_sessionSettle": (300, 1102, 300, 1103),
    "wc_sessionUpdate": (86400, 1104, 86400, 1105),
    "wc_sessionExtend": (86400, 1106, 86400, 1107),
    "wc_sessionRequest": (300, 1108, 300, 1109),
    "wc_sessionEvent": (300, 1110, 300, 1111),
    "wc_sessionDelete": (86400, 1112, 86400, 1113),
    "wc_sessionPing": (86400, 1114, 86400, 1115),
    "wc_sessionAuthenticate": (3600, 1116, 3600, 1117),
    "wc_pairingDelete": (86400, 1000, 86400, 1001),
    "wc_pairingPing": (30, 1002, 30, 1003),
}
PROPOSE_REJECT = (300, 1120)

# @walletconnect/utils SDK_ERRORS
USER_REJECTED = 5000
UNSUPPORTED_CHAINS = 5100
UNSUPPORTED_METHODS = 5101
UNSUPPORTED_NAMESPACE_KEY = 5104
USER_DISCONNECTED = 6000


class RelayError(Exception):
    pass


# --- keys and envelopes ---

_P = 2**255 - 19


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 X25519. Not constant-time (Python integers): used only for ephemeral session keys."""
    if len(k) != 32 or len(u) != 32:
        raise ValueError("X25519 takes 32-byte keys")
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + 121665 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def x25519_base(k: bytes) -> bytes:
    return x25519(k, (9).to_bytes(32, "little"))


def keypair():
    """(private, public) X25519 keys, 32 bytes each"""
    priv = os.urandom(32)
    return priv, x25519_base(priv)


def derive_sym_key(priv: bytes, peer_pub: bytes) -> bytes:
    shared = x25519(priv, peer_pub)
    if not any(shared):
        raise ValueError("the peer's public key is a low-order point")
    return HKDF(shared, 32, None, SHA256, num_keys=1, context=b"")


def topic_of(sym_key: bytes) -> str:
    return hashlib.sha256(sym_key).hexdigest()


def seal(sym_key: bytes, plaintext: str, iv: bytes = None) -> str:
    """A type 0 envelope, base64 (with padding), as @walletconnect/utils encrypt()"""
    iv = iv if iv is not None else os.urandom(12)
    c = ChaCha20_Poly1305.new(key=sym_key, nonce=iv)
    ct, tag = c.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(b"\x00" + iv + ct + tag).decode()


def unseal(sym_key: bytes, encoded: str) -> str:
    """Opens a type 0 or type 1 envelope with the topic's symKey; raises ValueError if it doesn't authenticate"""
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_" if ("-" in encoded or "_" in encoded)
                               else None, validate=False)
    except ValueError:
        raise ValueError("envelope is not base64") from None
    if not raw:
        raise ValueError("empty envelope")
    if raw[0] == 0:
        iv, sealed = raw[1:13], raw[13:]
    elif raw[0] == 1:
        iv, sealed = raw[33:45], raw[45:]
    else:
        raise ValueError(f"envelope type {raw[0]} is not supported")
    if len(iv) != 12 or len(sealed) < 16:
        raise ValueError("envelope too short")
    c = ChaCha20_Poly1305.new(key=sym_key, nonce=iv)
    return c.decrypt_and_verify(sealed[:-16], sealed[-16:]).decode()


# --- pairing URI ---

def parse_uri(uri: str) -> dict:
    """{topic, sym_key, relay_protocol, expiry, methods} from a wc: URI (v2 only). Errors never echo the URI: it holds
    the pairing's key."""
    uri = uri.strip()
    if not uri.startswith("wc:") or "@" not in uri:
        raise ValueError("not a WalletConnect URI (wc:...@2?...)")
    head, _, query = uri[3:].partition("?")
    topic, _, version = head.partition("@")
    if version != "2":
        raise ValueError(f"WalletConnect version {version or '?'} is not supported (v2 only)")
    q = dict(urllib.parse.parse_qsl(query))
    try:
        sym = bytes.fromhex(q.get("symKey", ""))
        int(topic, 16)
    except ValueError:
        raise ValueError("the URI's topic or symKey is not hex") from None
    if len(sym) != 32 or len(topic) != 64:
        raise ValueError("the URI's topic or symKey has the wrong length")
    if topic_of(sym) != topic.lower():
        # sign-client derives the pairing topic independently of the key, so this isn't required; only noted
        pass
    exp = q.get("expiryTimestamp")
    return {"topic": topic.lower(), "sym_key": sym, "relay_protocol": q.get("relay-protocol", PROTOCOL),
            "expiry": int(exp) if exp and exp.isdigit() else None, "methods": q.get("methods")}


# --- relay authentication (relay-auth 1.1.0) ---

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _json(o) -> bytes:
    return json.dumps(o, separators=(",", ":")).encode()


def did_key(ed25519_pub: bytes) -> str:
    return "did:key:z" + b58encode(b"\xed\x01" + ed25519_pub)


def relay_jwt(seed: bytes, sub: str, aud: str, iat: int = None, ttl: int = 86400) -> str:
    key = ECC.construct(curve="Ed25519", seed=seed)
    pub = key.public_key().export_key(format="raw")
    iat = int(time.time()) if iat is None else iat
    data = _b64url(_json({"alg": "EdDSA", "typ": "JWT"})) + "." + _b64url(_json(
        {"iss": did_key(pub), "sub": sub, "aud": aud, "iat": iat, "exp": iat + ttl}))
    return data + "." + _b64url(eddsa.new(key, "rfc8032").sign(data.encode()))


def payload_id() -> int:
    """JSON-RPC ids as @walletconnect/jsonrpc-utils makes them: milliseconds * 1000 + 3 random digits"""
    return int(time.time() * 1000) * 1000 + random.randrange(1000)


# --- relay client ---

class Relay:
    """JSON-RPC to a WalletConnect relay over one WebSocket, reconnecting (and resubscribing) when it drops.
    `on_message(topic, message, published_at)` runs on the reader thread and must not wait for the relay."""

    def __init__(self, url: str = DEFAULT_RELAY, project_id: str = None, log=print, timeout=30):
        self.base = url.rstrip("/") if url.count("/") <= 2 else url
        self.project_id = project_id
        self.log = log
        self.timeout = timeout
        self._seed = os.urandom(32)  # the relay JWT's Ed25519 key: in memory only
        self._sub = os.urandom(32).hex()
        self.on_message = None
        self.topics = {}
        self._pending = {}
        self._lock = threading.Lock()
        self._connected = threading.Event()
        self._closing = False
        self._seen = []
        self.conn = None

    def url(self) -> str:
        params = {"auth": relay_jwt(self._seed, self._sub, self.base), "ua": UA}
        if self.project_id:
            params["projectId"] = self.project_id
        sep = "&" if "?" in self.base else "?"
        return self.base + sep + urllib.parse.urlencode(params)

    def host(self) -> str:
        u = urllib.parse.urlsplit(self.base)
        return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")

    def start(self):
        self._connect()
        threading.Thread(target=self._keepalive, daemon=True).start()

    def _connect(self):
        self.conn = ws.connect(self.url(), timeout=self.timeout)
        self._connected.set()
        threading.Thread(target=self._reader, args=(self.conn,), daemon=True).start()

    def close(self):
        self._closing = True
        self._connected.clear()
        if self.conn:
            self.conn.close()

    def _keepalive(self):
        while not self._closing:
            time.sleep(20)
            if self._connected.is_set():
                try:
                    self.conn.ping()
                except ws.WsClosed:
                    pass

    def _reader(self, conn):
        while True:
            try:
                text = conn.recv()
            except ws.WsClosed as e:
                if self._closing or conn is not self.conn:
                    return
                self._connected.clear()
                self.log(f"  (relay connection lost: {e}; reconnecting)")
                threading.Thread(target=self._reconnect, daemon=True).start()
                return
            try:
                msg = json.loads(text)
            except ValueError:
                continue
            if "method" in msg:
                if msg["method"].endswith("_subscription"):
                    try:
                        conn.send_text(json.dumps({"id": msg.get("id"), "jsonrpc": "2.0", "result": True}))
                    except ws.WsClosed:
                        pass
                    data = (msg.get("params") or {}).get("data") or {}
                    digest = hashlib.sha256((data.get("topic", "") + data.get("message", "")).encode()).digest()
                    if digest in self._seen:
                        continue  # delivered again after a reconnect
                    self._seen = (self._seen + [digest])[-512:]
                    if self.on_message and data.get("topic") in self.topics:
                        self.on_message(data["topic"], data.get("message", ""), data.get("publishedAt"))
                continue
            with self._lock:
                slot = self._pending.get(msg.get("id"))
            if slot:
                slot[1] = msg
                slot[0].set()

    def _reconnect(self):
        delay = 1
        while not self._closing:
            try:
                self._connect()
                for topic in list(self.topics):
                    self.topics[topic] = self.request("irn_subscribe", {"topic": topic})
                self.log("  (relay reconnected)")
                return
            except (ws.WsClosed, RelayError) as e:
                self.log(f"  (relay: {e}; retrying in {delay} s)")
                time.sleep(delay)
                delay = min(delay * 2, 30)

    def request(self, method: str, params: dict, timeout: float = None):
        timeout = timeout or self.timeout
        deadline = time.time() + timeout
        for attempt in (0, 1):
            if not self._connected.wait(max(0.1, deadline - time.time())):
                raise RelayError(f"{method}: not connected to the relay")
            rid = payload_id()
            ev = threading.Event()
            with self._lock:
                self._pending[rid] = [ev, None]
            try:
                self.conn.send_text(json.dumps({"id": rid, "jsonrpc": "2.0", "method": method, "params": params}))
                got = ev.wait(max(0.1, deadline - time.time()))
            except ws.WsClosed:
                got = False
            finally:
                with self._lock:
                    resp = self._pending.pop(rid)[1]
            if got and resp is not None:
                if "error" in resp:
                    raise RelayError(f"{method}: {str(resp['error'].get('message', resp['error']))[:200]}")
                return resp.get("result")
            if time.time() >= deadline:
                break
        raise RelayError(f"{method}: no answer from the relay")

    def subscribe(self, topic: str):
        self.topics[topic] = None
        self.topics[topic] = self.request("irn_subscribe", {"topic": topic})

    def unsubscribe(self, topic: str):
        sid = self.topics.pop(topic, None)
        if sid:
            try:
                self.request("irn_unsubscribe", {"topic": topic, "id": sid})
            except RelayError:
                pass

    def publish(self, topic: str, message: str, ttl: int, tag: int, prompt: bool = False, correlation_id=None):
        params = {"topic": topic, "message": message, "ttl": ttl, "tag": tag}
        if prompt:
            params["prompt"] = True
        if correlation_id is not None:
            params["correlationId"] = correlation_id
        self.request("irn_publish", params)


# --- the Sign protocol, wallet side ---

class Proposal:
    def __init__(self, rid, pairing_topic, params):
        self.id = rid
        self.pairing_topic = pairing_topic
        self.params = params
        proposer = params.get("proposer") or {}
        self.peer_public_key = bytes.fromhex(proposer.get("publicKey", ""))
        self.metadata = proposer.get("metadata") or {}
        self.required = params.get("requiredNamespaces") or {}
        self.optional = params.get("optionalNamespaces") or {}
        self.expiry = params.get("expiryTimestamp")


class Session:
    def __init__(self, topic, sym_key, peer, namespaces, expiry, pairing_topic):
        self.topic = topic
        self.sym_key = sym_key
        self.peer = peer  # the dapp's metadata (claimed, not verified)
        self.namespaces = namespaces
        self.expiry = expiry
        self.pairing_topic = pairing_topic
        self.acknowledged = False


class Request:
    def __init__(self, rid, topic, params, received):
        self.id = rid
        self.topic = topic
        req = params.get("request") or {}
        self.method = req.get("method")
        self.params = req.get("params")
        self.chain_id = params.get("chainId")
        exp = req.get("expiryTimestamp")
        # without an expiry, sign-client's default of 300 s applies
        self.expiry = int(exp) if isinstance(exp, (int, float)) else int(received) + 300


class Wallet:
    """The wallet's side of pairings and sessions. Events (proposals, requests, deletions) arrive on `events` as
    (kind, object) tuples; answers go out with approve, reject and respond."""

    def __init__(self, relay: Relay, metadata: dict, log=print):
        self.relay = relay
        self.metadata = metadata
        self.log = log
        self.keys = {}  # topic -> symKey, in memory only
        self.sessions = {}
        self._our_requests = {}
        self.events = queue.Queue()
        self._inbox = queue.Queue()
        relay.on_message = lambda topic, message, at: self._inbox.put((topic, message))
        threading.Thread(target=self._dispatch, daemon=True).start()

    # --- outgoing ---

    def _send(self, topic, payload, ttl, tag, prompt=False):
        self.relay.publish(topic, seal(self.keys[topic], json.dumps(payload, separators=(",", ":"))), ttl, tag, prompt,
                           correlation_id=payload.get("id"))

    def _request(self, topic, method, params):
        rid = payload_id()
        self._our_requests[rid] = (topic, method)
        ttl, tag, _, _ = RPC_OPTS[method]
        self._send(topic, {"id": rid, "jsonrpc": "2.0", "method": method, "params": params}, ttl, tag)
        return rid

    def _result(self, topic, rid, method, result):
        _, _, ttl, tag = RPC_OPTS.get(method, (0, 0, 300, 0))
        self._send(topic, {"id": rid, "jsonrpc": "2.0", "result": result}, ttl, tag)

    def _error(self, topic, rid, method, code, message, opts=None):
        _, _, ttl, tag = RPC_OPTS.get(method, (0, 0, 300, 0))
        if opts:
            ttl, tag = opts
        self._send(topic, {"id": rid, "jsonrpc": "2.0", "error": {"code": code, "message": message}}, ttl, tag)

    def pair(self, uri: str) -> str:
        p = parse_uri(uri)
        if p["expiry"] and p["expiry"] < time.time():
            raise ValueError("the pairing URI has expired: get a new one from the dapp")
        if p["relay_protocol"] != PROTOCOL:
            raise ValueError(f"relay protocol {p['relay_protocol']} is not supported")
        self.keys[p["topic"]] = p["sym_key"]
        self.relay.subscribe(p["topic"])
        return p["topic"]

    def approve(self, proposal: Proposal, namespaces: dict, session_properties: dict = None) -> Session:
        priv, pub = keypair()
        sym = derive_sym_key(priv, proposal.peer_public_key)
        topic = topic_of(sym)
        self.keys[topic] = sym
        expiry = int(time.time()) + SESSION_EXPIRY
        settle = {"relay": {"protocol": PROTOCOL}, "namespaces": namespaces,
                  "controller": {"publicKey": pub.hex(), "metadata": self.metadata}, "expiry": expiry}
        if session_properties:
            settle["sessionProperties"] = session_properties
        session = Session(topic, sym, proposal.metadata, namespaces, expiry, proposal.pairing_topic)
        self.sessions[topic] = session
        self.relay.subscribe(topic)
        # as sign-client 2.21 orders it: the settlement on the session topic first, then the answer to the proposal
        self._request(topic, "wc_sessionSettle", settle)
        self._result(proposal.pairing_topic, proposal.id, "wc_sessionPropose",
                     {"relay": {"protocol": PROTOCOL}, "responderPublicKey": pub.hex()})
        return session

    def reject(self, proposal: Proposal, code: int, message: str):
        self._error(proposal.pairing_topic, proposal.id, "wc_sessionPropose", code, message, PROPOSE_REJECT)

    def respond(self, req: Request, result=None, error=None):
        """Answers a session request: `error` is (code, message)"""
        if error:
            self._error(req.topic, req.id, "wc_sessionRequest", error[0], error[1])
        else:
            self._result(req.topic, req.id, "wc_sessionRequest", result)

    def emit(self, session: Session, chain_id: str, name: str, data):
        self._request(session.topic, "wc_sessionEvent", {"event": {"name": name, "data": data}, "chainId": chain_id})

    def disconnect(self, session: Session, code=USER_DISCONNECTED, message="User disconnected"):
        try:
            self._request(session.topic, "wc_sessionDelete", {"code": code, "message": message})
        except RelayError:
            pass
        self._forget(session.topic)

    def _forget(self, topic):
        self.sessions.pop(topic, None)
        self.relay.unsubscribe(topic)
        self.keys.pop(topic, None)

    # --- incoming ---

    def _dispatch(self):
        while True:
            topic, message = self._inbox.get()
            try:
                self._handle(topic, message)
            except Exception as e:  # a malformed message must not stop the session
                self.log(f"  (WalletConnect: dropped a message on {topic[:8]}…: {type(e).__name__}: {str(e)[:120]})")

    def _handle(self, topic, message):
        key = self.keys.get(topic)
        if key is None:
            return
        try:
            payload = json.loads(unseal(key, message))
        except ValueError:
            self.log(f"  (WalletConnect: a message on {topic[:8]}… doesn't decrypt: ignored)")
            return
        rid = payload.get("id")
        method = payload.get("method")
        if method is None:  # an answer to one of our requests
            sent = self._our_requests.pop(rid, None)
            if sent and sent[1] == "wc_sessionSettle" and sent[0] in self.sessions:
                if "error" in payload:
                    self.events.put(("settle_failed", self.sessions[sent[0]]))
                else:
                    self.sessions[sent[0]].acknowledged = True
                    self.events.put(("settled", self.sessions[sent[0]]))
            return
        params = payload.get("params") or {}
        if method == "wc_sessionPropose":
            self.events.put(("proposal", Proposal(rid, topic, params)))
        elif method == "wc_sessionRequest" and topic in self.sessions:
            self.events.put(("request", Request(rid, topic, params, time.time())))
        elif method in ("wc_sessionPing", "wc_pairingPing"):
            self._result(topic, rid, method, True)
        elif method == "wc_sessionDelete" and topic in self.sessions:
            self._result(topic, rid, method, True)
            session = self.sessions[topic]
            self._forget(topic)
            self.events.put(("deleted", session))
        elif method == "wc_pairingDelete":
            self._result(topic, rid, method, True)
        elif method == "wc_sessionAuthenticate":
            pass  # one-click auth: not supported; the dapp's session proposal on the same pairing is answered
        else:
            self._error(topic, rid, method, -32601, f"{method} is not supported by this wallet")
