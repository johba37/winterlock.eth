"""A stand-in for a WalletConnect relay, for tests: WebSocket JSON-RPC with the irn_* methods (relay-api), plus the two
methods newer sign-client dapps use for proposals and approvals (wc_proposeSession, wc_approveSession, since 2.21.6),
handled as their client code implies. It checks the client's EdDSA JWT (relay-auth) as the real relay does, and
optionally a project ID.

Behaviour, as the clients expect it: a published message goes to every other connection subscribed to its topic, and
is kept (for its ttl) for connections that subscribe later; a connection never gets its own messages back. Not
modelled: tags, prompts, rate limits, webhooks, the mailbox per client id across reconnects (here per connection, plus
replay on subscribe).

usage: python -m tests.mock_relay --port PORT [--project-id ID]   (or Relay(...).start() in a test)
"""
import argparse
import base64
import hashlib
import itertools
import json
import socket
import threading
import time
import urllib.parse

from Crypto.Signature import eddsa

from winterlock_signer import ws

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jwt(jwt: str, aud_prefix: str = None) -> bool:
    """relay-auth's verifyJWT: EdDSA over header.payload with the did:key issuer, unexpired"""
    try:
        h, p, sig = jwt.split(".")
        header, payload = json.loads(_b64url(h)), json.loads(_b64url(p))
        if header != {"alg": "EdDSA", "typ": "JWT"}:
            return False
        iss = payload["iss"]
        if not iss.startswith("did:key:z"):
            return False
        raw = _b58decode(iss[len("did:key:z"):])
        if raw[:2] != b"\xed\x01" or len(raw) != 34:
            return False
        key = eddsa.import_public_key(raw[2:])
        eddsa.new(key, "rfc8032").verify(f"{h}.{p}".encode(), _b64url(sig))
        return payload["exp"] > time.time() and (aud_prefix is None or payload["aud"].startswith(aud_prefix))
    except (ValueError, KeyError, TypeError):
        return False


class Relay:
    def __init__(self, port=0, project_id=None):
        self.project_id = project_id
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.url = f"ws://127.0.0.1:{self.port}"
        self.lock = threading.Lock()
        self.subs = {}  # topic -> {conn: subscription id}
        self.mailbox = []  # (topic, message, tag, publishedAt ms, expires, sender conn)
        self.delivered = set()  # (conn id, message digest)
        self.published = []  # (method, topic, tag) for tests to inspect
        self.connections = []
        self.ua = {}  # connection -> the client's ua parameter
        self.rejected = 0
        self._ids = itertools.count(1)
        self.closed = False

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def close(self):
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass
        for c in list(self.connections):
            c.close()

    def drop_connections(self, ua_prefix=""):
        """Closes the client connections whose ua starts with `ua_prefix`, as a relay restart would"""
        for c in list(self.connections):
            if self.ua.get(c, "").startswith(ua_prefix):
                c.close()

    def _accept(self):
        while not self.closed:
            try:
                s, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(s,), daemon=True).start()

    def _serve(self, s):
        try:
            conn, path = ws.server_handshake(s)
        except (ws.WsClosed, OSError):
            return
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(path).query))
        if not verify_jwt(q.get("auth", "")) or (self.project_id and q.get("projectId") != self.project_id):
            self.rejected += 1
            conn.close()  # the real relay answers 401 or 403 before the upgrade; closing is enough here
            return
        self.connections.append(conn)
        self.ua[conn] = q.get("ua", "")
        try:
            while True:
                msg = json.loads(conn.recv())
                if "method" not in msg:
                    continue  # an acknowledgement of irn_subscription
                try:
                    result = self._call(conn, msg["method"], msg.get("params") or {})
                    reply = {"id": msg["id"], "jsonrpc": "2.0", "result": result}
                except ValueError as e:
                    reply = {"id": msg["id"], "jsonrpc": "2.0", "error": {"code": -32602, "message": str(e)}}
                conn.send_text(json.dumps(reply))
        except (ws.WsClosed, ValueError, OSError):
            pass
        finally:
            with self.lock:
                for subs in self.subs.values():
                    subs.pop(conn, None)
            if conn in self.connections:
                self.connections.remove(conn)

    # --- methods ---

    def _subscribe(self, conn, topic):
        sid = hashlib.sha256(f"{topic}{id(conn)}".encode()).hexdigest()
        with self.lock:
            self.subs.setdefault(topic, {})[conn] = sid
            now = time.time()
            pending = [m for m in self.mailbox if m[0] == topic and m[4] > now and m[5] is not conn]
        for m in pending:
            self._deliver(conn, sid, *m[:4])
        return sid

    def _publish(self, conn, method, topic, message, ttl, tag):
        if not isinstance(topic, str) or not isinstance(message, str):
            raise ValueError("topic and message are required")
        now = time.time()
        rec = (topic, message, tag, int(now * 1000), now + (ttl or 300), conn)
        with self.lock:
            self.mailbox.append(rec)
            self.published.append((method, topic, tag))
            targets = [(c, sid) for c, sid in self.subs.get(topic, {}).items() if c is not conn]
        for c, sid in targets:
            self._deliver(c, sid, *rec[:4])

    def _deliver(self, conn, sid, topic, message, tag, at):
        key = (id(conn), hashlib.sha256((topic + message).encode()).digest())
        with self.lock:
            if key in self.delivered:
                return
            self.delivered.add(key)
        payload = {"id": next(self._ids), "jsonrpc": "2.0", "method": "irn_subscription",
                   "params": {"id": sid, "data": {"topic": topic, "message": message, "publishedAt": at, "tag": tag}}}
        try:
            conn.send_text(json.dumps(payload))
        except ws.WsClosed:
            pass

    def _call(self, conn, method, p):
        if method == "irn_subscribe":
            return self._subscribe(conn, p["topic"])
        if method == "irn_batchSubscribe":
            return [self._subscribe(conn, t) for t in p["topics"]]
        if method == "irn_unsubscribe":
            with self.lock:
                self.subs.get(p["topic"], {}).pop(conn, None)
            return True
        if method == "irn_publish":
            self._publish(conn, method, p.get("topic"), p.get("message"), p.get("ttl"), p.get("tag"))
            return True
        if method in ("irn_fetchMessages", "irn_batchFetchMessages"):
            topics = p.get("topics") or [p.get("topic")]
            now = time.time()
            with self.lock:
                msgs = [{"topic": m[0], "message": m[1], "publishedAt": m[3], "tag": m[2]} for m in self.mailbox
                        if m[0] in topics and m[4] > now and m[5] is not conn]
            return {"messages": msgs, "hasMore": False}
        if method == "wc_proposeSession":  # the dapp's proposal, published on the pairing topic for it
            self._subscribe(conn, p["pairingTopic"])
            self._publish(conn, method, p["pairingTopic"], p["sessionProposal"], p.get("ttl"), 1100)
            return True
        if method == "wc_approveSession":  # a wallet's settlement and answer, published for it
            self._subscribe(conn, p["sessionTopic"])
            self._publish(conn, method, p["sessionTopic"], p["sessionSettlementRequest"], p.get("ttl"), 1102)
            self._publish(conn, method, p["pairingTopic"], p["sessionProposalResponse"], p.get("ttl"), 1101)
            return True
        raise ValueError(f"unknown method {method}")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--port", type=int, required=True)
    a.add_argument("--project-id")
    args = a.parse_args()
    r = Relay(args.port, args.project_id).start()
    print(f"relay at {r.url}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
