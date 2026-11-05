"""A scripted dapp for tests: the proposer's side of WalletConnect v2 as @walletconnect/sign-client 2.21 runs it,
over a relay. It makes a pairing URI, proposes a session, takes the wallet's settlement, and sends requests.

Its crypto comes from winterlock_signer.walletconnect, whose primitives are checked byte for byte against the JS SDK
(tests/test_walletconnect.py); the protocol steps here are written separately, from sign-client's engine.
"""
import json
import os
import queue
import threading
import time

from winterlock_signer import walletconnect as wc
from winterlock_signer import ws

DAPP_METADATA = {"name": "Mock dapp", "description": "a scripted test dapp", "url": "https://app.example",
                 "icons": []}


class DappError(Exception):
    def __init__(self, error):
        super().__init__(f"{error.get('code')}: {error.get('message')}")
        self.code = error.get("code")
        self.message = error.get("message")


class MockDapp:
    def __init__(self, relay_url, metadata=DAPP_METADATA, use_propose_session=False):
        self.conn = ws.connect(relay_url + "?" + "auth=" + wc.relay_jwt(os.urandom(32), os.urandom(32).hex(),
                                                                       relay_url), idle_timeout=None)
        self.metadata = metadata
        self.use_propose_session = use_propose_session  # sign-client 2.21.6+: the relay publishes the proposal
        self.keys = {}
        self.waiting = {}  # JSON-RPC id -> Queue for the answer (relay calls and sign protocol alike)
        self.inbox = queue.Queue()  # requests from the wallet: (topic, payload)
        self.session_topic = None
        self.namespaces = None
        self.peer = None
        self.lock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def close(self):
        self.conn.close()

    # --- relay ---

    def _reader(self):
        while True:
            try:
                msg = json.loads(self.conn.recv())
            except (ws.WsClosed, ValueError):
                return
            if msg.get("method") == "irn_subscription":
                self.conn.send_text(json.dumps({"id": msg["id"], "jsonrpc": "2.0", "result": True}))
                data = msg["params"]["data"]
                key = self.keys.get(data["topic"])
                if key is None:
                    continue
                payload = json.loads(wc.unseal(key, data["message"]))
                if "method" in payload:
                    self.inbox.put((data["topic"], payload))
                elif payload.get("id") in self.waiting:
                    self.waiting[payload["id"]].put(payload)
            elif msg.get("id") in self.waiting:
                self.waiting[msg["id"]].put(msg)

    def _relay(self, method, params, timeout=10):
        rid = wc.payload_id()
        self.waiting[rid] = queue.Queue()
        self.conn.send_text(json.dumps({"id": rid, "jsonrpc": "2.0", "method": method, "params": params}))
        resp = self.waiting[rid].get(timeout=timeout)
        del self.waiting[rid]
        if "error" in resp:
            raise DappError(resp["error"])
        return resp["result"]

    def _send(self, topic, payload, tag, ttl=300):
        self._relay("irn_publish", {"topic": topic, "message": wc.seal(self.keys[topic], json.dumps(payload)),
                                    "ttl": ttl, "tag": tag})

    # --- the protocol ---

    def uri(self, expiry=300) -> str:
        sym = os.urandom(32)
        self.pairing_topic = wc.topic_of(sym)
        self.keys[self.pairing_topic] = sym
        if not self.use_propose_session:
            self._relay("irn_subscribe", {"topic": self.pairing_topic})
        return (f"wc:{self.pairing_topic}@2?expiryTimestamp={int(time.time()) + expiry}&relay-protocol=irn"
                f"&symKey={sym.hex()}")

    def propose(self, required=None, optional=None, timeout=20):
        """Proposes a session and waits for the wallet's answer and settlement. Returns the settled namespaces, or
        raises DappError with the wallet's rejection."""
        priv, pub = wc.keypair()
        rid = wc.payload_id()
        params = {"requiredNamespaces": required or {}, "optionalNamespaces": optional or {},
                  "relays": [{"protocol": "irn"}], "proposer": {"publicKey": pub.hex(), "metadata": self.metadata},
                  "expiryTimestamp": int(time.time()) + 300, "pairingTopic": self.pairing_topic, "id": rid}
        payload = {"id": rid, "jsonrpc": "2.0", "method": "wc_sessionPropose", "params": params}
        self.waiting[rid] = queue.Queue()
        sealed = wc.seal(self.keys[self.pairing_topic], json.dumps(payload))
        if self.use_propose_session:
            self._relay("wc_proposeSession", {"pairingTopic": self.pairing_topic, "sessionProposal": sealed,
                                              "ttl": 300, "correlationId": rid})
        else:
            self._relay("irn_publish", {"topic": self.pairing_topic, "message": sealed, "ttl": 300, "tag": 1100})
        resp = self.waiting[rid].get(timeout=timeout)
        if "error" in resp:
            raise DappError(resp["error"])
        sym = wc.derive_sym_key(priv, bytes.fromhex(resp["result"]["responderPublicKey"]))
        topic = wc.topic_of(sym)
        self.keys[topic] = sym
        self._relay("irn_subscribe", {"topic": topic})  # the settlement waits in the relay's mailbox
        t, settle = self.inbox.get(timeout=timeout)
        assert t == topic and settle["method"] == "wc_sessionSettle", settle
        self._send(topic, {"id": settle["id"], "jsonrpc": "2.0", "result": True}, 1103)
        self.session_topic = topic
        self.namespaces = settle["params"]["namespaces"]
        self.peer = settle["params"]["controller"]
        self.settle = settle["params"]
        return self.namespaces

    def request(self, method, params, chain_id, expiry=300, timeout=None):
        """A session request; returns the result or raises DappError"""
        rid = wc.payload_id()
        self.waiting[rid] = queue.Queue()
        self._send(self.session_topic, {"id": rid, "jsonrpc": "2.0", "method": "wc_sessionRequest", "params": {
            "request": {"method": method, "params": params, "expiryTimestamp": int(time.time()) + expiry},
            "chainId": chain_id}}, 1108)
        resp = self.waiting[rid].get(timeout=timeout or expiry + 5)
        del self.waiting[rid]
        if "error" in resp:
            raise DappError(resp["error"])
        return resp["result"]

    def ping(self, timeout=10):
        rid = wc.payload_id()
        self.waiting[rid] = queue.Queue()
        self._send(self.session_topic, {"id": rid, "jsonrpc": "2.0", "method": "wc_sessionPing", "params": {}}, 1114)
        return self.waiting[rid].get(timeout=timeout).get("result")

    def disconnect(self):
        rid = wc.payload_id()
        self._send(self.session_topic, {"id": rid, "jsonrpc": "2.0", "method": "wc_sessionDelete",
                                        "params": {"code": 6000, "message": "User disconnected"}}, 1112)
