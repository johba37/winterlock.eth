"""WalletConnect v2, the wallet's side (winterlock_signer/walletconnect.py): its crypto against known answers from
WalletConnect's own tests and its JS SDK, the pairing URI, and the protocol against a scripted dapp over a stand-in
relay (pairing, approval and rejection, requests, pings, deletion, a relay that drops the connection, a dapp that
proposes through wc_proposeSession). Optionally, with Node and the official SDK installed outside the repository, a
dapp on @walletconnect/sign-client itself: set WINTERLOCK_WC_JS to a node_modules directory that holds it.
"""
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

from tests.mock_dapp import DappError, MockDapp
from tests.mock_relay import Relay as MockRelay
from tests.mock_relay import verify_jwt
from winterlock_signer import walletconnect as wc
from winterlock_signer.bridge import session_namespaces, RpcFail

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "vectors", "walletconnect.json")) as f:
    V = json.load(f)
SAFE = "0x5B81D3ce1Ca48be48F154D8AD060Cf9f883E86B2"
NS = {"eip155": {"chains": ["eip155:31337"], "methods": ["personal_sign", "eth_sendTransaction"],
                 "events": ["chainChanged"]}}


def b(x):
    return bytes.fromhex(x)


class KnownAnswers(unittest.TestCase):
    def test_x25519_rfc7748(self):
        r = V["rfc7748"]
        self.assertEqual(wc.x25519_base(b(r["alice_priv"])).hex(), r["alice_pub"])
        self.assertEqual(wc.x25519_base(b(r["bob_priv"])).hex(), r["bob_pub"])
        self.assertEqual(wc.x25519(b(r["alice_priv"]), b(r["bob_pub"])).hex(), r["shared"])
        self.assertEqual(wc.x25519(b(r["bob_priv"]), b(r["alice_pub"])).hex(), r["shared"])

    def test_monorepo_values(self):
        m = V["monorepo"]
        self.assertEqual(wc.x25519_base(b(m["a_priv"])).hex(), m["a_pub"])
        self.assertEqual(wc.x25519(b(m["a_priv"]), b(m["b_pub"])).hex(), m["shared"])
        sym = wc.derive_sym_key(b(m["a_priv"]), b(m["b_pub"]))
        self.assertEqual(sym.hex(), m["sym_key"])
        self.assertEqual(wc.seal(sym, m["message"], b(m["iv"])), m["type0"])
        for env in ("type0", "type0_b64url", "type1"):
            self.assertEqual(wc.unseal(sym, m[env]), m["message"])
        jwt = wc.relay_jwt(b(m["jwt_seed"]), m["jwt_sub"], m["jwt_aud"], m["jwt_iat"])
        self.assertEqual(jwt, m["jwt"])
        self.assertTrue(verify_jwt(wc.relay_jwt(b(m["jwt_seed"]), "s", "ws://x")))  # and the stand-in relay agrees

    def test_sdk_values(self):
        s = V["sdk"]
        self.assertEqual(wc.x25519_base(b(s["priv"])).hex(), s["pub"])
        sym = wc.derive_sym_key(b(s["priv"]), b(s["peer_pub"]))
        self.assertEqual(sym.hex(), s["sym_key"])
        self.assertEqual(wc.topic_of(sym), s["topic"])
        self.assertEqual(wc.seal(sym, s["message"], b(s["iv"])), s["type0"])
        self.assertEqual(wc.unseal(sym, s["type1"]), s["message"])
        self.assertEqual(wc.relay_jwt(b(s["jwt_seed"]), s["jwt_sub"], s["jwt_aud"], s["jwt_iat"]), s["jwt"])

    def test_did_key(self):
        from Crypto.PublicKey import ECC
        m = V["monorepo"]
        pub = ECC.construct(curve="Ed25519", seed=b(m["jwt_seed"])).public_key().export_key(format="raw")
        self.assertEqual(wc.did_key(pub), m["jwt_iss"])

    def test_envelopes_authenticate(self):
        sym = os.urandom(32)
        env = wc.seal(sym, "hello")
        self.assertEqual(wc.unseal(sym, env), "hello")
        with self.assertRaises(ValueError):
            wc.unseal(os.urandom(32), env)  # another key
        raw = bytearray(__import__("base64").b64decode(env))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            wc.unseal(sym, __import__("base64").b64encode(bytes(raw)).decode())  # a changed tag
        with self.assertRaises(ValueError):
            wc.unseal(sym, "Ag==")  # type 2 (unencrypted) is refused
        with self.assertRaises(ValueError):
            wc.derive_sym_key(os.urandom(32), bytes(32))  # a low-order peer key

    def test_uri(self):
        sym = os.urandom(32)
        topic = wc.topic_of(sym)
        p = wc.parse_uri(f"wc:{topic}@2?expiryTimestamp=4102444800&relay-protocol=irn&symKey={sym.hex()}")
        self.assertEqual((p["topic"], p["sym_key"], p["relay_protocol"], p["expiry"]), (topic, sym, "irn", 4102444800))
        bad = [f"wc:{topic}@1?bridge=https%3A%2F%2Fx&key={sym.hex()}", "https://example.com",
               f"wc:{topic}@2?relay-protocol=irn&symKey=zz", f"wc:{topic[:10]}@2?relay-protocol=irn&symKey={sym.hex()}"]
        for uri in bad:
            with self.assertRaises(ValueError) as e:
                wc.parse_uri(uri)
            self.assertNotIn(sym.hex(), str(e.exception))  # errors never echo the key


class Namespaces(unittest.TestCase):
    def prop(self, required=None, optional=None):
        return wc.Proposal(1, "t", {"requiredNamespaces": required or {}, "optionalNamespaces": optional or {},
                                    "proposer": {"publicKey": "00" * 32, "metadata": {}}})

    def test_rules(self):
        ns, notes = session_namespaces(self.prop(optional=NS), 31337, SAFE)
        self.assertEqual(ns["eip155"]["accounts"], [f"eip155:31337:{SAFE}"])
        self.assertIn("personal_sign", ns["eip155"]["methods"])
        self.assertNotIn("eth_sign", ns["eip155"]["methods"])
        self.assertEqual(notes, [])
        # the Safe's chain must be offered somewhere
        with self.assertRaises(RpcFail) as e:
            session_namespaces(self.prop(optional={"eip155": {"chains": ["eip155:1"]}}), 31337, SAFE)
        self.assertEqual(e.exception.code, wc.UNSUPPORTED_CHAINS)
        # other ecosystems can't be required
        with self.assertRaises(RpcFail) as e:
            session_namespaces(self.prop(required={"solana": {"chains": ["solana:x"]}}, optional=NS), 31337, SAFE)
        self.assertEqual(e.exception.code, wc.UNSUPPORTED_NAMESPACE_KEY)
        # required chains are listed (as Safe's app does), with a note; requests there are refused later
        ns, notes = session_namespaces(self.prop(required={"eip155": {"chains": ["eip155:1"], "methods": ["eth_sign"],
                                                                      "events": []}}, optional=NS), 31337, SAFE)
        self.assertEqual(ns["eip155"]["chains"], ["eip155:1", "eip155:31337"])
        self.assertIn("eth_sign", ns["eip155"]["methods"])
        self.assertEqual(len(notes), 2)
        # chain-keyed namespaces
        ns, _ = session_namespaces(self.prop(required={"eip155:31337": {"methods": ["personal_sign"], "events": []}}),
                                   31337, SAFE)
        self.assertEqual(ns["eip155"]["chains"], ["eip155:31337"])


class Protocol(unittest.TestCase):
    """The wallet engine against the scripted dapp, through the stand-in relay"""

    def setUp(self):
        self.relay = MockRelay().start()
        self.cleanup = [self.relay.close]

    def tearDown(self):
        for c in reversed(self.cleanup):
            c()

    def pair(self, use_propose_session=False, project_id=None):
        dapp = MockDapp(self.relay.url, use_propose_session=use_propose_session)
        self.cleanup.append(dapp.close)
        relay = wc.Relay(self.relay.url, project_id, log=lambda *a: None, timeout=5)
        relay.start()
        self.cleanup.append(relay.close)
        wallet = wc.Wallet(relay, {"name": "Winterlock test", "description": "", "url": "https://w.example",
                                   "icons": []}, log=lambda *a: None)
        wallet.pair(dapp.uri())
        return dapp, wallet

    def event(self, wallet, kind, timeout=10):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                k, obj = wallet.events.get(timeout=0.2)
            except queue.Empty:
                continue
            if k == kind:
                return obj
        self.fail(f"no {kind} event")

    def session(self, use_propose_session=False):
        dapp, wallet = self.pair(use_propose_session)
        box = {}
        t = threading.Thread(target=lambda: box.update(ns=dapp.propose(optional=NS)))
        t.start()
        prop = self.event(wallet, "proposal")
        self.assertEqual(prop.metadata["url"], "https://app.example")
        session = wallet.approve(prop, session_namespaces(prop, 31337, SAFE)[0])
        t.join(10)
        self.assertEqual(box["ns"]["eip155"]["accounts"], [f"eip155:31337:{SAFE}"])
        self.event(wallet, "settled")
        self.assertTrue(session.acknowledged)
        return dapp, wallet, session

    def serve_one(self, wallet, answer):
        def run():
            req = self.event(wallet, "request")
            r = answer(req)
            if isinstance(r, tuple):
                wallet.respond(req, error=r)
            else:
                wallet.respond(req, result=r)
        t = threading.Thread(target=run)
        t.start()
        return t

    def test_session_requests_ping_delete(self):
        dapp, wallet, session = self.session()
        seen = {}

        def answer(req):
            seen.update(method=req.method, params=req.params, chain=req.chain_id, expiry=req.expiry)
            return "0xabcd"
        t = self.serve_one(wallet, answer)
        self.assertEqual(dapp.request("personal_sign", ["0x68656c6c6f", SAFE], "eip155:31337", expiry=600), "0xabcd")
        t.join(5)
        self.assertEqual((seen["method"], seen["chain"]), ("personal_sign", "eip155:31337"))
        self.assertAlmostEqual(seen["expiry"], time.time() + 600, delta=10)
        t = self.serve_one(wallet, lambda req: (4001, "no"))
        with self.assertRaises(DappError) as e:
            dapp.request("eth_sendTransaction", [{}], "eip155:31337")
        t.join(5)
        self.assertEqual(e.exception.code, 4001)
        self.assertTrue(dapp.ping())
        dapp.disconnect()
        self.assertIs(self.event(wallet, "deleted"), session)
        self.assertNotIn(session.topic, wallet.keys)  # the session key is forgotten

    def test_rejected_proposal(self):
        dapp, wallet = self.pair()
        box = {}

        def propose():
            try:
                dapp.propose(optional={"eip155": {"chains": ["eip155:1"], "methods": [], "events": []}})
            except DappError as e:
                box["error"] = e
        t = threading.Thread(target=propose)
        t.start()
        prop = self.event(wallet, "proposal")
        with self.assertRaises(RpcFail) as e:
            session_namespaces(prop, 31337, SAFE)
        wallet.reject(prop, e.exception.code, e.exception.message)
        t.join(10)
        self.assertEqual(box["error"].code, wc.UNSUPPORTED_CHAINS)
        self.assertEqual(wallet.sessions, {})

    def test_propose_session_relay_method(self):
        """sign-client 2.21.6 and later propose through the relay's wc_proposeSession: the wallet sees the same"""
        dapp, wallet, session = self.session(use_propose_session=True)
        self.assertIn(("wc_proposeSession", dapp.pairing_topic, 1100), self.relay.published)
        t = self.serve_one(wallet, lambda req: [SAFE])
        self.assertEqual(dapp.request("eth_accounts", [], "eip155:31337"), [SAFE])
        t.join(5)

    def test_relay_drops_the_connection(self):
        dapp, wallet, session = self.session()
        self.relay.drop_connections(wc.UA)  # only the wallet's connection
        time.sleep(1.5)  # it reconnects and subscribes again
        t = self.serve_one(wallet, lambda req: "ok")
        self.assertEqual(dapp.request("eth_chainId", [], "eip155:31337", timeout=15), "ok")
        t.join(5)

    def test_forged_messages_are_ignored(self):
        dapp, wallet, session = self.session()
        # a message sealed with another key on the session topic: dropped, the session goes on
        dapp._relay("irn_publish", {"topic": session.topic, "message": wc.seal(os.urandom(32), json.dumps(
            {"id": 1, "jsonrpc": "2.0", "method": "wc_sessionRequest", "params": {}})), "ttl": 300, "tag": 1108})
        t = self.serve_one(wallet, lambda req: "fine")
        self.assertEqual(dapp.request("eth_chainId", [], "eip155:31337"), "fine")
        t.join(5)

    def test_project_id(self):
        self.relay.project_id = "abc"
        relay = wc.Relay(self.relay.url, None, log=lambda *a: None, timeout=3)
        with self.assertRaises(Exception):
            relay.start()
            relay.subscribe("00" * 32)
        relay.close()
        relay = wc.Relay(self.relay.url, "abc", log=lambda *a: None, timeout=3)
        relay.start()
        relay.subscribe("00" * 32)
        relay.close()
        self.assertGreaterEqual(self.relay.rejected, 1)


JS = os.environ.get("WINTERLOCK_WC_JS")


@unittest.skipUnless(JS and os.path.isdir(os.path.join(JS or "", "@walletconnect", "sign-client")) and shutil.which(
    "node"), "set WINTERLOCK_WC_JS to a node_modules with @walletconnect/sign-client to run the JS dapp")
class JsDappInterop(unittest.TestCase):
    """A dapp on the official SDK, connected to this wallet through the stand-in relay"""

    def test_js_dapp(self):
        relay = MockRelay().start()
        tmp = tempfile.TemporaryDirectory()
        reqs = [{"method": "personal_sign", "params": ["0x68656c6c6f", SAFE]},
                {"method": "eth_sendTransaction", "params": [{"from": SAFE, "to": SAFE}]}]
        p = subprocess.Popen(["node", os.path.join(HERE, "js_dapp.js"), relay.url, os.path.join(tmp.name, "wc.db"),
                              "31337", json.dumps(reqs)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env=dict(os.environ, NODE_PATH=JS))
        try:
            uri = json.loads(p.stdout.readline())["uri"]
            wrelay = wc.Relay(relay.url, log=lambda *a: None)
            wrelay.start()
            wallet = wc.Wallet(wrelay, {"name": "Winterlock test", "description": "", "url": "https://w.example",
                                        "icons": []}, log=lambda *a: None)
            wallet.pair(uri)
            prop = wallet.events.get(timeout=20)[1]
            self.assertEqual(prop.metadata["name"], "JS dapp")
            wallet.approve(prop, session_namespaces(prop, 31337, SAFE)[0])
            answers = {"personal_sign": ("result", "0x" + "ab" * 40), "eth_sendTransaction": ("error", (4001, "no"))}
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    kind, obj = wallet.events.get(timeout=0.5)
                except queue.Empty:
                    if p.poll() is not None:
                        break
                    continue
                if kind == "request":
                    how, val = answers[obj.method]
                    wallet.respond(obj, **{how: val})
                if kind == "deleted":
                    break
            out, err = p.communicate(timeout=30)
            # the script's lines after the URI (the SDK's own log lines, which have a "level", are skipped)
            lines = [x for x in map(json.loads, filter(str.strip, out.splitlines())) if "level" not in x]
            self.assertEqual(lines[0]["session"]["eip155"]["accounts"], [f"eip155:31337:{SAFE}"], err)
            self.assertEqual(lines[1], {"method": "personal_sign", "result": "0x" + "ab" * 40})
            self.assertEqual(lines[2]["error"]["code"], 4001, out)
            self.assertEqual(lines[-1], {"done": True})
            wrelay.close()
        finally:
            if p.poll() is None:
                p.kill()
            relay.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
