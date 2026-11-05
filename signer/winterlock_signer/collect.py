"""A minimal collection endpoint for message signatures (D8, for messages): the connected member posts a message file,
other members fetch it, sign it and post their signatures, and the connected member reads them back. The documents
are the message files of messages.py, so files and the endpoint mix freely.

It holds public data only, so it can withhold or delay signatures but not forge them. Before it stores anything it
checks what a member would: the request decodes to the file's hashes under D14's rules (an off-chain message), the
Safe is on this chain, and each signature is from an owner of the Safe and accepted by that owner's contract
(eth_call). No accounts, no persistence: a restart forgets everything, and members post again.

  PUT  /v1/messages/{safeMessageHash}              a message file; its valid signatures are kept
  POST /v1/messages/{safeMessageHash}/signatures   {"owner": ..., "signature": ...}
  GET  /v1/messages/{safeMessageHash}              the file with every valid signature so far

usage: python -m winterlock_signer.collect --rpc URL [--port 8790] [--host 127.0.0.1]
"""

import argparse
import json
import re
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import abi, messages
from .rpc import Rpc

MAX_BODY = 256 * 1024
MAX_DOCS = 10_000


class CollectError(Exception):
    pass


# --- client ---

def _request(method, url, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "User-Agent": "winterlock-signer"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read()).get("error")
        except ValueError:
            detail = None
        raise CollectError(f"{method} {url.split('/v1/')[0]}: HTTP {e.code}" + (f": {detail}" if detail else "")) \
            from None
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as e:
        raise CollectError(f"{method} {url.split('/v1/')[0]}: {type(e).__name__}") from None


def put(base, doc):
    return _request("PUT", f"{base.rstrip('/')}/v1/messages/{doc['safeMessageHash']}", doc)


def get(base, smh):
    return _request("GET", f"{base.rstrip('/')}/v1/messages/{smh}")


def post_signature(base, smh, owner, signature):
    return _request("POST", f"{base.rstrip('/')}/v1/messages/{smh}/signatures",
                    {"owner": owner, "signature": signature})


# --- server ---

class Store:
    def __init__(self, rpc):
        self.rpc = rpc
        self.chain = rpc.chain_id()
        self.docs = {}
        self.lock = threading.Lock()

    def owners(self, safe):
        return abi.dec_addresses(self.rpc.eth_call(safe, abi.calldata("getOwners()")))

    def _valid(self, doc, owners):
        keep = {o.lower() for o, _, _ in messages.valid_signatures(self.rpc, doc, owners)}
        return [s for s in doc.get("signatures", []) if s.get("owner", "").lower() in keep]

    def put(self, smh, doc):
        if doc.get("safeMessageHash") != smh:
            raise CollectError("the path's hash differs from the file's")
        try:
            safe = abi.address(doc.get("safe", ""))
            owners = self.owners(safe)
            d = messages.check_doc(doc, self.chain, owners)
        except Exception as e:
            raise CollectError(f"not a valid message file: {e}") from None
        if d.path != messages.OFFCHAIN:
            raise CollectError(f"only off-chain messages are collected here ({d.path}: {d.reason})")
        with self.lock:
            have = self.docs.get(smh)
            if have is None and len(self.docs) >= MAX_DOCS:
                raise CollectError("the endpoint is full")
            stored = have or {k: doc[k] for k in ("kind", "version", "chain", "safe", "request", "dapp", "appHash",
                                                  "safeMessageHash")}
            stored.setdefault("signatures", [])
            incoming = dict(stored, signatures=doc.get("signatures", []))
        valid = self._valid(incoming, owners)
        with self.lock:
            for s in valid:
                messages.add_signature(stored, s["owner"], s["signature"])
            self.docs[smh] = stored
            return json.loads(json.dumps(stored))

    def add(self, smh, sig):
        with self.lock:
            doc = self.docs.get(smh)
        if doc is None:
            raise KeyError(smh)
        return self.put(smh, dict(doc, signatures=[sig]))

    def get(self, smh):
        with self.lock:
            doc = self.docs.get(smh)
            return json.loads(json.dumps(doc)) if doc else None


class Handler(BaseHTTPRequestHandler):
    store = None

    def log_message(self, *a):
        pass

    def reply(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise CollectError("body too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def route(self, method):
        m = re.fullmatch(r"/v1/messages/(0x[0-9a-fA-F]{64})(/signatures)?/?", self.path)
        if not m:
            return self.reply(404, {"error": "not found"})
        smh = m[1].lower()
        try:
            if method == "GET" and not m[2]:
                doc = self.store.get(smh)
                return self.reply(200, doc) if doc else self.reply(404, {"error": "no such message"})
            if method == "PUT" and not m[2]:
                return self.reply(200, self.store.put(smh, self.body()))
            if method == "POST" and m[2]:
                return self.reply(200, self.store.add(smh, self.body()))
        except KeyError:
            return self.reply(404, {"error": "no such message"})
        except (CollectError, ValueError) as e:
            return self.reply(400, {"error": str(e)})
        self.reply(405, {"error": "method not allowed"})

    def do_GET(self):
        self.route("GET")

    def do_PUT(self):
        self.route("PUT")

    def do_POST(self):
        self.route("POST")


def serve(rpc_url, host="127.0.0.1", port=0):
    """Starts the endpoint in a thread; returns (server, base URL)"""
    handler = type("BoundHandler", (Handler,), {"store": Store(Rpc(rpc_url))})
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{host}:{server.server_address[1]}"


def main():
    p = argparse.ArgumentParser(description="Winterlock message-signature collection endpoint (public data only)")
    p.add_argument("--rpc", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8790)
    a = p.parse_args()
    server, url = serve(a.rpc, a.host, a.port)
    print(f"collecting message signatures at {url}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
