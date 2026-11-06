"""A stand-in for Safe's Transaction Service on a local chain, for the end-to-end test: the endpoints and payload
shapes the signer uses (as the hosted service answered them in the live run, docs/decisions.md), and the checks the
service makes before it stores a signature: the SafeTx hash recomputed by the Safe, the signer an owner, and a
contract signature checked with an eth_call of the owner's isValidSignature (safe-eth-py's SafeSignatureContract).

A second confirmation by the same owner, through either endpoint, is answered 201 and changes nothing: the first one
stays, as in the hosted service (its serializers store confirmations with get_or_create per SafeTx hash and owner;
seen live on Sepolia on 2026-11-06, docs/decisions.md, "Owner v2, live on Sepolia").

Differences from the hosted service, unverified there: no delegates, messages, pagination or indexing delay.

usage: python -m tests.mock_service --rpc URL --port PORT
"""
import argparse
import json
import re
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from winterlock_signer import abi, owner
from winterlock_signer.abi import b2h, h2b
from winterlock_signer.keccak import keccak256
from winterlock_signer.rpc import Rpc
from winterlock_signer.safe import SafeTx, parse_signature

SUCCESS = b2h(keccak256(b"ExecutionSuccess(bytes32,uint256)"))


class Store:
    def __init__(self, rpc):
        self.rpc = rpc
        self.txs = {}

    def owners(self, safe):
        return abi.dec_addresses(self.rpc.eth_call(safe, abi.calldata("getOwners()")))

    def threshold(self, safe):
        return abi.dec_uint(self.rpc.eth_call(safe, abi.calldata("getThreshold()")))

    def nonce(self, safe):
        return abi.dec_uint(self.rpc.eth_call(safe, abi.calldata("nonce()")))

    def check_signature(self, safe, h, sig_hex, sender=None):
        try:
            o, data, is_contract = parse_signature(h2b(sig_hex))
        except ValueError as e:
            return None, f"signature: {e}"
        if not is_contract:
            return None, "only contract signatures in this mock"
        if o.lower() not in [x.lower() for x in self.owners(safe)]:
            return None, f"Signer={o} is not an owner"
        if sender and sender.lower() != o.lower():
            return None, "sender is not the signer"
        if not owner.is_valid_signature(self.rpc, o, h, data):
            return None, f"No valid signature found for signer={o}"
        return o, None

    @staticmethod
    def add_confirmation(x, o, signature, now):
        """The hosted service's get_or_create: an owner's first confirmation stays; a later one is dropped"""
        if any(c["owner"] == o for c in x["confirmations"]):
            return
        x["confirmations"].append({"owner": o, "signature": signature, "signatureType": "CONTRACT_SIGNATURE",
                                   "submissionDate": now})

    def executed(self, safe, h):
        frm = hex(self.txs[h.lower()]["_block"]) if h.lower() in self.txs else "latest"
        logs = self.rpc.call("eth_getLogs", [{"address": safe, "fromBlock": frm, "toBlock": "latest",
                                              "topics": [SUCCESS]}])
        # v1.4.1 indexes the hash (topic 1); v1.3.0 put it in the data
        return any(h[2:].lower() in (lg["topics"][1][2:].lower() if len(lg["topics"]) > 1 else lg["data"][2:66].lower())
                   for lg in logs)

    def view(self, h):
        x = {k: v for k, v in self.txs[h].items() if not k.startswith("_")}
        x["isExecuted"] = self.executed(x["safe"], h)
        x["confirmationsRequired"] = self.threshold(x["safe"])
        return x


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

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        s = self.store
        if m := re.fullmatch(r"/api/v1/safes/(0x[0-9a-fA-F]{40})/", u.path):
            safe = abi.checksum(m[1])
            return self.reply(200, {"address": safe, "nonce": s.nonce(safe), "threshold": s.threshold(safe),
                                    "owners": s.owners(safe)})
        if m := re.fullmatch(r"/api/v1/owners/(0x[0-9a-fA-F]{40})/safes/", u.path):
            o = m[1].lower()  # the Safes this mock has seen transactions for, among them those this address owns
            safes = sorted({x["safe"] for x in s.txs.values()})
            return self.reply(200, {"safes": [x for x in safes if o in [y.lower() for y in s.owners(x)]]})
        if m := re.fullmatch(r"/api/v2/multisig-transactions/(0x[0-9a-fA-F]{64})/", u.path):
            h = m[1].lower()
            return self.reply(200, s.view(h)) if h in s.txs else self.reply(404, {"detail": "Not found."})
        if m := re.fullmatch(r"/api/v2/safes/(0x[0-9a-fA-F]{40})/multisig-transactions/", u.path):
            safe = abi.checksum(m[1])
            res = [s.view(h) for h, x in s.txs.items() if x["safe"] == safe]
            if "nonce" in q:
                res = [x for x in res if x["nonce"] == int(q["nonce"])]
            if "nonce__gte" in q:
                res = [x for x in res if x["nonce"] >= int(q["nonce__gte"])]
            if q.get("executed") == "false":
                res = [x for x in res if not x["isExecuted"]]
            res.sort(key=lambda x: (-x["nonce"], x["submissionDate"]))
            return self.reply(200, {"count": len(res), "results": res})
        self.reply(404, {"detail": "Not found."})

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        s = self.store
        if m := re.fullmatch(r"/api/v2/safes/(0x[0-9a-fA-F]{40})/multisig-transactions/", u.path):
            safe = abi.checksum(m[1])
            try:
                t = SafeTx.from_json(body)
            except (KeyError, ValueError) as e:
                return self.reply(400, {"nonFieldErrors": [f"bad fields: {e}"]})
            h = b2h(abi.dec_word(s.rpc.eth_call(safe, t.get_transaction_hash_calldata())))
            if h.lower() != body.get("contractTransactionHash", "").lower():
                return self.reply(422, {"nonFieldErrors": [f"Contract-transaction-hash={h} does not match provided "
                                                           f"contract-tx-hash={body.get('contractTransactionHash')}"]})
            if t.nonce < s.nonce(safe):
                return self.reply(422, {"nonFieldErrors": ["Nonce already executed"]})
            o, err = s.check_signature(safe, h2b(h), body.get("signature", ""), body.get("sender"))
            if err:
                return self.reply(422, {"nonFieldErrors": [err]})
            now = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
            x = s.txs.setdefault(h.lower(), dict(t.to_json(), safe=safe, safeTxHash=h, proposer=o, submissionDate=now,
                                                 confirmations=[], _block=int(s.rpc.call("eth_blockNumber"), 16)))
            s.add_confirmation(x, o, body["signature"], now)
            return self.reply(201, None)
        if m := re.fullmatch(r"/api/v1/multisig-transactions/(0x[0-9a-fA-F]{64})/confirmations/", u.path):
            h = m[1].lower()
            if h not in s.txs:
                return self.reply(404, {"detail": "Not found."})
            x = s.txs[h]
            if s.executed(x["safe"], h):
                return self.reply(400, {"signature": ["Transaction already executed"]})
            o, err = s.check_signature(x["safe"], h2b(h), body.get("signature", ""))
            if err:
                return self.reply(400, {"signature": [err]})
            now = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
            s.add_confirmation(x, o, body["signature"], now)
            return self.reply(201, {"signature": body["signature"]})
        self.reply(404, {"detail": "Not found."})


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rpc", required=True)
    p.add_argument("--port", type=int, required=True)
    a = p.parse_args()
    Handler.store = Store(Rpc(a.rpc))
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
