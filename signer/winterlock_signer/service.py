"""Safe's Transaction Service: proposals, confirmations and the queue, with the payloads that worked live
(contracts/bench/safe/live.py; docs/decisions.md, "Safe owner, live on Sepolia").

Base URL https://api.safe.global/tx-service/{short name}/api, header `Authorization: Bearer $SAFE_API_KEY`.
The service only stores public data; the signer decodes and checks everything it gets from it.
"""

import json
import os
import time
import urllib.error
import urllib.request

SHORT_NAMES = {1: "eth", 10: "oeth", 56: "bnb", 100: "gno", 137: "pol", 8453: "base", 42161: "arb1",
               11155111: "sep", 84532: "basesep"}


def default_url(chain_id: int):
    short = SHORT_NAMES.get(chain_id)
    return f"https://api.safe.global/tx-service/{short}/api" if short else None


class ServiceError(Exception):
    pass


class Service:
    def __init__(self, base_url: str, api_key: str = None, timeout=60):
        self.base = base_url.rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("SAFE_API_KEY")
        self.timeout = timeout

    def request(self, method: str, path: str, body=None):
        """(HTTP status, parsed JSON or text); retries once on a network error, never on an HTTP status"""
        headers = {"User-Agent": "winterlock-signer", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        for attempt in (0, 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    status, raw = r.status, r.read()
                break
            except urllib.error.HTTPError as e:
                status, raw = e.code, e.read()
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt or method != "GET":
                    raise ServiceError(f"{method} {path}: {type(e).__name__}") from None
                time.sleep(3)
        try:
            resp = json.loads(raw) if raw else None
        except ValueError:
            resp = raw.decode(errors="replace")[:1000]
        return status, resp

    def get(self, path):
        status, resp = self.request("GET", path)
        if status != 200:
            raise ServiceError(f"GET {path}: HTTP {status}: {str(resp)[:300]}")
        return resp

    # --- endpoints ---

    def safe_info(self, safe):
        return self.get(f"/v1/safes/{safe}/")

    def propose(self, safe, safe_tx, safe_tx_hash_hex, sender, signature_hex):
        body = dict(safe_tx.to_json(), contractTransactionHash=safe_tx_hash_hex, sender=sender,
                    signature=signature_hex, origin=None)
        return self.request("POST", f"/v2/safes/{safe}/multisig-transactions/", body)

    def confirm(self, safe_tx_hash_hex, signature_hex):
        return self.request("POST", f"/v1/multisig-transactions/{safe_tx_hash_hex}/confirmations/",
                            {"signature": signature_hex})

    def transaction(self, safe_tx_hash_hex):
        return self.get(f"/v2/multisig-transactions/{safe_tx_hash_hex}/")

    def at_nonce(self, safe, nonce):
        return self.get(f"/v2/safes/{safe}/multisig-transactions/?nonce={nonce}").get("results", [])

    def pending(self, safe, from_nonce):
        out, path = [], f"/v2/safes/{safe}/multisig-transactions/?executed=false&nonce__gte={from_nonce}&limit=100"
        resp = self.get(path)
        out += resp.get("results", [])
        return sorted(out, key=lambda x: (int(x["nonce"]), x.get("submissionDate") or ""))
