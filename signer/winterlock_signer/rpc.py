"""JSON-RPC client. URLs may carry an API key in their path, so errors name only the scheme and host."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .abi import b2h, h2b


class RpcError(Exception):
    pass


class Reverted(RpcError):
    def __init__(self, msg, data=None):
        super().__init__(msg)
        self.data = data


def safe_url(url: str) -> str:
    """scheme://host only: never print a path or query, which may hold an API key"""
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")


class Rpc:
    def __init__(self, url: str, timeout=120):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def __repr__(self):
        return f"Rpc({safe_url(self.url)})"

    def call(self, method, params=()):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json",
                                                                   "User-Agent": "winterlock-signer"})
        for attempt in (0, 1, 2):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    resp = json.load(r)
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(2 + 3 * attempt)
                    continue
                raise RpcError(f"{method} at {safe_url(self.url)}: HTTP {e.code}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt == 2:
                    reason = getattr(e, "reason", e)
                    raise RpcError(f"{method} at {safe_url(self.url)}: {type(e).__name__} "
                                   f"{str(reason).replace(self.url, safe_url(self.url))[:200]}") from None
                time.sleep(1 + 2 * attempt)
        if "error" in resp:
            err = resp["error"]
            msg = str(err.get("message", err))[:500]
            if "revert" in msg.lower() or err.get("code") == 3:
                data = err.get("data")
                raise Reverted(f"{method}: {msg}", data if isinstance(data, str) else None)
            raise RpcError(f"{method}: {msg}")
        return resp["result"]

    # --- helpers ---

    def chain_id(self) -> int:
        return int(self.call("eth_chainId"), 16)

    def eth_call(self, to, data: bytes, sender=None, gas=None, block="latest", value=0) -> bytes:
        tx = {"to": to, "data": b2h(data)}
        if sender:
            tx["from"] = sender
        if gas:
            tx["gas"] = hex(gas)
        if value:
            tx["value"] = hex(value)
        return h2b(self.call("eth_call", [tx, block]))

    def code(self, addr) -> bytes:
        return h2b(self.call("eth_getCode", [addr, "latest"]))

    def balance(self, addr) -> int:
        return int(self.call("eth_getBalance", [addr, "latest"]), 16)

    def nonce(self, addr, block="pending") -> int:
        return int(self.call("eth_getTransactionCount", [addr, block]), 16)

    def estimate_gas(self, sender, to, data: bytes, value=0) -> int:
        tx = {"from": sender, "data": b2h(data), "value": hex(value)}
        if to:
            tx["to"] = to
        return int(self.call("eth_estimateGas", [tx, "latest"]), 16)

    def base_fee(self) -> int:
        blk = self.call("eth_getBlockByNumber", ["latest", False])
        return int(blk.get("baseFeePerGas", "0x0"), 16)

    def priority_fee(self) -> int:
        try:
            return int(self.call("eth_maxPriorityFeePerGas"), 16)
        except RpcError:
            return 10**9

    def send_raw(self, raw: bytes) -> str:
        return self.call("eth_sendRawTransaction", [b2h(raw)])

    def receipt(self, tx_hash, timeout=600, poll=3.0):
        t0, wait = time.time(), 0.1
        while True:
            r = self.call("eth_getTransactionReceipt", [tx_hash])
            if r:
                return r
            if time.time() - t0 > timeout:
                raise RpcError(f"no receipt for {tx_hash} after {timeout} s")
            time.sleep(wait)
            wait = min(poll, wait * 2)
