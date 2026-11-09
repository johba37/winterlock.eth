#!/usr/bin/env python3
"""Whole-transaction gas on a local chain (run by gas.sh): deploys both verifiers from out/, sends
verify(pk, message, signature) for every gas sample as a transaction of its own, and splits each receipt's gasUsed
into 21,000 + calldata (4 gas per zero byte, 16 per other byte) + execution.

    python3 tools/txgas.py http://127.0.0.1:8548

Also prints EIP-7623's floor (21,000 + 10 per calldata token, a token per zero byte and four per other byte), which
applies when it exceeds the total, and the total under EIP-7976 as decisions.md models it: max(gas used, 21,000 + 64
per calldata byte).
"""
import json
import os
import statistics
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
RPC = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8548"
SELECTOR = "de8f50a1"  # verify(bytes,bytes,bytes)


def rpc(method, *params):
    req = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)})
                                 .encode(), {"Content-Type": "application/json"})
    out = json.load(urllib.request.urlopen(req))
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def send(sender, to, data, gas):
    tx = {"from": sender, "data": "0x" + data.hex(), "gas": hex(gas)}
    if to:
        tx["to"] = to
    h = rpc("eth_sendTransaction", tx)
    r = None
    for _ in range(200):
        r = rpc("eth_getTransactionReceipt", h)
        if r:
            break
        time.sleep(0.05)
    assert int(r["status"], 16) == 1, r
    return r


def encode_bytes(*args):
    """ABI encoding of (bytes, bytes, ...)."""
    head, tail = b"", b""
    offset = 32 * len(args)
    for a in args:
        head += (offset + len(tail)).to_bytes(32, "big")
        tail += len(a).to_bytes(32, "big") + a + bytes(-len(a) % 32)
    return head + tail


def calldata_gas(data):
    zeros = data.count(0)
    return 4 * zeros + 16 * (len(data) - zeros), 21000 + 10 * (zeros + 4 * (len(data) - zeros))


def vectors(name):
    h = lambda s: bytes.fromhex(s[2:])  # noqa: E731
    for v in json.load(open(os.path.join(ROOT, "fixtures", name)))["vectors"]:
        if v["valid"] and not v["internal"] and v["context"] == "0x" and len(h(v["message"])) == 32:
            yield h(v["pk"]), h(v["message"]), h(v["signature"])


def main():
    sender = rpc("eth_accounts")[0]
    print(f"chain {int(rpc('eth_chainId'), 16)}, client {rpc('web3_clientVersion')}")
    for contract, files in [
        ("SlhDsaSha2_128s", ["noble-sha2-128s-gas.json", "rustcrypto-sha2-128s.json"]),
        ("SlhDsaSha2_128_24_DRAFT", ["draft-sha2-128-24.json", "sphincs-minus-sha2-128-24.json"]),
    ]:
        art = json.load(open(os.path.join(ROOT, "out", contract + ".sol", contract + ".json")))
        r = send(sender, None, bytes.fromhex(art["bytecode"]["object"][2:]), 15_000_000)
        addr = r["contractAddress"]
        code = len(bytes.fromhex(rpc("eth_getCode", addr, "latest")[2:]))
        print(f"\n{contract}: deployed with {int(r['gasUsed'], 16):,} gas, runtime {code:,} bytes")
        rows = []
        for f in files:
            for pk, m, sig in vectors(f):
                data = bytes.fromhex(SELECTOR) + encode_bytes(pk, m, sig)
                assert int(rpc("eth_call", {"to": addr, "data": "0x" + data.hex()}, "latest"), 16) == 1
                used = int(send(sender, addr, data, 3_000_000)["gasUsed"], 16)
                cd, floor = calldata_gas(data)
                rows.append(dict(used=used, calldata=len(data), cd=cd, execution=used - 21000 - cd, floor=floor,
                                 eip7976=max(used, 21000 + 64 * len(data))))
        for key, label in [("used", "gasUsed"), ("cd", "calldata gas"), ("execution", "execution"),
                           ("floor", "EIP-7623 floor"), ("eip7976", "with EIP-7976")]:
            xs = [row[key] for row in rows]
            print(f"  {label:>15}: mean {statistics.mean(xs):>9,.0f}  min {min(xs):>9,}  max {max(xs):>9,}")
        print(f"  {len(rows)} transactions, calldata {rows[0]['calldata']:,} bytes; the EIP-7623 floor applies to "
              f"{sum(r['floor'] > r['used'] for r in rows)} of them")


if __name__ == "__main__":
    main()
