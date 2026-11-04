#!/usr/bin/env python3
"""Price the benchmark transactions on an OP Stack L2 (default: Base mainnet), read-only.

For each account, one steady-state transaction is taken from the local anvil run. Its raw bytes go to
the L2's GasPriceOracle (getL1Fee, Fjord formula: FastLZ-compressed size x L1 base and blob fees), and
its gas is priced at the L2's current gas price. Signed raw bytes are used, so the L1 fee is slightly
overstated (the oracle adds its own 68-byte signature allowance); this affects every row alike.

usage: l2.py <run-latest.json> <labels.json> <local rpc> <l2 rpc>
"""
import json
import subprocess
import sys

ORACLE = "0x420000000000000000000000000000000000000F"


def cast(*args):
    return subprocess.run(["cast", *args], check=True, capture_output=True, text=True).stdout.strip()


def main(run_path, labels_path, local_rpc, l2_rpc):
    run = json.load(open(run_path))
    labels = json.load(open(labels_path))
    receipts = {r["transactionHash"]: r for r in run["receipts"]}
    txs = [t for t in run["transactions"] if (t.get("function") or "").startswith("handleOps")]

    gas_price = int(cast("gas-price", "--rpc-url", l2_rpc))
    chain = cast("chain-id", "--rpc-url", l2_rpc)
    rows, bases = {}, {}
    for tx, label in zip(txs, labels):
        if label["nonce"] == 0:
            continue
        rows.setdefault(label["name"], []).append((tx["hash"], int(receipts[tx["hash"]]["gasUsed"], 16)))
        bases[label["name"]] = label.get("base", "")

    priced = {}
    for name, items in rows.items():
        gas = sum(g for _, g in items) / len(items)
        raw = cast("tx", items[-1][0], "--raw", "--rpc-url", local_rpc)
        l1 = int(cast("call", ORACLE, "getL1Fee(bytes)(uint256)", raw, "--rpc-url", l2_rpc).split()[0])
        priced[name] = dict(gas=gas, l2=gas * gas_price, l1=l1, size=(len(raw) - 2) // 2)

    print(f"\nOn chain {chain} at gas price {gas_price / 1e9:g} gwei (fees in 1e-9 ETH, i.e. gwei):")
    print("  'x100 L1' assumes L1 data fees 100 times today's.")
    print(f"  {'account':46} {'L2 exec':>8} {'L1 data':>8} {'total':>8} {'ratio':>6} {'x100 L1':>8} {'ratio':>6}")
    for base in dict.fromkeys(b for b in bases.values() if b):
        b = priced[base]
        bt, bt100 = b["l2"] + b["l1"], b["l2"] + 100 * b["l1"]
        print(f"  against {base}: {bt / 1e9:.0f} (x100 L1: {bt100 / 1e9:.0f})")
        for name, p in priced.items():
            if bases[name] == base:
                t, t100 = p["l2"] + p["l1"], p["l2"] + 100 * p["l1"]
                print(f"  {name:46} {p['l2'] / 1e9:>8.0f} {p['l1'] / 1e9:>8.1f} {t / 1e9:>8.0f} {t / bt:>5.2f}x "
                      f"{t100 / 1e9:>8.0f} {t100 / bt100:>5.2f}x")


if __name__ == "__main__":
    main(*sys.argv[1:5])
