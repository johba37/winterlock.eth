#!/usr/bin/env python3
"""Turn a forge broadcast of script/GasBench.s.sol into gas tables.

usage: report.py <run-latest.json> <labels.json>
"""
import json
import sys


def as_int(v):
    return int(v, 16) if isinstance(v, str) else int(v)


def avg(rows, key):
    return sum(r[key] for r in rows) / len(rows)


def main(run_path, labels_path):
    run = json.load(open(run_path))
    labels = json.load(open(labels_path))
    receipts = {r["transactionHash"]: r for r in run["receipts"]}
    txs = [t for t in run["transactions"] if (t.get("function") or "").startswith("handleOps")]
    assert len(txs) == len(labels), f"{len(txs)} handleOps txs but {len(labels)} labels"

    groups, bases = {}, {}
    for tx, label in zip(txs, labels):
        r = receipts[tx["hash"]]
        assert as_int(r["status"]) == 1, f"reverted: {label}"
        # UserOperationEvent: 4 topics, data = nonce, success, actualGasCost, actualGasUsed
        events = [l for l in r["logs"] if len(l["topics"]) == 4 and len(l["data"]) == 2 + 4 * 64]
        assert len(events) == 1 and int(events[0]["data"][2 + 64 : 2 + 128], 16) == 1, f"op failed: {label}"

        data = bytes.fromhex((tx["transaction"].get("input") or tx["transaction"]["data"])[2:])
        zeros = data.count(0)
        nonzeros = len(data) - zeros
        calldata_gas = 4 * zeros + 16 * nonzeros
        used = as_int(r["gasUsed"])
        groups.setdefault(label["name"], []).append(
            dict(nonce=label["nonce"], used=used, calldata=len(data), calldata_gas=calldata_gas,
                 execution=used - 21000 - calldata_gas, floor=21000 + 10 * (zeros + 4 * nonzeros),
                 sig=label["sigBytes"])
        )
        bases[label["name"]] = label.get("base", "")

    steady = {name: rows[1:] for name, rows in groups.items()}
    n = len(next(iter(steady.values())))
    print(f"Steady state: one ETH transfer per handleOps tx, average of {n} ops (nonce 1..{n}), EntryPoint v0.7\n")
    hdr = (f"{'account':46} {'tx gas':>8} {'min':>7} {'max':>7} {'sig B':>6} {'calldata B':>10} "
           f"{'calldata gas':>12} {'execution':>9} {'7623 floor':>10}")
    print(hdr)
    print("-" * len(hdr))
    for name, rows in steady.items():
        print(f"{name:46} {avg(rows, 'used'):>8.0f} {min(r['used'] for r in rows):>7} "
              f"{max(r['used'] for r in rows):>7} {rows[0]['sig']:>6} {rows[0]['calldata']:>10} "
              f"{avg(rows, 'calldata_gas'):>12.0f} {avg(rows, 'execution'):>9.0f} {rows[0]['floor']:>10}")

    for base in dict.fromkeys(b for b in bases.values() if b):
        b = avg(steady[base], "used")
        print(f"\nAgainst {base} ({b:.0f} gas):")
        for name, rows in steady.items():
            if bases[name] == base:
                used = avg(rows, "used")
                print(f"  {name:46} {used:>8.0f} {used - b:>+9.0f} {used / b:>5.2f}x")

    print("\nFirst op on a fresh account (nonce 0: cold nonce slot and deposit), tx gas:")
    for name, rows in groups.items():
        print(f"  {name:46} {rows[0]['used']:>8}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
