#!/usr/bin/env python3
"""Turn a forge broadcast of script/GasBench.s.sol into a gas table.

usage: report.py <run-latest.json> <labels.json>
"""
import json
import sys
from collections import defaultdict


def as_int(v):
    return int(v, 16) if isinstance(v, str) else int(v)


def main(run_path, labels_path):
    run = json.load(open(run_path))
    labels = json.load(open(labels_path))
    receipts = {r["transactionHash"]: r for r in run["receipts"]}
    txs = [t for t in run["transactions"] if (t.get("function") or "").startswith("handleOps")]
    assert len(txs) == len(labels), f"{len(txs)} handleOps txs but {len(labels)} labels"

    groups = defaultdict(list)
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
        floor = 21000 + 10 * (zeros + 4 * nonzeros)  # EIP-7623
        used = as_int(r["gasUsed"])
        groups[label["name"]].append(
            dict(nonce=label["nonce"], used=used, calldata=len(data), calldata_gas=calldata_gas,
                 execution=used - 21000 - calldata_gas, floor=floor, sig=label["sigBytes"])
        )

    baseline = "MiniAccount + ECDSA validator"

    def avg(rows, key):
        return sum(r[key] for r in rows) / len(rows)

    steady = {name: rows[1:] for name, rows in groups.items()}
    base = avg(steady[baseline], "used")
    n = len(next(iter(steady.values())))

    print(f"Steady state: one ETH transfer per handleOps tx, average of {n} ops (nonce 1..{n}), EntryPoint v0.7\n")
    hdr = (f"{'account':32} {'tx gas':>8} {'min':>7} {'max':>7} {'vs ECDSA':>9} {'x':>5} "
           f"{'calldata B':>10} {'calldata gas':>12} {'execution':>9} {'7623 floor':>10}")
    print(hdr)
    print("-" * len(hdr))
    for name, rows in steady.items():
        used = avg(rows, "used")
        print(f"{name:32} {used:>8.0f} {min(r['used'] for r in rows):>7} {max(r['used'] for r in rows):>7} "
              f"{used - base:>+9.0f} {used / base:>5.2f} {rows[0]['calldata']:>10} {avg(rows, 'calldata_gas'):>12.0f} "
              f"{avg(rows, 'execution'):>9.0f} {rows[0]['floor']:>10}")

    print("\nFirst op on a fresh account (nonce 0: cold nonce slot and deposit), tx gas:")
    for name, rows in groups.items():
        print(f"  {name:34} {rows[0]['used']:>8}")

    print("\nEvery op:")
    for name, rows in groups.items():
        print(f"  {name:34} " + "  ".join(f"n{r['nonce']}={r['used']}" for r in rows))


if __name__ == "__main__":
    main(*sys.argv[1:3])
