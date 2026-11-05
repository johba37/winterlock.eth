#!/usr/bin/env python3
"""D10 live: one Winterlock account on several chains.

The same Kernel v3.3 account (same install data, so the same address) is deployed on every chain by its first
WOTS-signed operation, which also enrols that chain's operation tree with a certificate. A second operation
then uses the enrolled tree. Each chain gets its own operation tree, certified by the member's stateless key
(D12): the tree index, which picks the tree's secrets, is the chain's position in --chain.

The signer helper derives keys from --tag. Use a secret tag (multichain.sh keeps one in .env): with a public
one, anyone could sign for the account. The helper has keys for nonces 0 and 1 only, so a tag serves one run.

usage: multichain.py --chain NAME=NODE_URL,BUNDLER_URL [--chain ...] --funder KEY --signer-rpc URL
                     --signer-helper ADDRESS --tag TAG [--fund AMOUNT] [--out FILE]
"""
import argparse
import json

from driver import Driver, cast, cast_values

# The same on every chain: canonical EntryPoint v0.7, ZeroDev Kernel v3.3, the deterministic Winterlock validator
DEPLOYMENT = {
    "entryPoint": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    "kernelFactory": "0x2577507b78c2008Ff367261CB6285d44ba5eF2E9",
    "factoryStaker": "0xd703aaE79538628d27099B8c4f621bE4CCd142d5",
    # script/DeployValidator.s.sol, D6, as predicted for this source (D12); not deployed yet
    "winterlockD6": "0xE8bE004Eae7A744a0e626b4bdeDD8b506547ACE0",
}
D6 = (24, 431, 4, 0)
SALT = "0x" + "00" * 32


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", action="append", required=True, help="NAME=NODE_URL,BUNDLER_URL")
    ap.add_argument("--funder", required=True)
    ap.add_argument("--signer-rpc", required=True)
    ap.add_argument("--signer-helper", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--fund", default="0.01ether", help="balance each chain's account is topped up to")
    ap.add_argument("--out", default="bench/bundlers/results-multichain.json")
    args = ap.parse_args()

    validator = DEPLOYMENT["winterlockD6"]
    chains = []
    for i, spec in enumerate(args.chain):
        name, urls = spec.split("=", 1)
        node, bundler = urls.split(",", 1)
        d = Driver(node, DEPLOYMENT, args.signer_rpc, args.signer_helper)
        d.funder, d.fee_mode, d.transfer_wei, d.tree_index = args.funder, "bundler", 10**12, i
        if cast("code", validator, "--rpc-url", node) == "0x":
            raise SystemExit(f"{name}: no validator at {validator}; run script/DeployValidator.s.sol there first")
        chains.append((name, d, bundler))

    # Install data is the stateless public key alone, so it is the same on every chain, and so is the address
    init = chains[0][1].init_data(validator, D6, args.tag, 1, 1)
    addresses = {name: d.call(DEPLOYMENT["kernelFactory"], "getAddress(bytes,bytes32)(address)", init, SALT)
                 for name, d, _ in chains}
    for name, a in addresses.items():
        print(f"{name:18} account {a}")
    if len(set(addresses.values())) != 1:
        raise SystemExit("addresses differ")
    account = next(iter(addresses.values()))
    factory_data = cast("calldata", "deployWithFactory(address,bytes,bytes32)", DEPLOYMENT["kernelFactory"], init,
                        SALT)

    rows, trees = [], {}
    for name, d, bundler in chains:
        nonce = int(d.call(DEPLOYMENT["entryPoint"], "getNonce(address,uint192)(uint256)", account, 0))
        if nonce >= 2:
            raise SystemExit(f"{name}: nonces 0 and 1 are used; run again with a new tag")
        if int(cast("balance", account, "--rpc-url", d.rpc)) < int(cast("to-wei", args.fund.replace("ether", ""))):
            cast("send", "--private-key", d.funder, "--value", args.fund, account, "--rpc-url", d.rpc)
        deployed = cast("code", account, "--rpc-url", d.rpc) != "0x"
        while nonce < 2:
            row = d.submit("pimlico", bundler, account, nonce, D6, args.tag, [0], validator, 57_000,
                           None if deployed else factory_data)
            row["chain"] = name
            rows.append(row)
            print(f"{name:18} nonce {nonce}: {row['op']:17} certificate {row['certificates']}  "
                  f"{row.get('send', row.get('estimate'))[:70]}  included {row.get('included', '-')}  "
                  f"gas {row.get('gas_used', '')}  tx {row.get('tx', '')}", flush=True)
            if row.get("included") != "yes":
                break
            deployed, nonce = True, nonce + 1
        root, seed, height, start = cast_values(
            "call", validator, "tree(address,uint256)(bytes32,uint128,uint8,uint64)", account, 0, "--rpc-url", d.rpc)
        trees[name] = dict(root=root, seed=seed, height=height, start=start, tree_index=d.tree_index)
        print(f"{name:18} operation tree {root[:18]}… height {height}, from sequence {start}, "
              f"certified by the stateless key")

    json.dump(dict(account=account, validator=validator, trees=trees, operations=rows), open(args.out, "w"),
              indent=1)
    roots = [t["root"] for t in trees.values()]
    print(f"\nsame address on {len(chains)} chains: {account}; "
          f"separate operation trees: {'yes' if len(set(roots)) == len(roots) else 'NO'}")


if __name__ == "__main__":
    main()
