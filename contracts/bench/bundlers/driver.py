#!/usr/bin/env python3
"""Bundler acceptance test for Winterlock UserOperations (stage 1: local bundlers).

For every scenario and bundler, a fresh Kernel v3.3 account sends two operations:
  the account is deployed by an ordinary transaction, then two WOTS-signed transfers (nonces 0 and 1)
  test signature acceptance alone. Two extra probes (ECDSA and D6) deploy counterfactually through
  initCode and the staked FactoryStaker, to check factory handling separately.
Each operation goes through eth_estimateUserOperationGas (with a dummy signature of the right shape),
eth_sendUserOperation, and eth_getUserOperationReceipt, using the bundler's estimates unchanged, as a wallet
SDK would. The table records what each bundler accepted.

WOTS signatures, certificates (signed by each member's stateless leanSphincs key, D12) and install data come from
the WotsSignerHelper contract via eth_call. Its keys derive from public tags: local tests only. The stateless key
costs about 50M gas to generate and 55M to sign with, so the helper is called with a high gas limit, on a node
without an eth_call gas cap or time limit.

usage: driver.py --rpc URL --deployment FILE --funder KEY --bundler name=URL [--bundler name=URL ...]
       [--signer-rpc URL --signer-helper ADDRESS] [--fund AMOUNT] [--transfer-wei N] [--fees fixed|bundler]

Stage 2 (public testnet, bench/bundlers/testnet.sh) signs on a local node (--signer-rpc), funds each account
with a small amount, and takes fees from each bundler's own gas price method.
"""
import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request

GWEI = 10**9
RECIPIENT = "0x000000000000000000000000000000000000bEEF"
ECDSA_PK = "0x00000000000000000000000000000000000000000000000000000000000a11ce"
PARAMS_TYPE = "(uint256,uint256,uint256,uint256)"
HELPER_GAS = 2_000_000_000  # eth_call gas for the signer helper: stateless keygen and signing are costly
PACKED_OP = "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)"

# name, deployment key, parameter set (n, targetSum, logW, hashFn) or None for ECDSA, members, threshold,
# signers, verifier gas per signer (h = 20, from forge test), used only for fixed limits when estimation fails
SCENARIOS = [
    ("ECDSA (control)", "ecdsaValidator", None, 1, 1, [0], 0),
    ("Winterlock D6", "winterlockD6", (24, 431, 4, 0), 1, 1, [0], 57_000),
    ("Winterlock D6 2-of-3", "winterlockD6", (24, 431, 4, 0), 3, 2, [0, 1], 57_000),
    ("Winterlock 16-byte", "winterlock16", (16, 300, 4, 0), 1, 1, [0], 40_000),
    ("Winterlock 32-byte checksum", "winterlock32checksum", (32, 0, 4, 0), 1, 1, [0], 95_000),
    ("Winterlock D6 SHA-256", "winterlockSha256", (24, 431, 4, 1), 1, 1, [0], 108_000),
    ("Winterlock w=256", "winterlockW256", (24, 3216, 8, 0), 1, 1, [0], 350_000),
]


class RpcError(Exception):
    pass


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    # Some endpoints (Pimlico, Arbitrum's public RPC) refuse Python's default User-Agent with 403
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": "winterlock-bench"})
    with urllib.request.urlopen(req, timeout=180) as r:
        resp = json.load(r)
    if "error" in resp:
        raise RpcError(resp["error"].get("message", str(resp["error"])))
    return resp["result"]


def cast(*args):
    out = subprocess.run(["cast", *map(str, args)], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"cast {args[0]} failed: {out.stderr.strip()[:300]}")
    return out.stdout.strip().split(" ")[0]


def cast_values(*args):
    """cast output with one value per line (first token of each)"""
    out = subprocess.run(["cast", *map(str, args)], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"cast {args[0]} failed: {out.stderr.strip()[:300]}")
    return [line.split(" ")[0] for line in out.stdout.strip().splitlines()]


def h(x):
    return hex(int(x))


def op_sig_len(params):
    """Bytes of one member's operation signature and path: [R + chains][path of height 20]"""
    n, target, logw, _ = params
    w = 1 << logw
    len1 = 8 * n // logw
    chains = len1
    if target == 0:
        digits, cap = 1, w
        while cap <= len1 * (w - 1):
            digits, cap = digits + 1, cap * w
        chains += digits
    return n * (1 + chains) + n * 20


DUMMY_ECDSA = None


def dummy_signature(params, signers, certs):
    """What a wallet sends for estimation: the right shape, the real certificates (they don't depend on the
    operation, and only a valid one stores its tree), and filler in place of the operation signatures"""
    global DUMMY_ECDSA
    if params is None:  # a recoverable signature from a throwaway key: wrong signer, but no revert
        if DUMMY_ECDSA is None:
            DUMMY_ECDSA = cast("wallet", "sign", "--private-key", "0x" + "42" * 32, "0x" + "00" * 32)
        return DUMMY_ECDSA
    entries = [f"{i:02x}" + ("80" if c != "0x" else "00") + c[2:] + "ab" * op_sig_len(params)
               for i, c in zip(signers, certs)]  # member index, flags (slot 0), certificate, nonzero filler
    return "0x" + "".join(entries)


class Driver:
    def __init__(self, rpc_url, deployment, signer_rpc=None, signer_helper=None):
        self.rpc = rpc_url
        self.d = deployment
        self.ep = deployment["entryPoint"]
        # WOTS signing runs on the helper contract via eth_call, on a local node in stage 2
        self.signer_rpc = signer_rpc or rpc_url
        self.helper = signer_helper or deployment["signerHelper"]
        self.fund = "1ether"
        self.tree_index = 0  # which of a member's operation trees the helper signs with: one per chain
        self.transfer_wei = 10**15
        self.fee_mode = "fixed"
        self.run = ""  # appended to the account tags: a new label gives fresh accounts

    def helper_call(self, sig, *args):
        return cast("call", self.helper, sig, *args, "--gas-limit", HELPER_GAS, "--rpc-url", self.signer_rpc)

    def fees(self, bundler_url):
        """(maxFeePerGas, maxPriorityFeePerGas) as a wallet would pick them for this bundler"""
        if self.fee_mode == "fixed":
            return 50 * GWEI, 1 * GWEI
        try:  # Pimlico
            fast = rpc(bundler_url, "pimlico_getUserOperationGasPrice", [])["fast"]
            return int(fast["maxFeePerGas"], 16), int(fast["maxPriorityFeePerGas"], 16)
        except (RpcError, KeyError, urllib.error.HTTPError):
            pass
        try:  # Rundler (Alchemy)
            prio = int(rpc(bundler_url, "rundler_maxPriorityFeePerGas", []), 16)
        except (RpcError, urllib.error.HTTPError):
            prio = int(rpc(self.rpc, "eth_maxPriorityFeePerGas", []), 16)
        base = int(rpc(self.rpc, "eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
        return 2 * base + prio, prio

    def call(self, to, sig, *args):
        return cast("call", to, sig, *args, "--rpc-url", self.rpc)

    def init_data(self, validator, params, tag, members, threshold):
        vid = "0x01" + validator[2:].lower()
        if params is None:
            vdata = cast("wallet", "address", "--private-key", ECDSA_PK)
        else:
            vdata = self.helper_call(f"installData({PARAMS_TYPE},string,uint256,uint8)(bytes)",
                                     "(%d,%d,%d,%d)" % params, tag, members, threshold)
        return cast("calldata", "initialize(bytes21,address,bytes,bytes,bytes[])", vid,
                    "0x0000000000000000000000000000000000000000", vdata, "0x", "[]")

    def transfer(self, wei):
        packed = RECIPIENT[2:].lower() + f"{wei:064x}"
        return cast("calldata", "execute(bytes32,bytes)", "0x" + "00" * 32, "0x" + packed)

    def user_op_hash(self, op):
        init_code = (op.get("factory") or "0x") + (op.get("factoryData") or "0x")[2:]
        agl = "0x%032x%032x" % (int(op["verificationGasLimit"], 16), int(op["callGasLimit"], 16))
        fees = "0x%032x%032x" % (int(op["maxPriorityFeePerGas"], 16), int(op["maxFeePerGas"], 16))
        tup = "(%s,%d,%s,%s,%s,%d,%s,0x,0x)" % (op["sender"], int(op["nonce"], 16), init_code, op["callData"],
                                                 agl, int(op["preVerificationGas"], 16), fees)
        return self.call(self.ep, f"getUserOpHash({PACKED_OP})(bytes32)", tup)

    def certs(self, validator, account, params, tag, signers):
        """Each signer's operation-tree seed (derived by the validator on the target chain, for start 0) and
        certificate signed by its stateless key, or "0x" if its tree is already enrolled there (D10, D12)"""
        if params is None:
            return [], []
        certs, seeds = [], []
        p = "(%d,%d,%d,%d)" % params
        for m in signers:
            seed = self.call(validator, "statelessTreeSeed(address,uint256,uint64)(uint128)", account, m, 0)
            seeds.append(seed)
            root, height, start = cast_values(
                "call", self.helper, f"tree({PARAMS_TYPE},string,uint256,uint256,uint128)(bytes32,uint8,uint64)", p,
                tag, m, self.tree_index, seed, "--rpc-url", self.signer_rpc)
            enrolled = self.call(validator, "tree(address,uint256)(bytes32)", account, m)
            if enrolled.lower() == root.lower():
                certs.append("0x")
                continue
            digest = self.call(validator,
                               "statelessCertificateDigest(address,uint256,bytes32,uint8,uint64)(bytes32)",
                               account, m, root, height, start)
            certs.append(self.helper_call(f"certificate({PARAMS_TYPE},string,uint256,uint256,uint128,bytes32)(bytes)",
                                          p, tag, m, self.tree_index, seed, digest))
        return certs, seeds

    def sign(self, op, params, tag, signers, nonce, certs, seeds):
        digest = self.user_op_hash(op)
        if params is None:
            return cast("wallet", "sign", "--private-key", ECDSA_PK, digest)
        return self.helper_call(
            f"sign({PARAMS_TYPE},string,uint256,uint256[],uint128[],uint256,uint256,bytes[],bytes32)(bytes)",
            "(%d,%d,%d,%d)" % params, tag, self.tree_index, "[%s]" % ",".join(map(str, signers)),
            "[%s]" % ",".join(seeds), 0, nonce, "[%s]" % ",".join(certs), digest)

    def run_scenario(self, bundler_name, bundler_url, scenario, counterfactual=False):
        """counterfactual: the first op deploys the account through initCode. Otherwise the account is
        deployed by an ordinary transaction first, and two transfers test signature acceptance alone."""
        name, vkey, params, members, threshold, signers, verifier_gas = scenario
        self.fees(bundler_url)  # fail before funding an account if the bundler isn't reachable
        tag = f"{name} / {bundler_name} / {'cf' if counterfactual else 'pre'}" + (f" / {self.run}" if self.run else "")
        init = self.init_data(self.d[vkey], params, tag, members, threshold)
        salt = cast("keccak", tag)
        sender = self.call(self.d["kernelFactory"], "getAddress(bytes,bytes32)(address)", init, salt)
        cast("send", "--private-key", self.funder, "--value", self.fund, sender, "--rpc-url", self.rpc)
        if not counterfactual:
            cast("send", "--private-key", self.funder, self.d["factoryStaker"],
                 "deployWithFactory(address,bytes,bytes32)", self.d["kernelFactory"], init, salt, "--rpc-url", self.rpc)
        results = []
        for nonce in ((0,) if counterfactual else (0, 1)):
            factory_data = cast("calldata", "deployWithFactory(address,bytes,bytes32)", self.d["kernelFactory"],
                                init, salt) if counterfactual else None
            row = self.submit(bundler_name, bundler_url, sender, nonce, params, tag, signers, self.d[vkey],
                              verifier_gas, factory_data)
            row["scenario"] = name
            results.append(row)
            if row.get("send") != "accepted" or row.get("included") == "no (timeout)":
                break
        return results

    def submit(self, bundler_name, bundler_url, sender, nonce, params, tag, signers, validator, verifier_gas,
               factory_data=None):
        """One UserOperation through a bundler: estimate (dummy signature), sign, send, wait for the receipt.
        factory_data: deploy the account through the meta factory (initCode) with this operation."""
        certs, seeds = self.certs(validator, sender, params, tag, signers)
        max_fee, prio = self.fees(bundler_url)
        op = {
            "sender": sender,
            "nonce": h(nonce),
            "callData": self.transfer(self.transfer_wei),
            "maxFeePerGas": h(max_fee),
            "maxPriorityFeePerGas": h(prio),
            "signature": dummy_signature(params, signers, certs),
        }
        if factory_data:
            op["factory"] = self.d["factoryStaker"]
            op["factoryData"] = factory_data
        row = dict(op="deploy (initCode)" if factory_data else f"transfer n{nonce}", bundler=bundler_name,
                   sig_bytes=len(op["signature"]) // 2 - 1, certificates=sum(c != "0x" for c in certs))
        # Rundler estimates best from zero limits; Alto needs room to simulate. Try zero, then generous.
        est, errors = None, []
        for limits in ((0, 0, 0), (1_000_000, 2_000_000, 1_000_000)):
            op["callGasLimit"], op["verificationGasLimit"], op["preVerificationGas"] = map(h, limits)
            try:
                est = rpc(bundler_url, "eth_estimateUserOperationGas", [op, self.ep])
                if int(est["verificationGasLimit"], 16) == 0:
                    raise RpcError("estimate returned verificationGasLimit 0")
                break
            except (RpcError, KeyError, urllib.error.HTTPError) as e:
                errors.append(str(e))
                est = None
        if est:
            # the estimates unchanged: the validator spends as much gas on the dummy as on the real signature
            row["estimate"] = "ok"
            row["est_vgl"] = int(est["verificationGasLimit"], 16)
            row["est_pvg"] = int(est["preVerificationGas"], 16)
            for k in ("callGasLimit", "verificationGasLimit", "preVerificationGas"):
                op[k] = est[k]
        else:
            row["estimate"] = "rejected: " + " / ".join(errors)
            # fall back to fixed limits so acceptance itself can still be tested
            op["callGasLimit"] = h(100_000)
            op["preVerificationGas"] = h(100_000 + 20 * row["sig_bytes"])
            vgl = ((600_000 if factory_data else 150_000) + verifier_gas * len(signers)
                   + 110_000 * row["certificates"])  # a certificate: stateless verification and storage
            op["verificationGasLimit"] = h(vgl * 12 // 10)
        row["vgl"] = int(op["verificationGasLimit"], 16)
        op["signature"] = self.sign(op, params, tag, signers, nonce, certs, seeds)
        try:
            op_hash = rpc(bundler_url, "eth_sendUserOperation", [op, self.ep])
            row["send"] = "accepted"
        except RpcError as e:
            row["send"] = f"rejected: {e}"
            return row
        receipt = None
        for _ in range(300):
            receipt = rpc(bundler_url, "eth_getUserOperationReceipt", [op_hash])
            if receipt:
                break
            time.sleep(1)
        if receipt:
            row["included"] = "yes" if receipt.get("success") else "yes, execution failed"
            row["gas_used"] = int(receipt.get("actualGasUsed", "0x0"), 16)
            row["gas_cost_wei"] = int(receipt.get("actualGasCost", "0x0"), 16)
            row["tx"] = (receipt.get("receipt") or {}).get("transactionHash")
        else:
            row["included"] = "no (timeout)"
        return row

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--deployment", required=True)
    ap.add_argument("--funder", required=True, help="private key that funds the test accounts")
    ap.add_argument("--bundler", action="append", required=True, help="name=url")
    ap.add_argument("--out", default="bench/bundlers/results.json")
    ap.add_argument("--signer-rpc", help="node with the WotsSignerHelper (default: --rpc)")
    ap.add_argument("--signer-helper", help="WotsSignerHelper address on --signer-rpc (default: from deployment)")
    ap.add_argument("--fund", default="1ether", help="value sent to each test account")
    ap.add_argument("--transfer-wei", type=int, default=10**15, help="value each operation transfers")
    ap.add_argument("--only", help="comma-separated scenario names (default: all)")
    ap.add_argument("--run", default="", help="label for fresh test accounts (accounts derive from tags)")
    ap.add_argument("--fees", choices=("fixed", "bundler"), default="fixed",
                    help="fixed: 50 gwei / 1 gwei; bundler: each bundler's gas price method")
    args = ap.parse_args()

    driver = Driver(args.rpc, json.load(open(args.deployment)), args.signer_rpc, args.signer_helper)
    driver.funder = args.funder
    driver.fund, driver.transfer_wei, driver.fee_mode, driver.run = args.fund, args.transfer_wei, args.fees, args.run
    rows = []
    for spec in args.bundler:
        bname, burl = spec.split("=", 1)
        chosen = [sc for sc in SCENARIOS if not args.only or sc[0] in args.only.split(",")]
        runs = [(sc, False) for sc in chosen] + [(sc, True) for sc in chosen if sc in SCENARIOS[:2]]
        for scenario, counterfactual in runs:
            try:
                rows += driver.run_scenario(bname, burl, scenario, counterfactual)
            except Exception as e:  # keep going: one broken scenario must not hide the others
                rows.append(dict(scenario=scenario[0], op="setup", bundler=bname, estimate=f"error: {e}"))
            r = rows[-1]
            print(f"  {bname:8} {scenario[0]:28} {r.get('op', ''):16} {r.get('send', r.get('estimate'))[:60]}",
                  flush=True)
    json.dump(rows, open(args.out, "w"), indent=1)

    print(f"\n{'bundler':8} {'scenario':28} {'op':16} {'sig B':>6} {'estimate':10} {'est VGL':>8} {'VGL':>8} "
          f"{'est PVG':>8} {'send':10} {'included':10} {'gas used':>9} {'cost gwei':>10}")
    for r in rows:
        est = r.get("estimate", "")
        send = r.get("send", "")
        cost = f"{r['gas_cost_wei'] / GWEI:.0f}" if "gas_cost_wei" in r else ""
        print(f"{r['bundler']:8} {r['scenario']:28} {r.get('op', ''):16} {r.get('sig_bytes', ''):>6} "
              f"{est if est == 'ok' else 'REJECTED':10} {r.get('est_vgl', ''):>8} {r.get('vgl', ''):>8} "
              f"{r.get('est_pvg', ''):>8} {send if send == 'accepted' else ('REJECTED' if send else '-'):10} "
              f"{r.get('included', '-'):10} {r.get('gas_used', ''):>9} {cost:>10}")
    reasons = {(r["bundler"], r["scenario"], r.get("op")): (r.get("estimate"), r.get("send"))
               for r in rows if r.get("estimate", "ok") != "ok" or r.get("send", "accepted") != "accepted"}
    if reasons:
        print("\nRejection reasons:")
        for (b, s, o), (e, snd) in reasons.items():
            print(f"  {b} / {s} / {o}:")
            if e and e != "ok":
                print(f"    estimate: {e}")
            if snd and snd != "accepted":
                print(f"    send:     {snd}")


if __name__ == "__main__":
    main()
