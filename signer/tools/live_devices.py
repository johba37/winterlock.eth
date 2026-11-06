#!/usr/bin/env python3
"""Owner v2's first live run on Sepolia, through Safe's hosted Transaction Service: a NEW 2-of-2 Safe v1.4.1 (SafeL2,
canonical factory) whose owners are two NEW members' v2 owners, member 1 signing through a paired device key.
Steps (each runs once; a finished step is skipped on a re-run):
  init       member 1's home (the member key, device 0), member 2's home, and a device home for member 1 (device 1),
             in DIR/m1, DIR/m2 and DIR/d1, with new random seeds
  pair       member 1's home certifies the device key (`device certify`, comparing the device's check code); this
             creates member 1's owner first (the factory's deploy)
  safe       create the Safe (owners: the two members' owners) and fund it with 0.001 ETH
  enroll     a key tree of height 6 each: member 1's device 1, member 1's device 0, member 2 (deployAndEnroll)
  index      wait until the service has indexed the Safe (GET only)
  transfer   the device home proposes 1e11 wei to the gas account, member 2 confirms, the gas account executes
  pending    the device home proposes 2e11 wei; member 2 confirms; it stays pending
  revoke     member 1's home revokes device 1; then: does the device's confirmation still verify (the owner's
             isValidSignature), what the service shows, and what the device home and `execute` say
  reconfirm  member 1's home confirms the pending transaction through the service (and proposes it again): what the
             service answers, and what it holds afterwards
  through    member 1's home confirms again (the same one-time key, so the same signature) and, when the service keeps
             the stale confirmation, writes a proposal file with its signature; the gas account executes with it
  recertify  member 1's home certifies device 1 again (generation 2), the device home enrolls again and proposes
             3e11 wei, member 2 confirms, the gas account executes
Every service call made directly here is a GET; the signer makes the POSTs. Files the signer writes (proposal files)
land in DIR/files.

Environment (set -a; . contracts/bench/bundlers/.env; set +a): ALCHEMY_API_KEY, DEPLOYER_PRIVATE_KEY (the gas
account: a throwaway testnet key), SAFE_API_KEY. Nothing secret is printed or written: output passes
tools/live_check.py's redaction (the keys, and the homes' seeds). Results go to DIR/results.json.

usage: signer/.venv/bin/python signer/tools/live_devices.py --dir DIR [STEP ...]
"""
import argparse
import contextlib
import io
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import devchain  # noqa: E402
from live_check import CHAIN, MAX_BASE_FEE, RELEASE, Redactor  # noqa: E402

from winterlock_signer import abi, cli, owner  # noqa: E402
from winterlock_signer.abi import b2h, h2b  # noqa: E402
from winterlock_signer.ethtx import Account, send  # noqa: E402
from winterlock_signer.member import Member  # noqa: E402
from winterlock_signer.rpc import Reverted, Rpc  # noqa: E402
from winterlock_signer.safe import parse_signature  # noqa: E402
from winterlock_signer.service import Service, default_url  # noqa: E402

FUND = 10**15  # 0.001 ETH
MAX_SPEND = 3 * 10**15  # this tool stops past 0.003 ETH, including the funding
STEPS = ["init", "pair", "safe", "enroll", "index", "transfer", "pending", "revoke", "reconfirm", "through",
         "recertify"]
HOMES = ("m1", "m2", "d1")
GAS_LINE = re.compile(r"gas used ([\d,]+).*?tx (0x[0-9a-fA-F]{64})")


def device_record(rpc, owner_addr):
    key, gen, active = owner.read_device(rpc, owner_addr, 1)
    return {"key": b2h(key), "generation": gen, "active": active}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dir", required=True)
    p.add_argument("steps", nargs="*")
    a = p.parse_args()
    os.makedirs(a.dir, mode=0o700, exist_ok=True)
    homes = {k: os.path.join(a.dir, k) for k in HOMES}
    files_dir = os.path.join(a.dir, "files")
    os.makedirs(files_dir, mode=0o700, exist_ok=True)
    os.chdir(files_dir)
    state_path = os.path.join(a.dir, "results.json")
    st = {"done": [], "service": [], "onchain": {}, "outputs": {}}
    if os.path.exists(state_path):
        with open(state_path) as f:
            st = json.load(f)
    red = Redactor(list(homes.values()))

    def save():
        with open(state_path + ".tmp", "w") as f:
            f.write(red(json.dumps(st, indent=1)))
        os.replace(state_path + ".tmp", state_path)

    def log(*x):
        print(red(" ".join(map(str, x))), flush=True)

    url = f"https://eth-sepolia.g.alchemy.com/v2/{os.environ['ALCHEMY_API_KEY']}"
    os.environ["WINTERLOCK_RPC"] = url
    rpc = Rpc(url)
    service = default_url(CHAIN)
    svc = Service(service)
    gas = Account(os.environ["DEPLOYER_PRIVATE_KEY"])
    st.setdefault("gas_account", gas.address)
    st.setdefault("balance_start_wei", rpc.balance(gas.address))
    save()
    base = rpc.base_fee()
    if base > MAX_BASE_FEE:
        raise SystemExit(f"base fee {base:,} wei is above {MAX_BASE_FEE:,}: not starting")

    def run(step, home, *argv, ok=(0,)):
        """One signer command in-process; its output (redacted) is logged and kept under the step. Returns (exit
        code, text)."""
        args = ["--home", homes[home], "--yes", *argv]
        buf = io.StringIO()
        t0 = time.time()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli.main(args)
        text = red(buf.getvalue())
        for line in text.splitlines():
            log(f"    {home}: {line}")
        st["outputs"].setdefault(step, []).append({"home": home, "argv": " ".join(argv), "exit": code,
                                                   "seconds": round(time.time() - t0, 1),
                                                   "output": text.splitlines()})
        for m in GAS_LINE.finditer(text):
            st["onchain"].setdefault(step, []).append({"home": home, "command": " ".join(argv[:2]),
                                                       "gas_used": int(m[1].replace(",", "")), "tx": m[2]})
        save()
        if code not in ok:
            raise SystemExit(f"{' '.join(argv[:2])} ({home}) exited {code}")
        return code, text

    chain_args = ["--chain", str(CHAIN), "--gas-key-env", "DEPLOYER_PRIVATE_KEY"]

    def tx_view(step, h, label):
        """The service's record of SafeTx `h`, summarised: each confirmation's owner, device and size, and whether
        it counts now (the owner's isValidSignature by eth_call)"""
        status, resp = svc.request("GET", f"/v2/multisig-transactions/{h}/")
        summary = resp
        if status == 200:
            keep = ("nonce", "isExecuted", "isSuccessful", "transactionHash", "executor", "proposer",
                    "confirmationsRequired", "gasUsed", "trusted")
            summary = {k: resp.get(k) for k in keep}
            summary["confirmations"] = []
            for c in resp.get("confirmations") or []:
                entry = {"owner": c.get("owner"), "signatureType": c.get("signatureType"),
                         "bytes": (len(c.get("signature") or "") - 2) // 2, "submissionDate": c.get("submissionDate")}
                try:
                    o, data, is_contract = parse_signature(h2b(c["signature"]))
                    entry["device"] = cli.signature_device(c["signature"])
                    entry["counts_now"] = bool(is_contract and owner.is_valid_signature(rpc, o, h2b(h), data))
                except (ValueError, TypeError, Reverted) as e:
                    entry["parse"] = str(e)
                summary["confirmations"].append(entry)
            if resp.get("signatures"):
                summary["executed_signatures_bytes"] = (len(resp["signatures"]) - 2) // 2
        st["service"].append({"step": step, "what": label, "call": "GET /v2/multisig-transactions/{hash}/",
                              "status": status, "response": summary})
        log(f"  {label}: GET -> {status}: {json.dumps(summary)[:900]}")
        save()
        return status, resp

    def wait_indexed(step, h, label, polls=12):
        for _ in range(polls):
            time.sleep(20)
            status, resp = svc.request("GET", f"/v2/multisig-transactions/{h}/")
            if status == 200 and resp.get("isExecuted"):
                break
        return tx_view(step, h, label)

    def hash_from(text):
        return next(re.search(r"(0x[0-9a-fA-F]{64})", line)[1] for line in text.splitlines()
                    if line.startswith("Proposed "))

    def spent():
        s = st["balance_start_wei"] - rpc.balance(gas.address)
        if s > MAX_SPEND:
            raise SystemExit(f"spent {s} wei, over this tool's {MAX_SPEND} wei: stopping")
        return s

    for step in a.steps or STEPS:
        if step in st["done"]:
            log(f"{step}: done before, skipped")
            continue
        log(f"{step}:")
        if step == "init":
            for k in ("m1", "m2"):
                if not os.path.exists(os.path.join(homes[k], "seed")):
                    run(step, k, "init", "--insecure-plaintext-seed")  # throwaway testnet seeds: no phrase is printed
            m1 = Member(homes["m1"], lock=False)
            m1_owner = m1.owner
            m1.close()
            if not os.path.exists(os.path.join(homes["d1"], "seed")):
                run(step, "d1", "device", "new", "--owner", m1_owner, "--device", "1", "--insecure-plaintext-seed")
            red.__init__(list(homes.values()))  # redact the new seeds from here on
            st["members"] = {}
            for k in HOMES:
                m = Member(homes[k], lock=False)
                st["members"][k] = {"owner": m.owner, "device": m.device_no, "key": b2h(m.key)}
                if m.is_device:
                    st["members"][k]["check_code"] = m.check_code()
                m.close()
        elif step == "pair":
            d1 = st["members"]["d1"]
            run(step, "m1", "device", "certify", "--device", "1", "--key", d1["key"], "--check-code",
                d1["check_code"], *chain_args)
            st["device_1_after_pair"] = device_record(rpc, d1["owner"])
        elif step == "safe":
            owners = [st["members"]["m1"]["owner"], st["members"]["m2"]["owner"]]
            salt = st.setdefault("salt_nonce", int(time.time()))
            save()
            safe, r = devchain.create_safe(rpc, gas, RELEASE, owners, 2, salt, log=log)
            st["safe"] = safe
            if r:
                st["onchain"]["create_safe"] = {"tx": r["transactionHash"], "gas_used": int(r["gasUsed"], 16)}
            save()
            if rpc.balance(safe) < FUND:
                r = send(rpc, gas, safe, b"", value=FUND, log=log)
                st["onchain"]["fund"] = {"tx": r["transactionHash"], "gas_used": int(r["gasUsed"], 16),
                                         "value_wei": FUND}
            log(f"  Safe {safe}, 2 of 2, owners {owners}")
        elif step == "enroll":
            for k in ("d1", "m1", "m2"):
                run(step, k, "enroll", "--safe", st["safe"], "--height", "6", *chain_args)
                spent()
        elif step == "index":
            t0 = time.time()
            for poll in range(1, 31):
                status, resp = svc.request("GET", f"/v1/safes/{st['safe']}/")
                if status == 200:
                    break
                time.sleep(20)
            st["service"].append({"step": step, "call": "GET /v1/safes/{safe}/", "status": status, "polls": poll,
                                  "seconds": round(time.time() - t0),
                                  "response": {k: resp.get(k) for k in ("nonce", "threshold", "owners", "version",
                                                                        "masterCopy")} if status == 200 else resp})
            log(f"  GET /v1/safes/{{safe}}/ -> {status} after {poll} poll(s): {json.dumps(st['service'][-1])[:400]}")
            if status != 200:
                raise SystemExit("not indexed")
        elif step == "transfer":
            _, text = run(step, "d1", "propose", "--safe", st["safe"], "--to", gas.address, "--value", "100000000000wei",
                          "--service", service, *chain_args)
            h = st["transfer_hash"] = hash_from(text)
            run(step, "m2", "confirm", h, "--service", service, *chain_args)
            tx_view(step, h, "transfer, before execution")
            run(step, "m2", "execute", h, "--service", service, *chain_args)
            wait_indexed(step, h, "transfer, after execution")
        elif step == "pending":
            _, text = run(step, "d1", "propose", "--safe", st["safe"], "--to", gas.address, "--value", "200000000000wei",
                          "--service", service, *chain_args)
            h = st["pending_hash"] = hash_from(text)
            run(step, "m2", "confirm", h, "--service", service, *chain_args)
            _, resp = tx_view(step, h, "pending, both confirmations")
            st["pending_nonce"] = int(resp["nonce"])
        elif step == "revoke":
            h = st["pending_hash"]
            m1_owner = st["members"]["m1"]["owner"]
            run(step, "m1", "device", "revoke", "--device", "1", *chain_args)
            st["device_1_after_revoke"] = device_record(rpc, m1_owner)
            _, resp = tx_view(step, h, "pending, after the revoke")
            dev_sig = next(c["signature"] for c in resp["confirmations"] if c["owner"].lower() == m1_owner.lower())
            _, data, _ = parse_signature(h2b(dev_sig))
            calls = {}
            for sig, types, values in (("isValidSignature(bytes32,bytes)", ["bytes32", "bytes"], [h2b(h), data]),):
                try:
                    calls[sig] = b2h(rpc.eth_call(m1_owner, abi.calldata(sig, types, values))[:4])
                except Reverted as e:
                    calls[sig] = f"reverted: {e}"
            st["device_signature_after_revoke"] = {"device": data[1], "bytes": len(data), "eth_call": calls}
            log(f"  the device's confirmation, by eth_call: {calls}")
            run(step, "d1", "confirm", h, "--service", service, *chain_args, ok=(2,))
            run(step, "d1", "propose", "--safe", st["safe"], "--to", gas.address, "--value", "1wei",
                "--service", service, *chain_args, ok=(2,))
            run(step, "d1", "status", "--chain", str(CHAIN))
            run(step, "m2", "execute", h, "--service", service, *chain_args, ok=(1,))
        elif step == "reconfirm":
            h = st["pending_hash"]
            run(step, "m1", "queue", "--safe", st["safe"], "--service", service, *chain_args)
            run(step, "m1", "confirm", h, "--service", service, *chain_args, ok=(0, 1))
            tx_view(step, h, "pending, after member 1's home confirmed")
            run(step, "m1", "propose", "--safe", st["safe"], "--to", gas.address, "--value", "200000000000wei",
                "--nonce", str(st["pending_nonce"]), "--service", service, *chain_args, ok=(0, 1))
            tx_view(step, h, "pending, after member 1's home proposed it again")
        elif step == "through":
            h = st["pending_hash"]
            run(step, "m1", "confirm", h, "--service", service, *chain_args)
            path = os.path.join(files_dir, f"safetx-{h[:12]}.json")
            if not os.path.exists(path):
                raise SystemExit(f"no proposal file {path} from member 1's confirm: nothing to execute with")
            st["through_file"] = os.path.basename(path)
            run(step, "m2", "execute", h, "--file", path, "--service", service, *chain_args)
            wait_indexed(step, h, "pending, after execution")
        elif step == "recertify":
            d1 = st["members"]["d1"]
            run(step, "m1", "device", "certify", "--device", "1", "--key", d1["key"], "--check-code",
                d1["check_code"], *chain_args)
            st["device_1_after_recertify"] = device_record(rpc, d1["owner"])
            run(step, "d1", "status", "--chain", str(CHAIN))
            run(step, "d1", "enroll", "--safe", st["safe"], "--height", "6", *chain_args)
            _, text = run(step, "d1", "propose", "--safe", st["safe"], "--to", gas.address, "--value",
                          "300000000000wei", "--service", service, *chain_args)
            h = st["recertify_hash"] = hash_from(text)
            run(step, "m2", "confirm", h, "--service", service, *chain_args)
            run(step, "m2", "execute", h, "--service", service, *chain_args)
            wait_indexed(step, h, "generation 2 transfer, after execution")
        else:
            raise SystemExit(f"unknown step {step}")
        st["done"].append(step)
        st["spent_wei"] = spent()
        save()
    log(f"spent {st.get('spent_wei', 0):,} wei so far (including {FUND:,} wei in the Safe, less the "
        "transfers back)")


if __name__ == "__main__":
    main()
