#!/usr/bin/env python3
"""One end-to-end run of the signer on Sepolia, through Safe's hosted Transaction Service: a NEW 2-of-2 Safe v1.4.1
(SafeL2, canonical factory) whose owners are two NEW members' WinterlockOwner contracts, each with its own new
seed. Steps (each runs once; a finished step is skipped on a re-run):
  init     two new signers (new random seeds) in DIR/m1 and DIR/m2
  safe     create the Safe (owners: the two members' predicted proxy owners) and fund it with 0.00001 ETH
  enroll   member 1 with --deploy: the WOTS verifier, the v2 implementation and the factory if the chain lacks them
           (once per chain: about 4.1M, 13.0M and 2.7M gas under Glamsterdam, estimates), then each member's owner
           and first tree of height 6 in one deployAndEnroll (v1: about 0.61M gas under Glamsterdam)
  index    wait until the service has indexed the Safe (GET only)
  propose  member 1 proposes sending 1e11 wei to the gas account (one POST)
  confirm  member 2 confirms it (one POST)
  execute  the gas account executes it; then one GET to see the service index the execution
--fork rehearses everything on a local anvil fork of Sepolia with tests/mock_service.py instead of the service.

Environment (set -a; . contracts/bench/bundlers/.env; set +a): ALCHEMY_API_KEY, DEPLOYER_PRIVATE_KEY (the gas
account: a throwaway testnet key), SAFE_API_KEY. Nothing secret is printed or written: every line of output passes a
redaction of those values and of the members' seeds. Results (addresses, hashes, statuses) go to DIR/results.json.

usage: signer/.venv/bin/python signer/tools/live_check.py --dir DIR [--fork] [STEP ...]
"""
import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import devchain  # noqa: E402

from winterlock_signer import abi, cli, phrase  # noqa: E402
from winterlock_signer.ethtx import Account, send  # noqa: E402
from winterlock_signer.member import Member  # noqa: E402
from winterlock_signer.rpc import Rpc  # noqa: E402
from winterlock_signer.service import Service, default_url  # noqa: E402

CHAIN = 11155111
# Safe v1.4.1 canonical deployments (safe-deployments), as in contracts/bench/safe/live.py
RELEASE = {"singleton": "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
           "factory": "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
           "fallback_handler": "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"}
FUND = 10**13
TRANSFER = 10**11
MAX_SPEND = 5 * 10**15  # 0.005 ETH, including the funding
MAX_BASE_FEE = 10**10  # 10 gwei: Sepolia runs at a few dozen wei; stop rather than pay a spike
STEPS = ["init", "safe", "enroll", "index", "propose", "confirm", "execute"]


class Redactor:
    def __init__(self, homes):
        vals = [os.environ.get(k) for k in ("ALCHEMY_API_KEY", "DEPLOYER_PRIVATE_KEY", "SAFE_API_KEY",
                                            "SAFE_SPIKE_TAG", "MULTICHAIN_TAG", "PIMLICO_API_KEY")]
        for h in homes:
            p = os.path.join(h, "seed")
            if os.path.exists(p):
                hexseed = abi.read_file(p).strip()
                vals.append(hexseed)
                if len(hexseed) == 64:  # and the same seed spelled as its recovery phrase
                    vals.append(" ".join(phrase.to_phrase(bytes.fromhex(hexseed))))
        self.secrets = [v for v in vals if v and len(v) >= 8]

    def __call__(self, text):
        text = str(text)
        for s in self.secrets:
            text = text.replace(s, "<redacted>")
            if s.startswith("0x"):
                text = text.replace(s[2:], "<redacted>")
        return text


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dir", required=True)
    p.add_argument("--fork", action="store_true")
    p.add_argument("steps", nargs="*")
    a = p.parse_args()
    os.makedirs(a.dir, mode=0o700, exist_ok=True)
    homes = [os.path.join(a.dir, "m1"), os.path.join(a.dir, "m2")]
    state_path = os.path.join(a.dir, "results.json")
    st = {"done": [], "service": [], "onchain": {}}
    if os.path.exists(state_path):
        with open(state_path) as f:
            st = json.load(f)

    def save():
        with open(state_path + ".tmp", "w") as f:
            json.dump(st, f, indent=1)
        os.replace(state_path + ".tmp", state_path)

    red = Redactor(homes)

    def log(*x):
        print(red(" ".join(map(str, x))), flush=True)

    url = f"https://eth-sepolia.g.alchemy.com/v2/{os.environ['ALCHEMY_API_KEY']}"
    anvil = service_proc = None
    if a.fork:
        port = devchain.free_port()
        anvil = subprocess.Popen([devchain.tool("anvil"), "--port", str(port), "--fork-url", url, "--silent",
                                  "--chain-id", str(CHAIN)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f"http://127.0.0.1:{port}"
        for _ in range(200):
            try:
                Rpc(url).chain_id()
                break
            except Exception:
                time.sleep(0.1)
        sport = devchain.free_port()
        service_proc = subprocess.Popen([sys.executable, "-m", "tests.mock_service", "--rpc", url, "--port",
                                         str(sport)], cwd=devchain.SIGNER, stderr=subprocess.DEVNULL)
        service = f"http://127.0.0.1:{sport}/api"
        time.sleep(0.5)
    else:
        service = default_url(CHAIN)
    os.environ["WINTERLOCK_RPC"] = url
    rpc = Rpc(url)
    gas = Account(os.environ["DEPLOYER_PRIVATE_KEY"])
    st.setdefault("gas_account", gas.address)
    st.setdefault("balance_start_wei", rpc.balance(gas.address))
    save()
    base = rpc.base_fee()
    if base > MAX_BASE_FEE:
        raise SystemExit(f"base fee {base:,} wei is above {MAX_BASE_FEE:,}: not starting")

    def run(member, *argv):
        args = ["--home", homes[member], "--yes", argv[0], *argv[1:]]
        if argv[0] != "init":
            args += ["--chain", str(CHAIN), "--gas-key-env", "DEPLOYER_PRIVATE_KEY"]
        if argv[0] in ("propose", "confirm", "execute", "queue"):
            args += ["--service", service]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(args)
        text = red(buf.getvalue())
        for line in text.splitlines():
            log(f"    {line}")
        if code:
            raise SystemExit(f"{argv[0]} (member {member + 1}) exited {code}")
        return text

    def spent():
        s = st["balance_start_wei"] - rpc.balance(gas.address)
        if s > MAX_SPEND:
            raise SystemExit(f"spent {s} wei, over the 0.01 ETH budget: stopping")
        return s

    try:
        for step in a.steps or STEPS:
            if step in st["done"]:
                log(f"{step}: done before, skipped")
                continue
            log(f"{step}:")
            if step == "init":
                for i, h in enumerate(homes):
                    if not os.path.exists(os.path.join(h, "seed")):
                        run(i, "init", "--insecure-plaintext-seed")  # throwaway testnet seeds: no phrase is printed
                red.__init__(homes)  # redact the new seeds from here on
                st["owners"] = []
                for h in homes:
                    m = Member(h, lock=False)
                    st["owners"].append({"owner": m.owner, "key": abi.b2h(m.key)})
                    m.close()
            elif step == "safe":
                owners = [o["owner"] for o in st["owners"]]
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
                for i in (0, 1):
                    text = run(i, "enroll", "--safe", st["safe"], *(["--deploy"] if i == 0 else []), "--height", "6")
                    st["onchain"][f"enroll_m{i + 1}"] = [line.strip() for line in text.splitlines()
                                                         if "gas used" in line or "estimate" in line]
                    save()
                    spent()
            elif step == "index":
                svc = Service(service)
                t0 = time.time()
                for poll in range(1, 31):
                    status, resp = svc.request("GET", f"/v1/safes/{st['safe']}/")
                    if status == 200:
                        break
                    time.sleep(20)
                st["service"].append({"call": f"GET /v1/safes/{st['safe']}/", "status": status, "polls": poll,
                                      "seconds": round(time.time() - t0),
                                      "response": {k: resp.get(k) for k in ("nonce", "threshold", "owners", "version",
                                                                            "masterCopy")} if status == 200 else resp})
                log(f"  GET /v1/safes/{{safe}}/ -> {status} after {poll} poll(s)")
                if status != 200:
                    raise SystemExit("not indexed")
            elif step == "propose":
                text = run(0, "propose", "--safe", st["safe"], "--to", gas.address, "--value", f"{TRANSFER}wei")
                st["safe_tx_hash"] = next(line.split("SafeTx hash ")[1].split()[0] for line in text.splitlines()
                                          if "SafeTx hash" in line)
                st["service"].append({"call": "POST /v2/safes/{safe}/multisig-transactions/",
                                      "status": next(line.split("HTTP ")[1].split()[0] for line in text.splitlines()
                                                     if "HTTP" in line)})
            elif step == "confirm":
                text = run(1, "confirm", "--safe-tx-hash", st["safe_tx_hash"])
                st["service"].append({"call": "POST /v1/multisig-transactions/{hash}/confirmations/",
                                      "status": next(line.split("HTTP ")[1].split()[0] for line in text.splitlines()
                                                     if "HTTP" in line)})
            elif step == "execute":
                text = run(0, "execute", "--safe-tx-hash", st["safe_tx_hash"])
                st["onchain"]["execute"] = [line.strip() for line in text.splitlines()
                                            if "Executed" in line or "estimate" in line]
                save()
                time.sleep(5 if a.fork else 90)
                status, resp = Service(service).request("GET", f"/v2/multisig-transactions/{st['safe_tx_hash']}/")
                keep = ("isExecuted", "isSuccessful", "transactionHash", "executor", "proposer", "confirmationsRequired",
                        "gasUsed", "nonce")
                summary = {k: resp.get(k) for k in keep} if status == 200 else resp
                if status == 200:
                    summary["confirmations"] = [{"owner": c.get("owner"), "signatureType": c.get("signatureType"),
                                                 "bytes": (len(c.get("signature") or "") - 2) // 2}
                                                for c in resp.get("confirmations") or []]
                st["service"].append({"call": "GET /v2/multisig-transactions/{hash}/", "status": status,
                                      "response": summary})
                log(f"  GET after execution -> {status}: {json.dumps(summary)[:600]}")
            st["done"].append(step)
            st["spent_wei"] = spent()
            save()
        log(f"spent {st['spent_wei'] / 1e18:.8f} ETH (including {FUND / 1e18} ETH in the Safe)")
    finally:
        save()
        if service_proc:
            service_proc.terminate()
            service_proc.wait()
        if anvil:
            anvil.terminate()
            anvil.wait()


if __name__ == "__main__":
    main()
