#!/usr/bin/env python3
"""A live WalletConnect run on Sepolia, through Reown's relay: a dapp on the official SDK (tools/live_dapp.js) pairs
with member 1's `connect` and sees the team's Safe. Member 2 and the gas account are played by this script.

  sign-in      personal_sign of a sign-in with Ethereum message. Member 1 signs with its member key and writes a
               message file; this script has member 2 sign a copy (`message --file`) and returns it. The dapp gets
               the Safe's combined signature and checks it with viem's verifyMessage.
  transaction  eth_sendTransaction of 1e11 wei to the gas account. Member 1 proposes it to Safe's Transaction
               Service; the dapp gets the SafeTx hash. Member 2 confirms, the gas account executes, and the dapp,
               asking the wallet for the receipt of the SafeTx hash, gets the execution's receipt.
  permit2      eth_signTypedData_v4 of a Permit2 PermitSingle. Member 1 proposes the approval through SignMessageLib;
               member 2 confirms, the gas account executes, and the dapp gets the v2 owners' approved signatures (0x
               with fewer v2 owners than the threshold). It reports what viem makes of it, and of 0x.
Member 2 signs only those two transactions (checked against the scenario): anything else in the Safe's queue is left.

Needs: a DIR with two signer homes m1 and m2 whose owners are the Safe's owners, enrolled on it (as tools/
live_check.py and tools/live_devices.py leave them); Node, and a node_modules with @walletconnect/sign-client and viem (--node-modules).
Environment (set -a; . contracts/bench/bundlers/.env; set +a): ALCHEMY_API_KEY, DEPLOYER_PRIVATE_KEY (the gas
account: a throwaway testnet key), SAFE_API_KEY, WALLETCONNECT_PROJECT_ID. Nothing secret is printed: output passes
tools/live_check.py's redaction, plus the project ID. Results go to DIR/walletconnect-<time>.json.

usage: signer/.venv/bin/python signer/tools/live_walletconnect.py --dir DIR --safe SAFE --node-modules PATH
"""
import argparse
import contextlib
import datetime
import glob
import io
import json
import os
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_check import Redactor, MAX_BASE_FEE  # noqa: E402

from winterlock_signer import abi, cli, messages, safelibs  # noqa: E402
from winterlock_signer.abi import b2h  # noqa: E402
from winterlock_signer.eip712 import TypedData  # noqa: E402
from winterlock_signer.ethtx import Account  # noqa: E402
from winterlock_signer.member import Member  # noqa: E402
from winterlock_signer.rpc import Rpc  # noqa: E402
from winterlock_signer.service import Service, default_url  # noqa: E402

CHAIN = 11155111
SIGNER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN = "app.example"
TRANSFER = 10**11
TIMEOUT = 25 * 60


def sign_in_text(safe):
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    iso = lambda t: t.isoformat().replace("+00:00", "Z")  # noqa: E731
    return (f"{DOMAIN} wants you to sign in with your Ethereum account:\n{safe}\n\n"
            "Sign in to the Winterlock live test.\n\n"
            f"URI: https://{DOMAIN}\nVersion: 1\nChain ID: {CHAIN}\nNonce: {secrets.token_hex(8)}\n"
            f"Issued At: {iso(now)}\nExpiration Time: {iso(now + datetime.timedelta(hours=1))}")


def permit2(spender, nonce):
    return {"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"},
                                       {"name": "verifyingContract", "type": "address"}],
                      "PermitSingle": [{"name": "details", "type": "PermitDetails"},
                                       {"name": "spender", "type": "address"},
                                       {"name": "sigDeadline", "type": "uint256"}],
                      "PermitDetails": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"},
                                        {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}]},
            "primaryType": "PermitSingle",
            "domain": {"name": "Permit2", "chainId": CHAIN, "verifyingContract": messages.PERMIT2},
            "message": {"details": {"token": "0x1111111111111111111111111111111111111111", "amount": 1000000,
                                    "expiration": 4102444800, "nonce": nonce},
                        "spender": spender, "sigDeadline": 4102444800}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dir", required=True)
    p.add_argument("--safe", required=True)
    p.add_argument("--node-modules", required=True)
    a = p.parse_args()
    homes = {m: os.path.join(a.dir, m) for m in ("m1", "m2")}
    stamp = time.strftime("%Y%m%dT%H%M%S")
    work = os.path.join(a.dir, f"walletconnect-{stamp}")
    exchange = os.path.join(work, "exchange")
    os.makedirs(exchange, mode=0o700)
    red = Redactor(list(homes.values()))
    red.secrets.append(os.environ["WALLETCONNECT_PROJECT_ID"])

    def log(*x):
        print(red(" ".join(map(str, x))), flush=True)

    url = f"https://eth-sepolia.g.alchemy.com/v2/{os.environ['ALCHEMY_API_KEY']}"
    rpc = Rpc(url)
    safe = abi.address(a.safe)
    gas = Account(os.environ["DEPLOYER_PRIVATE_KEY"])
    service = default_url(CHAIN)
    owners = {}
    for m, h in homes.items():
        mem = Member(h, lock=False)
        owners[m] = mem.owner
        mem.close()
    on_chain = abi.dec_addresses(rpc.eth_call(safe, abi.calldata("getOwners()")))
    if not set(owners.values()) <= set(on_chain):
        raise SystemExit(f"m1 and m2 are not owners of {safe}")
    base = rpc.base_fee()
    if base > MAX_BASE_FEE:
        raise SystemExit(f"base fee {base:,} wei is above {MAX_BASE_FEE:,}: not starting")

    sc = {"chainId": CHAIN, "domain": DOMAIN, "safe": safe, "signIn": sign_in_text(safe),
          "transfer": {"to": gas.address, "value": str(TRANSFER)}, "permit2": permit2(gas.address, int(time.time())),
          "receiptWaitMs": 10 * 60 * 1000, "receiptPollMs": 15000}
    permit_hash = TypedData(sc["permit2"]).hash()
    sml = safelibs.default_address(safelibs.SIGN_MESSAGE_LIB)
    scenario = os.path.join(work, "scenario.json")
    with open(scenario, "w") as f:
        json.dump(sc, f, indent=1)
    res = {"safe": safe, "owners": owners, "gas_account": gas.address, "relay": "wss://relay.walletconnect.org",
           "sdk": json.load(open(os.path.join(a.node_modules, "@walletconnect/sign-client/package.json")))["version"],
           "viem": json.load(open(os.path.join(a.node_modules, "viem/package.json")))["version"],
           "balance_start_wei": rpc.balance(gas.address), "safe_nonce_start": safe_nonce(rpc, safe),
           "dapp": [], "member2": [], "skipped": []}

    def save():
        path = os.path.join(a.dir, f"walletconnect-{stamp}.json")
        with open(path + ".tmp", "w") as f:
            f.write(red(json.dumps(res, indent=1)))
        os.replace(path + ".tmp", path)

    events = queue.Queue()
    dapp = subprocess.Popen(["node", os.path.join(SIGNER, "tools", "live_dapp.js"), scenario,
                             os.path.join(work, "dapp.db")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=dict(os.environ, NODE_PATH=a.node_modules, SEPOLIA_RPC=url))

    def reader():
        for line in dapp.stdout:
            try:
                events.put(json.loads(line))
            except ValueError:
                events.put({"log": line.rstrip()})
        events.put({"exited": dapp.wait()})
    threading.Thread(target=reader, daemon=True).start()

    connect = None
    connect_log_path = os.path.join(work, "connect.log")
    connect_log = open(connect_log_path, "w")
    handled_files, handled_txs, executed = set(), set(), []

    def m2(*argv):
        args = ["--home", homes["m2"], "--yes", argv[0], "--chain", str(CHAIN), "--rpc", url, *argv[1:]]
        if argv[0] in ("confirm", "execute"):
            args += ["--service", service, "--gas-key-env", "DEPLOYER_PRIVATE_KEY"]
        buf = io.StringIO()
        t = time.time()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli.main(args)
        text = red(buf.getvalue())
        res["member2"].append({"command": argv[0], "exit": code, "seconds": round(time.time() - t, 1),
                               "output": text.strip().splitlines()[-6:]})
        for line in text.strip().splitlines():
            log(f"    m2 {argv[0]}: {line}")
        return code

    def expected(tx):
        to, op, value = tx["to"].lower(), int(tx["operation"]), int(tx["value"])
        data = abi.h2b(tx["data"]) if tx.get("data") else b""
        if to == gas.address.lower() and op == 0 and value == TRANSFER and not data:
            return "transfer"
        if to == sml.lower() and op == 1 and value == 0 and data == messages.sign_message_calldata(permit_hash):
            return "permit2 approval"
        return None

    def member2_turn():
        for path in sorted(glob.glob(os.path.join(exchange, "safe-message-*.json"))):
            if path in handled_files:
                continue
            handled_files.add(path)
            copy = os.path.join(work, "m2-" + os.path.basename(path))
            shutil.copy(path, copy)
            log(f"member 2 signs {os.path.basename(path)}")
            if m2("message", "--file", copy) == 0:
                shutil.copy(copy, os.path.join(exchange, "returned-by-m2-" + os.path.basename(path)))
        nonce = safe_nonce(rpc, safe)
        for tx in Service(service).pending(safe, nonce):
            h = tx["safeTxHash"]
            if h in handled_txs:
                continue
            what = expected(tx)
            signers = [c["owner"] for c in tx.get("confirmations") or []]
            if not what or owners["m1"] not in signers or int(tx["nonce"]) != nonce:
                if h not in res["skipped"]:
                    res["skipped"].append(h)
                    log(f"leaving {h} (nonce {tx['nonce']}): not one this run expects")
                continue
            handled_txs.add(h)
            log(f"member 2 confirms the {what} {h} (nonce {nonce}), then the gas account executes it")
            if owners["m2"] not in signers and m2("confirm", "--safe-tx-hash", h) != 0:
                continue
            if m2("execute", "--safe-tx-hash", h) == 0:
                executed.append(what)

    t0 = time.time()
    done = False
    try:
        while time.time() - t0 < TIMEOUT and not done:
            try:
                ev = events.get(timeout=3)
            except queue.Empty:
                ev = None
            if ev is not None:
                if "log" not in ev:
                    res["dapp"].append(ev)
                    save()
                log("dapp:", json.dumps(ev)[:600])
                if "uri" in ev and connect is None:
                    connect = subprocess.Popen(
                        [sys.executable, "-m", "winterlock_signer", "--home", homes["m1"], "--yes", "connect",
                         "--chain", str(CHAIN), "--rpc", url, "--service", service, "--safe", safe,
                         "--exchange-dir", exchange, "--poll", "3", ev["uri"]],
                        cwd=SIGNER, stdout=connect_log, stderr=subprocess.STDOUT,
                        env=dict(os.environ, PYTHONPATH=SIGNER))
                done = "done" in ev or "fatal" in ev or "exited" in ev
            if connect is not None and connect.poll() is not None and not done:
                log(f"connect exited with {connect.returncode}")
                with contextlib.suppress(subprocess.TimeoutExpired):
                    dapp.wait(15)
                time.sleep(1)  # the reader thread passes on the dapp's last lines
                while not events.empty():
                    ev = events.get()
                    if "log" not in ev:
                        res["dapp"].append(ev)
                    log("dapp:", json.dumps(ev)[:600])
                    done = done or "done" in ev
                break
            if connect is not None and not done:
                try:
                    member2_turn()
                except Exception as e:  # a Service hiccup: try again on the next round
                    log(f"member 2's turn failed: {e!r}")
    finally:
        for proc in (connect, dapp):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(10)
        connect_log.close()
        with open(connect_log_path) as f:
            res["connect_log_tail"] = red(f.read()).splitlines()[-60:]
        res["balance_end_wei"] = rpc.balance(gas.address)
        # the gas account paid the fees and received the transfer
        res["fees_wei"] = res["balance_start_wei"] - res["balance_end_wei"] + TRANSFER * executed.count("transfer")
        res["executed"] = executed
        res["safe_nonce_end"] = safe_nonce(rpc, safe)
        res["seconds"] = round(time.time() - t0)
        save()
    log(f"results in {os.path.join(a.dir, f'walletconnect-{stamp}.json')}")
    return 0 if done and not any("error" in e or "fatal" in e for e in res["dapp"]) else 1


def safe_nonce(rpc, safe):
    return abi.dec_uint(rpc.eth_call(safe, abi.calldata("nonce()")))


if __name__ == "__main__":
    sys.exit(main())
