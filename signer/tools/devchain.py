"""Development helpers for the signer's tests and tools: a local anvil, contract deployment from build artifacts,
and Safe creation through a Safe proxy factory. Not part of the signer."""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNER = os.path.dirname(HERE)
ROOT = os.path.dirname(SIGNER)
CONTRACTS = os.path.join(ROOT, "contracts")
sys.path.insert(0, SIGNER)

from winterlock_signer import abi  # noqa: E402
from winterlock_signer.abi import h2b  # noqa: E402
from winterlock_signer.ethtx import Account, send  # noqa: E402
from winterlock_signer.rpc import Rpc  # noqa: E402

# anvil's first default account (public test key, local chains only)
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
FOUNDRY_BIN = os.path.expanduser("~/.foundry/bin")
SAFE_141 = os.path.join(CONTRACTS, "lib/safe-smart-account-v1.4.1/build/forge-out")


def tool(name):
    path = shutil.which(name) or os.path.join(FOUNDRY_BIN, name)
    if not os.path.exists(path):
        raise RuntimeError(f"{name} not found (Foundry)")
    return path


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Anvil:
    def __init__(self, chain_id=None):
        self.port = free_port()
        args = [tool("anvil"), "--port", str(self.port), "--silent", "--disable-code-size-limit",
                "--disable-block-gas-limit"]
        if chain_id:
            args += ["--chain-id", str(chain_id)]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.url = f"http://127.0.0.1:{self.port}"
        self.rpc = Rpc(self.url, timeout=600)
        for _ in range(200):
            try:
                self.rpc.chain_id()
                break
            except Exception:
                time.sleep(0.05)
        else:
            self.close()
            raise RuntimeError("anvil didn't start")
        self.account = Account(ANVIL_KEY)

    def close(self):
        self.proc.terminate()
        self.proc.wait()


def artifact_code(path):
    with open(path) as f:
        return h2b(json.load(f)["bytecode"]["object"])


def deploy(rpc, account, creation_code: bytes, args_encoded: bytes = b"", log=lambda *a: None):
    r = send(rpc, account, None, creation_code + args_encoded, gas=30_000_000, log=log)
    return abi.checksum(r["contractAddress"])


def safe_release(rpc, account, build=SAFE_141, l2=True):
    """Deploys a Safe release from its build: singleton (SafeL2 or Safe), proxy factory, fallback handler"""
    name = "SafeL2" if l2 else "Safe"
    return {
        "singleton": deploy(rpc, account, artifact_code(f"{build}/{name}.sol/{name}.json")),
        "factory": deploy(rpc, account, artifact_code(f"{build}/SafeProxyFactory.sol/SafeProxyFactory.json")),
        "fallback_handler": deploy(rpc, account, artifact_code(
            f"{build}/CompatibilityFallbackHandler.sol/CompatibilityFallbackHandler.json")),
    }


def create_safe_calldata(singleton, owners, threshold, fallback_handler, salt_nonce):
    zero = "0x" + "00" * 20
    setup = abi.calldata("setup(address[],uint256,address,bytes,address,address,uint256,address)",
                         ["address[]", "uint256", "address", "bytes", "address", "address", "uint256", "address"],
                         [owners, threshold, zero, b"", fallback_handler, zero, 0, zero])
    return abi.calldata("createProxyWithNonce(address,bytes,uint256)", ["address", "bytes", "uint256"],
                        [singleton, setup, salt_nonce])


def create_safe(rpc, account, release, owners, threshold, salt_nonce=0, log=lambda *a: None):
    cd = create_safe_calldata(release["singleton"], owners, threshold, release["fallback_handler"], salt_nonce)
    predicted = abi.dec_addr(rpc.eth_call(release["factory"], cd, sender=account.address))
    if not rpc.code(predicted):
        r = send(rpc, account, release["factory"], cd, log=log)
        assert rpc.code(predicted), "Safe creation failed"
        return predicted, r
    return predicted, None


def forge_build(files, out_dir):
    """Builds files (paths relative to contracts/) into out_dir, leaving contracts/out and its cache alone"""
    subprocess.run([tool("forge"), "build", *files, "--out", os.path.join(out_dir, "out"),
                    "--cache-path", os.path.join(out_dir, "cache")], cwd=CONTRACTS, check=True,
                   stdout=subprocess.DEVNULL)
    return os.path.join(out_dir, "out")
