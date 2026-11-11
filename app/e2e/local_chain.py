#!/usr/bin/env python3
"""For the app's runs on a local chain (e2e/board.spec.ts): deploys owner v2's four shared contracts at their pinned
addresses (through the deterministic deployment proxy, from the Python signer's pinned code, as anvil_e2e.py does) and a
Safe v1.4.1 release (SafeL2, proxy factory, fallback handler) on the anvil at RPC_URL, and prints their addresses as
JSON. Pays with anvil's first default account.

usage: signer/.venv/bin/python -I app/e2e/local_chain.py RPC_URL
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "signer"))
sys.path.insert(0, os.path.join(ROOT, "signer", "tools"))

import devchain  # noqa: E402
from winterlock_signer import owner  # noqa: E402
from winterlock_signer.ethtx import Account, send  # noqa: E402
from winterlock_signer.rpc import Rpc  # noqa: E402

SAFE_141 = os.environ.get("SAFE_141_BUILD", "/home/johba/winterlock.eth/contracts/lib/safe-smart-account-v1.4.1/build/forge-out")
QUIET = dict(log=lambda *a: None)


def main():
    rpc = Rpc(sys.argv[1], timeout=600)
    acct = Account(devchain.ANVIL_KEY)
    for salt, init in ((owner.VERIFIER_SALT, owner.VERIFIER_CREATION),
                       (owner.WOTS_VERIFIER_SALT, owner.WOTS_VERIFIER_CREATION),
                       (owner.IMPLEMENTATION_SALT, owner.implementation_init_code()),
                       (owner.FACTORY_SALT, owner.factory_init_code())):
        send(rpc, acct, owner.PROXY, salt + init, gas=30_000_000, **QUIET)
    pinned = [owner.verifier_address(), owner.wots_verifier_address(), owner.implementation_address(),
              owner.factory_address()]
    for a in pinned:
        assert rpc.code(a), f"nothing at {a}"
    release = devchain.safe_release(rpc, acct, build=SAFE_141)
    print(json.dumps({"chainId": rpc.chain_id(), "factory": owner.factory_address(), "safe": release}))


if __name__ == "__main__":
    main()
