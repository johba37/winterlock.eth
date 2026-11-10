#!/usr/bin/env python3
"""End to end on a local chain, with the board's firmware in QEMU: the shared owner v2 contracts deployed through the
deterministic deployment proxy, the board's owner created by the factory, a Safe v1.4.1 whose only owner is the board,
and a parent Safe whose only owner is that Safe.

  1. setup on the board; its member key and owner address come over the link
  2. the gas key comes over the link; the gas account is funded and pays everything below
  3. the board enrols a key tree; its certificate is sent to the owner contract (enroll)
  4. the board confirms an ETH transfer; Safe.execTransaction with that one signature moves the ETH
  5. the board confirms an approveHash of the parent Safe's transfer, with the parent's fields; once executed, the
     parent executes its transfer on that approval

Needs Foundry's anvil, Safe v1.4.1's release build (SAFE_141_BUILD, default: the main checkout's contracts/lib build),
Espressif's QEMU (QEMU=...) and the test image.

usage: signer/.venv/bin/python -I hardware/board-signer/tools/anvil_e2e.py TEST_IMAGE [OUT_DIR]
"""
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, os.path.join(ROOT, "signer"))
sys.path.insert(0, os.path.join(ROOT, "signer", "tools"))
sys.path.insert(0, HERE)

import devchain  # noqa: E402
from board_client import encode_tx  # noqa: E402
from qemu_flows import PIN, Qemu, confirm, key_line, pin_keys, setup  # noqa: E402
from winterlock_signer import abi, owner, safe as safemod  # noqa: E402
from winterlock_signer.abi import b2h, checksum  # noqa: E402
from winterlock_signer.ethtx import Account, send  # noqa: E402
from winterlock_signer.keccak import keccak256  # noqa: E402

SAFE_141 = os.environ.get("SAFE_141_BUILD", "/home/johba/winterlock.eth/contracts/lib/safe-smart-account-v1.4.1/build/forge-out")
BOB = checksum(keccak256(b"anvil e2e: recipient")[12:])
QUIET = dict(log=lambda *a: None)


def deploy_shared(rpc, acct):
    """The four shared contracts from the signer's pinned code, through the deterministic deployment proxy"""
    for salt, init in ((owner.VERIFIER_SALT, owner.VERIFIER_CREATION),
                       (owner.WOTS_VERIFIER_SALT, owner.WOTS_VERIFIER_CREATION),
                       (owner.IMPLEMENTATION_SALT, owner.implementation_init_code()),
                       (owner.FACTORY_SALT, owner.factory_init_code())):
        send(rpc, acct, owner.PROXY, salt + init, gas=30_000_000, **QUIET)
    for a in (owner.verifier_address(), owner.wots_verifier_address(), owner.implementation_address(),
              owner.factory_address()):
        assert rpc.code(a), f"nothing at {a}"


def safe_nonce(rpc, safe):
    return abi.dec_uint(rpc.eth_call(safe, abi.calldata("nonce()")))


def main():
    image = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(image), "anvil-e2e")
    os.makedirs(out, exist_ok=True)
    flash = os.path.join(out, "flash.bin")
    shutil.copyfile(image, flash)
    t0 = time.time()

    chain = devchain.Anvil()
    rpc, funder = chain.rpc, chain.account
    q = None
    try:
        cid = rpc.chain_id()
        deploy_shared(rpc, funder)
        release = devchain.safe_release(rpc, funder, build=SAFE_141)
        key_line(f"anvil chain {cid}: owner v2 contracts at the pinned addresses (factory {owner.factory_address()}); "
                 "Safe v1.4.1 deployed")

        # 1. setup on the board
        q = Qemu(flash, out, "e2e")
        q.board.wait_booted(120)
        words, ident, _ = setup(q, os.urandom(32))
        q.board.press("RR")
        owner_addr = checksum(ident["owner"])
        key = ident["member_key"]
        predicted = abi.dec_addr(rpc.eth_call(owner.factory_address(), abi.calldata("predict(bytes32)", ["bytes32"],
                                                                                     [key])))
        assert predicted == owner_addr, (predicted, owner_addr)
        send(rpc, funder, owner.factory_address(), abi.calldata("deploy(bytes32)", ["bytes32"], [key]), **QUIET)
        assert rpc.code(owner_addr)
        key_line(f"board set up; the factory deployed its owner at {owner_addr} (the address the board computed)")

        # 2. the gas account
        gas = Account(b2h(q.board.gas_key()))
        rpc.call("anvil_setBalance", [gas.address, hex(10**19)])
        key_line(f"gas key from the board: account {gas.address}, funded with 10 ETH on anvil")

        # the Safes: the board's owner alone; a parent owned by that Safe alone
        child, _ = devchain.create_safe(rpc, funder, release, [owner_addr], 1, salt_nonce=1, **QUIET)
        parent, _ = devchain.create_safe(rpc, funder, release, [child], 1, salt_nonce=2, **QUIET)
        for s in (child, parent):
            send(rpc, funder, s, b"", value=10**18, **QUIET)
        key_line(f"Safe {child} (1 of 1: the board's owner), parent Safe {parent} (1 of 1: that Safe), 1 ETH each")

        # 3. enrol
        start = safe_nonce(rpc, child)
        rid = q.board.enrol(cid, bytes.fromhex(child[2:]), start)
        confirm(q.board, rid)
        e = q.board.parse_enrolled(q.board.wait(rid, 900))
        q.board.press("R")
        cd = abi.calldata("enroll(address,uint8,bytes32,uint8,uint64,bytes)",
                          ["address", "uint8", "bytes32", "uint8", "uint64", "bytes"],
                          [child, 0, e["root"].ljust(32, b"\0"), e["height"], e["start"], e["signature"]])
        r = send(rpc, gas, owner_addr, cd, **QUIET)
        assert int(r["status"], 16) == 1
        root, _, height, tstart, _ = owner.read_tree(rpc, owner_addr, child, 0)
        assert (root, height, tstart) == (e["root"], 10, start)
        key_line(f"enrolled: the board's certificate accepted by the owner contract (enroll, {int(r['gasUsed'], 16):,} "
                 f"gas, paid by the gas account); tree root {b2h(root)} from nonce {tstart}")

        # 4. an ETH transfer, confirmed on the board, executed
        n = safe_nonce(rpc, child)
        tx = safemod.SafeTx(to=BOB, value=25 * 10**16, nonce=n)
        rid = q.board.sign(cid, bytes.fromhex(child[2:]), encode_tx(BOB, value=tx.value, nonce=n))
        pages, _ = confirm(q.board, rid)
        sg = q.board.parse_signed(q.board.wait(rid, 120))
        q.board.press("R")
        sigs = safemod.pack([(owner_addr, sg["data"], True)])
        before = rpc.balance(BOB)
        r = send(rpc, gas, child, tx.exec_calldata(sigs), **QUIET)
        assert int(r["status"], 16) == 1 and rpc.balance(BOB) - before == tx.value, "the transfer executed"
        assert safe_nonce(rpc, child) == n + 1
        key_line(f"ETH transfer: confirmed on the board ({' / '.join(p[0] for p in pages)}), executed with its "
                 f"signature alone: Bob +0.25 ETH, {int(r['gasUsed'], 16):,} gas")

        # 5. approveHash of the parent's transfer, with the parent's fields; then the parent executes
        pn = safe_nonce(rpc, parent)
        ptx = safemod.SafeTx(to=BOB, value=10**17, nonce=pn)
        ph = ptx.hash(cid, parent)
        n = safe_nonce(rpc, child)
        atx = safemod.SafeTx(to=parent, data=bytes.fromhex("d4d9bdcd") + ph, nonce=n)
        rid = q.board.sign(cid, bytes.fromhex(child[2:]), encode_tx(parent, data=atx.data, nonce=n),
                           parent=encode_tx(BOB, value=ptx.value, nonce=pn))
        pages, _ = confirm(q.board, rid)
        sg = q.board.parse_signed(q.board.wait(rid, 120))
        q.board.press("R")
        r = send(rpc, gas, child, atx.exec_calldata(safemod.pack([(owner_addr, sg["data"], True)])), **QUIET)
        assert int(r["status"], 16) == 1
        approved = abi.dec_uint(rpc.eth_call(parent, abi.calldata("approvedHashes(address,bytes32)",
                                                                  ["address", "bytes32"], [child, ph])))
        assert approved == 1, "the parent recorded the child's approval"
        # the approved-hash signature: r = the approving owner, s = 0, v = 1
        approval = bytes(12) + bytes.fromhex(child[2:]) + bytes(32) + b"\x01"
        before = rpc.balance(BOB)
        r = send(rpc, gas, parent, ptx.exec_calldata(approval), **QUIET)
        assert int(r["status"], 16) == 1 and rpc.balance(BOB) - before == ptx.value
        key_line(f"approveHash: the board showed the parent's transfer ({pages[1][0]}: {pages[1][2].strip()}); the "
                 f"approval executed, then the parent Safe executed its transfer on it: Bob +0.1 ETH")
        key_line(f"anvil end to end passed in {time.time() - t0:.0f} s")
    finally:
        if q is not None:
            q.kill()
        chain.close()


if __name__ == "__main__":
    main()
