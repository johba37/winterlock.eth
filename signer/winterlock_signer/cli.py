"""winterlock-signer: a minimal signer for the members of a Safe whose owners are Winterlock owner contracts (D13).

  init      create a signer (a new recovery phrase, checked), or --restore one from its phrase on a new device
  backup    show and check the recovery phrase;  passphrase: change the seed file's passphrase
  move      move to a new device while the old one works: start (new), export (old), import (new)
  device    adopt, or retire the key trees of, a key log that looks like a copy
  address   your owner address (the same on every chain) and stateless key
  enroll    certify a key tree (one-time keys for a range of nonces) for a Safe; creates your owner if needed
  propose   build, show and sign a Safe transaction, and post it to Safe's Transaction Service
  confirm   fetch a proposed transaction by its SafeTx hash, decode and show it, sign it, and post the confirmation
  queue     the Safe's pending transactions, decoded here, with your one-time keys used at each nonce
  execute   send execTransaction with the collected signatures, paid by a gas account
  connect   answer a dapp over WalletConnect as the team's Safe: transactions, batches and messages (bridge.py)
  message   sign a Safe message file another member collects for a dapp (peer to peer)
  status    your key trees and one-time keys left, the device and the recovery phrase's last check

Chain access: --chain (name or id) and --rpc URL (or WINTERLOCK_RPC). Service: Safe's hosted Transaction Service
for the chain (SAFE_API_KEY), --service URL, or --offline with --file for peer-to-peer proposal files. Gas account:
any funded account, not an owner; its private key in the environment variable named by --gas-key-env (default
WINTERLOCK_GAS_KEY). It pays for enroll and execute, and is never printed.
"""

import argparse
import json
import os
import sys
import time
from decimal import Decimal

from . import abi, owner, wots
from .abi import b2h, h2b
from .ethtx import Account, send
from .keylog import LogCorrupt, Refused
from .member import DEFAULT_HEIGHT, STATELESS_B, Member, default_home
from .rpc import Reverted, Rpc, RpcError, safe_url
from .safe import SAFE_TX_TYPEHASH, SafeTx, contract_signature, decode, eip712, pack, parse_signature
from .service import Service, ServiceError, default_url
from .keccak import keccak256

CHAINS = {"mainnet": 1, "ethereum": 1, "sepolia": 11155111, "base": 8453, "base-sepolia": 84532, "arbitrum": 42161,
          "optimism": 10, "gnosis": 100, "polygon": 137, "anvil": 31337}
CHAIN_NAMES = {1: "Ethereum", 11155111: "Sepolia", 8453: "Base", 84532: "Base Sepolia", 42161: "Arbitrum One",
               10: "OP Mainnet", 100: "Gnosis", 137: "Polygon", 31337: "local anvil"}
MAX_TX_GAS = 16_777_216  # EIP-7825
SUCCESS_TOPIC = b2h(keccak256(b"ExecutionSuccess(bytes32,uint256)"))
FAILURE_TOPIC = b2h(keccak256(b"ExecutionFailure(bytes32,uint256)"))
STATELESS_BUDGET = {10: 210_000}  # signatures at 128 bits (D11's Light tier)


class Abort(Exception):
    pass


_members = []


def open_member(args, lock=True) -> Member:
    m = Member(args.home, lock=lock)
    _members.append(m)
    return m


def out(*a):
    print(*a, flush=True)


# --- context ---

def chain_id_of(s: str, rpc_url: str = None) -> int:
    if s is None:
        hint = ""
        if rpc_url:  # the member's RPC knows its chain: name it, but don't pick it for them
            try:
                cid = Rpc(rpc_url, timeout=10).chain_id()
                name = next((n for n, i in CHAINS.items() if i == cid), str(cid))
                hint = f" Your RPC ({safe_url(rpc_url)}) is {chain_label(cid)}: --chain {name}."
            except (RpcError, OSError, ValueError):
                pass
        raise Abort("which chain is the Safe on? Add --chain with a name (" + ", ".join(sorted(set(CHAINS) - {
            "ethereum"})) + ") or a chain id, for example `--chain sepolia`." + hint)
    if s.isdigit():
        return int(s)
    if s.lower() not in CHAINS:
        raise Abort(f"unknown chain {s}: use a chain id or one of {', '.join(sorted(CHAINS))}")
    return CHAINS[s.lower()]


def chain_label(cid: int) -> str:
    return f"{CHAIN_NAMES.get(cid, 'chain')} (chain {cid})"


class Ctx:
    def __init__(self, args, need_rpc=True):
        self.args = args
        url = args.rpc or os.environ.get("WINTERLOCK_RPC")
        self.chain = chain_id_of(args.chain, url)
        self.rpc = None
        if url:
            self.rpc = Rpc(url)
            got = self.rpc.chain_id()
            if got != self.chain:
                raise Abort(f"the RPC at {safe_url(url)} is {chain_label(got)}, not {chain_label(self.chain)}: "
                            "refusing")
        elif need_rpc:
            raise Abort(f"no RPC for {chain_label(self.chain)}: add --rpc URL, or set WINTERLOCK_RPC to the chain's "
                        "JSON-RPC URL")
        self.service = None
        if not getattr(args, "offline", False):
            surl = getattr(args, "service", None) or os.environ.get("WINTERLOCK_SERVICE") or default_url(self.chain)
            if surl:
                self.service = Service(surl)

    def gas_account(self, required=True):
        name = self.args.gas_key_env
        key = os.environ.get(name)
        if not key:
            if required:
                raise Abort(f"no gas account: set {name} to a funded account's private key (it pays gas only)")
            return None
        return Account(key)


def safe_state(rpc, safe):
    if not rpc.code(safe):
        raise Abort(f"no contract at {safe} on this chain")
    nonce = abi.dec_uint(rpc.eth_call(safe, abi.calldata("nonce()")))
    threshold = abi.dec_uint(rpc.eth_call(safe, abi.calldata("getThreshold()")))
    owners = abi.dec_addresses(rpc.eth_call(safe, abi.calldata("getOwners()")))
    return nonce, threshold, owners


def confirm_prompt(args, question):
    if args.yes:
        return
    try:
        ans = input(f"{question} [y/N] ")
    except EOFError:
        ans = ""
    if ans.strip().lower() not in ("y", "yes"):
        raise Abort("not confirmed: nothing signed")


def parse_value(s: str) -> int:
    s = (s or "0").strip().lower()
    if s.endswith("wei"):
        return int(s[:-3])
    v = Decimal(s.removesuffix("eth")) * 10**18
    if v != v.to_integral_value():
        raise Abort("value has more than 18 decimals")
    return int(v)


# --- shared checks before a transaction signature ---

TAKEN_OVER = ("another device has taken over this owner on this Safe: the Safe holds a newer key tree (root {root}, "
              "from nonce {start}) that this signer didn't make, after a restore or a move on another device. Stop "
              "using this device for this Safe.")


def taken_over(m: Member, chain: int, safe: str, root, start: int) -> bool:
    """Whether another device has taken over this member on this Safe: the enrolled tree isn't in this key log, and
    it is newer than every tree this key log made for the Safe. A key log with no tree for the Safe (a fresh restore)
    isn't taken over: certifying a fresh tree is its next step."""
    if root is None or m.log.tree_by_root(chain, safe, b2h(root)):
        return False
    mine = m.log.trees(chain, safe)
    return bool(mine) and max(t["start"] for t in mine) < start


def signing_tree(m: Member, ctx: Ctx, safe: str):
    """The key log's record of the tree enrolled on-chain for this member and Safe, or Refused"""
    if not owner_deployed(ctx, m):
        raise Refused(f"your owner {m.owner} doesn't exist on this chain yet: run `enroll` (it creates it)")
    root, _, height, start = owner.read_tree(ctx.rpc, m.owner, safe)
    mine = m.log.trees(ctx.chain, safe)
    if root is None:
        raise Refused("no key tree is enrolled for you on this Safe: run `enroll`" +
                      (" (a key tree is waiting for its enrolment)" if mine else ""))
    rec = m.log.tree_by_root(ctx.chain, safe, b2h(root))
    if rec is None and taken_over(m, ctx.chain, safe, root, start):
        raise Refused(TAKEN_OVER.format(root=b2h(root), start=start))
    if rec is None:
        if mine and max(t["start"] for t in mine) > start:
            raise Refused("your newest key tree isn't enrolled yet: run `enroll` to send its certificate")
        raise Refused(f"the key tree enrolled for you (root {b2h(root)}, from nonce {start}) isn't in this signer's "
                      "key log: it was made by another device or before a restore. This signer never reuses a key "
                      "tree it doesn't have a log for: run `enroll` to certify a fresh one from the current nonce.")
    if rec["start"] != start or rec["height"] != height:
        raise Refused("the enrolled key tree's start or height differs from the key log: refusing")
    return rec


def key_words(slot: int, nonce: int = None) -> str:
    """Which of the member's two one-time keys for a nonce a slot is, in words (D4: the first signs; the second is
    kept for a replacement or a cancellation at the same nonce)"""
    at = "this nonce" if nonce is None else f"nonce {nonce}"
    return f"your first of two keys for {at}" if slot == 0 else f"your second and last key for {at}"


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}" + ("" if n == 1 else "s")


def stale_log_check(m: Member, ctx: Ctx, safe: str, rec: dict, at_nonce: list):
    """Refuses if the service shows a signature by this member's current tree that the key log doesn't know: the
    log is stale (an old copy restored, or another device signing with the same log)"""
    root = h2b(rec["root"])
    seed = owner.tree_seed(ctx.chain, rec["owner"], safe, rec["start"])
    for tx in at_nonce:
        for c in tx.get("confirmations") or []:
            if (c.get("owner") or "").lower() != m.owner.lower() or not c.get("signature"):
                continue
            try:
                _, data, is_contract = parse_signature(h2b(c["signature"]))
            except ValueError:
                continue
            parsed = owner.parse_tx_signature_data(data) if is_contract else None
            if not parsed:
                continue
            slot, sig_safe, words, sig, path = parsed
            nonce = int.from_bytes(words[9], "big")
            try:
                k = owner.key_index(nonce, rec["start"], slot, rec["height"])
            except ValueError:
                continue
            h = eip712(ctx.chain, sig_safe, keccak256(SAFE_TX_TYPEHASH + b"".join(words)))
            if wots.verify_root(seed, k, h, sig, path) != root:
                continue  # another tree's signature (before a rotation or a restore)
            logged = m.log.used(ctx.chain, safe, rec["root"], k)
            if not logged or logged["hash"] != b2h(h):
                raise Refused(f"the Transaction Service shows your signature with one-time key {k}, "
                              f"{key_words(slot, nonce)} (slot {slot}), for {b2h(h)}, which the key log doesn't "
                              "record: the key log is stale. Stop using this copy; run `enroll --rotate` to continue "
                              "with a fresh key tree.")


def show_tx(m, ctx, safe, t: SafeTx, h: bytes, safe_nonce, threshold, owners, rec=None, slot=None, k=None,
            reused=False, existing=None):
    lines, warnings = decode(t, safe)
    out(f"Safe         {safe} on {chain_label(ctx.chain)}, {threshold} of {len(owners)} owners, "
        f"next nonce on-chain {safe_nonce}")
    out(f"Transaction  nonce {t.nonce}" + (" (next to execute)" if t.nonce == safe_nonce else
                                         f" ({t.nonce - safe_nonce} after the next)"))
    for line in lines:
        out(f"  {line}")
    out(f"  operation {'DELEGATECALL' if t.operation else 'call'}, to {t.to}, value {t.value:,} wei, "
        f"data {len(t.data)} bytes" + (f" {b2h(t.data)}" if 0 < len(t.data) <= 100 else ""))
    out(f"  SafeTx hash {b2h(h)} (computed here)")
    for w in warnings:
        out(f"  WARNING: {w}")
    if existing:
        for x in existing:
            if x.get("safeTxHash", "").lower() != b2h(h).lower():
                out(f"  also at nonce {t.nonce}: {x.get('safeTxHash')} "
                    f"({plural(len(x.get('confirmations') or []), 'signature')}); only one of them can execute")
    if rec is not None:
        end = rec["start"] + owner.capacity(rec["height"]) - 1
        out(f"Key          one-time key {k}: {key_words(slot, t.nonce)} (slot {slot}); key tree {rec['root'][:18]}… "
            f"(nonces {rec['start']}–{end})")
        if reused:
            out("             you already signed this exact transaction with it: the same signature again")
        elif slot == 1:
            out("             kept for a replacement or cancellation: no third version can be signed at this nonce")
    return warnings


def prepare(m: Member, ctx: Ctx, safe: str, t: SafeTx, expect_hash: bytes = None):
    safe = abi.address(safe)
    safe_nonce, threshold, owners = safe_state(ctx.rpc, safe)
    if m.owner.lower() not in [o.lower() for o in owners]:
        raise Refused(f"your owner {m.owner} is not an owner of {safe}")
    if t.nonce < safe_nonce:
        raise Refused(f"nonce {t.nonce} is already used (the Safe is at nonce {safe_nonce})")
    h = t.hash(ctx.chain, safe)
    if expect_hash is not None and h != expect_hash:
        raise Refused(f"the fields hash to {b2h(h)}, not {b2h(expect_hash)}: refusing")
    onchain = abi.dec_word(ctx.rpc.eth_call(safe, t.get_transaction_hash_calldata()))
    if onchain != h:
        raise Refused(f"the Safe computes {b2h(onchain)} for these fields, not {b2h(h)}: refusing")
    rec = signing_tree(m, ctx, safe)
    owner.key_index(t.nonce, rec["start"], 0, rec["height"])  # in range, or ValueError
    at_nonce = []
    if ctx.service:
        try:
            at_nonce = ctx.service.at_nonce(safe, t.nonce)
        except ServiceError as e:
            out(f"  (service: {e}; the stale-log check is skipped)")
        stale_log_check(m, ctx, safe, rec, at_nonce)
    else:
        out("  (offline: no service to check this key log against other copies' signatures)")
    slot, reused = m.log.pick_slot(ctx.chain, safe, rec, t.nonce, b2h(h))
    k = owner.key_index(t.nonce, rec["start"], slot, rec["height"])
    show_tx(m, ctx, safe, t, h, safe_nonce, threshold, owners, rec, slot, k, reused, at_nonce)
    return safe, h, rec, slot


def sign_and_check(m, ctx, safe, t, rec, slot, h):
    out("Steps        record the key's use -> sign -> check -> send")
    data, slot2, k, h2 = m.sign_safe_tx(ctx.chain, safe, rec, t, slot)
    assert slot2 == slot and h2 == h
    out(f"  key log saved to disk first; signed with one-time key {k} ({len(data):,} bytes of signature data)")
    if not owner.is_valid_signature(ctx.rpc, m.owner, h, data):
        raise Abort("your owner contract refuses the signature (eth_call): not sending")
    out("  your owner contract accepts it (isValidSignature, by eth_call)")
    return data


# --- proposal files (peer to peer, and the offline mode) ---

def load_file(path):
    with open(path) as f:
        return json.load(f)


def save_file(path, doc):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def add_file_signature(doc, owner_addr, sig_hex):
    doc["signatures"] = [s for s in doc.get("signatures", []) if s["owner"].lower() != owner_addr.lower()]
    doc["signatures"].append({"owner": owner_addr, "signature": sig_hex})


# --- commands ---

def cmd_init(args):
    """New signers, restores and moves: cli_recovery.py"""
    from . import cli_recovery
    return cli_recovery.cmd_init(args)


def shared_contracts():
    """(name, address, salt, init code) of the contracts deployed once per chain, in deployment order"""
    return [("stateless verifier", owner.verifier_address(), owner.VERIFIER_SALT, owner.VERIFIER_CREATION),
            ("WinterlockOwner implementation", owner.implementation_address(), owner.IMPLEMENTATION_SALT,
             owner.implementation_init_code()),
            ("owner factory", owner.factory_address(), owner.FACTORY_SALT, owner.factory_init_code())]


def owner_deployed(ctx, m) -> bool:
    """Whether the member's owner exists; refuses if the code at its address isn't the member's proxy of the pinned
    implementation (77 bytes: the ERC-1167 proxy and the key)"""
    code = ctx.rpc.code(m.owner)
    if not code:
        return False
    if code != owner.proxy_runtime(owner.implementation_address(), m.key):
        raise Refused(f"the code at your owner address {m.owner} isn't your proxy of the implementation "
                      f"{owner.implementation_address()} ({len(code)} bytes): refusing")
    return True


def cmd_address(args):
    m = open_member(args, lock=False)
    out(f"owner address    {m.owner}  (your owner contract, the same on every chain: list it in the Safe)")
    out(f"stateless key    {b2h(m.key)}")
    budget = STATELESS_BUDGET.get(STATELESS_B)
    out("parameters       one-time keys: WOTS, D6 (n = 24, w = 16, target sum 431, keccak); stateless key: "
        f"leanSphincs, kept subtree of height {STATELESS_B}" + (f" (about {budget:,} signatures)" if budget else ""))
    for label, (_, addr, _, _) in zip(("verifier", "implementation", "factory"), shared_contracts()):
        out(f"{label:17}{addr}")
    out(f"contract code    pinned at {owner.PINNED_COMMIT}")
    if args.chain and (args.rpc or os.environ.get("WINTERLOCK_RPC")):
        ctx = Ctx(args)
        state = "deployed" if owner_deployed(ctx, m) else "not deployed"
        shared = ", ".join(f"{name} {'deployed' if ctx.rpc.code(addr) else 'not deployed'}"
                           for name, addr, _, _ in shared_contracts())
        out(f"on {chain_label(ctx.chain)}: your owner {state}; {shared}")


def _deploy(ctx, gas, name, salt, init_code):
    """One contract through the deterministic deployment proxy, with a gas limit from the node's own estimate (it prices
    by the chain's rules, Glamsterdam's included), under EIP-7825's cap"""
    addr = owner.create2(salt, init_code)
    if ctx.rpc.code(addr):
        return addr
    data = salt + init_code
    est = ctx.rpc.estimate_gas(gas.address, owner.PROXY, data)
    if est > MAX_TX_GAS:
        raise Abort(f"{name}: the node estimates {est:,} gas, over the {MAX_TX_GAS:,} transaction cap")
    limit = min(int(est * 1.2), MAX_TX_GAS)
    out(f"  {name}: deploying at {addr} through the deterministic deployment proxy (estimate {est:,} gas)")
    confirm_prompt(ctx.args, f"Deploy the {name} from {gas.address}?")
    r = send(ctx.rpc, gas, owner.PROXY, data, gas=limit, log=out)
    if not ctx.rpc.code(addr):
        raise Abort(f"{name}: no code at {addr} after {r['transactionHash']}")
    out(f"  {name}: deployed, gas used {int(r['gasUsed'], 16):,}, tx {r['transactionHash']}")
    return addr


def deploy_shared(ctx, gas):
    """Once per chain, for every member and team: the verifier, the implementation and the factory, each unless it
    exists, in order (each estimate needs the one before deployed)"""
    for name, _, salt, init_code in shared_contracts():
        _deploy(ctx, gas, name, salt, init_code)
    impl, factory = owner.implementation_address(), owner.factory_address()
    if abi.dec_addr(ctx.rpc.eth_call(factory, abi.calldata("IMPLEMENTATION()"))) != impl or \
            abi.dec_addr(ctx.rpc.eth_call(impl, abi.calldata("IMPLEMENTATION()"))) != impl:
        raise Abort("the factory or the implementation on this chain isn't the pinned one: refusing")


def _owner_views(ctx, m, safe, rec):
    """The deployed owner's own tree seed and certificate digest for `rec`"""
    seed = abi.dec_uint(ctx.rpc.eth_call(m.owner, abi.calldata("treeSeed(address,uint64)", ["address", "uint256"],
                                                                [safe, rec["start"]])))
    digest = abi.dec_word(ctx.rpc.eth_call(m.owner, abi.calldata(
        "certificateDigest(address,bytes32,uint8,uint64)", ["address", "bytes32", "uint256", "uint256"],
        [safe, owner.root_word(h2b(rec["root"])), rec["height"], rec["start"]])))
    return seed, digest


def cmd_enroll(args):
    m = open_member(args)
    ctx = Ctx(args)
    safe = abi.address(args.safe)
    deployed = owner_deployed(ctx, m)
    gas = ctx.gas_account(required=False)
    if not deployed:
        missing = [name for name, addr, _, _ in shared_contracts() if not ctx.rpc.code(addr)]
        if missing:
            if not args.deploy:
                raise Abort(f"not on this chain yet: {', '.join(missing)}. Add --deploy to deploy them once for the "
                            "chain (every member and team shares them; under Glamsterdam pricing the implementation "
                            "takes about 11.6M gas and the factory 2.7M), or have someone deploy them")
            if gas is None:
                gas = ctx.gas_account()
            deploy_shared(ctx, gas)
        predicted = abi.dec_addr(ctx.rpc.eth_call(owner.factory_address(), abi.calldata(
            "predict(bytes32)", ["bytes32"], [m.key])))
        if predicted != m.owner:
            raise Abort(f"the factory predicts {predicted} for your key, not {m.owner}: refusing")
        out(f"Your owner {m.owner} doesn't exist yet: the factory creates it and enrols its first key tree in one "
            "transaction (deployAndEnroll)")
    elif abi.dec_word(ctx.rpc.eth_call(m.owner, abi.calldata("KEY()"))) != m.key:
        raise Abort("the contract at your owner address has another KEY: refusing")
    safe_nonce, threshold, owners = safe_state(ctx.rpc, safe)
    is_owner = m.owner.lower() in [o.lower() for o in owners]
    root, height, start = None, 0, 0
    if deployed:
        root, _, height, start = owner.read_tree(ctx.rpc, m.owner, safe)
    out(f"Safe {safe} on {chain_label(ctx.chain)}: nonce {safe_nonce}, {threshold} of {len(owners)}"
        + ("" if is_owner else f"; your owner {m.owner} is NOT one of its owners yet (enrolling first is fine)"))
    out("Key tree enrolled for you: " + (f"root {b2h(root)}, nonces {start}–{start + owner.capacity(height) - 1}"
                                         if root else "none"))
    if taken_over(m, ctx.chain, safe, root, start):
        msg = TAKEN_OVER.format(root=b2h(root), start=start)
        if not args.take_over:
            raise Refused(msg + " Enrolling here would retire that device's key tree, and its approvals would stop "
                          "counting. Only if that device is gone for good: `enroll --take-over`.")
        out(f"WARNING: {msg}")
        out("--take-over: a fresh key tree here retires that device's. If that device still signs, its approvals stop "
            "counting; if it's in someone else's hands, a fresh key tree doesn't help: the team replaces this owner.")
        confirm_prompt(args, "Take over from the other device?")
    if root is not None and m.log.tree_by_root(ctx.chain, safe, b2h(root)) and not args.rotate:
        out("Already enrolled with a key tree from this signer's key log; nothing to do (--rotate starts a new one).")
        return
    latest = m.active_tree(ctx.chain, safe)
    if latest and not args.rotate and (root is None or latest["start"] > start):
        # made before but its enrolment never landed: send the same tree again
        rec = latest
        out(f"Resending the certificate of this signer's newest key tree (from nonce {rec['start']}), not yet "
            "enrolled")
    else:
        # start sequences only grow on-chain, and this signer never makes two trees with one start
        new_start = max([safe_nonce] + ([start + 1] if root is not None else [])
                        + [t["start"] + 1 for t in m.log.trees(ctx.chain, safe)])
        if root is not None:
            out("A fresh key tree replaces the enrolled one. Confirmations already given with the old one for "
                "pending nonces stop counting; members confirm those again.")
        if args.height < 1:
            raise Abort("--height is at least 1: a key tree covers 2^(height-1) nonces")
        end = new_start + owner.capacity(args.height) - 1
        confirm_prompt(args, f"Make a fresh key tree for nonces {new_start}–{end} (height {args.height})?")
        t0 = time.time()
        rec = m.new_tree(ctx.chain, safe, new_start, args.height)
        out(f"New key tree: root {rec['root']}, nonces {new_start}–{end} (height {rec['height']}; "
            f"{time.time() - t0:.1f} s; key log saved)")
    # tree seed and certificate digest, offline, for the owner's address (predicted when it doesn't exist yet)
    seed = owner.tree_seed(ctx.chain, m.owner, safe, rec["start"])
    digest = owner.certificate_digest(ctx.chain, m.owner, safe, h2b(rec["root"]), rec["height"], rec["start"])
    if deployed and _owner_views(ctx, m, safe, rec) != (seed, digest):
        raise Abort("your owner derives another tree seed or certificate digest: refusing to sign")
    t0 = time.time()
    cert = m.certificate(rec)
    out(f"Certificate: your stateless key signed {b2h(digest)} ({len(cert):,} bytes, {time.time() - t0:.1f} s), "
        f"for {'your owner' if deployed else 'your predicted owner'} {m.owner}")
    if deployed:
        target, cd = m.owner, owner.enroll_calldata(safe, h2b(rec["root"]), rec["height"], rec["start"], cert)
    else:
        target = owner.factory_address()
        cd = owner.deploy_and_enroll_calldata(m.key, safe, h2b(rec["root"]), rec["height"], rec["start"], cert)
    what = "enroll" if deployed else "deployAndEnroll"
    if gas is None:
        path = args.out or f"enroll-{ctx.chain}-{safe}.calldata"
        with open(path, "w") as f:
            f.write(b2h(cd) + "\n")
        out(f"No gas account: wrote the {what} calldata for {target} to {path} ({len(cd):,} bytes); anyone may send it")
        return
    try:
        ret = ctx.rpc.eth_call(target, cd, sender=gas.address)
    except Reverted as e:
        raise Abort(f"{what} would revert: {e}") from None
    if not deployed and abi.dec_addr(ret) != m.owner:
        raise Abort("deployAndEnroll would create another owner: refusing")
    confirm_prompt(args, f"Send {what} from {gas.address}?")
    r = send(ctx.rpc, gas, target, cd, log=out)
    # cross-check against the owner as it now exists
    if not owner_deployed(ctx, m):
        raise Abort(f"{what} was mined but there is no owner at {m.owner}")
    if abi.dec_word(ctx.rpc.eth_call(m.owner, abi.calldata("KEY()"))) != m.key:
        raise Abort("the new owner reads another KEY")
    if _owner_views(ctx, m, safe, rec) != (seed, digest):
        raise Abort("the owner derives another tree seed or certificate digest than this signer did offline")
    root2, seed2, _, start2 = owner.read_tree(ctx.rpc, m.owner, safe)
    if b2h(root2 or b"") != rec["root"] or start2 != rec["start"] or seed2 != seed:
        raise Abort(f"{what} was mined but the stored tree differs")
    out(f"Enrolled{'' if deployed else ' (owner created)'}: gas used {int(r['gasUsed'], 16):,}, "
        f"tx {r['transactionHash']}")


def cmd_propose(args):
    m = open_member(args)
    ctx = Ctx(args)
    safe = abi.address(args.safe)
    safe_nonce = abi.dec_uint(ctx.rpc.eth_call(safe, abi.calldata("nonce()")))
    nonce = args.nonce
    if nonce is None:
        if args.cancel:
            raise Abort("--cancel needs --nonce: the nonce of the transaction to cancel")
        nonce = safe_nonce
        if ctx.service:
            try:
                pending = ctx.service.pending(safe, safe_nonce)
                nonce = max([safe_nonce] + [int(x["nonce"]) + 1 for x in pending])
            except ServiceError as e:
                out(f"  (service: {e}; using the on-chain nonce)")
    if args.cancel:
        t = SafeTx(to=safe, nonce=nonce)
    else:
        if not args.to:
            raise Abort("--to is required (or --cancel)")
        if args.operation == 1 and not args.allow_delegatecall:
            raise Abort("operation 1 (delegatecall) needs --allow-delegatecall")
        t = SafeTx(to=abi.address(args.to), value=parse_value(args.value), data=h2b(args.data or "0x"),
                   operation=args.operation, nonce=nonce)
    safe, h, rec, slot = prepare(m, ctx, safe, t)
    confirm_prompt(args, "Sign and propose this transaction?")
    data = sign_and_check(m, ctx, safe, t, rec, slot, h)
    sig = contract_signature(m.owner, data)
    if args.out or not ctx.service:
        path = args.out or f"safetx-{b2h(h)[:12]}.json"
        doc = {"chain": ctx.chain, "safe": safe, "safeTx": t.to_json(), "safeTxHash": b2h(h), "signatures": []}
        add_file_signature(doc, m.owner, b2h(sig))
        save_file(path, doc)
        out(f"  wrote {path}: send it to the other members (confirm --file)")
    if ctx.service:
        status, resp = ctx.service.propose(safe, t, b2h(h), m.owner, b2h(sig))
        out(f"  POST proposal -> HTTP {status}" + ("" if status in (200, 201) else f": {str(resp)[:400]}"))
        if status not in (200, 201):
            raise Abort("the service didn't accept the proposal (your key use stays recorded)")
    out(f"Proposed {b2h(h)} at nonce {t.nonce}, signed with {key_words(slot)}")


def safe_tx_hash_arg(args):
    """The SafeTx hash given after the command or with --safe-tx-hash (if both, the same one), checked; None with
    --file and no hash. Checked before anything is read from the chain or the service."""
    given = [x for x in (args.hash, args.safe_tx_hash) if x]
    if len({x.lower() for x in given}) > 1:
        raise Abort(f"two different SafeTx hashes: {args.hash} and --safe-tx-hash {args.safe_tx_hash}. Give one.")
    if not given:
        if args.file:
            return None
        raise Abort(f"which proposal? Give its SafeTx hash, as in `{args.cmd} --chain {args.chain or 'sepolia'} "
                    "0x…` (`queue` lists them), or --file with a proposal file")
    try:
        h = h2b(given[0])
    except ValueError:
        h = b""
    if len(h) != 32:
        raise Abort(f"{given[0]} isn't a whole SafeTx hash (0x and 64 hex digits): `queue` lists them in full")
    return h


def _load_proposal(ctx, args, want):
    """(safe, SafeTx, hash, service record or file doc) for the hash `want` (safe_tx_hash_arg) or args.file"""
    if args.file:
        doc = load_file(args.file)
        if doc["chain"] != ctx.chain:
            raise Abort(f"{args.file} is for {chain_label(doc['chain'])}, not {chain_label(ctx.chain)}")
        if want is not None and h2b(doc["safeTxHash"]) != want:
            raise Abort(f"{args.file} holds the proposal {doc['safeTxHash']}, not {b2h(want)}")
        t = SafeTx.from_json(doc["safeTx"])
        return abi.address(doc["safe"]), t, h2b(doc["safeTxHash"]), doc
    if not ctx.service:
        raise Abort("no Transaction Service for this chain: use --file with a proposal file")
    rec = ctx.service.transaction(b2h(want))
    t = SafeTx.from_json(rec)
    return abi.address(rec["safe"]), t, want, rec


def cmd_confirm(args):
    want = safe_tx_hash_arg(args)
    m = open_member(args)
    ctx = Ctx(args)
    safe, t, h, src = _load_proposal(ctx, args, want)
    if t.hash(ctx.chain, safe) != h:
        raise Refused(f"the proposal's fields hash to {b2h(t.hash(ctx.chain, safe))}, not {b2h(h)}: refusing")
    have = src.get("confirmations") or src.get("signatures") or []
    out(f"Proposal {b2h(h)}" + (f", proposed by {src.get('proposer')}" if src.get("proposer") else "")
        + f", {plural(len(have), 'signature')} so far: " + ", ".join(c.get("owner", "?") for c in have))
    safe, h, rec, slot = prepare(m, ctx, safe, t, expect_hash=h)
    confirm_prompt(args, "Sign this transaction?")
    data = sign_and_check(m, ctx, safe, t, rec, slot, h)
    sig = contract_signature(m.owner, data)
    if args.file:
        add_file_signature(src, m.owner, b2h(sig))
        save_file(args.file, src)
        out(f"  added your signature to {args.file}")
    else:
        status, resp = ctx.service.confirm(b2h(h), b2h(sig))
        out(f"  POST confirmation -> HTTP {status}" + ("" if status in (200, 201) else f": {str(resp)[:400]}"))
        if status not in (200, 201):
            raise Abort("the service didn't accept the confirmation (your key use stays recorded)")
    out(f"Confirmed {b2h(h)} at nonce {t.nonce}, signed with {key_words(slot)}")


def cmd_queue(args):
    m = open_member(args, lock=False)
    ctx = Ctx(args)
    safe = abi.address(args.safe)
    safe_nonce, threshold, owners = safe_state(ctx.rpc, safe)
    if args.file:
        doc = load_file(args.file)
        txs = [dict(doc["safeTx"], safeTxHash=doc["safeTxHash"], confirmations=doc.get("signatures", []))]
    elif ctx.service:
        txs = ctx.service.pending(safe, safe_nonce)
    else:
        raise Abort("no service for this chain: use --file")
    out(f"Safe {safe} on {chain_label(ctx.chain)}: next nonce {safe_nonce}, {threshold} of {len(owners)}; "
        f"{len(txs)} pending")
    rec = None
    try:
        rec = signing_tree(m, ctx, safe)
    except Refused as e:
        out(f"  (you: {e})")
    for x in txs:
        t = SafeTx.from_json(x)
        h = t.hash(ctx.chain, safe)
        ok = b2h(h).lower() == (x.get("safeTxHash") or "").lower()
        lines, warnings = decode(t, safe)
        confs = x.get("confirmations") or []
        mine = [c for c in confs if (c.get("owner") or "").lower() == m.owner.lower()]
        out(f"- nonce {t.nonce}  {b2h(h)}" + ("" if ok else "  HASH MISMATCH: the service's hash differs"))
        for line in lines:
            out(f"    {line}")
        for w in warnings:
            out(f"    WARNING: {w}")
        out(f"    signatures {len(confs)} of {threshold}: " + ", ".join(c.get("owner", "?") for c in confs))
        if rec:
            used = {}
            for slot in (0, 1):
                try:
                    k = owner.key_index(t.nonce, rec["start"], slot, rec["height"])
                except ValueError:
                    continue
                r = m.log.used(ctx.chain, safe, rec["root"], k)
                used[slot] = r["hash"] if r else None
            state = ", ".join(("first " if s == 0 else "second ") + (
                "unused" if v is None else "signed this one" if v.lower() == b2h(h).lower() else
                "signed another version") for s, v in used.items())
            out(f"    you: {'signed' if mine else 'not signed'}; "
                + (f"your two keys for this nonce: {state}" if used else "this nonce is outside your key tree"))


def cmd_execute(args):
    want = safe_tx_hash_arg(args)
    ctx = Ctx(args)
    safe, t, h, src = _load_proposal(ctx, args, want)
    if t.hash(ctx.chain, safe) != h:
        raise Refused("the proposal's fields don't hash to its SafeTx hash: refusing")
    safe_nonce, threshold, owners = safe_state(ctx.rpc, safe)
    if t.nonce != safe_nonce:
        raise Abort(f"the Safe is at nonce {safe_nonce}; this transaction has nonce {t.nonce}")
    show_tx(None, ctx, safe, t, h, safe_nonce, threshold, owners)
    sigs = []
    for c in src.get("confirmations") or src.get("signatures") or []:
        try:
            o, data, is_contract = parse_signature(h2b(c["signature"]))
        except (ValueError, KeyError):
            continue
        o = o or abi.address(c["owner"])
        if o.lower() not in [x.lower() for x in owners]:
            continue
        if is_contract and not owner.is_valid_signature(ctx.rpc, o, h, data):
            out(f"  {o}: signature refused by its owner contract (another tree, or not enrolled): skipped")
            continue
        sigs.append((o, data, is_contract))
    out(f"Signatures: {len(sigs)} valid of {threshold} needed: " + ", ".join(s[0] for s in sigs))
    if len(sigs) < threshold:
        raise Abort("not enough valid signatures")
    blob = pack(sorted(sigs, key=lambda s: int(s[0], 16))[:threshold])
    gas = ctx.gas_account()
    cd = t.exec_calldata(blob)
    try:
        ok = abi.dec_uint(ctx.rpc.eth_call(safe, cd, sender=gas.address))
    except Reverted as e:
        raise Abort(f"execTransaction would revert: {e}") from None
    if not ok:
        raise Abort("execTransaction would return false")
    confirm_prompt(args, f"Execute from {gas.address} (pays the gas)?")
    r = send(ctx.rpc, gas, safe, cd, log=out)
    # ExecutionSuccess / ExecutionFailure(bytes32 indexed txHash, uint256 payment) in v1.4.1 (not indexed in v1.3.0)
    logs = [lg for lg in r["logs"] if lg["address"].lower() == safe.lower()
            and b2h(h)[2:].lower() in "".join(lg["topics"][1:]).lower() + lg["data"].lower()]
    if any(lg["topics"][0] == FAILURE_TOPIC for lg in logs):
        raise Abort(f"executed, but the inner call failed (ExecutionFailure): {r['transactionHash']}")
    if not any(lg["topics"][0] == SUCCESS_TOPIC for lg in logs):
        raise Abort(f"no ExecutionSuccess event in {r['transactionHash']}")
    out(f"Executed nonce {t.nonce}: gas used {int(r['gasUsed'], 16):,}, {len(blob):,} bytes of signatures, "
        f"tx {r['transactionHash']}")


def cmd_status(args):
    from . import cli_recovery
    if cli_recovery.pending_move_status(args):  # a new device waiting for a move's bundle: no key log to open yet
        return
    m = open_member(args, lock=False)
    out(f"Signer {m.home}")
    out(f"  owner {m.owner}, stateless key {b2h(m.key)}")
    for line in cli_recovery.status_lines(m):
        out(line)
    ident = m.log.identity()
    if ident and ident["t"] == "restore":
        out(f"  restored from the recovery phrase on {ident['at']}: the old device's key trees are never used")
    certs = len(m.log.certs())
    certs += sum(1 for r in m.log.records if r["t"] == "msg")  # message signatures (bridge.py)
    budget = STATELESS_BUDGET.get(STATELESS_B)
    out(f"  stateless key: {plural(certs, 'signature')} so far (key tree certificates, messages)"
        + (f", of about {budget:,} it can safely make" if budget else ""))
    for w in m.log.warnings:
        out(f"  WARNING: {w}")
    ctx = None
    if args.chain and (args.rpc or os.environ.get("WINTERLOCK_RPC")):
        ctx = Ctx(args)
    groups = {}
    for r in m.log.all_trees():
        groups.setdefault((r["chain"], r["safe"]), []).append(r)
    if not groups:
        out("  no key trees yet: run `enroll --chain CHAIN --safe SAFE` for each Safe")
    for (chain, safe), trees in groups.items():
        if args.safe and safe.lower() != args.safe.lower():
            continue
        out(f"Safe {safe} on {chain_label(chain)}")
        onchain = safe_nonce = None
        if ctx and ctx.chain == chain:
            try:
                onchain = owner.read_tree(ctx.rpc, m.owner, safe)
                safe_nonce = abi.dec_uint(ctx.rpc.eth_call(safe, abi.calldata("nonce()")))
            except (RpcError, ValueError) as e:
                out(f"  (chain: {e})")
        for r in trees:
            cap = owner.capacity(r["height"])
            signs = m.log.signs(chain, safe, r["root"])
            spare = sum(1 for s in signs if s["slot"] == 1)
            last = max((s["nonce"] for s in signs), default=None)
            state = ""
            if onchain is not None:
                if onchain[0] is not None and b2h(onchain[0]) == r["root"]:
                    state = " ENROLLED"
                elif r is not trees[-1]:
                    state = " retired"
                elif onchain[0] is None:
                    state = " not enrolled yet"
                elif taken_over(m, chain, safe, onchain[0], onchain[3]):
                    state = " REPLACED (another device enrolled a newer key tree)"
                else:
                    state = " not enrolled (the Safe has another key tree for this owner)"
            if m.log.retired(r):
                state += " RETIRED HERE (never signs again: `enroll` certifies a fresh key tree)"
            used = "no one-time key used yet"
            if signs:
                used = (f"{plural(len(signs), 'one-time key')} used"
                        + (f" ({spare} for a replacement or cancellation)" if spare else "")
                        + f", last at nonce {last}")
            out(f"  key tree {r['root'][:18]}… for nonces {r['start']}–{r['start'] + cap - 1} (height {r['height']})"
                f"{state}: {used}")
            if safe_nonce is not None and state == " ENROLLED":
                left = r["start"] + cap - max(safe_nonce, r["start"])
                used_pct = 100 * (cap - left) / cap
                out(f"    the Safe is at nonce {safe_nonce}: {left} of {cap} nonces left in this key tree "
                    f"({used_pct:.0f}% used)" + ("  -> rotate soon: `enroll --rotate`" if used_pct >= 80 else ""))
        if onchain is not None and taken_over(m, chain, safe, onchain[0], onchain[3]):
            out("  WARNING: " + TAKEN_OVER.format(root=b2h(onchain[0])[:18] + "…", start=onchain[3]) + " If that "
                "device is gone for good, `enroll --take-over` certifies a fresh key tree here.")
        elif onchain is not None and onchain[0] is not None and not m.log.tree_by_root(chain, safe, b2h(onchain[0])):
            out(f"  WARNING: the enrolled key tree {b2h(onchain[0])[:18]}… isn't in this key log: another device signs "
                "for this owner (after a move or a restore). If that device is your signer now, stop using this one. "
                "If this one is, `enroll` certifies a fresh key tree here, and the other device's approvals stop "
                "counting.")


# --- argument parsing ---

def build_parser():
    p = argparse.ArgumentParser(prog="winterlock-signer", description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("--home", default=None, help=f"signer directory (default {default_home()}, or WINTERLOCK_HOME)")
    p.add_argument("--yes", "-y", action="store_true", help="don't ask for confirmation")
    sub = p.add_subparsers(dest="cmd", required=True)
    _add = sub.add_parser

    def add_parser(name, **kw):  # --home and --yes also after the command
        sp = _add(name, **kw)
        sp.add_argument("--home", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        sp.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        return sp

    sub.add_parser = add_parser

    def chain_opts(sp, service=True):
        sp.add_argument("--chain", help="chain name or id, e.g. sepolia")
        sp.add_argument("--rpc", help="JSON-RPC URL (or WINTERLOCK_RPC)")
        sp.add_argument("--gas-key-env", default="WINTERLOCK_GAS_KEY",
                        help="environment variable holding the gas account's private key")
        if service:
            sp.add_argument("--service", help="Transaction Service base URL (default: Safe's hosted one)")
            sp.add_argument("--offline", action="store_true", help="no Transaction Service: proposal files only")

    def safe_tx_hash_opts(sp):
        sp.add_argument("hash", nargs="?", metavar="SAFE_TX_HASH", help="the proposal's SafeTx hash (`queue` lists them)")
        sp.add_argument("--safe-tx-hash", metavar="HASH", help="the same, as an option")
        sp.add_argument("--file", help="a proposal file instead (peer to peer)")

    from . import cli_recovery  # init, backup, passphrase, move, device
    cli_recovery.add_parsers(sub, chain_opts, COMMANDS)
    sp = sub.add_parser("address", help="your owner address and stateless key")
    chain_opts(sp, service=False)
    safe_help = "the Safe's address"
    sp = sub.add_parser("enroll", help="certify a key tree for a Safe and send enroll")
    chain_opts(sp, service=False)
    sp.add_argument("--safe", required=True, help=safe_help)
    sp.add_argument("--height", type=int, default=DEFAULT_HEIGHT,
                    help=f"key tree height: 2^(height-1) nonces (default {DEFAULT_HEIGHT})")
    sp.add_argument("--rotate", action="store_true", help="replace the enrolled key tree with a fresh one")
    sp.add_argument("--take-over", action="store_true",
                    help="enroll although another device has taken over this owner on this Safe (only if that device "
                         "is gone for good)")
    sp.add_argument("--deploy", action="store_true",
                    help="deploy the verifier, implementation and factory if this chain lacks them (once per chain)")
    sp.add_argument("--out", help="where to write the calldata when there is no gas account")
    sp = sub.add_parser("propose", help="sign a new Safe transaction and post it")
    chain_opts(sp)
    sp.add_argument("--safe", required=True, help=safe_help)
    sp.add_argument("--to", help="the address the Safe calls or pays")
    sp.add_argument("--value", default="0", help="in ETH (0.01) or wei (1000wei)")
    sp.add_argument("--data", default="0x", help="calldata, hex (default: none)")
    sp.add_argument("--operation", type=int, default=0, choices=(0, 1), help="0 call (default), 1 delegatecall")
    sp.add_argument("--allow-delegatecall", action="store_true", help="needed with --operation 1")
    sp.add_argument("--nonce", type=int, help="default: the next free nonce; an existing one makes a replacement")
    sp.add_argument("--cancel", action="store_true", help="propose Safe's on-chain rejection at --nonce")
    sp.add_argument("--out", help="also write a proposal file for peer-to-peer signing")
    sp = sub.add_parser("confirm", help="sign a proposed Safe transaction")
    chain_opts(sp)
    safe_tx_hash_opts(sp)
    sp = sub.add_parser("queue", help="pending transactions, decoded")
    chain_opts(sp)
    sp.add_argument("--safe", required=True, help=safe_help)
    sp.add_argument("--file", help="proposal file (peer to peer)")
    sp = sub.add_parser("execute", help="send execTransaction with the collected signatures")
    chain_opts(sp)
    safe_tx_hash_opts(sp)
    from .bridge import add_commands
    add_commands(sub, chain_opts)  # connect, message
    sp = sub.add_parser("status", help="key trees, one-time keys left, device and backup")
    chain_opts(sp, service=False)
    sp.add_argument("--safe", help="only this Safe")
    return p


COMMANDS = {"init": cmd_init, "address": cmd_address, "enroll": cmd_enroll, "propose": cmd_propose,
            "confirm": cmd_confirm, "queue": cmd_queue, "execute": cmd_execute, "status": cmd_status}


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        (COMMANDS.get(args.cmd) or args.func)(args)
    except Refused as e:
        out(f"REFUSED: {e}")
        return 2
    except (Abort, LogCorrupt, RpcError, ServiceError, ValueError) as e:
        out(f"error: {e}")
        return 1
    except OSError as e:  # a file named on the command line: missing or unreadable
        out(f"error: {e.strerror or e}" + (f": {e.filename}" if e.filename else ""))
        return 1
    except KeyboardInterrupt:
        out("\ninterrupted")
        return 130
    finally:
        while _members:
            _members.pop().close()
    return 0
