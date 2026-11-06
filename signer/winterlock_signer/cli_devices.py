"""Device keys (owner v2, docs/notes/owner-v2.md): the `device` command.

  device new       on the new device: makes a device home (a random device key, no recovery phrase) for a member's
                   owner and a device number 1 to 3, and shows the key with its check code
  device certify   on the member key's home: shows the check code for the key it is given, and once the member says
                   it matches, the member key certifies the device key on each chain named (certifyDevice)
  device revoke    on the member key's home: the member key revokes a device on every chain this key log certified it
                   on, and on any chain named; a per-chain report says where it no longer signs
  device list      on any home: the member's devices per chain, from the contract
  device adopt, device fresh-trees   for a key log that looks like a copy (cli_recovery.py, device.py)

Device certificates and revocations are per chain (decision 3): a device revoked on one chain still signs on the
others, so revoking defaults to every chain where it was certified. Each takes one leanSphincs-keccak signature by the
member key, recorded in the key log first, and one transaction from any gas account (about 0.25M gas under Prague
pricing). Without a gas account, the calldata is written to a file for anyone to send.
"""

import os
import re
import time

from . import abi, owner
from .abi import address, b2h, h2b
from .cli import (Abort, Ctx, chain_id_of, chain_label, confirm_prompt, device_lines, global_options, open_member,
                  out, owner_deployed, shared_contracts)
from .ethtx import send
from .keylog import Refused
from .member import Member, check_code
from .rpc import Reverted, Rpc, RpcError


# --- chains ---

def chains_given(args) -> list:
    """The chain ids named with --chain (repeatable, or comma-separated), in order, without duplicates"""
    out_ = []
    for c in args.chain or []:
        for x in c.split(","):
            cid = chain_id_of(x.strip())
            if cid not in out_:
                out_.append(cid)
    return out_


def rpc_urls(args, chains: list) -> dict:
    """{chain: RPC URL} for the chains that have one: --rpc given once per --chain in the same order, or
    WINTERLOCK_RPC_<chain id>, or WINTERLOCK_RPC for the chain it serves. A URL is checked against its chain when it
    is used (Ctx)."""
    named = chains_given(args)
    rpcs = list(args.rpc or [])
    if rpcs and len(rpcs) != len(named):
        raise Abort("give one --rpc per --chain, in the same order (or set WINTERLOCK_RPC_<chain id> for each chain)")
    urls = dict(zip(named, rpcs))
    default = os.environ.get("WINTERLOCK_RPC")
    default_chain = None
    for c in chains:
        if c not in urls and os.environ.get(f"WINTERLOCK_RPC_{c}"):
            urls[c] = os.environ[f"WINTERLOCK_RPC_{c}"]
    if default and any(c not in urls for c in chains):
        try:
            default_chain = Rpc(default, timeout=10).chain_id()
        except (RpcError, OSError, ValueError):
            default_chain = None
        if default_chain in chains and default_chain not in urls:
            urls[default_chain] = default
    return urls


def contexts(args, chains: list) -> dict:
    """{chain: Ctx} for the chains with an RPC"""
    urls = rpc_urls(args, chains)
    return {c: Ctx(args, chain=c, url=urls[c]) for c in chains if c in urls}


def _normal_code(text: str) -> str:
    return " ".join(w for w in re.split(r"[\s,;-]+", (text or "").strip().lower()) if w)


# --- device new ---

def cmd_new(args):
    from . import cli_recovery
    home = cli_recovery.home_of(args)
    try:
        own = address(args.owner)
    except ValueError as e:
        raise Abort(f"--owner: {e}") from None
    if not 1 <= args.device <= owner.MAX_DEVICE:
        raise Abort("--device is 1, 2 or 3: device 0 is the member key itself")
    cli_recovery._home_is_free(home)
    if args.insecure_plaintext_seed:
        pw = None
    else:
        out("This device's key is encrypted with a passphrase, which you type to sign. It has no recovery phrase: if")
        out("the device is lost, the member key revokes it and you pair a new one.")
        pw = cli_recovery.new_passphrase()
    t0 = time.time()
    m = Member.init_device(home, own, args.device, passphrase=pw)
    cli_recovery._members_add(m)
    out(f"Made a device home in {m.home} ({time.time() - t0:.1f} s): device {m.device_no} of owner {m.owner}")
    if args.insecure_plaintext_seed:
        out("TEST MODE: the device seed is saved in plain hex. Don't hold funds.")
    out(f"  device key   {b2h(m.key)}")
    out(f"  check code   {m.check_code()}")
    out("Pair it: on the member key's home (the one with your recovery phrase), run for each chain")
    out(f"    winterlock-signer device certify --device {m.device_no} --key {b2h(m.key)} --chain CHAIN")
    out("and check that it shows the same five words before you agree. Then here, for each Safe and chain:")
    out("    winterlock-signer enroll --chain CHAIN --safe SAFE")
    out("This home holds no recovery phrase. If this device is lost or stolen, revoke it from the member key's home")
    out(f"(`device revoke --device {m.device_no}`) and pair a new one; there is no restore and no move for it.")


# --- device certify ---

def _require_member_home(m):
    m.require_member_key("certifying or revoking a device")


def _ensure_owner(ctx, m, gas) -> bool:
    """The member's owner exists on ctx.chain, created through the factory if needed (with a gas account); False if
    it can't be"""
    if owner_deployed(ctx, m):
        return True
    missing = [name for name, addr, _, _ in shared_contracts() if not ctx.rpc.code(addr)]
    if missing:
        out(f"  the owner contracts aren't on {chain_label(ctx.chain)} ({', '.join(missing)}): `enroll --deploy` "
            "there first")
        return False
    if gas is None:
        out(f"  your owner {m.owner} doesn't exist on {chain_label(ctx.chain)} yet: run `enroll` there first, or give "
            "a gas account to create it")
        return False
    cd = abi.calldata("deploy(bytes32)", ["bytes32"], [m.key])
    if abi.dec_addr(ctx.rpc.eth_call(owner.factory_address(), cd, sender=gas.address)) != m.owner:
        raise Abort("the factory would create another owner: refusing")
    out(f"  your owner {m.owner} doesn't exist on {chain_label(ctx.chain)} yet: the factory creates it first (deploy)")
    confirm_prompt(ctx.args, f"Create your owner on {chain_label(ctx.chain)} from {gas.address}?")
    r = send(ctx.rpc, gas, owner.factory_address(), cd, log=out)
    if not owner_deployed(ctx, m):
        raise Abort(f"the factory's deploy was mined, but there is no owner at {m.owner}")
    out(f"  owner created: gas used {int(r['gasUsed'], 16):,}, tx {r['transactionHash']}")
    return True


def _send_or_write(ctx, gas, m, cd, what, path_hint):
    """Sends `cd` to the member's owner from the gas account (after an eth_call), or writes it to a file. Returns the
    receipt, or None when written to a file."""
    if gas is None:
        path = f"{path_hint}-{ctx.chain}.calldata"
        with open(path, "w") as f:
            f.write(b2h(cd) + "\n")
        out(f"  no gas account: wrote the {what} calldata for {m.owner} to {path} ({len(cd):,} bytes); anyone may "
            "send it")
        return None
    try:
        ctx.rpc.eth_call(m.owner, cd, sender=gas.address)
    except Reverted as e:
        raise Abort(f"{what} would revert: {e}") from None
    confirm_prompt(ctx.args, f"Send {what} on {chain_label(ctx.chain)} from {gas.address}?")
    return send(ctx.rpc, gas, m.owner, cd, log=out)


def _view_digest(ctx, m, sig, types, values) -> bytes:
    return abi.dec_word(ctx.rpc.eth_call(m.owner, abi.calldata(sig, types, values)))


def certify_on(ctx, m, d: int, key: bytes, gas) -> tuple:
    """Certifies `key` as device `d` on ctx.chain; returns (certified there?, report line)"""
    where = chain_label(ctx.chain)
    out(f"{where}:")
    if not _ensure_owner(ctx, m, gas):
        return False, f"{where}: NOT CERTIFIED (no owner there yet)"
    old_key, gen, active = owner.read_device(ctx.rpc, m.owner, d)
    if active and old_key == key:
        out(f"  device {d} is already certified with this key (generation {gen}): nothing to do")
        return True, f"{where}: already certified (generation {gen})"
    for other in range(1, owner.MAX_DEVICE + 1):
        if other != d and owner.read_device(ctx.rpc, m.owner, other)[0] == key:
            out(f"  WARNING: this key is (or was) device {other}'s on this chain. A device home signs as one device "
                "number only; the other number's certificate doesn't move with it.")
    if active:
        out(f"  WARNING: device {d} is active with another key ({b2h(old_key)[:18]}…, generation {gen}). Certifying "
            "replaces it: that key's key trees and messages stop counting, including its confirmations of pending "
            "transactions.")
        confirm_prompt(ctx.args, f"Replace device {d}'s key on {where}?")
    elif old_key == key:
        out(f"  WARNING: this key was revoked on this chain (generation {gen}). Certifying it again gives it back its "
            "power. If the device was lost or stolen, pair a new device instead.")
        confirm_prompt(ctx.args, f"Certify the revoked key again on {where}?")
    new_gen = gen + 1
    if new_gen > owner.MAX_GENERATION:
        raise Abort(f"device {d} has used all {owner.MAX_GENERATION:,} generations on {where}: use another device number")
    digest = owner.device_digest(ctx.chain, m.owner, d, new_gen, key)
    if _view_digest(ctx, m, "deviceDigest(uint8,uint16,bytes32)", ["uint256", "uint256", "bytes32"],
                    [d, new_gen, key]) != digest:
        raise Abort("your owner derives another device certificate digest: refusing to sign")
    t0 = time.time()
    sig = m.device_certificate(ctx.chain, d, new_gen, key)
    out(f"  the member key signed the certificate of device {d}, generation {new_gen} ({len(sig):,} bytes, "
        f"{time.time() - t0:.1f} s)")
    r = _send_or_write(ctx, gas, m, owner.certify_device_calldata(d, new_gen, key, sig), "certifyDevice",
                       f"certify-device-{d}")
    if r is None:
        return False, f"{where}: NOT CERTIFIED YET: the certificate was written to a file; send it"
    if owner.read_device(ctx.rpc, m.owner, d) != (key, new_gen, True):
        raise Abort(f"certifyDevice was mined on {where}, but device {d} doesn't read as certified")
    out(f"  certified: gas used {int(r['gasUsed'], 16):,}, tx {r['transactionHash']}")
    return True, f"{where}: CERTIFIED as device {d}, generation {new_gen}"


def cmd_certify(args):
    m = open_member(args)
    _require_member_home(m)
    d = args.device
    if not 1 <= d <= owner.MAX_DEVICE:
        raise Abort("--device is 1, 2 or 3: device 0 is the member key itself")
    try:
        key = h2b(args.key)
        owner.check_key(key)
    except ValueError:
        raise Abort("--key is the 32-byte device key the new device shows (0x and 64 hex digits)") from None
    if key == m.key:
        raise Abort("that is the member key itself, not a device key")
    chains = chains_given(args)
    if not chains:
        raise Abort("on which chains? Add --chain (several times for several chains, each with its --rpc in the "
                    "same order)")
    code = check_code(m.owner, d, key)
    out(f"Device {d} of owner {m.owner}")
    out(f"  device key   {b2h(key)}")
    out(f"  check code   {code}")
    if args.check_code is not None:
        if _normal_code(args.check_code) != code:
            raise Refused(f"the check code you gave ({_normal_code(args.check_code)}) isn't this key's ({code}): the "
                          "key, the device number or the owner differs from what the new device made. Nothing signed.")
        out("  the check code you gave matches")
    elif args.yes:
        out("  WARNING: --yes without --check-code: the check code was not compared")
    else:
        confirm_prompt(args, "Does the new device show exactly these five words?")
    ctxs = contexts(args, chains)
    missing = [c for c in chains if c not in ctxs]
    if missing:
        raise Abort("no RPC for " + ", ".join(chain_label(c) for c in missing) + ": add --rpc for each --chain, in the "
                    "same order, or set WINTERLOCK_RPC_<chain id>")
    report = [certify_on(ctxs[c], m, d, key, ctxs[c].gas_account(required=False)) for c in chains]
    out("Report:")
    for _, line in report:
        out(f"  {line}")
    if not all(ok for ok, _ in report):
        raise Abort(f"device {d} isn't certified on every chain named")
    out("On the device: `enroll --chain CHAIN --safe SAFE` for each Safe; it signs from then on.")


# --- device revoke ---

def revoke_on(ctx, m, d: int, gas) -> tuple:
    """Revokes device `d` on ctx.chain; returns (still active there?, report line)"""
    where = chain_label(ctx.chain)
    out(f"{where}:")
    if not owner_deployed(ctx, m):
        return False, f"{where}: no owner there, so no device"
    key, gen, active = owner.read_device(ctx.rpc, m.owner, d)
    if gen == 0:
        out(f"  device {d} was never certified here: nothing to revoke")
        return False, f"{where}: device {d} was never certified here"
    if not active:
        out(f"  device {d} is revoked already (generation {gen}): nothing to do")
        return False, f"{where}: already revoked (generation {gen}); it signs nothing here"
    out(f"  device {d} is active at generation {gen}, key {b2h(key)[:18]}…")
    digest = owner.revocation_digest(ctx.chain, m.owner, d, gen)
    if _view_digest(ctx, m, "revocationDigest(uint8,uint16)", ["uint256", "uint256"], [d, gen]) != digest:
        raise Abort("your owner derives another revocation digest: refusing to sign")
    t0 = time.time()
    sig = m.revocation(ctx.chain, d, gen)
    out(f"  the member key signed the revocation of device {d}, generation {gen} ({len(sig):,} bytes, "
        f"{time.time() - t0:.1f} s)")
    r = _send_or_write(ctx, gas, m, owner.revoke_device_calldata(d, gen, sig), "revokeDevice", f"revoke-device-{d}")
    if r is None:
        return True, f"{where}: STILL ACTIVE: the revocation was written to a file, not sent; send it now"
    if owner.read_device(ctx.rpc, m.owner, d)[2]:
        raise Abort(f"revokeDevice was mined on {where}, but device {d} still reads as active")
    out(f"  revoked: gas used {int(r['gasUsed'], 16):,}, tx {r['transactionHash']}")
    return False, (f"{where}: REVOKED (generation {gen}): its key trees and messages stop counting here, including "
                   "confirmations of pending transactions")


def cmd_revoke(args):
    m = open_member(args)
    _require_member_home(m)
    d = args.device
    if not 1 <= d <= owner.MAX_DEVICE:
        raise Abort("--device is 1, 2 or 3: device 0, the member key, can't be revoked (if the phrase is compromised, "
                    "the team replaces your owner)")
    named = chains_given(args)
    logged = m.certified_chains(d)
    chains = named if args.only else logged + [c for c in named if c not in logged]
    if not chains:
        raise Abort(f"this key log has no record of certifying device {d}, so name the chains with --chain (each with "
                    "its --rpc)")
    out(f"Revoking device {d} of owner {m.owner} on " + ", ".join(chain_label(c) for c in chains)
        + (" (every chain this key log certified it on" + (", and those named)" if named else ")")
           if not args.only else ""))
    confirm_prompt(args, f"Revoke device {d}? It stops signing for your owner on each of these chains.")
    ctxs = contexts(args, chains)
    report, still = [], []
    for c in chains:
        if c not in ctxs:
            report.append(f"{chain_label(c)}: NOT REVOKED: no RPC for this chain, so device {d} may still sign here. "
                          f"Run `device revoke --device {d} --chain {c} --rpc URL`.")
            still.append(c)
            continue
        try:
            active, line = revoke_on(ctxs[c], m, d, ctxs[c].gas_account(required=False))
        except (Abort, RpcError, OSError) as e:
            active, line = True, f"{chain_label(c)}: NOT REVOKED: {e}"
        report.append(line)
        if active:
            still.append(c)
    out("Report (revocations are per chain: a device revoked on one chain still signs on the others):")
    for line in report:
        out(f"  {line}")
    if not args.only:
        out("  Chains this key log doesn't know of (certified from another home, or before a restore) aren't covered: "
            "name them with --chain.")
    if still:
        raise Abort(f"device {d} may still sign on " + ", ".join(chain_label(c) for c in still))


# --- device list ---

def cmd_list(args):
    m = open_member(args, lock=False)
    chains = chains_given(args)
    if not chains and not m.is_device:
        chains = sorted({c for d in range(1, owner.MAX_DEVICE + 1) for c in m.certified_chains(d)})
    if not chains:
        raise Abort("on which chains? Add --chain (each with its --rpc)")
    ctxs = contexts(args, chains)
    out(f"Owner {m.owner}; this home is {m.what()}")
    for c in chains:
        if c not in ctxs:
            out(f"Devices on {chain_label(c)}: no RPC (add --rpc, or set WINTERLOCK_RPC_{c})")
            continue
        for line in device_lines(ctxs[c], m):
            out(line)


# --- arguments ---

COPY_ACTIONS = ("adopt", "fresh-trees")


def cmd_device(args):
    if args.action in COPY_ACTIONS:
        from . import cli_recovery
        return cli_recovery.cmd_device(args)
    return {"new": cmd_new, "certify": cmd_certify, "revoke": cmd_revoke, "list": cmd_list}[args.action](args)


def add_parser(sub, commands):
    def multi_chain(s, rpc=True):
        s.add_argument("--chain", action="append", help="chain name or id; repeat for several chains")
        if rpc:
            s.add_argument("--rpc", action="append",
                           help="JSON-RPC URL, once per --chain in the same order (or WINTERLOCK_RPC_<chain id>, or "
                                "WINTERLOCK_RPC for its own chain)")
        s.add_argument("--gas-key-env", default="WINTERLOCK_GAS_KEY",
                       help="environment variable holding the gas account's private key")

    sp = sub.add_parser("device", help="device keys: new, certify, revoke, list; adopt or fresh-trees for a copied log",
                        description="Device keys: a device home (`new`, on the new device) holds a random device key "
                                    "without the recovery phrase; the member key's home certifies it (`certify`) and "
                                    "revokes it (`revoke`), per chain. `list` shows a member's devices. For a key log "
                                    "that looks like a copy: `adopt` or `fresh-trees`.")
    dsub = sp.add_subparsers(dest="action", required=True)
    _add = dsub.add_parser
    dsub.add_parser = lambda name, **kw: global_options(_add(name, **kw))
    s = dsub.add_parser("new", help="on the new device: make a device home and show its key and check code")
    s.add_argument("--owner", required=True, help="the member's owner address (`address` on the member key's home)")
    s.add_argument("--device", type=int, required=True, help="this device's number: 1, 2 or 3")
    s.add_argument("--insecure-plaintext-seed", action="store_true",
                   help="TESTS ONLY: no passphrase on the device seed")
    s = dsub.add_parser("certify", help="member key's home: certify a device key on one or more chains")
    s.add_argument("--device", type=int, required=True, help="the device number: 1, 2 or 3")
    s.add_argument("--key", required=True, help="the device key the new device shows")
    s.add_argument("--check-code", help="the five words the new device shows (else you're asked to compare them)")
    multi_chain(s)
    s = dsub.add_parser("revoke", help="member key's home: revoke a device on every chain where it was certified")
    s.add_argument("--device", type=int, required=True, help="the device number: 1, 2 or 3")
    s.add_argument("--only", action="store_true", help="only the chains named with --chain")
    multi_chain(s)
    s = dsub.add_parser("list", help="a member's devices per chain, from the contract")
    multi_chain(s)
    dsub.add_parser("adopt", help="trust a key log that looks like a copy as complete (see `status`)")
    dsub.add_parser("fresh-trees", help="retire every key tree of a key log that looks like a copy")
    commands["device"] = cmd_device
