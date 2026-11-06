"""The signer's commands for backup, recovery and devices (cli.py registers them):

  init        a new signer: shows the recovery phrase once, hides it (on a terminal), checks three of its words
              against the written copy, asks for a passphrase
  init --restore   a signer from its phrase on a new device; asks what happened to the old one:
                   it still works -> a move (no fee); lost -> fresh trees (a fee per Safe and chain);
                   someone else may have it -> no restore: the team replaces this member
  backup      shows the phrase again and checks it (--check: only the check)
  passphrase  changes the seed file's passphrase, or encrypts a plain one (--forgot: set a new one from the phrase)
  move        start (new device), export (old device), import (new device), cancel: move.py. The member key's
              home only: a device home has no phrase to move with; a new device is paired instead (cli_devices.py)
  device adopt, device fresh-trees   for a key log that looks like a copy (device.py); the `device` command itself,
              with its device-key actions, is in cli_devices.py
"""

import calendar
import getpass
import json
import os
import sys
import time
from types import SimpleNamespace

from . import device, member, move, owner, phrase, seedfile
from .abi import b2h, h2b
from .cli import (Abort, Ctx, chain_label, open_member, out, owner_deployed, safe_state,
                  stale_log_check)
from .keylog import Refused
from .member import Member, default_home, identity_of
from .service import ServiceError

ENROLL_COST = ("about 0.25M gas (0.39M with Glamsterdam's pricing, as on Sepolia) and 5.9 KB of calldata (a few "
               "dollars on Ethereum, about a cent on an L2)")
CHECK_EVERY_DAYS = 90
HOW = {"init": "created here", "restore": "restored from the recovery phrase, with fresh key trees",
       "move-in": "moved in from another device", "adopt": "an adopted copy", "upgrade": "bound on first use",
       "fresh-trees": "fresh key trees after a suspected copy", "device-new": "made here as a device home"}
NO_PHRASE = ("a device home has no recovery phrase: if this device is lost or its passphrase forgotten, revoke it "
             "from the member key's home (`device revoke`) and pair a new device (`device new`)")


def ask(prompt: str, secret: bool = False) -> str:
    """One line from the member; tests replace this"""
    try:
        return getpass.getpass(prompt) if secret else input(prompt)
    except EOFError:
        raise Abort("no answer (end of input)") from None


member.ask_passphrase = lambda prompt: ask(prompt, secret=True)


def confirm(args, question):
    if args.yes:
        return
    if ask(f"{question} [y/N] ").strip().lower() not in ("y", "yes"):
        raise Abort("not confirmed: nothing changed")


def home_of(args) -> str:
    return args.home or default_home()


CLEAR = "\033[H\033[2J\033[3J"  # cursor home, clear the screen, clear the scrollback


def clear_screen(note="(screen and scrollback cleared)") -> bool:
    """Clears the terminal and its scrollback; False (and nothing done) when the output isn't a terminal"""
    if not sys.stdout.isatty():
        return False
    sys.stdout.write(CLEAR)
    sys.stdout.flush()
    if note:
        out(note)
    return True


# --- the phrase ---

def read_phrase(source, prompt="Recovery phrase (24 words, hidden): ") -> bytes:
    """The seed from a phrase in a file, on stdin (-), or typed at a prompt (retried on a typo)"""
    if source and source != "-":
        with open(source) as f:
            text = f.read()
        return _seed_or_abort(text)
    if source == "-":
        return _seed_or_abort(sys.stdin.readline())
    for attempt in range(3):
        try:
            return phrase.to_seed(ask(prompt, secret=True))
        except phrase.PhraseError as e:
            out(f"  {e}")
    raise Abort("no valid recovery phrase")


def _seed_or_abort(text):
    try:
        return phrase.to_seed(text)
    except phrase.PhraseError as e:
        raise Abort(str(e)) from None


def show_phrase(words):
    out("")
    out("Your recovery phrase. Write the 24 words on paper, in order, and keep it offline, apart from this device.")
    out("It is the only backup you need: it restores your owner address and stateless key on any device.")
    out("Anyone who reads it can act as you. Never type it into a website, a wallet app or a chat.")
    out("")
    for line in phrase.columns(words):
        out("    " + line)
    out("")


def hide_phrase() -> bool:
    """Takes the phrase off the screen before the check, since words copied from the screen prove nothing about the
    written copy: on a terminal, once the member says it's written down, the screen and scrollback are cleared"""
    if not sys.stdout.isatty():
        out("(The output isn't a terminal, so the phrase can't be hidden from it. Type the words from your written "
            "copy, not from the screen.)")
        return False
    ask("When the 24 words are written down, press Enter to hide them: ")
    return clear_screen(note=None)


def _numbers(positions) -> str:
    ps = [f"#{p}" for p in positions]
    return ps[0] if len(ps) == 1 else ", ".join(ps[:-1]) + " and " + ps[-1]


def backup_check(words, shown=True, positions=None):
    """Asks for a few words at random positions until they match, with the phrase hidden first if it is `shown`.
    There is no skip; giving up saves nothing."""
    positions = positions or phrase.check_positions()
    for attempt in range(5):
        if shown or attempt == 0:
            if shown and hide_phrase():
                out("The phrase is now hidden (screen and scrollback cleared).")
            shown = False
            out(f"Backup check: from your written copy, type words {_numbers(positions)}.")
        wrong = [p for p in positions if not phrase.matches(words, p, ask(f"  word #{p}: "))]
        if not wrong:
            out("  Correct.")
            return
        out(f"  Word {_numbers(wrong)} doesn't match. Check your copy." if len(wrong) == 1 else
            f"  Words {_numbers(wrong)} don't match. Check your copy.")
        if ask("  Show the phrase again? [y/N] ").strip().lower() in ("y", "yes"):
            show_phrase(words)
            shown = True
    raise Abort("the backup check didn't pass: nothing was saved")


def new_passphrase() -> str:
    env = os.environ.get("WINTERLOCK_PASSPHRASE")
    if env is not None:
        if len(env) < seedfile.MIN_PASSPHRASE:
            raise Abort(f"WINTERLOCK_PASSPHRASE is shorter than {seedfile.MIN_PASSPHRASE} characters")
        return env
    out("The seed file on this device is encrypted with a passphrase, which you type to sign. It doesn't replace the")
    out("recovery phrase: if you forget it, `passphrase --forgot` sets a new one from the phrase.")
    for attempt in range(3):
        a = ask(f"New passphrase (at least {seedfile.MIN_PASSPHRASE} characters): ", secret=True)
        if len(a) < seedfile.MIN_PASSPHRASE:
            out("  too short")
            continue
        if ask("Same passphrase again: ", secret=True) != a:
            out("  the two differ")
            continue
        return a
    raise Abort("no passphrase set: nothing was saved")


def _home_is_free(home):
    for name, what in (("seed", "a signer"), ("keylog.jsonl", "a key log"), (member.REQUEST, "a pending move")):
        if os.path.exists(os.path.join(home, name)):
            raise Refused(f"{home} already has {what}: use another --home, or move it away first")


# --- init and restore ---

def cmd_init(args):
    home = home_of(args)
    if args.restore is not None:
        return restore(args, home)
    _home_is_free(home)
    t0 = time.time()
    if args.insecure_plaintext_seed:
        m = Member.init(home)
        out("TEST MODE: the seed is saved in plain hex and no recovery phrase was shown or checked. Don't hold funds.")
    else:
        seed = os.urandom(32)
        words = phrase.to_phrase(seed)
        show_phrase(words)
        backup_check(words)  # hides the phrase first
        clear_screen()  # the words typed for the check
        pw = new_passphrase()
        t0 = time.time()
        m = Member.init(home, passphrase=pw, backup="init", new_seed=seed)
    out(f"Created a signer in {m.home} ({time.time() - t0:.1f} s)")
    out(f"  owner address  {m.owner}  (the same on every chain)")
    out(f"  stateless key  {b2h(m.key)}  (leanSphincs-keccak: it certifies your key trees and signs messages)")
    out("  Your recovery phrase restores it on a new device; `move` takes it there with its key trees, without a fee.")
    out("  Check the phrase now and then with `backup --check`.")
    m.close()


def ask_situation() -> str:
    out("What happened to your old device?")
    out("  1  I still have it and it works: move this signer from it (no fee, the same key trees)")
    out("  2  It is lost, broken or wiped: restore with fresh key trees (a fee per Safe and chain)")
    out("  3  Someone else may have my recovery phrase or my device")
    for attempt in range(3):
        a = ask("Choose 1, 2 or 3: ").strip()
        if a in ("1", "2", "3"):
            return {"1": "move", "2": "lost", "3": "compromised"}[a]
    raise Abort("no choice made: nothing restored")


def compromised_guidance(own):
    out("This is not something a restore can fix. Whoever has your phrase or your device can sign as you, and a")
    out("restore would only give them company. What to do:")
    out("  1. Tell your team now. Ask them to stop approving anything you propose until this is settled.")
    out(f"  2. They replace your owner {own} in each Safe with a Safe transaction")
    out("     (swapOwner), signed by the other members. Until it executes, your old owner still counts toward the")
    out("     threshold.")
    out("  3. Make a new signer with a NEW phrase (`init` in an empty --home); give the team its owner address")
    out("     (`address`) for the swap, and `enroll` it on each Safe.")
    out("  4. Don't reuse the old phrase anywhere.")


def restore(args, home):
    _home_is_free(home)
    seed = read_phrase(args.restore or None)
    key, own = identity_of(seed)
    out(f"This phrase belongs to the signer with owner address {own}.")
    situation = "move" if args.move else "lost" if args.lost else ask_situation()
    if situation == "compromised":
        compromised_guidance(own)
        raise Abort("nothing restored")
    if situation == "move":
        return start_move(args, home, seed)
    pw = None if args.insecure_plaintext_seed else new_passphrase()
    t0 = time.time()
    m = Member.init(home, restore_seed=seed, passphrase=pw, backup="restore")
    _members_add(m)
    out(f"Restored a signer in {m.home} ({time.time() - t0:.1f} s)")
    out(f"  owner address  {m.owner}  (the same as before)")
    out(f"  stateless key  {b2h(m.key)}")
    out("  The key log starts empty: this signer never uses the old device's key trees. Run `enroll` for each")
    out("  Safe to certify a fresh key tree from the current nonce; the old device's pending approvals stop counting.")
    out("What it costs and changes:")
    out("  - A fresh key tree per Safe and chain, certified by your stateless key: one `enroll` transaction each,")
    out(f"    {ENROLL_COST}. Anyone may send it.")
    out("  - Once your fresh key tree is enrolled on a Safe, every approval your old device gave there for a")
    out("    transaction that hasn't executed stops counting. Approve those again with this signer.")
    out("  - If the old device turns up, don't use it: its key trees are retired once the fresh ones are enrolled.")
    out("Tell your team:")
    out(f'  "I lost my Winterlock signer and restored it from my recovery phrase (owner {m.owner}).')
    out("  My approvals of pending transactions stop counting once my new key tree is enrolled; I'll approve them")
    out('  again. If you see an approval from me that I didn\'t make, tell me at once: then replace me as an owner."')
    if args.chain and (args.rpc or os.environ.get("WINTERLOCK_RPC")):
        lost_report(m, Ctx(args), args.safe)


def _members_add(m):
    from . import cli
    cli._members.append(m)


def lost_report(m, ctx, safes):
    """What the restore means for each Safe on this chain: the enrolled tree and the approvals that stop counting"""
    if not safes and ctx.service:
        try:
            safes = ctx.service.get(f"/v1/owners/{m.owner}/safes/").get("safes", [])
        except ServiceError as e:
            out(f"  (service: {e}; name your Safes with --safe)")
    if not safes:
        out(f"On {chain_label(ctx.chain)}: no Safes found for {m.owner} (name them with --safe)")
        return
    deployed = owner_deployed(ctx, m)
    for safe in safes:
        safe_nonce, threshold, owners = safe_state(ctx.rpc, safe)
        if m.owner.lower() not in [o.lower() for o in owners]:
            continue
        out(f"Safe {safe} on {chain_label(ctx.chain)}: {threshold} of {len(owners)}, next nonce {safe_nonce}")
        root, _, height, start, _ = owner.read_tree(ctx.rpc, m.owner, safe) if deployed else (None, 0, 0, 0, 0)
        if root is None:
            out("  no key tree enrolled for you yet")
        else:
            out(f"  the enrolled key tree is the old device's (nonces {start}–{start + owner.capacity(height) - 1}): "
                f"`enroll --chain {ctx.chain} --safe {safe}` certifies a fresh one")
        if not ctx.service:
            continue
        try:
            txs = ctx.service.pending(safe, safe_nonce)
        except ServiceError as e:
            out(f"  (service: {e})")
            continue
        for tx in txs:
            if any((c.get("owner") or "").lower() == m.owner.lower() for c in tx.get("confirmations") or []):
                out(f"  nonce {tx['nonce']} {tx.get('safeTxHash')}: approved by your old device; stops counting once "
                    "your fresh key tree is enrolled: approve it again (Safe's service keeps the old confirmation, so "
                    "`confirm` writes a proposal file for whoever executes)")


# --- backup and passphrase ---

def cmd_backup(args):
    m = open_member(args)
    if m.is_device:
        raise Refused(NO_PHRASE)
    m.require_active()  # a moved device has no seed; a locked one can't record the check
    words = phrase.to_phrase(m.seed())
    if not args.check:
        show_phrase(words)
    backup_check(words, shown=not args.check)
    clear_screen()  # the words typed for the check
    m.log.append({"t": "backup", "how": "check" if args.check else "shown"})
    out("Recovery phrase checked; `status` shows when.")


def cmd_passphrase(args):
    m = open_member(args)
    if m.move_out():
        raise Refused(m.state()[1])
    if args.forgot:
        if m.is_device:
            raise Refused(NO_PHRASE)
        m.use_seed(read_phrase(args.phrase))
    else:
        m.seed()
    m.set_passphrase(new_passphrase())
    out(f"The seed file in {m.home} is now encrypted with the new passphrase.")


# --- moving ---

def start_move(args, home, seed):
    pw = None if args.insecure_plaintext_seed else new_passphrase()
    req = move.start(home, seed, pw)
    out(f"This device waits for a move of owner {req['owner']}. Move code:")
    out("")
    out(f"    {req['request']}")
    out("")
    for line in move_steps(req["request"]):
        out(line)
    out("With --chain (sepolia, for example), each step first checks the key log against that chain and its")
    out("Transaction Service.")
    out(CHANGED_MIND)


CHANGED_MIND = ("Changed your mind (or the old device doesn't work after all)? `move cancel`, then "
                "`init --restore --lost`.")


def move_steps(code, indent=""):
    """What to run on each device to finish the move a new device waits for"""
    return [f"{indent}On your OLD device, run:",
            f"{indent}    winterlock-signer move export --code {code} --out winterlock-move.json --chain CHAIN",
            f"{indent}It locks the old device for good and writes the bundle. Bring the file here, then run:",
            f"{indent}    winterlock-signer move import winterlock-move.json --chain CHAIN"]


def check_online(m, ctx, purpose):
    """Checks the key log against the chain and the Transaction Service for every Safe it has a live tree for on
    ctx.chain. Refuses if the service holds a signature from an enrolled tree that the log doesn't record."""
    safes = sorted({t["safe"] for t in m.log.all_trees() if t["chain"] == ctx.chain and not m.log.retired(t)})
    out(f"Checking the key log against {chain_label(ctx.chain)}"
        + (" and its Transaction Service" if ctx.service else " (no Transaction Service)") + ":")
    if not safes:
        out("  no key trees on this chain")
        return
    deployed = owner_deployed(ctx, m)
    for safe in safes:
        safe_nonce, _, owners = safe_state(ctx.rpc, safe)
        root, _, height, start, _ = owner.read_tree(ctx.rpc, m.owner, safe) if deployed else (None, 0, 0, 0, 0)
        rec = m.log.tree_by_root(ctx.chain, safe, b2h(root)) if root else None
        if root is None:
            out(f"  Safe {safe}: nonce {safe_nonce}; no key tree enrolled yet")
            continue
        if rec is None:
            out(f"  Safe {safe}: nonce {safe_nonce}; the enrolled key tree {b2h(root)[:18]}… isn't in this key log (a "
                "later enrolment by another device or a restore): no signing there until `enroll` certifies a fresh "
                "one")
            continue
        pend = [s for s in m.log.signs(ctx.chain, safe, rec["root"]) if s["nonce"] >= safe_nonce]
        out(f"  Safe {safe}: nonce {safe_nonce}; the enrolled key tree is in the log, with {len(pend)} approval(s) "
            "at pending nonces")
        if not ctx.service:
            continue
        try:
            txs = ctx.service.pending(safe, safe_nonce)
        except ServiceError as e:
            out(f"    (service: {e}; signatures not checked)")
            continue
        try:
            stale_log_check(m, ctx, safe, rec, txs)
        except Refused as e:
            if purpose == "import":
                raise Refused(f"not imported: {e} So the bundle is stale: a copy of the old log signed after it was "
                              "made. Run `move cancel`, then `init --restore --lost` (fresh key trees), and tell your "
                              "team that another copy of your signer may be active.") from None
            raise Refused(f"not exported: {e} Another copy of this signer is active somewhere; handing this log on "
                          "would carry the problem along. Use `device fresh-trees` and `enroll` instead.") from None
        out(f"    the service holds no signature by this tree that the log lacks ({len(txs)} pending transaction(s))")


def move_export(args):
    m = open_member(args)
    if m.is_device:
        raise Refused(f"a device home doesn't move: its key never leaves the device. On the new machine, make a new "
                      f"device home (`device new`), have the member key certify it (`device certify`), then revoke "
                      f"this one (`device revoke --device {m.device_no}`). It costs a certificate per chain and an "
                      "enrolment per Safe and chain, about 0.25M gas each.")
    code = move.normalize_code(args.code)
    st, why = m.state()
    mo = m.move_out()
    if mo is None and st != "active":
        raise Refused(why)
    trees = [t for t in m.log.all_trees() if not m.log.retired(t)]
    out(f"Signer {m.home}: owner {m.owner}; {len(trees)} live key tree(s), {len(m.log.signs())} one-time key(s) used")
    for t in trees:
        out(f"  {chain_label(t['chain'])}, Safe {t['safe']}: key tree {t['root'][:18]}… from nonce {t['start']}")
    if args.chain and (args.rpc or os.environ.get("WINTERLOCK_RPC")):
        check_online(m, Ctx(args), "export")
    elif mo is None:
        out("  (not checked online: add --chain, with --rpc or WINTERLOCK_RPC, to check the log against a chain and "
            "its Transaction Service first)")
    if mo is None:
        out("After this, this device signs nothing, ever: it records the move, writes the bundle, and removes its seed.")
        confirm(args, f"Lock this device and write the bundle for move {code}?")
    elif mo["request"] == code:
        out(f"This device already moved for {code} on {mo['at']}: writing the same bundle again.")
    elif not args.replace_request:
        move.lock_for(m, code)  # refuses, explaining why
    else:
        out(f"WARNING: this device moved for {mo['request']} before. Handing over to {code} instead is safe only if "
            f"the device that asked with {mo['request']} never imported its bundle and never will.")
        confirm(args, f"Hand this signer over to {code} instead?")
    if os.path.exists(m.seed_path):
        m.seed()
    else:
        out("This device's seed file is gone (the move finished before); the bundle needs your recovery phrase.")
        m.use_seed(read_phrase(args.phrase))
    payload = move.export(m, code, args.out, args.replace_request)
    out(f"Wrote {args.out}: {len(payload['log'])} key log records, encrypted with a key from your recovery phrase.")
    out("This device is now locked for good and its seed file is removed. On the new device run:")
    out(f"    winterlock-signer move import {os.path.basename(args.out)} --chain {args.chain or 'CHAIN'}")


def move_import(args):
    home = home_of(args)
    try:
        with open(args.bundle) as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise Abort(f"can't read the bundle {args.bundle}: {e}") from None
    seed, payload, records = move.open_bundle(home, doc)
    mo = records[-1]
    age = time.time() - calendar.timegm(time.strptime(payload["exported"], "%Y-%m-%dT%H:%M:%SZ"))
    trees = [t for t in records if t["t"] == "tree"]
    out(f"Bundle for owner {payload['owner']}, from device {payload.get('device')}, exported {payload['exported']}: "
        f"{len(records)} key log records, {len(trees)} key tree(s), {sum(1 for r in records if r['t'] == 'sign')} "
        "one-time key(s) used")
    staged = move.stage(home, records)
    try:
        if args.chain and (args.rpc or os.environ.get("WINTERLOCK_RPC")):
            view = SimpleNamespace(owner=payload["owner"], key=h2b(payload["key"]), log=staged, is_device=False,
                                   device_no=0)
            check_online(view, Ctx(args), "import")
        else:
            out("  Not checked online. With --chain (and --rpc or WINTERLOCK_RPC), the import first checks the log "
                "against that chain and its Transaction Service"
                + (" (recommended: this bundle is over a day old)" if age > 86400 else ""))
    except BaseException:
        staged.close()
        move.unstage(home)
        raise
    staged.close()
    m = move.install(home, seed, payload, records)
    _members_add(m)
    move.unstage(home)
    if not args.keep_bundle:
        try:
            os.remove(args.bundle)
        except OSError:
            pass
    out(f"Moved in: this device now signs for owner {m.owner} with the same key trees, without any fee"
        f" (device {m.device()['id']}, move {mo['move']}).")
    out("Every approval still checks the Transaction Service for signatures this log doesn't know.")


def move_cancel(args):
    home = home_of(args)
    req = move.cancel(home)
    out(f"Cancelled move request {req['request']} in {home}: its seed file and request are removed.")


def cmd_move(args):
    if args.action == "start":
        home = home_of(args)
        _home_is_free(home)
        seed = read_phrase(args.phrase)
        out(f"This phrase belongs to the signer with owner address {identity_of(seed)[1]}.")
        return start_move(args, home, seed)
    return {"export": move_export, "import": move_import, "cancel": move_cancel}[args.action](args)


# --- devices ---

def cmd_device(args):
    m = open_member(args)
    if m.move_out():
        raise Refused(m.state()[1])
    for _, p in m.problems:
        out(f"WARNING: {p}")
    if args.action == "adopt":
        if not m.problems:
            out("This device is the one bound to this key log: nothing to adopt.")
            return
        if any(k == device.ROLLBACK for k, _ in m.problems):
            raise Refused("this key log was rolled back, so it misses records this device wrote, maybe signatures: "
                          "trusting it could reuse a one-time key. Use `device fresh-trees` instead.")
        out("Adopting declares this copy the only one in use, complete up to the original's last signature. If the")
        out("original still signs, or signed after this copy was made, two devices could use one key twice.")
        confirm(args, "Is the original gone (or never used again) and this copy complete?")
        rec = m.add_device("adopt")
        out(f"Adopted: this key log is now device {rec['id']} on this machine.")
    else:
        out("Fresh key trees: every key tree in this key log is retired, so a stale or copied log can't reuse a")
        out(f"one-time key. Each Safe then needs `enroll` for a fresh key tree ({ENROLL_COST}); approvals given")
        out("with the old key trees for pending transactions stop counting once the fresh one is enrolled, and are")
        out("given again.")
        confirm(args, "Retire every key tree in this key log?")
        rec = m.add_device("fresh-trees", retire=True)
        out(f"Retired the key trees; this key log is now device {rec['id']}. Run `enroll` for each Safe.")


# --- status ---

def pending_move_status(args) -> bool:
    """`status` on a new device that waits for a move's bundle (it has a seed and a move request, but no key log to
    open yet): what it waits for and what to run next. False if the directory waits for nothing."""
    home = home_of(args)
    req = move.pending(home)
    if not req:
        return False
    out(f"Signer {home}")
    out(f"  owner {req['owner']}, stateless key {req['key']}")
    seed_line = f"  seed file {seedfile.describe(os.path.join(home, 'seed'))}"
    if os.path.exists(os.path.join(home, "keylog.jsonl")):
        out(f"  device MOVING IN: the import of move {req['request']} stopped half way. Run `move import` again "
            "with the same bundle to finish it.")
        out(seed_line)
        return True
    out(f"  device WAITING FOR A MOVE: request {req['request']}, started {req['created']}; it signs nothing until "
        "the bundle from your old device is imported")
    for p in move.request_problems(home, req):
        out(f"  WARNING: {p}")
    out(seed_line)
    for line in move_steps(req["request"], indent="  "):
        out(line)
    out("  " + CHANGED_MIND)
    return True


def status_lines(m) -> list:
    lines = []
    st, why = m.state()
    dev = m.device()
    if dev:
        how = HOW.get(dev["how"], dev["how"])
        if dev["how"] == "move-in" and dev.get("from_device"):
            how += f" ({dev['from_device']})"
        lines.append(f"  key log {st.upper()} on this machine: id {dev['id']}, {how} on {dev['at']}")
    else:
        lines.append(f"  key log {st.upper()}: not bound to this machine yet (a key log from before device checks; the "
                     "next command that signs binds it)")
    for _, p in m.problems:
        lines.append(f"  WARNING: {p}")
    if why:  # a copy's reason repeats the warnings above: only what to do
        remedy = member.DEVICE_COPY_REMEDY if m.is_device else member.COPY_REMEDY
        lines.append(f"    {remedy if why.startswith('this key log looks like a copy') else why}")
    lines.append(f"  seed file {seedfile.describe(m.seed_path)}")
    if m.is_device:
        lines.append("  no recovery phrase (a device home): if this device is lost, the member key revokes it and you "
                     "pair a new one")
        return lines
    b = m.log.last("backup")
    if b:
        days = (time.time() - calendar.timegm(time.strptime(b["at"], "%Y-%m-%dT%H:%M:%SZ"))) / 86400
        lines.append(f"  recovery phrase checked {b['at']} ({b['how']})"
                     + (f"; over {CHECK_EVERY_DAYS} days ago: run `backup --check`" if days > CHECK_EVERY_DAYS else ""))
    elif st != "moved":
        lines.append("  recovery phrase NEVER CHECKED: run `backup` (it shows the phrase and checks three words)")
    return lines


# --- arguments ---

def add_parsers(sub, chain_opts, commands):
    sp = sub.add_parser("init", help="create a signer (a new recovery phrase), or --restore one from its phrase")
    chain_opts(sp)
    sp.add_argument("--restore", nargs="?", const="", metavar="FILE",
                    help="restore from the recovery phrase: typed at a prompt, or read from FILE (- for stdin); "
                         "a 64-digit hex seed backup works too")
    sp.add_argument("--move", action="store_true", help="with --restore: the old device works; start a move")
    sp.add_argument("--lost", action="store_true", help="with --restore: the old device is lost; fresh key trees")
    sp.add_argument("--safe", action="append", help="with --restore --lost and --chain: a Safe to report on")
    sp.add_argument("--insecure-plaintext-seed", action="store_true",
                    help="TESTS ONLY: no passphrase, no phrase shown or checked")
    commands["init"] = cmd_init
    sp = sub.add_parser("backup", help="show the recovery phrase and check it (--check: only check it)")
    sp.add_argument("--check", action="store_true")
    commands["backup"] = cmd_backup
    sp = sub.add_parser("passphrase", help="change the seed file's passphrase (or encrypt a plain seed file)")
    sp.add_argument("--forgot", action="store_true", help="set a new passphrase from the recovery phrase")
    sp.add_argument("--phrase", metavar="FILE", help="with --forgot: the phrase from FILE (- for stdin)")
    commands["passphrase"] = cmd_passphrase
    sp = sub.add_parser("move", help="move this signer to a new device: start, export, import, cancel")
    msub = sp.add_subparsers(dest="action", required=True)
    from .cli import global_options
    _add = msub.add_parser
    msub.add_parser = lambda name, **kw: global_options(_add(name, **kw))
    s = msub.add_parser("start", help="new device: take the phrase and show a move code")
    s.add_argument("--phrase", metavar="FILE", help="the phrase from FILE (- for stdin) instead of a prompt")
    s.add_argument("--insecure-plaintext-seed", action="store_true", help="TESTS ONLY: no passphrase")
    s = msub.add_parser("export", help="old device: lock it for good and write the bundle for a move code")
    chain_opts(s)
    s.add_argument("--code", required=True, help="the move code the new device showed")
    s.add_argument("--out", required=True, help="where to write the bundle")
    s.add_argument("--phrase", metavar="FILE", help="the phrase, if the seed file is gone (FILE, or - for stdin)")
    s.add_argument("--replace-request", action="store_true",
                   help="hand over to another move code after an earlier export (only if that device never imported)")
    s = msub.add_parser("import", help="new device: check and install the bundle")
    chain_opts(s)
    s.add_argument("bundle")
    s.add_argument("--keep-bundle", action="store_true", help="don't delete the bundle file after the import")
    msub.add_parser("cancel", help="new device: drop a pending move")
    commands["move"] = cmd_move
