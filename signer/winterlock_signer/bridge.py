"""The WalletConnect bridge: a member connects the signer to a dapp, and the dapp sees the team's Safe as its account,
as with Safe's own WalletConnect support. Every request is decoded and shown here, and answered only after the member
agrees.

  eth_sendTransaction    a SafeTx (a call), signed as this member with a WOTS key and proposed through Safe's
                         Transaction Service (or a proposal file, offline), as `propose` does. The dapp gets the SafeTx
                         hash once it is proposed, as Safe's app answers; with --wait-for-execution it gets the
                         transaction hash instead if the Safe executes it before the request expires.
                         eth_getTransactionByHash and eth_getTransactionReceipt map that SafeTx hash to the execution.
  wallet_sendCalls       EIP-5792: one call, or a batch as a delegatecall to Safe's MultiSendCallOnly; the id is the
                         SafeTx hash; wallet_getCallsStatus reports it (100 pending, 200 executed, 400 replaced,
                         500 reverted).
  personal_sign,         D14 (messages.py decides): off-chain messages are signed with the stateless key and the other
  eth_signTypedData_v4   members' signatures gathered from message files; k of them, combined and checked with the
                         Safe's isValidSignature, go to the dapp. On-chain messages are approved by a proposed Safe
                         transaction through SignMessageLib; the dapp gets 0x once it has executed.
  refused                eth_sign, eth_signTransaction, raw transactions, contract creation, Safe self-calls that change
                         owners, modules, guard or fallback handler, and any message messages.py refuses.

Commands: `connect` (a session with a dapp) and `message` (another member signs a message file).
"""

import argparse
import glob
import json
import os
import sys
import threading
import time

from . import abi, collect, messages, owner, safelibs, walletconnect
from .abi import b2h, checksum, h2b, word
from .keccak import keccak256
from .keylog import Refused
from .safe import DANGEROUS, SafeTx, contract_signature
from .service import ServiceError
from .walletconnect import (DEFAULT_RELAY, UNSUPPORTED_CHAINS, UNSUPPORTED_NAMESPACE_KEY, USER_REJECTED,
                            RelayError, Wallet)

METADATA = {"name": "Winterlock signer", "description": "Hash-based signer for a Safe's members",
            "url": "https://winterlock.eth.limo", "icons": []}
SIGN_METHODS = ["eth_sendTransaction", "personal_sign", "eth_signTypedData", "eth_signTypedData_v4",
                "wallet_sendCalls", "wallet_getCallsStatus", "wallet_getCapabilities", "wallet_switchEthereumChain"]
READ_METHODS = ["eth_accounts", "eth_requestAccounts", "eth_chainId", "net_version", "eth_blockNumber",
                "eth_getBalance", "eth_getCode", "eth_getTransactionCount", "eth_getStorageAt", "eth_getBlockByNumber",
                "eth_getBlockByHash", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_estimateGas",
                "eth_call", "eth_getLogs", "eth_gasPrice"]
SUPPORTED = set(SIGN_METHODS + READ_METHODS)
EVENTS = {"chainChanged", "accountsChanged"}
SUCCESS_TOPIC = b2h(keccak256(b"ExecutionSuccess(bytes32,uint256)"))
FAILURE_TOPIC = b2h(keccak256(b"ExecutionFailure(bytes32,uint256)"))
MARGIN = 10  # answer this many seconds before the dapp's request expires
_DANGEROUS_SELECTORS = {abi.selector(s) for s in DANGEROUS}


class RpcFail(Exception):
    """A JSON-RPC error for the dapp: EIP-1193 codes (4001 rejected, 4200 unsupported, 4902 unknown chain) or
    WalletConnect's (5100 unsupported chains)"""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class Ui:
    """The member's console: shows what a request does and asks before anything is signed"""

    def __init__(self, yes=False, out=None):
        self.yes = yes
        self.out = out or (lambda *a: print(*a, flush=True))

    def show(self, *lines):
        for line in lines:
            self.out(line)

    def ask(self, question) -> bool:
        if self.yes:
            self.out(f"{question} yes (--yes)")
            return True
        try:
            return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
        except EOFError:
            return False


def _quantity(v, what="value") -> int:
    if v is None:
        return 0
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, str):
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        except ValueError:
            pass
    raise RpcFail(-32602, f"{what} is not a number")


def _hexdata(v, what="data") -> bytes:
    if v in (None, ""):
        return b""
    try:
        return h2b(v)
    except (ValueError, AttributeError, TypeError):
        raise RpcFail(-32602, f"{what} is not hex") from None


def _same(a, b) -> bool:
    try:
        return h2b(a) == h2b(b)
    except (ValueError, AttributeError, TypeError):
        return False


def session_namespaces(proposal, chain: int, safe: str):
    """(namespaces, notes) to approve a proposal with, or RpcFail to reject it. As Safe's app does, the required chains
    are listed so the dapp's SDK accepts the session, and requests on any chain but the Safe's are refused."""
    ours = f"eip155:{chain}"
    chains_req, methods_req, events_req = set(), set(), set()
    for key, ns in (proposal.required or {}).items():
        if key != "eip155" and not key.startswith("eip155:"):
            raise RpcFail(UNSUPPORTED_NAMESPACE_KEY, f"only Ethereum (eip155) is supported, not {key}")
        chains_req |= set(ns.get("chains") or ([key] if ":" in key else []))
        methods_req |= set(ns.get("methods") or [])
        events_req |= set(ns.get("events") or [])
    chains_opt, methods_opt, events_opt = set(), set(), set()
    for key, ns in (proposal.optional or {}).items():
        if key == "eip155" or key.startswith("eip155:"):
            chains_opt |= set(ns.get("chains") or ([key] if ":" in key else []))
            methods_opt |= set(ns.get("methods") or [])
            events_opt |= set(ns.get("events") or [])
    if ours not in chains_req | chains_opt:
        raise RpcFail(UNSUPPORTED_CHAINS, f"the app doesn't offer chain {chain}, where this Safe is")
    chains = sorted(chains_req | {ours})
    methods = sorted(methods_req | ((methods_opt | set(SIGN_METHODS)) & SUPPORTED))
    events = sorted(events_req | ((events_opt | EVENTS) & EVENTS))
    notes = []
    if chains_req - {ours}:
        notes.append(f"the app requires {', '.join(sorted(chains_req - {ours}))} too: requests there are refused")
    if methods_req - SUPPORTED:
        notes.append(f"the app requires {', '.join(sorted(methods_req - SUPPORTED))}, which this signer refuses")
    ns = {"eip155": {"chains": chains, "accounts": [f"{c}:{safe}" for c in chains], "methods": methods,
                     "events": events}}
    return ns, notes


class Bridge:
    def __init__(self, member, ctx, safe, ui: Ui = None, exchange_dir=".", sign_message_lib=None, multisend=None,
                 wait_for_execution=False, poll=3.0, dapp=None, collect_url=None):
        from . import cli
        self.cli = cli
        self.collect = collect_url
        self.m = member
        self.ctx = ctx
        self.rpc = ctx.rpc
        self.chain = ctx.chain
        self.safe = checksum(safe)
        self.ui = ui or Ui()
        self.exchange_dir = exchange_dir
        self.sign_message_lib = sign_message_lib
        self.multisend = multisend
        self.wait_for_execution = wait_for_execution
        self.poll = poll
        self.dapp = dapp or {}
        self.submitted = {}  # SafeTx hash -> {"nonce", "block", "calls"}
        self.stop = threading.Event()

    # --- dispatch ---

    def handle(self, method: str, params, chain_id: str = None, expiry: float = None):
        """The result for the dapp, or RpcFail"""
        if chain_id and chain_id != f"eip155:{self.chain}":
            raise RpcFail(UNSUPPORTED_CHAINS, f"this Safe is on eip155:{self.chain}, not {chain_id}")
        deadline = (expiry or time.time() + 300) - MARGIN
        params = params if params is not None else []
        if method in ("eth_accounts", "eth_requestAccounts"):
            return [self.safe]
        if method == "eth_chainId":
            return hex(self.chain)
        if method == "net_version":
            return str(self.chain)
        if method == "wallet_switchEthereumChain":
            want = _quantity((params[0] or {}).get("chainId") if params and isinstance(params[0], dict) else None,
                             "chainId")
            if want == self.chain:
                return None
            raise RpcFail(4902, f"this signer serves the Safe on chain {self.chain} only; reconnect for chain {want}")
        if method == "wallet_getCapabilities":
            if params and isinstance(params[0], str) and not _same(params[0], self.safe):
                return {}
            return {hex(self.chain): {"atomicBatch": {"supported": True}, "atomic": {"status": "supported"}}}
        if method == "eth_sendTransaction":
            return self.send_transaction(params[0] if params else None, deadline)
        if method == "wallet_sendCalls":
            return self.send_calls(params[0] if params else None, deadline)
        if method == "wallet_getCallsStatus":
            return self.calls_status(params[0] if params else None)
        if method in ("personal_sign", "eth_sign", "eth_signTypedData", "eth_signTypedData_v3",
                      "eth_signTypedData_v4"):
            return self.sign_message(method, params, deadline)
        if method in ("eth_getTransactionByHash", "eth_getTransactionReceipt") and params and \
                str(params[0]).lower() in self.submitted:
            return self.mapped_lookup(method, str(params[0]).lower())
        if method in READ_METHODS:
            return self.rpc.call(method, params)
        if method in ("eth_signTransaction", "eth_sendRawTransaction"):
            raise RpcFail(4200, f"{method}: a Safe has no key that signs raw transactions; use eth_sendTransaction")
        raise RpcFail(4200, f"{method} is not supported by this signer")

    # --- transactions ---

    def next_nonce(self) -> int:
        nonce = abi.dec_uint(self.rpc.eth_call(self.safe, abi.calldata("nonce()")))
        pending = [s["nonce"] + 1 for s in self.submitted.values() if s["nonce"] >= nonce]
        if self.ctx.service:
            try:
                pending += [int(x["nonce"]) + 1 for x in self.ctx.service.pending(self.safe, nonce)]
            except ServiceError as e:
                self.ui.show(f"  (service: {e}; using the on-chain nonce)")
        return max([nonce] + pending)

    def _call(self, tx: dict, where="the transaction"):
        """(to, value, data) of one call a dapp asks for, after the checks that apply to every call"""
        if not isinstance(tx, dict):
            raise RpcFail(-32602, f"{where} is not an object")
        if tx.get("from") and not _same(tx["from"], self.safe):
            raise RpcFail(-32602, f"{where} is from {tx['from']}, not this Safe {self.safe}")
        if tx.get("chainId") is not None and _quantity(tx["chainId"], "chainId") != self.chain:
            raise RpcFail(UNSUPPORTED_CHAINS, f"{where} is for chain {tx['chainId']}, not {self.chain}")
        if not tx.get("to"):
            raise RpcFail(4200, f"{where} creates a contract, which this signer doesn't do from a Safe")
        if not abi.is_address(tx["to"]):
            raise RpcFail(-32602, f"{where}: `to` is not an address")
        to = checksum(tx["to"])
        data = _hexdata(tx.get("data") if tx.get("data") is not None else tx.get("input"))
        value = _quantity(tx.get("value"))
        if _same(to, self.safe) and data[:4] in _DANGEROUS_SELECTORS:
            raise RpcFail(4001, "an app asks the Safe to change its owners, threshold, modules, guard or fallback "
                                "handler: refused over WalletConnect (use `propose` if the team means it)")
        return to, value, data

    def send_transaction(self, tx, deadline):
        to, value, data = self._call(tx)
        t = SafeTx(to=to, value=value, data=data, nonce=self.next_nonce())
        h = self.propose(t, calls=1)
        if not self.wait_for_execution:
            self.ui.show("The app gets the SafeTx hash")
        else:
            self.ui.show(f"Waiting for the Safe to execute it, until the app's request expires "
                         f"({time.strftime('%H:%M:%S', time.localtime(deadline + MARGIN))})")
            while time.time() < deadline and not self.stop.is_set():
                ex = self.execution(h)
                if ex:
                    self.ui.show(f"Executed in {ex[0]}: the app gets this transaction hash")
                    return ex[0]
                time.sleep(self.poll)
            self.ui.show("Not executed before the request expires: the app gets the SafeTx hash")
        return h

    def send_calls(self, bundle, deadline):
        if not isinstance(bundle, dict) or not isinstance(bundle.get("calls"), list) or not bundle["calls"]:
            raise RpcFail(-32602, "wallet_sendCalls needs a bundle with calls")
        if bundle.get("chainId") is not None and _quantity(bundle["chainId"], "chainId") != self.chain:
            raise RpcFail(UNSUPPORTED_CHAINS, f"the calls are for chain {bundle['chainId']}, not {self.chain}")
        if bundle.get("from") and not _same(bundle["from"], self.safe):
            raise RpcFail(-32602, f"the calls are from {bundle['from']}, not this Safe")
        for name, cap in (bundle.get("capabilities") or {}).items():
            if isinstance(cap, dict) and cap.get("optional") is False:
                raise RpcFail(5700, f"capability {name} is not supported")
        calls = [self._call(dict(c, **{"from": None}), f"call {i}") for i, c in enumerate(bundle["calls"])]
        if len(calls) == 1:
            to, value, data = calls[0]
            t = SafeTx(to=to, value=value, data=data, nonce=self.next_nonce())
        else:
            try:
                ms = safelibs.check(self.rpc, safelibs.MULTISEND, self.multisend)
            except safelibs.UnknownLibrary as e:
                raise RpcFail(-32000, str(e)) from None
            payload = b"".join(b"\x00" + h2b(to) + word(value) + word(len(data)) + data for to, value, data in calls)
            t = SafeTx(to=ms, data=abi.calldata("multiSend(bytes)", ["bytes"], [payload]), operation=1,
                       nonce=self.next_nonce())
        note = (None if len(calls) == 1 else f"  The batch is a delegatecall to Safe's MultiSendCallOnly at {t.to} (code "
                "checked), which can only make calls")
        h = self.propose(t, calls=len(calls), note=note)
        self.ui.show("The app gets the SafeTx hash as the batch's id")
        return {"id": h}

    def propose(self, t: SafeTx, calls=1, question="Sign and propose this transaction?", note=None,
                header=True) -> str:
        cli = self.cli
        if header:
            self.ui.show(f"Request from {self.dapp.get('name') or 'the app'} ({self.dapp.get('url') or 'no URL'})")
        try:
            safe, h, rec, slot = cli.prepare(self.m, self.ctx, self.safe, t)
        except Refused as e:
            raise RpcFail(4001, f"the signer refuses: {e}") from None
        if note:
            self.ui.show(note)
        if not self.ui.ask(question):
            raise RpcFail(4001, "the member rejected the transaction")
        try:
            data = cli.sign_and_check(self.m, self.ctx, safe, t, rec, slot, h)
        except (Refused, cli.Abort) as e:
            raise RpcFail(-32000, f"not signed: {e}") from None
        sig = contract_signature(self.m.owner, data)
        hx = b2h(h)
        if self.ctx.service:
            status, resp = self.ctx.service.propose(safe, t, hx, self.m.owner, b2h(sig))
            self.ui.show(f"  POST proposal -> HTTP {status}" + ("" if status in (200, 201) else f": {str(resp)[:300]}"))
            if status not in (200, 201):
                raise RpcFail(-32000, f"the Transaction Service refused the proposal (HTTP {status})")
        else:
            path = os.path.join(self.exchange_dir, f"safetx-{hx[:12]}.json")
            doc = {"chain": self.chain, "safe": safe, "safeTx": t.to_json(), "safeTxHash": hx, "signatures": []}
            cli.add_file_signature(doc, self.m.owner, b2h(sig))
            cli.save_file(path, doc)
            self.ui.show(f"  wrote {path}: the other members confirm it (confirm --file)")
        self.submitted[hx.lower()] = {"nonce": t.nonce, "block": int(self.rpc.call("eth_blockNumber"), 16),
                                      "calls": calls}
        self.ui.show(f"Proposed {hx} at nonce {t.nonce}")
        return hx

    def execution(self, h: str):
        """(transaction hash, succeeded) once the Safe has executed SafeTx `h`, else None"""
        frm = self.submitted.get(h.lower(), {}).get("block", 0)
        logs = self.rpc.call("eth_getLogs", [{"address": self.safe, "fromBlock": hex(frm), "toBlock": "latest",
                                              "topics": [[SUCCESS_TOPIC, FAILURE_TOPIC]]}])
        for lg in logs:
            # v1.4.1 indexes the hash (topic 1); v1.3.0 puts it in the data
            got = lg["topics"][1] if len(lg["topics"]) > 1 else "0x" + lg["data"][2:66]
            if got.lower() == h.lower():
                return lg["transactionHash"], lg["topics"][0] == SUCCESS_TOPIC
        return None

    def calls_status(self, bid):
        h = str(bid or "").lower()
        if h not in self.submitted:
            raise RpcFail(5730, "unknown bundle id (this signer only knows the calls it proposed in this session)")
        out = {"version": "2.0.0", "id": h, "chainId": hex(self.chain), "atomic": True}
        ex = self.execution(h)
        if not ex:
            nonce = abi.dec_uint(self.rpc.eth_call(self.safe, abi.calldata("nonce()")))
            out["status"] = 400 if nonce > self.submitted[h]["nonce"] else 100
            return out
        r = self.rpc.call("eth_getTransactionReceipt", [ex[0]])
        receipt = {k: r.get(k) for k in ("blockHash", "blockNumber", "gasUsed", "transactionHash")}
        receipt["logs"] = [{k: lg.get(k) for k in ("address", "data", "topics")} for lg in r.get("logs", [])]
        receipt["status"] = "0x1" if ex[1] else "0x0"
        out["status"] = 200 if ex[1] else 500
        out["receipts"] = [receipt]
        return out

    def mapped_lookup(self, method, h):
        """A SafeTx hash this signer gave the app, looked up as the transaction that executed it (as Safe's app does)"""
        ex = self.execution(h)
        if ex:
            return self.rpc.call(method, [ex[0]])
        if method == "eth_getTransactionReceipt":
            return None
        return {"hash": h, "from": self.safe, "to": None, "blockHash": None, "blockNumber": None,
                "transactionIndex": None, "nonce": "0x0", "gas": "0x0", "gasPrice": "0x0", "value": "0x0",
                "input": "0x"}

    # --- messages ---

    def owners(self):
        _, threshold, owners = self.cli.safe_state(self.rpc, self.safe)
        return threshold, owners

    def sign_message(self, method, params, deadline):
        threshold, owners = self.owners()
        # a connected app that names no URL can't pass a sign-in's domain check
        d = messages.decide(method, params, self.safe, self.chain, self.dapp.get("url") or "", owners)
        self.ui.show(f"Request from {self.dapp.get('name') or 'the app'} ({self.dapp.get('url') or 'no URL'})",
                     *d.show())
        if d.path == messages.REFUSE:
            raise RpcFail(4001, f"refused: {d.reason}")
        if d.path == messages.ONCHAIN:
            return self.approve_onchain(d, deadline)
        return self.collect_offchain(method, params, d, threshold, owners, deadline)

    def approve_onchain(self, d, deadline):
        if messages.approved_onchain(self.rpc, self.safe, self.chain, d.app_hash):
            self.ui.show("The Safe has already approved this message on-chain: the app gets 0x (an empty signature)")
            return "0x"
        try:
            lib = safelibs.check(self.rpc, safelibs.SIGN_MESSAGE_LIB, self.sign_message_lib)
        except safelibs.UnknownLibrary as e:
            raise RpcFail(-32000, str(e)) from None
        self.ui.show(
            "On-chain approval: a Safe transaction delegatecalls Safe's SignMessageLib at " + lib + " (code checked),",
            "  which records the message in the Safe. Once it executes, the Safe accepts an empty signature for it,",
            "  and the app gets 0x. Apps that verify with viem refuse 0x (its ERC-6492 check needs 32 bytes or more);",
            "  contracts such as Permit2 accept it. An approval can't be withdrawn with Safe's own contracts.")
        t = SafeTx(to=lib, data=messages.sign_message_calldata(d.app_hash), operation=1, nonce=self.next_nonce())
        h = self.propose(t, question="Sign and propose this approval?", header=False)
        until = time.strftime('%H:%M:%S', time.localtime(deadline + MARGIN))
        self.ui.show(f"Waiting for the approval to execute (members confirm it; anyone executes it), until the app's "
                     f"request expires ({until})")
        while time.time() < deadline and not self.stop.is_set():
            if messages.approved_onchain(self.rpc, self.safe, self.chain, d.app_hash):
                self.ui.show("Approved on-chain: the app gets 0x")
                return "0x"
            time.sleep(self.poll)
        raise RpcFail(-32000, f"the approval {h} hasn't executed yet; once it has, ask again: the signer answers 0x "
                              "at once")

    def _doc_path(self, smh: str) -> str:
        return os.path.join(self.exchange_dir, f"safe-message-{smh[2:14]}.json")

    def _gather(self, doc):
        """Merges the signatures for the same message from every message file in the exchange directory, and from
        the collection endpoint if there is one"""
        for path in glob.glob(os.path.join(self.exchange_dir, "*.json")):
            try:
                with open(path) as f:
                    other = json.load(f)
            except (OSError, ValueError):
                continue
            if isinstance(other, dict) and other.get("kind") == messages.DOC_KIND:
                messages.merge(doc, other)
        if self.collect:
            try:
                messages.merge(doc, collect.get(self.collect, doc["safeMessageHash"]))
            except collect.CollectError:
                pass  # not posted yet, or the endpoint is down: files still work

    def _post(self, doc):
        if self.collect:
            try:
                collect.put(self.collect, doc)
            except collect.CollectError as e:
                self.ui.show(f"  (collection endpoint: {e}; message files still work)")

    def collect_offchain(self, method, params, d, threshold, owners, deadline):
        smh = b2h(messages.safe_message_hash(self.chain, self.safe, d.app_hash))
        path = self._doc_path(smh)
        doc = messages.new_doc(self.chain, self.safe, method, params, d, self.dapp)
        self._gather(doc)
        valid = messages.valid_signatures(self.rpc, doc, owners)
        mine = any(o.lower() == self.m.owner.lower() for o, _, _ in valid)
        if len(valid) < threshold and not mine:
            if not self.cli.owner_deployed(self.ctx, self.m):
                raise RpcFail(-32000, f"your owner {self.m.owner} isn't deployed on this chain yet: run `enroll`")
            if not self.ui.ask("Sign this message with your stateless key?"):
                raise RpcFail(4001, "the member rejected the message")
            data = messages.signature_data(self.m, self.chain, self.safe, d.app_hash)
            if not owner.is_valid_signature(self.rpc, self.m.owner, h2b(smh), data):
                raise RpcFail(-32000, "your owner contract refuses the message signature (eth_call): not sent")
            messages.add_signature(doc, self.m.owner, b2h(contract_signature(self.m.owner, data)))
            valid = messages.valid_signatures(self.rpc, doc, owners)
        self.cli.save_file(path, doc)
        if len(valid) < threshold:
            self._post(doc)
            until = time.strftime('%H:%M:%S', time.localtime(deadline + MARGIN))
            self.ui.show(f"Signatures {len(valid)} of {threshold}. Send {path} to the other members: each runs",
                         f"  winterlock-signer message --chain {self.chain} --file <the file>",
                         f"  and sends it back into {self.exchange_dir}.")
            if self.collect:
                self.ui.show("  Or, through the collection endpoint:",
                             f"  winterlock-signer message --chain {self.chain} --collect {self.collect} --hash {smh}")
            self.ui.show(f"Waiting until the app's request expires ({until}).")
        while len(valid) < threshold:
            if time.time() >= deadline or self.stop.is_set():
                raise RpcFail(-32000, f"{len(valid)} of {threshold} signatures before the request expired; the "
                                      f"file keeps them: once the others have signed, ask again and the signer "
                                      "answers at once")
            time.sleep(self.poll)
            before = len(valid)
            self._gather(doc)
            valid = messages.valid_signatures(self.rpc, doc, owners)
            if len(valid) != before:
                self.ui.show(f"  signatures {len(valid)} of {threshold}: " + ", ".join(o for o, _, _ in valid))
                self.cli.save_file(path, doc)
        blob = messages.combine(valid, threshold)
        if not messages.safe_accepts(self.rpc, self.safe, d.app_hash, blob):
            raise RpcFail(-32000, "the Safe's isValidSignature refuses the combined signature: not sent")
        doc["signature"] = b2h(blob)
        self.cli.save_file(path, doc)
        self.ui.show(f"The Safe accepts the combined signature (eth_call isValidSignature): {len(blob):,} bytes, "
                     f"{threshold} of {len(owners)} owners; the app gets it")
        return b2h(blob)


# --- the session loop ---

def serve(wallet: Wallet, session, bridge: Bridge, ui: Ui, max_requests=None, stop: threading.Event = None):
    """Answers the dapp's requests one at a time until it disconnects, `stop` is set, or `max_requests` are done"""
    done = 0
    stop = stop or threading.Event()
    while not stop.is_set() and (max_requests is None or done < max_requests):
        try:
            kind, obj = wallet.events.get(timeout=0.5)
        except Exception:
            continue
        if kind == "deleted" and obj.topic == session.topic:
            ui.show("The app disconnected.")
            return done
        if kind == "settled":
            ui.show("The app confirmed the session.")
            continue
        if kind == "proposal":
            wallet.reject(obj, USER_REJECTED, "this signer serves one app at a time")
            continue
        if kind != "request" or obj.topic != session.topic:
            continue
        ui.show("", f"=== {messages.printable(obj.method, 80)} (request {messages.printable(obj.id, 40)})")
        try:
            result = bridge.handle(obj.method, obj.params, obj.chain_id, obj.expiry)
            wallet.respond(obj, result=result)
            shown = result if not isinstance(result, str) or len(result) < 140 else f"{result[:66]}… " \
                                                                                    f"({(len(result) - 2) // 2:,} bytes)"
            ui.show(f"--> answered: {json.dumps(shown, ensure_ascii=False)[:300]}")
        except RpcFail as e:
            wallet.respond(obj, error=(e.code, e.message))
            ui.show(f"--> error {e.code}: {messages.printable(e.message, 2000)}")
        except RelayError as e:
            ui.show(f"--> couldn't answer: {e}")
        except Exception as e:  # the chain, the service or the key log failed: answer, and keep the session
            msg = f"{type(e).__name__}: {str(e)[:300]}"
            ui.show(f"--> failed: {msg}")
            try:
                wallet.respond(obj, error=(-32603, f"the signer failed: {msg}"))
            except RelayError:
                pass
        done += 1
    return done


def _read_uri(arg):
    if arg and arg != "-":
        return arg
    if arg == "-":
        return sys.stdin.readline().strip()
    try:
        import getpass
        return getpass.getpass("WalletConnect URI from the app (not shown): ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def cmd_connect(args):
    from . import cli
    m = cli.open_member(args)
    ctx = cli.Ctx(args)
    safe = abi.address(args.safe)
    nonce, threshold, owners = cli.safe_state(ctx.rpc, safe)
    if m.owner.lower() not in [o.lower() for o in owners]:
        raise Refused(f"your owner {m.owner} is not an owner of {safe}")
    relay_url = args.relay or os.environ.get("WALLETCONNECT_RELAY") or DEFAULT_RELAY
    project = os.environ.get("WALLETCONNECT_PROJECT_ID")
    if relay_url.rstrip("/") == DEFAULT_RELAY and not project:
        raise cli.Abort("Reown's relay needs a project ID: create one at cloud.reown.com and set "
                        "WALLETCONNECT_PROJECT_ID (or use --relay for another relay)")
    uri = _read_uri(args.uri)
    if not uri:
        raise cli.Abort("no WalletConnect URI")
    ui = Ui(yes=args.yes)
    if args.yes:
        cli.out("WARNING: --yes: every request the signer's rules allow is signed without asking you")
    os.makedirs(args.exchange_dir, exist_ok=True)
    relay = walletconnect.Relay(relay_url, project, log=cli.out)
    try:
        relay.start()
    except Exception as e:
        raise cli.Abort(f"relay: {e}") from None
    wallet = Wallet(relay, METADATA, log=cli.out)
    session = None
    try:
        try:
            wallet.pair(uri)
        except RelayError as e:
            raise cli.Abort(f"relay: {e}") from None
        cli.out(f"Paired through {relay.host()}; waiting for the app's session proposal")
        deadline = time.time() + args.proposal_timeout
        proposal = None
        while time.time() < deadline and proposal is None:
            try:
                kind, obj = wallet.events.get(timeout=0.5)
            except Exception:
                continue
            if kind == "proposal":
                proposal = obj
        if proposal is None:
            raise cli.Abort("no session proposal from the app: the URI may be used or expired")
        md = messages.clean_metadata(proposal.metadata)  # printable: a dapp's strings never reach the terminal raw
        cli.out(f"App          {md.get('name')!r} at {md.get('url')} (as it describes itself: WalletConnect doesn't "
                "verify this)")
        if md.get("description"):
            cli.out(f"             {md['description']}")
        try:
            ns, notes = session_namespaces(proposal, ctx.chain, safe)
        except RpcFail as e:
            wallet.reject(proposal, e.code, e.message)
            raise cli.Abort(f"session refused: {e.message}") from None
        cli.out(f"Account      the Safe {safe} on {cli.chain_label(ctx.chain)}, {threshold} of {len(owners)}")
        cli.out(f"Methods      {messages.printable(', '.join(ns['eip155']['methods']), 1000)}")
        for n in notes:
            cli.out(f"  note: {messages.printable(n, 500)}")
        if not ui.ask(f"Connect {md.get('name')!r} to the Safe?"):
            wallet.reject(proposal, USER_REJECTED, "rejected by the member")
            raise cli.Abort("not connected")
        props = {"capabilities": json.dumps({safe: {hex(ctx.chain): {"atomicBatch": {"supported": True}}}}),
                 "atomic": json.dumps({"status": "supported"})}
        session = wallet.approve(proposal, ns, props)
        cli.out("Connected: answering the app's requests (Ctrl-C disconnects)")
        bridge = Bridge(m, ctx, safe, ui, args.exchange_dir, args.sign_message_lib, args.multisend,
                        args.wait_for_execution, poll=args.poll, dapp=md, collect_url=args.collect)
        try:
            serve(wallet, session, bridge, ui, args.max_requests)
        except KeyboardInterrupt:
            cli.out("")
    except KeyboardInterrupt:
        raise cli.Abort("interrupted before the session started") from None
    finally:
        if session is not None and session.topic in wallet.sessions:
            wallet.disconnect(session)
            cli.out("Disconnected.")
        relay.close()


def cmd_message(args):
    """Another member signs a message the connected member collects: a message file they sent, or one on the
    collection endpoint"""
    from . import cli
    if bool(args.file) == bool(args.collect):
        raise cli.Abort("give --file, or --collect URL with --hash")
    m = cli.open_member(args)
    ctx = cli.Ctx(args)
    if args.collect:
        if not args.hash:
            raise cli.Abort("--collect needs --hash: the SafeMessage hash the connected member shows")
        try:
            doc = collect.get(args.collect, args.hash.lower())
        except collect.CollectError as e:
            raise cli.Abort(str(e)) from None
    else:
        doc = cli.load_file(args.file)
    try:
        safe = abi.address(doc.get("safe", ""))
    except ValueError:
        raise cli.Abort("the message names no Safe") from None
    _, threshold, owners = cli.safe_state(ctx.rpc, safe)
    if m.owner.lower() not in [o.lower() for o in owners]:
        raise Refused(f"your owner {m.owner} is not an owner of {safe}")
    try:
        d = messages.check_doc(doc, ctx.chain, owners)
    except ValueError as e:
        raise Refused(str(e)) from None
    dapp = messages.clean_metadata(doc.get("dapp"))
    cli.out(f"Safe         {safe} on {cli.chain_label(ctx.chain)}, {threshold} of {len(owners)}")
    cli.out(f"App          {dapp.get('name')!r} at {dapp.get('url')} (as the connected member's app described itself)")
    for line in d.show():
        cli.out(line)
    if d.path == messages.REFUSE:
        raise Refused(d.reason)
    if d.path == messages.ONCHAIN:
        raise Refused("this message is approved on-chain, by a Safe transaction through SignMessageLib: confirm that "
                      "transaction instead")
    valid = messages.valid_signatures(ctx.rpc, doc, owners)
    cli.out(f"Signatures   {len(valid)} of {threshold} so far: " + ", ".join(o for o, _, _ in valid))
    if any(o.lower() == m.owner.lower() for o, _, _ in valid):
        cli.out("You have signed this message already.")
        return
    if not cli.owner_deployed(ctx, m):
        raise Refused(f"your owner {m.owner} isn't deployed on this chain yet: run `enroll`")
    cli.confirm_prompt(args, "Sign this message with your stateless key?")
    smh = h2b(doc["safeMessageHash"])
    data = messages.signature_data(m, ctx.chain, safe, d.app_hash)
    if not owner.is_valid_signature(ctx.rpc, m.owner, smh, data):
        raise cli.Abort("your owner contract refuses the message signature (eth_call): not added")
    sig = b2h(contract_signature(m.owner, data))
    if args.collect:
        try:
            stored = collect.post_signature(args.collect, doc["safeMessageHash"], m.owner, sig)
        except collect.CollectError as e:
            raise cli.Abort(f"the endpoint didn't take the signature: {e}") from None
        cli.out(f"Signed and posted: the endpoint holds {len(stored.get('signatures', []))} of {threshold}")
        return
    messages.add_signature(doc, m.owner, sig)
    cli.save_file(args.file, doc)
    cli.out(f"Signed ({len(valid) + 1} of {threshold}): send {args.file} back to the member who is connected")


def add_commands(sub, chain_opts):
    sp = sub.add_parser("connect", help="answer a dapp over WalletConnect as the team's Safe")
    chain_opts(sp)
    sp.add_argument("--safe", required=True)
    sp.add_argument("uri", nargs="?", help="the app's wc: URI, or - to read it from stdin (default: asked for, "
                                           "not shown)")
    sp.add_argument("--relay", help=f"WalletConnect relay (default {DEFAULT_RELAY}, which needs "
                                    "WALLETCONNECT_PROJECT_ID; or WALLETCONNECT_RELAY)")
    sp.add_argument("--exchange-dir", default=".", help="where message files are written and collected (default .)")
    sp.add_argument("--collect", metavar="URL", help="also gather message signatures through a collection endpoint "
                                                     "(collect.py)")
    sp.add_argument("--sign-message-lib", help="SignMessageLib address (default: Safe v1.4.1's canonical one)")
    sp.add_argument("--multisend", help="MultiSendCallOnly address (default: Safe v1.4.1's canonical one)")
    sp.add_argument("--wait-for-execution", action="store_true",
                    help="answer eth_sendTransaction with the transaction hash if the Safe executes it in time")
    sp.add_argument("--proposal-timeout", type=float, default=60, help=argparse.SUPPRESS)
    sp.add_argument("--poll", type=float, default=3.0, help=argparse.SUPPRESS)
    sp.add_argument("--max-requests", type=int, help=argparse.SUPPRESS)
    sp.set_defaults(func=cmd_connect)
    sp = sub.add_parser("message", help="sign a Safe message that another member collects for a dapp")
    chain_opts(sp, service=False)
    sp.add_argument("--file", help="the message file the connected member sent you")
    sp.add_argument("--collect", metavar="URL", help="or: the collection endpoint the connected member names")
    sp.add_argument("--hash", help="with --collect: the message's SafeMessage hash")
    sp.set_defaults(func=cmd_message)
