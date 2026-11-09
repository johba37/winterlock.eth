#!/usr/bin/env python3
"""Known answers from the Python signer for the Rust core (core/), which must match them byte for byte.

Writes JSON to core/tests/vectors/: phrase.json (the word list and parser cases, check codes), keys.json (member,
device and gas keys, tree secret seeds), leansphincs.json (signatures), wots.json (trees, signatures, paths),
owner.json (v2 digests, key indices, layouts, addresses), safe.json (SafeTx and SafeMessage hashes, amounts),
keylog.json (sign requests and what the key log answers), board.json, the compact subset the ESP32 firmware
embeds, and hbkd.json (hash-based key derivation from BIP-39, a draft ERC: library code nothing uses yet). Every input
is a fixed public test value: no randomness, so the files only change when the signer does.

usage: signer/.venv/bin/python signer/tools/core_vectors.py [OUT_DIR]
"""
import json
import os
import re
import sys
import tempfile
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from winterlock_signer import abi, eip712, hbkd, leansphincs, member, messages, owner, phrase, safe, wots  # noqa: E402
from winterlock_signer.abi import b2h, checksum, h2b  # noqa: E402
from winterlock_signer.ethtx import Account  # noqa: E402
from winterlock_signer.keccak import keccak256  # noqa: E402
from winterlock_signer.keylog import KeyLog, Refused  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "core", "tests", "vectors")


def k(label: str) -> bytes:
    return keccak256(label.encode())


def addr(label: str) -> str:
    return checksum(k(label)[12:])


SEEDS = [bytes(32), bytes([0xFF] * 32), bytes(range(32)), k("winterlock core vectors seed 1"),
         k("winterlock core vectors seed 2")]
SEED = SEEDS[3]  # the seed most vectors (and the board) use
CHAIN = 421614  # Arbitrum Sepolia
SAFE = addr("winterlock core vectors safe")
SALT = k("winterlock core vectors salt")


def write(name, data):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{path}: {os.path.getsize(path):,} bytes")


# --- phrase ---

def phrase_vectors():
    words = phrase._M.wordlist
    spaces = [c for c in range(0x110000) if chr(c).isspace()]
    digits = [c for c in range(0x110000) if re.fullmatch(r"\d", chr(c))]
    round_trips = []
    for s in SEEDS:
        ws = phrase.to_phrase(s)
        round_trips.append({"seed": b2h(s), "words": " ".join(ws)})
    ws = phrase.to_phrase(SEED)
    line = " ".join(ws)
    typed = [
        line,
        line.upper(),
        "  " + "\n".join(f"{i + 1}. {w}" for i, w in enumerate(ws)) + "\n",
        ", ".join(f"{i + 1}) {w.capitalize()}" for i, w in enumerate(ws)),
        ";".join(w[:4] for w in ws),
        "\t".join(f"{i + 1}: {w[:5]}" for i, w in enumerate(ws)),
        " ".join(ws),
        "　".join(ws) + " ",
        "\x1c".join(ws),
        " ".join(f"١٢. {w}" if i == 0 else w for i, w in enumerate(ws)),  # Arabic-Indic numbering
        b2h(SEED),
        b2h(SEED)[2:].upper(),
        "  " + b2h(SEED) + "\n",
    ]
    parses = []
    for t in typed:
        parses.append({"text": t, "seed": b2h(phrase.to_seed(t))})
    errors = []

    def err(text):
        try:
            phrase.to_seed(text)
        except phrase.PhraseError as e:
            msg = str(e)
            if msg.startswith("a recovery phrase has"):
                errors.append({"text": text, "error": "count", "count": int(msg.rsplit(" ", 1)[1])})
            elif msg.startswith("word "):
                n = int(msg.split()[1])
                tok = [t for t in re.split(r"[\s,;]+", text.strip())
                       if t and not re.fullmatch(r"\d+[.):]?", t)][n - 1]
                errors.append({"text": text, "error": "word", "position": n, "token": tok})
            elif "checksum" in msg:
                errors.append({"text": text, "error": "checksum"})
            else:
                raise
            return
        raise AssertionError(f"accepted: {text!r}")

    err(" ".join(ws[:23]))
    err(" ".join(ws + ["abandon"]))
    err("")
    err(" ".join(ws[:5] + ["notaword"] + ws[6:]))
    err(" ".join(ws[:7] + ["aba"] + ws[8:]))  # three letters: not an abbreviation
    err(" ".join(ws[:2] + [ws[3], ws[2]] + ws[4:]))  # two swapped (if the checksum catches it)
    err(" ".join(ws[:-1] + [words[(words.index(ws[-1]) + 1) % 2048]]))
    err(" ".join(["Kite" if i == 9 else w for i, w in enumerate(ws)]))  # Kelvin sign: becomes "kite"
    err(b2h(SEED)[:-1])
    err("0X" + b2h(SEED)[2:])
    tokens = ["abandon", "ABANDON", "aban", "abando", "abandons", "aba", "act", "acti", "zoo", "zoo.", " zoo\n",
              "Kite", "Abİ", "wor", "worl", "world", "zz", "", "1.", "élève"]
    word_cases = [{"token": t, "word": phrase.word(t)} for t in tokens]
    match_cases = [{"position": p, "answer": a, "matches": phrase.matches(ws, p, a)}
                   for p, a in [(1, ws[0]), (1, ws[0][:4].upper()), (2, ws[0]), (24, ws[23]), (24, ""), (13, ws[12])]]
    codes = []
    for i, s in enumerate(SEEDS[:3]):
        key = k(f"device key {i}")
        o = addr(f"owner {i}")
        for d in (0, 1, 3):
            codes.append({"owner": o, "device": d, "key": b2h(key), "code": member.check_code(o, d, key)})
    return {"words": words, "spaces": spaces, "digits": digits, "round_trips": round_trips, "parses": parses,
            "errors": errors, "word_cases": word_cases, "match_cases": match_cases, "check_codes": codes}


# --- keys ---

GAS_KEY_LABEL = b"winterlock.app.gas.v1"  # the signer app's gas account (docs/notes/signer-app.md)


def gas_key(seed: bytes) -> dict:
    """The app's gas account for a phrase's seed: keccak256(abi.encode("winterlock.app.gas.v1", seed)), with the
    signer's own helpers, and its address"""
    key = member._abi_label(GAS_KEY_LABEL, seed)
    acct = Account(b2h(key))  # refuses 0 and keys >= n
    return {"gas_key": b2h(key), "gas_address": acct.address}


def key_vectors():
    out = []
    for s in SEEDS[:4]:
        mk = member.stateless_key(s)
        dk = member.stateless_key(s, member.DEVICE_KEY_LABEL)
        out.append({
            "seed": b2h(s),
            "member_key_seed": b2h(member._abi_label(member.MEMBER_KEY_LABEL, s)),
            "member_key": b2h(mk.public_key), "member_p": b2h(mk.p), "member_s": mk.s,
            "member_leaves_hash": b2h(keccak256(mk.kept_leaves_bytes())),
            "member_leaves_first": [b2h(x) for x in mk.levels[0][:3]],
            "owner": owner.owner_address(mk.public_key),
            "device_key_seed": b2h(member._abi_label(member.DEVICE_KEY_LABEL, s)),
            "device_key": b2h(dk.public_key),
            **gas_key(s),
        })
    trees = []
    for i, (dev, gen, start) in enumerate([(0, 0, 0), (1, 1, 7), (3, 65535, (1 << 40) - 1), (2, 2, 12345)]):
        o = addr(f"owner {i}")
        sf = addr(f"safe {i}")
        salt = k(f"salt {i}")
        rec = {"chain": CHAIN + i, "owner": o, "safe": sf, "device": dev, "gen": gen, "start": start, "salt": b2h(salt)}
        m = member.Member.__new__(member.Member)
        m._seed_value = SEED
        trees.append({**rec, "seed": b2h(SEED), "sk_seed": b2h(m._tree_sk_seed(rec)),
                      "tree_seed": b2h(owner.tree_seed(rec["chain"], o, sf, dev, gen, start).to_bytes(16, "big"))})
    return {"keys": out, "tree_secrets": trees}


# --- leanSphincs ---

def grind_tries(key, m):
    r0 = leansphincs.th(key.p, leansphincs.addr(leansphincs.RANDOMIZER, 0, 0, 0), key.seed + m)
    rho, _ = key._grind(m)
    return ((int.from_bytes(rho, "little") - int.from_bytes(r0, "little")) % (1 << 128)) + 1


def leansphincs_vectors():
    key = member.stateless_key(SEED)
    cands = [k(f"winterlock core vectors message {i}") for i in range(64)]
    tries = [grind_tries(key, m) for m in cands]
    order = sorted(range(len(cands)), key=lambda i: tries[i])
    picks = [order[0], order[len(order) // 2], order[len(order) // 4], order[-1]]  # short, typical, typical, long
    sigs = []
    for i in picks:
        m = cands[i]
        sig = key.sign(m)
        assert leansphincs.verify(key.public_key, m, sig)
        sigs.append({"message": b2h(m), "sig": b2h(sig), "grind_tries": tries[i],
                     "counter": int.from_bytes(sig[4240:4244], "little"),
                     "fors_indices": leansphincs.fors_indices(key.p, m, sig[:16])})
    small = leansphincs.Key(k("winterlock core vectors b6"), 6)
    m6 = k("winterlock core vectors b6 message")
    sig6 = small.sign(m6)
    return {"key_seed": b2h(member._abi_label(member.MEMBER_KEY_LABEL, SEED)), "b": key.b,
            "public_key": b2h(key.public_key), "signatures": sigs,
            "b6": {"key_seed": b2h(small.seed), "public_key": b2h(small.public_key), "message": b2h(m6),
                   "sig": b2h(sig6)}}


# --- WOTS ---

def tree_place(i=0):
    o = owner.owner_address(member.stateless_key(SEED).public_key)
    return {"chain": CHAIN, "owner": o, "safe": SAFE, "device": 0, "gen": 0, "start": 100 + i, "salt": b2h(SALT)}


def tree_material(rec, height):
    m = member.Member.__new__(member.Member)
    m._seed_value = SEED
    sk = m._tree_sk_seed(rec)
    seed = owner.tree_seed(rec["chain"], rec["owner"], rec["safe"], rec["device"], rec["gen"], rec["start"])
    return seed, sk, wots.Tree.create(seed, sk, height, workers=1)


def tx(nonce, i=0):
    return safe.SafeTx(to=addr(f"recipient {i}"), value=10 ** 15 * (i + 1), nonce=nonce)


def wots_vectors():
    out = {"params": wots.PARAMS, "trees": []}
    for height in (6, 10):
        rec = tree_place(height)
        seed, sk, tree = tree_material(rec, height)
        t = {"place": rec, "height": height, "tree_seed": b2h(seed.to_bytes(16, "big")), "sk_seed": b2h(sk),
             "root": b2h(tree.root), "leaves_hash": b2h(keccak256(b"".join(x[:24] for x in tree.levels[0]))),
             "leaves_first": [b2h(x[:24]) for x in tree.levels[0][:4]], "cache_hash": b2h(keccak256(tree.to_bytes())),
             "signatures": []}
        start = rec["start"]
        nonces = [(start, 0), (start, 1), (start + 1, 0), (start + (1 << (height - 1)) - 1, 1)]
        for j, (nonce, slot) in enumerate(nonces):
            st = tx(nonce, j)
            h = st.hash(rec["chain"], rec["safe"])
            ki = owner.key_index(nonce, start, slot, height)
            _, _, tries = wots.encode(seed, sk, ki, h, wots.Prf.SIGNER)
            sig = wots.sign(seed, sk, ki, h, wots.Prf.SIGNER)
            path = tree.path(ki)
            assert wots.verify_root(seed, ki, h, sig, path) == tree.root
            t["signatures"].append({"nonce": nonce, "slot": slot, "key_index": ki, "tx": safetx_json(st),
                                    "hash": b2h(h), "sig": b2h(sig), "path": b2h(path), "tries": tries,
                                    "data": b2h(owner.tx_signature_data(slot, 0, rec["safe"], st.words(), sig, path))})
        out["trees"].append(t)
    # single leaves and a partial test tree (k < height, fixed upper siblings, the test PRF)
    seed, sk = 0x0123456789ABCDEF0123456789ABCDEF, k("unit test tree")
    out["leaves"] = [{"seed": b2h(seed.to_bytes(16, "big")), "sk_seed": b2h(sk), "key_index": ki,
                      "signer": b2h(wots.leaf(seed, sk, ki, wots.Prf.SIGNER)[:24]),
                      "test": b2h(wots.leaf(seed, sk, ki, wots.Prf.TEST)[:24])} for ki in (0, 1, 31, (1 << 64) - 1)]
    pt = wots.Tree.create(seed, sk, 8, 4, prf=wots.Prf.TEST, workers=1)
    out["partial"] = {"seed": b2h(seed.to_bytes(16, "big")), "sk_seed": b2h(sk), "height": 8, "k": 4,
                      "root": b2h(pt.root), "path5": b2h(pt.path(5)), "cache": b2h(pt.to_bytes())}
    prf = []
    for p, name in ((wots.Prf.SIGNER, "signer"), (wots.Prf.TEST, "test")):
        prf.append({"prf": name, "secret": b2h(p.secret(sk, 7, 47)[:24]),
                    "randomizer": b2h(p.randomizer(sk, 7, k("m"), 12345)[:24]),
                    "sibling": b2h(p.upper_sibling(sk, 9)[:24])})
    out["prf"] = prf
    return out


# --- Safe ---

def safetx_json(t):
    return {"to": t.to, "value": str(t.value), "data": b2h(t.data), "operation": t.operation,
            "safe_tx_gas": str(t.safe_tx_gas), "base_gas": str(t.base_gas), "gas_price": str(t.gas_price),
            "gas_token": t.gas_token, "refund_receiver": t.refund_receiver, "nonce": str(t.nonce)}


def safe_vectors():
    erc20 = abi.calldata("transfer(address,uint256)", ["address", "uint256"], [addr("token recipient"), 12345 * 10 ** 6])
    txs = [
        safe.SafeTx(to=addr("recipient 0")),
        safe.SafeTx(to=addr("recipient 1"), value=10 ** 17, nonce=6),
        safe.SafeTx(to=addr("token"), data=erc20, nonce=7),
        safe.SafeTx(to=addr("multisend"), data=bytes(range(256)) * 3, operation=1, nonce=8),
        safe.SafeTx(to=addr("recipient 2"), value=(1 << 256) - 1, data=b"\x01", safe_tx_gas=100000, base_gas=21000,
                    gas_price=10 ** 9, gas_token=addr("gas token"), refund_receiver=addr("refund"),
                    nonce=(1 << 64) + 5),
    ]
    cases = []
    for t in txs:
        for chain in (1, 11155111, 42161, 421614):
            cases.append({"tx": safetx_json(t), "chain": chain, "safe": SAFE,
                          "words": [b2h(w) for w in t.words()], "struct_hash": b2h(t.struct_hash()),
                          "domain_separator": b2h(safe.domain_separator(chain, SAFE)), "hash": b2h(t.hash(chain, SAFE)),
                          "preimage": b2h(t.preimage(chain, SAFE))})
    msgs = []
    for i, h in enumerate([bytes(32), k("app hash 1"), eip712.personal_hash(b"Sign in to example.org")]):
        msgs.append({"chain": CHAIN, "safe": SAFE, "app_hash": b2h(h), "message_hash": b2h(messages.message_hash(h)),
                     "safe_message_hash": b2h(messages.safe_message_hash(CHAIN, SAFE, h))})
    personal = [{"message": b2h(m), "hash": b2h(eip712.personal_hash(m))}
                for m in (b"", b"hello", b"Sign in to example.org\nNonce: 42", bytes(1000))]
    amounts = [{"wei": str(v), "fmt": safe.fmt_eth(v)}
               for v in (0, 1, 999, 1000, 10 ** 17, 10 ** 18, 123456789012345678901, (1 << 256) - 1)]
    checksums = [checksum(k(f"address {i}")[12:]) for i in range(8)] + [owner.PROXY, SAFE]
    return {"cases": cases, "safe_messages": msgs, "personal": personal, "amounts": amounts, "checksums": checksums,
            "typehashes": {"domain": b2h(safe.DOMAIN_TYPEHASH), "safe_tx": b2h(safe.SAFE_TX_TYPEHASH),
                           "safe_message": b2h(messages.SAFE_MSG_TYPEHASH)}}


# --- owner v2 ---

def owner_vectors():
    o = owner.owner_address(member.stateless_key(SEED).public_key)
    key = member.stateless_key(SEED).public_key
    dkey = member.device_key_of(SEED)
    digests = []
    for dev in range(4):
        for gen in (0, 1, 65535):
            digests.append({"chain": CHAIN, "owner": o, "safe": SAFE, "device": dev, "generation": gen, "key": b2h(dkey),
                            "root": b2h(k("root")[:24]), "height": 10, "start": 12345,
                            "smh": b2h(k("safe message hash")),
                            "device_digest": b2h(owner.device_digest(CHAIN, o, dev, gen, dkey)),
                            "revocation_digest": b2h(owner.revocation_digest(CHAIN, o, dev, gen)),
                            "certificate_digest": b2h(owner.certificate_digest(CHAIN, o, SAFE, dev, gen, k("root")[:24],
                                                                               10, 12345)),
                            "message_digest": b2h(owner.message_digest(CHAIN, o, SAFE, dev, gen, k("safe message hash"))),
                            "tree_seed": b2h(owner.tree_seed(CHAIN, o, SAFE, dev, gen, 12345).to_bytes(16, "big"))})
    for chain, start, height in ((1, 0, 1), (42161, (1 << 40) - 1, 40), (11155111, 6, 6)):
        digests.append({"chain": chain, "owner": o, "safe": SAFE, "device": 2, "generation": 2, "key": b2h(dkey),
                        "root": b2h(bytes(range(24))), "height": height, "start": start, "smh": b2h(bytes(32)),
                        "device_digest": b2h(owner.device_digest(chain, o, 2, 2, dkey)),
                        "revocation_digest": b2h(owner.revocation_digest(chain, o, 2, 2)),
                        "certificate_digest": b2h(owner.certificate_digest(chain, o, SAFE, 2, 2, bytes(range(24)), height,
                                                                           start)),
                        "message_digest": b2h(owner.message_digest(chain, o, SAFE, 2, 2, bytes(32))),
                        "tree_seed": b2h(owner.tree_seed(chain, o, SAFE, 2, 2, start).to_bytes(16, "big"))})
    indices = []
    for nonce, start, slot, height in [(0, 0, 0, 1), (0, 0, 1, 1), (1, 0, 0, 1), (5, 5, 1, 6), (36, 5, 1, 6),
                                       (37, 5, 0, 6), (4, 5, 0, 6), (611, 100, 1, 10), (612, 100, 0, 10),
                                       ((1 << 40) - 1 + (1 << 39) - 1, (1 << 40) - 1, 1, 40), (7, 7, 2, 6)]:
        try:
            indices.append({"nonce": nonce, "start": start, "slot": slot, "height": height,
                            "index": owner.key_index(nonce, start, slot, height)})
        except ValueError as e:
            indices.append({"nonce": nonce, "start": start, "slot": slot, "height": height, "error": str(e)})
    addresses = []
    for s in SEEDS[:4]:
        mk = member.stateless_key(s).public_key
        addresses.append({"key": b2h(mk), "owner": owner.owner_address(mk),
                          "init_code": b2h(owner.proxy_init_code(owner.implementation_address(), mk)),
                          "runtime": b2h(owner.proxy_runtime(owner.implementation_address(), mk))})
    addresses.append({"key": b2h(k("any key")), "owner": owner.owner_address(k("any key")),
                      "init_code": b2h(owner.proxy_init_code(owner.implementation_address(), k("any key"))),
                      "runtime": b2h(owner.proxy_runtime(owner.implementation_address(), k("any key")))})
    # the three layouts, with real signatures
    rec = tree_place(6)
    seed, sk, tree = tree_material(rec, 6)
    st = safe.SafeTx(to=addr("recipient 0"), value=12345, data=b"\xca\xfe", nonce=rec["start"] + 3)
    h = st.hash(CHAIN, SAFE)
    ki = owner.key_index(st.nonce, rec["start"], 1, 6)
    sig = wots.sign(seed, sk, ki, h, wots.Prf.SIGNER)
    tx_data = owner.tx_signature_data(1, 2, SAFE, st.words(), sig, tree.path(ki))
    app_hash = k("an app's hash")
    mkey = member.stateless_key(SEED)
    smh = messages.safe_message_hash(CHAIN, SAFE, app_hash)
    md = owner.message_digest(CHAIN, o, SAFE, 0, 0, smh)
    msig = mkey.sign(md)
    msg_data = owner.message_signature_data(0, SAFE, messages.message_hash(app_hash), msig)
    appr = owner.approved_signature_data(SAFE, messages.message_hash(app_hash))
    parsed = owner.parse_tx_signature_data(tx_data)
    layouts = {"tx": {"tree": rec, "tx": safetx_json(st), "slot": 1, "device": 2, "key_index": ki, "hash": b2h(h),
                      "data": b2h(tx_data), "root": b2h(tree.root),
                      "parsed": {"slot": parsed[0], "device": parsed[1], "safe": parsed[2],
                                 "words": [b2h(w) for w in parsed[3]], "sig": b2h(parsed[4]), "path": b2h(parsed[5])}},
               "message": {"app_hash": b2h(app_hash), "safe_message_hash": b2h(smh), "digest": b2h(md),
                           "owner": o, "device": 0, "generation": 0, "data": b2h(msg_data)},
               "approved": {"msg_hash": b2h(messages.message_hash(app_hash)), "data": b2h(appr)},
               "not_tx": [b2h(tx_data[:-1]), b2h(bytes([2]) + tx_data[1:]), b2h(tx_data[:1] + bytes([4]) + tx_data[2:]),
                          b2h(tx_data[:owner.TX_HEADER + wots.SIG_BYTES - 1])]}
    pinned = {"proxy": owner.PROXY, "verifier": owner.verifier_address(), "wots_verifier": owner.wots_verifier_address(),
              "implementation": owner.implementation_address(), "factory": owner.factory_address(),
              "commit": owner.PINNED_COMMIT, "params": wots.PARAMS}
    domains = {n: b2h(getattr(owner, n)) for n in ("DEVICE_DOMAIN", "REVOCATION_DOMAIN", "CERTIFICATE_DOMAIN",
                                                   "MESSAGE_DOMAIN", "TREE_SEED_DOMAIN", "VERIFIER_SALT",
                                                   "WOTS_VERIFIER_SALT", "IMPLEMENTATION_SALT", "FACTORY_SALT")}
    member_code = owner.proxy_runtime(owner.implementation_address(), key)
    member_of = [{"address": o, "code": b2h(member_code), "key": b2h(owner.member_key_of(o, member_code))},
                 {"address": addr("elsewhere"), "code": b2h(member_code), "key": None},
                 {"address": o, "code": b2h(member_code[:-1]), "key": None}]
    return {"digests": digests, "key_indices": indices, "addresses": addresses, "layouts": layouts, "pinned": pinned,
            "domains": domains, "member_key_of": member_of}


# --- key log ---

SCENARIOS = [
    ("first, second, third version at a nonce",
     [("sign", 100, "a"), ("sign", 100, "a"), ("sign", 100, "b"), ("sign", 100, "b"), ("sign", 100, "a"),
      ("sign", 100, "c"), ("sign", 101, "c")]),
    ("explicit slots: reuse refused, the same hash again allowed",
     [("record", 102, 1, "a"), ("sign", 102, "b"), ("sign", 102, "a"), ("record", 102, 1, "c"), ("record", 102, 0, "b"),
      ("record", 102, 0, "c"), ("sign", 102, "c")]),
    ("nonces outside the tree, and a bad slot",
     [("sign", 99, "a"), ("sign", 131, "a"), ("sign", 132, "a"), ("record", 110, 2, "a"), ("sign", 110, "a")]),
    ("trees, Safes and chains are separate",
     [("sign", 100, "a", 0), ("sign", 100, "b", 1), ("sign", 100, "c", 2), ("sign", 100, "d", 3), ("sign", 100, "e", 0),
      ("sign", 100, "f", 0), ("sign", 100, "a", 1)]),
]


def keylog_trees():
    base = {"chain": CHAIN, "safe": SAFE, "root": b2h(k("tree root 0")[:24]), "start": 100, "height": 6}
    return [base,
            {**base, "root": b2h(k("tree root 1")[:24])},
            {**base, "safe": addr("another safe")},
            {**base, "chain": CHAIN + 1}]


def keylog_vectors():
    trees = keylog_trees()
    out = []
    for name, steps in SCENARIOS:
        with tempfile.TemporaryDirectory() as d:
            log = KeyLog(os.path.join(d, "keylog.jsonl"))
            done = []
            for st in steps:
                if st[0] == "sign":
                    nonce, hl, t = st[1], st[2], st[3] if len(st) > 3 else 0
                    slot = None
                else:
                    nonce, slot, hl, t = st[1], st[2], st[3], 0
                tree = trees[t]
                hx = b2h(k(f"hash {hl}"))
                step = {"op": st[0], "tree": t, "nonce": nonce, "hash": hx}
                if slot is not None:
                    step["slot"] = slot
                before = len(log.records)
                try:
                    if slot is None:
                        slot_, already = log.pick_slot(tree["chain"], tree["safe"], tree, nonce, hx)
                        step["expect"] = {"slot": slot_, "already": already}
                        log.record_sign(tree["chain"], tree["safe"], tree, nonce, slot_, hx)
                    else:
                        log.record_sign(tree["chain"], tree["safe"], tree, nonce, slot, hx)
                        step["expect"] = {"slot": slot, "already": len(log.records) == before}
                    step["expect"]["appended"] = len(log.records) > before
                except Refused as e:
                    m = str(e)
                    step["expect"] = {"refused": "third-version" if m.startswith("both keys") else "key-reused"}
                except ValueError:
                    step["expect"] = {"refused": "not-in-tree"}
                done.append(step)
            uses = [{"chain": r["chain"], "safe": r["safe"], "root": r["root"], "start": r["start"], "nonce": r["nonce"],
                     "slot": r["slot"], "key_index": r["key"], "hash": r["hash"]} for r in log.signs()]
            log.close()
        out.append({"name": name, "steps": done, "uses": uses})
    return {"trees": trees, "scenarios": out}


# --- HBKD (draft ERC: Hash-Based Key Derivation from BIP-39) ---

def _hbkd_words(entropy: bytes) -> list:
    return phrase._M.to_mnemonic(entropy).split()


HBKD_PHRASES = [  # (words, passphrase): every length BIP-39 has, each with a checksum that holds
    (("abandon " * 23 + "art").split(), ""),  # the ERC's test cases
    (("abandon " * 23 + "art").split(), "TREZOR"),
    ("legal winner thank year wave sausage worth useful legal winner thank yellow".split(), "TREZOR"),
    (("abandon " * 11 + "about").split(), ""),
    (_hbkd_words(bytes(range(20))), "x"),  # 15 words
    (_hbkd_words(bytes([0xFF] * 24)), ""),  # 18 words
    (_hbkd_words(k("winterlock core vectors hbkd 21 words")[:28]), "TREZOR"),  # 21 words
    (("zoo " * 23 + "vote").split(), "a passphrase, with spaces & punctuation!"),
    (("abandon " * 23 + "art").split(), "\x00\t\x7f"),  # ASCII control characters in a passphrase are hashed
]
_ABANDON = ("abandon " * 23 + "art").split()
HBKD_BAD_MNEMONICS = [  # refused on both sides: not canonical, a word outside the list, or a failed checksum
    ["abandon"] * 24,  # the ERC's: the checksum fails
    _ABANDON[:22] + ["art", "abandon"],  # two words swapped
    _ABANDON[:11], _ABANDON + ["abandon"], [],  # 11, 25 and 0 words
    "legal winner thank year wave sausage worth useful legal winner thank yellow abandon".split(),  # 13
    [w.upper() for w in _ABANDON], ["Abandon"] + _ABANDON[1:],  # case
    ["aban"] + _ABANDON[1:],  # an abbreviation
    _ABANDON[:-1] + ["art "], _ABANDON[:-1] + [""], ["abandon abandon"] + _ABANDON[2:],  # spacing
    _ABANDON[:-1] + ["\xe1rt"], ["\u3042\u3044\u3053\u304f\u3057\u3093"] * 24,  # not words of the English list
]
HBKD_KEY_TYPES = ["leanSphincs-keccak/wambsgans-keccak/b10",
                  "a-key-type,with_punctuation:!\"#$%&'()*+,-./;<=>?@[\\]^_`{|}~", "!", "k" * 200]
HBKD_ACCOUNTS = [0, 1, 1 << 31, (1 << 32) - 1]
HBKD_LABELS = ["example.app.gas", "", "winterlock.app.gas.v1", "a label with spaces", "app.\xfcn\xefc\xf8d\xe9.\u4f8b",
               "u\u0308", "l" * 200]
HBKD_STATEFUL = [  # (context, instance)
    (bytes(range(32)), bytes([0xA5] * 32)),
    (bytes(32), bytes(32)),
    (k("winterlock core vectors hbkd context"), k("winterlock core vectors hbkd instance")),
    (bytes([0xFF] * 32), bytes(range(32, 64))),
]
HBKD_BAD_KEY_TYPES = ["", " ", "leanSphincs keccak", "leanSphincs-keccak/wambsgans-keccak/b10 ", "\t", "line\nbreak",
                      "\x00", "\x1f", "\x7f", "caf\xe9", "no\xa0break", "\u3000"]
HBKD_NON_ASCII = [  # (words, passphrase): Python normalises the passphrase (NFKD); the core refuses it
    (_ABANDON, "p\xe4ssphr\xe4se"),
    (_ABANDON, "pa\u0308ssphra\u0308se"),
    (_ABANDON, "\ufb01"),  # the ligature fi: "fi" after NFKD
    ("legal winner thank year wave sausage worth useful legal winner thank yellow".split(), "TREZOR\u3000"),
]


def hbkd_vectors():
    phrases = []
    for ws, p in HBKD_PHRASES:
        s = hbkd.bip39_seed(ws, p)
        phrases.append({"words": ws, "passphrase": p, "bip39_seed": b2h(s), "root": b2h(hbkd.root_from_seed(s))})
    assert sorted({len(c["words"]) for c in phrases}) == list(hbkd.WORD_COUNTS)
    for ws in HBKD_BAD_MNEMONICS:
        try:
            hbkd.bip39_seed(ws)
        except ValueError:
            continue
        raise AssertionError(f"accepted mnemonic {ws!r}")
    winterlock = []
    for s in SEEDS:
        for p in ("", "TREZOR"):
            winterlock.append({"seed": b2h(s), "passphrase": p, "words": " ".join(phrase.to_phrase(s)),
                               "root": b2h(hbkd.winterlock_root(s, p))})
    roots = [h2b(phrases[0]["root"]), h2b(phrases[2]["root"]), hbkd.winterlock_root(SEED),
             k("winterlock core vectors hbkd random root"), bytes(range(0x20, 0x40))]
    stateless, stateful, apps = [], [], []
    for r in roots:
        for t in HBKD_KEY_TYPES:
            for a in HBKD_ACCOUNTS:
                stateless.append({"root": b2h(r), "key_type": t, "account": a,
                                  "seed": b2h(hbkd.stateless_seed(r, t, a))})
        for i, (c, n) in enumerate(HBKD_STATEFUL):
            t, a = HBKD_KEY_TYPES[i % len(HBKD_KEY_TYPES)], HBKD_ACCOUNTS[(i + 1) % len(HBKD_ACCOUNTS)]
            stateful.append({"root": b2h(r), "key_type": t, "account": a, "context": b2h(c), "instance": b2h(n),
                             "seed": b2h(hbkd.stateful_seed(r, t, c, n, a))})
        for lb in HBKD_LABELS:
            for a in (0, (1 << 32) - 1):
                apps.append({"root": b2h(r), "label": lb, "account": a, "secret": b2h(hbkd.app_secret(r, lb, a))})
    for t in HBKD_BAD_KEY_TYPES:
        try:
            hbkd.stateless_seed(roots[0], t)
        except ValueError:
            continue
        raise AssertionError(f"accepted key type {t!r}")
    non_ascii = []
    for ws, p in HBKD_NON_ASCII:
        non_ascii.append({"words": ws, "passphrase": p, "nfkd_passphrase": unicodedata.normalize("NFKD", p),
                          "bip39_seed": b2h(hbkd.bip39_seed(ws, p))})
    return {"phrases": phrases, "bad_mnemonics": HBKD_BAD_MNEMONICS, "winterlock": winterlock,
            "stateless": stateless, "stateful": stateful, "app_secrets": apps, "bad_key_types": HBKD_BAD_KEY_TYPES,
            "non_ascii": non_ascii}


# --- the board's subset ---

def board_vectors(ph, keys, ls, wv, sv, ov, kl):
    words = phrase.to_phrase(SEED)
    k0 = keys["keys"][3]
    assert k0["seed"] == b2h(SEED)
    h6 = wv["trees"][0]
    h10 = wv["trees"][1]
    d = ov["digests"][4]  # device 1, generation 1
    code = ph["check_codes"][1]
    return {
        "phrase": " ".join(f"{i + 1}. {w.upper()}" for i, w in enumerate(words)), "seed": b2h(SEED),
        "member_key_seed": k0["member_key_seed"], "member_key": k0["member_key"], "owner": k0["owner"],
        "device_key": k0["device_key"],
        "stateless": [{"message": s["message"], "sig": s["sig"], "grind_tries": s["grind_tries"]}
                      for s in ls["signatures"]],
        "h6": {"place": h6["place"], "tree_seed": h6["tree_seed"], "sk_seed": h6["sk_seed"], "root": h6["root"],
               "signatures": h6["signatures"]},
        "h10": {"place": h10["place"], "tree_seed": h10["tree_seed"], "sk_seed": h10["sk_seed"], "root": h10["root"],
                "signatures": h10["signatures"]},
        "safetx": [sv["cases"][15], sv["cases"][19]],  # a delegatecall with data; every field nonzero
        "device_digest": {k_: d[k_] for k_ in ("chain", "owner", "device", "generation", "key", "device_digest")},
        "check_code": code,
        "keylog": {"trees": kl["trees"], "scenario": kl["scenarios"][0]},
    }


def main():
    ph = phrase_vectors()
    write("phrase.json", ph)
    keys = key_vectors()
    write("keys.json", keys)
    ls = leansphincs_vectors()
    write("leansphincs.json", ls)
    wv = wots_vectors()
    write("wots.json", wv)
    sv = safe_vectors()
    write("safe.json", sv)
    ov = owner_vectors()
    write("owner.json", ov)
    kl = keylog_vectors()
    write("keylog.json", kl)
    write("board.json", board_vectors(ph, keys, ls, wv, sv, ov, kl))
    write("hbkd.json", hbkd_vectors())
    print(f"Python {sys.version.split()[0]}, Unicode {unicodedata.unidata_version}")


if __name__ == "__main__":
    main()
