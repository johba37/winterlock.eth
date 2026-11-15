#!/usr/bin/env python3
"""Known answers of the board's USB link from the Python client (board_client.py), for the app's TypeScript client:
the two CRCs, a frame of every message type, the request payloads the client builds, answers as it parses them, and a
noisy stream with the frames and noise its reader finds. Deterministic: run it again and the file doesn't change.

usage: python3 -I hardware/board-signer/tools/frame_vectors.py   (writes logic/tests/vectors/frames.json)
"""
import binascii
import json
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import board_client as bc  # noqa: E402

OUT = os.path.join(os.path.dirname(HERE), "logic", "tests", "vectors", "frames.json")


def det(label: str, n: int) -> bytes:
    """n deterministic bytes from a label (CRC-32 as a counter-mode stream: test data, not randomness)"""
    out = b""
    i = 0
    while len(out) < n:
        out += struct.pack(">I", zlib.crc32(f"{label}/{i}".encode()) & 0xFFFFFFFF)
        i += 1
    return out[:n]


def h(b: bytes) -> str:
    return b.hex()


def fake_link():
    """A Board whose sends are kept, not written: the payloads the client builds"""
    class Link:
        def __init__(self):
            self.sent = []

        def write(self, data):
            self.sent.append(data)

        def read(self):
            return b""

        def close(self):
            pass
    return Link()


def main():
    v = {"note": "from hardware/board-signer/tools/frame_vectors.py (the Python client, board_client.py)"}

    # --- checksums ---
    inputs = [b"", b"123456789", b"\xa5WLZ", det("crc", 61), det("crc-long", 1000)]
    v["crc"] = [{"data": h(d), "crc16": binascii.crc_hqx(d, 0xFFFF), "crc32": zlib.crc32(d) & 0xFFFFFFFF}
                for d in inputs]

    # --- frames ---
    frames = []
    for ty, ident, payload in [
        (bc.STATUS, 1, b""),
        (bc.SETUP, 2, det("app random", 32)),
        (bc.RECOVER, 3, b""),
        (bc.GAS_KEY, 4, b""),
        (bc.TREES, 5, b""),
        (bc.CANCEL, 0xFFFF, b""),
        (bc.TEST_BUTTONS, 0x1234, bytes([1, 2, 3, 3])),
        (bc.A_DONE, 9, b""),
        (bc.EV_BOOTED, 0, det("booted", 60)),
        (bc.A_ERROR, 7, bytes([10]) + bytes([26]) + b"delegate calls are refused"),
        (bc.A_SIGNED, 300, det("signed", 1801)),
        (bc.A_ENROLLED, 301, det("enrolled", 61 + 5684)),
        (bc.SIGN, 302, det("max", bc.MAX_PAYLOAD)),
    ]:
        frames.append({"type": ty, "id": ident, "payload": h(payload), "frame": h(bc.encode(ty, ident, payload))})
    v["frames"] = frames

    # --- request payloads, as the client builds them ---
    b = bc.Board(fake_link())
    safe = det("safe", 20)
    parent_safe = det("parent", 20)
    bob = det("bob", 20)
    root = det("root", 24)
    tx = bc.encode_tx(bob, value=25 * 10**16, nonce=7)
    approve = bc.encode_tx(parent_safe, data=bytes.fromhex("d4d9bdcd") + det("parent hash", 32), nonce=8)
    parent = bc.encode_tx(bob, value=10**17, nonce=3, data=b"", operation=0, safe_tx_gas=1, base_gas=2, gas_price=3,
                          gas_token=det("gas token", 20), refund_receiver=det("receiver", 20))
    requests = []

    def took(name, args):
        raw = b.link.sent[-1]
        d = bc.Deframer()
        d.push(raw)
        f = d.next()
        requests.append({"name": name, "args": args, "type": f.ty, "id": f.id, "payload": h(f.payload),
                         "frame": h(raw)})

    b.setup(det("app random", 32))
    took("setup", {"appRandom": h(det("app random", 32))})
    b.recover()
    took("recover", {})
    b.enrol(11155111, safe, 12)
    took("enrol", {"chain": 11155111, "safe": h(safe), "start": 12})
    b.sign(11155111, safe, tx)
    took("sign", {"chain": 11155111, "safe": h(safe), "tx": h(tx), "parent": "", "root": h(bytes(24))})
    b.sign(42161, safe, approve, parent=parent, root=root)
    took("sign", {"chain": 42161, "safe": h(safe), "tx": h(approve), "parent": h(parent), "root": h(root)})
    v["requests"] = requests
    v["transactions"] = [
        {"fields": {"to": h(bob), "value": str(25 * 10**16), "nonce": 7}, "encoded": h(tx)},
        {"fields": {"to": h(parent_safe), "data": "d4d9bdcd" + h(det("parent hash", 32)), "nonce": 8},
         "encoded": h(approve)},
        {"fields": {"to": h(bob), "value": str(10**17), "nonce": 3, "safeTxGas": 1, "baseGas": 2, "gasPrice": 3,
                    "gasToken": h(det("gas token", 20)), "refundReceiver": h(det("receiver", 20))},
         "encoded": h(parent)},
    ]

    # --- answers, as the client parses them ---
    member_key, owner = det("member key", 32), det("owner", 20)
    version = b"0.1.0 WINTERLOCK-TEST-HOOKS"
    status = (bytes([1, len(version)]) + version + bytes([2, 1, 3]) + member_key + owner
              + struct.pack(">HIII", 2, 123456, 3080192, 5))
    st = bc.Board.parse_status(status)
    signed = bytes([1]) + struct.pack(">Q", 513) + det("hash", 32) + struct.pack(">H", 1758) + det("data", 1758)
    sg = bc.Board.parse_signed(bc.Frame(1, bc.A_SIGNED, 1, signed))
    enrolled = (struct.pack(">Q", 11155111) + safe + struct.pack(">Q", 12) + bytes([10]) + root + det("cert", 5684))
    en = bc.Board.parse_enrolled(bc.Frame(1, bc.A_ENROLLED, 1, enrolled))
    trees = struct.pack(">H", 2)
    for i in range(2):
        trees += (struct.pack(">Q", 11155111) + det(f"tree safe {i}", 20) + struct.pack(">Q", 512 * i)
                  + bytes([10]) + det(f"tree root {i}", 24) + struct.pack(">H", 3 * i) + bytes([i]))

    class OneTrees(bc.Board):
        def call(self, ty, payload=b"", timeout=60.0):
            return bc.Frame(1, bc.A_TREES, 1, trees)
    tr = OneTrees(fake_link()).trees()
    identity = member_key + owner + bytes([1])
    idn = bc.Board.parse_identity(bc.Frame(1, bc.A_IDENTITY, 1, identity))
    err = bytes([5]) + bytes([len(b"enter the PIN on the board first")]) + b"enter the PIN on the board first"
    hexify = lambda d: {k: (h(x) if isinstance(x, bytes) else x) for k, x in d.items()}  # noqa: E731
    v["answers"] = {
        "status": {"payload": h(status), "parsed": hexify(st)},
        "signed": {"payload": h(signed), "parsed": hexify(sg)},
        "enrolled": {"payload": h(enrolled), "parsed": hexify(en)},
        "trees": {"payload": h(trees), "parsed": [hexify(t) for t in tr]},
        "identity": {"payload": h(identity), "parsed": hexify(idn)},
        "error": {"payload": h(err), "code": 5, "codeName": bc.CODES[5], "text": "enter the PIN on the board first"},
    }

    # --- a noisy stream ---
    good1 = bc.encode(bc.EV_BOOTED, 0, status)
    good2 = bc.encode(bc.A_SIGNED, 40, signed)
    good3 = bc.encode(bc.A_DONE, 41)
    bad = bytearray(bc.encode(bc.A_TREES, 42, trees))
    bad[20] ^= 1  # a damaged payload byte: the CRC-32 fails
    badhead = bytearray(bc.encode(bc.A_DONE, 43))
    badhead[11] ^= 0xFF  # a damaged header CRC
    inner = bc.encode(bc.A_DONE, 44)
    outer = bytearray(bc.encode(bc.SIGN, 45, bytes(40)))
    outer[bc.HEADER + 2:bc.HEADER + 2 + len(inner)] = inner  # a whole frame inside a damaged one
    boot = (b"ets Jun  8 2016 00:22:57\r\n\r\nrst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)\r\n"
            b"configsip: 0, SPIWP:0xee\r\nload:0x3fff0030,len:7104\r\nentry 0x40080400\r\n\xa5W")
    stream = boot + good1 + bytes(bad) + b"I (31) boot: ESP-IDF\r\n" + bytes(badhead) + good2 + bytes(outer) + good3
    # cut where the reader must wait for more
    cuts = [len(boot) - 1, len(boot) + 5, len(boot) + len(good1) + 30, len(stream) - 3]
    d = bc.Deframer()
    found = []
    last = 0
    for c in cuts + [len(stream)]:
        d.push(stream[last:c])
        last = c
        while (f := d.next()) is not None:
            found.append({"type": f.ty, "id": f.id, "payload": h(f.payload)})
    v["stream"] = {"bytes": h(stream), "chunks": cuts, "frames": found, "noise": h(bytes(d.noise)),
                   "held": len(d.buf)}

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(v, f, indent=1)
        f.write("\n")
    print(f"wrote {OUT}: {len(frames)} frames, {len(requests)} requests, {len(found)} frames from the stream")


if __name__ == "__main__":
    main()
