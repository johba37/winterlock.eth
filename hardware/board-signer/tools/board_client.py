#!/usr/bin/env python3
"""A client for the board signer's USB link (hardware/board-signer/PROTOCOL.md): framed messages over the board's
serial port, or over QEMU's serial port on TCP. Standard library only; pyserial for a real port.

  python3 board_client.py --tcp 127.0.0.1:5555 status
  python3 board_client.py --serial /dev/ttyUSB0 status
  python3 board_client.py --tcp 127.0.0.1:5555 screen          (test builds only)
  python3 board_client.py --tcp 127.0.0.1:5555 press RRB       (test builds only: Right, Right, Both)

As a library: Board(TcpLink(host, port)) or Board(SerialLink(device)); see the methods below.
"""
import binascii
import socket
import struct
import sys
import time
import zlib

MAGIC = b"\xa5WLZ"
VERSION = 1
HEADER = 12
MAX_PAYLOAD = 16 * 1024

# requests
STATUS, SETUP, RECOVER, GAS_KEY, TREES, ENROL, SIGN, CANCEL = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
TEST_BUTTONS, TEST_SCREEN, TEST_MEMORY, TEST_STALL = 0x70, 0x71, 0x72, 0x73
# answers and events
A_STATUS, A_IDENTITY, A_GAS_KEY, A_TREES, A_ENROLLED, A_SIGNED, A_DONE, A_ERROR = (0x81, 0x82, 0x84, 0x85, 0x86, 0x87,
                                                                                   0x88, 0x8F)
EV_BOOTED, A_SCREEN, A_MEMORY = 0xA0, 0xF0, 0xF1

CODES = {1: "unknown type", 2: "bad payload", 3: "bad version", 4: "busy", 5: "locked", 6: "not set up",
         7: "already set up", 8: "rejected", 9: "cancelled", 10: "refused", 11: "storage", 12: "storage full",
         13: "damaged"}
STATES = {0: "blank", 1: "locked", 2: "ready", 3: "damaged"}
BUTTONS = {"L": 1, "R": 2, "B": 3}


def encode(ty: int, ident: int, payload: bytes = b"") -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too long")
    head = struct.pack(">BBHH", VERSION, ty, ident, len(payload))
    hcrc = binascii.crc_hqx(head, 0xFFFF)
    body = head + struct.pack(">H", hcrc) + payload
    return MAGIC + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


class Frame:
    def __init__(self, version, ty, ident, payload):
        self.version, self.ty, self.id, self.payload = version, ty, ident, payload

    def __repr__(self):
        return f"Frame(type={self.ty:#04x}, id={self.id}, {len(self.payload)} bytes)"


class Deframer:
    """Frames out of a byte stream that also carries the bootloader's text and, in test builds, log lines. Whatever
    isn't a checked frame is kept in `noise`."""

    def __init__(self):
        self.buf = bytearray()
        self.noise = bytearray()

    def push(self, data: bytes):
        self.buf += data

    def _skip(self, n):
        self.noise += self.buf[:n]
        del self.buf[:n]

    def next(self):
        while True:
            i = self.buf.find(MAGIC)
            if i < 0:
                keep = next((k for k in (3, 2, 1) if self.buf.endswith(MAGIC[:k])), 0)
                self._skip(len(self.buf) - keep)
                return None
            self._skip(i)
            if len(self.buf) < HEADER:
                return None
            version, ty, ident, n, hcrc = struct.unpack(">BBHHH", self.buf[4:12])
            if binascii.crc_hqx(bytes(self.buf[4:10]), 0xFFFF) != hcrc or n > MAX_PAYLOAD:
                self._skip(1)
                continue
            if len(self.buf) < HEADER + n + 4:
                return None
            (crc,) = struct.unpack(">I", self.buf[HEADER + n:HEADER + n + 4])
            if zlib.crc32(bytes(self.buf[4:HEADER + n])) & 0xFFFFFFFF != crc:
                self._skip(1)
                continue
            f = Frame(version, ty, ident, bytes(self.buf[HEADER:HEADER + n]))
            del self.buf[:HEADER + n + 4]
            return f

    def stalled(self):
        if self.buf.startswith(MAGIC):
            self._skip(1)


class TcpLink:
    def __init__(self, host, port, connect_timeout=30):
        deadline = time.time() + connect_timeout
        while True:
            try:
                self.sock = socket.create_connection((host, port), timeout=5)
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.1)
        self.sock.settimeout(0.05)

    def write(self, data: bytes):
        self.sock.sendall(data)

    def read(self) -> bytes:
        try:
            d = self.sock.recv(65536)
            if d == b"":
                raise ConnectionError("the board's link closed")
            return d
        except socket.timeout:
            return b""

    def close(self):
        self.sock.close()


class SerialLink:
    def __init__(self, device, baud=115200):
        import serial  # pyserial
        # DTR and RTS low: the board's auto-reset circuit doesn't restart it or enter the bootloader
        self.port = serial.Serial(device, baud, timeout=0.05, dsrdtr=False, rtscts=False)
        self.port.dtr = False
        self.port.rts = False

    def write(self, data: bytes):
        self.port.write(data)
        self.port.flush()

    def read(self) -> bytes:
        return self.port.read(4096)

    def close(self):
        self.port.close()


class BoardError(Exception):
    def __init__(self, code, text):
        super().__init__(f"{CODES.get(code, code)}: {text}")
        self.code, self.text = code, text


def _text(b: bytes, at: int):
    n = b[at]
    return b[at + 1:at + 1 + n].decode(), at + 1 + n


def encode_tx(to, value=0, data=b"", operation=0, safe_tx_gas=0, base_gas=0, gas_price=0, gas_token=bytes(20),
              refund_receiver=bytes(20), nonce=0) -> bytes:
    """The app's SafeTx encoding: to | value | operation | safeTxGas | baseGas | gasPrice | gasToken |
    refundReceiver | nonce | data."""
    def a(x):
        return bytes.fromhex(x[2:]) if isinstance(x, str) else bytes(x)

    def w(x):
        return int(x).to_bytes(32, "big")
    return (a(to) + w(value) + bytes([operation]) + w(safe_tx_gas) + w(base_gas) + w(gas_price) + a(gas_token)
            + a(refund_receiver) + w(nonce) + bytes(data))


class Board:
    def __init__(self, link, log=None):
        self.link = link
        self.d = Deframer()
        self.frames = []  # received and not yet taken
        self.events = []
        self.next_id = 1
        self.log = log

    def close(self):
        self.link.close()

    # --- the link ---

    def _pump(self, timeout):
        """Reads for up to `timeout` seconds, or until at least one frame came."""
        end = time.time() + timeout
        quiet_since = time.time()
        while True:
            data = self.link.read()
            if data:
                self.d.push(data)
                quiet_since = time.time()
            elif self.d.buf and time.time() - quiet_since > 0.5:
                self.d.stalled()
            got = False
            while (f := self.d.next()) is not None:
                if f.ty == EV_BOOTED:
                    self.events.append(f)
                else:
                    self.frames.append(f)
                got = True
            if self.log and self.d.noise:
                self.log(bytes(self.d.noise))
                self.d.noise.clear()
            if got or time.time() > end:
                return

    def send(self, ty: int, payload: bytes = b"") -> int:
        ident = self.next_id
        self.next_id = self.next_id % 0xFFFF + 1
        self.link.write(encode(ty, ident, payload))
        return ident

    def wait(self, ident: int, timeout=60.0) -> Frame:
        end = time.time() + timeout
        while True:
            for f in self.frames:
                if f.id == ident:
                    self.frames.remove(f)
                    if f.ty == A_ERROR:
                        code = f.payload[0]
                        text, _ = _text(f.payload, 1)
                        raise BoardError(code, text)
                    return f
            left = end - time.time()
            if left <= 0:
                raise TimeoutError(f"no answer to request {ident} in {timeout} s")
            self._pump(min(left, 0.5))

    def call(self, ty, payload=b"", timeout=60.0) -> Frame:
        return self.wait(self.send(ty, payload), timeout)

    def wait_booted(self, timeout=60.0):
        end = time.time() + timeout
        while not self.events:
            if time.time() > end:
                raise TimeoutError("the board didn't say it started")
            self._pump(0.5)
        return self.parse_status(self.events.pop(0).payload)

    # --- requests ---

    @staticmethod
    def parse_status(p: bytes) -> dict:
        proto = p[0]
        version, at = _text(p, 1)
        state, busy, flags = p[at], p[at + 1], p[at + 2]
        at += 3
        member_key, owner = p[at:at + 32], p[at + 32:at + 52]
        at += 52
        trees, used, size, stateless = struct.unpack(">HIII", p[at:at + 14])
        return {"protocol": proto, "version": version, "state": STATES.get(state, state), "busy": bool(busy),
                "test_hooks": bool(flags & 1), "recovered": bool(flags & 2), "member_key": member_key,
                "owner": owner, "trees": trees, "storage_used": used, "storage_size": size,
                "stateless_signatures": stateless}

    def status(self) -> dict:
        return self.parse_status(self.call(STATUS).payload)

    def setup(self, app_random: bytes) -> int:
        """Starts a setup; the member goes through it on the board. Returns the request id: wait() for it."""
        assert len(app_random) == 32
        return self.send(SETUP, app_random)

    def recover(self) -> int:
        return self.send(RECOVER)

    @staticmethod
    def parse_identity(f: Frame) -> dict:
        p = f.payload
        return {"member_key": p[:32], "owner": p[32:52], "recovered": p[52] == 1}

    def gas_key(self) -> bytes:
        return self.call(GAS_KEY).payload

    def trees(self) -> list:
        p = self.call(TREES).payload
        (n,) = struct.unpack(">H", p[:2])
        out, at = [], 2
        for _ in range(n):
            chain, = struct.unpack(">Q", p[at:at + 8])
            safe = p[at + 8:at + 28]
            start, = struct.unpack(">Q", p[at + 28:at + 36])
            height = p[at + 36]
            root = p[at + 37:at + 61]
            used, = struct.unpack(">H", p[at + 61:at + 63])
            certified = p[at + 63] == 1
            out.append({"chain": chain, "safe": safe, "start": start, "height": height, "root": root,
                        "used": used, "certified": certified})
            at += 64
        return out

    def enrol(self, chain: int, safe: bytes, start: int) -> int:
        return self.send(ENROL, struct.pack(">Q", chain) + bytes(safe) + struct.pack(">Q", start))

    @staticmethod
    def parse_enrolled(f: Frame) -> dict:
        p = f.payload
        chain, = struct.unpack(">Q", p[:8])
        start, = struct.unpack(">Q", p[28:36])
        return {"chain": chain, "safe": p[8:28], "start": start, "height": p[36], "root": p[37:61],
                "signature": p[61:]}

    def sign(self, chain: int, safe: bytes, tx: bytes, parent: bytes = b"", root: bytes = bytes(24)) -> int:
        """tx and parent in encode_tx's encoding. Returns the request id: the member confirms on the board."""
        p = struct.pack(">Q", chain) + bytes(safe) + bytes(root)
        p += struct.pack(">H", len(tx)) + tx + struct.pack(">H", len(parent)) + parent
        return self.send(SIGN, p)

    @staticmethod
    def parse_signed(f: Frame) -> dict:
        p = f.payload
        slot = p[0]
        key_index, = struct.unpack(">Q", p[1:9])
        h = p[9:41]
        n, = struct.unpack(">H", p[41:43])
        return {"slot": slot, "key_index": key_index, "hash": h, "data": p[43:43 + n]}

    def cancel(self):
        return self.call(CANCEL)

    # --- test builds only ---

    @staticmethod
    def parse_screen(p: bytes) -> list:
        n, at, out = p[0], 1, []
        for _ in range(n):
            s, at = _text(p, at)
            out.append(s)
        return out

    def press(self, events: str, timeout=600.0) -> list:
        """Presses buttons ("L", "R", "B" for both) and returns the screen's text after them."""
        lines = None
        for i in range(0, max(len(events), 1), 512):
            chunk = bytes(BUTTONS[c] for c in events[i:i + 512])
            lines = self.parse_screen(self.call(TEST_BUTTONS, chunk, timeout).payload)
        return lines

    def screen(self) -> list:
        return self.parse_screen(self.call(TEST_SCREEN).payload)

    def memory(self) -> dict:
        v = struct.unpack(">8I", self.call(TEST_MEMORY).payload)
        keys = ["heap_peak", "heap_size", "heap_now", "stack0_peak", "stack0_size", "stack1_peak", "stack1_size",
                "second_core_jobs"]
        return dict(zip(keys, v))

    def stall(self, after_writes: int):
        """The firmware stops right after its n-th flash write or erase from now (then kill QEMU)."""
        self.call(TEST_STALL, struct.pack(">I", after_writes))


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--tcp", help="host:port of QEMU's serial port")
    g.add_argument("--serial", help="the board's serial device")
    ap.add_argument("command", choices=["status", "screen", "press", "trees", "memory"])
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    if a.tcp:
        host, port = a.tcp.rsplit(":", 1)
        link = TcpLink(host, int(port))
    else:
        link = SerialLink(a.serial)
    b = Board(link)
    if a.command == "status":
        s = b.status()
        for k, v in s.items():
            print(f"{k}: {v.hex() if isinstance(v, bytes) else v}")
    elif a.command == "screen":
        print("\n".join(b.screen()))
    elif a.command == "press":
        print("\n".join(b.press("".join(a.args))))
    elif a.command == "trees":
        for t in b.trees():
            print({k: (v.hex() if isinstance(v, bytes) else v) for k, v in t.items()})
    elif a.command == "memory":
        print(b.memory())
    b.close()


if __name__ == "__main__":
    main(sys.argv[1:])
