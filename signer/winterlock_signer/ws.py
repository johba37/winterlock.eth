"""A minimal WebSocket (RFC 6455) client, enough for a WalletConnect relay: text frames, ping and pong, close, over
TCP or TLS. Also the server half of the handshake and the frame codec, which the tests' stand-in relay uses.

Not supported: extensions (no compression), subprotocols, proxies.
"""

import base64
import hashlib
import os
import socket
import ssl
import struct
import threading
import urllib.parse

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TEXT, BINARY, CLOSE, PING, PONG, CONT = 0x1, 0x2, 0x8, 0x9, 0xA, 0x0
MAX_MESSAGE = 4 << 20  # WalletConnect relay messages are small; a cap keeps a hostile peer from filling memory


class WsClosed(Exception):
    pass


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()


def _read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise WsClosed("connection closed")
        buf += chunk
    return buf


def _read_headers(sock) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = sock.recv(1)
        if not c:
            raise WsClosed("connection closed during the handshake")
        buf += c
        if len(buf) > 16384:
            raise WsClosed("handshake headers too long")
    return buf


def encode_frame(opcode: int, payload: bytes, mask: bool) -> bytes:
    head = bytes([0x80 | opcode])
    n = len(payload)
    m = 0x80 if mask else 0
    if n < 126:
        head += bytes([m | n])
    elif n < 1 << 16:
        head += bytes([m | 126]) + struct.pack(">H", n)
    else:
        head += bytes([m | 127]) + struct.pack(">Q", n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i & 3] for i, b in enumerate(payload))


def read_frame(sock):
    """(fin, opcode, payload) of one frame, unmasked"""
    b0, b1 = _read_exact(sock, 2)
    fin, opcode = b0 & 0x80, b0 & 0x0F
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", _read_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", _read_exact(sock, 8))[0]
    if n > MAX_MESSAGE:
        raise WsClosed("frame too large")
    key = _read_exact(sock, 4) if b1 & 0x80 else None
    payload = _read_exact(sock, n)
    if key:
        payload = bytes(b ^ key[i & 3] for i, b in enumerate(payload))
    return bool(fin), opcode, payload


class Connection:
    """One WebSocket connection. `mask` is True on the client side (RFC 6455 requires clients to mask)."""

    def __init__(self, sock, mask: bool):
        self.sock = sock
        self.mask = mask
        self._send_lock = threading.Lock()
        self.closed = False

    def _send(self, opcode, payload: bytes):
        with self._send_lock:
            if self.closed:
                raise WsClosed("connection closed")
            try:
                self.sock.sendall(encode_frame(opcode, payload, self.mask))
            except OSError as e:
                self.closed = True
                raise WsClosed(f"send failed: {type(e).__name__}") from None

    def send_text(self, text: str):
        self._send(TEXT, text.encode())

    def ping(self, payload: bytes = b""):
        self._send(PING, payload)

    def recv(self) -> str:
        """The next text message; answers pings, skips pongs, raises WsClosed on close"""
        parts, opcode0 = [], None
        while True:
            try:
                fin, opcode, payload = read_frame(self.sock)
            except OSError as e:
                self.closed = True
                raise WsClosed(f"receive failed: {type(e).__name__}") from None
            if opcode == PING:
                try:
                    self._send(PONG, payload)
                except WsClosed:
                    pass
                continue
            if opcode == PONG:
                continue
            if opcode == CLOSE:
                try:
                    self._send(CLOSE, payload[:2])
                except WsClosed:
                    pass
                self.close()
                raise WsClosed("closed by peer" + (f" ({struct.unpack('>H', payload[:2])[0]})" if len(payload) >= 2
                                                   else ""))
            if opcode in (TEXT, BINARY):
                parts, opcode0 = [payload], opcode
            elif opcode == CONT and opcode0 is not None:
                parts.append(payload)
            else:
                raise WsClosed(f"unexpected opcode {opcode}")
            if sum(map(len, parts)) > MAX_MESSAGE:
                raise WsClosed("message too large")
            if fin:
                data = b"".join(parts)
                if opcode0 == TEXT:
                    return data.decode()
                parts, opcode0 = [], None  # binary messages aren't used by the relay: dropped

    def close(self):
        if not self.closed:
            try:
                with self._send_lock:
                    self.sock.sendall(encode_frame(CLOSE, struct.pack(">H", 1000), self.mask))
            except OSError:
                pass
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def connect(url: str, timeout: float = 30, idle_timeout: float = 75) -> Connection:
    """Opens ws:// or wss:// `url`. Errors name only the host: the query may carry credentials. A read that waits
    longer than `idle_timeout` ends the connection (the caller reconnects)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("ws", "wss"):
        raise ValueError("relay URL must start with ws:// or wss://")
    port = u.port or (443 if u.scheme == "wss" else 80)
    try:
        sock = socket.create_connection((u.hostname, port), timeout=timeout)
        if u.scheme == "wss":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        host = u.hostname + (f":{u.port}" if u.port else "")
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: winterlock-signer\r\n\r\n")
        sock.sendall(req.encode())
        head = _read_headers(sock).decode("latin-1")
    except (OSError, ssl.SSLError) as e:
        raise WsClosed(f"can't connect to {u.scheme}://{u.hostname}: {type(e).__name__}") from None
    status = head.split("\r\n", 1)[0]
    if " 101 " not in status + " ":
        sock.close()
        raise WsClosed(f"{u.scheme}://{u.hostname} refused the WebSocket upgrade: {status[:80]}")
    headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in head.split("\r\n")[1:])
               if k}
    if headers.get("sec-websocket-accept") != accept_key(key):
        sock.close()
        raise WsClosed("bad Sec-WebSocket-Accept from the relay")
    # the relay client pings every 20 s and the relay pongs: 75 s of silence means the connection is dead
    sock.settimeout(idle_timeout)
    return Connection(sock, mask=True)


def server_handshake(sock):
    """Server side: reads the client's upgrade request and answers it. Returns (Connection, path with query)."""
    head = _read_headers(sock).decode("latin-1")
    lines = head.split("\r\n")
    path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
    headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:]) if k}
    key = headers.get("sec-websocket-key")
    if not key or headers.get("upgrade", "").lower() != "websocket":
        sock.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        sock.close()
        raise WsClosed("not a WebSocket upgrade")
    sock.sendall((f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Accept: {accept_key(key)}\r\n\r\n").encode())
    return Connection(sock, mask=False), path
