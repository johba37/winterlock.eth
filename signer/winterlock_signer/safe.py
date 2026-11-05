"""Safe transactions: the SafeTx struct, Safe's EIP-712 hash, signature blobs, and a decoder that shows what a
transaction does. Safe v1.3.0 and later (EIP-712 domain with the chain id); checked against v1.4.1."""

from dataclasses import dataclass, field

from . import abi
from .abi import b2h, checksum, h2b, word
from .keccak import keccak256

ZERO = "0x" + "00" * 20
DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)")
SAFE_TX_TYPEHASH = keccak256(
    b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,"
    b"uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
GET_TX_HASH = "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)"
EXEC_TX = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
EXEC_TYPES = ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"]


def domain_separator(chain_id: int, safe: str) -> bytes:
    return keccak256(DOMAIN_TYPEHASH + word(chain_id) + word(safe))


def eip712(chain_id: int, safe: str, struct_hash: bytes) -> bytes:
    return keccak256(b"\x19\x01" + domain_separator(chain_id, safe) + struct_hash)


@dataclass
class SafeTx:
    to: str
    value: int = 0
    data: bytes = b""
    operation: int = 0
    safe_tx_gas: int = 0
    base_gas: int = 0
    gas_price: int = 0
    gas_token: str = ZERO
    refund_receiver: str = ZERO
    nonce: int = 0
    extra: dict = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self):
        self.to = checksum(self.to)
        self.gas_token = checksum(self.gas_token)
        self.refund_receiver = checksum(self.refund_receiver)
        self.data = bytes(self.data)
        if self.operation not in (0, 1):
            raise ValueError("operation must be 0 (call) or 1 (delegatecall)")
        for v in (self.value, self.safe_tx_gas, self.base_gas, self.gas_price, self.nonce):
            if not 0 <= v < 1 << 256:
                raise ValueError("SafeTx field out of range")

    def words(self) -> list:
        """The ten SafeTx words after the type hash (WinterlockOwner's transaction signature carries them)"""
        return [word(self.to), word(self.value), keccak256(self.data), word(self.operation), word(self.safe_tx_gas),
                word(self.base_gas), word(self.gas_price), word(self.gas_token), word(self.refund_receiver),
                word(self.nonce)]

    def struct_hash(self) -> bytes:
        return keccak256(SAFE_TX_TYPEHASH + b"".join(self.words()))

    def hash(self, chain_id: int, safe: str) -> bytes:
        return eip712(chain_id, safe, self.struct_hash())

    def preimage(self, chain_id: int, safe: str) -> bytes:
        """The 66 bytes Safe v1.4.1 passes to a contract owner's legacy isValidSignature(bytes, bytes)"""
        return b"\x19\x01" + domain_separator(chain_id, safe) + self.struct_hash()

    def args(self):
        return [self.to, self.value, self.data, self.operation, self.safe_tx_gas, self.base_gas, self.gas_price,
                self.gas_token, self.refund_receiver]

    def get_transaction_hash_calldata(self) -> bytes:
        return abi.calldata(GET_TX_HASH, EXEC_TYPES[:9] + ["uint256"], self.args() + [self.nonce])

    def exec_calldata(self, signatures: bytes) -> bytes:
        return abi.calldata(EXEC_TX, EXEC_TYPES, self.args() + [signatures])

    def to_json(self) -> dict:
        """As Safe's Transaction Service takes and returns it"""
        return {"to": self.to, "value": str(self.value), "data": b2h(self.data),
                "operation": self.operation, "safeTxGas": str(self.safe_tx_gas), "baseGas": str(self.base_gas),
                "gasPrice": str(self.gas_price), "gasToken": self.gas_token, "refundReceiver": self.refund_receiver,
                "nonce": self.nonce}

    @classmethod
    def from_json(cls, d: dict):
        return cls(to=d["to"], value=int(d.get("value") or 0), data=h2b(d.get("data") or "0x"),
                   operation=int(d.get("operation") or 0), safe_tx_gas=int(d.get("safeTxGas") or 0),
                   base_gas=int(d.get("baseGas") or 0), gas_price=int(d.get("gasPrice") or 0),
                   gas_token=d.get("gasToken") or ZERO, refund_receiver=d.get("refundReceiver") or ZERO,
                   nonce=int(d["nonce"]))


# --- signatures ---

def contract_signature(owner: str, data: bytes) -> bytes:
    """One owner's standalone contract signature (v = 0): r = owner, s = 65, then [length][data]. The form the
    Transaction Service takes for a proposal or confirmation."""
    return word(owner) + word(65) + b"\x00" + word(len(data)) + data


def parse_signature(sig: bytes):
    """A standalone signature as the service returns it: (owner, data, is_contract). For an ECDSA signature
    (65 bytes) the owner is unknown here (None)."""
    if len(sig) >= 97 and sig[64] == 0 and int.from_bytes(sig[32:64], "big") == 65:
        n = int.from_bytes(sig[65:97], "big")
        if len(sig) != 97 + n:
            raise ValueError("contract signature length mismatch")
        return checksum(sig[12:32]), sig[97:], True
    if len(sig) == 65:
        return None, sig, False
    raise ValueError("unknown signature form")


def pack(signatures) -> bytes:
    """Safe's signatures blob from [(owner, data, is_contract)], in increasing owner order"""
    sigs = sorted(signatures, key=lambda s: int(s[0], 16))
    owners = [s[0].lower() for s in sigs]
    if len(set(owners)) != len(owners):
        raise ValueError("an owner signs twice")
    static, dynamic = b"", b""
    for owner, data, is_contract in sigs:
        if is_contract:
            static += word(owner) + word(65 * len(sigs) + len(dynamic)) + b"\x00"
            dynamic += word(len(data)) + data
        else:
            static += data
    return static + dynamic


# --- decoding, for display ---

KNOWN = {
    "transfer(address,uint256)": ("ERC-20 transfer", ["address", "uint256"], ["to", "amount"]),
    "approve(address,uint256)": ("ERC-20 approve", ["address", "uint256"], ["spender", "amount"]),
    "transferFrom(address,address,uint256)": ("ERC-20 transferFrom", ["address", "address", "uint256"],
                                              ["from", "to", "amount"]),
    "addOwnerWithThreshold(address,uint256)": ("Safe: add an owner", ["address", "uint256"], ["owner", "threshold"]),
    "removeOwner(address,address,uint256)": ("Safe: remove an owner", ["address", "address", "uint256"],
                                             ["prevOwner", "owner", "threshold"]),
    "swapOwner(address,address,address)": ("Safe: swap an owner", ["address", "address", "address"],
                                           ["prevOwner", "oldOwner", "newOwner"]),
    "changeThreshold(uint256)": ("Safe: change the threshold", ["uint256"], ["threshold"]),
    "enableModule(address)": ("Safe: ENABLE A MODULE", ["address"], ["module"]),
    "disableModule(address,address)": ("Safe: disable a module", ["address", "address"], ["prevModule", "module"]),
    "setGuard(address)": ("Safe: SET A GUARD", ["address"], ["guard"]),
    "setFallbackHandler(address)": ("Safe: SET THE FALLBACK HANDLER", ["address"], ["handler"]),
    "multiSend(bytes)": ("MultiSend batch", ["bytes"], ["transactions"]),
    "enroll(address,bytes32,uint8,uint64,bytes)": ("Winterlock: enrol an operation tree",
                                                   ["address", "bytes32", "uint256", "uint256", "bytes"],
                                                   ["safe", "root", "height", "start", "certificate"]),
}
_BY_SELECTOR = {abi.selector(sig): (sig, *v) for sig, v in KNOWN.items()}
# a Safe calling itself with these needs every member's attention: they change who controls the funds
DANGEROUS = {"enableModule(address)", "setGuard(address)", "setFallbackHandler(address)",
             "addOwnerWithThreshold(address,uint256)", "removeOwner(address,address,uint256)",
             "swapOwner(address,address,address)", "changeThreshold(uint256)"}


def fmt_eth(wei: int) -> str:
    s = f"{wei / 10**18:.18f}".rstrip("0").rstrip(".")
    return f"{s} ETH ({wei:,} wei)"


def decode(t: SafeTx, safe: str, depth=0) -> tuple:
    """(lines, warnings) describing what the transaction does, decoded here rather than taken from a service"""
    lines, warnings = [], []
    pad = "  " * depth
    if t.operation == 1:
        warnings.append("DELEGATECALL: the called code runs as the Safe itself and can change anything in it")
    if t.to.lower() == safe.lower() and t.value == 0 and not t.data and t.operation == 0:
        lines.append(f"{pad}Cancel: an empty call from the Safe to itself (Safe's on-chain rejection); "
                     f"it only uses up nonce {t.nonce}")
        return lines, warnings
    if not t.data:
        lines.append(f"{pad}Send {fmt_eth(t.value)} to {t.to}")
        return lines, warnings
    sel = t.data[:4]
    known = _BY_SELECTOR.get(sel)
    target = "the Safe itself" if t.to.lower() == safe.lower() else t.to
    if known and len(t.data) >= 4:
        sig, title, types, names = known
        try:
            vals = abi.dec_args(t.data[4:], types)
        except ValueError:
            vals = None
        if vals is None:
            lines.append(f"{pad}Call {target}: {sig}, arguments malformed ({len(t.data)} bytes of data)")
            warnings.append("calldata doesn't decode as its selector says")
        elif sig == "multiSend(bytes)":
            lines.append(f"{pad}{title} through {target} (operation {'delegatecall' if t.operation else 'call'}):")
            try:
                for inner in _multisend(vals[0]):
                    inner_lines, inner_warn = decode(inner, safe, depth + 1)
                    lines += inner_lines
                    warnings += inner_warn
            except ValueError as e:
                warnings.append(f"MultiSend payload malformed: {e}")
        else:
            args = ", ".join(f"{n} = {_fmt_arg(v)}" for n, v in zip(names, vals))
            lines.append(f"{pad}{title} on {target}: {args}")
            if sig in DANGEROUS and t.to.lower() == safe.lower():
                warnings.append(f"{title}: changes who or what controls this Safe")
    else:
        lines.append(f"{pad}Call {target} with {len(t.data)} bytes of data, selector 0x{sel.hex()} (not decoded)")
        warnings.append("unknown call: check the raw data before signing")
    if t.value:
        lines.append(f"{pad}  with {fmt_eth(t.value)}")
    if t.gas_price or t.base_gas or t.safe_tx_gas or int(t.gas_token, 16) or int(t.refund_receiver, 16):
        warnings.append(f"refund fields set: safeTxGas {t.safe_tx_gas}, baseGas {t.base_gas}, gasPrice "
                        f"{t.gas_price}, gasToken {t.gas_token}, refundReceiver {t.refund_receiver}")
    return lines, warnings


def _fmt_arg(v):
    if isinstance(v, bytes):
        return b2h(v) if len(v) <= 40 else f"{len(v)} bytes"
    if isinstance(v, int):
        return f"{v:,}"
    return str(v)


def _multisend(payload: bytes):
    out, i = [], 0
    while i < len(payload):
        if i + 85 > len(payload):
            raise ValueError("truncated entry")
        op = payload[i]
        to = checksum(payload[i + 1: i + 21])
        value = int.from_bytes(payload[i + 21: i + 53], "big")
        n = int.from_bytes(payload[i + 53: i + 85], "big")
        data = payload[i + 85: i + 85 + n]
        if len(data) != n:
            raise ValueError("truncated data")
        out.append(SafeTx(to=to, value=value, data=data, operation=op))
        i += 85 + n
    return out
