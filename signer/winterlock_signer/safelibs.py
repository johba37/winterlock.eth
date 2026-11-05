"""Safe's libraries that a Safe transaction delegatecalls: SignMessageLib (approve a message on-chain) and
MultiSendCallOnly (a batch of calls). A delegatecall runs the library's code as the Safe itself, so the signer only
builds one to code it recognises: Safe v1.4.1's release build, pinned in safe_libs.json (tools/pin_safe_libs.py),
compared without the trailing CBOR metadata. The canonical deployments match it; so does a local build.
"""

import json
import os

from .abi import checksum
from .keccak import keccak256

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe_libs.json")) as _f:
    PINNED = json.load(_f)

SIGN_MESSAGE_LIB = "SignMessageLib"
MULTISEND = "MultiSendCallOnly"


class UnknownLibrary(Exception):
    pass


def strip_metadata(code: bytes) -> bytes:
    """Runtime code without Solidity's CBOR metadata (its length is the last two bytes)"""
    if len(code) < 2:
        return code
    n = int.from_bytes(code[-2:], "big") + 2
    if n > len(code) or n > 128:
        return code
    return code[:-n]


def default_address(name: str) -> str:
    return checksum(PINNED[name]["address"])


def check(rpc, name: str, address: str = None) -> str:
    """The library's address, after checking its code on this chain is Safe's release code"""
    address = checksum(address or default_address(name))
    code = rpc.code(address)
    if not code:
        raise UnknownLibrary(f"no {name} at {address} on this chain (deploy Safe v1.4.1's, or name it with its option)")
    pin = PINNED[name]
    if "0x" + keccak256(code).hex() != pin["codeHash"] and \
            "0x" + keccak256(strip_metadata(code)).hex() != pin["codeWithoutMetadataHash"]:
        raise UnknownLibrary(f"the code at {address} isn't Safe's {name} ({PINNED['release']}): the signer won't "
                             "delegatecall it")
    return address
