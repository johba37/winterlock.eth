"""WinterlockOwner (contracts/src/safe/WinterlockOwner.sol): a member's EIP-1271 Safe owner. Its formats, digests
and deterministic addresses, computed natively and offline; the tests check each against the contracts.

Transaction signature data: [slot: 1][safe: 20][SafeTx: 10 x 32][WOTS signature: 1,176][path: 24 x height]
Key index:                  (nonce - start) * 2 + slot; a tree of height h covers 2^(h-1) nonces from start
Certificate digest:         keccak256(abi.encode(CERTIFICATE_DOMAIN, chainid, owner, safe, root, height, start))
Tree seed:                  first 16 bytes of keccak256(abi.encode(TREE_SEED_DOMAIN, chainid, owner, safe, start))
                            (owner: the member's proxy address, which runs the implementation by DELEGATECALL)
Addresses (script/DeploySafeOwner.s.sol, SafeOwnerDeployment), the same on every chain:
  verifier        CREATE2(deterministic deployment proxy, VERIFIER_SALT, LeanSphincsAsm creation code)
  implementation  CREATE2(proxy, IMPLEMENTATION_SALT, WinterlockOwner creation code ‖ abi.encode(params, verifier))
  factory         CREATE2(proxy, FACTORY_SALT, WinterlockOwnerFactory creation code ‖ abi.encode(implementation))
  member's owner  CREATE2(factory, KEY, Solady LibClone's init code of a clone of the implementation with KEY as its
                  immutable argument): WinterlockOwnerFactory.predict(KEY). Runtime code: 77 bytes,
                  363d3d373d3d3d363d73 ‖ implementation ‖ 5af43d82803e903d91602b57fd5bf3 ‖ KEY
"""

import json
import os

from . import abi, wots
from .abi import checksum, h2b, word
from .keccak import keccak256

SLOTS = 2
MAX_HEIGHT = 40
MAX_START = (1 << 40) - 1
STATELESS_SIG_LEN = 5684
TX_HEADER = 1 + 20 + 320
CERTIFICATE_DOMAIN = keccak256(b"Winterlock.safe-owner.certificate.v1")
MESSAGE_DOMAIN = keccak256(b"Winterlock.safe-owner.message.v1")
TREE_SEED_DOMAIN = keccak256(b"Winterlock.safe-owner.tree-seed.v1")
MAGIC = bytes.fromhex("1626ba7e")
LEGACY_MAGIC = bytes.fromhex("20c13b0b")

PROXY = "0x4e59b44847b379578588920cA78FbF26c0B4956C"  # deterministic deployment proxy
VERIFIER_SALT = keccak256(b"Winterlock.stateless-verifier.v1")
IMPLEMENTATION_SALT = keccak256(b"Winterlock.safe-owner.implementation.v1")
FACTORY_SALT = keccak256(b"Winterlock.safe-owner.factory.v1")
OWNER_CODE_BYTES = 77

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "contracts.json")) as _f:
    _PINNED = json.load(_f)
IMPLEMENTATION_CREATION = h2b(_PINNED["WinterlockOwner"]["creation_code"])
FACTORY_CREATION = h2b(_PINNED["WinterlockOwnerFactory"]["creation_code"])
VERIFIER_CREATION = h2b(_PINNED["LeanSphincsAsm"]["creation_code"])
PINNED_COMMIT = _PINNED.get("commit")


def create2(salt: bytes, init_code: bytes, deployer: str = PROXY) -> str:
    return checksum(keccak256(b"\xff" + h2b(deployer) + salt + keccak256(init_code))[12:])


def verifier_address() -> str:
    return create2(VERIFIER_SALT, VERIFIER_CREATION)


def implementation_init_code(params=wots.PARAMS) -> bytes:
    return IMPLEMENTATION_CREATION + abi.encode(["uint256", "address"], [params, verifier_address()])


def implementation_address(params=wots.PARAMS) -> str:
    return create2(IMPLEMENTATION_SALT, implementation_init_code(params))


def factory_init_code(params=wots.PARAMS) -> bytes:
    return FACTORY_CREATION + abi.encode(["address"], [implementation_address(params)])


def factory_address(params=wots.PARAMS) -> str:
    return create2(FACTORY_SALT, factory_init_code(params))


def _check_key(key: bytes):
    if len(key) != 32 or not any(key[:16]) or not any(key[16:]):
        raise ValueError("a stateless key is 32 bytes with both halves nonzero")


def proxy_init_code(implementation: str, key: bytes) -> bytes:
    """Solady LibClone.initCode(implementation, abi.encodePacked(key)): a clone with immutable args"""
    _check_key(key)
    n = len(key)
    return (b"\x61" + (0x2D + n).to_bytes(2, "big") + bytes.fromhex("3d81600a3d39f3363d3d373d3d3d363d73")
            + h2b(implementation) + bytes.fromhex("5af43d82803e903d91602b57fd5bf3") + key)


def proxy_runtime(implementation: str, key: bytes) -> bytes:
    """The 77 bytes of code a member's owner has: the ERC-1167 proxy, then the key (read by KEY())"""
    return (bytes.fromhex("363d3d373d3d3d363d73") + h2b(implementation) + bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
            + key)


def owner_address(key: bytes, params=wots.PARAMS) -> str:
    """WinterlockOwnerFactory.predict(key), offline"""
    return create2(key, proxy_init_code(implementation_address(params), key), factory_address(params))


def tree_seed(chain_id: int, owner: str, safe: str, start: int) -> int:
    d = keccak256(TREE_SEED_DOMAIN + word(chain_id) + word(owner) + word(safe) + word(start))
    return int.from_bytes(d[:16], "big")


def root_word(root: bytes) -> bytes:
    """A tree root (n bytes) high-aligned in a bytes32"""
    return root.ljust(32, b"\x00")


def certificate_digest(chain_id: int, owner: str, safe: str, root: bytes, height: int, start: int) -> bytes:
    return keccak256(CERTIFICATE_DOMAIN + word(chain_id) + word(owner) + word(safe) + root_word(root)
                     + word(height) + word(start))


def message_digest(chain_id: int, owner: str, safe: str, safe_message_hash: bytes) -> bytes:
    return keccak256(MESSAGE_DOMAIN + word(chain_id) + word(owner) + word(safe) + safe_message_hash)


def capacity(height: int) -> int:
    """Nonces a tree of `height` covers (two keys each)"""
    return 1 << (height - 1)


def key_index(nonce: int, start: int, slot: int, height: int) -> int:
    if not 0 <= slot < SLOTS:
        raise ValueError("slot must be 0 or 1")
    if nonce < start or nonce - start >= capacity(height):
        raise ValueError(f"nonce {nonce} is outside the tree (nonces {start} to {start + capacity(height) - 1})")
    return (nonce - start) * SLOTS + slot


def tx_signature_data(slot: int, safe: str, safe_tx_words, wots_sig: bytes, path: bytes) -> bytes:
    return bytes([slot]) + h2b(safe) + b"".join(safe_tx_words) + wots_sig + path


def parse_tx_signature_data(data: bytes):
    """(slot, safe, ten words, WOTS signature, path), or None if it isn't a transaction signature"""
    if len(data) < TX_HEADER + wots.SIG_BYTES or data[0] >= SLOTS or (len(data) - TX_HEADER - wots.SIG_BYTES) % wots.N:
        return None
    words = [data[21 + 32 * i: 53 + 32 * i] for i in range(10)]
    return (data[0], checksum(data[1:21]), words, data[TX_HEADER: TX_HEADER + wots.SIG_BYTES],
            data[TX_HEADER + wots.SIG_BYTES:])


def enroll_calldata(safe: str, root: bytes, height: int, start: int, certificate: bytes) -> bytes:
    """WinterlockOwner.enroll, sent to the member's owner once it exists"""
    return abi.calldata("enroll(address,bytes32,uint8,uint64,bytes)",
                        ["address", "bytes32", "uint256", "uint256", "bytes"],
                        [safe, root_word(root), height, start, certificate])


def deploy_and_enroll_calldata(key: bytes, safe: str, root: bytes, height: int, start: int,
                               certificate: bytes) -> bytes:
    """WinterlockOwnerFactory.deployAndEnroll: creates the owner and enrols its first tree in one transaction"""
    return abi.calldata("deployAndEnroll(bytes32,address,bytes32,uint8,uint64,bytes)",
                        ["bytes32", "address", "bytes32", "uint256", "uint256", "bytes"],
                        [key, safe, root_word(root), height, start, certificate])


def read_tree(rpc, owner: str, safe: str):
    """(root n bytes or None, seed, height, start) of the tree enrolled for `safe` on the RPC's chain"""
    ret = rpc.eth_call(owner, abi.calldata("tree(address)", ["address"], [safe]))
    root = abi.dec_word(ret, 0)[: wots.N]
    if not any(root):
        return None, 0, 0, 0
    return root, abi.dec_uint(ret, 1), abi.dec_uint(ret, 2), abi.dec_uint(ret, 3)


def is_valid_signature(rpc, owner: str, h: bytes, data: bytes) -> bool:
    ret = rpc.eth_call(owner, abi.calldata("isValidSignature(bytes32,bytes)", ["bytes32", "bytes"], [h, data]))
    return ret[:4] == MAGIC
