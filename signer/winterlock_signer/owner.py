"""WinterlockOwner v2 (contracts/src/safe/WinterlockOwner.sol): a member's EIP-1271 Safe owner. Its formats, digests
and deterministic addresses, computed natively and offline; the tests check each against the compiled contract.

Devices: device 0 is the member key (the stateless key from the recovery phrase, fixed in the member's proxy, always
active at generation 0); devices 1-3 are device keys that the member key certifies and revokes, per chain. A tree or a
message of a device counts only while the device is active at the generation it was made under.

Signature data (the contract signature that Safe appends to its blob; byte 0 is the kind):
  transaction  [slot: 1][device: 1][safe: 20][SafeTx: 10 x 32][WOTS signature: 1,176][path: 24 x height]
  message      [0x02][device: 1][safe: 20][keccak256(message): 32][stateless signature: 5,684]
  approved     [0x03][safe: 20][keccak256(message): 32]  valid once the Safe has approved the SafeMessage on-chain
Key index:     (nonce - start) * 2 + slot; a tree of height h covers 2^(h-1) nonces from start
Digests (keccak256 of abi.encode(DOMAIN, chainid, owner, ...); owner: the member's proxy address):
  device certificate  (device, generation, key)                            signed by the member key
  revocation          (device, generation)                                 signed by the member key
  tree certificate    (safe, device, generation, root, height, start)      signed by the device's key
  message             (safe, device, generation, SafeMessage hash)         signed by the device's key
  tree seed           first 16 bytes of (safe, device, generation, start)  derived, not signed
Addresses (script/DeploySafeOwner.s.sol, SafeOwnerDeployment), the same on every chain:
  verifier        CREATE2(deterministic deployment proxy, VERIFIER_SALT, LeanSphincsAsm creation code)
  WOTS verifier   CREATE2(proxy, WOTS_VERIFIER_SALT, SharedWotsVerifier creation code)
  implementation  CREATE2(proxy, IMPLEMENTATION_SALT, WinterlockOwner creation code ‖
                  abi.encode(params, verifier, WOTS verifier))
  factory         CREATE2(proxy, FACTORY_SALT, WinterlockOwnerFactory creation code ‖ abi.encode(implementation))
  member's owner  CREATE2(factory, KEY, Solady LibClone's init code of a clone of the implementation with KEY as its
                  immutable argument): WinterlockOwnerFactory.predict(KEY). Runtime code: 77 bytes,
                  363d3d373d3d3d363d73 ‖ implementation ‖ 5af43d82803e903d91602b57fd5bf3 ‖ KEY
"""

import functools
import json
import os

from . import abi, wots
from .abi import checksum, h2b, word
from .keccak import keccak256

SLOTS = 2
MAX_HEIGHT = 40
MAX_START = (1 << 40) - 1
MAX_DEVICE = 3
MAX_GENERATION = (1 << 16) - 1
STATELESS_SIG_LEN = 5684
KIND_MESSAGE = 0x02
KIND_APPROVED = 0x03
PREFIX = 1 + 1 + 20  # kind or slot, device, safe
TX_HEADER = PREFIX + 320
MESSAGE_LEN = PREFIX + 32 + STATELESS_SIG_LEN
APPROVED_LEN = 1 + 20 + 32
DEVICE_DOMAIN = keccak256(b"Winterlock.safe-owner.device.v2")
REVOCATION_DOMAIN = keccak256(b"Winterlock.safe-owner.revocation.v2")
CERTIFICATE_DOMAIN = keccak256(b"Winterlock.safe-owner.certificate.v2")
MESSAGE_DOMAIN = keccak256(b"Winterlock.safe-owner.message.v2")
TREE_SEED_DOMAIN = keccak256(b"Winterlock.safe-owner.tree-seed.v2")
MAGIC = bytes.fromhex("1626ba7e")
LEGACY_MAGIC = bytes.fromhex("20c13b0b")

PROXY = "0x4e59b44847b379578588920cA78FbF26c0B4956C"  # deterministic deployment proxy
VERIFIER_SALT = keccak256(b"Winterlock.stateless-verifier.v1")
WOTS_VERIFIER_SALT = keccak256(b"Winterlock.wots-verifier.v1")
IMPLEMENTATION_SALT = keccak256(b"Winterlock.safe-owner.implementation.v2")
FACTORY_SALT = keccak256(b"Winterlock.safe-owner.factory.v2")
OWNER_CODE_BYTES = 77
KEY_OFFSET = 0x2D
VERSION = 2

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "contracts.json")) as _f:
    _PINNED = json.load(_f)
IMPLEMENTATION_CREATION = h2b(_PINNED["WinterlockOwner"]["creation_code"])
FACTORY_CREATION = h2b(_PINNED["WinterlockOwnerFactory"]["creation_code"])
VERIFIER_CREATION = h2b(_PINNED["LeanSphincsAsm"]["creation_code"])
WOTS_VERIFIER_CREATION = h2b(_PINNED["SharedWotsVerifier"]["creation_code"])
PINNED_COMMIT = _PINNED.get("commit")


def create2(salt: bytes, init_code: bytes, deployer: str = PROXY) -> str:
    return checksum(keccak256(b"\xff" + h2b(deployer) + salt + keccak256(init_code))[12:])


@functools.lru_cache(maxsize=None)
def verifier_address() -> str:
    return create2(VERIFIER_SALT, VERIFIER_CREATION)


@functools.lru_cache(maxsize=None)
def wots_verifier_address() -> str:
    return create2(WOTS_VERIFIER_SALT, WOTS_VERIFIER_CREATION)


def implementation_init_code(params=wots.PARAMS) -> bytes:
    return IMPLEMENTATION_CREATION + abi.encode(["uint256", "address", "address"],
                                                [params, verifier_address(), wots_verifier_address()])


@functools.lru_cache(maxsize=None)
def implementation_address(params=wots.PARAMS) -> str:
    return create2(IMPLEMENTATION_SALT, implementation_init_code(params))


def factory_init_code(params=wots.PARAMS) -> bytes:
    return FACTORY_CREATION + abi.encode(["address"], [implementation_address(params)])


@functools.lru_cache(maxsize=None)
def factory_address(params=wots.PARAMS) -> str:
    return create2(FACTORY_SALT, factory_init_code(params))


def check_key(key: bytes):
    """A stateless public key (root ‖ P) as the contracts take it: 32 bytes, both halves nonzero"""
    if len(key) != 32 or not any(key[:16]) or not any(key[16:]):
        raise ValueError("a stateless key is 32 bytes with both halves nonzero")


_check_key = check_key


def proxy_init_code(implementation: str, key: bytes) -> bytes:
    """Solady LibClone.initCode(implementation, abi.encodePacked(key)): a clone with immutable args"""
    check_key(key)
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


def member_key_of(address: str, code: bytes):
    """The member key in `code` if it is the code of a v2 owner of the pinned implementation at `address` (the
    factory's proxy for that key), else None"""
    if len(code) != OWNER_CODE_BYTES:
        return None
    key = code[KEY_OFFSET:]
    try:
        if code != proxy_runtime(implementation_address(), key) or owner_address(key).lower() != address.lower():
            return None
    except ValueError:
        return None
    return key


def is_v2_owner(rpc, address: str) -> bool:
    """Whether `address` holds a v2 Winterlock owner of the pinned implementation (its code, checked offline)"""
    return member_key_of(address, rpc.code(address)) is not None


def _check_device(device: int):
    if not 0 <= device <= MAX_DEVICE:
        raise ValueError(f"devices are numbered 0 to {MAX_DEVICE}")


def tree_place_digest(chain_id: int, owner: str, safe: str, device: int, generation: int, start: int) -> bytes:
    """keccak256(abi.encode(TREE_SEED_DOMAIN, chain, owner, safe, device, generation, start)): where a tree belongs.
    Its first 16 bytes are the tree's seed; the signer app's ERC-8499 trees take all 32 as their context
    (erc8499.py)."""
    return keccak256(TREE_SEED_DOMAIN + word(chain_id) + word(owner) + word(safe) + word(device) + word(generation)
                     + word(start))


def tree_seed(chain_id: int, owner: str, safe: str, device: int, generation: int, start: int) -> int:
    d = tree_place_digest(chain_id, owner, safe, device, generation, start)
    return int.from_bytes(d[:16], "big")


def root_word(root: bytes) -> bytes:
    """A tree root (n bytes) high-aligned in a bytes32"""
    return root.ljust(32, b"\x00")


def device_digest(chain_id: int, owner: str, device: int, generation: int, key: bytes) -> bytes:
    """What the member key signs to certify `key` as device `device`'s key from `generation` on"""
    return keccak256(DEVICE_DOMAIN + word(chain_id) + word(owner) + word(device) + word(generation) + key)


def revocation_digest(chain_id: int, owner: str, device: int, generation: int) -> bytes:
    """What the member key signs to revoke device `device` at `generation`"""
    return keccak256(REVOCATION_DOMAIN + word(chain_id) + word(owner) + word(device) + word(generation))


def certificate_digest(chain_id: int, owner: str, safe: str, device: int, generation: int, root: bytes, height: int,
                       start: int) -> bytes:
    """What the device's key (the member key for device 0) signs to certify a tree"""
    return keccak256(CERTIFICATE_DOMAIN + word(chain_id) + word(owner) + word(safe) + word(device) + word(generation)
                     + root_word(root) + word(height) + word(start))


def message_digest(chain_id: int, owner: str, safe: str, device: int, generation: int,
                   safe_message_hash: bytes) -> bytes:
    """What the device's key (the member key for device 0) signs to approve a SafeMessage"""
    return keccak256(MESSAGE_DOMAIN + word(chain_id) + word(owner) + word(safe) + word(device) + word(generation)
                     + safe_message_hash)


def capacity(height: int) -> int:
    """Nonces a tree of `height` covers (two keys each)"""
    return 1 << (height - 1)


def key_index(nonce: int, start: int, slot: int, height: int) -> int:
    if not 0 <= slot < SLOTS:
        raise ValueError("slot must be 0 or 1")
    if nonce < start or nonce - start >= capacity(height):
        raise ValueError(f"nonce {nonce} is outside the tree (nonces {start} to {start + capacity(height) - 1})")
    return (nonce - start) * SLOTS + slot


def tx_signature_data(slot: int, device: int, safe: str, safe_tx_words, wots_sig: bytes, path: bytes) -> bytes:
    _check_device(device)
    return bytes([slot, device]) + h2b(safe) + b"".join(safe_tx_words) + wots_sig + path


def parse_tx_signature_data(data: bytes):
    """(slot, device, safe, ten words, WOTS signature, path), or None if it isn't a transaction signature"""
    if len(data) < TX_HEADER + wots.SIG_BYTES or data[0] >= SLOTS or data[1] > MAX_DEVICE or \
            (len(data) - TX_HEADER - wots.SIG_BYTES) % wots.N:
        return None
    words = [data[PREFIX + 32 * i: PREFIX + 32 + 32 * i] for i in range(10)]
    return (data[0], data[1], checksum(data[2:PREFIX]), words, data[TX_HEADER: TX_HEADER + wots.SIG_BYTES],
            data[TX_HEADER + wots.SIG_BYTES:])


def message_signature_data(device: int, safe: str, msg_hash: bytes, stateless_sig: bytes) -> bytes:
    """[0x02][device][safe][keccak256(message)][stateless signature of message_digest]"""
    _check_device(device)
    return bytes([KIND_MESSAGE, device]) + h2b(safe) + msg_hash + stateless_sig


def approved_signature_data(safe: str, msg_hash: bytes) -> bytes:
    """[0x03][safe][keccak256(message)]: valid for any v2 owner of the Safe once the Safe has approved the
    SafeMessage on-chain (SignMessageLib). No key signs it."""
    if len(msg_hash) != 32:
        raise ValueError("the message hash is 32 bytes")
    return bytes([KIND_APPROVED]) + h2b(safe) + msg_hash


def enroll_calldata(safe: str, device: int, root: bytes, height: int, start: int, certificate: bytes) -> bytes:
    """WinterlockOwner.enroll, sent to the member's owner once it exists"""
    return abi.calldata("enroll(address,uint8,bytes32,uint8,uint64,bytes)",
                        ["address", "uint256", "bytes32", "uint256", "uint256", "bytes"],
                        [safe, device, root_word(root), height, start, certificate])


def deploy_and_enroll_calldata(key: bytes, safe: str, root: bytes, height: int, start: int,
                               certificate: bytes) -> bytes:
    """WinterlockOwnerFactory.deployAndEnroll: creates the owner and enrols device 0's first tree in one transaction"""
    return abi.calldata("deployAndEnroll(bytes32,address,bytes32,uint8,uint64,bytes)",
                        ["bytes32", "address", "bytes32", "uint256", "uint256", "bytes"],
                        [key, safe, root_word(root), height, start, certificate])


def certify_device_calldata(device: int, generation: int, key: bytes, signature: bytes) -> bytes:
    return abi.calldata("certifyDevice(uint8,uint16,bytes32,bytes)", ["uint256", "uint256", "bytes32", "bytes"],
                        [device, generation, key, signature])


def revoke_device_calldata(device: int, generation: int, signature: bytes) -> bytes:
    return abi.calldata("revokeDevice(uint8,uint16,bytes)", ["uint256", "uint256", "bytes"],
                        [device, generation, signature])


def read_tree(rpc, owner: str, safe: str, device: int = 0):
    """(root n bytes or None, seed, height, start, generation) of `device`'s tree for `safe` on the RPC's chain. A
    tree stays in storage after its device is revoked or replaced: read_device says whether it still verifies."""
    _check_device(device)
    ret = rpc.eth_call(owner, abi.calldata("tree(address,uint8)", ["address", "uint256"], [safe, device]))
    root = abi.dec_word(ret, 0)[: wots.N]
    if not any(root):
        return None, 0, 0, 0, 0
    return root, abi.dec_uint(ret, 1), abi.dec_uint(ret, 2), abi.dec_uint(ret, 3), abi.dec_uint(ret, 4)


def read_device(rpc, owner: str, device: int):
    """(key, generation, active) of `device` on the RPC's chain; device 0 is the member key, active at 0"""
    _check_device(device)
    ret = rpc.eth_call(owner, abi.calldata("devices(uint8)", ["uint256"], [device]))
    return abi.dec_word(ret, 0), abi.dec_uint(ret, 1), abi.dec_uint(ret, 2) != 0


def read_devices(rpc, owner: str) -> list:
    """[(key, generation, active)] of devices 0 to 3"""
    return [read_device(rpc, owner, d) for d in range(MAX_DEVICE + 1)]


def tree_usable(tree, dev) -> bool:
    """Whether a tree (read_tree) verifies: its device (read_device) is active at the tree's generation"""
    root, _, _, _, generation = tree
    _, dev_generation, active = dev
    return root is not None and active and dev_generation == generation


def is_valid_signature(rpc, owner: str, h: bytes, data: bytes) -> bool:
    ret = rpc.eth_call(owner, abi.calldata("isValidSignature(bytes32,bytes)", ["bytes32", "bytes"], [h, data]))
    return ret[:4] == MAGIC
