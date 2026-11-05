// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IStatelessVerifier} from "../interfaces/IStatelessVerifier.sol";
import {WotsVerifier} from "../WotsVerifier.sol";

/// @title WinterlockOwner
/// @notice A Safe owner for one member: an EIP-1271 contract owner (signature type v = 0) that Safe's ordinary
///         multisig path checks. A team keeps its Safe, its address, and Safe's app and Transaction Service; each
///         member's ECDSA owner is swapped for the member's WinterlockOwner (OwnerManager.swapOwner).
///         The same verifiers as WinterlockValidator (D1): WotsVerifier and the shared stateless verifier.
///
///         Keys of the member (D10–D12, as in WinterlockValidator):
///         - A stateless leanSphincs key, fixed at deployment (KEY). It is the member's only long-term key: it certifies
///           operation trees and signs SafeMessages (D11).
///         - Per Safe and per chain, an operation tree of WOTS keys that signs Safe transactions. A permissionless
///           `enroll` transaction stores it once its certificate verifies. Safe checks owners with view calls, which
///           can't store anything, so a certificate can't ride in a Safe signature as it does in a UserOperation.
///
/// Nonce binding (D2, D4). Safe increments its nonce before it checks signatures (Safe.execTransaction, v1.4.1 and
///         v1.5.0), and its Transaction Service checks a confirmation with an eth_call to this contract, from no
///         particular sender, while the Safe's nonce is still lower. So this contract reads neither the Safe's nonce nor
///         msg.sender. A transaction signature carries the Safe's address and the SafeTx fields; the owner recomputes
///         Safe's EIP-712 hash from them and refuses the signature unless it is the hash being checked. The key index
///         then follows from the SafeTx's own nonce: keyIndex = (nonce - start) * SLOTS + slot. So a WOTS key verifies
///         only for a SafeTx of one Safe, on one chain, at one nonce, and the signer uses each key once: slot 0 signs,
///         slot 1 is kept for a replacement or cancellation at the same nonce. The answer is the same before execution
///         (eth_call) and during it.
///
/// Signatures (the contract signature data that Safe appends to its signatures blob; the first byte is the kind):
///   Transaction, WOTS:      [slot: 1][safe: 20][SafeTx: 10 x 32][WOTS signature][path: N x height]
///                           SafeTx = abi.encode(to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice,
///                           gasToken, refundReceiver, nonce): the words of Safe's SafeTx struct after its type hash.
///   SafeMessage, stateless: [0x02][safe: 20][keccak256(message): 32][stateless signature: 5,684]
///                           The SafeMessage(bytes message) that Safe's CompatibilityFallbackHandler checks; for an app's
///                           isValidSignature(bytes32 h, ...) the message is abi.encode(h). The stateless key signs
///                           messageDigest(safe, SafeMessage hash).
///   Each kind is checked against the hash it claims to be: a SafeMessage signature can't approve a SafeTx, a WOTS
///   signature can't sign a message, and neither signs any other typed data a module might ask the Safe to check.
///
/// Enrolment: enroll(safe, root, height, start, stateless signature of certificateDigest). The certificate binds the
///   chain, this contract, the Safe, the root, the height and the start. Start sequences only grow: a new certificate
///   must start after the stored tree, so an old certificate can't bring back a tree it was replaced by. Only valid
///   certificates are stored. The tree's public seed is derived (treeSeed), not stored.
///
/// Address: deployed with CREATE2 through the deterministic deployment proxy, with KEY as the salt
///   (script/DeploySafeOwner.s.sol). Nothing in the constructor depends on the chain, so a member's owner, and a Safe
///   set up with such owners, has the same address on every chain.
///
/// @dev Status: research prototype. Unaudited. Not for real funds. Hash sizes up to 24 bytes (one slot per tree).
///      Supports Safe v1.3.0 and later (EIP-712 domain with chain id); checked against v1.4.1 and v1.5.0.
contract WinterlockOwner {
    /// Keys per nonce: slot 0 signs, slot 1 is reserved for a replacement or cancellation (D4).
    uint256 public constant SLOTS = 2;
    /// Largest operation tree.
    uint256 public constant MAX_HEIGHT = 40;
    /// A tree's start nonce must fit in 40 bits (packed storage).
    uint256 public constant MAX_START = (1 << 40) - 1;
    /// Length of a stateless signature (leanSphincs: n = 16, h = 26, FORS k = 24, a = 10).
    uint256 public constant STATELESS_SIG_LEN = 5684;
    /// Domains of what the stateless key signs, and of a tree's public seed. Distinct from WinterlockValidator's.
    bytes32 public constant CERTIFICATE_DOMAIN = keccak256("Winterlock.safe-owner.certificate.v1");
    bytes32 public constant MESSAGE_DOMAIN = keccak256("Winterlock.safe-owner.message.v1");
    bytes32 public constant TREE_SEED_DOMAIN = keccak256("Winterlock.safe-owner.tree-seed.v1");

    /// Safe's EIP-712 types (Safe.sol and CompatibilityFallbackHandler.sol, unchanged from v1.3.0 to v1.5.0)
    bytes32 internal constant SAFE_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 internal constant SAFE_TX_TYPEHASH = keccak256(
        "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    );
    bytes32 internal constant SAFE_MSG_TYPEHASH = keccak256("SafeMessage(bytes message)");

    /// isValidSignature(bytes32,bytes): asked by Safe v1.5.0, by the Transaction Service, and by apps
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    /// isValidSignature(bytes,bytes): asked by Safe up to v1.4.1 (legacy EIP-1271)
    bytes4 internal constant LEGACY_MAGIC_VALUE = 0x20c13b0b;
    bytes4 internal constant INVALID = 0xffffffff;

    uint256 internal constant KIND_MESSAGE = 0x02;
    /// The ten SafeTx words
    uint256 internal constant SAFE_TX_LEN = 320;
    /// Transaction signature before the WOTS signature: slot, safe, SafeTx
    uint256 internal constant TX_HEADER = 1 + 20 + SAFE_TX_LEN;
    /// SafeMessage signature: kind, safe, message hash, stateless signature
    uint256 internal constant MESSAGE_LEN = 1 + 20 + 32 + STATELESS_SIG_LEN;
    /// Low 64 bits of a packed tree: start << 8 | height
    uint256 internal constant META_MASK = (1 << 64) - 1;
    uint256 internal constant HIGH_128 = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

    /// Packed WOTS parameter set (WotsVerifier.encodeParams)
    uint256 public immutable PARAMS;
    /// Hash size in bytes (16 or 24)
    uint256 public immutable N;
    /// WOTS signature length for this parameter set
    uint256 internal immutable SIG_LEN;
    /// Verifier of the stateless key, shared by all owners and validators
    IStatelessVerifier public immutable STATELESS_VERIFIER;
    /// The member's stateless public key: leanSphincs root (16 bytes) ‖ public parameter P (16 bytes)
    bytes32 public immutable KEY;

    /// Operation tree per Safe on this chain: root in the high N bytes, then start (40 bits) and height (8 bits)
    mapping(address safe => uint256) internal _trees;

    event Enrolled(address indexed safe, bytes32 root, uint8 height, uint64 start);

    error InvalidConfig();
    error InvalidCertificate();

    constructor(uint256 params, IStatelessVerifier statelessVerifier, bytes32 key) {
        WotsVerifier.checkParams(params);
        if (params & 0xff > 24 || address(statelessVerifier).code.length == 0) revert InvalidConfig();
        // both halves set: a root and a public parameter
        if (uint256(key) >> 128 == 0 || uint128(uint256(key)) == 0) revert InvalidConfig();
        PARAMS = params;
        N = params & 0xff;
        SIG_LEN = WotsVerifier.sigBytes(params);
        STATELESS_VERIFIER = statelessVerifier;
        KEY = key;
    }

    // --- views ---

    /// The operation tree enrolled for `safe` on this chain (root 0 if none)
    function tree(address safe) public view returns (bytes32 root, uint128 seed, uint8 height, uint64 start) {
        uint256 word = _trees[safe];
        if (word == 0) return (0, 0, 0, 0);
        uint256 meta = word & META_MASK;
        root = bytes32(word ^ meta);
        // forge-lint: disable-next-line(unsafe-typecast)
        height = uint8(meta);
        // forge-lint: disable-next-line(unsafe-typecast)
        start = uint64(meta >> 8);
        seed = treeSeed(safe, start);
    }

    /// Public seed of the tree certified from `start` for `safe` on this chain. Unique per stored tree, because start
    /// nonces only grow.
    function treeSeed(address safe, uint64 start) public view returns (uint128) {
        // the seed is the hash's first 16 bytes
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint128(bytes16(keccak256(abi.encode(TREE_SEED_DOMAIN, block.chainid, address(this), safe, start))));
    }

    /// What the stateless key signs to certify an operation tree for `safe` on this chain
    function certificateDigest(address safe, bytes32 root, uint8 height, uint64 start) public view returns (bytes32) {
        return keccak256(abi.encode(CERTIFICATE_DOMAIN, block.chainid, address(this), safe, root, height, start));
    }

    /// What the stateless key signs to approve `safeMessageHash`, a SafeMessage of `safe` on this chain
    function messageDigest(address safe, bytes32 safeMessageHash) public view returns (bytes32) {
        return keccak256(abi.encode(MESSAGE_DOMAIN, block.chainid, address(this), safe, safeMessageHash));
    }

    // --- enrolment ---

    /// Stores the operation tree for `safe` on this chain. Anyone may send it, the Safe itself included (for example
    /// in a MultiSend next to swapOwner); only a certificate signed by KEY is stored.
    /// @param signature the stateless key's signature of certificateDigest(safe, root, height, start)
    function enroll(address safe, bytes32 root, uint8 height, uint64 start, bytes calldata signature) external {
        uint256 stored = _trees[safe];
        // root: n bytes, high-aligned (it shares its slot with start and height)
        if (root == bytes32(0) || uint256(root) << (8 * N) != 0 || height == 0 || height > MAX_HEIGHT) {
            revert InvalidCertificate();
        }
        // start nonces only grow
        if (start > MAX_START || (stored != 0 && start <= (stored & META_MASK) >> 8)) {
            revert InvalidCertificate();
        }
        if (!_statelessSigned(certificateDigest(safe, root, height, start), signature)) revert InvalidCertificate();
        _trees[safe] = uint256(root) | (uint256(start) << 8) | height;
        // the only external call above is a staticcall to the verifier
        // forge-lint: disable-next-line(reentrancy-events)
        emit Enrolled(safe, root, height, start);
    }

    // --- EIP-1271 ---

    /// EIP-1271 as Safe v1.5.0 and the Transaction Service ask it
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _isValid(hash, signature) ? MAGIC_VALUE : INVALID;
    }

    /// Legacy EIP-1271 as Safe up to v1.4.1 asks it: `data` is the EIP-712 preimage of the hash
    /// (0x1901 ‖ domain separator ‖ struct hash)
    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4) {
        return _isValid(keccak256(data), signature) ? LEGACY_MAGIC_VALUE : INVALID;
    }

    function _isValid(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signature.length < 21) return false;
        uint256 kind = uint8(signature[0]);
        address safe = address(bytes20(signature[1:21]));
        if (kind < SLOTS) return _transaction(hash, safe, kind, signature);
        if (kind == KIND_MESSAGE) return _message(hash, safe, signature);
        return false;
    }

    /// A WOTS signature of a SafeTx, with the key bound to the SafeTx's nonce
    function _transaction(bytes32 hash, address safe, uint256 slot, bytes calldata s) internal view returns (bool) {
        uint256 word = _trees[safe];
        uint256 height = word & 0xff;
        if (word == 0 || s.length != TX_HEADER + SIG_LEN + N * height) return false;
        if (_safeTxHash(safe, s[21:TX_HEADER]) != hash) return false;
        uint256 start = (word & META_MASK) >> 8;
        uint256 nonce = uint256(bytes32(s[TX_HEADER - 32:TX_HEADER]));
        // the tree holds 2^(height - 1) nonces from `start`, SLOTS keys each
        if (nonce < start || (nonce - start) >> (height - 1) != 0) return false;
        // forge-lint: disable-next-line(unsafe-typecast)
        return _wotsSigned(word, treeSeed(safe, uint64(start)), (nonce - start) * SLOTS + slot, hash, s[TX_HEADER:]);
    }

    /// Whether `sig` ([WOTS signature][path]) is key `keyIndex`'s signature of `hash` under the packed tree `word`
    function _wotsSigned(uint256 word, uint128 seed, uint256 keyIndex, bytes32 hash, bytes calldata sig)
        internal
        view
        returns (bool)
    {
        bytes32 root = WotsVerifier.computeRoot(PARAMS, seed, keyIndex, hash, sig[:SIG_LEN], sig[SIG_LEN:]);
        return root != bytes32(0) && root == bytes32(word & ~META_MASK);
    }

    /// A stateless signature of a SafeMessage of `safe`
    function _message(bytes32 hash, address safe, bytes calldata s) internal view returns (bool) {
        if (s.length != MESSAGE_LEN) return false;
        bytes32 structHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, bytes32(s[21:53])));
        if (_eip712(safe, structHash) != hash) return false;
        return _statelessSigned(messageDigest(safe, hash), s[53:]);
    }

    /// Safe's transaction hash (Safe.getTransactionHash) from the ten SafeTx words
    function _safeTxHash(address safe, bytes calldata safeTx) internal view returns (bytes32) {
        bytes32 structHash;
        bytes32 typeHash = SAFE_TX_TYPEHASH;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, typeHash)
            calldatacopy(add(m, 0x20), safeTx.offset, SAFE_TX_LEN)
            structHash := keccak256(m, add(0x20, SAFE_TX_LEN))
        }
        return _eip712(safe, structHash);
    }

    /// keccak256(0x1901 ‖ Safe's domain separator on this chain ‖ structHash)
    function _eip712(address safe, bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(SAFE_DOMAIN_TYPEHASH, block.chainid, safe));
        return keccak256(abi.encodePacked(bytes2(0x1901), domain, structHash));
    }

    /// Whether `sig` is KEY's signature of `message`. The verifier takes both halves of the key high-aligned. A call
    /// that reverts (wrong length, non-canonical input) counts as an invalid signature.
    function _statelessSigned(bytes32 message, bytes calldata sig) internal view returns (bool valid) {
        address verifier = address(STATELESS_VERIFIER);
        bytes32 key = KEY;
        bytes4 selector = IStatelessVerifier.verify.selector;
        assembly ("memory-safe") {
            // verify(pkSeed, pkRoot, message, sig), encoded beyond the free memory pointer
            let m := mload(0x40)
            mstore(m, selector)
            mstore(add(m, 0x04), shl(128, key))
            mstore(add(m, 0x24), and(key, HIGH_128))
            mstore(add(m, 0x44), message)
            mstore(add(m, 0x64), 0x80)
            mstore(add(m, 0x84), sig.length)
            let padded := and(add(sig.length, 31), not(31))
            if padded { mstore(add(add(m, 0xa4), sub(padded, 0x20)), 0) }
            calldatacopy(add(m, 0xa4), sig.offset, sig.length)
            let ok := staticcall(gas(), verifier, m, add(0xa4, padded), 0x00, 0x20)
            valid := and(ok, and(eq(returndatasize(), 0x20), eq(mload(0x00), 1)))
        }
    }
}
