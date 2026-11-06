// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IStatelessVerifier} from "../interfaces/IStatelessVerifier.sol";
import {IWotsVerifier} from "../interfaces/IWotsVerifier.sol";
import {WotsVerifier} from "../WotsVerifier.sol";

/// The one Safe function the approved kind reads (Safe v1.3.0 to v1.5.0): set by SignMessageLib.signMessage
interface ISafeSignedMessages {
    function signedMessages(bytes32 messageHash) external view returns (uint256);
}

/// @title WinterlockOwner (v2)
/// @notice A Safe owner for one member: an EIP-1271 contract owner (signature type v = 0) that Safe's ordinary
///         multisig path checks. A team keeps its Safe, its address, and Safe's app and Transaction Service; each
///         member's ECDSA owner is swapped for the member's WinterlockOwner (OwnerManager.swapOwner).
///         The same verifiers as WinterlockValidator (D1), both as shared contracts: WotsVerifier behind
///         SharedWotsVerifier, and the stateless verifier. Version 2 (docs/notes/owner-v2.md) adds device keys and the
///         approved signature kind; to keep its code within the deployment budget, it calls WOTS verification in a
///         shared contract instead of carrying it in its own code as v1 did.
///
///         Keys of the member (D10–D12):
///         - The member key: a stateless leanSphincs-keccak key from the member's recovery phrase, fixed at
///           deployment in the member's proxy (KEY). The owner's address follows from it. It is device 0: it signs
///           everything a device key signs, and it alone certifies and revokes device keys.
///         - Up to three device keys, devices 1 to 3: leanSphincs-keccak keys that a member's devices make from their
///           own seeds, without the phrase, checked by the same stateless verifier. A device key certifies its
///           device's operation trees and signs SafeMessages for it. The phrase can then stay offline, and a lost or
///           stolen device can be cut off on-chain.
///         - Per Safe, chain and device, an operation tree of WOTS keys that signs Safe transactions. A permissionless
///           `enroll` transaction stores it once its certificate verifies. Safe checks owners with view calls, which
///           can't store anything, so a certificate can't ride in a Safe signature as it does in a UserOperation.
///           Each device has its own trees, so two devices never share a one-time key, even at the same nonce.
///
/// Devices. Per device key, two words: the key, and its generation with an active flag.
///   - certifyDevice(device, generation, key, member key's signature of deviceDigest): the generation must be the
///     stored one plus one, so an old certificate can't come back. It replaces the key of an active device.
///   - revokeDevice(device, generation, member key's signature of revocationDigest): the device must be active at
///     that generation. It clears the active flag and keeps the generation.
///   - Anyone may send either. Device 0, the member key, can't be certified or revoked: it is active at generation
///     0 for good.
///   - What a device signed or certified counts only while the device is active at the generation it was signed
///     under: a revoke or a replacement ends its trees and its messages, including confirmations it gave for
///     transactions not yet executed.
///
/// Nonce binding (D2, D4). Safe increments its nonce before it checks signatures (Safe.execTransaction, v1.4.1 and
///         v1.5.0), and its Transaction Service checks a confirmation with an eth_call to this contract, from no
///         particular sender, while the Safe's nonce is still lower. So this contract reads neither the Safe's nonce nor
///         msg.sender. A transaction signature carries the Safe's address and the SafeTx fields; the owner recomputes
///         Safe's EIP-712 hash from them and refuses the signature unless it is the hash being checked. The key index
///         then follows from the SafeTx's own nonce: keyIndex = (nonce - start) * SLOTS + slot. So a WOTS key verifies
///         only for a SafeTx of one Safe, on one chain, at one nonce, and the signer uses each key once: slot 0 signs,
///         slot 1 is kept for a replacement or cancellation at the same nonce. The answer is the same before execution
///         (eth_call) and during it, as long as the device stays active.
///
/// Signatures (the contract signature data that Safe appends to its signatures blob; the first byte is the kind):
///   Transaction, WOTS:      [slot: 1][device: 1][safe: 20][SafeTx: 10 x 32][WOTS signature][path: N x height]
///                           SafeTx = abi.encode(to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice,
///                           gasToken, refundReceiver, nonce): the words of Safe's SafeTx struct after its type hash.
///                           Checked against the device's tree for the Safe.
///   SafeMessage, stateless: [0x02][device: 1][safe: 20][keccak256(message): 32][stateless signature: 5,684]
///                           The SafeMessage(bytes message) that Safe's CompatibilityFallbackHandler checks; for an app's
///                           isValidSignature(bytes32 h, ...) the message is abi.encode(h). The device's key (the member
///                           key for device 0) signs messageDigest(safe, device, generation, SafeMessage hash).
///   SafeMessage, approved:  [0x03][safe: 20][keccak256(message): 32]
///                           Valid when the hash is that Safe's SafeMessage hash and the Safe has approved it on-chain:
///                           Safe.signedMessages(hash) != 0, which a quorum-signed transaction through SignMessageLib sets.
///                           No key signs it, so anyone can build it: it is exactly as strong as the empty signature
///                           that the fallback handler accepts for an approved message. A wallet answers apps that
///                           refuse the empty signature (viem) with k of these instead.
///   Each kind is checked against the hash it claims to be: a SafeMessage signature can't approve a SafeTx, a WOTS
///   signature can't sign a message, and none signs any other typed data a module might ask the Safe to check.
///
/// Enrolment: enroll(safe, device, root, height, start, signature). The device's key (the member key for device 0)
///   signs certificateDigest, which binds the chain, this contract, the Safe, the device and its generation, the root,
///   the height and the start; the device must be active. Within a generation, start nonces only grow, per Safe and
///   device: a new certificate must start after the stored tree, so an old certificate can't bring back a tree it was
///   replaced by. A tree of an earlier generation no longer verifies and sets no bound. Only valid certificates are
///   stored, one word per Safe and device: root (N bytes, high) ‖ generation (16 bits) ‖ start (40 bits) ‖
///   height (8 bits). The tree's public seed is derived (treeSeed), not stored.
///
/// Deployment: one implementation per chain and parameter set, and a minimal proxy per member.
///   - This contract is the implementation. It holds the code and the parameter set (immutables), and no key: called
///     directly, KEY() is 0, so it can't certify a device or a tree or sign anything, and it is nobody's owner.
///   - A member's owner is an ERC-1167 minimal proxy of it with the member key appended to the proxy's code (Solady
///     LibClone, clone with immutable args): [45-byte proxy][KEY: 32], 77 bytes in all. The proxy DELEGATECALLs here,
///     so address(this) is the member's owner in every digest and seed, and the devices and trees live in the proxy's
///     storage. The member key is read from the proxy's own code (EXTCODECOPY of address(this)), never from calldata,
///     so no caller can choose it.
///   - WinterlockOwnerFactory creates the proxies with CREATE2, with the member key as the salt. The implementation and
///     the factory are deployed through the deterministic deployment proxy with fixed salts
///     (script/DeploySafeOwner.s.sol). Nothing in any of the three depends on the chain, so a member's owner, and a
///     Safe set up with such owners, has the same address on every chain.
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
    /// Devices: 0 is the member key, 1 to MAX_DEVICE are device keys.
    uint256 public constant MAX_DEVICE = 3;
    /// Length of a stateless signature (leanSphincs: n = 16, h = 26, FORS k = 24, a = 10), of the member key and of
    /// device keys alike.
    uint256 public constant STATELESS_SIG_LEN = 5684;
    /// Domains of what the member key and device keys sign, and of a tree's public seed. Distinct from v1's and from
    /// WinterlockValidator's.
    bytes32 public constant DEVICE_DOMAIN = keccak256("Winterlock.safe-owner.device.v2");
    bytes32 public constant REVOCATION_DOMAIN = keccak256("Winterlock.safe-owner.revocation.v2");
    bytes32 public constant CERTIFICATE_DOMAIN = keccak256("Winterlock.safe-owner.certificate.v2");
    bytes32 public constant MESSAGE_DOMAIN = keccak256("Winterlock.safe-owner.message.v2");
    bytes32 public constant TREE_SEED_DOMAIN = keccak256("Winterlock.safe-owner.tree-seed.v2");

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
    uint256 internal constant KIND_APPROVED = 0x03;
    /// The ten SafeTx words
    uint256 internal constant SAFE_TX_LEN = 320;
    /// Transaction and SafeMessage signatures begin with kind, device and safe
    uint256 internal constant PREFIX = 1 + 1 + 20;
    /// Transaction signature before the WOTS signature: slot, device, safe, SafeTx
    uint256 internal constant TX_HEADER = PREFIX + SAFE_TX_LEN;
    /// SafeMessage signature: kind, device, safe, message hash, stateless signature
    uint256 internal constant MESSAGE_LEN = PREFIX + 32 + STATELESS_SIG_LEN;
    /// Approved SafeMessage: kind, safe, message hash
    uint256 internal constant APPROVED_LEN = 1 + 20 + 32;
    /// Low 64 bits of a packed tree: generation << 48 | start << 8 | height
    uint256 internal constant META_MASK = (1 << 64) - 1;
    /// A device's state: its generation in the low 16 bits, and ACTIVE while it is active
    uint256 internal constant GENERATION_MASK = (1 << 16) - 1;
    uint256 internal constant ACTIVE = 1 << 16;
    /// Where a member's proxy keeps the key: right after the 45-byte ERC-1167 proxy code (LibClone's clone with
    /// immutable args)
    uint256 internal constant KEY_OFFSET = 0x2d;
    uint256 internal constant HIGH_128 = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

    /// Packed WOTS parameter set (WotsVerifier.encodeParams)
    uint256 public immutable PARAMS;
    /// Hash size in bytes (16 or 24)
    uint256 public immutable N;
    /// WOTS signature length for this parameter set
    uint256 internal immutable SIG_LEN;
    /// Verifier of the stateless keys (member and device keys), shared by all owners and validators
    IStatelessVerifier public immutable STATELESS_VERIFIER;
    /// Verifier of WOTS signatures and their tree paths (SharedWotsVerifier), shared by all owners
    IWotsVerifier public immutable WOTS_VERIFIER;
    /// This implementation's own address. In a member's proxy, which runs this code by DELEGATECALL, address(this) is
    /// the proxy's instead.
    address public immutable IMPLEMENTATION;

    /// A device key and its state: generation | ACTIVE while the device is active
    struct Device {
        bytes32 key;
        uint256 state;
    }

    /// Operation trees per Safe on this chain, one per device: root in the high N bytes, then the device's generation
    /// (16 bits), start (40 bits) and height (8 bits)
    mapping(address safe => uint256[MAX_DEVICE + 1]) internal _trees;
    /// Device keys 1 to MAX_DEVICE; entry 0 stays empty (the member key is in the proxy's code)
    Device[MAX_DEVICE + 1] internal _devices;

    event DeviceCertified(uint8 indexed device, uint16 generation, bytes32 key);
    event DeviceRevoked(uint8 indexed device, uint16 generation);
    event Enrolled(
        address indexed safe, uint8 indexed device, uint16 generation, bytes32 root, uint8 height, uint64 start
    );

    error InvalidConfig();
    error InvalidCertificate();
    error InvalidRevocation();

    /// The implementation, for one parameter set. The members' keys come with their proxies (WinterlockOwnerFactory).
    constructor(uint256 params, IStatelessVerifier statelessVerifier, IWotsVerifier wotsVerifier) {
        WotsVerifier.checkParams(params);
        if (params & 0xff > 24) revert InvalidConfig();
        if (address(statelessVerifier).code.length == 0 || address(wotsVerifier).code.length == 0) {
            revert InvalidConfig();
        }
        PARAMS = params;
        N = params & 0xff;
        SIG_LEN = WotsVerifier.sigBytes(params);
        STATELESS_VERIFIER = statelessVerifier;
        WOTS_VERIFIER = wotsVerifier;
        IMPLEMENTATION = address(this);
    }

    // --- views ---

    /// The member key: leanSphincs root (16 bytes) ‖ public parameter P (16 bytes). 0 on the implementation itself,
    /// which has no key.
    // forge-lint: disable-next-line(mixed-case-function)
    function KEY() external view returns (bytes32) {
        return _key();
    }

    /// Device `device`'s key, generation, and whether it is active. Device 0 is the member key, active at generation
    /// 0 wherever there is one. Reverts for a device above MAX_DEVICE.
    function devices(uint8 device) external view returns (bytes32 key, uint16 generation, bool active) {
        if (device == 0) {
            key = _key();
            return (key, 0, key != 0);
        }
        Device storage d = _devices[device];
        uint256 state = d.state;
        // forge-lint: disable-next-line(unsafe-typecast)
        return (d.key, uint16(state), state & ACTIVE != 0);
    }

    /// The operation tree enrolled for `safe` and `device` on this chain (root 0 if none). It verifies only while the
    /// device is active at `generation`. Reverts for a device above MAX_DEVICE.
    function tree(address safe, uint8 device)
        external
        view
        returns (bytes32 root, uint128 seed, uint8 height, uint64 start, uint16 generation)
    {
        uint256 word = _trees[safe][device];
        if (word == 0) return (0, 0, 0, 0, 0);
        uint256 meta = word & META_MASK;
        root = bytes32(word ^ meta);
        // forge-lint: disable-next-line(unsafe-typecast)
        height = uint8(meta);
        // forge-lint: disable-next-line(unsafe-typecast)
        start = uint64((meta >> 8) & MAX_START);
        // forge-lint: disable-next-line(unsafe-typecast)
        generation = uint16(meta >> 48);
        seed = _seed(safe, device, word);
    }

    /// Public seed of the tree that `device`, at `generation`, certified from `start` for `safe` on this chain. Unique
    /// per stored tree, because start nonces only grow within a generation.
    function treeSeed(address safe, uint8 device, uint16 generation, uint64 start) public view returns (uint128) {
        bytes32 h =
            keccak256(abi.encode(TREE_SEED_DOMAIN, block.chainid, address(this), safe, device, generation, start));
        // the seed is the hash's first 16 bytes
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint128(bytes16(h));
    }

    /// What the member key signs to certify `key` as device `device`'s key from `generation` on, on this chain
    function deviceDigest(uint8 device, uint16 generation, bytes32 key) public view returns (bytes32) {
        return keccak256(abi.encode(DEVICE_DOMAIN, block.chainid, address(this), device, generation, key));
    }

    /// What the member key signs to revoke device `device` at `generation` on this chain
    function revocationDigest(uint8 device, uint16 generation) public view returns (bytes32) {
        return keccak256(abi.encode(REVOCATION_DOMAIN, block.chainid, address(this), device, generation));
    }

    /// What the device's key (the member key for device 0) signs to certify an operation tree of `device`, at
    /// `generation`, for `safe` on this chain
    function certificateDigest(address safe, uint8 device, uint16 generation, bytes32 root, uint8 height, uint64 start)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(CERTIFICATE_DOMAIN, block.chainid, address(this), safe, device, generation, root, height, start)
        );
    }

    /// What the device's key (the member key for device 0) signs, at `generation`, to approve `safeMessageHash`, a
    /// SafeMessage of `safe` on this chain
    function messageDigest(address safe, uint8 device, uint16 generation, bytes32 safeMessageHash)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(MESSAGE_DOMAIN, block.chainid, address(this), safe, device, generation, safeMessageHash)
        );
    }

    // --- devices ---

    /// Certifies `key` as the key of device `device` from `generation` on, replacing its key if it is active. Anyone
    /// may send it; only a certificate signed by the member key counts.
    /// @param device 1 to MAX_DEVICE
    /// @param generation the device's stored generation plus one
    /// @param key the device's leanSphincs-keccak public key: root (16 bytes) ‖ public parameter P (16 bytes)
    /// @param signature the member key's stateless signature of deviceDigest(device, generation, key)
    function certifyDevice(uint8 device, uint16 generation, bytes32 key, bytes calldata signature) external {
        // both halves of the key set: a root and a public parameter
        if (device == 0 || device > MAX_DEVICE || uint256(key) >> 128 == 0 || uint128(uint256(key)) == 0) {
            revert InvalidCertificate();
        }
        Device storage d = _devices[device];
        if (generation != (d.state & GENERATION_MASK) + 1) revert InvalidCertificate();
        if (!_statelessSigned(_key(), deviceDigest(device, generation, key), signature)) revert InvalidCertificate();
        d.key = key;
        d.state = generation | ACTIVE;
        // the only external call above is a staticcall to the verifier
        // forge-lint: disable-next-line(reentrancy-events)
        emit DeviceCertified(device, generation, key);
    }

    /// Revokes device `device`, active at `generation`: its trees and its message signatures stop verifying. Anyone
    /// may send it; only a revocation signed by the member key counts.
    /// @param signature the member key's stateless signature of revocationDigest(device, generation)
    function revokeDevice(uint8 device, uint16 generation, bytes calldata signature) external {
        if (device == 0 || device > MAX_DEVICE) revert InvalidRevocation();
        Device storage d = _devices[device];
        if (d.state != generation | ACTIVE) revert InvalidRevocation();
        if (!_statelessSigned(_key(), revocationDigest(device, generation), signature)) revert InvalidRevocation();
        d.state = generation;
        // the only external call above is a staticcall to the verifier
        // forge-lint: disable-next-line(reentrancy-events)
        emit DeviceRevoked(device, generation);
    }

    // --- enrolment ---

    /// Stores the operation tree of `device` for `safe` on this chain. Anyone may send it, the Safe itself included
    /// (for example in a MultiSend next to swapOwner); only a certificate signed by the device's key, while the device
    /// is active, is stored.
    /// @param signature the stateless signature of certificateDigest(safe, device, generation, root, height, start) by
    ///        the device's key (the member key for device 0), with the device's current generation
    function enroll(address safe, uint8 device, bytes32 root, uint8 height, uint64 start, bytes calldata signature)
        external
    {
        if (device > MAX_DEVICE) revert InvalidCertificate();
        // root: n bytes, high-aligned (it shares its slot with generation, start and height)
        if (root == bytes32(0) || uint256(root) << (8 * N) != 0 || height == 0 || height > MAX_HEIGHT) {
            revert InvalidCertificate();
        }
        (bytes32 key, uint256 generation) = _signer(device);
        uint256 stored = _trees[safe][device];
        // within a generation, start nonces only grow; a tree of an earlier generation sets no bound
        if (
            start > MAX_START
                || (stored != 0 && (stored >> 48) & GENERATION_MASK == generation && start <= (stored >> 8) & MAX_START)
        ) {
            revert InvalidCertificate();
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 digest = certificateDigest(safe, device, uint16(generation), root, height, start);
        if (!_statelessSigned(key, digest, signature)) revert InvalidCertificate();
        _trees[safe][device] = uint256(root) | (generation << 48) | (uint256(start) << 8) | height;
        // the only external call above is a staticcall to the verifier
        // forge-lint: disable-next-line(reentrancy-events,unsafe-typecast)
        emit Enrolled(safe, device, uint16(generation), root, height, start);
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
        if (signature.length < PREFIX) return false;
        uint256 kind = uint8(signature[0]);
        if (kind == KIND_APPROVED) return _approved(hash, signature);
        uint256 device = uint8(signature[1]);
        if (kind > KIND_MESSAGE || device > MAX_DEVICE) return false;
        address safe = address(bytes20(signature[2:PREFIX]));
        if (kind == KIND_MESSAGE) return _message(hash, safe, device, signature);
        return _transaction(hash, safe, device, kind, signature);
    }

    /// A WOTS signature of a SafeTx by `device`'s tree, with the key bound to the SafeTx's nonce
    function _transaction(bytes32 hash, address safe, uint256 device, uint256 slot, bytes calldata s)
        internal
        view
        returns (bool)
    {
        uint256 word = _trees[safe][device];
        // a tree, whose device is active at the tree's generation (the member key always is, at 0)
        if (word == 0 || _state(device) != ((word >> 48) & GENERATION_MASK) | ACTIVE) return false;
        if (s.length != TX_HEADER + SIG_LEN + N * (word & 0xff)) return false;
        if (_safeTxHash(safe, s[PREFIX:TX_HEADER]) != hash) return false;
        uint256 start = (word >> 8) & MAX_START;
        uint256 nonce = uint256(bytes32(s[TX_HEADER - 32:TX_HEADER]));
        // the tree holds 2^(height - 1) nonces from `start`, SLOTS keys each
        if (nonce < start || (nonce - start) >> ((word & 0xff) - 1) != 0) return false;
        return _wotsSigned(word, _seed(safe, device, word), (nonce - start) * SLOTS + slot, hash, s[TX_HEADER:]);
    }

    /// Whether `sig` ([WOTS signature][path]) is key `keyIndex`'s signature of `hash` under the packed tree `word`,
    /// as the shared WOTS verifier computes it. The caller has checked the lengths; a call that reverts all the same
    /// counts as an invalid signature.
    function _wotsSigned(uint256 word, uint128 seed, uint256 keyIndex, bytes32 hash, bytes calldata sig)
        internal
        view
        returns (bool valid)
    {
        address verifier = address(WOTS_VERIFIER);
        uint256 params = PARAMS;
        bytes4 selector = IWotsVerifier.computeRoot.selector;
        assembly ("memory-safe") {
            // computeRoot(params, seed, keyIndex, hash, sig), encoded beyond the free memory pointer
            let m := mload(0x40)
            mstore(m, selector)
            mstore(add(m, 0x04), params)
            mstore(add(m, 0x24), seed)
            mstore(add(m, 0x44), keyIndex)
            mstore(add(m, 0x64), hash)
            mstore(add(m, 0x84), 0xa0)
            mstore(add(m, 0xa4), sig.length)
            let padded := and(add(sig.length, 31), not(31))
            if padded { mstore(add(add(m, 0xc4), sub(padded, 0x20)), 0) }
            calldatacopy(add(m, 0xc4), sig.offset, sig.length)
            let ok := staticcall(gas(), verifier, m, add(0xc4, padded), 0x00, 0x20)
            let root := mload(0x00)
            // a nonzero root, the one stored in the high bytes of the tree's word
            valid := and(
                and(ok, eq(returndatasize(), 0x20)),
                and(iszero(iszero(root)), eq(root, and(word, not(META_MASK))))
            )
        }
    }

    /// A stateless signature of a SafeMessage of `safe` by `device`'s key
    function _message(bytes32 hash, address safe, uint256 device, bytes calldata s) internal view returns (bool) {
        if (s.length != MESSAGE_LEN || _safeMessageHash(safe, bytes32(s[PREFIX:PREFIX + 32])) != hash) return false;
        (bytes32 key, uint256 generation) = _signer(device);
        // forge-lint: disable-next-line(unsafe-typecast)
        return _statelessSigned(key, messageDigest(safe, uint8(device), uint16(generation), hash), s[PREFIX + 32:]);
    }

    /// A SafeMessage of `safe` that the Safe has approved on-chain (Safe.signedMessages). An account without code, a
    /// call that reverts, and an answer shorter than a word count as not approved.
    function _approved(bytes32 hash, bytes calldata s) internal view returns (bool approved) {
        if (s.length != APPROVED_LEN) return false;
        address safe = address(bytes20(s[1:21]));
        // the hash first: the Safe is asked only about its own SafeMessage
        if (_safeMessageHash(safe, bytes32(s[21:APPROVED_LEN])) != hash) return false;
        bytes4 selector = ISafeSignedMessages.signedMessages.selector;
        assembly ("memory-safe") {
            // signedMessages(hash), encoded in scratch space
            mstore(0x00, selector)
            mstore(0x04, hash)
            if extcodesize(safe) {
                let ok := staticcall(gas(), safe, 0x00, 0x24, 0x00, 0x20)
                approved := and(ok, and(gt(returndatasize(), 0x1f), iszero(iszero(mload(0x00)))))
            }
        }
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

    /// The hash of SafeMessage(message) for `safe` on this chain, from keccak256(message), as the fallback handler
    /// computes it (getMessageHashForSafe)
    function _safeMessageHash(address safe, bytes32 messageHash) internal view returns (bytes32) {
        return _eip712(safe, keccak256(abi.encode(SAFE_MSG_TYPEHASH, messageHash)));
    }

    /// keccak256(0x1901 ‖ Safe's domain separator on this chain ‖ structHash)
    function _eip712(address safe, bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(SAFE_DOMAIN_TYPEHASH, block.chainid, safe));
        return keccak256(abi.encodePacked(bytes2(0x1901), domain, structHash));
    }

    /// The public seed of `device`'s packed tree `word` for `safe` (treeSeed with the tree's generation and start)
    function _seed(address safe, uint256 device, uint256 word) internal view returns (uint128) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return treeSeed(safe, uint8(device), uint16(word >> 48), uint64((word >> 8) & MAX_START));
    }

    /// `device`'s generation | ACTIVE while it is active. The member key, device 0, is always active, at generation 0.
    function _state(uint256 device) internal view returns (uint256) {
        return device == 0 ? ACTIVE : _devices[device].state;
    }

    /// The key that signs for `device`, and the device's generation. The key is 0, which signs nothing, unless the
    /// device is active.
    function _signer(uint256 device) internal view returns (bytes32 key, uint256 generation) {
        uint256 state = _state(device);
        generation = state & GENERATION_MASK;
        if (state & ACTIVE != 0) key = device == 0 ? _key() : _devices[device].key;
    }

    /// The member key appended to this member's proxy code; 0 when called on the implementation itself. Everything
    /// the member key approves (device keys, device 0's trees and messages) goes through _statelessSigned, which
    /// refuses a zero key; device keys can only be certified by it.
    /// Virtual only for the gas tests, which measure the spike's full-contract design with it
    /// (test/utils/FullWinterlockOwner.sol).
    function _key() internal view virtual returns (bytes32 key) {
        if (address(this) == IMPLEMENTATION) return 0;
        assembly ("memory-safe") {
            // scratch space; a code shorter than the proxy and key reads as zeros
            extcodecopy(address(), 0x00, KEY_OFFSET, 0x20)
            key := mload(0x00)
        }
    }

    /// Whether `sig` is `key`'s signature of `message`. The verifier takes both halves of the key high-aligned. A call
    /// that reverts (wrong length, non-canonical input) counts as an invalid signature, and so does any signature when
    /// the key is 0 (no member key, or a device that isn't active).
    function _statelessSigned(bytes32 key, bytes32 message, bytes calldata sig) internal view returns (bool valid) {
        if (key == 0) return false;
        address verifier = address(STATELESS_VERIFIER);
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
