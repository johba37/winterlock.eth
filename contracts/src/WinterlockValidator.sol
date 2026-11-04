// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, MODULE_TYPE_VALIDATOR} from "./interfaces/IERC7579Module.sol";
import {WotsVerifier} from "./WotsVerifier.sol";

/// @title WinterlockValidator
/// @notice ERC-7579 validator that accepts UserOperations signed with WOTS+ one-time keys from a Merkle
///         tree. Each key is bound to one nonce: keyIndex = sequence * SLOTS + slot (decisions D2, D4).
///         Each deployment fixes one parameter set (hash size and encoding, see WotsVerifier).
/// @dev Signature layout: [slot: 1 byte][WOTS signature: WotsVerifier.sigBytes][Merkle path: height * n bytes]
///      Status: research prototype. Unaudited. Not for real funds.
contract WinterlockValidator is IValidator {
    /// Keys per nonce: slot 0 signs, slot 1 is reserved for a replacement or cancellation.
    uint256 public constant SLOTS = 2;

    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant VALIDATION_FAILED = 1;

    /// Hash size in bytes (16, 24 or 32).
    uint256 public immutable N;
    /// 0 for checksum encoding, otherwise the required digit sum.
    uint256 public immutable TARGET_SUM;
    uint256 internal immutable HEADER;

    struct Config {
        bytes32 root;
        uint128 seed;
        uint8 height;
        uint192 nonceKey; // the only EntryPoint nonce lane this validator signs on
    }

    mapping(address account => Config) internal _config;

    error AlreadyInitialized();
    error InvalidConfig();

    constructor(uint256 n, uint256 targetSum) {
        if ((n != 16 && n != 24 && n != 32) || targetSum > 30 * n) revert InvalidConfig();
        N = n;
        TARGET_SUM = targetSum;
        HEADER = 1 + WotsVerifier.sigBytes(n, targetSum);
    }

    /// @param data abi.encode(bytes32 root, uint128 seed, uint8 height, uint192 nonceKey)
    function onInstall(bytes calldata data) external {
        (bytes32 root, uint128 seed, uint8 height, uint192 nonceKey) =
            abi.decode(data, (bytes32, uint128, uint8, uint192));
        if (_config[msg.sender].root != bytes32(0)) revert AlreadyInitialized();
        if (root == bytes32(0) || height == 0 || height > 40) revert InvalidConfig();
        _config[msg.sender] = Config(root, seed, height, nonceKey);
    }

    function onUninstall(bytes calldata) external {
        delete _config[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view returns (bool) {
        return _config[account].root != bytes32(0);
    }

    function config(address account) external view returns (Config memory) {
        return _config[account];
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        returns (uint256)
    {
        Config storage c = _config[msg.sender];
        uint256 height = c.height;
        bytes calldata s = userOp.signature;
        uint256 header = HEADER;

        if (height == 0 || s.length != header + N * height) return VALIDATION_FAILED;
        // nonce = key (192 bits) || sequence (64 bits); both casts below split it exactly
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint192(userOp.nonce >> 64) != c.nonceKey) return VALIDATION_FAILED;

        uint256 slot = uint8(s[0]);
        if (slot >= SLOTS) return VALIDATION_FAILED;

        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 keyIndex = uint256(uint64(userOp.nonce)) * SLOTS + slot;
        if (keyIndex >> height != 0) return VALIDATION_FAILED; // tree exhausted

        bytes32 root =
            WotsVerifier.computeRoot(N, TARGET_SUM, c.seed, keyIndex, userOpHash, s[1:header], s[header:]);
        return (root != bytes32(0) && root == c.root) ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /// Off-chain messages (ERC-1271) are an open question; until then this validator signs none.
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
