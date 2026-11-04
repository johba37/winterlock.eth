// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, MODULE_TYPE_VALIDATOR} from "../../src/interfaces/IERC7579Module.sol";
import {WotsVerifier} from "../../src/WotsVerifier.sol";

/// @notice The smallest 4337 account that sends validation to a 7579-style validator through an
///         external call. Real 7579 accounts (Kernel, Nexus, Safe7579) add the same dispatch overhead
///         whichever validator is installed, so deltas measured on this account carry over.
contract MiniAccount is IAccount {
    IEntryPoint public immutable entryPoint;
    IValidator public immutable validator;

    constructor(IEntryPoint entryPoint_, IValidator validator_, bytes memory installData) payable {
        entryPoint = entryPoint_;
        validator = validator_;
        validator_.onInstall(installData);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        require(msg.sender == address(entryPoint), "not EntryPoint");
        validationData = validator.validateUserOp(userOp, userOpHash);
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok);
        }
    }

    function execute(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == address(entryPoint), "not EntryPoint");
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    receive() external payable {}
}

/// @notice Baseline: the same ECDSA check SimpleAccount performs, packaged as a validator.
contract EcdsaValidator is IValidator {
    mapping(address => address) public owner;

    function onInstall(bytes calldata data) external {
        owner[msg.sender] = abi.decode(data, (address));
    }

    function onUninstall(bytes calldata) external {
        delete owner[msg.sender];
    }

    function isModuleType(uint256 t) external pure returns (bool) {
        return t == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address a) external view returns (bool) {
        return owner[a] != address(0);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        bytes calldata s = userOp.signature;
        if (s.length != 65) return 1;
        bytes32 h = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        address rec = ecrecover(h, uint8(s[64]), bytes32(s[0:32]), bytes32(s[32:64]));
        return (rec != address(0) && rec == owner[msg.sender]) ? 0 : 1;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}

/// @notice Exposes the library with real calldata, for unit tests and isolated gas measurement.
contract VerifierHarness {
    function computeRoot(
        uint256 n,
        uint256 targetSum,
        uint128 seed,
        uint256 keyIndex,
        bytes32 message,
        bytes calldata sig,
        bytes calldata path
    ) external pure returns (bytes32) {
        return WotsVerifier.computeRoot(n, targetSum, seed, keyIndex, message, sig, path);
    }

    /// Gas of the library call alone, measured inside the callee where memory is fresh.
    function computeRootGas(
        uint256 n,
        uint256 targetSum,
        uint128 seed,
        uint256 keyIndex,
        bytes32 message,
        bytes calldata sig,
        bytes calldata path
    ) external view returns (bytes32 root, uint256 gasUsed) {
        gasUsed = gasleft();
        root = WotsVerifier.computeRoot(n, targetSum, seed, keyIndex, message, sig, path);
        gasUsed -= gasleft();
    }
}

/// @notice Baseline for multisig: k-of-n ECDSA owners, signatures sorted by signer address
///         (the same shape as Safe's or Rhinestone's OwnableValidator checks).
contract EcdsaThresholdValidator is IValidator {
    struct Config {
        uint8 threshold;
        uint8 count;
        address[16] owners;
    }

    mapping(address => Config) internal _config;

    /// @param data abi.encode(uint8 threshold, address[] owners)
    function onInstall(bytes calldata data) external {
        (uint8 threshold, address[] memory owners) = abi.decode(data, (uint8, address[]));
        Config storage c = _config[msg.sender];
        c.threshold = threshold;
        c.count = uint8(owners.length);
        for (uint256 i; i < owners.length; ++i) {
            c.owners[i] = owners[i];
        }
    }

    function onUninstall(bytes calldata) external {
        delete _config[msg.sender];
    }

    function isModuleType(uint256 t) external pure returns (bool) {
        return t == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address a) external view returns (bool) {
        return _config[a].count != 0;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        Config storage c = _config[msg.sender];
        bytes calldata s = userOp.signature;
        if (s.length % 65 != 0) return 1;
        bytes32 h = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        address last;
        uint256 valid;
        for (uint256 off; off < s.length; off += 65) {
            address rec = ecrecover(h, uint8(s[off + 64]), bytes32(s[off:off + 32]), bytes32(s[off + 32:off + 64]));
            if (rec <= last || !_isOwner(c, rec)) return 1; // sorted, distinct, owner
            last = rec;
            ++valid;
        }
        return valid >= c.threshold ? 0 : 1;
    }

    function _isOwner(Config storage c, address a) internal view returns (bool) {
        uint256 count = c.count;
        for (uint256 i; i < count; ++i) {
            if (c.owners[i] == a) return true;
        }
        return false;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
