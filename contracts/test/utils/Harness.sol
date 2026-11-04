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
    function computeRoot(uint128 seed, uint256 keyIndex, bytes32 message, bytes calldata sig, bytes calldata path)
        external
        pure
        returns (bytes32)
    {
        return WotsVerifier.computeRoot(seed, keyIndex, message, sig, path);
    }

    /// Gas of the library call alone, measured inside the callee where memory is fresh.
    function computeRootGas(uint128 seed, uint256 keyIndex, bytes32 message, bytes calldata sig, bytes calldata path)
        external
        view
        returns (bytes32 root, uint256 gasUsed)
    {
        gasUsed = gasleft();
        root = WotsVerifier.computeRoot(seed, keyIndex, message, sig, path);
        gasUsed -= gasleft();
    }
}
