// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";

/// @notice The validator's address must be the same on every chain (D10): it is part of the account's install
///         data, and so of the account's address. It is deployed with CREATE2 through the deterministic
///         deployment proxy, which exists at the same address on most EVM chains. The address then depends
///         only on the bytecode and the parameter set.
/// @dev    The bytecode comes from this repository's compiler settings (foundry.toml: solc 0.8.28, optimizer
///         1,000,000 runs, EVM prague). Any change to the source or the settings changes the address, so a
///         release pins both. The bytecode needs Cancun opcodes, so a chain must support them.
library ValidatorDeployment {
    /// Deterministic deployment proxy (github.com/Arachnid/deterministic-deployment-proxy)
    address internal constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    /// Its runtime code, for test environments that lack it
    bytes internal constant DEPLOYER_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
    bytes32 internal constant SALT = keccak256("Winterlock.validator.v1");

    function initCode(uint256 params) internal pure returns (bytes memory) {
        return abi.encodePacked(type(WinterlockValidator).creationCode, abi.encode(params));
    }

    function predict(uint256 params) internal pure returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), DEPLOYER, SALT, keccak256(initCode(params))));
        return address(uint160(uint256(h)));
    }

    /// Deploys unless the validator already exists; returns its address either way
    function deploy(uint256 params) internal returns (address validator) {
        validator = predict(params);
        if (validator.code.length != 0) return validator;
        require(DEPLOYER.code.length != 0, "no deterministic deployment proxy on this chain");
        (bool ok, bytes memory ret) = DEPLOYER.call(abi.encodePacked(SALT, initCode(params)));
        require(ok && address(bytes20(ret)) == validator, "deterministic deployment failed");
    }
}

/// @notice Deploys the Winterlock validator for one parameter set at its deterministic address.
///         Parameter set from the environment (default D6): WOTS_N, WOTS_TARGET_SUM, WOTS_LOG_W, WOTS_HASH.
///         DEPLOYER_PRIVATE_KEY pays for the deployment; anyone may deploy, the address is the same.
contract DeployValidator is Script {
    function run() external returns (address validator) {
        uint256 params = WotsVerifier.encodeParams(
            vm.envOr("WOTS_N", uint256(24)),
            vm.envOr("WOTS_LOG_W", uint256(4)),
            vm.envOr("WOTS_HASH", uint256(0)),
            vm.envOr("WOTS_TARGET_SUM", uint256(431))
        );
        validator = ValidatorDeployment.predict(params);
        if (validator.code.length != 0) {
            console.log("already deployed at", validator);
            return validator;
        }
        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        ValidatorDeployment.deploy(params);
        vm.stopBroadcast();
        console.log("deployed at", validator);
    }
}
