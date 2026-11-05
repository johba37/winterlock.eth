// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WinterlockOwner} from "../src/safe/WinterlockOwner.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";
import {ValidatorDeployment} from "./DeployValidator.s.sol";

/// @notice A member's Safe owner at the same address on every chain: CREATE2 through the deterministic deployment
///         proxy, with the member's stateless public key as the salt. The init code holds the parameter set, the
///         stateless verifier's deterministic address (ValidatorDeployment) and the key, and nothing chain-specific.
///         A Safe whose owners are such contracts then also has the same address on every chain, since its address
///         depends on its setup data (owners, threshold, fallback handler) and on Safe's canonical factory and
///         singleton.
library SafeOwnerDeployment {
    function initCode(uint256 params, bytes32 key) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(WinterlockOwner).creationCode, abi.encode(params, ValidatorDeployment.predictVerifier(), key)
        );
    }

    function predict(uint256 params, bytes32 key) internal view returns (address) {
        return ValidatorDeployment._create2(key, initCode(params, key));
    }

    /// Deploys the stateless verifier, then the owner, each unless it exists; returns the owner's address either way
    function deploy(uint256 params, bytes32 key) internal returns (address owner) {
        ValidatorDeployment.deployVerifier();
        owner = ValidatorDeployment._deploy(key, initCode(params, key));
    }
}

/// @notice Deploys a member's WinterlockOwner at its deterministic address.
///         WINTERLOCK_KEY: the member's stateless public key (root ‖ P, 32 bytes). Parameter set from the environment
///         (default D6): WOTS_N, WOTS_TARGET_SUM, WOTS_LOG_W, WOTS_HASH. DEPLOYER_PRIVATE_KEY pays; anyone may deploy.
contract DeploySafeOwner is Script {
    function run() external returns (address owner) {
        uint256 params = WotsVerifier.encodeParams(
            vm.envOr("WOTS_N", uint256(24)),
            vm.envOr("WOTS_LOG_W", uint256(4)),
            vm.envOr("WOTS_HASH", uint256(0)),
            vm.envOr("WOTS_TARGET_SUM", uint256(431))
        );
        bytes32 key = vm.envBytes32("WINTERLOCK_KEY");
        owner = SafeOwnerDeployment.predict(params, key);
        if (owner.code.length != 0) {
            console.log("already deployed at", owner);
            return owner;
        }
        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        SafeOwnerDeployment.deploy(params, key);
        vm.stopBroadcast();
        console.log("deployed at", owner);
    }
}
