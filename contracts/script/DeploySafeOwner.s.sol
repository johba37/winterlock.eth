// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {WinterlockOwner} from "../src/safe/WinterlockOwner.sol";
import {WinterlockOwnerFactory} from "../src/safe/WinterlockOwnerFactory.sol";
import {SharedWotsVerifier} from "../src/SharedWotsVerifier.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";
import {ValidatorDeployment} from "./DeployValidator.s.sol";

/// @notice Members' Safe owners (WinterlockOwner v2) at the same address on every chain.
///         - Once per chain, for every parameter set: the stateless verifier (ValidatorDeployment) and the shared WOTS
///           verifier (SharedWotsVerifier), each with CREATE2 through the deterministic deployment proxy and a fixed
///           salt.
///         - Once per chain and parameter set: the WinterlockOwner implementation and its WinterlockOwnerFactory, the
///           same way. The implementation's init code holds the parameter set and both verifiers' deterministic
///           addresses; the factory's holds the implementation's address. The salts name v2: v1's implementation and
///           factory, deployed under the v1 salts, stay where they are and keep working.
///         - Per member: the factory creates the member's owner, a 77-byte proxy of the implementation with the
///           member's stateless key in its code, with CREATE2 and the key as the salt.
///         Nothing chain-specific enters any init code or salt, so a member's owner has the same address on every
///         chain, and so does a Safe whose owners are such contracts, since its address depends on its setup data
///         (owners, threshold, fallback handler) and on Safe's canonical factory and singleton.
library SafeOwnerDeployment {
    bytes32 internal constant WOTS_VERIFIER_SALT = keccak256("Winterlock.wots-verifier.v1");
    bytes32 internal constant IMPLEMENTATION_SALT = keccak256("Winterlock.safe-owner.implementation.v2");
    bytes32 internal constant FACTORY_SALT = keccak256("Winterlock.safe-owner.factory.v2");

    /// The shared WOTS verifier's creation code (no constructor arguments)
    function wotsVerifierInitCode() internal pure returns (bytes memory) {
        return type(SharedWotsVerifier).creationCode;
    }

    function predictWotsVerifier() internal pure returns (address) {
        return ValidatorDeployment._create2(WOTS_VERIFIER_SALT, wotsVerifierInitCode());
    }

    /// Deploys the shared WOTS verifier unless it exists; returns its address either way
    function deployWotsVerifier() internal returns (address) {
        return ValidatorDeployment._deploy(WOTS_VERIFIER_SALT, wotsVerifierInitCode());
    }

    function implementationInitCode(uint256 params) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(WinterlockOwner).creationCode,
            abi.encode(params, ValidatorDeployment.predictVerifier(), predictWotsVerifier())
        );
    }

    function predictImplementation(uint256 params) internal view returns (address) {
        return ValidatorDeployment._create2(IMPLEMENTATION_SALT, implementationInitCode(params));
    }

    function factoryInitCode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(type(WinterlockOwnerFactory).creationCode, abi.encode(implementation));
    }

    function predictFactory(uint256 params) internal view returns (address) {
        return ValidatorDeployment._create2(FACTORY_SALT, factoryInitCode(predictImplementation(params)));
    }

    /// The owner of the member with stateless key `key` (WinterlockOwnerFactory.predict, without the factory deployed)
    function predict(uint256 params, bytes32 key) internal view returns (address) {
        address implementation = predictImplementation(params);
        address factory = ValidatorDeployment._create2(FACTORY_SALT, factoryInitCode(implementation));
        return LibClone.predictDeterministicAddress(implementation, abi.encodePacked(key), key, factory);
    }

    /// Once per chain: deploys the stateless verifier, the shared WOTS verifier, the implementation and the factory,
    /// each unless it exists; returns the factory either way
    function deployShared(uint256 params) internal returns (WinterlockOwnerFactory) {
        ValidatorDeployment.deployVerifier();
        deployWotsVerifier();
        address implementation = ValidatorDeployment._deploy(IMPLEMENTATION_SALT, implementationInitCode(params));
        return WinterlockOwnerFactory(ValidatorDeployment._deploy(FACTORY_SALT, factoryInitCode(implementation)));
    }

    /// Deploys what deployShared deploys, then the member's owner, each unless it exists; returns the owner's address
    function deploy(uint256 params, bytes32 key) internal returns (address owner) {
        owner = deployShared(params).deploy(key);
    }
}

/// @notice Deploys the stateless verifier, the shared WOTS verifier, the WinterlockOwner implementation and its factory
///         (once per chain), and a member's owner, each at its deterministic address unless it is there already.
///         WINTERLOCK_KEY: the member's stateless public key (root ‖ P, 32 bytes); without it only the shared contracts
///         are deployed. Parameter set from the environment (default D6): WOTS_N, WOTS_TARGET_SUM, WOTS_LOG_W, WOTS_HASH.
///         DEPLOYER_PRIVATE_KEY pays; anyone may deploy, the addresses are the same.
///
///         Gas on chains with Glamsterdam's state pricing (EIP-8037; Sepolia since 2026-10-06). Forge simulates the
///         transactions locally with the old prices and by default sets each gas limit to about 130% of the simulated
///         gas. EIP-8037 charges new state far more: 1,530 gas per byte of code (old: 200) and 183,600 per new account
///         (old: 32,000). v1's implementation (7,236 bytes) needed 11.4M gas there, where Forge simulated 1.6M, and a
///         member's owner about 0.33M against 0.07M, so the simulated limits run out of gas. On such a chain run
///             forge script script/DeploySafeOwner.s.sol --rpc-url $RPC --broadcast --skip-simulation --slow \
///                 --gas-estimate-multiplier 120
///         Forge then asks the node for each transaction's gas (eth_estimateGas, priced by the chain's own rules)
///         right before sending it, once the transaction before it is mined: the factory's deployment can only be
///         estimated once the implementation exists, and the owner's once the factory does. Each limit is the node's
///         estimate times --gas-estimate-multiplier (default 130%); unused gas is not charged. (Checked on a local
///         anvil: one eth_estimateGas per transaction, each after the previous receipt, limits at 1.3x.)
///         The largest limit is the implementation's. v2's implementation (8,144 bytes) should need about 13.0M: 12.64M
///         of state gas, plus about the 0.36M that v1's estimate had beyond its state gas. That is about 15.6M at
///         120%, within EIP-7825's 16,777,216 cap, but about 16.9M at the default 130%, which is over it; hence the
///         multiplier above, which applies to the node's own estimate. The shared WOTS verifier (2,484 bytes) should
///         need about 4.1M. Both are estimates from v1's Sepolia receipts, not measured.
///         Before broadcasting, the script logs the state gas that EIP-8037 charges for each contract it will deploy
///         (stateGas8037). On a Glamsterdam chain the node's estimate should be that plus 0.1M to 0.2M of execution
///         and calldata (0.33M in all for an owner); on a chain with the old pricing it is far lower.
contract DeploySafeOwner is Script {
    /// EIP-8037: gas per byte of new state, and the state bytes of a new account
    uint256 internal constant COST_PER_STATE_BYTE = 1530;
    uint256 internal constant NEW_ACCOUNT_BYTES = 120;
    /// A member's owner: the 45-byte proxy and the key
    uint256 internal constant OWNER_BYTES = 77;

    function run() external returns (address owner) {
        uint256 params = WotsVerifier.encodeParams(
            vm.envOr("WOTS_N", uint256(24)),
            vm.envOr("WOTS_LOG_W", uint256(4)),
            vm.envOr("WOTS_HASH", uint256(0)),
            vm.envOr("WOTS_TARGET_SUM", uint256(431))
        );
        bytes32 key = vm.envOr("WINTERLOCK_KEY", bytes32(0));
        address[4] memory shared = [
            ValidatorDeployment.predictVerifier(),
            SafeOwnerDeployment.predictWotsVerifier(),
            SafeOwnerDeployment.predictImplementation(params),
            SafeOwnerDeployment.predictFactory(params)
        ];
        if (key != 0) owner = SafeOwnerDeployment.predict(params, key);

        // runtime sizes, from a deployment in the script's local state only (outside the broadcast, then reverted)
        uint256[4] memory sizes;
        uint256 snap = vm.snapshotState();
        SafeOwnerDeployment.deployShared(params);
        for (uint256 i; i < 4; ++i) {
            sizes[i] = shared[i].code.length;
        }
        vm.revertToState(snap);

        uint256 toDeploy = _plan("stateless verifier", shared[0], sizes[0]);
        toDeploy += _plan("WOTS verifier", shared[1], sizes[1]);
        toDeploy += _plan("implementation", shared[2], sizes[2]);
        toDeploy += _plan("factory", shared[3], sizes[3]);
        if (key != 0) toDeploy += _plan("owner", owner, OWNER_BYTES);
        if (toDeploy == 0) return owner;

        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        SafeOwnerDeployment.deployShared(params);
        if (key != 0) WinterlockOwnerFactory(shared[3]).deploy(key);
        vm.stopBroadcast();

        for (uint256 i; i < 4; ++i) {
            require(shared[i].code.length == sizes[i], "shared contract not deployed");
        }
        require(key == 0 || owner.code.length == OWNER_BYTES, "owner not deployed");
    }

    /// Logs `a`, and if it has no code yet, the state gas of its deployment under EIP-8037; returns 1 if it has none
    function _plan(string memory name, address a, uint256 runtimeBytes) internal view returns (uint256) {
        if (a.code.length != 0) {
            console.log(string.concat(name, ": deployed at"), a);
            return 0;
        }
        console.log(string.concat(name, ": to deploy at"), a);
        console.log("  runtime bytes", runtimeBytes, ", stateGas8037", stateGas8037(runtimeBytes));
        return 1;
    }

    /// The state gas EIP-8037 charges for a new account with `codeBytes` bytes of code: (120 + codeBytes) * 1,530.
    /// The old prices were 32,000 for the account and 200 per byte.
    function stateGas8037(uint256 codeBytes) public pure returns (uint256) {
        return (NEW_ACCOUNT_BYTES + codeBytes) * COST_PER_STATE_BYTE;
    }
}
