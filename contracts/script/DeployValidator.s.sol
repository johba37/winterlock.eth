// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";
import {Ops} from "../test/utils/WotsSigner.sol";

/// @notice The validator's address must be the same on every chain (D10): it is part of the account's install
///         data, and so of the account's address. It is deployed with CREATE2 through the deterministic
///         deployment proxy, which exists at the same address on most EVM chains. So is the stateless verifier it
///         calls (D11), whose address is a constructor argument. The validator's address then depends only on the
///         bytecode of both and on the parameter set.
/// @dev    The bytecode comes from this repository's compiler settings (foundry.toml: solc 0.8.28, optimizer
///         1,000,000 runs, EVM prague; the vendored stateless verifier with via-IR). Any change to the source or
///         the settings changes the addresses, so a release pins both. The bytecode needs Cancun opcodes, so a chain
///         must support them.
library ValidatorDeployment {
    /// Deterministic deployment proxy (github.com/Arachnid/deterministic-deployment-proxy)
    address internal constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    /// Its runtime code, for test environments that lack it
    bytes internal constant DEPLOYER_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
    bytes32 internal constant SALT = keccak256("Winterlock.validator.v1");
    bytes32 internal constant VERIFIER_SALT = keccak256("Winterlock.stateless-verifier.v1");
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// The stateless verifier's creation code, from its build artifact (it has no constructor arguments)
    function verifierInitCode() internal view returns (bytes memory) {
        return VM.getCode(Ops.STATELESS_VERIFIER_ARTIFACT);
    }

    function predictVerifier() internal view returns (address) {
        return _create2(VERIFIER_SALT, verifierInitCode());
    }

    function initCode(uint256 params) internal view returns (bytes memory) {
        return abi.encodePacked(type(WinterlockValidator).creationCode, abi.encode(params, predictVerifier()));
    }

    function predict(uint256 params) internal view returns (address) {
        return _create2(SALT, initCode(params));
    }

    /// Deploys the stateless verifier, then the validator, each unless it already exists; returns the validator's
    /// address either way
    function deploy(uint256 params) internal returns (address validator) {
        deployVerifier();
        validator = _deploy(SALT, initCode(params));
    }

    /// Deploys the stateless verifier unless it exists; returns its address either way
    function deployVerifier() internal returns (address) {
        return _deploy(VERIFIER_SALT, verifierInitCode());
    }

    /// CREATE2 address of `code` deployed by the proxy with `salt`
    function _create2(bytes32 salt, bytes memory code) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), DEPLOYER, salt, keccak256(code))))));
    }

    /// Deploys `code` through the proxy with `salt` unless it exists; returns its address either way
    function _deploy(bytes32 salt, bytes memory code) internal returns (address deployed) {
        deployed = _create2(salt, code);
        if (deployed.code.length != 0) return deployed;
        require(DEPLOYER.code.length != 0, "no deterministic deployment proxy on this chain");
        (bool ok, bytes memory ret) = DEPLOYER.call(abi.encodePacked(salt, code));
        require(ok && address(bytes20(ret)) == deployed, "deterministic deployment failed");
    }
}

/// @notice Deploys the Winterlock validator for one parameter set at its deterministic address, and the stateless
///         verifier at its own.
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
        console.log("stateless verifier at", ValidatorDeployment.predictVerifier());
    }
}
