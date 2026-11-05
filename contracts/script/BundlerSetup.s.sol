// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {FactoryStaker} from "kernel/factory/FactoryStaker.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {IEntryPoint as KernelEntryPoint} from "kernel/interfaces/IEntryPoint.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {IStatelessVerifier} from "../src/interfaces/IStatelessVerifier.sol";
import {WotsParams, Ops} from "../test/utils/WotsSigner.sol";
import {WotsSignerHelper} from "../test/utils/SignerHelper.sol";

/// @notice Deploys everything the bundler acceptance test needs on a local dev chain (bench/bundlers/run.sh):
///         EntryPoint v0.7, Kernel v3.3 from its production build, a FactoryStaker staked in the EntryPoint
///         (ERC-7562 requires a staked factory when validation reads the new account's storage in another
///         contract), Kernel's ECDSA validator, Winterlock validators for five parameter sets, and the
///         signing helper. Writes the addresses to bench/bundlers/deployment.json.
contract BundlerSetup is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        vm.startBroadcast(pk);

        // The canonical v0.7 EntryPoint if the runner deployed it (bundlers infer the version from the address)
        address existing = vm.envOr("ENTRY_POINT", address(0));
        EntryPoint ep = existing == address(0) ? new EntryPoint() : EntryPoint(payable(existing));
        address kImpl = vm.deployCode("lib/kernel/out/Kernel.sol/Kernel.json", abi.encode(address(ep)));
        address kFactory = vm.deployCode("lib/kernel/out/KernelFactory.sol/KernelFactory.json", abi.encode(kImpl));
        FactoryStaker staker =
            FactoryStaker(vm.deployCode("lib/kernel/out/FactoryStaker.sol/FactoryStaker.json", abi.encode(deployer)));
        staker.approveFactory(KernelFactory(kFactory), true);
        staker.stake{value: 1 ether}(KernelEntryPoint(address(ep)), 86400);
        address ecdsa = vm.deployCode("lib/kernel/out/ECDSAValidator.sol/ECDSAValidator.json");

        IStatelessVerifier slh = Ops.deployStatelessVerifier(); // shared by the five validators
        address d6 = address(new WinterlockValidator(Ops.params(WotsParams(24, 431, 4, 0)), slh));
        address n16 = address(new WinterlockValidator(Ops.params(WotsParams(16, 300, 4, 0)), slh));
        address n32 = address(new WinterlockValidator(Ops.params(WotsParams(32, 0, 4, 0)), slh));
        address sha = address(new WinterlockValidator(Ops.params(WotsParams(24, 431, 4, 1)), slh));
        address w256 = address(new WinterlockValidator(Ops.params(WotsParams(24, 3216, 8, 0)), slh));
        address helper = address(new WotsSignerHelper());
        vm.stopBroadcast();

        string memory j = "deployment";
        vm.serializeAddress(j, "entryPoint", address(ep));
        vm.serializeAddress(j, "kernelFactory", kFactory);
        vm.serializeAddress(j, "factoryStaker", address(staker));
        vm.serializeAddress(j, "ecdsaValidator", ecdsa);
        vm.serializeAddress(j, "winterlockD6", d6);
        vm.serializeAddress(j, "winterlock16", n16);
        vm.serializeAddress(j, "winterlock32checksum", n32);
        vm.serializeAddress(j, "winterlockSha256", sha);
        vm.serializeAddress(j, "winterlockW256", w256);
        string memory out = vm.serializeAddress(j, "signerHelper", helper);
        vm.writeJson(out, "bench/bundlers/deployment.json");
    }
}
