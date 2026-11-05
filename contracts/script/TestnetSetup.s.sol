// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {WotsParams, Ops} from "../test/utils/WotsSigner.sol";

/// @notice Stage 2 of the bundler acceptance test (bench/bundlers/testnet.sh): deploys the Winterlock validators
///         on a public testnet that already has the canonical EntryPoint v0.7 and ZeroDev's Kernel v3.3
///         (implementation, factory, staked meta factory, ECDSA validator). Writes the addresses, ZeroDev's
///         included, to the file named by DEPLOYMENT_FILE.
contract TestnetSetup is Script {
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    // ZeroDev Kernel v3.3 (lib/kernel/README.md)
    address constant KERNEL_FACTORY = 0x2577507b78c2008Ff367261CB6285d44ba5eF2E9;
    address constant META_FACTORY = 0xd703aaE79538628d27099B8c4f621bE4CCd142d5;
    address constant ECDSA_VALIDATOR = 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57;

    function run() external {
        require(ENTRY_POINT.code.length > 0 && KERNEL_FACTORY.code.length > 0, "EntryPoint or Kernel missing");
        require(META_FACTORY.code.length > 0 && ECDSA_VALIDATOR.code.length > 0, "Kernel meta factory missing");

        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        address d6 = address(new WinterlockValidator(Ops.params(WotsParams(24, 431, 4, 0))));
        address n16 = address(new WinterlockValidator(Ops.params(WotsParams(16, 300, 4, 0))));
        address n32 = address(new WinterlockValidator(Ops.params(WotsParams(32, 0, 4, 0))));
        address sha = address(new WinterlockValidator(Ops.params(WotsParams(24, 431, 4, 1))));
        address w256 = address(new WinterlockValidator(Ops.params(WotsParams(24, 3216, 8, 0))));
        vm.stopBroadcast();

        string memory j = "deployment";
        vm.serializeAddress(j, "entryPoint", ENTRY_POINT);
        vm.serializeAddress(j, "kernelFactory", KERNEL_FACTORY);
        vm.serializeAddress(j, "factoryStaker", META_FACTORY);
        vm.serializeAddress(j, "ecdsaValidator", ECDSA_VALIDATOR);
        vm.serializeAddress(j, "winterlockD6", d6);
        vm.serializeAddress(j, "winterlock16", n16);
        vm.serializeAddress(j, "winterlock32checksum", n32);
        vm.serializeAddress(j, "winterlockSha256", sha);
        string memory out = vm.serializeAddress(j, "winterlockW256", w256);
        vm.writeJson(out, vm.envString("DEPLOYMENT_FILE"));
    }
}
