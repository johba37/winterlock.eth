// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

interface ISha256Evm {
    function compressGas(uint256[8] memory state, bytes memory blk)
        external
        view
        returns (uint256[8] memory out, uint256 used);
}

/// The SHA-256 precompile can't resume from PK.seed's midstate, so every F, H and T_l call hashes the 64-byte PK.seed
/// block again. Would compressing from the midstate in EVM code be cheaper? One compression in Yul against the
/// precompile's whole two-block call for F.
contract Sha256MidstateTest is Test {
    function test_gas_compressionInEvm() public {
        ISha256Evm s = ISha256Evm(deployCode("Sha256Evm.sol:Sha256Evm"));
        uint256[8] memory iv =
            [uint256(0x6a09e667), 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        // SHA-256 of a 55-byte message is one compression of message | 0x80 | its bit length
        bytes memory m = new bytes(55);
        for (uint256 i; i < 55; ++i) {
            m[i] = bytes1(uint8(i * 7 + 1));
        }
        (uint256[8] memory out, uint256 used) = s.compressGas(iv, bytes.concat(m, hex"80", bytes8(uint64(55 * 8))));
        bytes32 got;
        for (uint256 i; i < 8; ++i) {
            got |= bytes32(out[i] << (224 - 32 * i));
        }
        assertEq(got, sha256(m));
        console.log("one SHA-256 compression in EVM code:", used);
        console.log("F through the precompile (102 bytes, two compressions): 208 = 100 (warm STATICCALL) + 60 + 12 * 4");
    }
}
