// SPDX-License-Identifier: MIT
//
// TEST ONLY. Vendored without changes below this header from Permit2 (https://github.com/Uniswap/permit2), file
// src/interfaces/IERC1271.sol at commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219. MIT licence: see LICENSE in
// test/vendor/permit2.
pragma solidity ^0.8.0;

interface IERC1271 {
    /// @dev Should return whether the signature provided is valid for the provided data
    /// @param hash      Hash of the data to be signed
    /// @param signature Signature byte array associated with _data
    /// @return magicValue The bytes4 magic value 0x1626ba7e
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}
