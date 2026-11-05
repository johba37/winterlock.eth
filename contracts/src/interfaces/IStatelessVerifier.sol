// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice A stateless hash-based signature verifier (decision D11). The interface of the SPHINCs- verifiers,
///         here the vendored leanSphincs one (src/vendor/sphincs-minus/LeanSphincsAsm.sol).
/// @dev    Public key words are high-aligned: pkSeed = P ‖ 0^16, pkRoot = root ‖ 0^16. Reverts on a signature of the
///         wrong length or a non-canonical key; returns false for any other invalid signature.
interface IStatelessVerifier {
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool valid);
}
