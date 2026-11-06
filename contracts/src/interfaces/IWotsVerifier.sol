// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice A shared verifier of WOTS signatures under a Merkle tree of one-time keys: WotsVerifier as a contract
///         (src/SharedWotsVerifier.sol), for adapters that can't afford its code in their own (WinterlockOwner v2).
/// @dev    Reverts on input it can't verify: an invalid parameter set, a key index of more than 64 bits, a signature
///         shorter than the parameter set's or a path that isn't whole hashes. Callers treat a revert as invalid.
interface IWotsVerifier {
    /// The root that `sig` ([WOTS signature][path]) implies for key `keyIndex` of the tree with public seed `seed`,
    /// signing `message` under the packed parameter set `params` (WotsVerifier.encodeParams); 0 if the encoding is
    /// invalid. The caller compares it with the root it stores.
    function computeRoot(uint256 params, uint128 seed, uint256 keyIndex, bytes32 message, bytes calldata sig)
        external
        view
        returns (bytes32 root);
}
