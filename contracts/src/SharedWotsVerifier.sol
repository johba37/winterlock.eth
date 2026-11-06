// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWotsVerifier} from "./interfaces/IWotsVerifier.sol";
import {WotsVerifier} from "./WotsVerifier.sol";

/// @title SharedWotsVerifier
/// @notice WotsVerifier as a contract, for every parameter set: the same code that WinterlockValidator links in, behind
///         one external function. WinterlockOwner v2 calls it instead of carrying the verifier in its own code, which
///         keeps the owner's implementation small enough to deploy under Glamsterdam's state pricing within the
///         transaction gas cap (docs/notes/owner-v2.md, "Costs").
///         Deployed once per chain through the deterministic deployment proxy with a fixed salt, like the stateless
///         verifier (script/DeploySafeOwner.s.sol). It has no state, no owner and no constructor arguments, so its
///         address is the same on every chain.
/// @dev Status: research prototype. Unaudited. Not for real funds.
contract SharedWotsVerifier is IWotsVerifier {
    /// @inheritdoc IWotsVerifier
    function computeRoot(uint256 params, uint128 seed, uint256 keyIndex, bytes32 message, bytes calldata sig)
        external
        view
        returns (bytes32)
    {
        // [WOTS signature][path]: the signature's length follows from the parameter set
        uint256 len = WotsVerifier.sigBytes(params);
        return WotsVerifier.computeRoot(params, seed, keyIndex, message, sig[:len], sig[len:]);
    }
}
