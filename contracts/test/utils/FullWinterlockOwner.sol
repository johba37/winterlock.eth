// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WinterlockOwner} from "../../src/safe/WinterlockOwner.sol";
import {IStatelessVerifier} from "../../src/interfaces/IStatelessVerifier.sol";

/// Test only: a WinterlockOwner as a full contract, with the member's key an immutable of its own code, as in the
/// Safe owner spike before owners became proxies. It runs the same code without the proxy, so the gas tests can
/// compare a member's owner as a proxy (deployment, each check, execTransaction) with the spike's design.
contract FullWinterlockOwner is WinterlockOwner {
    bytes32 internal immutable FULL_KEY;

    constructor(uint256 params, IStatelessVerifier statelessVerifier, bytes32 key)
        WinterlockOwner(params, statelessVerifier)
    {
        if (uint256(key) >> 128 == 0 || uint128(uint256(key)) == 0) revert InvalidConfig();
        FULL_KEY = key;
    }

    function _key() internal view override returns (bytes32) {
        return FULL_KEY;
    }
}
