// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// The entry points of the generated SLH-DSA verifiers (src/SlhDsaSha2_*.sol).
interface ISlhDsaVerifier {
    /// FIPS 205 Algorithm 24 (pure SLH-DSA), empty context
    function verify(bytes calldata pk, bytes calldata message, bytes calldata signature) external view returns (bool);

    /// FIPS 205 Algorithm 24 (pure SLH-DSA), context of up to 255 bytes
    function verifyWithContext(bytes calldata pk, bytes calldata ctx, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool);

    /// FIPS 205 Algorithm 20 on M' as given
    function verifyInternal(bytes calldata pk, bytes calldata mPrime, bytes calldata signature)
        external
        view
        returns (bool);
}
