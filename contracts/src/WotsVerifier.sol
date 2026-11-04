// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WotsVerifier
/// @notice Verifies WOTS+ one-time signatures (w = 16, n = 32 bytes, keccak256) under a Merkle tree of
///         one-time keys. It returns the root that the signature implies; the caller compares that root
///         with the one it stores.
/// @dev Every hash input begins with a 32-byte tweak, SPHINCS+ "simple" style, so no two hash calls in
///      any tree, chain or account share an input prefix:
///
///        bits 255..128  public seed (128 bits, chosen per key tree)
///        bits 127..120  type: 0 chain step, 1 public-key compression, 2 tree node, 3 message digest
///        bits 119..56   key index (chain, pk, digest) or parent node index (tree)
///        bits  55..48   chain index (0..66)
///        bits  47..40   chain step (0..14) or tree level (1..height)
///
///      Chain step j maps the value at position j to position j + 1: x' = keccak256(tweak(i, j) || x).
///      For base-16 digit a, the signature reveals position a. The verifier hashes forward to position 15.
///      Digits: 64 nibbles of the digest (most significant first), then 3 nibbles of the checksum
///      sum(15 - a_i) <= 960.
library WotsVerifier {
    uint256 internal constant LEN = 67;
    uint256 internal constant SIG_BYTES = LEN * 32; // 2144

    error BadSignatureLength();
    error BadPathLength();

    /// @param seed      public seed of the key tree
    /// @param keyIndex  index of the one-time key (leaf); must be < 2^64
    /// @param message   32-byte message (e.g. a userOpHash)
    /// @param sig       67 x 32-byte chain values
    /// @param path      Merkle authentication path, leaf level first, 32 bytes per level
    function computeRoot(uint128 seed, uint256 keyIndex, bytes32 message, bytes calldata sig, bytes calldata path)
        internal
        pure
        returns (bytes32 root)
    {
        if (sig.length != SIG_BYTES) revert BadSignatureLength();
        if (path.length & 31 != 0) revert BadPathLength();

        assembly ("memory-safe") {
            let seedHi := shl(128, seed)
            let base := or(seedHi, shl(56, keyIndex))

            // Message digest, bound to the seed and key index.
            mstore(0x00, or(base, shl(120, 3)))
            mstore(0x20, message)
            let d := keccak256(0x00, 0x40)

            // Scratch beyond the free memory pointer: [pk tweak][end_0] ... [end_66]
            let buf := mload(0x40)
            let ends := add(buf, 0x20)
            let csum := 0

            for { let i := 0 } lt(i, 67) { i := add(i, 1) } {
                let a
                switch lt(i, 64)
                case 1 {
                    a := and(shr(sub(252, shl(2, i)), d), 0xf)
                    csum := add(csum, sub(15, a))
                }
                default {
                    // checksum digits, most significant first: shifts 8, 4, 0
                    a := and(shr(sub(8, shl(2, sub(i, 64))), csum), 0xf)
                }

                // The chain value lives at 0x20; the tweak word advances one step (1 << 40) per hash.
                mstore(0x20, calldataload(add(sig.offset, shl(5, i))))
                let ti := or(base, shl(48, i))
                let tEnd := or(ti, 0xf0000000000) // step 15
                for { let t := or(ti, shl(40, a)) } lt(t, tEnd) { t := add(t, 0x10000000000) } {
                    mstore(0x00, t)
                    mstore(0x20, keccak256(0x00, 0x40))
                }
                mstore(add(ends, shl(5, i)), mload(0x20))
            }

            // Compress the 67 chain ends into the leaf.
            mstore(buf, or(base, shl(120, 1)))
            let node := keccak256(buf, 0x880) // 32 + 67 * 32

            // Climb the Merkle tree.
            let idx := keyIndex
            let h := shr(5, path.length)
            for { let l := 0 } lt(l, h) { l := add(l, 1) } {
                let sib := calldataload(add(path.offset, shl(5, l)))
                let bit := and(idx, 1)
                idx := shr(1, idx)
                mstore(buf, or(or(seedHi, shl(120, 2)), or(shl(56, idx), shl(40, add(l, 1)))))
                switch bit
                case 0 {
                    mstore(add(buf, 0x20), node)
                    mstore(add(buf, 0x40), sib)
                }
                default {
                    mstore(add(buf, 0x20), sib)
                    mstore(add(buf, 0x40), node)
                }
                node := keccak256(buf, 0x60)
            }
            root := node
        }
    }
}
