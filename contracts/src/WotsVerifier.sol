// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WotsVerifier
/// @notice Verifies WOTS+ one-time signatures (w = 16, keccak256 truncated to n bytes) under a Merkle tree
///         of one-time keys. Returns the root the signature implies, or 0 if the encoding is invalid. The
///         caller compares the result with the root it stores.
///
/// Parameter sets
///   n          hash size in bytes: 16, 24 or 32 (roughly NIST category 1, 3, 5, by analogy to SLH-DSA)
///   targetSum  0  -> checksum encoding: 2n message digits plus 3 checksum digits
///              T  -> target-sum encoding: 2n message digits that must add up to exactly T, no checksum
///                    chains. The signer retries its randomizer until the sum is hit.
///
/// Signature: [R: n bytes][chain value: n bytes] x chains(n, targetSum)
/// Path:      n bytes per level, leaf level first
///
/// @dev Every hash input begins with a 32-byte tweak, SPHINCS+ "simple" style, so no two hash calls in any
///      tree, chain or account share an input prefix:
///
///        bits 255..128  public seed (128 bits, chosen per key tree)
///        bits 127..120  type: 0 chain step, 1 public-key compression, 2 tree node, 3 message digest
///        bits 119..56   key index (chain, pk, digest) or parent node index (tree)
///        bits  55..48   chain index
///        bits  47..40   chain step (0..14) or tree level (1..height)
///
///      Values are n bytes, kept in the high bytes of a 32-byte word with the low bytes zero. They are
///      hashed as full words. Chain step j maps position j to j + 1: x' = trunc(keccak256(tweak(i, j) || x)).
///      For digit a the signature reveals position a, and the verifier hashes forward to position 15.
///      The digest is trunc(keccak256(tweak || R || message)). The signer picks R, so nobody can
///      precompute digest collisions against it.
library WotsVerifier {
    error BadParams();
    error BadSignatureLength();
    error BadPathLength();

    /// Number of hash chains for a parameter set.
    function chains(uint256 n, uint256 targetSum) internal pure returns (uint256) {
        return 2 * n + (targetSum == 0 ? 3 : 0);
    }

    /// Signature length in bytes: randomizer plus chain values.
    function sigBytes(uint256 n, uint256 targetSum) internal pure returns (uint256) {
        return n * (1 + chains(n, targetSum));
    }

    function computeRoot(
        uint256 n,
        uint256 targetSum,
        uint128 seed,
        uint256 keyIndex,
        bytes32 message,
        bytes calldata sig,
        bytes calldata path
    ) internal pure returns (bytes32 root) {
        if ((n != 16 && n != 24 && n != 32) || targetSum > 30 * n || keyIndex >> 64 != 0) revert BadParams();
        if (sig.length != sigBytes(n, targetSum)) revert BadSignatureLength();
        if (path.length % n != 0) revert BadPathLength();

        // seed and key index travel together in the tweak word: seed << 128 | keyIndex << 56
        uint256 base = (uint256(seed) << 128) | (keyIndex << 56);
        (bytes32 leaf, uint256 sum) = _leaf(n, chains(n, targetSum), base, message, sig);
        if (targetSum != 0 && sum != targetSum) return bytes32(0);
        root = _climb(n, base, leaf, path);
    }

    /// Computes the randomized digest, hashes every chain to its end and compresses the ends into the
    /// leaf. Also returns the sum of the message digits.
    function _leaf(uint256 n, uint256 len, uint256 base, bytes32 message, bytes calldata sig)
        private
        pure
        returns (bytes32 leaf, uint256 sum)
    {
        assembly ("memory-safe") {
            let mask := not(shr(shl(3, n), not(0)))
            // Scratch beyond the free memory pointer: [pk tweak][end_0] ... [end_len-1]
            let buf := mload(0x40)

            // d = trunc(keccak256(tweak_msg || R || message)), kept at buf until the chains start
            mstore(buf, or(base, shl(120, 3)))
            mstore(add(buf, 0x20), and(calldataload(sig.offset), mask))
            mstore(add(buf, 0x40), message)
            mstore(buf, and(keccak256(buf, 0x60), mask))

            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let a
                switch lt(i, shl(1, n))
                case 1 {
                    a := and(shr(sub(252, shl(2, i)), mload(buf)), 0xf)
                    sum := add(sum, a)
                }
                default {
                    // checksum = sum(15 - a_i) = 15 * 2n - sum, as 3 digits, most significant first
                    a := and(shr(sub(8, shl(2, sub(i, shl(1, n)))), sub(mul(30, n), sum)), 0xf)
                }
                // The chain value lives at 0x20; the tweak advances one step (1 << 40) per hash.
                mstore(0x20, and(calldataload(add(sig.offset, mul(add(i, 1), n))), mask))
                let ti := or(base, shl(48, i))
                let tEnd := or(ti, 0xf0000000000) // step 15
                for { let t := or(ti, shl(40, a)) } lt(t, tEnd) { t := add(t, 0x10000000000) } {
                    mstore(0x00, t)
                    mstore(0x20, and(keccak256(0x00, 0x40), mask))
                }
                // end_i goes to buf + 32 * (i + 1); slot 0 still holds the digest until the loop ends
                mstore(add(buf, shl(5, add(i, 1))), mload(0x20))
            }
            mstore(buf, or(base, shl(120, 1)))
            leaf := and(keccak256(buf, shl(5, add(len, 1))), mask)
        }
    }

    function _climb(uint256 n, uint256 base, bytes32 leaf, bytes calldata path) private pure returns (bytes32 node) {
        assembly ("memory-safe") {
            let mask := not(shr(shl(3, n), not(0)))
            let nodeTweak := or(and(base, not(0xffffffffffffffffffffffffffffffff)), shl(120, 2))
            let idx := and(shr(56, base), 0xffffffffffffffff)
            let buf := mload(0x40)
            node := leaf
            let h := div(path.length, n)
            for { let l := 0 } lt(l, h) { l := add(l, 1) } {
                let sib := and(calldataload(add(path.offset, mul(l, n))), mask)
                let bit := and(idx, 1)
                idx := shr(1, idx)
                mstore(buf, or(nodeTweak, or(shl(56, idx), shl(40, add(l, 1)))))
                switch bit
                case 0 {
                    mstore(add(buf, 0x20), node)
                    mstore(add(buf, 0x40), sib)
                }
                default {
                    mstore(add(buf, 0x20), sib)
                    mstore(add(buf, 0x40), node)
                }
                node := and(keccak256(buf, 0x60), mask)
            }
        }
    }
}
