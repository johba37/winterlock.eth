// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WotsVerifier
/// @notice Verifies WOTS+ one-time signatures under a Merkle tree of one-time keys. Returns the root the
///         signature implies, or 0 if the encoding is invalid. The caller compares the result with the
///         root it stores.
///
/// Parameter set, packed into one word (see encodeParams):
///   n          hash size in bytes: 16, 24 or 32 (roughly NIST category 1, 3, 5, by analogy to SLH-DSA)
///   logW       log2 of the Winternitz parameter w: 2, 4 or 8 (w = 4, 16, 256)
///   hashFn     0 = keccak256, 1 = SHA-256 (precompile), truncated to n bytes
///   targetSum  0 -> checksum encoding: 8n/logW message digits plus checksum digits
///              T -> target-sum encoding: message digits must add up to exactly T, no checksum chains.
///                   The signer retries its randomizer until the sum is hit.
///
/// Signature: [R: n bytes][chain value: n bytes] x chains(params)
/// Path:      n bytes per level, leaf level first
///
/// @dev Every hash input begins with a 32-byte tweak, SPHINCS+ "simple" style, so no two hash calls in any
///      tree, chain or account share an input prefix:
///
///        bits 255..128  public seed (128 bits, chosen per key tree)
///        bits 127..120  type: 0 chain step, 1 public-key compression, 2 tree node, 3 message digest
///        bits 119..56   key index (chain, pk, digest) or parent node index (tree)
///        bits  55..48   chain index
///        bits  47..40   chain step (0..w-2) or tree level (1..height)
///
///      Values are n bytes, kept in the high bytes of a 32-byte word with the low bytes zero, and hashed as
///      full words. Chain step j maps position j to j + 1: x' = trunc(H(tweak(i, j) || x)). For digit a the
///      signature reveals position a, and the verifier hashes forward to position w - 1.
///      The digest is trunc(H(tweak || R || message)). The signer picks R, so nobody can precompute digest
///      collisions against it.
library WotsVerifier {
    uint256 internal constant KECCAK = 0;
    uint256 internal constant SHA256 = 1;

    error BadParams();
    error BadSignatureLength();
    error BadPathLength();

    // --- parameters ---

    function encodeParams(uint256 n, uint256 logW, uint256 hashFn, uint256 targetSum) internal pure returns (uint256 p) {
        p = n | (logW << 8) | (hashFn << 16) | (targetSum << 32);
        checkParams(p);
    }

    function decodeParams(uint256 p)
        internal
        pure
        returns (uint256 n, uint256 logW, uint256 hashFn, uint256 targetSum)
    {
        n = p & 0xff;
        logW = (p >> 8) & 0xff;
        hashFn = (p >> 16) & 0xff;
        targetSum = (p >> 32) & 0xffffffff;
    }

    function checkParams(uint256 p) internal pure {
        (uint256 n, uint256 logW, uint256 hashFn, uint256 targetSum) = decodeParams(p);
        if ((n != 16 && n != 24 && n != 32) || (logW != 2 && logW != 4 && logW != 8) || hashFn > 1) revert BadParams();
        if (p >> 64 != 0 || targetSum > messageDigits(p) * ((1 << logW) - 1)) revert BadParams();
    }

    /// Number of message digits: 8n / log2(w)
    function messageDigits(uint256 p) internal pure returns (uint256) {
        return (8 * (p & 0xff)) / ((p >> 8) & 0xff);
    }

    /// Number of checksum digits: enough base-w digits to hold messageDigits * (w - 1)
    function checksumDigits(uint256 p) internal pure returns (uint256 digits) {
        uint256 w = 1 << ((p >> 8) & 0xff);
        uint256 max = messageDigits(p) * (w - 1);
        digits = 1;
        for (uint256 cap = w; cap <= max; cap *= w) {
            ++digits;
        }
    }

    /// Number of hash chains for a parameter set.
    function chains(uint256 p) internal pure returns (uint256) {
        return messageDigits(p) + ((p >> 32) & 0xffffffff == 0 ? checksumDigits(p) : 0);
    }

    /// Signature length in bytes: randomizer plus chain values.
    function sigBytes(uint256 p) internal pure returns (uint256) {
        return (p & 0xff) * (1 + chains(p));
    }

    // --- verification ---

    function computeRoot(
        uint256 p,
        uint128 seed,
        uint256 keyIndex,
        bytes32 message,
        bytes calldata sig,
        bytes calldata path
    ) internal view returns (bytes32) {
        checkParams(p);
        if (keyIndex >> 64 != 0) revert BadParams();
        uint256 len = chains(p);
        if (sig.length != (p & 0xff) * (1 + len)) revert BadSignatureLength();
        if (path.length % (p & 0xff) != 0) revert BadPathLength();
        // seed and key index travel together in the tweak word: seed << 128 | keyIndex << 56
        return _root(p, len, (uint256(seed) << 128) | (keyIndex << 56), message, sig, path);
    }

    function _root(uint256 p, uint256 len, uint256 base, bytes32 message, bytes calldata sig, bytes calldata path)
        private
        view
        returns (bytes32)
    {
        uint256[] memory a = _encode(p, len, base, message, sig);
        if (a.length == 0) return bytes32(0); // digits miss the target sum
        uint256 values;
        assembly ("memory-safe") {
            values := add(sig.offset, and(p, 0xff)) // chain values start after R
        }
        return _climb(p, base, _leaf(p, base, a, values), path);
    }

    /// Digest and digits. Returns an empty array if a target sum is set and the digits miss it.
    function _encode(uint256 p, uint256 len, uint256 base, bytes32 message, bytes calldata sig)
        private
        view
        returns (uint256[] memory a)
    {
        uint256 sum;
        assembly ("memory-safe") {
            let n := and(p, 0xff)
            let b := and(shr(8, p), 0xff)
            let wm1 := sub(shl(b, 1), 1)
            let mask := not(shr(shl(3, n), not(0)))

            // d = trunc(H(tweak_msg || R || message)), hashed in scratch beyond the free memory pointer
            let buf := mload(0x40)
            mstore(buf, or(base, shl(120, 3)))
            mstore(add(buf, 0x20), and(calldataload(sig.offset), mask))
            mstore(add(buf, 0x40), message)
            let d
            switch and(shr(16, p), 0xff)
            case 0 { d := keccak256(buf, 0x60) }
            default {
                pop(staticcall(gas(), 2, buf, 0x60, buf, 0x20))
                d := mload(buf)
            }
            d := and(d, mask)

            // allocate a[len]; every entry is written below
            a := buf
            mstore(a, len)
            mstore(0x40, add(a, shl(5, add(len, 1))))

            // message digits, most significant first
            let len1 := div(shl(3, n), b)
            let ptr := add(a, 0x20)
            let end := add(ptr, shl(5, len1))
            let sh := 256
            for {} lt(ptr, end) { ptr := add(ptr, 0x20) } {
                sh := sub(sh, b)
                let x := and(shr(sh, d), wm1)
                mstore(ptr, x)
                sum := add(sum, x)
            }
            // checksum digits: sum(w - 1 - a_i), base w, most significant first
            let len2 := sub(len, len1)
            if len2 {
                let csum := sub(mul(len1, wm1), sum)
                sh := mul(b, len2)
                end := add(ptr, shl(5, len2))
                for {} lt(ptr, end) { ptr := add(ptr, 0x20) } {
                    sh := sub(sh, b)
                    mstore(ptr, and(shr(sh, csum), wm1))
                }
            }
        }
        uint256 targetSum = (p >> 32) & 0xffffffff;
        if (targetSum != 0 && sum != targetSum) return new uint256[](0);
    }

    /// Hashes every chain from its revealed position to w - 1 and compresses the ends into the leaf.
    /// @param values calldata offset of the first chain value
    function _leaf(uint256 p, uint256 base, uint256[] memory a, uint256 values) private view returns (bytes32 leaf) {
        assembly ("memory-safe") {
            let n := and(p, 0xff)
            let mask := not(shr(shl(3, n), not(0)))
            let stepEnd := shl(40, sub(shl(and(shr(8, p), 0xff), 1), 1)) // step w - 1
            let len := mload(a)
            // Scratch beyond the free memory pointer: [pk tweak][end_0] ... [end_len-1]
            let buf := mload(0x40)
            // The chain value lives at 0x20; the tweak advances one step (1 << 40) per hash.
            switch and(shr(16, p), 0xff)
            case 0 {
                for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                    let k := shl(5, add(i, 1))
                    mstore(0x20, and(calldataload(add(values, mul(i, n))), mask))
                    let ti := or(base, shl(48, i))
                    let tEnd := or(ti, stepEnd)
                    for { let t := or(ti, shl(40, mload(add(a, k)))) } lt(t, tEnd) { t := add(t, 0x10000000000) } {
                        mstore(0x00, t)
                        mstore(0x20, and(keccak256(0x00, 0x40), mask))
                    }
                    mstore(add(buf, k), mload(0x20))
                }
                mstore(buf, or(base, shl(120, 1)))
                leaf := keccak256(buf, shl(5, add(len, 1)))
            }
            default {
                for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                    let k := shl(5, add(i, 1))
                    mstore(0x20, and(calldataload(add(values, mul(i, n))), mask))
                    let ti := or(base, shl(48, i))
                    let tEnd := or(ti, stepEnd)
                    for { let t := or(ti, shl(40, mload(add(a, k)))) } lt(t, tEnd) { t := add(t, 0x10000000000) } {
                        mstore(0x00, t)
                        // A failed precompile call leaves the value unchanged, so the root mismatches.
                        pop(staticcall(gas(), 2, 0x00, 0x40, 0x20, 0x20))
                        mstore(0x20, and(mload(0x20), mask))
                    }
                    mstore(add(buf, k), mload(0x20))
                }
                mstore(buf, or(base, shl(120, 1)))
                pop(staticcall(gas(), 2, buf, shl(5, add(len, 1)), buf, 0x20))
                leaf := mload(buf)
            }
            leaf := and(leaf, mask)
        }
    }

    function _climb(uint256 p, uint256 base, bytes32 leaf, bytes calldata path) private view returns (bytes32 node) {
        assembly ("memory-safe") {
            let n := and(p, 0xff)
            let mask := not(shr(shl(3, n), not(0)))
            let sha := and(shr(16, p), 0xff)
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
                switch sha
                case 0 { node := keccak256(buf, 0x60) }
                default {
                    pop(staticcall(gas(), 2, buf, 0x60, buf, 0x20))
                    node := mload(buf)
                }
                node := and(node, mask)
            }
        }
    }
}
