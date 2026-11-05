// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {StatelessKey, StatelessSigner} from "./StatelessSigner.sol";

/// @notice Test signer for leanSphincs-s (keccak256, n = 16, one XMSS layer of height 26, FORS k = 13 a = 12, WOTS+C
///         with 64 chains of w = 4 and target sum 128, 4,164-byte signatures): the verifier vendored test-only in
///         test/vendor/sphincs-minus/LeanSphincs-SAsm.sol. Written from the upstream spec (SPHINCs-,
///         docs/leanSphincs-S-keccak.md), not from the verifier, and checked against the upstream known answers
///         (test/StatelessVerifierS.t.sol). Test use only: tests derive seeds from public labels.
/// @dev    Keys: leanSphincs and leanSphincs-s derive P, the WOTS secrets, the XMSS tree and the surrogates
///         identically from the seed (upstream spec §9 and docs/leanSphincs-keccak.md, "Key separation"), so
///         StatelessSigner.keygen makes the key and only signing differs. One seed must still be one key of one
///         scheme: a seed used for both would make a one-time WOTS key sign two different encodings.
///
///         What differs from StatelessSigner's signing (leanSphincs), by spec section:
///         - §5 digest: one call (hi = 0); the leaf index is word 3, FORS index κ is 12 bits of word ⌊κ/5⌋
///         - §7 FORS: 13 trees of 4,096 leaves, levels 1..11, tops at level 11 (416 bytes)
///         - §6 encoding: 452-byte input (P ‖ address ‖ tops ‖ LE32(c)), target sum 128
///         - §11 offsets: FORS opening 16 + 208κ, counter 2720, WOTS 2724 + 16i, auth path 3748 + 16ℓ
///         Cost: a signature grinds about 2^(26 - b) randomizers, builds 13 FORS trees of 4,096 leaves (133K calls)
///         and grinds about 14,670 WOTS+C counters, about twice leanSphincs's work.
library StatelessSignerS {
    uint256 internal constant H = 26;
    uint256 internal constant K = 13;
    uint256 internal constant A = 12;
    uint256 internal constant V = 64;
    uint256 internal constant TARGET = 128;
    uint256 internal constant SIG_BYTES = 4164;
    /// One FORS tree's opening: the secret and A path nodes, 16 bytes each: 16 (1 + A)
    uint256 internal constant FORS_STRIDE = 208;
    uint256 internal constant OFF_COUNTER = 2720;
    uint256 internal constant OFF_WOTS = 2724;
    uint256 internal constant OFF_AUTH = 3748;
    /// The FORS tops the encoding absorbs, 2 per tree: 2 K 16
    uint256 internal constant TOPS_BYTES = 416;
    /// Default kept-subtree height for test keys, as StatelessSigner's
    uint256 internal constant TEST_B = 10;

    uint256 internal constant HIGH = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

    // address types (spec §3)
    uint256 internal constant ENC = 4;
    uint256 internal constant RANDOMIZER = 7;
    uint256 internal constant FTS_PRF = 8;
    uint256 internal constant FTS_LEAF = 9;
    uint256 internal constant FTS_NODE = 10;
    uint256 internal constant MSG = 12;

    /// A leanSphincs-s key from a public label, for tests. Its seed domain differs from StatelessSigner.testKey's, so
    /// a label never gives one seed to both schemes.
    function testKey(string memory label) internal pure returns (StatelessKey memory) {
        return StatelessSigner.keygen(keccak256(abi.encode("winterlock.test.stateless-s", label)), TEST_B);
    }

    /// Signs a 32-byte message; returns the 4,164-byte signature
    function sign(StatelessKey memory k, bytes32 m) internal pure returns (bytes memory sig) {
        (bytes32 rho, uint256 idx, bytes32 d) = _grind(k, m);
        uint256[] memory u = _forsIndices(d);
        sig = new bytes(SIG_BYTES + 32); // room for the last 16-byte field's 32-byte store
        assembly ("memory-safe") {
            mstore(add(sig, 0x20), rho)
        }
        bytes memory tops = _fors(k, idx, u, sig);
        _wots(k, idx, tops, sig);
        _authPath(k, idx, sig);
        assembly ("memory-safe") {
            mstore(sig, SIG_BYTES)
        }
    }

    /// ρ = R_0 + i (u128 little endian) for the least i whose digest leaf index lies in the kept subtree (§10), and
    /// that digest D = ThFull(P, address(MSG, 0, 0, 0), m ‖ ρ) (§5)
    function _grind(StatelessKey memory k, bytes32 m) private pure returns (bytes32 rho, uint256 idx, bytes32 d) {
        bytes32 r0 = StatelessSigner.th(k.p, StatelessSigner.addr(RANDOMIZER, 0, 0, 0), abi.encodePacked(k.seed, m));
        uint256 w0 = uint256(k.p) | StatelessSigner.addr(MSG, 0, 0, 0);
        uint256 b = k.b;
        uint256 s = k.s;
        uint256 r0le = _bswap128(uint256(r0) >> 128);
        assembly ("memory-safe") {
            let buf := mload(0x40)
            mstore(buf, w0)
            mstore(add(buf, 0x20), m)
            for { let i := 0 } 1 { i := add(i, 1) } {
                rho := shl(128, _bswap(and(add(r0le, i), 0xffffffffffffffffffffffffffffffff)))
                mstore(add(buf, 0x40), rho)
                d := keccak256(buf, 0x50)
                // word 3: u64 little endian of D[24:32], low 26 bits
                idx := or(or(byte(24, d), shl(8, byte(25, d))), or(shl(16, byte(26, d)), shl(24, and(byte(27, d), 3))))
                if eq(shr(b, idx), s) { break }
            }

            // byte reversal of a 128-bit value
            function _bswap(v) -> r {
                r := or(
                    shr(8, and(v, 0xff00ff00ff00ff00ff00ff00ff00ff00)),
                    shl(8, and(v, 0x00ff00ff00ff00ff00ff00ff00ff00ff))
                )
                r := or(
                    shr(16, and(r, 0xffff0000ffff0000ffff0000ffff0000)),
                    shl(16, and(r, 0x0000ffff0000ffff0000ffff0000ffff))
                )
                r := or(
                    shr(32, and(r, 0xffffffff00000000ffffffff00000000)),
                    shl(32, and(r, 0x00000000ffffffff00000000ffffffff))
                )
                r := and(or(shr(64, r), shl(64, r)), 0xffffffffffffffffffffffffffffffff)
            }
        }
    }

    function _bswap128(uint256 v) private pure returns (uint256 r) {
        for (uint256 i; i < 16; ++i) {
            r = (r << 8) | ((v >> (8 * i)) & 0xff);
        }
    }

    /// u64 little endian of d[8w : 8w + 8]
    function _word(bytes32 d, uint256 w) private pure returns (uint256 x) {
        for (uint256 i; i < 8; ++i) {
            x |= uint256(uint8(d[8 * w + i])) << (8 * i);
        }
    }

    /// The 13 FORS indices: u_κ = (word ⌊κ/5⌋ >> 12 (κ mod 5)) & 0xfff (§5)
    function _forsIndices(bytes32 d) private pure returns (uint256[] memory u) {
        u = new uint256[](K);
        for (uint256 kappa; kappa < K; ++kappa) {
            u[kappa] = (_word(d, kappa / 5) >> (A * (kappa % 5))) & 0xfff;
        }
    }

    /// Builds FORS instance idx tree by tree; writes each tree's opened secret and path into the signature and
    /// returns the 26 tops (top_{κ,0} ‖ top_{κ,1}, 16 bytes each)
    function _fors(StatelessKey memory k, uint256 idx, uint256[] memory u, bytes memory sig)
        private
        pure
        returns (bytes memory tops)
    {
        tops = new bytes(TOPS_BYTES + 16);
        bytes32[] memory nodes = new bytes32[](1 << A);
        bytes memory hb = new bytes(0x60); // hash input: word0, then up to 32 bytes of payload
        uint256 arr;
        uint256 w;
        assembly ("memory-safe") {
            arr := add(nodes, 0x20)
            w := add(hb, 0x20)
        }
        uint256 pl = uint256(k.p) | StatelessSigner._lo(idx);
        for (uint256 kappa; kappa < K; ++kappa) {
            uint256 out;
            assembly ("memory-safe") {
                out := add(add(sig, 0x20), add(16, mul(FORS_STRIDE, kappa))) // this tree's opening
            }
            _forsLeaves(pl, k.seed, kappa, u[kappa], out, arr, w);
            _forsClimb(pl, kappa, u[kappa], out, arr, w);
            assembly ("memory-safe") {
                mstore(add(add(tops, 0x20), shl(5, kappa)), mload(arr))
                mstore(add(add(tops, 0x30), shl(5, kappa)), mload(add(arr, 0x20)))
            }
        }
        assembly ("memory-safe") {
            mstore(tops, TOPS_BYTES)
        }
    }

    /// hi (u24 little endian) and type, in the first word
    function _ht(uint256 t, uint256 hi) private pure returns (uint256) {
        return StatelessSigner._hiType(t, 0, hi);
    }

    /// Tree κ's 4,096 leaves into arr; the opened secret sk_{κ,u} to `out`. pos(κ, ℓ, j) = κ + 32ℓ + 512j (§4).
    function _forsLeaves(uint256 pl, bytes32 seed, uint256 kappa, uint256 uk, uint256 out, uint256 arr, uint256 w)
        private
        pure
    {
        for (uint256 t; t < 1 << (A - 1); ++t) {
            uint256 prf = pl | _ht(FTS_PRF, kappa + (t << 9));
            uint256 leaf0 = pl | _ht(FTS_LEAF, kappa + (t << 10));
            uint256 leaf1 = pl | _ht(FTS_LEAF, kappa + (((t << 1) | 1) << 9));
            assembly ("memory-safe") {
                mstore(w, prf)
                mstore(add(w, 0x20), seed)
                let d := keccak256(w, 0x40)
                let j := shl(1, t)
                let sk := and(d, HIGH)
                if eq(j, uk) { mstore(out, sk) }
                mstore(w, leaf0)
                mstore(add(w, 0x20), sk)
                mstore(add(arr, shl(5, j)), and(keccak256(w, 0x30), HIGH))
                j := add(j, 1)
                sk := shl(128, d)
                if eq(j, uk) { mstore(out, sk) }
                mstore(w, leaf1)
                mstore(add(w, 0x20), sk)
                mstore(add(arr, shl(5, j)), and(keccak256(w, 0x30), HIGH))
            }
        }
    }

    /// Levels 1..11 of tree κ, in place in arr (the two level-11 tops end up in arr[0], arr[1]); path[ℓ], the
    /// sibling at level ℓ, to out + 16 + 16ℓ
    function _forsClimb(uint256 pl, uint256 kappa, uint256 uk, uint256 out, uint256 arr, uint256 w) private pure {
        uint256 count = 1 << A;
        for (uint256 l; l < A; ++l) {
            assembly ("memory-safe") {
                mstore(add(out, add(16, shl(4, l))), mload(add(arr, shl(5, xor(shr(l, uk), 1)))))
            }
            if (l + 1 == A) break;
            count >>= 1;
            for (uint256 j; j < count; ++j) {
                uint256 w0 = pl | _ht(FTS_NODE, kappa + ((l + 1) << 5) + (j << 9));
                assembly ("memory-safe") {
                    mstore(w, w0)
                    mstore(add(w, 0x20), mload(add(arr, shl(6, j))))
                    mstore(add(w, 0x30), mload(add(arr, add(shl(6, j), 0x20))))
                    mstore(add(arr, shl(5, j)), and(keccak256(w, 0x40), HIGH))
                }
            }
        }
    }

    /// WOTS+C at leaf idx: the least counter whose encoding of the tops has digit sum 128, then the chains (§6)
    function _wots(StatelessKey memory k, uint256 idx, bytes memory tops, bytes memory sig) private pure {
        uint256 pe = uint256(k.p) | StatelessSigner._lo(idx);
        bytes memory buf = abi.encodePacked(pe | (uint256(ENC) << 64), tops, bytes32(0));
        uint256 x; // the encoding: digit i is bits 2(i mod 4) of byte i / 4
        uint256 c;
        assembly ("memory-safe") {
            let data := add(buf, 0x20)
            let counterAt := add(data, add(32, TOPS_BYTES))
            for {} 1 { c := add(c, 1) } {
                // LE32(c) after the tops
                mstore(
                    counterAt,
                    or(
                        or(shl(248, and(c, 0xff)), shl(240, and(shr(8, c), 0xff))),
                        or(shl(232, and(shr(16, c), 0xff)), shl(224, shr(24, c)))
                    )
                )
                x := and(keccak256(data, add(36, TOPS_BYTES)), HIGH)
                // digit sum: pairs of 2-bit digits, then bytes, then all bytes
                let y :=
                    add(
                        and(x, 0x3333333333333333333333333333333333333333333333333333333333333333),
                        and(shr(2, x), 0x3333333333333333333333333333333333333333333333333333333333333333)
                    )
                y := add(
                    and(y, 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f),
                    and(shr(4, y), 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f)
                )
                if eq(shr(248, mul(y, 0x0101010101010101010101010101010101010101010101010101010101010101)), TARGET) {
                    break
                }
            }
            // counter, then σ_i at OFF_WOTS + 16i
            mstore(
                add(add(sig, 0x20), OFF_COUNTER),
                or(
                    or(shl(248, and(c, 0xff)), shl(240, and(shr(8, c), 0xff))),
                    or(shl(232, and(shr(16, c), 0xff)), shl(224, shr(24, c)))
                )
            )
        }
        bytes32 seed = k.seed;
        assembly ("memory-safe") {
            let base := add(add(sig, 0x20), OFF_WOTS)
            for { let t := 0 } lt(t, 32) { t := add(t, 1) } {
                mstore(0x00, or(pe, shl(88, t))) // PRF, hi = t
                mstore(0x20, seed)
                let d := keccak256(0x00, 0x40)
                for { let half := 0 } lt(half, 2) { half := add(half, 1) } {
                    let i := add(shl(1, t), half)
                    let v := and(shl(shl(7, half), d), HIGH)
                    let digit := and(shr(shl(1, and(i, 3)), byte(shr(2, i), x)), 3)
                    for { let step := 0 } lt(step, digit) { step := add(step, 1) } {
                        mstore(0x00, or(pe, or(shl(88, i), shl(64, or(1, shl(5, step))))))
                        mstore(0x20, v)
                        v := and(keccak256(0x00, 0x30), HIGH)
                    }
                    mstore(add(base, shl(4, i)), v)
                }
            }
        }
    }

    /// XMSS auth path of idx: kept-subtree siblings below level b, surrogates above
    function _authPath(StatelessKey memory k, uint256 idx, bytes memory sig) private pure {
        require(idx >> k.b == k.s, "leaf outside the kept subtree");
        uint256 local = idx - (k.s << k.b);
        for (uint256 l; l < H; ++l) {
            bytes32 node = l < k.b ? k.levels[l][(local >> l) ^ 1] : k.surrogates[l - k.b];
            assembly ("memory-safe") {
                mstore(add(add(sig, 0x20), add(OFF_AUTH, shl(4, l))), node)
            }
        }
    }
}
