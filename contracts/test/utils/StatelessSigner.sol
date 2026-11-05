// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice A leanSphincs key (keccak256, n = 16, one XMSS layer of height 26, FORS k = 24 a = 10, WOTS+C with
///         64 chains of w = 4 and target sum 120): the stateless key of decision D11. The signer keeps a subtree
///         of height `b` (a pruned key); the verifier can't tell it from a full key.
struct StatelessKey {
    bytes32 seed; // secret seed S
    bytes32 p; // public parameter P, high 16 bytes
    uint256 b; // height of the kept subtree
    uint256 s; // position of the kept subtree
    bytes32[][] levels; // kept subtree: levels[0] its 2^b WOTS leaves ... levels[b] its root
    bytes32[] surrogates; // siblings above the kept subtree, levels b..25
    bytes32 root; // high 16 bytes
}

/// @notice Test signer for the vendored leanSphincs verifier (src/vendor/sphincs-minus/LeanSphincsAsm.sol),
///         written from the upstream specification (SPHINCs-, docs/leanSphincs-S-keccak.md as amended by
///         docs/leanSphincs-keccak.md), not from the verifier. It reproduces the upstream known answers byte for
///         byte (test/StatelessVerifier.t.sol), so signer and verifier cross-check each other.
///         Test and benchmark use only: tests derive seeds from public labels.
/// @dev    Cost: keygen 225 keccak calls per kept leaf; a signature grinds about 2^(26 - b) randomizers, builds
///         24 FORS trees of 1,024 leaves (61K calls) and grinds about 830 WOTS+C counters. b = 10 balances the
///         two for tests.
///
///         Hash input: P (16 bytes) ‖ address (16 bytes) ‖ payload, so the first word is P ‖ address. Address
///         bytes: lo as u32 little endian, hi as u24 little endian, type | step << 5, eight zero bytes. In the
///         first word that is lo at bits 96..127, hi at bits 72..95, the type byte at bits 64..71.
library StatelessSigner {
    uint256 internal constant H = 26;
    uint256 internal constant K = 24;
    uint256 internal constant A = 10;
    uint256 internal constant V = 64;
    uint256 internal constant TARGET = 120;
    uint256 internal constant SIG_BYTES = 5684;
    /// Default kept-subtree height for test keys
    uint256 internal constant TEST_B = 10;

    uint256 internal constant HIGH = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

    // address types
    uint256 internal constant PRF = 0;
    uint256 internal constant CHAIN = 1;
    uint256 internal constant LEAF = 2;
    uint256 internal constant NODE = 3;
    uint256 internal constant ENC = 4;
    uint256 internal constant PARAMETER = 5;
    uint256 internal constant RANDOMIZER = 7;
    uint256 internal constant FTS_PRF = 8;
    uint256 internal constant FTS_LEAF = 9;
    uint256 internal constant FTS_NODE = 10;
    uint256 internal constant MSG = 12;
    uint256 internal constant SURROGATE = 13;

    // --- address ---

    /// lo (u32) as little-endian bytes at bits 96..127 of the first word
    function _lo(uint256 lo) internal pure returns (uint256) {
        return
            ((lo & 0xff) << 120) | (((lo >> 8) & 0xff) << 112) | (((lo >> 16) & 0xff) << 104)
                | (((lo >> 24) & 0xff) << 96);
    }

    /// hi (u24) as little-endian bytes at bits 72..95, and the type byte at bits 64..71
    function _hiType(uint256 t, uint256 step, uint256 hi) internal pure returns (uint256) {
        return
            ((hi & 0xff) << 88) | (((hi >> 8) & 0xff) << 80) | (((hi >> 16) & 0xff) << 72) | ((t | (step << 5)) << 64);
    }

    /// The 16-byte address as the low half of the first word
    function addr(uint256 t, uint256 step, uint256 hi, uint256 lo) internal pure returns (uint256) {
        require(t < 32 && step < 8 && hi < 1 << 24 && lo < 1 << 32, "address field out of range");
        return _lo(lo) | _hiType(t, step, hi);
    }

    /// keccak256(P ‖ address ‖ payload), all 32 bytes
    function thFull(bytes32 p, uint256 address_, bytes memory payload) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint256(p) | address_, payload));
    }

    /// Th: the first 16 bytes of keccak256(P ‖ address ‖ payload)
    function th(bytes32 p, uint256 address_, bytes memory payload) internal pure returns (bytes32) {
        return thFull(p, address_, payload) & bytes32(HIGH);
    }

    function _node(bytes32 p, uint256 level, uint256 j, bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return th(p, addr(NODE, 0, level, j), abi.encodePacked(bytes16(left), bytes16(right)));
    }

    // --- keys ---

    /// The 32-byte public key: root ‖ P (the verifier's pkRoot is its high half, pkSeed its low half shifted up)
    function publicKey(StatelessKey memory k) internal pure returns (bytes32) {
        return k.root | (k.p >> 128);
    }

    /// A key from a public label, for tests
    function testKey(string memory label) internal pure returns (StatelessKey memory) {
        return keygen(keccak256(abi.encode("winterlock.test.stateless", label)), TEST_B);
    }

    /// Key generation with a kept subtree of height b (b = 26: a full key)
    function keygen(bytes32 seed, uint256 b) internal pure returns (StatelessKey memory k) {
        require(b <= H, "b > 26");
        k.seed = seed;
        k.b = b;
        k.p = th(bytes32(0), addr(PARAMETER, 0, 0, 0), abi.encodePacked(seed));
        if (b < H) {
            uint256 le;
            for (uint256 i; i < 8; ++i) {
                le |= uint256(uint8(k.p[i])) << (8 * i); // u64 little endian of P[0:8]
            }
            k.s = le & ((1 << (H - b)) - 1);
        }
        uint256 first = k.s << b;
        k.levels = new bytes32[][](b + 1);
        k.levels[0] = new bytes32[](1 << b);
        bytes memory buf = new bytes(32 + 16 * V + 32);
        for (uint256 j; j < 1 << b; ++j) {
            k.levels[0][j] = _wotsLeaf(k.p, seed, first + j, buf);
        }
        for (uint256 l = 1; l <= b; ++l) {
            bytes32[] memory below = k.levels[l - 1];
            bytes32[] memory here = new bytes32[](below.length >> 1);
            uint256 off = k.s << (b - l); // global index of this level's first kept node
            for (uint256 j; j < here.length; ++j) {
                here[j] = _node(k.p, l, off + j, below[2 * j], below[2 * j + 1]);
            }
            k.levels[l] = here;
        }
        k.surrogates = new bytes32[](H - b);
        bytes32 node = k.levels[b][0];
        for (uint256 t; t < H - b; ++t) {
            bytes32 sib = th(k.p, addr(SURROGATE, 0, b + t, 0), abi.encodePacked(seed));
            k.surrogates[t] = sib;
            uint256 j = k.s >> t; // this node's index at level b + t
            node = j & 1 == 0 ? _node(k.p, b + t + 1, j >> 1, node, sib) : _node(k.p, b + t + 1, j >> 1, sib, node);
        }
        k.root = node;
    }

    /// The WOTS+C leaf at e: 32 PRF pairs give the 64 chain secrets, each walked 3 steps, then LEAF over the ends.
    /// @param buf scratch of at least 32 + 16 * 64 + 16 bytes
    function _wotsLeaf(bytes32 p, bytes32 seed, uint256 e, bytes memory buf) private pure returns (bytes32 leaf) {
        uint256 pe = uint256(p) | _lo(e);
        assembly ("memory-safe") {
            let out := add(buf, 0x20)
            for { let t := 0 } lt(t, 32) { t := add(t, 1) } {
                mstore(0x00, or(pe, shl(88, t))) // PRF, hi = t (t < 256)
                mstore(0x20, seed)
                let d := keccak256(0x00, 0x40)
                for { let half := 0 } lt(half, 2) { half := add(half, 1) } {
                    let i := add(shl(1, t), half)
                    let x := and(shl(shl(7, half), d), HIGH)
                    for { let step := 0 } lt(step, 3) { step := add(step, 1) } {
                        mstore(0x00, or(pe, or(shl(88, i), shl(64, or(1, shl(5, step))))))
                        mstore(0x20, x)
                        x := and(keccak256(0x00, 0x30), HIGH)
                    }
                    mstore(add(add(out, 0x20), shl(4, i)), x)
                }
            }
            mstore(out, or(pe, shl(64, 2))) // LEAF
            leaf := and(keccak256(out, 1056), HIGH)
        }
    }

    // --- signing ---

    /// Signs a 32-byte message; returns the 5,684-byte signature
    function sign(StatelessKey memory k, bytes32 m) internal pure returns (bytes memory sig) {
        (bytes32 rho, uint256 idx) = _grind(k, m);
        uint256[] memory u = _forsIndices(k.p, m, rho);
        sig = new bytes(SIG_BYTES + 32); // room for the last 16-byte field's 32-byte store
        assembly ("memory-safe") {
            mstore(add(sig, 0x20), rho)
        }
        bytes memory tops = _fors(k, idx, u, sig);
        _wots(k, idx, tops, sig);
        _authPath(k, idx, sig);
        assembly ("memory-safe") {
            mstore(sig, 5684)
        }
    }

    /// ρ = R_0 + i (u128 little endian) for the least i whose digest leaf index lies in the kept subtree
    function _grind(StatelessKey memory k, bytes32 m) private pure returns (bytes32 rho, uint256 idx) {
        bytes32 r0 = th(k.p, addr(RANDOMIZER, 0, 0, 0), abi.encodePacked(k.seed, m));
        uint256 w0 = uint256(k.p) | addr(MSG, 0, 0, 0);
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
                let d := keccak256(buf, 0x50)
                // u64 little endian of D[16:24], low 26 bits
                idx := or(or(byte(16, d), shl(8, byte(17, d))), or(shl(16, byte(18, d)), shl(24, and(byte(19, d), 3))))
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

    /// The 24 FORS indices: tree κ in call κ / 12, word (κ mod 12) / 6, bits 10 * (κ mod 6)
    function _forsIndices(bytes32 p, bytes32 m, bytes32 rho) private pure returns (uint256[] memory u) {
        bytes32[2] memory d;
        for (uint256 c; c < 2; ++c) {
            d[c] = thFull(p, addr(MSG, 0, c, 0), abi.encodePacked(m, bytes16(rho)));
        }
        u = new uint256[](K);
        for (uint256 kappa; kappa < K; ++kappa) {
            uint256 r = kappa % 12;
            u[kappa] = (_word(d[kappa / 12], r / 6) >> (A * (r % 6))) & 0x3ff;
        }
    }

    /// Builds FORS instance idx tree by tree; writes each tree's opened secret and path into the signature and
    /// returns the 48 tops (top_{κ,0} ‖ top_{κ,1}, 16 bytes each)
    function _fors(StatelessKey memory k, uint256 idx, uint256[] memory u, bytes memory sig)
        private
        pure
        returns (bytes memory tops)
    {
        tops = new bytes(2 * K * 16 + 16);
        bytes32[] memory nodes = new bytes32[](1 << A);
        bytes memory hb = new bytes(0x60); // hash input: word0, then up to 32 bytes of payload
        uint256 arr;
        uint256 w;
        assembly ("memory-safe") {
            arr := add(nodes, 0x20)
            w := add(hb, 0x20)
        }
        uint256 pl = uint256(k.p) | _lo(idx);
        for (uint256 kappa; kappa < K; ++kappa) {
            uint256 out;
            assembly ("memory-safe") {
                out := add(add(sig, 0x20), add(16, mul(176, kappa))) // this tree's opening
            }
            _forsLeaves(pl, k.seed, kappa, u[kappa], out, arr, w);
            _forsClimb(pl, kappa, u[kappa], out, arr, w);
            assembly ("memory-safe") {
                mstore(add(add(tops, 0x20), shl(5, kappa)), mload(arr))
                mstore(add(add(tops, 0x30), shl(5, kappa)), mload(add(arr, 0x20)))
            }
        }
        assembly ("memory-safe") {
            mstore(tops, 768)
        }
    }

    /// hi (u24 little endian) and type, in the first word
    function _ht(uint256 t, uint256 hi) private pure returns (uint256) {
        return _hiType(t, 0, hi);
    }

    /// Tree κ's 1,024 leaves into arr; the opened secret sk_{κ,u} to `out`. pos(κ, ℓ, j) = κ + 32ℓ + 512j.
    function _forsLeaves(uint256 pl, bytes32 seed, uint256 kappa, uint256 uk, uint256 out, uint256 arr, uint256 w)
        private
        pure
    {
        for (uint256 t; t < 512; ++t) {
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

    /// Levels 1..9 of tree κ, in place in arr (the two level-9 tops end up in arr[0], arr[1]); path[ℓ], the
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

    /// WOTS+C at leaf idx: the least counter whose encoding of the tops has digit sum 120, then the chains
    function _wots(StatelessKey memory k, uint256 idx, bytes memory tops, bytes memory sig) private pure {
        uint256 pe = uint256(k.p) | _lo(idx);
        bytes memory buf = abi.encodePacked(pe | (uint256(ENC) << 64), tops, bytes32(0));
        uint256 x; // the encoding: digit i is bits 2(i mod 4) of byte i / 4
        uint256 c;
        assembly ("memory-safe") {
            let data := add(buf, 0x20)
            for {} 1 { c := add(c, 1) } {
                // LE32(c) at offset 800
                mstore(
                    add(data, 800),
                    or(
                        or(shl(248, and(c, 0xff)), shl(240, and(shr(8, c), 0xff))),
                        or(shl(232, and(shr(16, c), 0xff)), shl(224, shr(24, c)))
                    )
                )
                x := and(keccak256(data, 804), HIGH)
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
                if eq(shr(248, mul(y, 0x0101010101010101010101010101010101010101010101010101010101010101)), 120) {
                    break
                }
            }
            // counter at 4240, then σ_i at 4244 + 16i
            let base := add(sig, 0x20)
            mstore(
                add(base, 4240),
                or(
                    or(shl(248, and(c, 0xff)), shl(240, and(shr(8, c), 0xff))),
                    or(shl(232, and(shr(16, c), 0xff)), shl(224, shr(24, c)))
                )
            )
        }
        bytes32 seed = k.seed;
        assembly ("memory-safe") {
            let base := add(add(sig, 0x20), 4244)
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
                mstore(add(add(sig, 0x20), add(5268, shl(4, l))), node)
            }
        }
    }
}
