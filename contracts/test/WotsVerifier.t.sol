// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {VerifierHarness} from "./utils/Harness.sol";
import {WotsParams, WotsSigner, WotsTree, WotsKey, Ops} from "./utils/WotsSigner.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";

/// Runs once per parameter set (see the subclasses at the bottom).
abstract contract WotsVerifierTestBase is Test {
    VerifierHarness internal v;

    uint128 internal constant SEED = 0x5eed0000000000000000000000000001;
    bytes32 internal constant SK = keccak256("winterlock.test.verifier");
    uint256 internal constant H = 4;

    function _p() internal pure virtual returns (WotsParams memory);

    function setUp() public {
        v = new VerifierHarness();
    }

    function _name() internal pure returns (string memory) {
        WotsParams memory p = _p();
        return string.concat(
            "n=",
            vm.toString(p.n),
            " w=",
            vm.toString(1 << p.logW),
            p.hashFn == 0 ? " keccak" : " sha256",
            p.targetSum == 0 ? " checksum" : string.concat(" T=", vm.toString(p.targetSum))
        );
    }

    function _root(uint256 keyIndex, bytes32 m, bytes memory sig, bytes memory path) internal view returns (bytes32) {
        WotsParams memory p = _p();
        return v.computeRoot(Ops.params(p), SEED, keyIndex, m, sig, path);
    }

    function _fullTree() internal pure returns (WotsKey memory) {
        return WotsTree.create(_p(), SEED, SK, H, H);
    }

    function _sign(uint256 keyIndex, bytes32 m) internal pure returns (bytes memory) {
        return WotsSigner.sign(_p(), SEED, SK, keyIndex, m);
    }

    /// Root from a leaf and siblings, in plain Solidity, independent of the assembly.
    function _climb(bytes32 leaf, uint256 keyIndex, bytes32[] memory sibs) internal pure returns (bytes32 node) {
        WotsParams memory p = _p();
        node = leaf;
        uint256 idx = keyIndex;
        for (uint256 l; l < sibs.length; ++l) {
            uint256 parent = idx >> 1;
            node = (idx & 1 == 0)
                ? WotsSigner.node(p, SEED, l + 1, parent, node, sibs[l])
                : WotsSigner.node(p, SEED, l + 1, parent, sibs[l], node);
            idx = parent;
        }
    }

    function _getElem(bytes memory sig, uint256 off) internal pure returns (bytes32 x) {
        for (uint256 j; j < _p().n; ++j) {
            x |= bytes32(sig[off + j]) >> (8 * j);
        }
    }

    function _setElem(bytes memory sig, uint256 off, bytes32 x) internal pure {
        for (uint256 j; j < _p().n; ++j) {
            sig[off + j] = x[j];
        }
    }

    function test_signatureLength() public pure {
        WotsParams memory p = _p();
        assertEq(_sign(0, keccak256("m")).length, WotsVerifier.sigBytes(Ops.params(p)));
    }

    function test_everyKeyInTreeVerifies() public view {
        WotsKey memory key = _fullTree();
        for (uint256 i; i < (1 << H); ++i) {
            bytes32 m = keccak256(abi.encode("msg", i));
            assertEq(_root(i, m, _sign(i, m), WotsTree.path(key, i)), key.root, "valid signature rejected");
        }
    }

    /// forge-config: default.fuzz.runs = 64
    function testFuzz_verifierMatchesSigner(bytes32 m, uint64 rawIndex) public view {
        WotsParams memory p = _p();
        uint256 keyIndex = uint256(rawIndex) & ((1 << 20) - 1);
        bytes32[] memory sibs = new bytes32[](20);
        bytes memory path;
        for (uint256 l; l < 20; ++l) {
            sibs[l] = WotsSigner.trunc(p, keccak256(abi.encode(m, l)));
            path = bytes.concat(path, WotsSigner.pack(p, sibs[l]));
        }
        bytes32 expected = _climb(WotsSigner.leaf(p, SEED, SK, keyIndex), keyIndex, sibs);
        assertEq(_root(keyIndex, m, _sign(keyIndex, m), path), expected);
    }

    function test_wrongMessageFails() public view {
        WotsKey memory key = _fullTree();
        bytes memory sig = _sign(3, keccak256("pay alice"));
        assertTrue(_root(3, keccak256("pay mallory"), sig, WotsTree.path(key, 3)) != key.root);
    }

    function test_wrongKeyIndexFails() public view {
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = _sign(3, m);
        bytes memory path = WotsTree.path(key, 3);
        assertTrue(_root(2, m, sig, path) != key.root);
        assertTrue(_root(3 + (1 << H), m, sig, path) != key.root);
    }

    function test_wrongSeedFails() public view {
        WotsParams memory p = _p();
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = _sign(5, m);
        assertTrue(v.computeRoot(Ops.params(p), SEED + 1, 5, m, sig, WotsTree.path(key, 5)) != key.root);
    }

    /// forge-config: default.fuzz.runs = 64
    function testFuzz_tamperedSignatureFails(uint16 pos, uint8 flip) public view {
        vm.assume(flip != 0);
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = _sign(7, m);
        uint256 at = uint256(pos) % sig.length;
        sig[at] = bytes1(uint8(sig[at]) ^ flip);
        assertTrue(_root(7, m, sig, WotsTree.path(key, 7)) != key.root);
    }

    function test_tamperedPathFails() public view {
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = _sign(9, m);
        bytes memory path = WotsTree.path(key, 9);
        path[_p().n + 3] = bytes1(uint8(path[_p().n + 3]) ^ 1);
        assertTrue(_root(9, m, sig, path) != key.root);
    }

    /// Hashing a revealed value forward one step is free for anyone. It must not produce a valid
    /// signature: the checksum chains (or the fixed digit sum) would have to move backwards.
    function test_advancingAChainFails() public view {
        WotsParams memory p = _p();
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        (uint256[] memory a, bytes32 r) = WotsSigner.encode(p, SEED, SK, 1, m);
        bytes memory sig = WotsSigner.signDigits(p, SEED, SK, 1, a, r);
        uint256 i;
        while (a[i] == WotsSigner.wm1(p)) ++i;
        uint256 off = p.n * (i + 1);
        bytes32 x = WotsSigner.chain(p, SEED, 1, i, _getElem(sig, off), a[i], a[i] + 1);
        _setElem(sig, off, x);
        assertTrue(_root(1, m, sig, WotsTree.path(key, 1)) != key.root);
    }

    /// Target sum only: chains that are honestly computed for digits with the wrong sum must be rejected.
    /// Without the sum check this signature would verify, so the test pins the check down.
    function test_wrongDigitSumRejected() public {
        WotsParams memory p = _p();
        if (p.targetSum == 0) vm.skip(true);
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes32 r;
        uint256[] memory a;
        uint256 sum;
        for (uint256 c;; ++c) {
            r = WotsSigner.randomizer(p, SK, 2, m, 1_000_000 + c);
            (a, sum) = WotsSigner.digits(p, WotsSigner.digest(p, SEED, 2, r, m));
            if (sum != p.targetSum) break;
        }
        bytes memory sig = WotsSigner.signDigits(p, SEED, SK, 2, a, r);
        assertEq(_root(2, m, sig, WotsTree.path(key, 2)), bytes32(0));
    }

    function test_revertsOnMalformedLengths() public {
        WotsParams memory p = _p();
        uint256 len = WotsVerifier.sigBytes(Ops.params(p));
        vm.expectRevert(WotsVerifier.BadSignatureLength.selector);
        v.computeRoot(Ops.params(p), SEED, 0, bytes32(0), new bytes(len - 1), "");
        vm.expectRevert(WotsVerifier.BadPathLength.selector);
        v.computeRoot(Ops.params(p), SEED, 0, bytes32(0), new bytes(len), new bytes(p.n + 1));
    }

    /// Gas of the verifier library alone (no call overhead, no calldata), height 20, 16 random messages.
    function test_gas_verifierOnly() public view {
        WotsParams memory p = _p();
        WotsKey memory key = WotsTree.create(p, SEED, SK, 20, 0);
        bytes memory path = WotsTree.path(key, 0);
        uint256 total;
        uint256 lo = type(uint256).max;
        uint256 hi;
        for (uint256 r; r < 16; ++r) {
            bytes32 m = keccak256(abi.encode("bench", r));
            (bytes32 root, uint256 g) = v.computeRootGas(Ops.params(p), SEED, 0, m, _sign(0, m), path);
            require(root == key.root, "bench signature invalid");
            total += g;
            if (g < lo) lo = g;
            if (g > hi) hi = g;
        }
        console.log(
            string.concat(
                "verifier gas, h=20, ", _name(), ": avg ", vm.toString(total / 16), " (min ", vm.toString(lo),
                ", max ", vm.toString(hi), "), sig ", vm.toString(WotsVerifier.sigBytes(Ops.params(p))), " B"
            )
        );
    }
}

contract WotsVerifier_n32_checksum is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(32, 0, 4, 0);
    }
}

contract WotsVerifier_n32_target is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(32, 560, 4, 0);
    }
}

contract WotsVerifier_n24_checksum is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 0, 4, 0);
    }
}

contract WotsVerifier_n24_target is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }
}

contract WotsVerifier_n16_checksum is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(16, 0, 4, 0);
    }
}

contract WotsVerifier_n16_target is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(16, 300, 4, 0);
    }
}

// --- Winternitz parameter and hash function (n = 24) ---

contract WotsVerifier_n24_w4_checksum is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 0, 2, 0);
    }
}

contract WotsVerifier_n24_w4_target is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 173, 2, 0);
    }
}

contract WotsVerifier_n24_w256_checksum is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 0, 8, 0);
    }
}

contract WotsVerifier_n24_w256_target is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 3216, 8, 0);
    }
}

contract WotsVerifier_n24_sha256_checksum is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 0, 4, 1);
    }
}

contract WotsVerifier_n24_sha256_target is WotsVerifierTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 1);
    }
}
