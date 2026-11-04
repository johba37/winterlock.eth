// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {VerifierHarness} from "./utils/Harness.sol";
import {WotsSigner, WotsTree, WotsKey} from "./utils/WotsSigner.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";

contract WotsVerifierTest is Test {
    VerifierHarness internal v;

    uint128 internal constant SEED = 0x5eed0000000000000000000000000001;
    bytes32 internal constant SK = keccak256("winterlock.test.verifier");
    uint256 internal constant H = 4;

    function setUp() public {
        v = new VerifierHarness();
    }

    function _fullTree() internal pure returns (WotsKey memory) {
        return WotsTree.create(SEED, SK, H, H);
    }

    /// Root from a leaf and path, in plain Solidity, independent of the assembly.
    function _climb(bytes32 leaf, uint256 keyIndex, bytes32[] memory sibs) internal pure returns (bytes32 node) {
        node = leaf;
        uint256 idx = keyIndex;
        for (uint256 l; l < sibs.length; ++l) {
            uint256 parent = idx >> 1;
            node = (idx & 1 == 0)
                ? WotsSigner.node(SEED, l + 1, parent, node, sibs[l])
                : WotsSigner.node(SEED, l + 1, parent, sibs[l], node);
            idx = parent;
        }
    }

    function test_everyKeyInTreeVerifies() public view {
        WotsKey memory key = _fullTree();
        for (uint256 i; i < (1 << H); ++i) {
            bytes32 m = keccak256(abi.encode("msg", i));
            bytes memory sig = WotsSigner.sign(SEED, SK, i, m);
            assertEq(v.computeRoot(SEED, i, m, sig, WotsTree.path(key, i)), key.root, "valid signature rejected");
        }
    }

    function testFuzz_verifierMatchesSigner(bytes32 m, uint64 rawIndex) public view {
        uint256 keyIndex = uint256(rawIndex) & ((1 << 20) - 1);
        bytes32[] memory sibs = new bytes32[](20);
        bytes memory path;
        for (uint256 l; l < 20; ++l) {
            sibs[l] = keccak256(abi.encode(m, l));
            path = abi.encodePacked(path, sibs[l]);
        }
        bytes32 expected = _climb(WotsSigner.leaf(SEED, SK, keyIndex), keyIndex, sibs);
        bytes memory sig = WotsSigner.sign(SEED, SK, keyIndex, m);
        assertEq(v.computeRoot(SEED, keyIndex, m, sig, path), expected);
    }

    function test_wrongMessageFails() public view {
        WotsKey memory key = _fullTree();
        bytes memory sig = WotsSigner.sign(SEED, SK, 3, keccak256("pay alice"));
        assertTrue(v.computeRoot(SEED, 3, keccak256("pay mallory"), sig, WotsTree.path(key, 3)) != key.root);
    }

    function test_wrongKeyIndexFails() public view {
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = WotsSigner.sign(SEED, SK, 3, m);
        bytes memory path = WotsTree.path(key, 3);
        assertTrue(v.computeRoot(SEED, 2, m, sig, path) != key.root);
        assertTrue(v.computeRoot(SEED, 3 + (1 << H), m, sig, path) != key.root);
    }

    function test_wrongSeedFails() public view {
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = WotsSigner.sign(SEED, SK, 5, m);
        assertTrue(v.computeRoot(SEED + 1, 5, m, sig, WotsTree.path(key, 5)) != key.root);
    }

    function testFuzz_tamperedSignatureFails(uint8 pos, bytes32 delta) public view {
        vm.assume(delta != bytes32(0));
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = WotsSigner.sign(SEED, SK, 7, m);
        uint256 off = 32 + 32 * (uint256(pos) % 67);
        assembly {
            mstore(add(sig, off), xor(mload(add(sig, off)), delta))
        }
        assertTrue(v.computeRoot(SEED, 7, m, sig, WotsTree.path(key, 7)) != key.root);
    }

    function test_tamperedPathFails() public view {
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        bytes memory sig = WotsSigner.sign(SEED, SK, 9, m);
        bytes memory path = WotsTree.path(key, 9);
        path[40] = bytes1(uint8(path[40]) ^ 1);
        assertTrue(v.computeRoot(SEED, 9, m, sig, path) != key.root);
    }

    /// Hashing a revealed value forward one step is free for anyone. It must not produce a valid
    /// signature for any message: the checksum chains would have to move backwards.
    function test_advancingAChainFails() public view {
        WotsKey memory key = _fullTree();
        bytes32 m = keccak256("m");
        uint256[67] memory a = WotsSigner.digits(SEED, 1, m);
        bytes memory sig = WotsSigner.sign(SEED, SK, 1, m);
        uint256 i;
        while (a[i] == 15) ++i;
        bytes32 x;
        assembly {
            x := mload(add(sig, add(32, mul(32, i))))
        }
        x = keccak256(abi.encodePacked(WotsSigner.tweak(SEED, 0, 1, i, a[i]), x));
        assembly {
            mstore(add(sig, add(32, mul(32, i))), x)
        }
        assertTrue(v.computeRoot(SEED, 1, m, sig, WotsTree.path(key, 1)) != key.root);
    }

    function test_revertsOnMalformedLengths() public {
        bytes memory sig = new bytes(WotsVerifier.SIG_BYTES - 1);
        vm.expectRevert(WotsVerifier.BadSignatureLength.selector);
        v.computeRoot(SEED, 0, bytes32(0), sig, "");
        sig = new bytes(WotsVerifier.SIG_BYTES);
        vm.expectRevert(WotsVerifier.BadPathLength.selector);
        v.computeRoot(SEED, 0, bytes32(0), sig, new bytes(33));
    }

    /// Gas of the verifier library alone (no call overhead, no calldata), over 32 random messages.
    function test_gas_verifierOnly() public view {
        uint256[3] memory heights = [uint256(10), 16, 20];
        for (uint256 t; t < 3; ++t) {
            WotsKey memory key = WotsTree.create(SEED, SK, heights[t], 0);
            bytes memory path = WotsTree.path(key, 0);
            uint256 total;
            uint256 lo = type(uint256).max;
            uint256 hi;
            for (uint256 r; r < 32; ++r) {
                bytes32 m = keccak256(abi.encode("bench", r));
                bytes memory sig = WotsSigner.sign(SEED, SK, 0, m);
                (bytes32 root, uint256 g) = v.computeRootGas(SEED, 0, m, sig, path);
                require(root == key.root, "bench signature invalid");
                total += g;
                if (g < lo) lo = g;
                if (g > hi) hi = g;
            }
            console.log(
                string.concat(
                    "height ", vm.toString(heights[t]), ": verifier gas avg ", vm.toString(total / 32),
                    " (min ", vm.toString(lo), ", max ", vm.toString(hi), ")"
                )
            );
        }
    }
}
