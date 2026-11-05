// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IStatelessVerifier} from "../src/interfaces/IStatelessVerifier.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";

/// Measures the verifier inside a contract frame, as the validator calls it.
contract StatelessVerifierCaller {
    function verifyGas(IStatelessVerifier v, bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        view
        returns (bool ok, uint256 gasUsed)
    {
        gasUsed = gasleft();
        ok = v.verify(pkSeed, pkRoot, message, sig);
        gasUsed -= gasleft();
    }
}

/// D11's stateless key: the vendored leanSphincs verifier (SPHINCs-, src/keccak/LeanSphincsAsm.sol) against the
/// upstream known answers, and the Solidity test signer (test/utils/StatelessSigner.sol) against both.
contract StatelessVerifierTest is Test {
    IStatelessVerifier internal verifier;

    /// Known answers from SPHINCs- (test/fixtures/leansphincs-keccak-kat.json, copied unchanged): signatures of
    /// the Rust signer, confirmed there by an independent Python verifier
    string internal constant FIXTURE = "test/fixtures/leansphincs-keccak-kat.json";
    /// Compiled with via-IR, as upstream measures it (foundry.toml: compilation_restrictions). Nothing imports the
    /// source, so it is compiled once.
    string internal constant STATELESS_VERIFIER_ARTIFACT = "LeanSphincsAsm.sol:LeanSphincsAsm";

    function setUp() public {
        verifier = IStatelessVerifier(deployCode(STATELESS_VERIFIER_ARTIFACT));
    }

    struct Vector {
        bytes32 seed;
        uint256 b;
        bytes32 pkSeed;
        bytes32 pkRoot;
        bytes32 message;
        bytes sig;
    }

    function _key(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "].", field);
    }

    function _vectors() internal view returns (Vector[] memory vs) {
        string memory json = vm.readFile(FIXTURE);
        uint256 n;
        while (vm.keyExistsJson(json, string.concat(".vectors[", vm.toString(n), "]"))) ++n;
        assertEq(n, 6);
        vs = new Vector[](n);
        for (uint256 i; i < n; ++i) {
            vs[i].seed = vm.parseJsonBytes32(json, _key(i, "seed"));
            vs[i].b = vm.parseJsonUint(json, _key(i, "b"));
            vs[i].pkSeed = vm.parseJsonBytes32(json, _key(i, "pkSeed"));
            vs[i].pkRoot = vm.parseJsonBytes32(json, _key(i, "pkRoot"));
            vs[i].message = vm.parseJsonBytes32(json, _key(i, "message"));
            vs[i].sig = vm.parseJsonBytes(json, _key(i, "sig"));
        }
    }

    function _split(bytes32 publicKey) internal pure returns (bytes32 pkSeed, bytes32 pkRoot) {
        pkSeed = publicKey << 128;
        pkRoot = publicKey & bytes32(StatelessSigner.HIGH);
    }

    // --- the vendored verifier ---

    function test_upstreamKnownAnswersVerify() public view {
        Vector[] memory vs = _vectors();
        for (uint256 i; i < vs.length; ++i) {
            assertEq(vs[i].sig.length, StatelessSigner.SIG_BYTES);
            assertTrue(verifier.verify(vs[i].pkSeed, vs[i].pkRoot, vs[i].message, vs[i].sig), "known answer");
            assertFalse(verifier.verify(vs[i].pkSeed, vs[i].pkRoot, ~vs[i].message, vs[i].sig), "other message");
            bytes memory flipped = bytes.concat(vs[i].sig);
            flipped[3000] ^= 0x01;
            assertFalse(verifier.verify(vs[i].pkSeed, vs[i].pkRoot, vs[i].message, flipped), "flipped byte");
        }
    }

    // --- the test signer ---

    /// The signer reproduces upstream's b = 10 known answers byte for byte: key and signature.
    function test_signerReproducesKnownAnswers() public view {
        Vector[] memory vs = _vectors();
        uint256 checked;
        for (uint256 i; i < vs.length; ++i) {
            if (vs[i].b != 10) continue;
            StatelessKey memory k = StatelessSigner.keygen(vs[i].seed, 10);
            (bytes32 pkSeed, bytes32 pkRoot) = _split(StatelessSigner.publicKey(k));
            assertEq(pkSeed, vs[i].pkSeed, "P");
            assertEq(pkRoot, vs[i].pkRoot, "root");
            assertEq(keccak256(StatelessSigner.sign(k, vs[i].message)), keccak256(vs[i].sig), "signature");
            ++checked;
        }
        assertEq(checked, 2);
    }

    /// The known answer of the upstream crate (leanXMSS-leanSPHINCS-candidates, branch keccak), quoted in
    /// SPHINCs- docs/leanSphincs-keccak.md: key_gen(seed(1), 11), seed(x)[i] = 31x + i, m[i] = 7i (mod 256).
    function test_signerReproducesUpstreamCrateKnownAnswer() public pure {
        bytes memory seed = new bytes(32);
        bytes memory m = new bytes(32);
        for (uint256 i; i < 32; ++i) {
            seed[i] = bytes1(uint8((31 + i) % 256));
            m[i] = bytes1(uint8((7 * i) % 256));
        }
        StatelessKey memory k = StatelessSigner.keygen(bytes32(seed), 11);
        assertEq(StatelessSigner.publicKey(k), 0x63b118353523319f8f74f387824956482e582128e480149accc2ed4f19edcd00);
        bytes memory sig = StatelessSigner.sign(k, bytes32(m));
        assertEq(keccak256(sig), 0x9a21b6bc61d6ba500b4d67809912c1424be1f58486eda144e4ef70afd01cf94d);
        assertEq(uint32(bytes4(_slice(sig, 4240, 4))), 0x98040000, "counter 1176, little endian");
    }

    function _slice(bytes memory b, uint256 from, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = b[from + i];
        }
    }

    function test_testKeySignsAndVerifies() public view {
        StatelessKey memory k = StatelessSigner.testKey("alice");
        (bytes32 pkSeed, bytes32 pkRoot) = _split(StatelessSigner.publicKey(k));
        bytes32 m = keccak256("a certificate digest");
        bytes memory sig = StatelessSigner.sign(k, m);
        assertTrue(verifier.verify(pkSeed, pkRoot, m, sig));
        assertFalse(verifier.verify(pkSeed, pkRoot, keccak256("another"), sig));
        (bytes32 otherSeed, bytes32 otherRoot) = _split(StatelessSigner.publicKey(StatelessSigner.testKey("bob")));
        assertFalse(verifier.verify(otherSeed, otherRoot, m, sig), "another key");
    }

    // --- gas ---

    /// Verification gas in the verifier's own frame, and from a calling contract (CALL plus ABI encoding of the
    /// 5,684-byte signature), over the six known answers
    function test_gas_verify() public {
        Vector[] memory vs = _vectors();
        StatelessVerifierCaller caller = new StatelessVerifierCaller();
        uint256 frameMin = type(uint256).max;
        uint256 frameMax;
        uint256 callerMax;
        for (uint256 i; i < vs.length; ++i) {
            assertTrue(verifier.verify(vs[i].pkSeed, vs[i].pkRoot, vs[i].message, vs[i].sig));
            uint256 frame = vm.lastCallGas().gasTotalUsed;
            if (frame < frameMin) frameMin = frame;
            if (frame > frameMax) frameMax = frame;
            (bool ok, uint256 g) = caller.verifyGas(verifier, vs[i].pkSeed, vs[i].pkRoot, vs[i].message, vs[i].sig);
            assertTrue(ok);
            if (g > callerMax) callerMax = g;
        }
        console.log("verify gas, own frame: min", frameMin, "max", frameMax);
        console.log("verify gas, from a contract (warm), max", callerMax);
        console.log("signature bytes", vs[0].sig.length);
        assertLe(frameMax, 53_542); // upstream's ceiling for any admissible signature (test/LeanSphincsTest.t.sol)
    }
}
