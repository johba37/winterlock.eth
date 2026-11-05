// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IStatelessVerifier} from "../src/interfaces/IStatelessVerifier.sol";
import {LeanSphincsSAsm} from "./vendor/sphincs-minus/LeanSphincs-SAsm.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";
import {StatelessSignerS} from "./utils/StatelessSignerS.sol";

/// Measures a verifier inside a contract frame, as an owner or validator calls it.
contract VerifierCaller {
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

/// Option A of docs/notes/safe-messages.md: leanSphincs-s as the stateless key. Its verifier, vendored test-only from
/// SPHINCs- (test/vendor/sphincs-minus/LeanSphincs-SAsm.sol), against the upstream known answers; the test signer
/// (test/utils/StatelessSignerS.sol) against both; and its size and gas next to leanSphincs, the production key (D12).
contract StatelessVerifierSTest is Test {
    IStatelessVerifier internal verifierS; // leanSphincs-s, default compiler pipeline
    IStatelessVerifier internal verifier; // leanSphincs, via-IR (foundry.toml), as production

    /// Known answers from SPHINCs- at 4c76aaf (test/fixtures/leansphincs-s-keccak-kat.json, copied unchanged):
    /// signatures of the Rust signer `lssk`, confirmed there by an independent Python signer
    string internal constant FIXTURE_S = "test/fixtures/leansphincs-s-keccak-kat.json";
    string internal constant FIXTURE = "test/fixtures/leansphincs-keccak-kat.json";

    function setUp() public {
        verifierS = IStatelessVerifier(address(new LeanSphincsSAsm()));
        verifier = IStatelessVerifier(deployCode("LeanSphincsAsm.sol:LeanSphincsAsm"));
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

    function _vectors(string memory path) internal view returns (Vector[] memory vs) {
        string memory json = vm.readFile(path);
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
        Vector[] memory vs = _vectors(FIXTURE_S);
        for (uint256 i; i < vs.length; ++i) {
            assertEq(vs[i].sig.length, StatelessSignerS.SIG_BYTES);
            assertTrue(verifierS.verify(vs[i].pkSeed, vs[i].pkRoot, vs[i].message, vs[i].sig), "known answer");
            assertFalse(verifierS.verify(vs[i].pkSeed, vs[i].pkRoot, ~vs[i].message, vs[i].sig), "other message");
            bytes memory flipped = bytes.concat(vs[i].sig);
            flipped[2000] ^= 0x01;
            assertFalse(verifierS.verify(vs[i].pkSeed, vs[i].pkRoot, vs[i].message, flipped), "flipped byte");
        }
    }

    /// The two schemes don't accept each other's signatures: each checks its own length first and reverts.
    function test_schemesDontMix() public {
        Vector[] memory s = _vectors(FIXTURE_S);
        Vector[] memory l = _vectors(FIXTURE);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(s[0].pkSeed, s[0].pkRoot, s[0].message, s[0].sig);
        vm.expectRevert(bytes("Invalid sig length"));
        verifierS.verify(l[0].pkSeed, l[0].pkRoot, l[0].message, l[0].sig);
    }

    // --- keys ---

    /// leanSphincs and leanSphincs-s derive the same public key from the same seed and subtree height: the fixtures'
    /// vectors with a common seed and b carry the same key words. So switching a member to leanSphincs-s with the same
    /// key isn't possible: upstream forbids one seed for two schemes. A switch is a new seed, a new key, a new owner.
    function test_sameSeedSameKeyInBothSchemes() public view {
        Vector[] memory s = _vectors(FIXTURE_S);
        Vector[] memory l = _vectors(FIXTURE);
        uint256 common;
        for (uint256 i; i < s.length; ++i) {
            for (uint256 j; j < l.length; ++j) {
                if (s[i].seed != l[j].seed || s[i].b != l[j].b) continue;
                assertEq(s[i].pkSeed, l[j].pkSeed, "P");
                assertEq(s[i].pkRoot, l[j].pkRoot, "root");
                ++common;
            }
        }
        assertEq(common, 4);
    }

    // --- the test signer ---

    /// The signer reproduces upstream's b = 10 and b = 12 known answers byte for byte: key and signature. (The b = 6
    /// vectors would grind 2^20 randomizers each.)
    function test_signerReproducesKnownAnswers() public view {
        Vector[] memory vs = _vectors(FIXTURE_S);
        uint256 checked;
        for (uint256 i; i < vs.length; ++i) {
            if (vs[i].b < 10) continue;
            StatelessKey memory k = StatelessSigner.keygen(vs[i].seed, vs[i].b);
            (bytes32 pkSeed, bytes32 pkRoot) = _split(StatelessSigner.publicKey(k));
            assertEq(pkSeed, vs[i].pkSeed, "P");
            assertEq(pkRoot, vs[i].pkRoot, "root");
            assertEq(keccak256(StatelessSignerS.sign(k, vs[i].message)), keccak256(vs[i].sig), "signature");
            ++checked;
        }
        assertEq(checked, 4);
    }

    function test_testKeySignsAndVerifies() public view {
        StatelessKey memory k = StatelessSignerS.testKey("alice");
        (bytes32 pkSeed, bytes32 pkRoot) = _split(StatelessSigner.publicKey(k));
        bytes32 m = keccak256("a SafeMessage digest");
        bytes memory sig = StatelessSignerS.sign(k, m);
        assertEq(sig.length, 4164);
        assertTrue(verifierS.verify(pkSeed, pkRoot, m, sig));
        assertFalse(verifierS.verify(pkSeed, pkRoot, keccak256("another"), sig));
        (bytes32 otherSeed, bytes32 otherRoot) = _split(StatelessSigner.publicKey(StatelessSignerS.testKey("bob")));
        assertFalse(verifierS.verify(otherSeed, otherRoot, m, sig), "another key");
        // a label gives different seeds to the two schemes' test keys
        assertTrue(StatelessSigner.publicKey(k) != StatelessSigner.publicKey(StatelessSigner.testKey("alice")));
    }

    // --- size and gas, side by side ---

    /// Verification gas over the six known answers of each scheme: in the verifier's own frame, and from a calling
    /// contract (warm verifier; the CALL and the ABI encoding of the signature included). leanSphincs is compiled
    /// with via-IR (foundry.toml), leanSphincs-s with the default pipeline: see the note for its via-IR figure.
    function test_gas_verify() public {
        VerifierCaller caller = new VerifierCaller();
        (uint256 sMin, uint256 sMax, uint256 sCaller) = _gas(verifierS, _vectors(FIXTURE_S), caller);
        (uint256 lMin, uint256 lMax, uint256 lCaller) = _gas(verifier, _vectors(FIXTURE), caller);
        console.log("leanSphincs-s: signature bytes 4164, own frame min", sMin, "max", sMax);
        console.log("leanSphincs-s: from a contract (warm), max", sCaller);
        console.log("leanSphincs:   signature bytes 5684, own frame min", lMin, "max", lMax);
        console.log("leanSphincs:   from a contract (warm), max", lCaller);
        assertLt(sMax, lMin, "leanSphincs-s verifies for less");
        assertLe(lMax, 53_542); // upstream's ceiling for leanSphincs (via-IR)
    }

    function _gas(IStatelessVerifier v, Vector[] memory vs, VerifierCaller caller)
        internal
        returns (uint256 frameMin, uint256 frameMax, uint256 callerMax)
    {
        frameMin = type(uint256).max;
        for (uint256 i; i < vs.length; ++i) {
            assertTrue(v.verify(vs[i].pkSeed, vs[i].pkRoot, vs[i].message, vs[i].sig));
            uint256 frame = vm.lastCallGas().gasTotalUsed;
            if (frame < frameMin) frameMin = frame;
            if (frame > frameMax) frameMax = frame;
            (bool ok, uint256 g) = caller.verifyGas(v, vs[i].pkSeed, vs[i].pkRoot, vs[i].message, vs[i].sig);
            assertTrue(ok);
            if (g > callerMax) callerMax = g;
        }
    }
}
