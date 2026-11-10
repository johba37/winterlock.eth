// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/Test.sol";
import {SlhDsaTest} from "./SlhDsaTest.sol";
import {ISlhDsaVerifier} from "../src/ISlhDsaVerifier.sol";

/// SLH-DSA-SHA2-128s against three independent sources of known answers:
/// - NIST ACVP (fixtures/acvp-sha2-128s.json): sigVer's verdicts and sigGen's signatures, pure and internal interfaces
/// - noble post-quantum 0.7.1 (fixtures/noble-sha2-128s.json, tools/noble/gen.mjs)
/// - RustCrypto slh-dsa (fixtures/rustcrypto-sha2-128s.json, tools/rust/)
contract SlhDsaSha2_128sTest is SlhDsaTest {
    function setUp() public {
        verifier = ISlhDsaVerifier(deployCode("SlhDsaSha2_128s.sol:SlhDsaSha2_128s"));
        layout = Layout({k: 14, a: 12, d: 7, hp: 9, len: 35});
    }

    function test_acvp() public view {
        Vector[] memory vs = _load("fixtures/acvp-sha2-128s.json");
        (uint256 valid, uint256 invalid) = _checkVerdicts(vs);
        assertEq(vs.length, 56);
        assertEq(valid, 32);
        assertEq(invalid, 24);
        console.log("ACVP: %d valid and %d invalid verdicts agree", valid, invalid);
    }

    function test_noble() public view {
        Vector[] memory vs = _load("fixtures/noble-sha2-128s.json");
        (uint256 valid, uint256 invalid) = _checkVerdicts(vs);
        assertGt(valid, 0);
        console.log("noble: %d valid and %d invalid verdicts agree", valid, invalid);
    }

    function test_rustcrypto() public view {
        Vector[] memory vs = _load("fixtures/rustcrypto-sha2-128s.json");
        (uint256 valid, uint256 invalid) = _checkVerdicts(vs);
        assertGt(valid, 0);
        console.log("RustCrypto: %d valid and %d invalid verdicts agree", valid, invalid);
    }

    /// Every valid signature of all three sources, mutated part by part
    function test_mutations() public view {
        string[3] memory files =
            ["fixtures/acvp-sha2-128s.json", "fixtures/noble-sha2-128s.json", "fixtures/rustcrypto-sha2-128s.json"];
        uint256 rejected;
        uint256 signatures;
        for (uint256 f; f < files.length; ++f) {
            Vector[] memory vs = _load(files[f]);
            for (uint256 i; i < vs.length; ++i) {
                if (!vs[i].valid) continue;
                rejected += _mutations(vs[i]);
                ++signatures;
            }
        }
        console.log("mutations: %d variants of %d valid signatures rejected", rejected, signatures);
    }

    function test_malformed() public view {
        Vector[] memory vs = _load("fixtures/noble-sha2-128s.json");
        uint256 rejected = _malformed(vs[0], vs[2]); // two keys
        console.log("malformed: %d rejected", rejected);
    }
}
