// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/Test.sol";
import {SlhDsaTest} from "./SlhDsaTest.sol";
import {ISlhDsaVerifier} from "../src/ISlhDsaVerifier.sol";

/// SLH-DSA-SHA2-128-24, a DRAFT parameter set (NIST SP 800-230 ipd). No independent implementation offers it, so:
/// - fixtures/draft-sha2-128-24.json comes from this benchmark's own Python reference (tools/draft.py): it shows the
///   verifier and the reference agree, NOT that either is right. The reference itself is checked against ACVP, noble
///   and RustCrypto on SLH-DSA-SHA2-128s, the same code at other parameters (tools/check_reference.py).
/// - fixtures/sphincs-minus-sha2-128-24.json holds the two known answers of SPHINCs- (Nicolas Consigny's adaptations
///   of the sphincsplus C reference and of noble to this set), which the Python reference re-creates byte for byte
///   from their seeds (`python3 tools/draft.py sphincs-minus`).
contract SlhDsaSha2_128_24_DRAFTTest is SlhDsaTest {
    function setUp() public {
        verifier = ISlhDsaVerifier(deployCode("SlhDsaSha2_128_24_DRAFT.sol:SlhDsaSha2_128_24_DRAFT"));
        layout = Layout({k: 6, a: 24, d: 1, hp: 22, len: 68});
    }

    function test_ownReference_DRAFT() public view {
        Vector[] memory vs = _load("fixtures/draft-sha2-128-24.json");
        (uint256 valid, uint256 invalid) = _checkVerdicts(vs);
        assertEq(valid, 3);
        console.log("DRAFT 128-24, own reference: %d valid, %d invalid verdicts agree", valid, invalid);
    }

    function test_sphincsMinus_DRAFT() public view {
        Vector[] memory vs = _load("fixtures/sphincs-minus-sha2-128-24.json");
        (uint256 valid,) = _checkVerdicts(vs);
        assertEq(valid, 2);
        console.log("DRAFT 128-24, SPHINCs- known answers: %d valid verdicts agree", valid);
    }

    function test_mutations_DRAFT() public view {
        string[2] memory files = ["fixtures/draft-sha2-128-24.json", "fixtures/sphincs-minus-sha2-128-24.json"];
        uint256 rejected;
        uint256 signatures;
        for (uint256 f; f < files.length; ++f) {
            Vector[] memory vs = _load(files[f]);
            for (uint256 i; i < vs.length; ++i) {
                rejected += _mutations(vs[i]);
                ++signatures;
            }
        }
        console.log("DRAFT 128-24 mutations: %d variants of %d valid signatures rejected", rejected, signatures);
    }

    function test_malformed_DRAFT() public view {
        Vector[] memory own = _load("fixtures/draft-sha2-128-24.json");
        Vector[] memory theirs = _load("fixtures/sphincs-minus-sha2-128-24.json");
        uint256 rejected = _malformed(own[0], theirs[0]);
        console.log("DRAFT 128-24 malformed: %d rejected", rejected);
    }
}
