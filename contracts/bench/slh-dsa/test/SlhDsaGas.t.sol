// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/Test.sol";
import {SlhDsaTest} from "./SlhDsaTest.sol";
import {ISlhDsaVerifier} from "../src/ISlhDsaVerifier.sol";
import {SlhDsaOwner} from "../src/SlhDsaOwner.sol";

/// Calls the verifier or an owner from a contract, as an owner or account would, and measures with gasleft.
contract GasProbe {
    function verify(ISlhDsaVerifier v, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (bool ok, uint256 used)
    {
        used = gasleft();
        ok = v.verify(pk, m, sig);
        used -= gasleft();
    }

    /// Two calls in one transaction: the second finds the verifier warm
    function verifyWarm(ISlhDsaVerifier v, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (bool ok, uint256 used)
    {
        v.verify(pk, m, sig);
        used = gasleft();
        ok = v.verify(pk, m, sig);
        used -= gasleft();
    }

    function erc1271(SlhDsaOwner owner, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4 r, uint256 used)
    {
        used = gasleft();
        r = owner.isValidSignature(hash, sig);
        used -= gasleft();
    }

    /// The verifier with a gas limit: 0 for false, 1 for true, 2 for a revert
    function verifyWithGas(ISlhDsaVerifier v, uint256 g, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (uint256)
    {
        try v.verify{gas: g}(pk, m, sig) returns (bool ok) {
            return ok ? 1 : 0;
        } catch {
            return 2;
        }
    }
}

/// Verification gas under the fork in foundry.toml (Prague), measured with gasleft from a calling contract: the
/// verifier cold (vm.cool: its first use in a transaction, 2,600 for the account) and warm. The whole transaction, with intrinsic
/// and calldata gas, is measured on anvil by gas.sh.
contract SlhDsaGasTest is SlhDsaTest {
    GasProbe internal probe;
    ISlhDsaVerifier internal v128s;
    ISlhDsaVerifier internal vDraft;

    function setUp() public {
        probe = new GasProbe();
        v128s = ISlhDsaVerifier(deployCode("SlhDsaSha2_128s.sol:SlhDsaSha2_128s"));
        vDraft = ISlhDsaVerifier(deployCode("SlhDsaSha2_128_24_DRAFT.sol:SlhDsaSha2_128_24_DRAFT"));
    }

    /// Valid signatures over 32-byte messages with an empty context
    function _hashVectors(string memory path) internal view returns (Vector[] memory out, uint256 n) {
        Vector[] memory vs = _load(path);
        out = new Vector[](vs.length);
        for (uint256 i; i < vs.length; ++i) {
            if (vs[i].valid && !vs[i].internalInterface && vs[i].ctx.length == 0 && vs[i].message.length == 32) {
                out[n++] = vs[i];
            }
        }
    }

    struct Stats {
        uint256 n;
        uint256 min;
        uint256 max;
        uint256 sum;
    }

    function _add(Stats memory st, uint256 g) internal pure {
        if (st.n == 0 || g < st.min) st.min = g;
        if (g > st.max) st.max = g;
        st.sum += g;
        ++st.n;
    }

    function _measure(ISlhDsaVerifier v, string memory name, string[2] memory files) internal {
        Stats memory cold;
        Stats memory warm;
        for (uint256 f; f < files.length; ++f) {
            (Vector[] memory vs, uint256 count) = _hashVectors(files[f]);
            for (uint256 i; i < count; ++i) {
                vm.cool(address(v));
                (bool ok, uint256 c) = probe.verify(v, vs[i].pk, vs[i].message, vs[i].sig);
                assertTrue(ok, vs[i].reason);
                (bool okWarm, uint256 w) = probe.verifyWarm(v, vs[i].pk, vs[i].message, vs[i].sig);
                assertTrue(okWarm);
                console.log("  %s: cold %d, warm %d", vs[i].reason, c, w);
                _add(cold, c);
                _add(warm, w);
            }
        }
        console.log(name, cold.n, "signatures over 32-byte hashes");
        console.log("  cold: min %d, mean %d, max %d", cold.min, cold.sum / cold.n, cold.max);
        console.log("  warm: min %d, mean %d, max %d", warm.min, warm.sum / warm.n, warm.max);
    }

    function test_gas_verify128s() public {
        _measure(
            v128s, "SLH-DSA-SHA2-128s,", ["fixtures/noble-sha2-128s-gas.json", "fixtures/rustcrypto-sha2-128s.json"]
        );
    }

    function test_gas_verifyDRAFT() public {
        _measure(
            vDraft,
            "SLH-DSA-SHA2-128-24 (DRAFT),",
            ["fixtures/draft-sha2-128-24.json", "fixtures/sphincs-minus-sha2-128-24.json"]
        );
    }

    /// A minimal owner's isValidSignature, owner and verifier cold, as the validator's ERC-1271 figure is measured
    /// (decisions.md: 69,052 gas for the validator's 1-of-1 check with leanSphincs-keccak)
    function test_gas_erc1271() public {
        string[2] memory sets = ["fixtures/noble-sha2-128s-gas.json", "fixtures/draft-sha2-128-24.json"];
        ISlhDsaVerifier[2] memory vs = [v128s, vDraft];
        for (uint256 s; s < 2; ++s) {
            (Vector[] memory hv, uint256 count) = _hashVectors(sets[s]);
            uint256 min = type(uint256).max;
            uint256 max;
            uint256 sum;
            for (uint256 i; i < count; ++i) {
                SlhDsaOwner owner = new SlhDsaOwner(address(vs[s]), bytes32(hv[i].pk));
                bytes32 hash = bytes32(hv[i].message);
                vm.cool(address(owner));
                vm.cool(address(vs[s]));
                (bytes4 r, uint256 g) = probe.erc1271(owner, hash, hv[i].sig);
                assertEq(r, bytes4(0x1626ba7e));
                assertEq(owner.isValidSignature(~hash, hv[i].sig), bytes4(0xffffffff));
                if (g < min) min = g;
                if (g > max) max = g;
                sum += g;
            }
            console.log(s == 0 ? "ERC-1271, SLH-DSA-SHA2-128s owner" : "ERC-1271, SLH-DSA-SHA2-128-24 (DRAFT) owner");
            console.log("  owner and verifier cold: min %d, mean %d, max %d", min, sum / count, max);
            console.log("  signature bytes %d, signatures %d", hv[0].sig.length, count);
        }
    }

    function test_codeSize() public {
        console.log("runtime bytes: SlhDsaSha2_128s", address(v128s).code.length);
        console.log("runtime bytes: SlhDsaSha2_128_24_DRAFT", address(vDraft).code.length);
        console.log("runtime bytes: SlhDsaOwner", address(new SlhDsaOwner(address(v128s), bytes32(0))).code.length);
    }

    /// The precompile calls are not checked for success (the verifier's header). Around the least gas a valid
    /// signature needs, every limit below it ends in a revert, never in an answer: a failed SHA-256 call leaves too
    /// little gas to reach RETURN.
    function test_outOfGasNeverAnswers() public view {
        (Vector[] memory vs,) = _hashVectors("fixtures/noble-sha2-128s-gas.json");
        Vector memory v = vs[0];
        uint256 lo = 100_000;
        uint256 hi = 2_000_000;
        assertEq(probe.verifyWithGas(v128s, hi, v.pk, v.message, v.sig), 1);
        while (lo + 1 < hi) {
            uint256 mid = (lo + hi) / 2;
            if (probe.verifyWithGas(v128s, mid, v.pk, v.message, v.sig) == 1) hi = mid;
            else lo = mid;
        }
        uint256 reverts;
        for (uint256 g = hi - 1500; g < hi; ++g) {
            assertEq(probe.verifyWithGas(v128s, g, v.pk, v.message, v.sig), 2);
            ++reverts;
        }
        console.log("least gas for a valid signature: %d; every one of the %d limits below it reverts", hi, reverts);
    }
}
