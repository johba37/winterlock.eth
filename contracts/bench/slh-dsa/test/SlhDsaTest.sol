// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ISlhDsaVerifier} from "../src/ISlhDsaVerifier.sol";

/// Known answers from fixtures/*.json against a verifier, and every way a valid signature must stop verifying.
abstract contract SlhDsaTest is Test {
    struct Vector {
        string source;
        bool internalInterface; // ACVP's internal interface: `message` is M' itself
        bytes pk;
        bytes message;
        bytes ctx;
        bytes sig;
        bool valid;
        string reason;
    }

    /// Where each part of a signature sits (FIPS 205 section 9)
    struct Layout {
        uint256 k;
        uint256 a;
        uint256 d;
        uint256 hp;
        uint256 len;
    }

    ISlhDsaVerifier internal verifier;
    Layout internal layout;

    function _key(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "].", field);
    }

    function _load(string memory path) internal view returns (Vector[] memory vs) {
        string memory json = vm.readFile(path);
        uint256 n;
        while (vm.keyExistsJson(json, string.concat(".vectors[", vm.toString(n), "]"))) ++n;
        vs = new Vector[](n);
        for (uint256 i; i < n; ++i) {
            vs[i].source = vm.parseJsonString(json, _key(i, "source"));
            vs[i].internalInterface = vm.parseJsonBool(json, _key(i, "internal"));
            vs[i].pk = vm.parseJsonBytes(json, _key(i, "pk"));
            vs[i].message = vm.parseJsonBytes(json, _key(i, "message"));
            vs[i].ctx = vm.parseJsonBytes(json, _key(i, "context"));
            vs[i].sig = vm.parseJsonBytes(json, _key(i, "signature"));
            vs[i].valid = vm.parseJsonBool(json, _key(i, "valid"));
            vs[i].reason = vm.parseJsonString(json, _key(i, "reason"));
        }
    }

    function _verify(Vector memory v, bytes memory pk, bytes memory message, bytes memory ctx, bytes memory sig)
        internal
        view
        returns (bool)
    {
        if (v.internalInterface) return verifier.verifyInternal(pk, message, sig);
        if (ctx.length == 0) return verifier.verify(pk, message, sig);
        return verifier.verifyWithContext(pk, ctx, message, sig);
    }

    /// Every vector's verdict; the three entry points agree. Returns the number of valid and invalid vectors.
    function _checkVerdicts(Vector[] memory vs) internal view returns (uint256 valid, uint256 invalid) {
        for (uint256 i; i < vs.length; ++i) {
            Vector memory v = vs[i];
            string memory what = string.concat(v.source, ": ", v.reason);
            assertEq(_verify(v, v.pk, v.message, v.ctx, v.sig), v.valid, what);
            if (!v.internalInterface) {
                bytes memory mPrime = bytes.concat(bytes1(0), bytes1(uint8(v.ctx.length)), v.ctx, v.message);
                assertEq(verifier.verifyInternal(v.pk, mPrime, v.sig), v.valid, string.concat(what, " (internal)"));
                assertEq(verifier.verifyWithContext(v.pk, v.ctx, v.message, v.sig), v.valid, what);
                if (v.ctx.length == 0) assertEq(verifier.verify(v.pk, v.message, v.sig), v.valid, what);
            }
            if (v.valid) ++valid;
            else ++invalid;
        }
    }

    function _flipped(bytes memory b, uint256 at, uint8 mask) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        c[at] ^= bytes1(mask);
    }

    function _rejects(Vector memory v, bytes memory pk, bytes memory message, bytes memory ctx, bytes memory sig)
        internal
        view
        returns (uint256)
    {
        assertFalse(_verify(v, pk, message, ctx, sig), v.source);
        return 1;
    }

    /// A valid signature with one bit flipped in R, in every FORS tree's secret and in one of its authentication
    /// nodes, in every hypertree layer's WOTS+ signature and in one of its authentication nodes; and the message,
    /// context and key changed. Returns the number of rejected variants.
    function _mutations(Vector memory v) internal view returns (uint256 rejected) {
        assertTrue(v.valid);
        Layout memory l = layout;
        uint256 n = 16;
        bytes memory sig = v.sig;
        // R
        rejected += _rejects(v, v.pk, v.message, v.ctx, _flipped(sig, 0, 0x80));
        rejected += _rejects(v, v.pk, v.message, v.ctx, _flipped(sig, n - 1, 0x01));
        // SIG_FORS: tree i's secret, and its authentication node at level i mod a
        for (uint256 i; i < l.k; ++i) {
            uint256 tree = n + i * (l.a + 1) * n;
            rejected += _rejects(v, v.pk, v.message, v.ctx, _flipped(sig, tree + (i % n), uint8(1 << (i % 8))));
            uint256 auth = tree + (1 + (i % l.a)) * n;
            rejected += _rejects(v, v.pk, v.message, v.ctx, _flipped(sig, auth + n - 1 - (i % n), 0x40));
        }
        // SIG_HT: layer j's WOTS+ signature (chain j mod len) and its authentication node at level j mod h'
        uint256 ht = n + l.k * (l.a + 1) * n;
        for (uint256 j; j < l.d; ++j) {
            uint256 layer = ht + j * (l.len + l.hp) * n;
            uint256 chainAt = layer + ((7 * j + 3) % l.len) * n;
            rejected += _rejects(v, v.pk, v.message, v.ctx, _flipped(sig, chainAt + (j % n), 0x01));
            uint256 auth = layer + (l.len + (j % l.hp)) * n;
            rejected += _rejects(v, v.pk, v.message, v.ctx, _flipped(sig, auth + (j % n), 0x02));
        }
        // the last byte: the top layer's last authentication node
        rejected += _rejects(v, v.pk, v.message, v.ctx, _flipped(sig, sig.length - 1, 0x01));
        // the message
        rejected += _rejects(v, v.pk, bytes.concat(v.message, bytes1(0)), v.ctx, sig);
        if (v.message.length > 0) {
            rejected += _rejects(v, v.pk, _flipped(v.message, v.message.length - 1, 0x01), v.ctx, sig);
        }
        // the key: PK.seed, PK.root
        rejected += _rejects(v, _flipped(v.pk, 0, 0x01), v.message, v.ctx, sig);
        rejected += _rejects(v, _flipped(v.pk, 31, 0x80), v.message, v.ctx, sig);
        if (!v.internalInterface) {
            // the context: another one, one byte longer, or none
            rejected += _rejects(v, v.pk, v.message, bytes.concat(v.ctx, bytes1(0x00)), sig);
            if (v.ctx.length > 0) {
                rejected += _rejects(v, v.pk, v.message, _flipped(v.ctx, 0, 0x01), sig);
                assertFalse(verifier.verify(v.pk, v.message, sig), "without the context");
                ++rejected;
            } else {
                assertFalse(verifier.verifyWithContext(v.pk, "ctx", v.message, sig), "with a context");
                ++rejected;
            }
            // pure SLH-DSA's M' is not the message itself
            assertFalse(verifier.verifyInternal(v.pk, v.message, sig), "internal on M");
            ++rejected;
        }
    }

    /// Wrong lengths and oversized contexts are false, not reverts.
    function _malformed(Vector memory v, Vector memory other) internal view returns (uint256 rejected) {
        bytes memory sig = v.sig;
        bytes memory shorter = new bytes(sig.length - 1);
        for (uint256 i; i < shorter.length; ++i) {
            shorter[i] = sig[i];
        }
        rejected += _rejects(v, v.pk, v.message, v.ctx, shorter);
        rejected += _rejects(v, v.pk, v.message, v.ctx, bytes.concat(sig, bytes1(0)));
        rejected += _rejects(v, v.pk, v.message, v.ctx, "");
        rejected += _rejects(v, bytes.concat(v.pk, bytes1(0)), v.message, v.ctx, sig);
        rejected += _rejects(v, "", v.message, v.ctx, sig);
        bytes memory pk31 = new bytes(31);
        for (uint256 i; i < 31; ++i) {
            pk31[i] = v.pk[i];
        }
        rejected += _rejects(v, pk31, v.message, v.ctx, sig);
        // another key, and another key's signature
        rejected += _rejects(v, other.pk, v.message, v.ctx, sig);
        rejected += _rejects(v, v.pk, v.message, v.ctx, other.sig);
        // a context of 256 bytes
        assertFalse(verifier.verifyWithContext(v.pk, new bytes(256), v.message, sig), "context of 256 bytes");
        ++rejected;
    }
}
