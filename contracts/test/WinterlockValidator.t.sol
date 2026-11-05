// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";
import {MiniAccount} from "./utils/Harness.sol";
import {WotsParams, MemberKeys, Ops} from "./utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";

/// End-to-end through EntryPoint v0.7: nonce binding, slots, lanes, exhaustion. Runs once per parameter set.
abstract contract WinterlockValidatorTestBase is Test {
    EntryPoint internal ep;
    WinterlockValidator internal val;
    MiniAccount internal acct;
    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");
    StatelessKey internal sk; // the member's stateless key, kept: its keygen is costly

    uint256 internal constant H = 4; // operation tree: 16 keys = 8 nonces x 2 slots
    string internal constant LABEL = "winterlock.test.validator";

    bytes internal constant AA24 = "AA24 signature error";

    function _p() internal pure virtual returns (WotsParams memory);

    function setUp() public {
        WotsParams memory p = _p();
        ep = new EntryPoint();
        val = new WinterlockValidator(Ops.params(p), Ops.deployStatelessVerifier());
        sk = StatelessSigner.testKey(LABEL);
        acct = new MiniAccount{value: 10 ether}(ep, val, Ops.installData(_keys()));
    }

    /// The member's keys: its stateless key, and operation tree 0 from sequence 0, which the first operation
    /// certifies
    function _keys() internal view returns (MemberKeys memory) {
        return Ops.keys(_p(), LABEL, H, H, sk);
    }

    function _op(uint256 nonce, uint256 value) internal view returns (PackedUserOperation memory) {
        return Ops.build(address(acct), nonce, abi.encodeCall(MiniAccount.execute, (recipient, value, "")), 400_000);
    }

    function _signed(uint256 nonce, uint256 slot, uint256 value) internal view returns (PackedUserOperation memory op) {
        op = _op(nonce, value);
        op.signature = Ops.wotsSignature(val, _keys(), slot, op, ep.getUserOpHash(op));
    }

    function _send(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(bundler, bundler);
        ep.handleOps(ops, bundler);
    }

    function _expectFail(bytes memory reason) internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, reason));
    }

    function test_install() public view {
        WotsParams memory p = _p();
        assertTrue(val.isInitialized(address(acct)));
        assertTrue(val.isModuleType(1));
        assertEq(val.member(address(acct), 0), StatelessSigner.publicKey(sk), "the stateless public key");
        assertEq(val.tree(address(acct), 0).root, bytes32(0)); // enrolled by the first operation
        (, uint8 threshold, uint8 count) = val.settings(address(acct));
        assertEq(threshold, 1);
        assertEq(count, 1);
        assertEq(val.N(), p.n);
        assertEq(val.TARGET_SUM(), p.targetSum);
    }

    function test_executesTransfersAcrossNonces() public {
        for (uint256 n; n < 3; ++n) {
            _send(_signed(n, 0, 1 ether));
        }
        assertEq(recipient.balance, 3 ether);
        assertEq(ep.getNonce(address(acct), 0), 3);
    }

    function test_slot1ReplacesAtSameNonce() public {
        _send(_signed(0, 1, 2 ether));
        assertEq(recipient.balance, 2 ether);
    }

    function test_rejectsKeyOfAnotherNonce() public {
        _send(_signed(0, 0, 1 ether)); // enrols the operation tree
        // The signature from nonce 2's key (index 4), submitted at nonce 1, claiming slot 0.
        PackedUserOperation memory op = _op(1, 1 ether);
        op.signature = Ops.entry(Ops.forAccount(val, address(acct), 0, _keys()), 0, 0, 2, "", ep.getUserOpHash(op));
        _expectFail(AA24);
        _send(op);
    }

    function test_rejectsSlotOutOfRange() public {
        PackedUserOperation memory op = _signed(0, 1, 1 ether);
        op.signature[1] |= bytes1(uint8(2)); // [member][flags]...: slot 2, but bit 1 is no flag
        _expectFail(AA24);
        _send(op);
    }

    function test_rejectsOtherNonceLane() public {
        PackedUserOperation memory op = _op((uint256(1) << 64) | 0, 1 ether);
        op.signature = Ops.wotsSignature(val, _keys(), 0, op, ep.getUserOpHash(op));
        _expectFail(AA24);
        _send(op);
    }

    function test_rejectsTamperedCallData() public {
        PackedUserOperation memory op = _signed(0, 0, 1 ether);
        op.callData = abi.encodeCall(MiniAccount.execute, (recipient, 9 ether, ""));
        _expectFail(AA24);
        _send(op);
    }

    function test_rejectsTruncatedPath() public {
        PackedUserOperation memory op = _signed(0, 0, 1 ether);
        bytes memory s = op.signature;
        uint256 n = _p().n;
        assembly {
            mstore(s, sub(mload(s), n))
        }
        _expectFail(AA24);
        _send(op);
    }

    function test_replayIsRejectedByEntryPoint() public {
        PackedUserOperation memory op = _signed(0, 0, 1 ether);
        _send(op);
        _expectFail("AA25 invalid account nonce");
        _send(op);
    }

    function test_treeExhaustion() public {
        WotsParams memory p = _p();
        // operation tree of height 1: two keys, i.e. exactly one nonce
        MemberKeys memory small = Ops.keys(p, "winterlock.test.small", 1, 1, sk);
        MiniAccount tiny = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(small));
        PackedUserOperation memory op =
            Ops.build(address(tiny), 0, abi.encodeCall(MiniAccount.execute, (recipient, 1, "")), 400_000);
        op.signature = Ops.wotsSignature(val, small, 0, op, ep.getUserOpHash(op));
        _send(op);

        op = Ops.build(address(tiny), 1, abi.encodeCall(MiniAccount.execute, (recipient, 1, "")), 400_000);
        op.signature =
            abi.encodePacked(uint8(0), uint8(0), new bytes(WotsVerifier.sigBytes(Ops.params(p))), new bytes(p.n));
        _expectFail(AA24);
        _send(op);
    }
}

contract WinterlockValidator_n32_checksum is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(32, 0, 4, 0);
    }
}

contract WinterlockValidator_n32_target is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(32, 560, 4, 0);
    }
}

contract WinterlockValidator_n24_checksum is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 0, 4, 0);
    }
}

contract WinterlockValidator_n24_target is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }
}

contract WinterlockValidator_n16_checksum is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(16, 0, 4, 0);
    }
}

contract WinterlockValidator_n16_target is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(16, 300, 4, 0);
    }
}

contract WinterlockValidator_n24_w4_target is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 173, 2, 0);
    }
}

contract WinterlockValidator_n24_sha256_target is WinterlockValidatorTestBase {
    function _p() internal pure override returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 1);
    }
}
