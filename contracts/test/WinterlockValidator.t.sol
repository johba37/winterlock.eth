// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {MiniAccount} from "./utils/Harness.sol";
import {WotsKey, WotsTree, WotsSigner, Ops} from "./utils/WotsSigner.sol";

/// End-to-end through EntryPoint v0.7: nonce binding, slots, lanes, exhaustion.
contract WinterlockValidatorTest is Test {
    EntryPoint internal ep;
    WinterlockValidator internal val;
    MiniAccount internal acct;
    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");

    uint128 internal constant SEED = 0x5eed0000000000000000000000000002;
    bytes32 internal constant SK = keccak256("winterlock.test.validator");
    uint256 internal constant H = 4; // 16 keys = 8 nonces x 2 slots

    bytes internal constant AA24 = "AA24 signature error";

    function setUp() public {
        ep = new EntryPoint();
        val = new WinterlockValidator();
        WotsKey memory key = WotsTree.create(SEED, SK, H, H);
        acct = new MiniAccount{value: 10 ether}(ep, val, abi.encode(key.root, SEED, uint8(H), uint192(0)));
    }

    function _key() internal pure returns (WotsKey memory) {
        return WotsTree.create(SEED, SK, H, H);
    }

    function _op(uint256 nonce, uint256 value) internal view returns (PackedUserOperation memory) {
        return Ops.build(address(acct), nonce, abi.encodeCall(MiniAccount.execute, (recipient, value, "")), 400_000);
    }

    function _signed(uint256 nonce, uint256 slot, uint256 value) internal view returns (PackedUserOperation memory op) {
        op = _op(nonce, value);
        uint256 keyIndex = uint256(uint64(nonce)) * 2 + slot;
        op.signature = Ops.wotsSignature(_key(), slot, keyIndex, ep.getUserOpHash(op));
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
        assertTrue(val.isInitialized(address(acct)));
        assertTrue(val.isModuleType(1));
        assertEq(val.config(address(acct)).height, H);
    }

    function test_executesTransfersAcrossNonces() public {
        for (uint256 n; n < 4; ++n) {
            _send(_signed(n, 0, 1 ether));
        }
        assertEq(recipient.balance, 4 ether);
        assertEq(ep.getNonce(address(acct), 0), 4);
    }

    function test_slot1ReplacesAtSameNonce() public {
        _send(_signed(0, 1, 2 ether));
        assertEq(recipient.balance, 2 ether);
    }

    function test_rejectsKeyOfAnotherNonce() public {
        // The signature from nonce 1's key (index 2), submitted at nonce 0, claiming slot 0.
        PackedUserOperation memory op = _op(0, 1 ether);
        WotsKey memory key = _key();
        bytes32 h = ep.getUserOpHash(op);
        op.signature = abi.encodePacked(uint8(0), WotsSigner.sign(SEED, SK, 2, h), WotsTree.path(key, 2));
        _expectFail(AA24);
        _send(op);
    }

    function test_rejectsSlotOutOfRange() public {
        PackedUserOperation memory op = _signed(0, 1, 1 ether);
        op.signature[0] = bytes1(uint8(2));
        _expectFail(AA24);
        _send(op);
    }

    function test_rejectsOtherNonceLane() public {
        PackedUserOperation memory op = _op((uint256(1) << 64) | 0, 1 ether);
        op.signature = Ops.wotsSignature(_key(), 0, 0, ep.getUserOpHash(op));
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
        assembly {
            mstore(s, sub(mload(s), 32))
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
        // height 1: two keys, i.e. exactly one nonce
        WotsKey memory small = WotsTree.create(SEED, SK, 1, 1);
        MiniAccount tiny = new MiniAccount{value: 1 ether}(ep, val, abi.encode(small.root, SEED, uint8(1), uint192(0)));
        PackedUserOperation memory op =
            Ops.build(address(tiny), 0, abi.encodeCall(MiniAccount.execute, (recipient, 1, "")), 400_000);
        op.signature = Ops.wotsSignature(small, 0, 0, ep.getUserOpHash(op));
        _send(op);

        op = Ops.build(address(tiny), 1, abi.encodeCall(MiniAccount.execute, (recipient, 1, "")), 400_000);
        op.signature = abi.encodePacked(uint8(0), new bytes(2144), new bytes(32));
        _expectFail(AA24);
        _send(op);
    }
}
