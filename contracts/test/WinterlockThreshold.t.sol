// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {MiniAccount, ValidationProbe} from "./utils/Harness.sol";
import {WotsParams, WotsKey, MemberKeys, Ops} from "./utils/WotsSigner.sol";

/// Threshold mode through EntryPoint v0.7, parameter set D6 (24-byte hashes, target sum 431).
/// A team account with members A, B, C and threshold 2; each member has their own key tree.
contract WinterlockThresholdTest is Test {
    EntryPoint internal ep;
    WinterlockValidator internal val;
    MiniAccount internal team;
    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");

    uint256 internal constant H = 4;
    uint256 internal constant K = 3; // real leaves for nonces 0..3

    bytes internal constant AA24 = "AA24 signature error";

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    /// Member i's keys for the team account (A = 0, B = 1, C = 2, ...)
    function _member(uint256 i) internal pure returns (MemberKeys memory) {
        return Ops.keys(_p(), string(abi.encode("team member", i)), H, K);
    }

    /// The first `count` members' master trees, for install data
    function _members(uint256 count) internal pure returns (WotsKey[] memory masters) {
        masters = new WotsKey[](count);
        for (uint256 i; i < count; ++i) {
            masters[i] = _member(i).master;
        }
    }

    function setUp() public {
        ep = new EntryPoint();
        val = new WinterlockValidator(Ops.params(_p()));
        team = new MiniAccount{value: 10 ether}(ep, val, Ops.installData(_members(3), 2));
    }

    function _op(address account, uint256 nonce) internal view returns (PackedUserOperation memory) {
        return Ops.build(account, nonce, abi.encodeCall(MiniAccount.execute, (recipient, 1 ether, "")), 800_000);
    }

    /// Entry for member i, signing at the op's nonce with the given slot (with a certificate on first use)
    function _entry(PackedUserOperation memory op, uint256 i, uint256 slot) internal view returns (bytes memory) {
        return Ops.memberSignature(val, op.sender, _member(i), i, slot, uint64(op.nonce), ep.getUserOpHash(op));
    }

    function _send(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(bundler, bundler);
        ep.handleOps(ops, bundler);
    }

    function _expectFail() internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, AA24));
    }

    // --- configuration ---

    function test_install() public view {
        (uint192 lane, uint8 threshold, uint8 count) = val.settings(address(team));
        assertEq(lane, 0);
        assertEq(threshold, 2);
        assertEq(count, 3);
        for (uint256 i; i < 3; ++i) {
            WotsKey memory m = _member(i).master;
            assertEq(val.member(address(team), i), val.masterCommitment(m.root, m.seed, uint8(m.height)));
        }
    }

    function test_installRejectsBadConfigs() public {
        WotsKey[] memory keys = _members(2);
        address acct = makeAddr("fresh account");
        vm.startPrank(acct);

        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(keys, 0)); // threshold 0

        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(keys, 3)); // threshold above member count

        keys[1] = keys[0];
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(keys, 1)); // same tree twice

        WinterlockValidator.Member[] memory many = new WinterlockValidator.Member[](17);
        for (uint256 i; i < 17; ++i) {
            many[i] = WinterlockValidator.Member(bytes32(i + 1), 1, 4);
        }
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(abi.encode(uint192(0), uint8(1), many)); // more than MAX_MEMBERS

        val.onInstall(Ops.installData(_members(2), 2));
        vm.expectRevert(WinterlockValidator.AlreadyInitialized.selector);
        val.onInstall(Ops.installData(_members(2), 2));
        vm.stopPrank();
    }

    // --- valid quorums ---

    function test_anyTwoOfThree() public {
        uint256[2][3] memory pairs = [[uint256(0), 1], [uint256(0), 2], [uint256(1), 2]];
        for (uint256 n; n < 3; ++n) {
            PackedUserOperation memory op = _op(address(team), n);
            op.signature = bytes.concat(_entry(op, pairs[n][0], 0), _entry(op, pairs[n][1], 0));
            _send(op);
        }
        assertEq(recipient.balance, 3 ether);
    }

    function test_allThreeAccepted() public {
        PackedUserOperation memory op = _op(address(team), 0);
        op.signature = bytes.concat(_entry(op, 0, 0), _entry(op, 1, 0), _entry(op, 2, 0));
        _send(op);
        assertEq(recipient.balance, 1 ether);
    }

    /// A signed a proposal at nonce 0 that was abandoned; A uses slot 1 for the replacement, B slot 0.
    function test_membersChooseSlotsIndependently() public {
        PackedUserOperation memory op = _op(address(team), 0);
        op.signature = bytes.concat(_entry(op, 0, 1), _entry(op, 1, 0));
        _send(op);
        assertEq(recipient.balance, 1 ether);
    }

    // --- invalid quorums ---

    function test_oneSignatureNotEnough() public {
        PackedUserOperation memory op = _op(address(team), 0);
        op.signature = _entry(op, 1, 0);
        _expectFail();
        _send(op);
    }

    function test_sameMemberTwiceRejected() public {
        PackedUserOperation memory op = _op(address(team), 0);
        op.signature = bytes.concat(_entry(op, 0, 0), _entry(op, 0, 1));
        _expectFail();
        _send(op);
    }

    function test_wrongOrderRejected() public {
        PackedUserOperation memory op = _op(address(team), 0);
        op.signature = bytes.concat(_entry(op, 1, 0), _entry(op, 0, 0));
        _expectFail();
        _send(op);
    }

    function test_unknownMemberRejected() public {
        PackedUserOperation memory op = _op(address(team), 0);
        bytes memory ghost = _entry(op, 0, 0);
        ghost[0] = bytes1(uint8(3)); // index 3 does not exist
        op.signature = bytes.concat(_entry(op, 0, 0), ghost);
        _expectFail();
        _send(op);
    }

    /// B's valid signature presented as C's entry: checked against C's root, so it fails.
    function test_signatureUnderWrongMemberRejected() public {
        PackedUserOperation memory op = _op(address(team), 0);
        bytes memory bAsC = _entry(op, 1, 0);
        bAsC[0] = bytes1(uint8(2));
        op.signature = bytes.concat(_entry(op, 0, 0), bAsC);
        _expectFail();
        _send(op);
    }

    function test_trailingBytesRejected() public {
        PackedUserOperation memory op = _op(address(team), 0);
        op.signature = bytes.concat(_entry(op, 0, 0), _entry(op, 1, 0), hex"00");
        _expectFail();
        _send(op);
    }

    // --- gas estimation ---

    /// Wallets estimate gas with a dummy signature of the right shape (member indices, flags, lengths). Every
    /// entry is verified even after one fails, so the dummy costs at least as much as the real signature.
    /// Measured on the steady state: the first call enrols both members' operation trees.
    function test_gas_dummySignatureCoversRealOne() public {
        ValidationProbe probe = new ValidationProbe();
        probe.install(val, Ops.installData(_members(3), 2)); // the probe is an account with the team's config
        PackedUserOperation memory op = _op(address(probe), 0);
        bytes32 h = ep.getUserOpHash(op);
        uint256 result;
        (result,) = _validate(probe, op, bytes.concat(_entry(op, 0, 0), _entry(op, 1, 0)), h); // enrols, warms up
        assertEq(result, 0);
        bytes memory real = bytes.concat(_entry(op, 0, 0), _entry(op, 1, 0)); // no certificates any more
        uint256 half = real.length / 2;

        uint256 realGas;
        uint256 dummyGas;
        uint256 firstBadGas;
        (result, realGas) = _validate(probe, op, real, h);
        assertEq(result, 0);

        // Both entries garbage
        (result, dummyGas) = _validate(probe, op, _garble(_garble(real, 2, half), half + 2, real.length), h);
        assertEq(result, 1);
        assertGe(dummyGas, realGas);
        assertLe(dummyGas, realGas + 2 * 80 * 48); // the digit replacement, once per entry (WotsVerifier test)

        // A's entry garbage, B's valid: still fails, and B's entry is still verified
        (result, firstBadGas) = _validate(probe, op, _garble(real, 2, half), h);
        assertEq(result, 1);
        assertGe(firstBadGas, realGas);
        assertLe(firstBadGas, realGas + 80 * 48);
        console.log("2-of-3 validation gas: real", realGas, ", dummy", dummyGas);
    }

    function _garble(bytes memory sig, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = bytes.concat(sig);
        for (uint256 i = from; i < to; ++i) {
            out[i] = 0xab;
        }
    }

    function _validate(ValidationProbe probe, PackedUserOperation memory op, bytes memory sig, bytes32 h)
        internal
        returns (uint256, uint256)
    {
        op.signature = sig;
        return probe.measure(val, op, h);
    }

    // --- private wallet and team account side by side ---

    /// A's private account (1-of-1) and the team account (2-of-3) share the validator contract but
    /// not their rules or keys. A's private tree is a different tree from A's team tree.
    function test_privateAndTeamAccountsAreIsolated() public {
        MemberKeys memory aPrivate = Ops.keys(_p(), "A private", H, K);
        MiniAccount mine = new MiniAccount{value: 10 ether}(ep, val, Ops.installData(aPrivate.master));

        // A alone controls the private account.
        PackedUserOperation memory op = _op(address(mine), 0);
        op.signature = Ops.wotsSignature(val, aPrivate, 0, op, ep.getUserOpHash(op));
        _send(op);
        assertEq(recipient.balance, 1 ether);

        // A's private-tree signature counts for nothing in the team account, even with B's.
        op = _op(address(team), 0);
        op.signature = bytes.concat(
            Ops.memberSignature(val, address(team), aPrivate, 0, 0, 0, ep.getUserOpHash(op)), _entry(op, 1, 0)
        );
        _expectFail();
        _send(op);

        // A's team-tree signature plus B's does.
        op.signature = bytes.concat(_entry(op, 0, 0), _entry(op, 1, 0));
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }

    // --- random quorums ---

    /// 2-of-4 with a random set of signers: valid exactly when at least two distinct members sign.
    /// forge-config: default.fuzz.runs = 32
    function testFuzz_randomSignerSets(uint8 mask) public {
        mask &= 0x0f;
        MemberKeys[] memory keys = new MemberKeys[](4);
        for (uint256 i; i < 4; ++i) {
            keys[i] = Ops.keys(_p(), string(abi.encode("fuzz member", i)), H, 0);
        }
        MiniAccount acct = new MiniAccount{value: 2 ether}(ep, val, Ops.installData(Ops.masters(keys), 2)); // transfer + gas
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes32 h = ep.getUserOpHash(op);
        uint256 signers;
        for (uint256 i; i < 4; ++i) {
            if (mask & (1 << i) != 0) {
                op.signature = bytes.concat(op.signature, Ops.memberSignature(val, address(acct), keys[i], i, 0, 0, h));
                ++signers;
            }
        }
        if (signers < 2) _expectFail();
        _send(op);
        if (signers >= 2) assertEq(recipient.balance, 1 ether);
    }
}
