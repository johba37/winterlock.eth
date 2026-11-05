// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";
import {MiniAccount, ValidationProbe} from "./utils/Harness.sol";
import {WotsParams, MemberKeys, Ops} from "./utils/WotsSigner.sol";

/// D10: master trees certify per-chain operation trees. Parameter set D6, through EntryPoint v0.7.
contract WinterlockCertificatesTest is Test {
    EntryPoint internal ep;
    WinterlockValidator internal val;
    MiniAccount internal acct;
    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");

    uint256 internal constant H = 3; // operation trees: 8 keys = 4 nonces x 2 slots
    string internal constant LABEL = "winterlock.test.certificates";

    bytes internal constant AA24 = "AA24 signature error";

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        ep = new EntryPoint();
        val = new WinterlockValidator(Ops.params(_p()));
        acct = new MiniAccount{value: 10 ether}(ep, val, Ops.installData(_keys().master));
    }

    /// Master key 0 certifies operation tree 0 from sequence 0
    function _keys() internal pure returns (MemberKeys memory) {
        return Ops.keys(_p(), LABEL, H, H);
    }

    /// The keys with their operation tree for the account built (tree seed from the validator)
    function _built() internal view returns (MemberKeys memory) {
        return Ops.forAccount(val, address(acct), 0, _keys());
    }

    /// The same member after a rotation: master key `masterIndex` certifies its tree from `start`
    function _rotated(uint256 masterIndex, uint64 start) internal view returns (MemberKeys memory k) {
        k = _keys();
        k.masterIndex = masterIndex;
        k.start = start;
        k = Ops.forAccount(val, address(acct), 0, k);
    }

    function _op(address account, uint256 nonce) internal view returns (PackedUserOperation memory) {
        return Ops.build(account, nonce, abi.encodeCall(MiniAccount.execute, (recipient, 1 ether, "")), 600_000);
    }

    /// Signed by k, with a certificate whenever the validator doesn't have k's operation tree
    function _signed(MemberKeys memory k, uint256 nonce) internal view returns (PackedUserOperation memory op) {
        op = _op(address(acct), nonce);
        op.signature = Ops.wotsSignature(val, k, 0, op, ep.getUserOpHash(op));
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

    // --- enrolment ---

    function test_firstOperationEnrolsTree() public {
        MemberKeys memory k = _built();
        PackedUserOperation memory op = _signed(k, 0);
        assertEq(uint8(op.signature[1]) & 0x80, 0x80, "first operation carries a certificate");
        _send(op);

        WinterlockValidator.Tree memory t = val.tree(address(acct), 0);
        assertEq(t.root, k.ops.root);
        assertEq(t.seed, k.ops.seed);
        assertEq(t.height, H);
        assertEq(t.start, 0);
        assertEq(t.nextMaster, 1);

        op = _signed(k, 1);
        assertEq(uint8(op.signature[1]) & 0x80, 0, "later operations don't");
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }

    function test_operationWithoutTreeRejected() public {
        PackedUserOperation memory op = _op(address(acct), 0);
        op.signature = Ops.entry(_built(), 0, 0, 0, "", ep.getUserOpHash(op));
        _expectFail();
        _send(op);
    }

    /// A certificate binds the chain id: one made for Arbitrum is worthless here.
    function test_certificateFromAnotherChainRejected() public {
        MemberKeys memory k = _keys();
        uint256 here = block.chainid;
        vm.chainId(42161);
        bytes memory cert = Ops.certificate(val, address(acct), 0, k);
        vm.chainId(here);

        PackedUserOperation memory op = _op(address(acct), 0);
        op.signature = Ops.entry(k, 0, 0, 0, cert, ep.getUserOpHash(op));
        _expectFail();
        _send(op);
    }

    /// A certificate binds the account: one made for another account with the same master tree is worthless.
    function test_certificateForAnotherAccountRejected() public {
        MemberKeys memory k = _keys();
        MiniAccount twin = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(k.master));
        bytes memory cert = Ops.certificate(val, address(twin), 0, k);

        PackedUserOperation memory op = _op(address(acct), 0);
        op.signature = Ops.entry(k, 0, 0, 0, cert, ep.getUserOpHash(op));
        _expectFail();
        _send(op);
    }

    /// A tree certified by someone else's master tree is refused, even with a matching operation signature.
    function test_foreignMasterRejected() public {
        MemberKeys memory mallory = Ops.keys(_p(), "mallory", H, H);
        PackedUserOperation memory op = _signed(mallory, 0);
        _expectFail();
        _send(op);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));
    }

    function test_startAfterSequenceRejected() public {
        // certifies the tree from sequence 1 on, used at 0 (no key exists for it, so the signature is filler)
        MemberKeys memory k = _rotated(0, 1);
        PackedUserOperation memory op = _op(address(acct), 0);
        uint256 sigBytes = WotsVerifier.sigBytes(Ops.params(_p())) + _p().n * H;
        op.signature =
            abi.encodePacked(uint8(0), uint8(0x80), Ops.certificate(val, address(acct), 0, k), new bytes(sigBytes));
        _expectFail();
        _send(op);
    }

    function test_masterIndexOutsideTreeRejected() public {
        MemberKeys memory k = _keys();
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes memory cert = Ops.certificate(val, address(acct), 0, k);
        cert[0] = 0x00;
        cert[1] = bytes1(uint8(1 << Ops.MASTER_HEIGHT)); // master index 64 in a tree of 64 keys
        op.signature = Ops.entry(k, 0, 0, 0, cert, ep.getUserOpHash(op));
        _expectFail();
        _send(op);
    }

    // --- packing ---

    /// Storage after the first operation: config, one slot for the master commitment, one for the tree (D6).
    function test_storagePacking() public {
        MemberKeys memory k = _built();
        _send(_signed(k, 0));
        uint256 base = uint256(keccak256(abi.encode(address(acct), uint256(0)))); // _config is slot 0
        bytes32 master = vm.load(address(val), bytes32(base + 1));
        assertEq(master, val.masterCommitment(k.master.root, k.master.seed, uint8(k.master.height)));
        assertEq(vm.load(address(val), bytes32(base + 2)), bytes32(0), "one slot per master");
        uint256 word = uint256(vm.load(address(val), bytes32(base + 17))); // trees[0][0]
        assertEq(bytes32(word & ~uint256(type(uint64).max)), k.ops.root);
        assertEq(word & type(uint64).max, (uint256(0) << 24) | (uint256(0) << 8) | H); // start 0, master 0, height
        assertEq(vm.load(address(val), bytes32(base + 18)), bytes32(0), "one slot per tree");
        assertEq(val.tree(address(acct), 0).seed, val.treeSeed(address(acct), 0, 0));
    }

    /// The certificate names the master seed and height; they must match the commitment.
    function test_wrongMasterSeedRejected() public {
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes memory cert = Ops.certificate(val, address(acct), 0, _keys());
        cert[43] ^= 0x01; // master seed: bytes 43..58 of the certificate
        op.signature = Ops.entry(_built(), 0, 0, 0, cert, ep.getUserOpHash(op));
        _expectFail();
        _send(op);
    }

    /// A root must be n bytes, high-aligned, or it would spill into the packed fields. The certificate below is
    /// properly signed by the master key, so only the shape check keeps it out of storage.
    function test_rootWithLowBytesRejected() public {
        MemberKeys memory k = _built();
        k.ops.root = bytes32(uint256(k.ops.root) | (1 << 8)); // would flip a master index bit
        bytes32 digest = val.certificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(k, 0, 0, 0, Ops.certificateFor(k, digest), h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0), "not stored");
    }

    /// Start sequences beyond 40 bits don't fit the packed tree.
    function test_startBeyond40BitsRejected() public {
        uint64 start = uint64(1 << 40);
        MemberKeys memory k = _keys();
        k.start = start;
        k = Ops.forAccount(val, address(acct), 0, k);
        PackedUserOperation memory op = _op(address(acct), start);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(k, 0, 0, start, Ops.certificate(val, address(acct), 0, k), h);
        vm.prank(address(acct)); // a direct call: the EntryPoint wouldn't accept this nonce yet
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));
    }

    // --- rotation ---

    function test_rotationReplacesTree() public {
        for (uint256 n; n < 3; ++n) {
            _send(_signed(_keys(), n));
        }
        MemberKeys memory next = _rotated(1, 3); // master key 1 certifies its tree from sequence 3
        PackedUserOperation memory op = _signed(next, 3);
        assertEq(uint8(op.signature[1]) & 0x80, 0x80);
        _send(op);
        WinterlockValidator.Tree memory t = val.tree(address(acct), 0);
        assertEq(t.root, next.ops.root);
        assertEq(t.start, 3);
        assertEq(t.nextMaster, 2);

        _send(_signed(next, 4)); // key index (4 - 3) * 2 in the new tree
        assertEq(recipient.balance, 5 ether);
    }

    /// After a rotation, the old tree no longer signs, and its certificate can't bring it back.
    function test_rollbackRejected() public {
        _send(_signed(_keys(), 0));
        _send(_signed(_rotated(1, 1), 1));

        PackedUserOperation memory op = _op(address(acct), 2);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(_built(), 0, 0, 2, "", h); // old tree, no certificate
        _expectFail();
        _send(op);

        // old certificate (master key 0): below nextMaster
        op.signature = Ops.entry(_built(), 0, 0, 2, Ops.certificate(val, address(acct), 0, _keys()), h);
        _expectFail();
        _send(op);
    }

    /// A master index must grow on each chain, so a skipped index can't be used later either.
    function test_masterIndexMustGrow() public {
        _send(_signed(_rotated(2, 0), 0)); // master key 2 first
        PackedUserOperation memory op = _signed(_rotated(1, 1), 1); // then 1
        _expectFail();
        _send(op);
    }

    // --- storage writes ---

    /// validateUserOp writes storage, and an account can call it outside the EntryPoint (a batch, an executor).
    /// Only a valid certificate is stored, so such a call can't install a tree the master key didn't sign.
    function test_directCallStoresOnlyValidCertificates() public {
        MemberKeys memory mallory = Ops.forAccount(val, address(acct), 0, Ops.keys(_p(), "mallory", H, H));
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(mallory, 0, 0, 0, Ops.certificateFor(mallory, bytes32(0)), h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));

        // A certificate the master key did sign is stored: harmless, the owner certified that tree.
        op.signature = Ops.wotsSignature(val, _keys(), 0, op, h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 0);
        assertEq(val.tree(address(acct), 0).root, _built().ops.root);
    }

    // --- gas ---

    /// The certificate's one-off cost, and gas estimation for an enrolling operation: a dummy that carries the
    /// real certificate (it doesn't depend on the operation) costs at least as much as the real signature.
    function test_gas_certificate() public {
        MemberKeys memory k = _keys();
        ValidationProbe probe = new ValidationProbe();
        probe.install(val, Ops.installData(k.master));
        (uint256 enrolGas, uint256 dummyGas, uint256 certBytes) = _enrolAndDummyGas(k, probe);
        assertGe(dummyGas, enrolGas);
        assertLe(dummyGas, enrolGas + 80 * 48);
        uint256 steadyGas = _steadyGas(k, probe);
        console.log("validation gas: steady state", steadyGas);
        console.log("validation gas: with certificate", enrolGas, ", dummy", dummyGas);
        console.log("certificate bytes", certBytes);
    }

    /// Validation gas of the enrolling operation and of its dummy; leaves the state as it was
    function _enrolAndDummyGas(MemberKeys memory k, ValidationProbe probe)
        internal
        returns (uint256 enrolGas, uint256 dummyGas, uint256 certBytes)
    {
        PackedUserOperation memory op = _op(address(probe), 0);
        bytes32 h = ep.getUserOpHash(op);
        bytes memory cert = Ops.certificate(val, address(probe), 0, k);
        certBytes = cert.length;
        bytes memory real = Ops.entry(k, 0, 0, 0, cert, h);
        bytes memory dummy = bytes.concat(real);
        for (uint256 i = 2 + certBytes; i < dummy.length; ++i) {
            dummy[i] = 0xab; // real certificate, garbage operation signature
        }
        uint256 snap = vm.snapshotState();
        uint256 result;
        (result, enrolGas) = _measure(probe, op, real, h);
        assertEq(result, 0);
        vm.revertToState(snap);
        (result, dummyGas) = _measure(probe, op, dummy, h);
        assertEq(result, 1);
        vm.revertToState(snap);
    }

    /// Validation gas of the next operation once the tree is enrolled
    function _steadyGas(MemberKeys memory k, ValidationProbe probe) internal returns (uint256 steadyGas) {
        PackedUserOperation memory op = _op(address(probe), 0);
        bytes32 h = ep.getUserOpHash(op);
        _measure(probe, op, Ops.wotsSignature(val, k, 0, op, h), h); // enrols
        op = _op(address(probe), 1);
        h = ep.getUserOpHash(op);
        uint256 result;
        (result, steadyGas) = _measure(probe, op, Ops.wotsSignature(val, k, 0, op, h), h);
        assertEq(result, 0);
    }

    /// Validation gas with the validator's storage cold, as at the start of a transaction
    function _measure(ValidationProbe probe, PackedUserOperation memory op, bytes memory sig, bytes32 h)
        internal
        returns (uint256, uint256)
    {
        op.signature = sig;
        vm.cool(address(val));
        return probe.measure(val, op, h);
    }
}
