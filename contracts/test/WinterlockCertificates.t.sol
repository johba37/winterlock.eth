// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {MiniAccount, ValidationProbe} from "./utils/Harness.sol";
import {WotsParams, MemberKeys, Ops} from "./utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";

/// D10 and D12: each member's stateless key (leanSphincs), which is all its install data holds, certifies an operation
/// tree per chain. The first operation on a chain carries the certificate; later certificates rotate the tree.
/// Parameter set D6, through EntryPoint v0.7.
contract WinterlockCertificatesTest is Test {
    EntryPoint internal ep;
    WinterlockValidator internal val;
    MiniAccount internal acct;
    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");
    StatelessKey internal sk; // the member's stateless key, kept: its keygen is costly

    uint256 internal constant H = 3; // operation trees: 8 keys = 4 nonces x 2 slots
    /// [root: 32][height: 1][start: 8][stateless signature: 5,684]
    uint256 internal constant CERTIFICATE_BYTES = 32 + 1 + 8 + 5684;
    /// D6 WOTS signature
    uint256 internal constant WOTS_BYTES = 1176;
    string internal constant LABEL = "winterlock.test.certificates";
    bytes internal constant AA24 = "AA24 signature error";

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        ep = new EntryPoint();
        val = new WinterlockValidator(Ops.params(_p()), Ops.deployStatelessVerifier());
        sk = StatelessSigner.testKey(LABEL);
        acct = new MiniAccount{value: 10 ether}(ep, val, Ops.installData(_keys()));
    }

    /// The member's keys: its stateless key, and operation tree 0 from sequence 0
    function _keys() internal view returns (MemberKeys memory) {
        return Ops.keys(_p(), LABEL, H, H, sk);
    }

    /// The member's operation tree certified from `start`, built for the account
    function _from(uint64 start) internal view returns (MemberKeys memory) {
        return Ops.forAccount(val, address(acct), 0, Ops.startingAt(_keys(), start));
    }

    function _op(address account, uint256 nonce) internal view returns (PackedUserOperation memory) {
        return Ops.build(account, nonce, abi.encodeCall(MiniAccount.execute, (recipient, 1 ether, "")), 900_000);
    }

    /// Signed by k, with a certificate whenever the validator doesn't have k's operation tree
    function _signed(MemberKeys memory k, uint256 nonce) internal view returns (PackedUserOperation memory op) {
        op = _op(address(acct), nonce);
        op.signature = Ops.wotsSignature(val, k, 0, op, ep.getUserOpHash(op));
    }

    /// An entry for k at `nonce` with a given certificate (none if empty)
    function _withCertificate(MemberKeys memory k, uint256 nonce, bytes memory cert)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(address(acct), nonce);
        k = Ops.forAccount(val, address(acct), 0, k);
        op.signature = Ops.entry(k, 0, 0, nonce, cert, ep.getUserOpHash(op));
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

    // --- install data and storage ---

    /// The install data is the members' stateless public keys and nothing chain-specific, so it is the same on every
    /// chain. A member's slot holds its key itself.
    function test_installStoresStatelessKey() public view {
        bytes32 pub = StatelessSigner.publicKey(sk);
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = pub;
        assertEq(Ops.installData(_keys()), abi.encode(uint192(0), uint8(1), keys));
        assertEq(val.member(address(acct), 0), pub);
        uint256 base = uint256(keccak256(abi.encode(address(acct), uint256(0)))); // _config is slot 0
        assertEq(vm.load(address(val), bytes32(base + 1)), pub, "members[0]: the key itself");
        assertEq(vm.load(address(val), bytes32(base + 2)), bytes32(0), "one slot per member");
    }

    function test_installRejectsBadStatelessKeys() public {
        bytes32 pub = StatelessSigner.publicKey(sk);
        bytes32[] memory keys = new bytes32[](2);
        keys[0] = pub;
        vm.startPrank(makeAddr("fresh account"));

        keys[1] = pub; // one key for two members: one key, two votes
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(keys, 1));

        keys[1] = pub & bytes32(StatelessSigner.HIGH); // no public parameter
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(keys, 1));

        keys[1] = pub >> 128; // no root
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(keys, 1));

        keys[1] = keccak256("another member's key");
        val.onInstall(Ops.installData(keys, 1));
        vm.stopPrank();
    }

    /// One slot per tree (D6): the root in the high bytes, then start (40 bits) and height (8 bits).
    function test_storagePacking() public {
        MemberKeys memory k = _from(5);
        PackedUserOperation memory op = _op(address(acct), 5);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.wotsSignature(val, k, 0, op, h);
        vm.prank(address(acct)); // a direct call: the EntryPoint would want nonce 0 first
        assertEq(val.validateUserOp(op, h), 0);

        uint256 base = uint256(keccak256(abi.encode(address(acct), uint256(0))));
        uint256 word = uint256(vm.load(address(val), bytes32(base + 17))); // trees[0][0]
        assertEq(bytes32(word & ~uint256(type(uint64).max)), k.ops.root);
        assertEq(word & type(uint64).max, (uint256(5) << 8) | H);
        assertEq(vm.load(address(val), bytes32(base + 18)), bytes32(0), "one slot per tree");
    }

    // --- enrolment ---

    function test_firstOperationEnrolsTree() public {
        MemberKeys memory k = _from(0);
        PackedUserOperation memory op = _signed(k, 0);
        assertEq(uint8(op.signature[1]), 0x80, "first operation carries a certificate");
        assertEq(op.signature.length, 2 + CERTIFICATE_BYTES + WOTS_BYTES + 24 * H);
        _send(op);

        WinterlockValidator.Tree memory t = val.tree(address(acct), 0);
        assertEq(t.root, k.ops.root);
        assertEq(t.height, H);
        assertEq(t.start, 0);
        // the tree's public seed is derived from the chain, the validator, the account, the member and the start
        assertEq(t.seed, k.ops.seed);
        bytes32 seedHash = keccak256(
            abi.encode(
                keccak256("Winterlock.stateless-tree-seed.v1"),
                block.chainid,
                address(val),
                address(acct),
                uint256(0),
                uint64(0)
            )
        );
        assertEq(t.seed, uint128(bytes16(seedHash)));

        op = _signed(k, 1);
        assertEq(uint8(op.signature[1]), 0, "later operations don't");
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }

    function test_operationWithoutTreeRejected() public {
        PackedUserOperation memory op = _op(address(acct), 0);
        op.signature = Ops.entry(_from(0), 0, 0, 0, "", ep.getUserOpHash(op));
        _expectFail();
        _send(op);
    }

    // --- bindings: chain, validator, account, member, key ---

    /// The digest binds the chain: the same tree, certified for Arbitrum, is refused here.
    function test_certificateFromAnotherChainRejected() public {
        MemberKeys memory k = _from(0);
        uint256 here = block.chainid;
        vm.chainId(42161);
        bytes32 digest = val.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        vm.chainId(here);
        PackedUserOperation memory op = _withCertificate(k, 0, Ops.certificateFor(k, digest));
        _expectFail();
        _send(op);
        _send(_signed(k, 0)); // control: the same tree certified for this chain
    }

    /// The digest binds the account: the same tree, certified for another account with the same key, is refused.
    function test_certificateForAnotherAccountRejected() public {
        MiniAccount twin = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(_keys()));
        MemberKeys memory k = _from(0);
        bytes32 digest = val.statelessCertificateDigest(address(twin), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _withCertificate(k, 0, Ops.certificateFor(k, digest));
        _expectFail();
        _send(op);
    }

    /// A certificate for another validator (same key, same account address) is refused: the digest binds it.
    function test_certificateForAnotherValidatorRejected() public {
        WinterlockValidator other = new WinterlockValidator(Ops.params(_p()), val.STATELESS_VERIFIER());
        MemberKeys memory k = _from(0);
        bytes32 digest = other.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _withCertificate(k, 0, Ops.certificateFor(k, digest));
        _expectFail();
        _send(op);
    }

    /// In a team, one member's key can't enrol a tree for another: the validator checks a certificate against the
    /// key stored for the member the entry names, and the digest names the member.
    function test_certificateForAnotherMemberRejected() public {
        MemberKeys[] memory ks = new MemberKeys[](2);
        ks[0] = _keys();
        ks[1] = Ops.keys(_p(), "second member", H, H);
        MiniAccount team = new MiniAccount{value: 2 ether}(ep, val, Ops.installData(ks, 1));
        PackedUserOperation memory op = _op(address(team), 0);
        bytes32 h = ep.getUserOpHash(op);

        // member 0's key certifies a tree for member 1
        MemberKeys memory k = Ops.forAccount(val, address(team), 1, ks[0]);
        bytes32 digest = val.statelessCertificateDigest(address(team), 1, k.ops.root, uint8(H), 0);
        op.signature = Ops.entry(k, 1, 0, 0, Ops.certificateFor(k, digest), h);
        _expectFail();
        _send(op);

        // member 1's own key, but over a digest that names member 0
        k = Ops.forAccount(val, address(team), 1, ks[1]);
        digest = val.statelessCertificateDigest(address(team), 0, k.ops.root, uint8(H), 0);
        op.signature = Ops.entry(k, 1, 0, 0, Ops.certificateFor(k, digest), h);
        _expectFail();
        _send(op);

        op.signature = Ops.memberSignature(val, address(team), ks[1], 1, 0, 0, h); // control: its own certificate
        _send(op);
    }

    /// Someone else's stateless key signs the certificate: refused, the validator checks the member's stored key.
    function test_foreignStatelessKeyRejected() public {
        StatelessKey memory mallory = StatelessSigner.testKey("mallory");
        MemberKeys memory k = _from(0);
        bytes32 digest = val.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _withCertificate(k, 0, Ops.certificateFor(k.ops, 0, mallory, digest));
        _expectFail();
        _send(op);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));
    }

    // --- certificate fields ---

    function test_startAfterSequenceRejected() public {
        // certifies a tree from sequence 1 on, used at 0 (no key exists for it, so the signature is filler)
        MemberKeys memory k = _from(1);
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes memory cert = Ops.certificate(val, address(acct), 0, k);
        op.signature = abi.encodePacked(uint8(0), uint8(0x80), cert, new bytes(WOTS_BYTES + 24 * H));
        _expectFail();
        _send(op);
    }

    /// Start sequences beyond 40 bits don't fit the packed tree; the largest one that fits is accepted.
    function test_startBeyond40BitsRejected() public {
        for (uint256 i; i < 2; ++i) {
            uint64 start = uint64(val.MAX_START() + 1 - i);
            MemberKeys memory k = _from(start);
            PackedUserOperation memory op = _op(address(acct), start);
            bytes32 h = ep.getUserOpHash(op);
            op.signature = Ops.entry(k, 0, 0, start, Ops.certificate(val, address(acct), 0, k), h);
            vm.prank(address(acct)); // a direct call: the EntryPoint wouldn't accept this nonce yet
            assertEq(val.validateUserOp(op, h), 1 - i);
            assertEq(val.tree(address(acct), 0).root, i == 0 ? bytes32(0) : k.ops.root);
        }
        assertEq(val.tree(address(acct), 0).start, val.MAX_START());
    }

    /// Unknown flag bits make an entry malformed; among them bit 6, which marked a second kind of certificate
    /// before D12.
    function test_unknownFlagsRejected() public {
        PackedUserOperation memory op = _signed(_keys(), 0);
        op.signature[1] = bytes1(uint8(0xc0));
        _expectFail();
        _send(op);
        op.signature[1] = bytes1(uint8(0x40));
        _expectFail();
        _send(op);
    }

    /// The root must be high-aligned, or it would spill into the packed fields. The certificate below is properly
    /// signed by the member's key, so only the shape check keeps it out of storage.
    function test_rootWithLowBytesRejected() public {
        MemberKeys memory k = _from(0);
        k.ops.root = bytes32(uint256(k.ops.root) | (1 << 8)); // would set a start bit
        bytes32 digest = val.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(k, 0, 0, 0, Ops.certificateFor(k, digest), h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0), "not stored");
    }

    // --- rotation: start sequences only grow ---

    function test_rotationReplacesTree() public {
        for (uint256 n; n < 3; ++n) {
            _send(_signed(_keys(), n));
        }
        MemberKeys memory next = _from(3); // a fresh tree from sequence 3
        PackedUserOperation memory op = _signed(next, 3);
        assertEq(uint8(op.signature[1]), 0x80);
        _send(op);
        WinterlockValidator.Tree memory t = val.tree(address(acct), 0);
        assertEq(t.root, next.ops.root);
        assertEq(t.start, 3);

        _send(_signed(next, 4)); // key index (4 - 3) * 2 in the new tree
        assertEq(recipient.balance, 5 ether);
    }

    /// After a rotation, the old tree no longer signs, and its certificate can't bring it back: a certificate must
    /// start after the stored tree.
    function test_rollbackRejected() public {
        bytes memory first = Ops.certificate(val, address(acct), 0, _keys());
        _send(_withCertificate(_keys(), 0, first));
        _send(_signed(_from(1), 1));

        // the old tree, no certificate
        PackedUserOperation memory op = _withCertificate(_keys(), 2, "");
        _expectFail();
        _send(op);
        // the old tree with its old certificate (start 0, not after 1)
        op = _withCertificate(_keys(), 2, first);
        _expectFail();
        _send(op);
        // the stored tree certified again: start 1 is not after itself
        op = _signed(_from(1), 2);
        assertEq(uint8(op.signature[1]), 0, "stored tree: no certificate");
        op = _withCertificate(_from(1), 2, Ops.certificate(val, address(acct), 0, _from(1)));
        _expectFail();
        _send(op);
    }

    /// Start sequences must grow on each chain: a start that was skipped can't be used later, and a start can't
    /// certify a second tree.
    function test_startMustGrow() public {
        _send(_signed(_keys(), 0));
        _send(_signed(_keys(), 1));
        _send(_signed(_from(2), 2)); // from 2, skipping 1

        PackedUserOperation memory op = _signed(_from(1), 3); // the skipped start
        _expectFail();
        _send(op);
        MemberKeys memory second = Ops.startingAt(_keys(), 2);
        second.tree = 1; // another tree from start 2
        op = _signed(second, 3);
        _expectFail();
        _send(op);
        _send(_signed(_from(3), 3));
        assertEq(val.tree(address(acct), 0).start, 3);
    }

    // --- storage writes ---

    /// validateUserOp writes storage, and an account can call it outside the EntryPoint (a batch, an executor).
    /// Only a valid certificate is stored, so such a call can't install a tree the member's key didn't sign.
    function test_directCallStoresOnlyValidCertificates() public {
        MemberKeys memory k = _from(0);
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes32 h = ep.getUserOpHash(op);
        bytes memory cert = Ops.certificate(val, address(acct), 0, k);

        bytes memory forged = bytes.concat(cert);
        forged[200] ^= 0x01; // inside the stateless signature
        op.signature = Ops.entry(k, 0, 0, 0, forged, h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));

        // an attacker's tree, with zeros in place of the stateless signature (the verifier reverts on it)
        StatelessKey memory none;
        MemberKeys memory mallory = Ops.forAccount(val, address(acct), 0, Ops.keys(_p(), "mallory", H, H, none));
        bytes memory junk = abi.encodePacked(mallory.ops.root, uint8(H), uint64(0), new bytes(5684));
        op.signature = Ops.entry(mallory, 0, 0, 0, junk, h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));

        // A certificate the member's key did sign is stored: harmless, the owner certified that tree.
        op.signature = Ops.entry(k, 0, 0, 0, cert, h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 0);
        assertEq(val.tree(address(acct), 0).root, k.ops.root);
    }

    // --- gas ---

    /// Validation gas of a chain's first operation, with its certificate, against the steady state; and gas
    /// estimation: a dummy that carries the real certificate (it doesn't depend on the operation) costs at least as
    /// much as the real signature. Storage and the verifier are cold, as in a fresh transaction.
    function test_gas_certificate() public {
        ValidationProbe probe = new ValidationProbe();
        probe.install(val, Ops.installData(_keys()));
        MemberKeys memory k = Ops.forAccount(val, address(probe), 0, _keys());
        (uint256 enrolGas, uint256 dummyGas, uint256 certBytes) = _enrolAndDummyGas(probe, k);
        assertGe(dummyGas, enrolGas);
        assertLe(dummyGas, enrolGas + 80 * 48);
        uint256 steadyGas = _steadyGas(probe, k);
        console.log("validation gas: steady state", steadyGas);
        console.log("validation gas: with certificate", enrolGas, ", dummy", dummyGas);
        console.log("certificate bytes", certBytes);
    }

    /// Validation gas of the dummy (state reverted after), then of the enrolling operation (its tree stays stored)
    function _enrolAndDummyGas(ValidationProbe probe, MemberKeys memory k)
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
        (result, dummyGas) = _measure(probe, op, dummy, h);
        assertEq(result, 1);
        vm.revertToState(snap);
        (result, enrolGas) = _measure(probe, op, real, h);
        assertEq(result, 0);
    }

    /// Validation gas of the next operation once the tree is enrolled
    function _steadyGas(ValidationProbe probe, MemberKeys memory k) internal returns (uint256 steadyGas) {
        PackedUserOperation memory op = _op(address(probe), 1);
        bytes32 h = ep.getUserOpHash(op);
        uint256 result;
        (result, steadyGas) = _measure(probe, op, Ops.memberSignature(val, address(probe), k, 0, 0, 1, h), h);
        assertEq(result, 0);
    }

    function _measure(ValidationProbe probe, PackedUserOperation memory op, bytes memory sig, bytes32 h)
        internal
        returns (uint256, uint256)
    {
        op.signature = sig;
        vm.cool(address(val));
        vm.cool(address(val.STATELESS_VERIFIER()));
        return probe.measure(val, op, h);
    }
}
