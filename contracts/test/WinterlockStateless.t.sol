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

/// D11: each member's stateless key (leanSphincs) in the install data, certifying operation trees next to the master
/// tree (D10), and recovering a signer that lost its state. Parameter set D6, through EntryPoint v0.7.
contract WinterlockStatelessTest is Test {
    EntryPoint internal ep;
    WinterlockValidator internal val;
    MiniAccount internal acct;
    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");
    bytes32 internal statelessPub; // the member's stateless public key, cached: its keygen is costly

    uint256 internal constant H = 3; // operation trees: 8 keys = 4 nonces x 2 slots
    string internal constant LABEL = "winterlock.test.stateless";
    bytes internal constant AA24 = "AA24 signature error";

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        ep = new EntryPoint();
        val = new WinterlockValidator(Ops.params(_p()), Ops.deployStatelessVerifier());
        statelessPub = StatelessSigner.publicKey(_sk());
        acct = new MiniAccount{value: 10 ether}(ep, val, Ops.installData(_keys()));
    }

    /// The member's stateless secret key (keygen of a kept subtree of height 10)
    function _sk() internal pure returns (StatelessKey memory) {
        return StatelessSigner.testKey(LABEL);
    }

    /// The member's keys: master tree, stateless public key; operation tree certified by master key 0 from 0
    function _keys() internal view returns (MemberKeys memory k) {
        k = Ops.keys(_p(), LABEL, H, H);
        k.statelessKey = statelessPub;
    }

    /// The member's operation tree certified by the stateless key from `start`
    function _statelessKeys(uint64 start) internal view returns (MemberKeys memory) {
        return Ops.statelessTree(_keys(), start);
    }

    /// The same member with master key `masterIndex` certifying its tree from `start`
    function _masterKeys(uint256 masterIndex, uint64 start) internal view returns (MemberKeys memory k) {
        k = _keys();
        k.masterIndex = masterIndex;
        k.start = start;
    }

    function _op(address account, uint256 nonce) internal view returns (PackedUserOperation memory) {
        return Ops.build(account, nonce, abi.encodeCall(MiniAccount.execute, (recipient, 1 ether, "")), 900_000);
    }

    /// Signed by k, with a certificate (of k's kind) whenever the validator doesn't have k's operation tree
    function _signed(MemberKeys memory k, uint256 nonce) internal view returns (PackedUserOperation memory op) {
        op = _op(address(acct), nonce);
        bytes32 h = ep.getUserOpHash(op);
        k = Ops.forAccount(val, address(acct), 0, k);
        bool enrolled = val.tree(address(acct), 0).root == k.ops.root;
        op.signature = k.stateless && !enrolled
            ? Ops.statelessMemberSignature(val, address(acct), k, _sk(), 0, 0, nonce, h)
            : Ops.memberSignature(val, address(acct), k, 0, 0, nonce, h);
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

    /// An entry for `k` at `nonce` with a given certificate (its kind from k.stateless)
    function _withCertificate(MemberKeys memory k, uint256 nonce, bytes memory cert)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(address(acct), nonce);
        k = Ops.forAccount(val, address(acct), 0, k);
        op.signature = Ops.entry(k, 0, 0, nonce, cert, ep.getUserOpHash(op));
    }

    // --- install data and storage (step 2) ---

    /// One slot per member: a commitment to the master tree and the stateless key. The install data has no
    /// chain-specific field, so it is the same on every chain.
    function test_installCommitsToStatelessKey() public view {
        MemberKeys memory k = _keys();
        assertEq(val.member(address(acct), 0), val.memberCommitment(Ops.masterCommitment(k), statelessPub));
        assertEq(Ops.masterCommitment(k), val.masterCommitment(k.master.root, k.master.seed, uint8(k.master.height)));
        uint256 base = uint256(keccak256(abi.encode(address(acct), uint256(0)))); // _config is slot 0
        assertEq(vm.load(address(val), bytes32(base + 2)), bytes32(0), "one slot per member");
    }

    function test_installRejectsBadStatelessKeys() public {
        MemberKeys[] memory ks = new MemberKeys[](2);
        ks[0] = _keys();
        ks[1] = Ops.keys(_p(), "second member", H, H);
        vm.startPrank(makeAddr("fresh account"));

        ks[1].statelessKey = statelessPub; // one stateless key for two members: one key, two votes
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(ks, 1));

        ks[1].statelessKey = statelessPub & bytes32(StatelessSigner.HIGH); // no public parameter
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(ks, 1));

        ks[1].statelessKey = statelessPub >> 128; // no root
        vm.expectRevert(WinterlockValidator.InvalidConfig.selector);
        val.onInstall(Ops.installData(ks, 1));

        ks[1].statelessKey = Ops.placeholderStatelessKey(ks[1].master);
        val.onInstall(Ops.installData(ks, 1));
        vm.stopPrank();
    }

    /// A master certificate carries the stateless key to open the member commitment; any other key fails it.
    function test_masterCertificateWithWrongStatelessKeyRejected() public {
        MemberKeys memory k = _keys();
        k.statelessKey = Ops.placeholderStatelessKey(k.master);
        PackedUserOperation memory op = _signed(k, 0);
        _expectFail();
        _send(op);
    }

    // --- stateless certificates (step 3) ---

    function test_statelessCertificateEnrolsTree() public {
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        PackedUserOperation memory op = _signed(k, 0);
        assertEq(uint8(op.signature[1]), 0x40, "first operation carries a stateless certificate");
        assertEq(op.signature.length, 2 + 105 + 5684 + 1176 + 24 * H);
        _send(op);

        WinterlockValidator.Tree memory t = val.tree(address(acct), 0);
        assertEq(t.root, k.ops.root);
        assertEq(t.seed, val.statelessTreeSeed(address(acct), 0, 0));
        assertEq(t.height, H);
        assertEq(t.start, 0);
        assertEq(t.nextMaster, 0, "no master key used on this chain");
        assertTrue(t.stateless);

        op = _signed(k, 1);
        assertEq(uint8(op.signature[1]), 0, "later operations don't");
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }

    /// Packed: start 0, next master 0, the stateless flag and the height after the root.
    function test_statelessTreeStoragePacking() public {
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        _send(_signed(k, 0));
        uint256 base = uint256(keccak256(abi.encode(address(acct), uint256(0))));
        uint256 word = uint256(vm.load(address(val), bytes32(base + 17))); // trees[0][0]
        assertEq(bytes32(word & ~uint256(type(uint64).max)), k.ops.root);
        assertEq(word & type(uint64).max, (1 << 6) | H);
        assertEq(vm.load(address(val), bytes32(base + 18)), bytes32(0), "one slot per tree");
    }

    /// The digest binds the chain: the same tree, certified for Arbitrum, is refused here.
    function test_statelessCertificateFromAnotherChainRejected() public {
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        uint256 here = block.chainid;
        vm.chainId(42161);
        bytes32 digest = val.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        vm.chainId(here);
        PackedUserOperation memory op = _withCertificate(k, 0, Ops.statelessCertificateFor(k, _sk(), digest));
        _expectFail();
        _send(op);
        _send(_signed(k, 0)); // control: the same tree certified for this chain
    }

    /// The digest binds the account: the same tree, certified for another account with the same keys, is refused.
    function test_statelessCertificateForAnotherAccountRejected() public {
        MiniAccount twin = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(_keys()));
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        bytes32 digest = val.statelessCertificateDigest(address(twin), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _withCertificate(k, 0, Ops.statelessCertificateFor(k, _sk(), digest));
        _expectFail();
        _send(op);
    }

    /// A certificate for another validator (same keys, same account address) is refused: the digest binds it.
    function test_statelessCertificateForAnotherValidatorRejected() public {
        WinterlockValidator other = new WinterlockValidator(Ops.params(_p()), val.STATELESS_VERIFIER());
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        bytes32 digest = other.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _withCertificate(k, 0, Ops.statelessCertificateFor(k, _sk(), digest));
        _expectFail();
        _send(op);
    }

    /// In a team, one member's certificate can't enrol a tree for another: the digest names the member, and the
    /// commitment check names the key.
    function test_statelessCertificateForAnotherMemberRejected() public {
        MemberKeys[] memory ks = new MemberKeys[](2);
        ks[0] = _keys();
        ks[1] = Ops.keys(_p(), "second member", H, H);
        MiniAccount team = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(ks, 1));
        MemberKeys memory k = Ops.forAccount(val, address(team), 1, Ops.statelessTree(ks[0], 0));
        bytes32 digest = val.statelessCertificateDigest(address(team), 1, k.ops.root, uint8(H), 0);
        bytes memory cert = Ops.statelessCertificateFor(k, _sk(), digest); // member 0's key, for member 1
        PackedUserOperation memory op = _op(address(team), 0);
        op.signature = Ops.entry(k, 1, 0, 0, cert, ep.getUserOpHash(op));
        _expectFail();
        _send(op);
    }

    /// Someone else's stateless key: refused whether the certificate names that key (commitment) or the member's
    /// (signature).
    function test_foreignStatelessKeyRejected() public {
        StatelessKey memory mallory = StatelessSigner.testKey("mallory");
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        bytes32 digest = val.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);

        PackedUserOperation memory op = _withCertificate(k, 0, Ops.statelessCertificateFor(k, mallory, digest));
        _expectFail();
        _send(op);

        bytes memory cert = Ops.statelessCertificateFor(k, mallory, digest);
        for (uint256 i; i < 32; ++i) {
            cert[73 + i] = statelessPub[i]; // the member's key, mallory's signature
        }
        op = _withCertificate(k, 0, cert);
        _expectFail();
        _send(op);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));
    }

    function test_wrongMasterCommitmentRejected() public {
        bytes memory cert = Ops.statelessCertificate(val, address(acct), 0, _statelessKeys(0), _sk());
        cert[41] ^= 0x01; // master commitment: bytes 41..72 of the certificate
        PackedUserOperation memory op = _withCertificate(_statelessKeys(0), 0, cert);
        _expectFail();
        _send(op);
    }

    function test_statelessStartAfterSequenceRejected() public {
        // certifies a tree from sequence 1 on, used at 0 (no key exists for it, so the signature is filler)
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(1));
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes memory cert = Ops.statelessCertificate(val, address(acct), 0, k, _sk());
        op.signature = abi.encodePacked(uint8(0), uint8(0x40), cert, new bytes(1176 + 24 * H));
        _expectFail();
        _send(op);
    }

    /// Both certificate flags at once is malformed.
    function test_bothCertificateFlagsRejected() public {
        PackedUserOperation memory op = _signed(_statelessKeys(0), 0);
        op.signature[1] = bytes1(uint8(0xc0));
        _expectFail();
        _send(op);
    }

    /// The root must be high-aligned, or it would spill into the packed fields; a properly signed certificate
    /// with low bytes set stays out of storage.
    function test_statelessRootWithLowBytesRejected() public {
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        k.ops.root = bytes32(uint256(k.ops.root) | (1 << 6)); // would set the stateless flag bit
        bytes32 digest = val.statelessCertificateDigest(address(acct), 0, k.ops.root, uint8(H), 0);
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(k, 0, 0, 0, Ops.statelessCertificateFor(k, _sk(), digest), h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0), "not stored");
    }

    // --- rotation: start sequences only grow ---

    function test_statelessRotationReplacesTree() public {
        _send(_signed(_statelessKeys(0), 0));
        _send(_signed(_statelessKeys(0), 1));
        MemberKeys memory next = Ops.forAccount(val, address(acct), 0, _statelessKeys(2));
        _send(_signed(next, 2));
        WinterlockValidator.Tree memory t = val.tree(address(acct), 0);
        assertEq(t.root, next.ops.root);
        assertEq(t.start, 2);
        _send(_signed(next, 3)); // key index (3 - 2) * 2 in the new tree
        assertEq(recipient.balance, 4 ether);
    }

    /// A stateless certificate must start after the stored tree, so an old one can't bring its tree back.
    function test_statelessRollbackRejected() public {
        bytes memory first = Ops.statelessCertificate(val, address(acct), 0, _statelessKeys(0), _sk());
        _send(_withCertificate(_statelessKeys(0), 0, first));
        _send(_signed(_statelessKeys(1), 1));

        // the old tree, no certificate
        PackedUserOperation memory op = _withCertificate(_statelessKeys(0), 2, "");
        _expectFail();
        _send(op);
        // the old tree with its old certificate (start 0, not after 1)
        op = _withCertificate(_statelessKeys(0), 2, first);
        _expectFail();
        _send(op);
        // a new certificate with the stored start
        op = _signed(_statelessKeys(1), 2);
        assertEq(uint8(op.signature[1]), 0, "stored tree: no certificate");
        bytes memory again = Ops.statelessCertificate(val, address(acct), 0, _statelessKeys(1), _sk());
        op = _withCertificate(_statelessKeys(1), 2, again);
        _expectFail();
        _send(op);
    }

    /// Mixed kinds: one order for all certificates on a chain. After a stateless rotation, an unused master
    /// certificate with an earlier start is refused, and so is one with a used master index; the next master index
    /// with a later start is accepted.
    function test_mixedRotationKeepsOneOrder() public {
        _send(_signed(_masterKeys(0, 0), 0)); // master key 0 from 0
        bytes memory statelessCert = Ops.statelessCertificate(val, address(acct), 0, _statelessKeys(1), _sk());
        _send(_withCertificate(_statelessKeys(1), 1, statelessCert)); // stateless from 1
        WinterlockValidator.Tree memory t = val.tree(address(acct), 0);
        assertTrue(t.stateless);
        assertEq(t.nextMaster, 1, "master key 0 stays used");

        PackedUserOperation memory op = _signed(_masterKeys(1, 1), 2); // next master key, but not after start 1
        _expectFail();
        _send(op);
        op = _signed(_masterKeys(0, 2), 2); // later start, used master key
        _expectFail();
        _send(op);
        _send(_signed(_masterKeys(1, 2), 2)); // next master key from 2
        t = val.tree(address(acct), 0);
        assertFalse(t.stateless);
        assertEq(t.nextMaster, 2);
        assertEq(t.start, 2);

        op = _withCertificate(_statelessKeys(1), 3, statelessCert); // the replaced stateless tree
        _expectFail();
        _send(op);
        _send(_signed(_masterKeys(1, 2), 3));
        assertEq(recipient.balance, 4 ether);
    }

    // --- storage writes ---

    /// An account can call validateUserOp outside the EntryPoint; only a valid stateless certificate is stored.
    function test_directCallStoresOnlyValidStatelessCertificates() public {
        MemberKeys memory k = Ops.forAccount(val, address(acct), 0, _statelessKeys(0));
        PackedUserOperation memory op = _op(address(acct), 0);
        bytes32 h = ep.getUserOpHash(op);
        bytes memory cert = Ops.statelessCertificate(val, address(acct), 0, k, _sk());
        bytes memory forged = bytes.concat(cert);
        forged[200] ^= 0x01; // inside the stateless signature
        op.signature = Ops.entry(k, 0, 0, 0, forged, h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(acct), 0).root, bytes32(0));

        op.signature = Ops.entry(k, 0, 0, 0, cert, h);
        vm.prank(address(acct));
        assertEq(val.validateUserOp(op, h), 0);
        assertEq(val.tree(address(acct), 0).root, k.ops.root);
    }

    // --- gas ---

    /// Validation gas of a chain's first operation with each kind of certificate, against the steady state; and
    /// gas estimation: a dummy that carries the real stateless certificate (it doesn't depend on the operation)
    /// costs at least as much as the real signature. Storage and the verifier are cold, as in a fresh transaction.
    function test_gas_statelessCertificate() public {
        ValidationProbe probe = new ValidationProbe();
        probe.install(val, Ops.installData(_keys()));
        (uint256 masterGas, uint256 masterDummy, uint256 masterBytes) = _enrolGas(probe, _masterKeys(0, 0));
        (uint256 statelessGas, uint256 statelessDummy, uint256 statelessBytes) = _enrolGas(probe, _statelessKeys(0));
        assertGe(masterDummy, masterGas);
        assertGe(statelessDummy, statelessGas);
        assertLe(statelessDummy, statelessGas + 80 * 48);
        uint256 steady = _steadyGas(probe);
        console.log("validation gas: steady state", steady);
        console.log("with master certificate", masterGas, ", bytes", masterBytes);
        console.log("with stateless certificate", statelessGas, ", bytes", statelessBytes);
        console.log("stateless certificate dummy", statelessDummy);
    }

    /// Validation gas of the enrolling operation with k's certificate, and of its dummy; leaves the state as it was
    function _enrolGas(ValidationProbe probe, MemberKeys memory k)
        internal
        returns (uint256 realGas, uint256 dummyGas, uint256 certBytes)
    {
        PackedUserOperation memory op = _op(address(probe), 0);
        bytes32 h = ep.getUserOpHash(op);
        k = Ops.forAccount(val, address(probe), 0, k);
        bytes memory cert = k.stateless
            ? Ops.statelessCertificate(val, address(probe), 0, k, _sk())
            : Ops.certificate(val, address(probe), 0, k);
        certBytes = cert.length;
        bytes memory real = Ops.entry(k, 0, 0, 0, cert, h);
        bytes memory dummy = bytes.concat(real);
        for (uint256 i = 2 + certBytes; i < dummy.length; ++i) {
            dummy[i] = 0xab; // real certificate, garbage operation signature
        }
        uint256 snap = vm.snapshotState();
        uint256 result;
        (result, realGas) = _measure(probe, op, real, h);
        assertEq(result, 0);
        vm.revertToState(snap);
        (result, dummyGas) = _measure(probe, op, dummy, h);
        assertEq(result, 1);
        vm.revertToState(snap);
    }

    /// Validation gas of the next operation once a tree is enrolled
    function _steadyGas(ValidationProbe probe) internal returns (uint256 steadyGas) {
        MemberKeys memory k = _masterKeys(0, 0);
        PackedUserOperation memory op = _op(address(probe), 0);
        bytes32 h = ep.getUserOpHash(op);
        _measure(probe, op, Ops.memberSignature(val, address(probe), k, 0, 0, 0, h), h); // enrols
        op = _op(address(probe), 1);
        h = ep.getUserOpHash(op);
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
