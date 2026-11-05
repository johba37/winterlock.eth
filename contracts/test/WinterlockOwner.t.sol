// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WinterlockOwner} from "../src/safe/WinterlockOwner.sol";
import {IStatelessVerifier} from "../src/interfaces/IStatelessVerifier.sol";
import {ValidatorDeployment} from "../script/DeployValidator.s.sol";
import {SafeOwnerDeployment} from "../script/DeploySafeOwner.s.sol";
import {WotsParams, WotsKey, Ops} from "./utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";
import {Member, OwnerSigner} from "./utils/SafeHarness.sol";

/// WinterlockOwner on its own: enrolment (D12's certificate properties, per Safe and chain), malformed signatures,
/// and the deterministic address. The Safe integration is in test/integration/SafeWinterlockOwner.t.sol.
contract WinterlockOwnerTest is Test {
    WinterlockOwner internal owner;
    StatelessKey internal sk; // kept: keygen is costly
    address internal safeA = makeAddr("safe A");
    address internal safeB = makeAddr("safe B");

    uint256 internal constant H = 4;
    string internal constant LABEL = "winterlock.test.safe-owner";

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        if (ValidatorDeployment.DEPLOYER.code.length == 0) {
            vm.etch(ValidatorDeployment.DEPLOYER, ValidatorDeployment.DEPLOYER_CODE);
        }
        sk = StatelessSigner.testKey(LABEL);
        owner = WinterlockOwner(SafeOwnerDeployment.deploy(Ops.params(_p()), StatelessSigner.publicKey(sk)));
    }

    function _member() internal view returns (Member memory) {
        return Member(LABEL, sk, owner);
    }

    function _tree(address safe, uint64 start) internal view returns (WotsKey memory) {
        return OwnerSigner.opsTree(_p(), _member(), safe, start, H, H);
    }

    function _enroll(address safe, WotsKey memory t, uint64 start, bytes memory sig) internal returns (bool ok) {
        // forge-lint: disable-next-line(unsafe-typecast)
        (ok,) = address(owner).call(abi.encodeCall(WinterlockOwner.enroll, (safe, t.root, uint8(t.height), start, sig)));
    }

    function _certificate(address safe, bytes32 root, uint8 height, uint64 start) internal view returns (bytes memory) {
        return StatelessSigner.sign(sk, owner.certificateDigest(safe, root, height, start));
    }

    function _root(address safe) internal view returns (bytes32 root) {
        (root,,,) = owner.tree(safe);
    }

    // --- construction ---

    function test_constructorChecks() public {
        IStatelessVerifier verifier = owner.STATELESS_VERIFIER();
        bytes32 key = StatelessSigner.publicKey(sk);
        vm.expectRevert(WinterlockOwner.InvalidConfig.selector); // 32-byte hashes need two slots per tree
        new WinterlockOwner(Ops.params(WotsParams(32, 560, 4, 0)), verifier, key);
        vm.expectRevert(WinterlockOwner.InvalidConfig.selector); // no public parameter
        new WinterlockOwner(Ops.params(_p()), verifier, key & bytes32(StatelessSigner.HIGH));
        vm.expectRevert(WinterlockOwner.InvalidConfig.selector); // no root
        new WinterlockOwner(Ops.params(_p()), verifier, key >> 128);
        vm.expectRevert(WinterlockOwner.InvalidConfig.selector); // no verifier code
        new WinterlockOwner(Ops.params(_p()), IStatelessVerifier(makeAddr("nothing")), key);
        assertEq(owner.KEY(), key);
    }

    // --- enrolment ---

    /// One slot per tree: root in the high bytes, start (40 bits) and height (8 bits) below. The seed is derived from
    /// the chain, the owner, the Safe and the start.
    function test_enrolStoresPackedTree() public {
        WotsKey memory t = _tree(safeA, 3);
        bytes memory cert = OwnerSigner.certificate(_member(), t, safeA, 3);
        vm.expectEmit(address(owner));
        emit WinterlockOwner.Enrolled(safeA, t.root, uint8(H), 3);
        assertTrue(_enroll(safeA, t, 3, cert));

        (bytes32 root, uint128 seed, uint8 height, uint64 start) = owner.tree(safeA);
        assertEq(root, t.root);
        assertEq(height, H);
        assertEq(start, 3);
        bytes32 seedHash = keccak256(
            abi.encode(keccak256("Winterlock.safe-owner.tree-seed.v1"), block.chainid, address(owner), safeA, uint64(3))
        );
        assertEq(seed, uint128(bytes16(seedHash)));
        assertEq(seed, t.seed);
        bytes32 word = vm.load(address(owner), keccak256(abi.encode(safeA, uint256(0)))); // _trees: slot 0
        assertEq(uint256(word), uint256(t.root) | (3 << 8) | H);
        assertEq(_root(safeB), bytes32(0), "per Safe");
    }

    /// The certificate binds the chain, the owner contract and the Safe, and must be signed by this owner's key. Only
    /// valid certificates are stored.
    function test_certificateBindings() public {
        WotsKey memory t = _tree(safeA, 0);
        bytes[] memory refused = _wrongCertificates(t.root);
        for (uint256 i; i < refused.length; ++i) {
            assertFalse(_enroll(safeA, t, 0, refused[i]));
        }
        assertEq(_root(safeA), bytes32(0), "nothing stored");
        assertTrue(_enroll(safeA, t, 0, _certificate(safeA, t.root, uint8(H), 0))); // control
        assertEq(_root(safeA), t.root);
    }

    /// Certificates for `root` (height H, start 0, safeA) that this owner on this chain must refuse
    function _wrongCertificates(bytes32 root) internal returns (bytes[] memory c) {
        uint8 h = uint8(H);
        c = new bytes[](6);
        // another chain
        uint256 here = block.chainid;
        vm.chainId(42161);
        c[0] = _certificate(safeA, root, h, 0);
        vm.chainId(here);
        // another owner contract with the same key (another parameter set)
        WinterlockOwner twin = WinterlockOwner(
            SafeOwnerDeployment.deploy(Ops.params(WotsParams(16, 300, 4, 0)), StatelessSigner.publicKey(sk))
        );
        c[1] = StatelessSigner.sign(sk, twin.certificateDigest(safeA, root, h, 0));
        // another Safe
        c[2] = _certificate(safeB, root, h, 0);
        // another key
        c[3] = StatelessSigner.sign(StatelessSigner.testKey("mallory"), owner.certificateDigest(safeA, root, h, 0));
        // a forged signature, and none
        c[4] = _certificate(safeA, root, h, 0);
        c[4][200] ^= 0x01;
        c[5] = "";
    }

    /// Start nonces only grow: no rollback to an old tree, no second tree for a start, no skipped start used later.
    function test_startOnlyGrows() public {
        WotsKey memory t0 = _tree(safeA, 0);
        bytes memory c0 = OwnerSigner.certificate(_member(), t0, safeA, 0);
        assertTrue(_enroll(safeA, t0, 0, c0));
        assertFalse(_enroll(safeA, t0, 0, c0), "the same certificate again");

        WotsKey memory t3 = _tree(safeA, 3);
        assertTrue(_enroll(safeA, t3, 3, OwnerSigner.certificate(_member(), t3, safeA, 3)));
        assertFalse(_enroll(safeA, t0, 0, c0), "rollback");
        WotsKey memory t2 = _tree(safeA, 2);
        assertFalse(_enroll(safeA, t2, 2, OwnerSigner.certificate(_member(), t2, safeA, 2)), "skipped start");
        WotsKey memory other = OwnerSigner.opsTree(_p(), Member("another tree", sk, owner), safeA, 3, H, H);
        assertFalse(
            _enroll(safeA, other, 3, OwnerSigner.certificate(_member(), other, safeA, 3)), "second tree, start 3"
        );
        assertEq(_root(safeA), t3.root);
    }

    /// Field checks, with certificates the key did sign: the root must be high-aligned (it shares its slot), the
    /// height between 1 and 40, the start within 40 bits.
    function test_certificateFieldsChecked() public {
        bytes32 root = _tree(safeA, 0).root;
        bytes32 lowBytes = root | bytes32(uint256(1 << 8)); // would set a start bit
        _expectRefused(lowBytes, 4, 0);
        _expectRefused(bytes32(0), 4, 0);
        _expectRefused(root, 0, 0);
        _expectRefused(root, 41, 0);
        uint64 maxStart = uint64(owner.MAX_START());
        _expectRefused(root, 4, maxStart + 1);
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        owner.enroll(safeA, root, 4, 0, new bytes(5684)); // the verifier reverts on garbage: refused, not bubbled
        owner.enroll(safeA, root, 40, maxStart, _certificate(safeA, root, 40, maxStart));
        (,, uint8 height, uint64 start) = owner.tree(safeA);
        assertEq(height, 40);
        assertEq(start, maxStart);
    }

    function _expectRefused(bytes32 root, uint8 height, uint64 start) internal {
        bytes memory sig = _certificate(safeA, root, height, start);
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        owner.enroll(safeA, root, height, start, sig);
    }

    // --- signatures ---

    /// Malformed signatures and Safes without a tree get the failure value from both entry points, never a revert,
    /// so Safe reports GS024 and the Transaction Service a plain rejection.
    function test_malformedSignaturesInvalid() public {
        bytes32 h = keccak256("hash");
        bytes[] memory sigs = new bytes[](6);
        sigs[0] = "";
        sigs[1] = abi.encodePacked(uint8(0), safeA); // transaction kind, too short
        sigs[2] = abi.encodePacked(uint8(3), safeA, new bytes(2000)); // unknown kind
        sigs[3] = abi.encodePacked(uint8(2), safeA, new bytes(100)); // message, too short
        sigs[4] = abi.encodePacked(uint8(2), safeA, new bytes(32 + 5684)); // message, wrong hash
        sigs[5] = abi.encodePacked(uint8(1), safeA, new bytes(320 + 1176 + 24 * H));
        WotsKey memory t = _tree(safeA, 0);
        assertTrue(_enroll(safeA, t, 0, OwnerSigner.certificate(_member(), t, safeA, 0)));
        for (uint256 i; i < sigs.length; ++i) {
            assertEq(owner.isValidSignature(h, sigs[i]), bytes4(0xffffffff));
            assertEq(owner.isValidSignature(abi.encodePacked(h), sigs[i]), bytes4(0xffffffff));
        }
    }

    /// The three things the stateless key signs for an owner have their own domains; none can stand in for another
    /// or for WinterlockValidator's.
    function test_domainsDistinct() public view {
        bytes32 x = keccak256("x");
        assertTrue(owner.CERTIFICATE_DOMAIN() != owner.MESSAGE_DOMAIN());
        assertTrue(owner.MESSAGE_DOMAIN() != keccak256("Winterlock.stateless-certificate.v1"));
        assertTrue(owner.certificateDigest(safeA, x, 4, 0) != owner.messageDigest(safeA, x));
    }

    // --- deterministic address ---

    /// CREATE2 through the deterministic deployment proxy, salt = the member's stateless key: the address depends on the
    /// key, the parameter set and the code, not on the chain.
    function test_deterministicAddress() public {
        uint256 params = Ops.params(_p());
        bytes32 key = StatelessSigner.publicKey(sk);
        assertEq(address(owner), SafeOwnerDeployment.predict(params, key));
        assertEq(SafeOwnerDeployment.deploy(params, key), address(owner)); // again: a no-op
        assertTrue(
            SafeOwnerDeployment.predict(params, keccak256("another key") | bytes32(uint256(1))) != address(owner)
        );
        assertTrue(SafeOwnerDeployment.predict(Ops.params(WotsParams(16, 300, 4, 0)), key) != address(owner));

        bytes32 other = keccak256("member on two chains") | bytes32(uint256(1));
        uint256 snap = vm.snapshotState();
        address onThisChain = SafeOwnerDeployment.deploy(params, other);
        vm.revertToState(snap);
        vm.chainId(10);
        assertEq(SafeOwnerDeployment.deploy(params, other), onThisChain);
    }
}
