// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {WinterlockOwner} from "../src/safe/WinterlockOwner.sol";
import {WinterlockOwnerFactory} from "../src/safe/WinterlockOwnerFactory.sol";
import {IStatelessVerifier} from "../src/interfaces/IStatelessVerifier.sol";
import {ValidatorDeployment} from "../script/DeployValidator.s.sol";
import {SafeOwnerDeployment} from "../script/DeploySafeOwner.s.sol";
import {WotsParams, WotsKey, Ops} from "./utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";
import {Member, OwnerSigner} from "./utils/SafeHarness.sol";

/// WinterlockOwner on its own: the member's owner as a proxy of the shared implementation (its key, its storage, the
/// implementation harmless on its own), the factory, enrolment (D12's certificate properties, per Safe and chain),
/// malformed signatures, and the deterministic addresses. The Safe integration is in
/// test/integration/SafeWinterlockOwner.t.sol.
contract WinterlockOwnerTest is Test {
    WinterlockOwner internal owner; // the member's proxy
    WinterlockOwner internal impl;
    WinterlockOwnerFactory internal factory;
    StatelessKey internal sk; // kept: keygen is costly
    address internal safeA = makeAddr("safe A");
    address internal safeB = makeAddr("safe B");

    uint256 internal constant H = 4;
    string internal constant LABEL = "winterlock.test.safe-owner";
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant INVALID = 0xffffffff;

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        if (ValidatorDeployment.DEPLOYER.code.length == 0) {
            vm.etch(ValidatorDeployment.DEPLOYER, ValidatorDeployment.DEPLOYER_CODE);
        }
        sk = StatelessSigner.testKey(LABEL);
        owner = WinterlockOwner(SafeOwnerDeployment.deploy(Ops.params(_p()), StatelessSigner.publicKey(sk)));
        impl = WinterlockOwner(SafeOwnerDeployment.predictImplementation(Ops.params(_p())));
        factory = WinterlockOwnerFactory(SafeOwnerDeployment.predictFactory(Ops.params(_p())));
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

    /// The implementation checks the parameter set and the verifier; the factory checks each member's key and that its
    /// implementation is one.
    /// The contracts are created with CREATE (_create), not `new` under vm.expectRevert: Forge's test preprocessing
    /// turns `new` into vm.deployCode, and an expected revert of that cheatcode ends the test as passed, so the checks
    /// after the first one never ran (seen with Forge 1.8.3).
    function test_constructorChecks() public {
        IStatelessVerifier verifier = owner.STATELESS_VERIFIER();
        bytes32 key = StatelessSigner.publicKey(sk);
        bytes memory invalidConfig = abi.encodeWithSelector(WinterlockOwner.InvalidConfig.selector);
        // 32-byte hashes need two slots per tree
        assertEq(_create(_implInit(Ops.params(WotsParams(32, 560, 4, 0)), verifier)), invalidConfig);
        // no verifier code
        assertEq(_create(_implInit(Ops.params(_p()), IStatelessVerifier(makeAddr("nothing")))), invalidConfig);
        assertEq(_create(_implInit(Ops.params(_p()), verifier)), ""); // control

        bytes memory invalidImpl = abi.encodeWithSelector(WinterlockOwnerFactory.InvalidImplementation.selector);
        assertEq(_create(_factoryInit(address(owner))), invalidImpl); // a member's proxy
        assertEq(_create(_factoryInit(makeAddr("nothing"))), invalidImpl); // no code
        assertEq(_create(_factoryInit(address(impl))), ""); // control

        vm.expectRevert(WinterlockOwnerFactory.InvalidKey.selector); // no public parameter
        factory.deploy(key & bytes32(StatelessSigner.HIGH));
        vm.expectRevert(WinterlockOwnerFactory.InvalidKey.selector); // no root
        factory.deploy(key >> 128);
        assertEq(owner.KEY(), key);
    }

    function _implInit(uint256 params, IStatelessVerifier verifier) internal pure returns (bytes memory) {
        return abi.encodePacked(type(WinterlockOwner).creationCode, abi.encode(params, verifier));
    }

    function _factoryInit(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(type(WinterlockOwnerFactory).creationCode, abi.encode(implementation));
    }

    /// Creates `initCode` with CREATE; returns the constructor's revert data, or "" if the contract was created
    function _create(bytes memory initCode) internal returns (bytes memory err) {
        address created;
        assembly ("memory-safe") {
            created := create(0, add(initCode, 0x20), mload(initCode))
        }
        if (created == address(0)) {
            err = new bytes(0);
            assembly ("memory-safe") {
                err := mload(0x40)
                mstore(err, returndatasize())
                returndatacopy(add(err, 0x20), 0, returndatasize())
                mstore(0x40, add(add(err, 0x20), and(add(returndatasize(), 31), not(31))))
            }
        }
    }

    // --- the member's proxy and the implementation ---

    /// The member's owner is the 45-byte ERC-1167 proxy of the implementation with the key appended (77 bytes). It
    /// reads its own key, and the trees live in its storage, not in the implementation's.
    function test_ownerIsAProxy() public {
        bytes32 key = StatelessSigner.publicKey(sk);
        assertEq(
            address(owner).code,
            abi.encodePacked(hex"363d3d373d3d3d363d73", address(impl), hex"5af43d82803e903d91602b57fd5bf3", key)
        );
        assertEq(owner.KEY(), key);
        assertEq(owner.IMPLEMENTATION(), address(impl));
        assertEq(impl.IMPLEMENTATION(), address(impl));
        assertEq(owner.PARAMS(), Ops.params(_p()));
        assertEq(address(factory.IMPLEMENTATION()), address(impl));

        WotsKey memory t = _tree(safeA, 0);
        assertTrue(_enroll(safeA, t, 0, OwnerSigner.certificate(_member(), t, safeA, 0)));
        bytes32 slot = keccak256(abi.encode(safeA, uint256(0))); // _trees: slot 0
        assertTrue(vm.load(address(owner), slot) != 0);
        assertEq(vm.load(address(impl), slot), 0);
        (bytes32 root,,,) = impl.tree(safeA);
        assertEq(root, 0);

        // another member's proxy of the same implementation reads its own key
        bytes32 other = keccak256("another member") | bytes32(uint256(1));
        WinterlockOwner second = WinterlockOwner(factory.deploy(other));
        assertEq(second.KEY(), other);
        assertEq(owner.KEY(), key);
    }

    /// Called directly, the implementation has no key (KEY() is 0): it refuses every certificate, so it never holds a
    /// tree and refuses every transaction signature, and it refuses every message signature. So does a proxy without
    /// a key, which only a deployer other than the factory can make.
    function test_implementationHarmless() public {
        assertEq(impl.KEY(), bytes32(0));
        WotsKey memory t = OwnerSigner.opsTree(_p(), Member(LABEL, sk, impl), safeA, 0, H, H);
        bytes memory cert = StatelessSigner.sign(sk, impl.certificateDigest(safeA, t.root, uint8(H), 0));
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        impl.enroll(safeA, t.root, uint8(H), 0, cert);
        (bytes32 root,,,) = impl.tree(safeA);
        assertEq(root, 0);

        // a SafeMessage of safeA, signed for the implementation and for the member's proxy by the member's key
        bytes32 msgHash = keccak256("message");
        bytes32 safeMsgHash = _safeMessageHash(safeA, msgHash);
        assertEq(impl.isValidSignature(safeMsgHash, _messageSig(impl, safeA, msgHash, safeMsgHash)), INVALID);
        assertEq(owner.isValidSignature(safeMsgHash, _messageSig(owner, safeA, msgHash, safeMsgHash)), MAGIC); // control

        // proxies without a key: a zero key, and no key at all (a plain ERC-1167 proxy)
        address[2] memory keyless =
            [LibClone.clone(address(impl), abi.encodePacked(bytes32(0))), LibClone.clone(address(impl))];
        for (uint256 i; i < 2; ++i) {
            WinterlockOwner k = WinterlockOwner(keyless[i]);
            assertEq(k.KEY(), bytes32(0));
            assertEq(k.isValidSignature(safeMsgHash, _messageSig(k, safeA, msgHash, safeMsgHash)), INVALID);
            bytes memory c = StatelessSigner.sign(sk, k.certificateDigest(safeA, t.root, uint8(H), 0));
            vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
            k.enroll(safeA, t.root, uint8(H), 0, c);
        }
    }

    function _safeMessageHash(address safe, bytes32 msgHash) internal view returns (bytes32) {
        bytes32 domainTypeHash = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
        bytes32 domain = keccak256(abi.encode(domainTypeHash, block.chainid, safe));
        bytes32 structHash = keccak256(abi.encode(keccak256("SafeMessage(bytes message)"), msgHash));
        return keccak256(abi.encodePacked(bytes2(0x1901), domain, structHash));
    }

    function _messageSig(WinterlockOwner o, address safe, bytes32 msgHash, bytes32 safeMsgHash)
        internal
        view
        returns (bytes memory)
    {
        return OwnerSigner.messageSignature(Member(LABEL, sk, o), safe, msgHash, safeMsgHash);
    }

    // --- factory ---

    /// deploy is idempotent and announces a new owner once. deployAndEnroll creates the owner and stores its first
    /// tree in one transaction, from a certificate signed for the owner's predicted address; a refused certificate
    /// reverts the whole. On an existing owner it only enrols.
    function test_factoryDeployAndEnroll() public {
        bytes32 key = StatelessSigner.publicKey(sk);
        vm.recordLogs();
        assertEq(factory.deploy(key), address(owner)); // exists: same address, no event
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(factory.predict(key), address(owner));

        // another parameter set: another implementation and factory, and an owner not deployed yet
        WotsParams memory p16 = WotsParams(16, 300, 4, 0);
        WinterlockOwnerFactory f16 = SafeOwnerDeployment.deployShared(Ops.params(p16));
        address predicted = f16.predict(key);
        assertEq(predicted.code.length, 0);
        // what the member's signer computes before the owner exists: the tree (its seed) and the certificate (its
        // digest) for the predicted address. Here computed with a throwaway deployment.
        uint256 snap = vm.snapshotState();
        Member memory m = Member(LABEL, sk, WinterlockOwner(f16.deploy(key)));
        WotsKey memory t = OwnerSigner.opsTree(p16, m, safeA, 0, H, H);
        bytes memory cert = OwnerSigner.certificate(m, t, safeA, 0);
        vm.revertToState(snap);
        assertEq(predicted.code.length, 0);

        bytes memory forged = bytes.concat(cert);
        forged[200] ^= 0x01;
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        f16.deployAndEnroll(key, safeA, t.root, uint8(H), 0, forged);
        assertEq(predicted.code.length, 0, "no owner left behind");

        vm.expectEmit(address(f16));
        emit WinterlockOwnerFactory.OwnerCreated(predicted, key);
        vm.expectEmit(predicted);
        emit WinterlockOwner.Enrolled(safeA, t.root, uint8(H), 0);
        assertEq(f16.deployAndEnroll(key, safeA, t.root, uint8(H), 0, cert), predicted);
        _expectTree(predicted, t.root, 0);

        // on the existing owner: a rotation
        WotsKey memory t3 = OwnerSigner.opsTree(p16, m, safeA, 3, H, H);
        cert = OwnerSigner.certificate(m, t3, safeA, 3);
        assertEq(f16.deployAndEnroll(key, safeA, t3.root, uint8(H), 3, cert), predicted);
        _expectTree(predicted, t3.root, 3);
    }

    function _expectTree(address o, bytes32 root, uint64 start) internal view {
        (bytes32 r,, uint8 h, uint64 s) = WinterlockOwner(o).tree(safeA);
        assertEq(r, root);
        assertEq(h, H);
        assertEq(s, start);
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

    // --- deterministic addresses ---

    /// The implementation and the factory: CREATE2 through the deterministic deployment proxy with fixed salts. The
    /// member's owner: CREATE2 by the factory, salt = the member's stateless key. The addresses depend on the key, the
    /// parameter set and the code, not on the chain.
    function test_deterministicAddress() public {
        uint256 params = Ops.params(_p());
        bytes32 key = StatelessSigner.publicKey(sk);
        assertEq(address(owner), SafeOwnerDeployment.predict(params, key));
        assertEq(address(owner), factory.predict(key));
        assertEq(
            address(owner),
            LibClone.predictDeterministicAddress(address(impl), abi.encodePacked(key), key, address(factory))
        );
        assertEq(SafeOwnerDeployment.deploy(params, key), address(owner)); // again: a no-op
        assertTrue(
            SafeOwnerDeployment.predict(params, keccak256("another key") | bytes32(uint256(1))) != address(owner)
        );
        assertTrue(SafeOwnerDeployment.predict(Ops.params(WotsParams(16, 300, 4, 0)), key) != address(owner));

        // a fresh parameter set on two chains, from the same state: implementation, factory and owner
        uint256 p16 = Ops.params(WotsParams(16, 300, 4, 0));
        bytes32 other = keccak256("member on two chains") | bytes32(uint256(1));
        uint256 snap = vm.snapshotState();
        address[3] memory here = _deployAll(p16, other);
        vm.revertToState(snap);
        vm.chainId(10);
        address[3] memory there = _deployAll(p16, other);
        for (uint256 i; i < 3; ++i) {
            assertEq(there[i], here[i]);
            assertGt(there[i].code.length, 0);
        }
    }

    function _deployAll(uint256 params, bytes32 key) internal returns (address[3] memory a) {
        a[2] = SafeOwnerDeployment.deploy(params, key);
        a[0] = SafeOwnerDeployment.predictImplementation(params);
        a[1] = SafeOwnerDeployment.predictFactory(params);
        assertEq(a[2], SafeOwnerDeployment.predict(params, key));
    }
}
