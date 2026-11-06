// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {WinterlockOwner} from "../src/safe/WinterlockOwner.sol";
import {WinterlockOwnerFactory} from "../src/safe/WinterlockOwnerFactory.sol";
import {SharedWotsVerifier} from "../src/SharedWotsVerifier.sol";
import {IStatelessVerifier} from "../src/interfaces/IStatelessVerifier.sol";
import {IWotsVerifier} from "../src/interfaces/IWotsVerifier.sol";
import {WotsVerifier} from "../src/WotsVerifier.sol";
import {ValidatorDeployment} from "../script/DeployValidator.s.sol";
import {SafeOwnerDeployment} from "../script/DeploySafeOwner.s.sol";
import {WotsParams, WotsKey, WotsSigner, WotsTree, Ops} from "./utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";
import {Member, DeviceKey, OwnerSigner, SafeTx, SafeHarness} from "./utils/SafeHarness.sol";

/// Stands in for a Safe in the approved kind's tests: only signedMessages, which SignMessageLib sets in a real Safe
contract SignedMessagesStub {
    mapping(bytes32 => uint256) public signedMessages;

    function approve(bytes32 safeMessageHash) external {
        signedMessages[safeMessageHash] = 1;
    }
}

/// Answers signedMessages with a revert
contract RevertingSafeStub {
    function signedMessages(bytes32) external pure returns (uint256) {
        revert("no");
    }
}

/// Answers any call with 31 nonzero bytes, less than a word
contract ShortAnswerStub {
    fallback() external {
        assembly {
            mstore(0x00, not(0))
            return(0x00, 31)
        }
    }
}

/// Measures WOTS verification linked in (WotsVerifier, as owner v1 had it) and through the shared verifier (as owner
/// v2 calls it, with the same encoding). `shared` is not a view, so that Forge runs a call to it as a transaction of its
/// own (isolate) and its first call finds the verifier cold.
contract WotsCallProbe {
    function linked(uint256 params, uint128 seed, uint256 keyIndex, bytes32 message, bytes calldata sig)
        external
        view
        returns (uint256 used, bytes32 root)
    {
        uint256 len = WotsVerifier.sigBytes(params);
        used = gasleft();
        root = WotsVerifier.computeRoot(params, seed, keyIndex, message, sig[:len], sig[len:]);
        used -= gasleft();
    }

    /// Two calls in one transaction: the first finds the verifier cold, the second warm
    function shared(
        IWotsVerifier v,
        uint256 params,
        uint128 seed,
        uint256 keyIndex,
        bytes32 message,
        bytes calldata sig
    ) external returns (uint256 first, uint256 second, bytes32 root) {
        first = gasleft();
        root = _call(v, params, seed, keyIndex, message, sig);
        first -= gasleft();
        second = gasleft();
        root = _call(v, params, seed, keyIndex, message, sig);
        second -= gasleft();
    }

    /// computeRoot encoded as WinterlockOwner._wotsSigned encodes it
    function _call(IWotsVerifier v, uint256 params, uint128 seed, uint256 keyIndex, bytes32 hash, bytes calldata sig)
        internal
        view
        returns (bytes32 root)
    {
        bytes4 selector = IWotsVerifier.computeRoot.selector;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, selector)
            mstore(add(m, 0x04), params)
            mstore(add(m, 0x24), seed)
            mstore(add(m, 0x44), keyIndex)
            mstore(add(m, 0x64), hash)
            mstore(add(m, 0x84), 0xa0)
            mstore(add(m, 0xa4), sig.length)
            let padded := and(add(sig.length, 31), not(31))
            if padded { mstore(add(add(m, 0xc4), sub(padded, 0x20)), 0) }
            calldatacopy(add(m, 0xc4), sig.offset, sig.length)
            if iszero(staticcall(gas(), v, m, add(0xc4, padded), 0x00, 0x20)) { revert(0, 0) }
            root := mload(0x00)
        }
    }
}

/// WinterlockOwner v2 on its own: the member's owner as a proxy of the shared implementation (its key, its storage, the
/// implementation harmless on its own), the factory, device keys (certify, revoke, generations), enrolment per device
/// (D12's certificate properties, per Safe, chain and device; start rules within and across generations), the
/// signature kinds against device state, the approved kind against stand-in Safes, malformed signatures, and the
/// deterministic addresses. The Safe integration is in test/integration/SafeWinterlockOwner.t.sol and
/// test/integration/SafeMessages.t.sol.
contract WinterlockOwnerTest is Test {
    WinterlockOwner internal owner; // the member's proxy
    WinterlockOwner internal impl;
    WinterlockOwnerFactory internal factory;
    StatelessKey internal sk; // the member key; kept: keygen is costly
    StatelessKey internal laptopKey; // device keys
    StatelessKey internal phoneKey;
    address internal safeA = makeAddr("safe A");
    address internal safeB = makeAddr("safe B");

    uint256 internal constant H = 4;
    string internal constant LABEL = "winterlock.test.safe-owner";
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant LEGACY_MAGIC = 0x20c13b0b;
    bytes4 internal constant INVALID = 0xffffffff;
    uint256 internal constant ACTIVE = 1 << 16;

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        if (ValidatorDeployment.DEPLOYER.code.length == 0) {
            vm.etch(ValidatorDeployment.DEPLOYER, ValidatorDeployment.DEPLOYER_CODE);
        }
        sk = StatelessSigner.testKey(LABEL);
        laptopKey = StatelessSigner.testKey("laptop");
        phoneKey = StatelessSigner.testKey("phone");
        owner = WinterlockOwner(SafeOwnerDeployment.deploy(Ops.params(_p()), StatelessSigner.publicKey(sk)));
        impl = WinterlockOwner(SafeOwnerDeployment.predictImplementation(Ops.params(_p())));
        factory = WinterlockOwnerFactory(SafeOwnerDeployment.predictFactory(Ops.params(_p())));
    }

    function _member() internal view returns (Member memory) {
        return Member(LABEL, sk, owner);
    }

    /// The laptop's key as device `device` at `generation`
    function _laptop(uint8 device, uint16 generation) internal view returns (DeviceKey memory) {
        return DeviceKey("laptop", laptopKey, owner, device, generation);
    }

    function _phone(uint8 device, uint16 generation) internal view returns (DeviceKey memory) {
        return DeviceKey("phone", phoneKey, owner, device, generation);
    }

    function _tree(address safe, uint64 start) internal view returns (WotsKey memory) {
        return OwnerSigner.opsTree(_p(), _member(), safe, start, H, H);
    }

    function _treeOf(DeviceKey memory d, address safe, uint64 start) internal view returns (WotsKey memory) {
        return OwnerSigner.opsTree(_p(), d, safe, start, H, H);
    }

    function _enroll(address safe, WotsKey memory t, uint64 start, bytes memory sig) internal returns (bool ok) {
        return _enrollAs(safe, 0, t, start, sig);
    }

    function _enrollAs(address safe, uint8 device, WotsKey memory t, uint64 start, bytes memory sig)
        internal
        returns (bool ok)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory cd = abi.encodeCall(WinterlockOwner.enroll, (safe, device, t.root, uint8(t.height), start, sig));
        (ok,) = address(owner).call(cd);
    }

    /// `d` enrols its own tree for `safe` from `start` (its key signs the certificate for its device and generation)
    function _enrollDevice(DeviceKey memory d, address safe, uint64 start) internal returns (bool ok) {
        (ok,) = address(owner).call(OwnerSigner.enrollCalldata(d, _treeOf(d, safe, start), safe, start));
    }

    function _certify(DeviceKey memory d) internal returns (bool ok) {
        (ok,) = address(owner).call(OwnerSigner.certifyCalldata(_member(), d));
    }

    function _certifyWith(DeviceKey memory d, bytes memory sig) internal returns (bool ok) {
        bytes memory cd = abi.encodeCall(
            WinterlockOwner.certifyDevice, (d.device, d.generation, StatelessSigner.publicKey(d.sk), sig)
        );
        (ok,) = address(owner).call(cd);
    }

    function _revoke(uint8 device, uint16 generation, bytes memory sig) internal returns (bool ok) {
        (ok,) = address(owner).call(abi.encodeCall(WinterlockOwner.revokeDevice, (device, generation, sig)));
    }

    function _certificate(address safe, bytes32 root, uint8 height, uint64 start) internal view returns (bytes memory) {
        return StatelessSigner.sign(sk, owner.certificateDigest(safe, 0, 0, root, height, start));
    }

    function _root(address safe) internal view returns (bytes32 root) {
        (root,,,,) = owner.tree(safe, 0);
    }

    function _rootOf(address safe, uint8 device) internal view returns (bytes32 root) {
        (root,,,,) = owner.tree(safe, device);
    }

    function _device(uint8 device) internal view returns (bytes32 key, uint16 generation, bool active) {
        return owner.devices(device);
    }

    // --- construction ---

    /// The implementation checks the parameter set and both verifiers; the factory checks each member's key and that
    /// its implementation is one.
    /// The contracts are created with CREATE (_create), not `new` under vm.expectRevert: Forge's test preprocessing
    /// turns `new` into vm.deployCode, and an expected revert of that cheatcode ends the test as passed, so the checks
    /// after the first one never ran (seen with Forge 1.8.3).
    function test_constructorChecks() public {
        IStatelessVerifier verifier = owner.STATELESS_VERIFIER();
        IWotsVerifier wots = owner.WOTS_VERIFIER();
        bytes32 key = StatelessSigner.publicKey(sk);
        bytes memory invalidConfig = abi.encodeWithSelector(WinterlockOwner.InvalidConfig.selector);
        // 32-byte hashes need two slots per tree
        assertEq(_create(_implInit(Ops.params(WotsParams(32, 560, 4, 0)), verifier, wots)), invalidConfig);
        // no verifier code
        assertEq(_create(_implInit(Ops.params(_p()), IStatelessVerifier(makeAddr("nothing")), wots)), invalidConfig);
        assertEq(_create(_implInit(Ops.params(_p()), verifier, IWotsVerifier(makeAddr("nothing")))), invalidConfig);
        assertEq(_create(_implInit(Ops.params(_p()), verifier, wots)), ""); // control

        bytes memory invalidImpl = abi.encodeWithSelector(WinterlockOwnerFactory.InvalidImplementation.selector);
        assertEq(_create(_factoryInit(address(owner))), invalidImpl); // a member's proxy
        assertEq(_create(_factoryInit(makeAddr("nothing"))), invalidImpl); // no code
        assertEq(_create(_factoryInit(address(impl))), ""); // control

        vm.expectRevert(WinterlockOwnerFactory.InvalidKey.selector); // no public parameter
        factory.deploy(key & bytes32(StatelessSigner.HIGH));
        vm.expectRevert(WinterlockOwnerFactory.InvalidKey.selector); // no root
        factory.deploy(key >> 128);
        assertEq(owner.KEY(), key);
        assertEq(address(owner.WOTS_VERIFIER()), SafeOwnerDeployment.predictWotsVerifier());
    }

    function _implInit(uint256 params, IStatelessVerifier verifier, IWotsVerifier wots)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(type(WinterlockOwner).creationCode, abi.encode(params, verifier, wots));
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
    /// reads its own key, and the trees and devices live in its storage, not in the implementation's: _trees at slot
    /// 0 (four words per Safe, one per device), then _devices from slot 1 (key and state per device).
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
        assertTrue(_certify(_laptop(2, 1)));
        assertTrue(_enrollDevice(_laptop(2, 1), safeA, 0));
        bytes32 slot = keccak256(abi.encode(safeA, uint256(0))); // _trees[safeA][0]
        assertTrue(vm.load(address(owner), slot) != 0);
        assertTrue(vm.load(address(owner), bytes32(uint256(slot) + 2)) != 0, "device 2's tree");
        assertEq(vm.load(address(owner), bytes32(uint256(1 + 2 * 2))), StatelessSigner.publicKey(laptopKey));
        assertEq(uint256(vm.load(address(owner), bytes32(uint256(2 + 2 * 2)))), 1 | ACTIVE);
        assertEq(vm.load(address(impl), slot), 0);
        assertEq(vm.load(address(impl), bytes32(uint256(5))), 0);
        (bytes32 root,,,,) = impl.tree(safeA, 0);
        assertEq(root, 0);
        (bytes32 implDeviceKey,,) = impl.devices(2);
        assertEq(implDeviceKey, 0);

        // another member's proxy of the same implementation reads its own key
        bytes32 other = keccak256("another member") | bytes32(uint256(1));
        WinterlockOwner second = WinterlockOwner(factory.deploy(other));
        assertEq(second.KEY(), other);
        assertEq(owner.KEY(), key);
    }

    /// Called directly, the implementation has no key (KEY() is 0): it refuses every certificate, device or tree, so
    /// it never holds a device or a tree and refuses every transaction signature, and it refuses every message
    /// signature. So does a proxy without a key, which only a deployer other than the factory can make.
    function test_implementationHarmless() public {
        assertEq(impl.KEY(), bytes32(0));
        (bytes32 k0,, bool active0) = impl.devices(0);
        assertEq(k0, 0);
        assertFalse(active0);
        WotsKey memory t = OwnerSigner.opsTree(_p(), Member(LABEL, sk, impl), safeA, 0, H, H);
        bytes memory cert = StatelessSigner.sign(sk, impl.certificateDigest(safeA, 0, 0, t.root, uint8(H), 0));
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        impl.enroll(safeA, 0, t.root, uint8(H), 0, cert);
        (bytes32 root,,,,) = impl.tree(safeA, 0);
        assertEq(root, 0);
        bytes memory dcert = OwnerSigner.deviceCertificate(Member(LABEL, sk, impl), _laptop(1, 1));
        bytes32 laptop = StatelessSigner.publicKey(laptopKey);
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        impl.certifyDevice(1, 1, laptop, dcert);

        // a SafeMessage of safeA, signed for the implementation and for the member's proxy by the member key
        bytes32 msgHash = keccak256("message");
        bytes32 safeMsgHash = _safeMessageHash(safeA, msgHash);
        assertEq(impl.isValidSignature(safeMsgHash, _messageSig(impl, safeA, msgHash, safeMsgHash)), INVALID);
        assertEq(owner.isValidSignature(safeMsgHash, _messageSig(owner, safeA, msgHash, safeMsgHash)), MAGIC); // control

        // proxies without a key: a zero key, and no key at all (a plain ERC-1167 proxy)
        _expectKeyless(WinterlockOwner(LibClone.clone(address(impl), abi.encodePacked(bytes32(0)))), t.root);
        _expectKeyless(WinterlockOwner(LibClone.clone(address(impl))), t.root);
    }

    /// `k`, a proxy without a key, refuses the member key's message signature, tree certificate and device certificate
    function _expectKeyless(WinterlockOwner k, bytes32 root) internal {
        bytes32 msgHash = keccak256("message");
        bytes32 safeMsgHash = _safeMessageHash(safeA, msgHash);
        assertEq(k.KEY(), bytes32(0));
        assertEq(k.isValidSignature(safeMsgHash, _messageSig(k, safeA, msgHash, safeMsgHash)), INVALID);
        bytes memory c = StatelessSigner.sign(sk, k.certificateDigest(safeA, 0, 0, root, uint8(H), 0));
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        k.enroll(safeA, 0, root, uint8(H), 0, c);
        c = OwnerSigner.deviceCertificate(Member(LABEL, sk, k), _laptop(1, 1));
        bytes32 laptop = StatelessSigner.publicKey(laptopKey);
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        k.certifyDevice(1, 1, laptop, c);
    }

    function _safeMessageHash(address safe, bytes32 msgHash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(keccak256("SafeMessage(bytes message)"), msgHash));
        return keccak256(abi.encodePacked(bytes2(0x1901), _safeDomain(safe), structHash));
    }

    function _safeTxHash(address safe, SafeTx memory t) internal view returns (bytes32) {
        bytes32 typeHash = keccak256(
            "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
        );
        bytes32 structHash = keccak256(bytes.concat(typeHash, SafeHarness.words(t)));
        return keccak256(abi.encodePacked(bytes2(0x1901), _safeDomain(safe), structHash));
    }

    function _safeDomain(address safe) internal view returns (bytes32) {
        return keccak256(
            abi.encode(keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), block.chainid, safe)
        );
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
    /// tree (device 0) in one transaction, from a certificate signed for the owner's predicted address; a refused
    /// certificate reverts the whole. On an existing owner it only enrols.
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
        emit WinterlockOwner.Enrolled(safeA, 0, 0, t.root, uint8(H), 0);
        assertEq(f16.deployAndEnroll(key, safeA, t.root, uint8(H), 0, cert), predicted);
        _expectTree(predicted, t.root, 0);

        // on the existing owner: a rotation
        WotsKey memory t3 = OwnerSigner.opsTree(p16, m, safeA, 3, H, H);
        cert = OwnerSigner.certificate(m, t3, safeA, 3);
        assertEq(f16.deployAndEnroll(key, safeA, t3.root, uint8(H), 3, cert), predicted);
        _expectTree(predicted, t3.root, 3);
    }

    function _expectTree(address o, bytes32 root, uint64 start) internal view {
        (bytes32 r,, uint8 h, uint64 s, uint16 g) = WinterlockOwner(o).tree(safeA, 0);
        assertEq(r, root);
        assertEq(h, H);
        assertEq(s, start);
        assertEq(g, 0);
    }

    // --- devices ---

    /// The member key certifies a device key: the device becomes active at generation 1, with its key, and anyone may
    /// send the certificate. Device 0 is the member key, active at generation 0; devices never certified are empty,
    /// and there is no device above 3.
    function test_certifyDevice() public {
        bytes32 laptop = StatelessSigner.publicKey(laptopKey);
        bytes memory cert = OwnerSigner.deviceCertificate(_member(), _laptop(1, 1));
        vm.expectEmit(address(owner));
        emit WinterlockOwner.DeviceCertified(1, 1, laptop);
        vm.prank(makeAddr("relayer"));
        owner.certifyDevice(1, 1, laptop, cert);

        (bytes32 key, uint16 generation, bool active) = _device(1);
        assertEq(key, laptop);
        assertEq(generation, 1);
        assertTrue(active);
        (key, generation, active) = _device(0);
        assertEq(key, owner.KEY());
        assertEq(generation, 0);
        assertTrue(active);
        (key, generation, active) = _device(2);
        assertEq(key, 0);
        assertEq(generation, 0);
        assertFalse(active);
        vm.expectRevert(); // out of range
        owner.devices(4);
    }

    /// A device certificate counts only if the member key signed it for this chain, this owner, this device, this
    /// generation (the stored one plus one) and this key, with both halves of the key set. Device 0 and devices above
    /// 3 can't be certified, a device key can't certify (itself or another), and a certificate can't be used twice.
    function test_certifyDeviceRefused() public {
        DeviceKey memory d = _laptop(1, 1);
        bytes32 laptop = StatelessSigner.publicKey(laptopKey);
        bytes[] memory refused = new bytes[](9);
        // another chain
        uint256 here = block.chainid;
        vm.chainId(42161);
        refused[0] = OwnerSigner.deviceCertificate(_member(), d);
        vm.chainId(here);
        // another owner with the same member key (another parameter set)
        WinterlockOwner twin = WinterlockOwner(
            SafeOwnerDeployment.deploy(Ops.params(WotsParams(16, 300, 4, 0)), StatelessSigner.publicKey(sk))
        );
        refused[1] = StatelessSigner.sign(sk, twin.deviceDigest(1, 1, laptop));
        // another device, another generation, another key
        refused[2] = StatelessSigner.sign(sk, owner.deviceDigest(2, 1, laptop));
        refused[3] = StatelessSigner.sign(sk, owner.deviceDigest(1, 2, laptop));
        refused[4] = StatelessSigner.sign(sk, owner.deviceDigest(1, 1, StatelessSigner.publicKey(phoneKey)));
        // signed by the device key itself, and by another key
        refused[5] = StatelessSigner.sign(laptopKey, owner.deviceDigest(1, 1, laptop));
        refused[6] = StatelessSigner.sign(StatelessSigner.testKey("mallory"), owner.deviceDigest(1, 1, laptop));
        // forged, and none
        refused[7] = OwnerSigner.deviceCertificate(_member(), d);
        refused[7][300] ^= 0x01;
        refused[8] = "";
        for (uint256 i; i < refused.length; ++i) {
            assertFalse(_certifyWith(d, refused[i]), vm.toString(i));
        }

        // generations other than stored + 1, with the member key's signature
        assertFalse(_certify(_laptop(1, 0)), "generation 0");
        assertFalse(_certify(_laptop(1, 2)), "generation 2");
        // device 0 (the member key) and devices above 3, signed by the member key
        assertFalse(_certify(_laptop(0, 1)), "device 0");
        assertFalse(_certify(_laptop(4, 1)), "device 4");
        assertFalse(_certify(_laptop(255, 1)), "device 255");
        // a key without a root or without a public parameter
        bytes32 noP = laptop & bytes32(StatelessSigner.HIGH);
        bytes memory cd = abi.encodeCall(
            WinterlockOwner.certifyDevice, (1, 1, noP, StatelessSigner.sign(sk, owner.deviceDigest(1, 1, noP)))
        );
        (bool ok,) = address(owner).call(cd);
        assertFalse(ok, "no public parameter");
        bytes32 noRoot = laptop >> 128;
        cd = abi.encodeCall(
            WinterlockOwner.certifyDevice, (1, 1, noRoot, StatelessSigner.sign(sk, owner.deviceDigest(1, 1, noRoot)))
        );
        (ok,) = address(owner).call(cd);
        assertFalse(ok, "no root");
        (,, bool active) = _device(1);
        assertFalse(active, "nothing stored");

        bytes memory cert = OwnerSigner.deviceCertificate(_member(), d);
        assertTrue(_certifyWith(d, cert)); // control
        assertFalse(_certifyWith(d, cert), "the same certificate again");
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        owner.certifyDevice(1, 1, laptop, cert);
    }

    /// The member key revokes an active device at its generation: the device turns inactive and keeps its generation
    /// and key. Only the member key's revocation for that device and generation counts; device 0 and devices above 3
    /// can't be revoked, nor can a device that isn't active.
    function test_revokeDevice() public {
        assertTrue(_certify(_laptop(1, 1)));
        assertFalse(_revoke(2, 0, OwnerSigner.revocation(_member(), 2, 0)), "never certified");
        assertFalse(_revoke(0, 0, OwnerSigner.revocation(_member(), 0, 0)), "device 0");
        assertFalse(_revoke(4, 0, OwnerSigner.revocation(_member(), 4, 0)), "device 4");
        assertFalse(_revoke(1, 2, OwnerSigner.revocation(_member(), 1, 2)), "a later generation");
        assertFalse(_revoke(1, 0, OwnerSigner.revocation(_member(), 1, 0)), "an earlier generation");
        assertFalse(_revoke(1, 1, OwnerSigner.revocation(_member(), 2, 1)), "for another device");
        assertFalse(_revoke(1, 1, StatelessSigner.sign(laptopKey, owner.revocationDigest(1, 1))), "by the device");
        bytes memory mallory = StatelessSigner.sign(StatelessSigner.testKey("mallory"), owner.revocationDigest(1, 1));
        assertFalse(_revoke(1, 1, mallory), "by another key");
        // a device certificate is not a revocation
        assertFalse(_revoke(1, 1, OwnerSigner.deviceCertificate(_member(), _laptop(1, 1))), "a certificate");
        uint256 here = block.chainid;
        vm.chainId(42161);
        bytes memory elsewhere = OwnerSigner.revocation(_member(), 1, 1);
        vm.chainId(here);
        assertFalse(_revoke(1, 1, elsewhere), "another chain");
        bytes memory forged = OwnerSigner.revocation(_member(), 1, 1);
        forged[300] ^= 0x01;
        assertFalse(_revoke(1, 1, forged), "forged");
        (,, bool active) = _device(1);
        assertTrue(active);

        bytes memory revocation = OwnerSigner.revocation(_member(), 1, 1);
        vm.expectEmit(address(owner));
        emit WinterlockOwner.DeviceRevoked(1, 1);
        vm.prank(makeAddr("relayer"));
        owner.revokeDevice(1, 1, revocation);
        (bytes32 key, uint16 generation, bool stillActive) = _device(1);
        assertEq(key, StatelessSigner.publicKey(laptopKey));
        assertEq(generation, 1);
        assertFalse(stillActive);
        vm.expectRevert(WinterlockOwner.InvalidRevocation.selector);
        owner.revokeDevice(1, 1, revocation); // again
    }

    /// Generations: after a revoke, the device is certified again at the next generation, never with an old
    /// certificate; an old revocation can't revoke the new generation. Certifying an active device replaces its key.
    function test_recertifyAndReplace() public {
        bytes memory cert1 = OwnerSigner.deviceCertificate(_member(), _laptop(1, 1));
        assertTrue(_certifyWith(_laptop(1, 1), cert1));
        bytes memory revocation1 = OwnerSigner.revocation(_member(), 1, 1);
        assertTrue(_revoke(1, 1, revocation1));

        assertFalse(_certifyWith(_laptop(1, 1), cert1), "the old certificate");
        assertTrue(_certify(_laptop(1, 2)), "the same key, generation 2");
        assertFalse(_revoke(1, 1, revocation1), "the old revocation");
        (bytes32 key, uint16 generation, bool active) = _device(1);
        assertEq(key, StatelessSigner.publicKey(laptopKey));
        assertEq(generation, 2);
        assertTrue(active);

        // replace while active: the phone's key at generation 3
        vm.expectEmit(address(owner));
        emit WinterlockOwner.DeviceCertified(1, 3, StatelessSigner.publicKey(phoneKey));
        assertTrue(_certify(_phone(1, 3)));
        (key, generation, active) = _device(1);
        assertEq(key, StatelessSigner.publicKey(phoneKey));
        assertEq(generation, 3);
        assertTrue(active);
        assertFalse(_certify(_laptop(1, 2)), "generation 2 again");
        assertFalse(_revoke(1, 2, OwnerSigner.revocation(_member(), 1, 2)), "revoking generation 2");
        // other devices are independent
        assertTrue(_certify(_laptop(2, 1)));
        assertTrue(_certify(_laptop(3, 1)), "the same key on two devices");
    }

    /// A device key enrols its own trees: one word per Safe and device, with the device's generation. The member key
    /// can't certify a device's tree, a device key can't certify another device's tree or device 0's, and a device
    /// that isn't active, or a certificate for another generation, is refused.
    function test_enrollByDevice() public {
        assertFalse(_enrollDevice(_laptop(1, 1), safeA, 0), "not certified yet");
        assertTrue(_certify(_laptop(1, 1)));
        DeviceKey memory d = _laptop(1, 1);
        WotsKey memory t = _treeOf(d, safeA, 3);
        vm.expectEmit(address(owner));
        emit WinterlockOwner.Enrolled(safeA, 1, 1, t.root, uint8(H), 3);
        assertTrue(_enrollAs(safeA, 1, t, 3, OwnerSigner.certificate(d, t, safeA, 3)));

        (bytes32 root, uint128 seed, uint8 height, uint64 start, uint16 generation) = owner.tree(safeA, 1);
        assertEq(root, t.root);
        assertEq(height, H);
        assertEq(start, 3);
        assertEq(generation, 1);
        bytes32 seedHash = keccak256(
            abi.encode(
                keccak256("Winterlock.safe-owner.tree-seed.v2"),
                block.chainid,
                address(owner),
                safeA,
                uint8(1),
                uint16(1),
                uint64(3)
            )
        );
        assertEq(seed, uint128(bytes16(seedHash)));
        assertEq(seed, t.seed);
        bytes32 word = vm.load(address(owner), bytes32(uint256(keccak256(abi.encode(safeA, uint256(0)))) + 1));
        assertEq(uint256(word), uint256(t.root) | (1 << 48) | (3 << 8) | H);
        assertEq(_root(safeA), bytes32(0), "device 0 has none");
        assertEq(_rootOf(safeB, 1), bytes32(0), "per Safe");

        // wrong signers and devices, each with a fresh tree at a later start
        WotsKey memory t5 = _treeOf(d, safeA, 5);
        bytes memory byMember =
            StatelessSigner.sign(sk, owner.certificateDigest(safeA, 1, 1, t5.root, uint8(H), uint64(5)));
        assertFalse(_enrollAs(safeA, 1, t5, 5, byMember), "the member key for device 1");
        WotsKey memory t0 = _tree(safeA, 5);
        bytes memory forZero =
            StatelessSigner.sign(laptopKey, owner.certificateDigest(safeA, 0, 0, t0.root, uint8(H), uint64(5)));
        assertFalse(_enrollAs(safeA, 0, t0, 5, forZero), "the device key for device 0");
        assertFalse(_enrollDevice(_laptop(2, 0), safeA, 5), "device 2, not certified");
        assertTrue(_certify(_phone(2, 1)));
        assertFalse(_enrollDevice(_laptop(2, 1), safeA, 5), "the laptop's key for the phone's device");
        assertFalse(_enrollDevice(_laptop(4, 0), safeA, 5), "device 4");
        assertFalse(_enrollDevice(_laptop(1, 2), safeA, 5), "a later generation");
        assertFalse(_enrollDevice(_laptop(1, 0), safeA, 5), "an earlier generation");
        assertTrue(_enrollDevice(_phone(2, 1), safeA, 5), "control: the phone");
        assertTrue(_enrollDevice(d, safeA, 5), "control: the laptop");
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        owner.enroll(safeA, 4, t5.root, uint8(H), 5, "");

        // revoked: its key can't enrol any more
        assertTrue(_revoke(1, 1, OwnerSigner.revocation(_member(), 1, 1)));
        assertFalse(_enrollDevice(d, safeA, 9), "revoked");
        // replaced by the phone's key at generation 2: the laptop's key can't enrol at either generation
        assertTrue(_certify(_phone(1, 2)));
        assertFalse(_enrollDevice(_laptop(1, 1), safeA, 9), "replaced, old generation");
        assertFalse(_enrollDevice(_laptop(1, 2), safeA, 9), "replaced, new generation");
        assertTrue(_enrollDevice(_phone(1, 2), safeA, 9), "control: the new key");
    }

    /// Start nonces only grow per Safe and device within a generation. A tree from an earlier generation sets no
    /// bound, and its certificates can't come back under the new one. Devices don't bound each other.
    function test_startRulesAcrossGenerations() public {
        assertTrue(_certify(_laptop(1, 1)));
        DeviceKey memory g1 = _laptop(1, 1);
        assertTrue(_enrollDevice(g1, safeA, 5));
        assertFalse(_enrollDevice(g1, safeA, 5), "the same start");
        assertFalse(_enrollDevice(g1, safeA, 3), "an earlier start");
        WotsKey memory t20 = _treeOf(g1, safeA, 20);
        bytes memory cert20 = OwnerSigner.certificate(g1, t20, safeA, 20); // signed now, used later
        assertTrue(_enrollDevice(g1, safeA, 9));
        // device 0 and device 2 start low again: independent
        WotsKey memory t0 = _tree(safeA, 0);
        assertTrue(_enroll(safeA, t0, 0, OwnerSigner.certificate(_member(), t0, safeA, 0)));
        assertTrue(_certify(_phone(2, 1)));
        assertTrue(_enrollDevice(_phone(2, 1), safeA, 1));

        // generation 2 (the same key, after a revoke): start 0 is accepted, below the old tree's 9
        assertTrue(_revoke(1, 1, OwnerSigner.revocation(_member(), 1, 1)));
        assertTrue(_certify(_laptop(1, 2)));
        DeviceKey memory g2 = _laptop(1, 2);
        assertTrue(_enrollDevice(g2, safeA, 0));
        (,,, uint64 start, uint16 generation) = owner.tree(safeA, 1);
        assertEq(start, 0);
        assertEq(generation, 2);
        assertFalse(_enrollAs(safeA, 1, t20, 20, cert20), "a generation-1 certificate");
        assertFalse(_enrollDevice(g2, safeA, 0), "start 0 again within generation 2");
        assertTrue(_enrollDevice(g2, safeA, 1));
        // generation 3 (replaced while active): start 0 again
        assertTrue(_certify(_phone(1, 3)));
        assertTrue(_enrollDevice(_phone(1, 3), safeA, 0));
    }

    // --- enrolment of device 0 ---

    /// One slot per tree: root in the high bytes, generation (16 bits, 0 for device 0), start (40 bits) and height
    /// (8 bits) below. The seed is derived from the chain, the owner, the Safe, the device, the generation and the
    /// start.
    function test_enrolStoresPackedTree() public {
        WotsKey memory t = _tree(safeA, 3);
        bytes memory cert = OwnerSigner.certificate(_member(), t, safeA, 3);
        vm.expectEmit(address(owner));
        emit WinterlockOwner.Enrolled(safeA, 0, 0, t.root, uint8(H), 3);
        assertTrue(_enroll(safeA, t, 3, cert));

        (bytes32 root, uint128 seed, uint8 height, uint64 start, uint16 generation) = owner.tree(safeA, 0);
        assertEq(root, t.root);
        assertEq(height, H);
        assertEq(start, 3);
        assertEq(generation, 0);
        bytes32 seedHash = keccak256(
            abi.encode(
                keccak256("Winterlock.safe-owner.tree-seed.v2"),
                block.chainid,
                address(owner),
                safeA,
                uint8(0),
                uint16(0),
                uint64(3)
            )
        );
        assertEq(seed, uint128(bytes16(seedHash)));
        assertEq(seed, t.seed);
        bytes32 word = vm.load(address(owner), keccak256(abi.encode(safeA, uint256(0)))); // _trees[safeA][0]
        assertEq(uint256(word), uint256(t.root) | (3 << 8) | H);
        assertEq(_root(safeB), bytes32(0), "per Safe");
        assertEq(_rootOf(safeA, 1), bytes32(0), "per device");
    }

    /// The certificate binds the chain, the owner contract, the Safe, the device and its generation, and must be
    /// signed by the device's key, here the member key. Only valid certificates are stored.
    function test_certificateBindings() public {
        WotsKey memory t = _tree(safeA, 0);
        bytes[] memory refused = _wrongCertificates(t.root);
        for (uint256 i; i < refused.length; ++i) {
            assertFalse(_enroll(safeA, t, 0, refused[i]), vm.toString(i));
        }
        assertEq(_root(safeA), bytes32(0), "nothing stored");
        assertTrue(_enroll(safeA, t, 0, _certificate(safeA, t.root, uint8(H), 0))); // control
        assertEq(_root(safeA), t.root);
    }

    /// Certificates for `root` (height H, start 0, safeA, device 0) that this owner on this chain must refuse
    function _wrongCertificates(bytes32 root) internal returns (bytes[] memory c) {
        uint8 h = uint8(H);
        c = new bytes[](9);
        // another chain
        uint256 here = block.chainid;
        vm.chainId(42161);
        c[0] = _certificate(safeA, root, h, 0);
        vm.chainId(here);
        // another owner contract with the same key (another parameter set)
        WinterlockOwner twin = WinterlockOwner(
            SafeOwnerDeployment.deploy(Ops.params(WotsParams(16, 300, 4, 0)), StatelessSigner.publicKey(sk))
        );
        c[1] = StatelessSigner.sign(sk, twin.certificateDigest(safeA, 0, 0, root, h, 0));
        // another Safe, another device, another generation
        c[2] = _certificate(safeB, root, h, 0);
        c[3] = StatelessSigner.sign(sk, owner.certificateDigest(safeA, 1, 0, root, h, 0));
        c[4] = StatelessSigner.sign(sk, owner.certificateDigest(safeA, 0, 1, root, h, 0));
        // another key
        c[5] =
            StatelessSigner.sign(StatelessSigner.testKey("mallory"), owner.certificateDigest(safeA, 0, 0, root, h, 0));
        // a message digest over the same words is not a certificate
        c[6] = StatelessSigner.sign(sk, owner.messageDigest(safeA, 0, 0, root));
        // a forged signature, and none
        c[7] = _certificate(safeA, root, h, 0);
        c[7][200] ^= 0x01;
        c[8] = "";
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
        bytes32 lowBytes = root | bytes32(uint256(1 << 48)); // would set a generation bit
        _expectRefused(lowBytes, 4, 0);
        _expectRefused(root | bytes32(uint256(1 << 8)), 4, 0); // would set a start bit
        _expectRefused(bytes32(0), 4, 0);
        _expectRefused(root, 0, 0);
        _expectRefused(root, 41, 0);
        uint64 maxStart = uint64(owner.MAX_START());
        _expectRefused(root, 4, maxStart + 1);
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        owner.enroll(safeA, 0, root, 4, 0, new bytes(5684)); // the verifier reverts on garbage: refused, not bubbled
        owner.enroll(safeA, 0, root, 40, maxStart, _certificate(safeA, root, 40, maxStart));
        (,, uint8 height, uint64 start,) = owner.tree(safeA, 0);
        assertEq(height, 40);
        assertEq(start, maxStart);
    }

    function _expectRefused(bytes32 root, uint8 height, uint64 start) internal {
        bytes memory sig = _certificate(safeA, root, height, start);
        vm.expectRevert(WinterlockOwner.InvalidCertificate.selector);
        owner.enroll(safeA, 0, root, height, start, sig);
    }

    // --- signatures ---

    /// Malformed signatures, devices above 3 and Safes without a tree get the failure value from both entry points,
    /// never a revert, so Safe reports GS024 and the Transaction Service a plain rejection.
    function test_malformedSignaturesInvalid() public {
        bytes32 h = keccak256("hash");
        SignedMessagesStub stub = new SignedMessagesStub();
        stub.approve(h);
        bytes[] memory sigs = new bytes[](13);
        sigs[0] = "";
        sigs[1] = abi.encodePacked(uint8(0), uint8(0), safeA); // transaction kind, too short
        sigs[2] = abi.encodePacked(uint8(4), uint8(0), safeA, new bytes(2000)); // unknown kind
        sigs[3] = abi.encodePacked(uint8(2), uint8(0), safeA, new bytes(100)); // message, too short
        sigs[4] = abi.encodePacked(uint8(2), uint8(0), safeA, new bytes(32 + 5684)); // message, wrong hash
        sigs[5] = abi.encodePacked(uint8(1), uint8(0), safeA, new bytes(320 + 1176 + 24 * H));
        sigs[6] = abi.encodePacked(uint8(0), uint8(4), safeA, new bytes(320 + 1176 + 24 * H)); // device 4
        sigs[7] = abi.encodePacked(uint8(2), uint8(255), safeA, new bytes(32 + 5684)); // device 255
        sigs[8] = abi.encodePacked(uint8(0), uint8(1), safeA, new bytes(320 + 1176 + 24 * H)); // device 1, no tree
        sigs[9] = abi.encodePacked(uint8(3), address(stub)); // approved, too short
        sigs[10] = abi.encodePacked(uint8(3), address(stub), bytes32(0), uint8(0)); // approved, too long
        sigs[11] = abi.encodePacked(uint8(3), address(stub), bytes32(0)); // approved, not the hash's message
        sigs[12] = abi.encodePacked(uint8(3), uint8(0), address(stub), bytes32(0)); // approved with a device byte
        WotsKey memory t = _tree(safeA, 0);
        assertTrue(_enroll(safeA, t, 0, OwnerSigner.certificate(_member(), t, safeA, 0)));
        for (uint256 i; i < sigs.length; ++i) {
            assertEq(owner.isValidSignature(h, sigs[i]), INVALID, vm.toString(i));
            assertEq(owner.isValidSignature(abi.encodePacked(h), sigs[i]), INVALID, vm.toString(i));
        }
    }

    /// A device's transaction and message signatures, for a stand-in Safe address (the owner recomputes Safe's hashes,
    /// so no Safe is needed): valid while the device is active at the generation they were made under, refused under
    /// another device number, and refused, including ones made before, once the device is revoked or replaced.
    function test_deviceSignaturesFollowDeviceState() public {
        assertTrue(_certify(_laptop(1, 1)));
        DeviceKey memory d = _laptop(1, 1);
        WotsKey memory t = _treeOf(d, safeA, 0);
        assertTrue(_enrollAs(safeA, 1, t, 0, OwnerSigner.certificate(d, t, safeA, 0)));
        SafeTx memory stx = SafeHarness.transfer(makeAddr("recipient"), 1 ether, 0);
        bytes32 txHash = _safeTxHash(safeA, stx);
        bytes memory txSig = OwnerSigner.txSignature(t, 1, 0, 0, safeA, stx, txHash);
        bytes32 msgHash = keccak256("message");
        bytes32 safeMsgHash = _safeMessageHash(safeA, msgHash);
        bytes memory msgSig = OwnerSigner.messageSignature(d, safeA, msgHash, safeMsgHash);
        assertEq(owner.isValidSignature(txHash, txSig), MAGIC);
        assertEq(owner.isValidSignature(safeMsgHash, msgSig), MAGIC);
        assertEq(owner.isValidSignature(_preimage(safeA, safeMsgHash, msgHash), msgSig), LEGACY_MAGIC);

        // the same signatures under device 0 and device 2 (certified with the same key: devices are bound too)
        assertTrue(_certify(_laptop(2, 1)));
        for (uint8 other; other < 3; other += 2) {
            bytes memory txOther = bytes.concat(txSig);
            txOther[1] = bytes1(other);
            bytes memory msgOther = bytes.concat(msgSig);
            msgOther[1] = bytes1(other);
            assertEq(owner.isValidSignature(txHash, txOther), INVALID);
            assertEq(owner.isValidSignature(safeMsgHash, msgOther), INVALID);
        }

        // revoked: both stop verifying
        assertTrue(_revoke(1, 1, OwnerSigner.revocation(_member(), 1, 1)));
        assertEq(owner.isValidSignature(txHash, txSig), INVALID, "revoked: transaction");
        assertEq(owner.isValidSignature(safeMsgHash, msgSig), INVALID, "revoked: message");
        // certified again with the same key, generation 2: what generation 1 signed stays refused; the tree must be
        // enrolled again, and messages are signed for generation 2
        assertTrue(_certify(_laptop(1, 2)));
        assertEq(owner.isValidSignature(txHash, txSig), INVALID, "generation 1's tree");
        assertEq(owner.isValidSignature(safeMsgHash, msgSig), INVALID, "generation 1's message");
        DeviceKey memory d2 = _laptop(1, 2);
        assertEq(
            owner.isValidSignature(safeMsgHash, OwnerSigner.messageSignature(d2, safeA, msgHash, safeMsgHash)), MAGIC
        );
        WotsKey memory t2 = _treeOf(d2, safeA, 0);
        assertTrue(_enrollAs(safeA, 1, t2, 0, OwnerSigner.certificate(d2, t2, safeA, 0)));
        bytes memory txSig2 = OwnerSigner.txSignature(t2, 1, 0, 0, safeA, stx, txHash);
        assertEq(owner.isValidSignature(txHash, txSig2), MAGIC);
        assertTrue(keccak256(txSig2) != keccak256(txSig), "another tree, other keys");
        // replaced by the phone's key: the laptop's tree and messages stop verifying
        assertTrue(_certify(_phone(1, 3)));
        assertEq(owner.isValidSignature(txHash, txSig2), INVALID, "replaced: transaction");
        bytes memory msgSig2 = OwnerSigner.messageSignature(d2, safeA, msgHash, safeMsgHash);
        assertEq(owner.isValidSignature(safeMsgHash, msgSig2), INVALID, "replaced: message");
        bytes memory phoneMsg = OwnerSigner.messageSignature(_phone(1, 3), safeA, msgHash, safeMsgHash);
        assertEq(owner.isValidSignature(safeMsgHash, phoneMsg), MAGIC);
    }

    /// keccak256 preimage of a SafeMessage hash, as Safe v1.4.1 passes it to the legacy entry point
    function _preimage(address safe, bytes32 safeMsgHash, bytes32 msgHash) internal view returns (bytes memory pre) {
        bytes32 structHash = keccak256(abi.encode(keccak256("SafeMessage(bytes message)"), msgHash));
        pre = abi.encodePacked(bytes2(0x1901), _safeDomain(safe), structHash);
        assertEq(keccak256(pre), safeMsgHash);
    }

    /// The approved kind against stand-ins for a Safe: valid only for the named contract's own SafeMessage hash, and
    /// only once signedMessages answers nonzero. An address without code, a precompile, a revert or a short answer is
    /// not an approval. A mismatching Safe or hash is refused.
    function test_approvedKind() public {
        SignedMessagesStub stub = new SignedMessagesStub();
        SignedMessagesStub other = new SignedMessagesStub();
        bytes32 msgHash = keccak256(abi.encode(keccak256("permit")));
        bytes32 h = _safeMessageHash(address(stub), msgHash);
        bytes memory sig = OwnerSigner.approvedSignature(address(stub), msgHash);
        assertEq(sig.length, 53);
        assertEq(owner.isValidSignature(h, sig), INVALID, "not approved yet");
        stub.approve(h);
        assertEq(owner.isValidSignature(h, sig), MAGIC);
        assertEq(owner.isValidSignature(_preimage(address(stub), h, msgHash), sig), LEGACY_MAGIC);
        // on the implementation and on a keyless proxy too: no key is involved
        assertEq(impl.isValidSignature(h, sig), MAGIC);

        // a mismatching Safe or hash
        other.approve(_safeMessageHash(address(other), msgHash));
        assertEq(owner.isValidSignature(h, OwnerSigner.approvedSignature(address(other), msgHash)), INVALID, "Safe");
        assertEq(owner.isValidSignature(keccak256("another hash"), sig), INVALID, "hash");
        bytes32 otherMsg = keccak256("another message");
        assertEq(owner.isValidSignature(h, OwnerSigner.approvedSignature(address(stub), otherMsg)), INVALID, "msg");
        // approved for one hash, asked about another the stub also approved: still the SafeMessage check first
        stub.approve(keccak256("a hash that is no SafeMessage"));
        assertEq(owner.isValidSignature(keccak256("a hash that is no SafeMessage"), sig), INVALID);

        // contracts that don't answer with a word, and accounts without code
        address[4] memory notSafes =
            [address(new RevertingSafeStub()), address(new ShortAnswerStub()), makeAddr("an account"), address(2)];
        for (uint256 i; i < notSafes.length; ++i) {
            bytes32 hi = _safeMessageHash(notSafes[i], msgHash);
            assertEq(owner.isValidSignature(hi, OwnerSigner.approvedSignature(notSafes[i], msgHash)), INVALID);
        }
    }

    /// The things the member key and device keys sign for an owner have their own domains; none can stand in for
    /// another, for v1's or for WinterlockValidator's.
    function test_domainsDistinct() public view {
        bytes32[5] memory domains = [
            owner.DEVICE_DOMAIN(),
            owner.REVOCATION_DOMAIN(),
            owner.CERTIFICATE_DOMAIN(),
            owner.MESSAGE_DOMAIN(),
            owner.TREE_SEED_DOMAIN()
        ];
        for (uint256 i; i < 5; ++i) {
            for (uint256 j = i + 1; j < 5; ++j) {
                assertTrue(domains[i] != domains[j]);
            }
            assertTrue(domains[i] != keccak256("Winterlock.safe-owner.certificate.v1"));
            assertTrue(domains[i] != keccak256("Winterlock.safe-owner.message.v1"));
            assertTrue(domains[i] != keccak256("Winterlock.stateless-certificate.v1"));
        }
        bytes32 x = keccak256("x");
        assertTrue(owner.certificateDigest(safeA, 0, 0, x, 4, 0) != owner.messageDigest(safeA, 0, 0, x));
        assertTrue(owner.deviceDigest(1, 1, x) != owner.revocationDigest(1, 1));
    }

    /// The shared WOTS verifier gives the root WotsVerifier computes, for the owner's parameter set and others, and
    /// reverts on input it can't verify, which the owner counts as invalid.
    function test_sharedWotsVerifier() public {
        IWotsVerifier wots = owner.WOTS_VERIFIER();
        WotsKey memory t = _tree(safeA, 0);
        bytes32 m = keccak256("message");
        bytes memory sig = bytes.concat(WotsSigner.sign(_p(), t.seed, t.skSeed, 3, m), WotsTree.path(t, 3));
        assertEq(wots.computeRoot(Ops.params(_p()), t.seed, 3, m, sig), t.root);
        assertTrue(wots.computeRoot(Ops.params(_p()), t.seed, 2, m, sig) != t.root, "another key index");
        WotsParams memory p16 = WotsParams(16, 300, 4, 0);
        WotsKey memory t16 = WotsTree.create(p16, 7, keccak256("sk"), 3, 2);
        sig = bytes.concat(WotsSigner.sign(p16, 7, keccak256("sk"), 1, m), WotsTree.path(t16, 1));
        assertEq(wots.computeRoot(Ops.params(p16), 7, 1, m, sig), t16.root);
        vm.expectRevert(WotsVerifier.BadPathLength.selector);
        wots.computeRoot(Ops.params(p16), 7, 1, m, bytes.concat(sig, hex"00"));
        vm.expectRevert(); // shorter than a WOTS signature
        wots.computeRoot(Ops.params(p16), 7, 1, m, new bytes(10));
        vm.expectRevert(WotsVerifier.BadParams.selector); // hash function 2
        wots.computeRoot(Ops.params(p16) | (2 << 16), 7, 1, m, sig);
    }

    /// What calling the shared verifier adds to a WOTS verification (D6, a tree of height 10), against the verifier
    /// linked into the caller as in owner v1: the first call in a transaction meets the verifier's account cold.
    function test_gas_sharedWotsVerifier() public {
        WotsParams memory p = _p();
        WotsKey memory t = WotsTree.create(p, 7, keccak256("sk"), 10, 4);
        bytes32 m = keccak256("message");
        bytes memory sig = bytes.concat(WotsSigner.sign(p, 7, keccak256("sk"), 3, m), WotsTree.path(t, 3));
        WotsCallProbe probe = new WotsCallProbe();
        (uint256 linked, bytes32 r1) = probe.linked(Ops.params(p), 7, 3, m, sig);
        (uint256 first, uint256 second, bytes32 r2) = probe.shared(owner.WOTS_VERIFIER(), Ops.params(p), 7, 3, m, sig);
        assertEq(r1, t.root);
        assertEq(r2, t.root);
        console.log("WOTS verification, gas: linked in", linked);
        console.log("  through the shared verifier, first (cold)", first, ", more", first - linked);
        console.log("  through the shared verifier, then (warm)  ", second, ", more", second - linked);
    }

    // --- deterministic addresses ---

    /// The verifiers, the implementation and the factory: CREATE2 through the deterministic deployment proxy with
    /// fixed salts. The member's owner: CREATE2 by the factory, salt = the member key. The addresses depend on the
    /// key, the parameter set and the code, not on the chain.
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
        assertGt(SafeOwnerDeployment.predictWotsVerifier().code.length, 0);

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
