// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ISafe} from "safe-v1.5.0/interfaces/ISafe.sol";
import {IOwnerManager} from "safe-v1.5.0/interfaces/IOwnerManager.sol";

import {WinterlockOwner} from "../../src/safe/WinterlockOwner.sol";
import {WinterlockOwnerFactory} from "../../src/safe/WinterlockOwnerFactory.sol";
import {ValidatorDeployment} from "../../script/DeployValidator.s.sol";
import {SafeOwnerDeployment} from "../../script/DeploySafeOwner.s.sol";
import {WotsParams, WotsKey, Ops} from "../utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "../utils/StatelessSigner.sol";
import {FullWinterlockOwner} from "../utils/FullWinterlockOwner.sol";
import {
    SafeHarness,
    SafeRelease,
    SafeTx,
    OwnerSignature,
    Member,
    DeviceKey,
    OwnerSigner,
    IERC1271
} from "../utils/SafeHarness.sol";

contract TestToken is ERC20 {
    /// `other` gets 1 wei, so its balance is never zero (steady state for transfers to it)
    constructor(address holder, address other) ERC20("Test", "TST") {
        _mint(holder, 1_000_000 ether);
        _mint(other, 1);
    }
}

/// An app that checks a Safe's message signature on-chain, and measures the gas of that check
contract MessageCheckProbe {
    function check(address safe, bytes32 hash, bytes calldata sigs)
        external
        view
        returns (bytes4 result, uint256 used)
    {
        used = gasleft();
        result = IERC1271(safe).isValidSignature(hash, sigs);
        used -= gasleft();
    }
}

/// Checks two owners' signatures of one hash in one transaction and reports the gas of each check, the call included.
/// The first check meets every account cold; the second finds warm what the first touched, such as the implementation
/// behind two proxies. Not a view, so that Forge runs a call to it as a transaction of its own (isolate).
contract OwnerCheckProbe {
    function check(address a, bytes calldata sigA, address b, bytes calldata sigB, bytes32 hash)
        external
        returns (uint256 first, uint256 second)
    {
        first = gasleft();
        bytes4 ra = IERC1271(a).isValidSignature(hash, sigA);
        first -= gasleft();
        second = gasleft();
        bytes4 rb = IERC1271(b).isValidSignature(hash, sigB);
        second -= gasleft();
        require(ra == 0x1626ba7e && rb == 0x1626ba7e, "refused");
    }
}

/// An owner that accepts a signature only if the asking Safe's nonce equals the value in the signature: it shows
/// what an owner sees during execTransaction (question 2 of the Safe owner spike).
contract SafeNonceProbe {
    function isValidSignature(bytes32, bytes calldata sig) external view returns (bytes4) {
        return _expected(sig) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    function isValidSignature(bytes calldata, bytes calldata sig) external view returns (bytes4) {
        return _expected(sig) ? bytes4(0x20c13b0b) : bytes4(0xffffffff);
    }

    function _expected(bytes calldata sig) internal view returns (bool) {
        return ISafe(payable(msg.sender)).nonce() == abi.decode(sig, (uint256));
    }
}

/// Winterlock as Safe owners: three members' WinterlockOwners (v2) own a 2-of-3 Safe, checked by Safe's own multisig
/// path (contract signatures, v = 0). Each owner is a member's proxy of the shared implementation, created by the
/// factory (SafeOwnerDeployment). Members sign with their member keys (device 0) unless a test certifies device keys.
/// Safe's contracts come from their release builds (setup.sh). Parameter set D6.
/// Run once per Safe release by the contracts below.
abstract contract SafeWinterlockOwnerTest is Test {
    using SafeHarness for ISafe;

    SafeRelease internal rel;
    StatelessKey[3] internal sks; // members' stateless keys, kept: their keygen is costly
    WinterlockOwner[3] internal owners;
    ISafe internal safe; // 2-of-3 of the three owners
    TestToken internal token;

    address internal recipient = makeAddr("recipient");
    address internal relayer = makeAddr("relayer"); // sends enroll transactions; anyone may
    address internal app = makeAddr("app"); // asks the Safe to check a message (Permit2, a marketplace)

    /// Operation trees: height 10 (512 nonces x 2 slots), of which the first 16 keys are generated
    uint256 internal constant H = 10;
    uint256 internal constant K = 4;
    uint256 internal constant SEPOLIA = 11155111;
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant LEGACY_MAGIC = 0x20c13b0b;
    bytes4 internal constant INVALID = 0xffffffff;

    /// Calldata of the last transaction _txGas measured: bytes, and their gas at 4 per zero byte and 16 per other
    uint256 internal lastCalldataBytes;
    uint256 internal lastCalldataGas;
    /// State after the release's deployment and the members' keys, before any Winterlock contract (for the
    /// deployment gas)
    uint256 internal beforeOwners;

    function _version() internal pure virtual returns (string memory);

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        if (ValidatorDeployment.DEPLOYER.code.length == 0) {
            vm.etch(ValidatorDeployment.DEPLOYER, ValidatorDeployment.DEPLOYER_CODE);
        }
        rel = SafeHarness.deployRelease(_version());
        for (uint256 i; i < 3; ++i) {
            sks[i] = StatelessSigner.testKey(_label(i));
        }
        beforeOwners = vm.snapshotState();
        for (uint256 i; i < 3; ++i) {
            owners[i] = WinterlockOwner(SafeOwnerDeployment.deploy(Ops.params(_p()), _key(i)));
        }
        safe = SafeHarness.createSafe(rel, _ownerList(), 2, 0);
        vm.deal(address(safe), 100 ether);
        vm.deal(recipient, 1 ether); // an existing account, as in steady state
        token = new TestToken(address(safe), recipient);
        for (uint256 i; i < 3; ++i) {
            _enrol(i, address(safe), 0);
        }
    }

    // --- members ---

    function _label(uint256 i) internal pure returns (string memory) {
        return string(abi.encode("safe member", i));
    }

    function _key(uint256 i) internal view returns (bytes32) {
        return StatelessSigner.publicKey(sks[i]);
    }

    function _member(uint256 i) internal view returns (Member memory) {
        return Member(_label(i), sks[i], owners[i]);
    }

    function _ownerList() internal view returns (address[] memory list) {
        list = new address[](3);
        for (uint256 i; i < 3; ++i) {
            list[i] = address(owners[i]);
        }
    }

    function _tree(uint256 i, address s, uint64 start) internal view returns (WotsKey memory) {
        return _treeOf(owners[i], i, s, start);
    }

    /// Member i's tree of `s` from `start` for owner contract `o` (a proxy, or a full contract for comparison)
    function _treeOf(WinterlockOwner o, uint256 i, address s, uint64 start) internal view returns (WotsKey memory) {
        return OwnerSigner.opsTree(_p(), Member(_label(i), sks[i], o), s, start, H, K);
    }

    /// Member i's certificate for its tree of `s` from `start`, sent by a relayer
    function _enrol(uint256 i, address s, uint64 start) internal {
        bytes memory cd = OwnerSigner.enrollCalldata(_member(i), _tree(i, s, start), s, start);
        vm.prank(relayer);
        (bool ok,) = address(owners[i]).call(cd);
        assertTrue(ok, "enroll");
    }

    /// Member i's WOTS signature of `t` for `s` with `slot`, from its enrolled tree
    function _sign(uint256 i, ISafe s, SafeTx memory t, uint256 slot) internal view returns (OwnerSignature memory) {
        return _signBy(owners[i], i, s, t, slot);
    }

    /// The same for member i's owner contract `o`
    function _signBy(WinterlockOwner o, uint256 i, ISafe s, SafeTx memory t, uint256 slot)
        internal
        view
        returns (OwnerSignature memory)
    {
        (,,, uint64 start,) = o.tree(address(s), 0);
        bytes memory data =
            OwnerSigner.txSignature(_treeOf(o, i, address(s), start), start, slot, address(s), t, s.hash(t));
        return SafeHarness.contractSig(address(o), data);
    }

    function _signed(ISafe s, SafeTx memory t, uint256 a, uint256 b) internal view returns (bytes memory) {
        return SafeHarness.pack(_sign(a, s, t, 0), _sign(b, s, t, 0));
    }

    /// Member i's stateless signature of the SafeMessage that the fallback handler builds for `appHash`
    function _messageSig(uint256 i, ISafe s, bytes32 appHash) internal view returns (OwnerSignature memory) {
        bytes32 msgHash = SafeHarness.messageHash(appHash);
        bytes memory data =
            OwnerSigner.messageSignature(_member(i), address(s), msgHash, SafeHarness.safeMessageHash(s, msgHash));
        return SafeHarness.contractSig(address(owners[i]), data);
    }

    function _execExpectRevert(ISafe s, SafeTx memory t, bytes memory sigs, bytes memory reason) internal {
        vm.expectRevert(reason);
        s.exec(t, sigs);
    }

    // --- transactions ---

    function test_ethAndErc20Transfers() public {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        bytes memory sigs = _signed(safe, t, 0, 1);
        assertTrue(safe.exec(t, sigs));
        assertEq(recipient.balance, 2 ether);

        t = SafeHarness.call(address(token), abi.encodeCall(ERC20.transfer, (recipient, 100 ether)), 1);
        assertTrue(safe.exec(t, _signed(safe, t, 1, 2)));
        assertEq(token.balanceOf(recipient), 100 ether + 1);
        assertEq(safe.nonce(), 2);
    }

    /// One member alone doesn't reach the threshold, and one member's signature can't count twice.
    function test_thresholdAndDistinctOwners() public {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        OwnerSignature memory a = _sign(0, safe, t, 0);
        OwnerSignature[] memory one = new OwnerSignature[](1);
        one[0] = a;
        vm.expectRevert(); // Safe reads a second static part out of the first signature's data
        safe.exec(t, SafeHarness.pack(one));
        _execExpectRevert(safe, t, SafeHarness.pack(a, a), "GS026");
        assertTrue(safe.exec(t, SafeHarness.pack(a, _sign(2, safe, t, 0)))); // control
    }

    /// Question 2: Safe increments its nonce before it checks signatures. An owner that compares the Safe's nonce with
    /// the one it signed sees nonce + 1 during execTransaction.
    function test_safeNonceDuringExecution() public {
        SafeNonceProbe probe = new SafeNonceProbe();
        address[] memory list = new address[](1);
        list[0] = address(probe);
        ISafe s = SafeHarness.createSafe(rel, list, 1, 7);
        vm.deal(address(s), 1 ether);

        SafeTx memory t = SafeHarness.transfer(recipient, 1, 0);
        OwnerSignature[] memory sig = new OwnerSignature[](1);
        sig[0] = SafeHarness.contractSig(address(probe), abi.encode(uint256(0))); // expects the signed nonce, 0
        _execExpectRevert(s, t, SafeHarness.pack(sig), "GS024");
        sig[0] = SafeHarness.contractSig(address(probe), abi.encode(uint256(1))); // expects nonce + 1
        assertTrue(s.exec(t, SafeHarness.pack(sig)));
    }

    /// Question 2: the Transaction Service checks a confirmation with an eth_call to the owner, from no particular
    /// sender, while the Safe's nonce is still lower; a queued transaction is checked even further ahead. The owner
    /// gives the same answer then as during execution, since it reads neither the Safe's nonce nor msg.sender.
    function test_sameAnswerBeforeAndDuringExecution() public {
        SafeTx memory t0 = SafeHarness.transfer(recipient, 1 ether, 0);
        SafeTx memory t1 = SafeHarness.transfer(recipient, 2 ether, 1); // queued behind t0
        OwnerSignature memory s0 = _sign(0, safe, t0, 0);
        OwnerSignature memory s1 = _sign(0, safe, t1, 0);
        bytes32 h0 = safe.hash(t0);
        bytes32 h1 = safe.hash(t1);

        vm.startPrank(address(0)); // eth_call without a sender
        assertEq(owners[0].isValidSignature(h0, s0.data), MAGIC);
        assertEq(owners[0].isValidSignature(h1, s1.data), MAGIC);
        // the legacy entry point, with the hash's preimage, as the service asks Safes before v1.5.0
        assertEq(owners[0].isValidSignature(_preimage(t0), s0.data), LEGACY_MAGIC);
        vm.stopPrank();
        assertEq(safe.nonce(), 0);

        assertTrue(safe.exec(t0, SafeHarness.pack(s0, _sign(1, safe, t0, 0)))); // checked at Safe nonce 1
        assertTrue(safe.exec(t1, SafeHarness.pack(s1, _sign(2, safe, t1, 0)))); // checked at Safe nonce 2
        assertEq(recipient.balance, 4 ether);
    }

    /// keccak256 preimage of t's hash: 0x1901 ‖ Safe's domain separator ‖ SafeTx struct hash
    function _preimage(SafeTx memory t) internal view returns (bytes memory) {
        bytes32 typeHash = keccak256(
            "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
        );
        bytes memory pre = abi.encodePacked(
            bytes2(0x1901), safe.domainSeparator(), keccak256(bytes.concat(typeHash, SafeHarness.words(t)))
        );
        assertEq(keccak256(pre), safe.hash(t));
        return pre;
    }

    // --- one key per nonce and slot ---

    /// D4: a member who signed a proposal at a nonce signs its replacement with slot 1. The replacement (here a
    /// cancellation, as Safe's app builds it: an empty call to the Safe itself) executes, and the original proposal's
    /// signatures are then worthless: its nonce is gone.
    function test_replacementWithSlot1() public {
        SafeTx memory original = SafeHarness.transfer(recipient, 5 ether, 0);
        bytes memory originalSigs = _signed(safe, original, 0, 1); // slot 0 each

        SafeTx memory cancel = SafeHarness.transfer(address(safe), 0, 0);
        bytes memory cancelSigs = SafeHarness.pack(_sign(0, safe, cancel, 1), _sign(2, safe, cancel, 0));
        assertTrue(safe.exec(cancel, cancelSigs));

        _execExpectRevert(safe, original, originalSigs, "GS024");
        original.nonce = 1; // the same transfer at the next nonce: signed for nonce 0, so refused
        _execExpectRevert(safe, original, originalSigs, "GS024");
        assertEq(recipient.balance, 1 ether);
    }

    /// A key belongs to one nonce. Signing nonce 1 with nonce 0's key is refused, and so is a signature whose SafeTx
    /// fields don't hash to the transaction being checked.
    function test_keyForAnotherNonceRefused() public {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(safe.exec(t, _signed(safe, t, 0, 1)));

        t.nonce = 1;
        bytes32 h = safe.hash(t);
        WotsKey memory tree = _tree(0, address(safe), 0);
        // nonce 0's key (index 0) signs the nonce-1 transaction
        bytes memory wrongKey = OwnerSigner.txSignatureWithKey(tree, 0, 0, address(safe), t, h);
        assertEq(owners[0].isValidSignature(h, wrongKey), INVALID);
        // nonce 0's key signs it, and the SafeTx fields claim nonce 0 to match the key: they don't hash to h
        SafeTx memory claimed = SafeHarness.transfer(recipient, 1 ether, 0);
        bytes memory lyingFields = OwnerSigner.txSignatureWithKey(tree, 0, 0, address(safe), claimed, h);
        assertEq(owners[0].isValidSignature(h, lyingFields), INVALID);
        // the right key, but fields of another transaction
        bytes memory wrongFields = OwnerSigner.txSignatureWithKey(tree, 2, 0, address(safe), claimed, h);
        assertEq(owners[0].isValidSignature(h, wrongFields), INVALID);

        OwnerSignature memory other = _sign(1, safe, t, 0);
        _execExpectRevert(
            safe, t, SafeHarness.pack(SafeHarness.contractSig(address(owners[0]), wrongKey), other), "GS024"
        );
        assertTrue(safe.exec(t, SafeHarness.pack(_sign(0, safe, t, 0), other))); // control
    }

    // --- bindings: Safe, chain ---

    /// Two Safes with the same owners: a signature for one is refused on the other.
    function test_signatureForAnotherSafeRefused() public {
        ISafe twin = SafeHarness.createSafe(rel, _ownerList(), 2, 1);
        vm.deal(address(twin), 10 ether);
        for (uint256 i; i < 3; ++i) {
            _enrol(i, address(twin), 0);
        }
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        bytes memory forFirst = _signed(safe, t, 0, 1);
        _execExpectRevert(twin, t, forFirst, "GS024");
        assertTrue(twin.exec(t, _signed(twin, t, 0, 1))); // control
        assertTrue(safe.exec(t, forFirst));
    }

    /// Two chains from one state snapshot (the same deployment, as on two chains with the same addresses), for a
    /// Safe without trees yet. The Safe's hash names the chain, and so do certificates and tree seeds: a certificate
    /// or a signature made on one chain is refused on the other.
    function test_signatureForAnotherChainRefused() public {
        ISafe s = SafeHarness.createSafe(rel, _ownerList(), 2, 1);
        vm.deal(address(s), 10 ether);
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        uint256 snap = vm.snapshotState();

        // this chain: certificates and signatures
        bytes memory certificateHere = OwnerSigner.enrollCalldata(_member(0), _tree(0, address(s), 0), address(s), 0);
        for (uint256 i; i < 2; ++i) {
            _enrol(i, address(s), 0);
        }
        bytes memory sigsHere = _signed(s, t, 0, 1);

        // the other chain
        vm.revertToState(snap);
        vm.chainId(SEPOLIA);
        vm.prank(relayer);
        (bool ok,) = address(owners[0]).call(certificateHere);
        assertFalse(ok, "certificate from another chain");
        for (uint256 i; i < 2; ++i) {
            _enrol(i, address(s), 0);
        }
        _execExpectRevert(s, t, sigsHere, "GS024");
        assertTrue(s.exec(t, _signed(s, t, 0, 1))); // control: signed on this chain
    }

    /// The owners' and the Safe's addresses don't depend on the chain: deployed from the same state under another chain
    /// id, they come out the same. (On real chains this needs Safe's singleton and factory at the same addresses, as
    /// Safe's canonical deployments are, and the deterministic deployment proxy.)
    function test_sameAddressesOnAnotherChain() public {
        uint256 params = Ops.params(WotsParams(16, 300, 4, 0)); // owners not deployed yet
        uint256 snap = vm.snapshotState();
        (address[] memory a, address sa) = _family(params);
        vm.revertToState(snap);
        vm.chainId(SEPOLIA);
        (address[] memory b, address sb) = _family(params);
        assertEq(sa, sb);
        for (uint256 i; i < 3; ++i) {
            assertEq(a[i], b[i]);
            assertEq(a[i].code.length, 77, "a member's proxy");
        }
    }

    function _family(uint256 params) internal returns (address[] memory list, address s) {
        list = new address[](3);
        for (uint256 i; i < 3; ++i) {
            list[i] = SafeOwnerDeployment.deploy(params, _key(i));
        }
        s = address(SafeHarness.createSafe(rel, list, 2, 0));
    }

    // --- messages ---

    /// SafeMessages through the fallback handler: an app asks the Safe isValidSignature(bytes32, bytes), the handler
    /// wraps the hash in a SafeMessage and has the Safe check its owners, each with its stateless key.
    function test_messageThroughFallbackHandler() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        bytes memory sigs = SafeHarness.pack(_messageSig(0, safe, appHash), _messageSig(2, safe, appHash));
        vm.prank(app);
        assertEq(IERC1271(address(safe)).isValidSignature(appHash, sigs), MAGIC);

        // the handler's SafeMessage hash is the one the members signed
        bytes32 msgHash = SafeHarness.messageHash(appHash);
        (bool ok, bytes memory ret) = address(safe)
            .staticcall(
                abi.encodeWithSignature("getMessageHashForSafe(address,bytes)", address(safe), abi.encode(appHash))
            );
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes32)), SafeHarness.safeMessageHash(safe, msgHash));
    }

    /// A message signature counts for one Safe, one chain and one message, and only as a message: it can't approve a
    /// transaction, and a WOTS transaction signature can't sign a message.
    function test_messageBindings() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        OwnerSignature memory m0 = _messageSig(0, safe, appHash);
        OwnerSignature memory m1 = _messageSig(1, safe, appHash);
        bytes memory sigs = SafeHarness.pack(m0, m1);

        ISafe twin = SafeHarness.createSafe(rel, _ownerList(), 2, 1);
        _expectMessageRefused(twin, appHash, sigs); // another Safe
        _expectMessageRefused(safe, keccak256("another message"), sigs); // another message
        vm.chainId(SEPOLIA);
        _expectMessageRefused(safe, appHash, sigs); // another chain
        vm.chainId(31337);

        // the message signatures as transaction signatures
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        _execExpectRevert(safe, t, sigs, "GS024");
        // transaction signatures as message signatures
        _expectMessageRefused(safe, appHash, _signed(safe, t, 0, 1));
        // A member phished into signing a SafeTx hash as a message: the stateless key's signature of the transaction
        // hash, in a message signature with any message hash, doesn't approve the transaction. The owner checks that
        // the hash is a SafeMessage of the Safe.
        bytes32 h = safe.hash(t);
        bytes memory phished = abi.encodePacked(
            uint8(2),
            uint8(0),
            address(safe),
            bytes32(0),
            StatelessSigner.sign(sks[0], owners[0].messageDigest(address(safe), 0, 0, h))
        );
        assertEq(owners[0].isValidSignature(h, phished), INVALID);
        _execExpectRevert(
            safe,
            t,
            SafeHarness.pack(SafeHarness.contractSig(address(owners[0]), phished), _sign(1, safe, t, 0)),
            "GS024"
        );
        // control
        vm.prank(app);
        assertEq(IERC1271(address(safe)).isValidSignature(appHash, sigs), MAGIC);
    }

    /// Safe v1.5.0's handler returns the magic value or reverts; v1.4.1's returns 0 when the Safe's legacy call fails
    /// to return its magic value, and reverts when checkSignatures reverts. Either way not the magic value.
    function _expectMessageRefused(ISafe s, bytes32 appHash, bytes memory sigs) internal {
        vm.prank(app);
        (bool ok, bytes memory ret) = address(s).staticcall(abi.encodeCall(IERC1271.isValidSignature, (appHash, sigs)));
        assertTrue(!ok || abi.decode(ret, (bytes4)) != MAGIC, "message refused");
    }

    // --- devices ---

    /// Member i's device key from `label`, as device `device` at `generation`
    function _deviceKey(uint256 i, string memory label, uint8 device, uint16 generation)
        internal
        view
        returns (DeviceKey memory)
    {
        string memory name = string.concat(_label(i), " ", label);
        return DeviceKey(name, StatelessSigner.testKey(name), owners[i], device, generation);
    }

    /// Member i's member key certifies device key `d`, sent by a relayer
    function _certifyDevice(uint256 i, DeviceKey memory d) internal {
        bytes memory cd = OwnerSigner.certifyCalldata(_member(i), d);
        vm.prank(relayer);
        (bool ok,) = address(owners[i]).call(cd);
        assertTrue(ok, "certifyDevice");
    }

    /// Member i's member key revokes device key `d`, sent by a relayer
    function _revokeDevice(uint256 i, DeviceKey memory d) internal {
        bytes memory cd = OwnerSigner.revokeCalldata(_member(i), d);
        vm.prank(relayer);
        (bool ok,) = address(owners[i]).call(cd);
        assertTrue(ok, "revokeDevice");
    }

    function _deviceTree(DeviceKey memory d, address s, uint64 start) internal view returns (WotsKey memory) {
        return OwnerSigner.opsTree(_p(), d, s, start, H, K);
    }

    /// Device key `d` certifies its own tree of `s` from `start`, sent by a relayer
    function _enrolDevice(DeviceKey memory d, address s, uint64 start) internal {
        bytes memory cd = OwnerSigner.enrollCalldata(d, _deviceTree(d, s, start), s, start);
        vm.prank(relayer);
        (bool ok,) = address(d.owner).call(cd);
        assertTrue(ok, "enroll (device)");
    }

    /// Device key `d`'s WOTS signature of `t` for `s` with `slot`, from its enrolled tree
    function _signByDevice(DeviceKey memory d, ISafe s, SafeTx memory t, uint256 slot)
        internal
        view
        returns (OwnerSignature memory)
    {
        (,,, uint64 start,) = d.owner.tree(address(s), d.device);
        WotsKey memory tree = _deviceTree(d, address(s), start);
        bytes memory data = OwnerSigner.txSignature(tree, d.device, start, slot, address(s), t, s.hash(t));
        return SafeHarness.contractSig(address(d.owner), data);
    }

    /// Device key `d`'s stateless signature of the SafeMessage the fallback handler builds for `appHash`
    function _messageSigByDevice(DeviceKey memory d, ISafe s, bytes32 appHash)
        internal
        view
        returns (OwnerSignature memory)
    {
        bytes32 msgHash = SafeHarness.messageHash(appHash);
        bytes memory data =
            OwnerSigner.messageSignature(d, address(s), msgHash, SafeHarness.safeMessageHash(s, msgHash));
        return SafeHarness.contractSig(address(d.owner), data);
    }

    /// Trees per device: member 0's member key (device 0) and laptop (device 1) each hold a tree for the Safe from
    /// nonce 0, and both sign the same transaction at nonce 0 with slot 0. Both signatures verify, from different
    /// one-time keys at the same key index, and neither verifies under the other's device number. The member's two
    /// devices count once, as one owner.
    function test_devicesSignTheSameNonce() public {
        DeviceKey memory laptop = _deviceKey(0, "laptop", 1, 1);
        _certifyDevice(0, laptop);
        _enrolDevice(laptop, address(safe), 0);
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        bytes32 h = safe.hash(t);
        OwnerSignature memory byMemberKey = _sign(0, safe, t, 0);
        OwnerSignature memory byLaptop = _signByDevice(laptop, safe, t, 0);
        assertEq(owners[0].isValidSignature(h, byMemberKey.data), MAGIC);
        assertEq(owners[0].isValidSignature(h, byLaptop.data), MAGIC);

        // under the other device's number: the laptop's signature differs beyond the device byte, and neither verifies
        bytes memory asZero = bytes.concat(byLaptop.data);
        asZero[1] = 0x00;
        assertTrue(keccak256(asZero) != keccak256(byMemberKey.data), "different one-time keys");
        assertEq(owners[0].isValidSignature(h, asZero), INVALID);
        bytes memory asOne = bytes.concat(byMemberKey.data);
        asOne[1] = 0x01;
        assertEq(owners[0].isValidSignature(h, asOne), INVALID);

        _execExpectRevert(safe, t, SafeHarness.pack(byMemberKey, byLaptop), "GS026"); // one owner, twice
        assertTrue(safe.exec(t, SafeHarness.pack(byLaptop, _sign(1, safe, t, 0))));
        assertEq(recipient.balance, 2 ether);
    }

    /// A revoked device: a confirmation it gave before the revoke (as Safe's service would hold it) stops counting,
    /// while the member's other devices still sign. A replaced device (a lost phone, certified anew with a new key at
    /// the next generation): the same for the old key; the new key signs once it has enrolled its own tree, from a
    /// start the old generation's tree doesn't bound.
    function test_revokedOrReplacedDeviceConfirmationRefused() public {
        DeviceKey memory laptop = _deviceKey(0, "laptop", 1, 1);
        _certifyDevice(0, laptop);
        _enrolDevice(laptop, address(safe), 0);
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        OwnerSignature memory collected = _signByDevice(laptop, safe, t, 0);
        OwnerSignature memory other = _sign(1, safe, t, 0);
        vm.prank(address(0)); // the service's eth_call
        assertEq(owners[0].isValidSignature(safe.hash(t), collected.data), MAGIC);

        _revokeDevice(0, laptop);
        assertEq(owners[0].isValidSignature(safe.hash(t), collected.data), INVALID);
        _execExpectRevert(safe, t, SafeHarness.pack(collected, other), "GS024");
        assertTrue(safe.exec(t, SafeHarness.pack(_sign(0, safe, t, 0), other))); // the member key

        DeviceKey memory phone = _deviceKey(1, "phone", 1, 1);
        _certifyDevice(1, phone);
        _enrolDevice(phone, address(safe), 1);
        t = SafeHarness.transfer(recipient, 1 ether, 1);
        collected = _signByDevice(phone, safe, t, 0);
        other = _sign(2, safe, t, 0);
        DeviceKey memory newPhone = _deviceKey(1, "new phone", 1, 2);
        _certifyDevice(1, newPhone); // replaces the phone's key
        assertEq(owners[1].isValidSignature(safe.hash(t), collected.data), INVALID);
        _execExpectRevert(safe, t, SafeHarness.pack(collected, other), "GS024");
        _enrolDevice(newPhone, address(safe), 1);
        assertTrue(safe.exec(t, SafeHarness.pack(_signByDevice(newPhone, safe, t, 0), other)));
        assertEq(recipient.balance, 3 ether);
    }

    /// A device key signs SafeMessages for its member through the fallback handler. Once it is revoked, its message
    /// signatures, those given before included, stop verifying.
    function test_deviceMessages() public {
        DeviceKey memory laptop = _deviceKey(0, "laptop", 1, 1);
        _certifyDevice(0, laptop);
        bytes32 appHash = keccak256("sign in to app.example");
        bytes memory sigs = SafeHarness.pack(_messageSigByDevice(laptop, safe, appHash), _messageSig(2, safe, appHash));
        vm.prank(app);
        assertEq(IERC1271(address(safe)).isValidSignature(appHash, sigs), MAGIC);
        _revokeDevice(0, laptop);
        _expectMessageRefused(safe, appHash, sigs);
    }

    // --- upgrade in place ---

    /// A Safe with three ECDSA owners swaps them one by one for WinterlockOwners (swapOwner), each swap in a
    /// MultiSend with the new owner's enrolment, so the Safe itself sends the certificate. Every transaction is
    /// signed by the owners of the moment: ECDSA, then mixed, then Winterlock only. The Safe keeps its address and
    /// funds; at the end no ECDSA key can sign.
    function test_upgradeInPlace() public {
        uint256[3] memory pks = [uint256(0xA11CE), 0xB0B, 0xCA401];
        address[] memory eoas = new address[](3);
        for (uint256 i; i < 3; ++i) {
            eoas[i] = vm.addr(pks[i]);
        }
        ISafe s = SafeHarness.createSafe(rel, eoas, 2, 42);
        address before = address(s);
        vm.deal(before, 10 ether);

        // nonce 0: E1 + E2 sign E0 -> W0
        SafeTx memory t = _swap(s, eoas[0], 0, 0);
        assertTrue(
            s.exec(t, SafeHarness.pack(SafeHarness.ecdsa(pks[1], s.hash(t)), SafeHarness.ecdsa(pks[2], s.hash(t))))
        );
        // nonce 1: W0 (WOTS) + E2 (ECDSA) sign E1 -> W1
        t = _swap(s, eoas[1], 1, 1);
        assertTrue(s.exec(t, SafeHarness.pack(_sign(0, s, t, 0), SafeHarness.ecdsa(pks[2], s.hash(t)))));
        // nonce 2: W0 + W1 sign E2 -> W2
        t = _swap(s, eoas[2], 2, 2);
        assertTrue(s.exec(t, SafeHarness.pack(_sign(0, s, t, 0), _sign(1, s, t, 0))));

        assertEq(address(s), before);
        address[] memory now_ = s.getOwners();
        assertEq(now_.length, 3);
        for (uint256 i; i < 3; ++i) {
            assertTrue(s.isOwner(address(owners[i])));
            assertFalse(s.isOwner(eoas[i]));
        }
        assertEq(s.getThreshold(), 2);

        // nonce 3: Winterlock owners move funds; the old ECDSA keys can't
        t = SafeHarness.transfer(recipient, 1 ether, 3);
        _execExpectRevert(
            s, t, SafeHarness.pack(SafeHarness.ecdsa(pks[0], s.hash(t)), SafeHarness.ecdsa(pks[1], s.hash(t))), "GS026"
        );
        assertTrue(s.exec(t, SafeHarness.pack(_sign(1, s, t, 0), _sign(2, s, t, 0))));
        assertEq(before.balance, 9 ether);
    }

    /// MultiSend: s.swapOwner(prev, old, W_i), then W_i.enroll(s, tree from the next nonce)
    function _swap(ISafe s, address old, uint256 i, uint256 nonce) internal view returns (SafeTx memory) {
        address[] memory targets = new address[](2);
        bytes[] memory data = new bytes[](2);
        targets[0] = address(s);
        data[0] = abi.encodeCall(IOwnerManager.swapOwner, (_prevOwner(s, old), old, address(owners[i])));
        targets[1] = address(owners[i]);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 start = uint64(nonce + 1);
        data[1] = OwnerSigner.enrollCalldata(_member(i), _tree(i, address(s), start), address(s), start);
        return SafeHarness.multiSend(rel, targets, data, nonce);
    }

    /// The owner before `owner` in the Safe's linked list (the sentinel 0x1 for the first)
    function _prevOwner(ISafe s, address owner) internal view returns (address prev) {
        address[] memory list = s.getOwners();
        prev = address(1);
        for (uint256 i; i < list.length && list[i] != owner; ++i) {
            prev = list[i];
        }
    }

    // --- gas and sizes ---

    /// Transaction gas of execTransaction for a 2-of-3 Safe of WinterlockOwners (members' proxies) against 2-of-3 ECDSA
    /// owners and against 2-of-3 WinterlockOwners as full contracts (the spike's design), all at steady state:
    /// nonce >= 1, and the recipient's ETH and token balances nonzero. See _txGas.
    function test_gas_execTransaction() public {
        (uint256 wlEth, uint256 wlErc20, uint256 sigBytes) = _winterlockGas(safe, owners);
        (uint256 wlBytes, uint256 wlCalldataGas) = (lastCalldataBytes, lastCalldataGas);
        (ISafe fullSafe, WinterlockOwner[3] memory full) = _fullOwnerSafe();
        (uint256 fullEth, uint256 fullErc20, uint256 fullSigBytes) = _winterlockGas(fullSafe, full);
        (uint256 ecEth, uint256 ecErc20) = _ecdsaGas();
        console.log(string.concat("Safe ", rel.version, ", transaction gas"));
        console.log("ETH transfer, 2-of-3 ECDSA owners                ", ecEth);
        console.log("ETH transfer, 2-of-3 WinterlockOwners (proxies)  ", wlEth);
        console.log("ETH transfer, 2-of-3 WinterlockOwners (full)     ", fullEth);
        console.log("ERC-20 transfer, 2-of-3 ECDSA owners             ", ecErc20);
        console.log("ERC-20 transfer, 2-of-3 WinterlockOwners (proxies)", wlErc20);
        console.log("ERC-20 transfer, 2-of-3 WinterlockOwners (full)  ", fullErc20);
        console.log("proxies over full, ETH, ERC-20                   ", wlEth - fullEth, wlErc20 - fullErc20);
        console.log("contract signature per owner, bytes              ", sigBytes);
        console.log("as a confirmation (65 + 32 + data)               ", 97 + sigBytes);
        console.log("ERC-20 calldata, bytes, ECDSA owners             ", lastCalldataBytes, ", gas", lastCalldataGas);
        console.log("ERC-20 calldata, bytes, WinterlockOwners          ", wlBytes, ", gas", wlCalldataGas);
        assertEq(sigBytes, 2 + 20 + 320 + 1176 + 24 * H);
        assertEq(fullSigBytes, sigBytes);
        assertLt(97 + sigBytes, 5000, "fits the Transaction Service's 5,000-byte confirmation");
    }

    function _winterlockGas(ISafe s, WinterlockOwner[3] memory o)
        internal
        returns (uint256 eth, uint256 erc20, uint256 sigBytes)
    {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(s.exec(t, _pair(s, o, t, 0, 1))); // nonce 0 -> 1
        t.nonce = 1;
        sigBytes = _signBy(o[0], 0, s, t, 0).data.length;
        eth = _txGas(address(s), SafeHarness.execCalldata(t, _pair(s, o, t, 0, 1)));
        t = SafeHarness.call(address(token), abi.encodeCall(ERC20.transfer, (recipient, 1 ether)), 2);
        erc20 = _txGas(address(s), SafeHarness.execCalldata(t, _pair(s, o, t, 1, 2)));
        assertEq(s.nonce(), 3);
    }

    /// Members i's and j's signatures of `t` (slot 0) through their owner contracts `o`, packed for `s`
    function _pair(ISafe s, WinterlockOwner[3] memory o, SafeTx memory t, uint256 i, uint256 j)
        internal
        view
        returns (bytes memory)
    {
        return SafeHarness.pack(_signBy(o[i], i, s, t, 0), _signBy(o[j], j, s, t, 0));
    }

    /// For comparison: a 2-of-3 Safe whose owners are the members' WinterlockOwners as full contracts (the spike's
    /// design: the key an immutable, no proxy), funded and enrolled like `safe`
    function _fullOwnerSafe() internal returns (ISafe s, WinterlockOwner[3] memory full) {
        address[] memory list = new address[](3);
        for (uint256 i; i < 3; ++i) {
            full[i] = new FullWinterlockOwner(
                Ops.params(_p()), owners[0].STATELESS_VERIFIER(), owners[0].WOTS_VERIFIER(), _key(i)
            );
            list[i] = address(full[i]);
        }
        s = SafeHarness.createSafe(rel, list, 2, 77);
        vm.deal(address(s), 10 ether);
        vm.prank(address(safe));
        token.transfer(address(s), 10 ether);
        for (uint256 i; i < 3; ++i) {
            Member memory m = Member(_label(i), sks[i], full[i]);
            bytes memory cd = OwnerSigner.enrollCalldata(m, _treeOf(full[i], i, address(s), 0), address(s), 0);
            (bool ok,) = address(full[i]).call(cd);
            assertTrue(ok, "enroll");
        }
    }

    /// What the proxy adds to each owner check: two owners' checks of a SafeTx (nonce 1) in one transaction, through
    /// the members' proxies and through full contracts. The proxy copies the calldata, DELEGATECALLs the implementation
    /// (cold for the first proxy in a transaction, warm for the next) and copies the result back.
    function test_gas_ownerCheck() public {
        (ISafe fullSafe, WinterlockOwner[3] memory full) = _fullOwnerSafe();
        OwnerCheckProbe probe = new OwnerCheckProbe();
        (uint256 proxy1, uint256 proxy2) = _checkGas(probe, safe, owners);
        (uint256 full1, uint256 full2) = _checkGas(probe, fullSafe, full);
        console.log("owner check (isValidSignature, SafeTx), gas of the call");
        console.log("first check, full contract       ", full1);
        console.log("first check, proxy (impl. cold)  ", proxy1, ", overhead", proxy1 - full1);
        console.log("second check, full contract      ", full2);
        console.log("second check, proxy (impl. warm) ", proxy2, ", overhead", proxy2 - full2);
        assertGt(proxy1, full1);
        assertLt(proxy1 - full1, 4000);
        assertLt(proxy2 - full2, 1500);
    }

    /// Owners 0 and 1 of `s` check their signatures of a SafeTx at nonce 1, in one transaction
    function _checkGas(OwnerCheckProbe probe, ISafe s, WinterlockOwner[3] memory o)
        internal
        returns (uint256 first, uint256 second)
    {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 1);
        OwnerSignature memory a = _signBy(o[0], 0, s, t, 0);
        OwnerSignature memory b = _signBy(o[1], 1, s, t, 0);
        return probe.check(a.owner, a.data, b.owner, b.data, s.hash(t));
    }

    function _ecdsaGas() internal returns (uint256 eth, uint256 erc20) {
        uint256[3] memory pks = [uint256(0xA11CE), 0xB0B, 0xCA401];
        address[] memory eoas = new address[](3);
        for (uint256 i; i < 3; ++i) {
            eoas[i] = vm.addr(pks[i]);
        }
        ISafe s = SafeHarness.createSafe(rel, eoas, 2, 99);
        vm.deal(address(s), 10 ether);
        vm.prank(address(safe));
        token.transfer(address(s), 10 ether);
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(s.exec(t, _ecdsaSigned(s, t, pks[0], pks[1])));
        t.nonce = 1;
        eth = _txGas(address(s), SafeHarness.execCalldata(t, _ecdsaSigned(s, t, pks[0], pks[1])));
        t = SafeHarness.call(address(token), abi.encodeCall(ERC20.transfer, (recipient, 1 ether)), 2);
        erc20 = _txGas(address(s), SafeHarness.execCalldata(t, _ecdsaSigned(s, t, pks[1], pks[2])));
        assertEq(s.nonce(), 3);
    }

    function _ecdsaSigned(ISafe s, SafeTx memory t, uint256 a, uint256 b) internal view returns (bytes memory) {
        bytes32 h = s.hash(t);
        return SafeHarness.pack(SafeHarness.ecdsa(a, h), SafeHarness.ecdsa(b, h));
    }

    /// The message check an app makes on-chain, Safe.isValidSignature(bytes32, bytes) through the fallback handler,
    /// 2-of-3, in a fresh transaction (everything cold): the check's own gas, without the app's calldata. And sizes.
    function test_gas_message() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        OwnerSignature memory m0 = _messageSig(0, safe, appHash);
        bytes memory sigs = SafeHarness.pack(m0, _messageSig(1, safe, appHash));
        MessageCheckProbe probe = new MessageCheckProbe();
        (bytes4 r, uint256 used) = probe.check(address(safe), appHash, sigs);
        assertEq(r, MAGIC);
        console.log(string.concat("Safe ", rel.version));
        console.log("message check, 2-of-3, gas of the call", used);
        console.log("message signature per owner, bytes", m0.data.length);
        console.log("as a confirmation (65 + 32 + data)", 97 + m0.data.length);
        console.log("2-of-3 signatures blob, bytes", sigs.length);
        assertEq(m0.data.length, 2 + 20 + 32 + 5684);
    }

    /// Transaction gas of the deployments and of enrolment, from a chain with Safe and the members' keys but no
    /// Winterlock contract yet:
    /// - once per chain: the stateless verifier, the implementation and the factory, each through the deterministic
    ///   deployment proxy
    /// - per member and chain: the member's owner (a proxy, by the factory); the same with a first tree in one
    ///   transaction (deployAndEnroll); and, for comparison, a full contract as in the spike
    /// - per Safe and chain: a first enrolment, and a rotation
    function test_gas_deployAndEnrol() public {
        vm.revertToState(beforeOwners);
        WinterlockOwnerFactory factory = _gasShared();
        address team = address(uint160(uint256(keccak256("a team's Safe"))));
        WinterlockOwner owner0 = _gasMembers(factory, team);

        // member 0 enrols for the team's Safe: a first tree (a new slot), then a rotation from nonce 5
        Member memory m0 = Member(_label(0), sks[0], owner0);
        bytes memory cd = OwnerSigner.enrollCalldata(m0, OwnerSigner.opsTree(_p(), m0, team, 0, H, K), team, 0);
        uint256 enrolGas = _txGas(address(owner0), cd);
        cd = OwnerSigner.enrollCalldata(m0, OwnerSigner.opsTree(_p(), m0, team, 5, H, K), team, 5);
        uint256 rotateGas = _txGas(address(owner0), cd);
        (,,, uint64 start,) = owner0.tree(team, 0);
        assertEq(start, 5);
        console.log("per Safe and chain, tx gas:");
        console.log("  enroll, first tree       ", enrolGas);
        console.log("  enroll, rotation         ", rotateGas);
        console.log("  enroll calldata bytes    ", cd.length);
    }

    /// Once per chain: the stateless verifier, the shared WOTS verifier, the implementation and the factory
    function _gasShared() internal returns (WinterlockOwnerFactory factory) {
        uint256 params = Ops.params(_p());
        address deployer = ValidatorDeployment.DEPLOYER;
        bytes memory init = ValidatorDeployment.verifierInitCode();
        uint256 verifierGas = _txGas(deployer, abi.encodePacked(ValidatorDeployment.VERIFIER_SALT, init));
        address verifier = ValidatorDeployment.predictVerifier();
        init = SafeOwnerDeployment.wotsVerifierInitCode();
        uint256 wotsGas = _txGas(deployer, abi.encodePacked(SafeOwnerDeployment.WOTS_VERIFIER_SALT, init));
        address wots = SafeOwnerDeployment.predictWotsVerifier();
        init = SafeOwnerDeployment.implementationInitCode(params);
        uint256 implGas = _txGas(deployer, abi.encodePacked(SafeOwnerDeployment.IMPLEMENTATION_SALT, init));
        address impl = SafeOwnerDeployment.predictImplementation(params);
        console.log("once per chain, tx gas (runtime bytes, init code bytes):");
        console.log("  stateless verifier       ", verifierGas, verifier.code.length);
        console.log("  shared WOTS verifier     ", wotsGas, wots.code.length);
        console.log("  WinterlockOwner impl.    ", implGas, impl.code.length, init.length);
        init = SafeOwnerDeployment.factoryInitCode(impl);
        uint256 factoryGas = _txGas(deployer, abi.encodePacked(SafeOwnerDeployment.FACTORY_SALT, init));
        factory = WinterlockOwnerFactory(SafeOwnerDeployment.predictFactory(params));
        console.log("  WinterlockOwnerFactory   ", factoryGas, address(factory).code.length, init.length);
    }

    /// Per member and chain: the owner as a proxy (member 0), as a proxy with its first tree for `team` in one
    /// transaction (member 1), and as a full contract as in the spike (member 2)
    function _gasMembers(WinterlockOwnerFactory factory, address team) internal returns (WinterlockOwner owner0) {
        uint256 proxyGas = _txGas(address(factory), abi.encodeCall(WinterlockOwnerFactory.deploy, (_key(0))));
        owner0 = WinterlockOwner(factory.predict(_key(0)));
        assertEq(owner0.KEY(), _key(0));
        assertEq(address(owner0).code.length, 77);

        // the signer knows the owner's address in advance; here its tree and certificate come from a throwaway
        // deployment
        uint256 snap = vm.snapshotState();
        Member memory m1 = Member(_label(1), sks[1], WinterlockOwner(factory.deploy(_key(1))));
        WotsKey memory t1 = OwnerSigner.opsTree(_p(), m1, team, 0, H, K);
        bytes memory cert = OwnerSigner.certificate(m1, t1, team, 0);
        vm.revertToState(snap);
        bytes memory cd =
            abi.encodeCall(WinterlockOwnerFactory.deployAndEnroll, (_key(1), team, t1.root, uint8(H), uint64(0), cert));
        uint256 deployAndEnrolGas = _txGas(address(factory), cd);
        (bytes32 root,,,,) = m1.owner.tree(team, 0);
        assertEq(root, t1.root);

        // through the deterministic deployment proxy with its key as the salt
        bytes memory init = abi.encodePacked(
            type(FullWinterlockOwner).creationCode,
            abi.encode(
                Ops.params(_p()),
                ValidatorDeployment.predictVerifier(),
                SafeOwnerDeployment.predictWotsVerifier(),
                _key(2)
            )
        );
        uint256 fullGas = _txGas(ValidatorDeployment.DEPLOYER, abi.encodePacked(_key(2), init));
        address full = ValidatorDeployment._create2(_key(2), init);
        console.log("per member and chain, tx gas (runtime bytes):");
        console.log("  owner, proxy             ", proxyGas, address(owner0).code.length);
        console.log("  owner, proxy + 1st tree  ", deployAndEnrolGas, ", calldata bytes", cd.length);
        console.log("  owner, full contract     ", fullGas, full.code.length);
    }

    /// Device keys, transaction gas (Forge, Prague pricing, as _txGas): certifying and revoking a device key; a first
    /// tree (a new slot) enrolled by device 0 and by a device key; and 2-of-3 ETH and ERC-20 transfers at steady state
    /// signed by members 0 and 1 with their member keys (device 0) and with device keys. The transactions that carry a
    /// stateless signature (5.7 KB) are logged with their EIP-7623 calldata floor, 21,000 + 10 gas per token, which
    /// sets their gas when execution costs less.
    function test_gas_devices() public {
        DeviceKey[2] memory d = [_deviceKey(0, "laptop", 1, 1), _deviceKey(1, "laptop", 1, 1)];
        console.log(string.concat("Safe ", rel.version, ", device keys, tx gas"));
        _gasDeviceSetup(d);
        _gasDeviceTransfers(d);
        uint256 revokeGas = _txGas(address(owners[0]), OwnerSigner.revokeCalldata(_member(0), d[0]));
        console.log("revokeDevice                             ", revokeGas, ", calldata bytes", lastCalldataBytes);
        console.log("  its EIP-7623 floor                     ", _floor());
    }

    /// The EIP-7623 floor of the last transaction _txGas measured: 21,000 + 10 per token, a token per zero byte and four
    /// per other byte (lastCalldataGas counts 4 per token)
    function _floor() internal view returns (uint256) {
        return 21000 + lastCalldataGas * 10 / 4;
    }

    /// Member 0 certifies its laptop (measured), member 1 too; member 0 enrols a first tree with its member key and
    /// with its laptop (each measured), member 1's laptop enrols too
    function _gasDeviceSetup(DeviceKey[2] memory d) internal {
        uint256 certifyGas = _txGas(address(owners[0]), OwnerSigner.certifyCalldata(_member(0), d[0]));
        console.log("certifyDevice                            ", certifyGas, ", calldata bytes", lastCalldataBytes);
        console.log("  its EIP-7623 floor                     ", _floor());
        _certifyDevice(1, d[1]);
        ISafe twin = SafeHarness.createSafe(rel, _ownerList(), 2, 5);
        bytes memory cd = OwnerSigner.enrollCalldata(_member(0), _tree(0, address(twin), 0), address(twin), 0);
        console.log("enroll, first tree, device 0 (member key)", _txGas(address(owners[0]), cd));
        console.log("  its EIP-7623 floor                     ", _floor());
        cd = OwnerSigner.enrollCalldata(d[0], _deviceTree(d[0], address(safe), 0), address(safe), 0);
        console.log("enroll, first tree, device 1 (device key)", _txGas(address(owners[0]), cd));
        console.log("  its EIP-7623 floor                     ", _floor());
        _enrolDevice(d[1], address(safe), 0);
    }

    /// Members 0 and 1 sign ETH and ERC-20 transfers with their member keys, then with their laptops, at steady state
    function _gasDeviceTransfers(DeviceKey[2] memory d) internal {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(safe.exec(t, _signed(safe, t, 0, 1))); // nonce 0 -> 1
        t.nonce = 1;
        uint256 byMemberKeys = _txGas(address(safe), SafeHarness.execCalldata(t, _signed(safe, t, 0, 1)));
        t.nonce = 2;
        bytes memory sigs = SafeHarness.pack(_signByDevice(d[0], safe, t, 0), _signByDevice(d[1], safe, t, 0));
        uint256 byDeviceKeys = _txGas(address(safe), SafeHarness.execCalldata(t, sigs));
        console.log("ETH transfer, 2-of-3, device 0           ", byMemberKeys);
        console.log("ETH transfer, 2-of-3, device keys        ", byDeviceKeys, ", more", byDeviceKeys - byMemberKeys);
        t = SafeHarness.call(address(token), abi.encodeCall(ERC20.transfer, (recipient, 1 ether)), 3);
        byMemberKeys = _txGas(address(safe), SafeHarness.execCalldata(t, _signed(safe, t, 0, 1)));
        t.nonce = 4;
        sigs = SafeHarness.pack(_signByDevice(d[0], safe, t, 0), _signByDevice(d[1], safe, t, 0));
        byDeviceKeys = _txGas(address(safe), SafeHarness.execCalldata(t, sigs));
        console.log("ERC-20 transfer, 2-of-3, device 0        ", byMemberKeys);
        console.log("ERC-20 transfer, 2-of-3, device keys     ", byDeviceKeys, ", more", byDeviceKeys - byMemberKeys);
        assertEq(safe.nonce(), 5);
    }

    // --- transaction gas ---

    /// The gas a transaction to `to` with calldata `cd` uses. Forge runs every call this test makes at the top level
    /// as its own transaction (isolate = true, the default), with intrinsic gas, the EIP-7623 calldata floor, fresh
    /// access lists and storage as committed by the transactions before; lastCallGas() reports its gas. Checked
    /// against a receipt from anvil (Prague) for a plain storage write: identical. Gas refunds are not subtracted;
    /// the transactions measured here earn none.
    function _txGas(address to, bytes memory cd) internal returns (uint256) {
        lastCalldataBytes = cd.length;
        lastCalldataGas = 0;
        for (uint256 i; i < cd.length; ++i) {
            lastCalldataGas += cd[i] == 0 ? 4 : 16;
        }
        (bool ok,) = to.call(cd);
        assertTrue(ok, "measured transaction failed");
        return vm.lastCallGas().gasTotalUsed;
    }
}

contract SafeWinterlockOwnerV141Test is SafeWinterlockOwnerTest {
    function _version() internal pure override returns (string memory) {
        return "v1.4.1";
    }
}

contract SafeWinterlockOwnerV150Test is SafeWinterlockOwnerTest {
    function _version() internal pure override returns (string memory) {
        return "v1.5.0";
    }
}
