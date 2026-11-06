// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ISafe} from "safe-v1.5.0/interfaces/ISafe.sol";
import {SafeStorage} from "safe-v1.5.0/libraries/SafeStorage.sol";
import {SignMessageLib as SignMessageLibV141} from "safe-v1.4.1/libraries/SignMessageLib.sol";
import {SignMessageLib as SignMessageLibV150} from "safe-v1.5.0/libraries/SignMessageLib.sol";

import {WinterlockOwner} from "../../src/safe/WinterlockOwner.sol";
import {IStatelessVerifier} from "../../src/interfaces/IStatelessVerifier.sol";
import {ValidatorDeployment} from "../../script/DeployValidator.s.sol";
import {SafeOwnerDeployment} from "../../script/DeploySafeOwner.s.sol";
import {WotsParams, WotsKey, WotsSigner, WotsTree, Ops} from "../utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "../utils/StatelessSigner.sol";
import {StatelessSignerS} from "../utils/StatelessSignerS.sol";
import {WinterlockOwnerS} from "../utils/WinterlockOwnerS.sol";
import {LeanSphincsSAsm} from "../vendor/sphincs-minus/LeanSphincs-SAsm.sol";
import {SignatureVerification} from "../vendor/permit2/libraries/SignatureVerification.sol";
import {
    SafeHarness,
    SafeRelease,
    SafeTx,
    OwnerSignature,
    Member,
    OwnerSigner,
    IERC1271
} from "../utils/SafeHarness.sol";

/// An app's on-chain check of a Safe message, Safe.isValidSignature(bytes32, bytes) (answered by the fallback
/// handler), and its gas. A revert counts as invalid.
contract AppProbe {
    function check(address safe, bytes32 hash, bytes calldata sig) external view returns (bool valid, uint256 used) {
        used = gasleft();
        (bool ok, bytes memory ret) = safe.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, sig)));
        used -= gasleft();
        valid = ok && ret.length == 32 && bytes4(bytes32(ret)) == IERC1271.isValidSignature.selector;
    }
}

/// Permit2's signature check (vendored unchanged): what Permit2 runs on every permit before it moves tokens
contract Permit2SignatureCheck {
    function verify(bytes calldata signature, bytes32 hash, address claimedSigner) external view {
        SignatureVerification.verify(signature, hash, claimedSigner);
    }
}

/// The same check as AppProbe, but not a view, so that Forge runs a call to it as a transaction of its own (isolate):
/// everything it touches is cold
contract ColdAppProbe {
    function check(address target, bytes32 hash, bytes calldata sig) external returns (bool valid, uint256 used) {
        used = gasleft();
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, sig)));
        used -= gasleft();
        valid = ok && ret.length == 32 && bytes4(bytes32(ret)) == IERC1271.isValidSignature.selector;
    }
}

/// TEST ONLY. Clears an on-chain message approval, signedMessages[hash], when a Safe transaction delegatecalls it.
/// Safe ships no such library: SignMessageLib only sets the flag, and no Safe function clears it (v1.4.1, v1.5.0).
/// The layout is Safe's own (SafeStorage, the same in both releases).
contract UnsignMessageLib is SafeStorage {
    function unsignMessage(bytes32 safeMessageHash) external {
        signedMessages[safeMessageHash] = 0;
    }
}

/// TEST ONLY. Sets signedMessages[hash] for any hash, a SafeTx hash included, when a Safe transaction delegatecalls
/// it. No Safe library does this (SignMessageLib sets only SafeMessage hashes); it shows that the approved kind still
/// can't approve a transaction.
contract MarkSignedLib is SafeStorage {
    function markSigned(bytes32 hash) external {
        signedMessages[hash] = 1;
    }
}

/// An EIP-2612 token as OpenZeppelin builds it: permit checks the signature with ECDSA.recover only
contract PermitToken is ERC20Permit {
    constructor(address holder) ERC20("Permit token", "PRM") ERC20Permit("Permit token") {
        _mint(holder, 1_000 ether);
    }
}

/// Safe messages with WinterlockOwner owners (docs/notes/safe-messages.md): the Transaction Service caps a message
/// signature at 5,000 bytes, and a leanSphincs one is 5,835 (5,834 in v1). Three ways out, on both Safe releases:
/// - A. leanSphincs-s as the stateless key (test-only WinterlockOwnerS and verifier): sizes, gas, end to end
/// - B. on-chain approval: a Safe transaction, signed with members' WOTS keys, delegatecalls Safe's SignMessageLib;
///      then the fallback handler accepts an empty signature
/// - C. the stateless 2-of-3 signature collected outside Safe's service (11,670 bytes), checked as apps check it
/// and how common consumers verify: sign-in with Ethereum (an eth_call), Permit2 (EIP-1271 on-chain), EIP-2612
/// (OpenZeppelin's ERC20Permit, ecrecover only). And owner v2's approved kind (0x03), which turns B's approval into k
/// owner signatures for apps that refuse the empty one (viem).
/// Option A's owner (test-only WinterlockOwnerS) is a copy of owner v1 and keeps v1's formats.
/// SignMessageLib is compiled from each release's source by the project's compiler, because setup.sh builds no
/// SignMessageLib artifact with the release settings. The release build's gas may differ slightly (not measured).
abstract contract SafeMessagesTest is Test {
    using SafeHarness for ISafe;

    event SignMsg(bytes32 indexed msgHash);

    SafeRelease internal rel;
    address internal signMessageLib;
    AppProbe internal probe;
    ColdAppProbe internal coldProbe;
    Permit2SignatureCheck internal permit2;

    /// Production owners (leanSphincs), as in SafeWinterlockOwner.t.sol
    StatelessKey[3] internal sks;
    WinterlockOwner[3] internal owners;
    ISafe internal safe; // 2-of-3

    /// Option A: owners with leanSphincs-s keys (set up by _setUpS)
    IStatelessVerifier internal verifierS;
    StatelessKey[3] internal sksS;
    WinterlockOwnerS[3] internal ownersS;
    ISafe internal safeS; // 2-of-3

    address internal recipient = makeAddr("recipient");
    address internal relayer = makeAddr("relayer");
    address internal app = makeAddr("app");
    address internal spender = makeAddr("spender");

    /// Operation trees: height 10, the first 16 keys generated (as SafeWinterlockOwner.t.sol)
    uint256 internal constant H = 10;
    uint256 internal constant K = 4;
    uint256 internal constant SEPOLIA = 11155111;
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant LEGACY_MAGIC = 0x20c13b0b;
    bytes4 internal constant INVALID = 0xffffffff;
    /// The Transaction Service's cap on a message signature, the whole entry (SIGNATURE_LENGTH)
    uint256 internal constant SERVICE_CAP = 5000;

    uint256 internal lastCalldataBytes;

    function _version() internal pure virtual returns (string memory);
    function _deploySignMessageLib() internal virtual returns (address);

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        if (ValidatorDeployment.DEPLOYER.code.length == 0) {
            vm.etch(ValidatorDeployment.DEPLOYER, ValidatorDeployment.DEPLOYER_CODE);
        }
        rel = SafeHarness.deployRelease(_version());
        signMessageLib = _deploySignMessageLib();
        probe = new AppProbe();
        coldProbe = new ColdAppProbe();
        permit2 = new Permit2SignatureCheck();
        for (uint256 i; i < 3; ++i) {
            sks[i] = StatelessSigner.testKey(_label(i));
            owners[i] = WinterlockOwner(SafeOwnerDeployment.deploy(Ops.params(_p()), StatelessSigner.publicKey(sks[i])));
        }
        safe = SafeHarness.createSafe(rel, _ownerList(), 2, 0);
        vm.deal(address(safe), 100 ether);
        vm.deal(recipient, 1 ether); // an existing account, as in steady state
        for (uint256 i; i < 3; ++i) {
            _enrol(i, address(safe), 0);
        }
    }

    // --- members (production owners) ---

    function _label(uint256 i) internal pure returns (string memory) {
        return string(abi.encode("safe member", i));
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
        return OwnerSigner.opsTree(_p(), _member(i), s, start, H, K);
    }

    function _enrol(uint256 i, address s, uint64 start) internal {
        bytes memory cd = OwnerSigner.enrollCalldata(_member(i), _tree(i, s, start), s, start);
        vm.prank(relayer);
        (bool ok,) = address(owners[i]).call(cd);
        assertTrue(ok, "enroll");
    }

    /// Member i's WOTS signature of `t`, from its enrolled tree
    function _sign(uint256 i, ISafe s, SafeTx memory t, uint256 slot) internal view returns (OwnerSignature memory) {
        (,,, uint64 start,) = owners[i].tree(address(s), 0);
        bytes memory data = OwnerSigner.txSignature(_tree(i, address(s), start), start, slot, address(s), t, s.hash(t));
        return SafeHarness.contractSig(address(owners[i]), data);
    }

    function _signed(ISafe s, SafeTx memory t, uint256 a, uint256 b) internal view returns (bytes memory) {
        return SafeHarness.pack(_sign(a, s, t, 0), _sign(b, s, t, 0));
    }

    /// Member i's stateless (leanSphincs) signature of the SafeMessage the fallback handler builds for `appHash`
    function _messageSig(uint256 i, ISafe s, bytes32 appHash) internal view returns (OwnerSignature memory) {
        bytes32 msgHash = SafeHarness.messageHash(appHash);
        bytes memory data =
            OwnerSigner.messageSignature(_member(i), address(s), msgHash, SafeHarness.safeMessageHash(s, msgHash));
        return SafeHarness.contractSig(address(owners[i]), data);
    }

    // --- option B: on-chain approval ---

    /// The Safe transaction that approves `appHash` on-chain, as Safe's app and protocol-kit build it: a delegatecall
    /// to SignMessageLib.signMessage(message) with the 32-byte app hash as the message. SignMessageLib then sets
    /// signedMessages[SafeMessage hash], the hash the fallback handler computes for isValidSignature(appHash, "").
    function _approvalTx(bytes32 appHash, uint256 nonce) internal view returns (SafeTx memory t) {
        t = SafeHarness.call(signMessageLib, abi.encodeWithSignature("signMessage(bytes)", abi.encode(appHash)), nonce);
        t.operation = 1; // delegatecall
    }

    /// Members 0 and 1 approve `appHash` with their WOTS keys at the Safe's next nonce
    function _approve(ISafe s, bytes32 appHash) internal {
        SafeTx memory t = _approvalTx(appHash, s.nonce());
        assertTrue(s.exec(t, _signed(s, t, 0, 1)));
    }

    function _check(ISafe s, bytes32 appHash, bytes memory sig) internal view returns (bool valid) {
        (valid,) = probe.check(address(s), appHash, sig);
    }

    function _safeMessageHash(ISafe s, bytes32 appHash) internal view returns (bytes32) {
        return SafeHarness.safeMessageHash(s, SafeHarness.messageHash(appHash));
    }

    /// A sign-in with Ethereum message (EIP-4361) for `who`, hashed as EIP-191 personal_sign
    function _siweHash(address who) internal view returns (bytes32) {
        string memory siwe = string.concat(
            "app.example wants you to sign in with your Ethereum account:\n",
            vm.toString(who),
            "\n\nSign in to the app.\n\nURI: https://app.example\nVersion: 1\nChain ID: ",
            vm.toString(block.chainid),
            "\nNonce: 32891756\nIssued At: 2026-11-05T12:00:00Z"
        );
        return MessageHashUtils.toEthSignedMessageHash(bytes(siwe));
    }

    /// B: before the approval the empty signature is refused; a WOTS-signed transaction approves the hash; then
    /// the fallback handler accepts the empty signature, for any app that asks.
    function test_B_approveThenEmptySignature() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        bytes32 safeMsgHash = _safeMessageHash(safe, appHash);
        assertFalse(_check(safe, appHash, ""), "not approved yet");

        SafeTx memory t = _approvalTx(appHash, 0);
        bytes memory sigs = _signed(safe, t, 0, 1);
        vm.expectEmit(true, false, false, false, address(safe));
        emit SignMsg(safeMsgHash); // SignMessageLib's event, emitted by the Safe
        assertTrue(safe.exec(t, sigs));

        assertEq(safe.signedMessages(safeMsgHash), 1);
        vm.prank(app);
        assertEq(IERC1271(address(safe)).isValidSignature(appHash, ""), MAGIC);
        // the same hash as the handler's own helper
        (bool ok, bytes memory ret) = address(safe)
            .staticcall(abi.encodeWithSignature("getMessageHashForSafe(address,bytes)", address(safe), abi.encode(appHash)));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes32)), safeMsgHash);
    }

    /// B: an approval counts for one Safe, one chain and one hash, and only for the empty signature: a non-empty
    /// signature is checked against the owners as before, so an approval never lowers that bar.
    function test_B_bindings() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        _approve(safe, appHash);
        assertTrue(_check(safe, appHash, ""));

        ISafe twin = SafeHarness.createSafe(rel, _ownerList(), 2, 1); // same owners, another address
        assertFalse(_check(twin, appHash, ""), "another Safe");
        assertFalse(_check(safe, keccak256("another message"), ""), "another message");
        vm.chainId(SEPOLIA);
        assertFalse(_check(safe, appHash, ""), "another chain");
        vm.chainId(31337);

        OwnerSignature[] memory one = new OwnerSignature[](1);
        one[0] = _messageSig(0, safe, appHash);
        assertFalse(_check(safe, appHash, SafeHarness.pack(one)), "one stateless signature of two");
        assertFalse(_check(safe, appHash, new bytes(65)), "junk signature");
        assertTrue(_check(safe, appHash, "")); // control
    }

    /// B: an approval is a Safe transaction: it needs the threshold of members' WOTS signatures, each bound to the
    /// Safe's nonce. Members' stateless keys can't approve it: a stateless signature of the SafeTx hash, as a phished
    /// "message", is refused by the owner.
    function test_B_needsQuorumOfWotsKeys() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        SafeTx memory t = _approvalTx(appHash, 0);
        OwnerSignature[] memory one = new OwnerSignature[](1);
        one[0] = _sign(0, safe, t, 0);
        vm.expectRevert(); // one member of a 2-of-3
        safe.exec(t, SafeHarness.pack(one));

        bytes32 h = safe.hash(t);
        bytes memory phished = abi.encodePacked(
            uint8(2),
            uint8(0),
            address(safe),
            bytes32(0),
            StatelessSigner.sign(sks[0], owners[0].messageDigest(address(safe), 0, 0, h))
        );
        bytes memory sigs = SafeHarness.pack(SafeHarness.contractSig(address(owners[0]), phished), _sign(1, safe, t, 0));
        vm.expectRevert("GS024");
        safe.exec(t, sigs);

        assertEq(safe.signedMessages(_safeMessageHash(safe, appHash)), 0);
        assertTrue(safe.exec(t, _signed(safe, t, 0, 1))); // control
        assertTrue(_check(safe, appHash, ""));
    }

    /// B: revoking. SignMessageLib only sets the flag: approving again leaves it set, and Safe has no function that
    /// clears it. Only a delegatecall to a library that writes Safe's storage clears it (UnsignMessageLib, test only),
    /// after which the empty signature is refused again.
    function test_B_revocation() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        bytes32 safeMsgHash = _safeMessageHash(safe, appHash);
        _approve(safe, appHash);
        _approve(safe, appHash);
        assertEq(safe.signedMessages(safeMsgHash), 1, "a second approval doesn't toggle");

        UnsignMessageLib unsign = new UnsignMessageLib();
        SafeTx memory t = SafeHarness.call(address(unsign), abi.encodeCall(UnsignMessageLib.unsignMessage, (safeMsgHash)), 2);
        t.operation = 1;
        assertTrue(safe.exec(t, _signed(safe, t, 1, 2)));
        assertEq(safe.signedMessages(safeMsgHash), 0);
        assertFalse(_check(safe, appHash, ""), "revoked");
    }

    // --- the approved kind (owner v2) ---

    /// Member i's approved signature for the SafeMessage of `appHash`: [0x03][safe][keccak256(message)], no key
    function _approvedSig(uint256 i, ISafe s, bytes32 appHash) internal view returns (OwnerSignature memory) {
        bytes memory data = OwnerSigner.approvedSignature(address(s), SafeHarness.messageHash(appHash));
        return SafeHarness.contractSig(address(owners[i]), data);
    }

    function _approvedSigs(ISafe s, bytes32 appHash, uint256 a, uint256 b) internal view returns (bytes memory) {
        return SafeHarness.pack(_approvedSig(a, s, appHash), _approvedSig(b, s, appHash));
    }

    /// keccak256 preimage of the SafeMessage hash for `appHash`, as Safe v1.4.1 passes it to an owner
    function _messagePreimage(ISafe s, bytes32 appHash) internal view returns (bytes memory pre) {
        bytes32 structHash =
            keccak256(abi.encode(keccak256("SafeMessage(bytes message)"), SafeHarness.messageHash(appHash)));
        pre = abi.encodePacked(bytes2(0x1901), s.domainSeparator(), structHash);
        assertEq(keccak256(pre), _safeMessageHash(s, appHash));
    }

    /// The approved kind: before the quorum approves the message on-chain, k approved signatures are refused, like
    /// the empty signature; after the SignMessageLib transaction, the Safe's isValidSignature accepts them through
    /// either release's fallback handler, from any k owners, and each owner answers both entry points. 150 bytes per
    /// owner in Safe's encoding, so the answer passes viem's ERC-6492 length check (at least 32 bytes); Permit2
    /// accepts it.
    function test_approved_beforeAndAfter() public {
        bytes32 appHash = keccak256("a Permit2 PermitSingle digest");
        bytes memory sigs = _approvedSigs(safe, appHash, 0, 1);
        assertEq(sigs.length, 2 * (65 + 32 + 53));
        assertFalse(_check(safe, appHash, sigs), "not approved yet");
        vm.expectRevert();
        permit2.verify(sigs, appHash, address(safe));
        bytes32 safeMsgHash = _safeMessageHash(safe, appHash);
        bytes memory one = _approvedSig(2, safe, appHash).data;
        assertEq(owners[2].isValidSignature(safeMsgHash, one), INVALID);

        _approve(safe, appHash);
        assertTrue(_check(safe, appHash, sigs));
        assertTrue(_check(safe, appHash, _approvedSigs(safe, appHash, 1, 2)), "any two owners");
        assertTrue(_check(safe, appHash, ""), "and the empty signature, as before");
        permit2.verify(sigs, appHash, address(safe));
        assertEq(owners[2].isValidSignature(safeMsgHash, one), MAGIC);
        assertEq(owners[2].isValidSignature(_messagePreimage(safe, appHash), one), LEGACY_MAGIC);
        OwnerSignature[] memory single = new OwnerSignature[](1);
        single[0] = _approvedSig(0, safe, appHash);
        assertFalse(_check(safe, appHash, SafeHarness.pack(single)), "one of two");
        // mixed with a stateless signature
        assertTrue(
            _check(safe, appHash, SafeHarness.pack(_approvedSig(0, safe, appHash), _messageSig(1, safe, appHash)))
        );
        // after the approval is withdrawn (test-only library), refused again
        UnsignMessageLib unsign = new UnsignMessageLib();
        SafeTx memory t =
            SafeHarness.call(address(unsign), abi.encodeCall(UnsignMessageLib.unsignMessage, (safeMsgHash)), 1);
        t.operation = 1;
        assertTrue(safe.exec(t, _signed(safe, t, 1, 2)));
        assertFalse(_check(safe, appHash, sigs), "withdrawn");
    }

    /// The approved kind can't approve a Safe transaction. Approved signatures for an approved message don't execute
    /// a transaction; and even with signedMessages set for the SafeTx hash itself (by a library no Safe ships), no
    /// approved signature names it, because the owner accepts only the Safe's SafeMessage hashes.
    function test_approved_cannotApproveSafeTx() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        _approve(safe, appHash); // nonce 0
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 2);
        bytes32 h = safe.hash(t);
        MarkSignedLib mark = new MarkSignedLib();
        SafeTx memory m = SafeHarness.call(address(mark), abi.encodeCall(MarkSignedLib.markSigned, (h)), 1);
        m.operation = 1;
        assertTrue(safe.exec(m, _signed(safe, m, 0, 1)));
        assertEq(safe.signedMessages(h), 1);

        bytes32[3] memory named = [SafeHarness.messageHash(appHash), h, keccak256(abi.encode(h))];
        for (uint256 i; i < named.length; ++i) {
            bytes memory one = OwnerSigner.approvedSignature(address(safe), named[i]);
            assertEq(owners[0].isValidSignature(h, one), INVALID);
            bytes memory sigs = SafeHarness.pack(
                SafeHarness.contractSig(address(owners[0]), one), SafeHarness.contractSig(address(owners[1]), one)
            );
            vm.expectRevert("GS024");
            safe.exec(t, sigs);
        }
        assertTrue(safe.exec(t, _signed(safe, t, 0, 1))); // control
    }

    /// Every kind is bound to the Safe and the hash it names. For each kind, a signature that is valid for `safe` is
    /// refused for the twin's hash (a Safe with the same owners, trees enrolled and the message approved there too),
    /// refused once it names the twin, and refused for another hash.
    function test_safeAndHashBoundForEveryKind() public {
        ISafe twin = SafeHarness.createSafe(rel, _ownerList(), 2, 1);
        vm.deal(address(twin), 1 ether);
        for (uint256 i; i < 3; ++i) {
            _enrol(i, address(twin), 0);
        }
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        _approve(safe, appHash);
        _approve(twin, appHash);
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 1);
        bytes[3] memory sigs = [
            _sign(0, safe, t, 0).data,
            _messageSig(0, safe, appHash).data,
            OwnerSigner.approvedSignature(address(safe), SafeHarness.messageHash(appHash))
        ];
        bytes32[3] memory hashes = [safe.hash(t), _safeMessageHash(safe, appHash), _safeMessageHash(safe, appHash)];
        bytes32[3] memory twinHashes = [twin.hash(t), _safeMessageHash(twin, appHash), _safeMessageHash(twin, appHash)];
        for (uint256 k; k < 3; ++k) {
            assertEq(owners[0].isValidSignature(hashes[k], sigs[k]), MAGIC, "control");
            assertEq(owners[0].isValidSignature(twinHashes[k], sigs[k]), INVALID, "the twin's hash");
            // the Safe's address sits after the kind and, but for the approved kind, the device
            bytes memory renamed = _renameSafe(sigs[k], address(twin), k == 2 ? 1 : 2);
            assertEq(owners[0].isValidSignature(hashes[k], renamed), INVALID, "naming the twin");
            assertEq(owners[0].isValidSignature(keccak256("another hash"), sigs[k]), INVALID, "another hash");
        }
    }

    /// `sig` with `to` written over the 20 bytes at `at`
    function _renameSafe(bytes memory sig, address to, uint256 at) internal pure returns (bytes memory out) {
        out = bytes.concat(sig);
        bytes20 a = bytes20(to);
        for (uint256 i; i < 20; ++i) {
            out[at + i] = a[i];
        }
    }

    // --- consumers ---

    /// B, as common consumers verify. Sign-in with Ethereum: an eth_call of isValidSignature with the EIP-191 hash and
    /// the empty signature the wallet returns. Permit2: its signature check accepts the empty signature from a contract
    /// owner whose isValidSignature agrees. EIP-2612 with OpenZeppelin's ERC20Permit: refused, although the Safe
    /// approved the permit digest, because permit only runs ecrecover, which no contract account can satisfy.
    function test_consumers_onChainApproval() public {
        // sign-in with Ethereum
        bytes32 siwe = _siweHash(address(safe));
        vm.prank(address(0));
        assertFalse(_check(safe, siwe, ""));
        _approve(safe, siwe);
        vm.prank(address(0)); // eth_call without a sender
        assertEq(IERC1271(address(safe)).isValidSignature(siwe, ""), MAGIC);

        // Permit2
        bytes32 permitDigest = keccak256("a Permit2 PermitSingle digest");
        vm.expectRevert();
        permit2.verify("", permitDigest, address(safe));
        _approve(safe, permitDigest);
        permit2.verify("", permitDigest, address(safe)); // doesn't revert

        // EIP-2612, OpenZeppelin's ERC20Permit
        PermitToken token = new PermitToken(address(safe));
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                address(safe),
                spender,
                100 ether,
                token.nonces(address(safe)),
                deadline
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(token.DOMAIN_SEPARATOR(), structHash);
        _approve(safe, digest);
        assertTrue(_check(safe, digest, ""), "the Safe approves the permit");
        vm.expectRevert(); // ecrecover yields some other address (or none) for any (v, r, s)
        token.permit(address(safe), spender, 100 ether, deadline, 27, bytes32(uint256(1)), bytes32(uint256(2)));
        assertEq(token.allowance(address(safe), spender), 0);
    }

    /// C, as common consumers verify: the members' stateless 2-of-3 signature (11,670 bytes), with no on-chain state.
    /// Sign-in with Ethereum (eth_call) and Permit2 accept it; EIP-2612 can't carry it (v, r, s only).
    function test_consumers_statelessSignature() public {
        bytes32 siwe = _siweHash(address(safe));
        bytes memory sigs = SafeHarness.pack(_messageSig(0, safe, siwe), _messageSig(2, safe, siwe));
        assertEq(sigs.length, 2 * (65 + 32 + 2 + 20 + 32 + 5684));
        vm.prank(address(0));
        assertEq(IERC1271(address(safe)).isValidSignature(siwe, sigs), MAGIC);

        bytes32 permitDigest = keccak256("a Permit2 PermitSingle digest");
        sigs = SafeHarness.pack(_messageSig(0, safe, permitDigest), _messageSig(1, safe, permitDigest));
        permit2.verify(sigs, permitDigest, address(safe));
        vm.expectRevert(); // the signature is for another hash
        permit2.verify(sigs, siwe, address(safe));
        assertEq(safe.signedMessages(_safeMessageHash(safe, permitDigest)), 0, "no on-chain state");
    }

    // --- option A: leanSphincs-s ---

    function _labelS(uint256 i) internal pure returns (string memory) {
        return string(abi.encode("safe member s", i));
    }

    function _ownerListS() internal view returns (address[] memory list) {
        list = new address[](3);
        for (uint256 i; i < 3; ++i) {
            list[i] = address(ownersS[i]);
        }
    }

    function _setUpS() internal {
        verifierS = IStatelessVerifier(address(new LeanSphincsSAsm()));
        for (uint256 i; i < 3; ++i) {
            sksS[i] = StatelessSignerS.testKey(_labelS(i));
            ownersS[i] = new WinterlockOwnerS(Ops.params(_p()), verifierS, StatelessSigner.publicKey(sksS[i]));
        }
        safeS = SafeHarness.createSafe(rel, _ownerListS(), 2, 100);
        vm.deal(address(safeS), 100 ether);
        for (uint256 i; i < 3; ++i) {
            vm.prank(relayer);
            (bool ok,) = address(ownersS[i]).call(_enrollCalldataS(i, address(safeS), 0));
            assertTrue(ok, "enroll (leanSphincs-s)");
        }
    }

    /// Member i's operation tree of `s` from `start` for its leanSphincs-s owner, which keeps owner v1's tree seed
    function _treeS(uint256 i, address s, uint64 start) internal view returns (WotsKey memory) {
        bytes32 skSeed = keccak256(abi.encode(_labelS(i), "safe ops", block.chainid, s, start));
        return WotsTree.create(_p(), ownersS[i].treeSeed(s, start), skSeed, H, K);
    }

    /// WinterlockOwnerS.enroll with member i's leanSphincs-s certificate for its tree of `s` from `start`
    function _enrollCalldataS(uint256 i, address s, uint64 start) internal view returns (bytes memory) {
        WotsKey memory tree = _treeS(i, s, start);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 height = uint8(tree.height);
        bytes memory cert = StatelessSignerS.sign(sksS[i], ownersS[i].certificateDigest(s, tree.root, height, start));
        return abi.encodeCall(WinterlockOwnerS.enroll, (s, tree.root, height, start, cert));
    }

    /// Member i's slot-0 signature of `t` in owner v1's format: [slot][safe][SafeTx words][WOTS signature][path]
    function _signS(uint256 i, ISafe s, SafeTx memory t) internal view returns (OwnerSignature memory) {
        (,,, uint64 start) = ownersS[i].tree(address(s));
        WotsKey memory tree = _treeS(i, address(s), start);
        uint256 keyIndex = (t.nonce - start) * 2;
        bytes memory wots = bytes.concat(
            WotsSigner.sign(tree.p, tree.seed, tree.skSeed, keyIndex, s.hash(t)), WotsTree.path(tree, keyIndex)
        );
        bytes memory data = abi.encodePacked(uint8(0), address(s), SafeHarness.words(t), wots);
        return SafeHarness.contractSig(address(ownersS[i]), data);
    }

    /// Member i's leanSphincs-s signature of the SafeMessage for `appHash`: [0x02][safe][msgHash][4,164 bytes]
    function _messageSigS(uint256 i, ISafe s, bytes32 appHash) internal view returns (OwnerSignature memory) {
        bytes32 msgHash = SafeHarness.messageHash(appHash);
        bytes32 digest = ownersS[i].messageDigest(address(s), SafeHarness.safeMessageHash(s, msgHash));
        bytes memory data = abi.encodePacked(uint8(2), address(s), msgHash, StatelessSignerS.sign(sksS[i], digest));
        return SafeHarness.contractSig(address(ownersS[i]), data);
    }

    function _confirmation(OwnerSignature memory sig) internal pure returns (bytes memory) {
        OwnerSignature[] memory one = new OwnerSignature[](1);
        one[0] = sig;
        return SafeHarness.pack(one);
    }

    /// A: with leanSphincs-s, one member's message confirmation, as the Transaction Service counts it (65 + 32 + data),
    /// is 4,314 bytes (in owner v1's format) and fits the 5,000-byte cap; leanSphincs's is 5,835 in owner v2's. The owner answers the service's checks (an
    /// eth_call with the SafeMessage hash, then the legacy entry with its preimage). The combined 2-of-3 signature
    /// (8,628 bytes) passes the fallback handler and Permit2. Transactions stay on WOTS and are unchanged.
    function test_A_leanSphincsSMessagesFitTheService() public {
        _setUpS();
        bytes32 appHash = _siweHash(address(safeS));
        OwnerSignature memory m0 = _messageSigS(0, safeS, appHash);
        OwnerSignature memory m2 = _messageSigS(2, safeS, appHash);

        bytes32 msgHash = SafeHarness.messageHash(appHash);
        bytes32 safeMsgHash = SafeHarness.safeMessageHash(safeS, msgHash);
        bytes memory preimage = abi.encodePacked(
            bytes2(0x1901),
            safeS.domainSeparator(),
            keccak256(abi.encode(keccak256("SafeMessage(bytes message)"), msgHash))
        );
        assertEq(keccak256(preimage), safeMsgHash);
        vm.startPrank(address(0)); // as the service's eth_call
        assertEq(ownersS[0].isValidSignature(safeMsgHash, m0.data), MAGIC);
        assertEq(ownersS[0].isValidSignature(preimage, m0.data), LEGACY_MAGIC);
        vm.stopPrank();

        assertEq(m0.data.length, 1 + 20 + 32 + 4164);
        assertEq(_confirmation(m0).length, 4314);
        assertLe(_confirmation(m0).length, SERVICE_CAP, "fits the service");
        assertEq(_confirmation(_messageSig(0, safe, appHash)).length, 5835);
        assertGt(_confirmation(_messageSig(0, safe, appHash)).length, SERVICE_CAP, "leanSphincs doesn't");

        bytes memory sigs = SafeHarness.pack(m0, m2);
        assertEq(sigs.length, 8628);
        vm.prank(app);
        assertEq(IERC1271(address(safeS)).isValidSignature(appHash, sigs), MAGIC);
        permit2.verify(sigs, appHash, address(safeS));
        assertFalse(_check(safeS, keccak256("another message"), sigs));

        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(safeS.exec(t, SafeHarness.pack(_signS(0, safeS, t), _signS(1, safeS, t))));
        assertEq(recipient.balance, 2 ether);
    }

    // --- gas and sizes ---

    /// B: transaction gas of an approval, 2-of-3 WinterlockOwners, steady state (nonce >= 1), next to an ETH transfer
    /// with the same signers and to the same approval by a 2-of-3 ECDSA Safe; then the app's check of the empty
    /// signature in a fresh transaction (cold), next to the 2-of-3 stateless check (C).
    function test_gas_onChainApproval() public {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(safe.exec(t, _signed(safe, t, 0, 1))); // nonce 0 -> 1

        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        t = _approvalTx(appHash, 1);
        uint256 approval = _txGas(address(safe), SafeHarness.execCalldata(t, _signed(safe, t, 0, 1)));
        uint256 approvalBytes = lastCalldataBytes;
        t = SafeHarness.transfer(recipient, 1 ether, 2);
        uint256 transfer = _txGas(address(safe), SafeHarness.execCalldata(t, _signed(safe, t, 0, 1)));
        uint256 ecdsaApproval = _ecdsaApprovalGas(appHash);

        (bool valid, uint256 emptyCheck) = probe.check(address(safe), appHash, "");
        assertTrue(valid);
        bytes32 other = keccak256("another permit");
        (bool valid2, uint256 statelessCheck) =
            probe.check(address(safe), other, SafeHarness.pack(_messageSig(0, safe, other), _messageSig(1, safe, other)));
        assertTrue(valid2);

        console.log(string.concat("Safe ", rel.version, ", on-chain approval (B)"));
        console.log("approval tx gas, 2-of-3 WinterlockOwners", approval, ", calldata bytes", approvalBytes);
        console.log("ETH transfer tx gas, same signers       ", transfer);
        console.log("approval tx gas, 2-of-3 ECDSA owners    ", ecdsaApproval);
        console.log("app's check, empty signature (cold)     ", emptyCheck);
        console.log("app's check, 2-of-3 leanSphincs (cold)  ", statelessCheck);
    }

    /// Owner v2's approved kind, once the message is approved: the app's check (Safe.isValidSignature through the
    /// fallback handler) with two approved signatures against the empty signature, and one owner's check on its own,
    /// each call in a transaction of its own, so everything is cold. The gas of the call, without the app's calldata.
    function test_gas_approvedKind() public {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        _approve(safe, appHash);
        bytes memory sigs = _approvedSigs(safe, appHash, 0, 1);
        (bool v1, uint256 empty) = coldProbe.check(address(safe), appHash, "");
        (bool v2, uint256 approved) = coldProbe.check(address(safe), appHash, sigs);
        bytes memory one = _approvedSig(2, safe, appHash).data;
        (bool v3, uint256 owner) = coldProbe.check(address(owners[2]), _safeMessageHash(safe, appHash), one);
        assertTrue(v1 && v2 && v3);
        console.log(string.concat("Safe ", rel.version, ", the approved kind (owner v2), cold"));
        console.log("app's check, empty signature        ", empty);
        console.log("app's check, 2 approved signatures  ", approved, ", more", approved - empty);
        console.log("one owner's check, approved kind     ", owner);
        console.log("2 approved signatures, bytes        ", sigs.length);
    }

    function _ecdsaApprovalGas(bytes32 appHash) internal returns (uint256) {
        uint256[3] memory pks = [uint256(0xA11CE), 0xB0B, 0xCA401];
        address[] memory eoas = new address[](3);
        for (uint256 i; i < 3; ++i) {
            eoas[i] = vm.addr(pks[i]);
        }
        ISafe s = SafeHarness.createSafe(rel, eoas, 2, 99);
        vm.deal(address(s), 10 ether);
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(s.exec(t, _ecdsaSigned(s, t, pks[0], pks[1])));
        t = _approvalTx(appHash, 1);
        uint256 g = _txGas(address(s), SafeHarness.execCalldata(t, _ecdsaSigned(s, t, pks[0], pks[1])));
        assertTrue(_check(s, appHash, ""));
        return g;
    }

    function _ecdsaSigned(ISafe s, SafeTx memory t, uint256 a, uint256 b) internal view returns (bytes memory) {
        bytes32 h = s.hash(t);
        return SafeHarness.pack(SafeHarness.ecdsa(a, h), SafeHarness.ecdsa(b, h));
    }

    /// A: leanSphincs-s against leanSphincs: the app's 2-of-3 check (cold), and enrolment (a first tree for a Safe,
    /// and a rotation), whose certificate carries one stateless signature.
    function test_gas_leanSphincsS() public {
        _setUpS();
        console.log(string.concat("Safe ", rel.version, ", leanSphincs-s (A) against leanSphincs"));
        _logMessageCheckGas();
        _logEnrolGas();
    }

    function _logMessageCheckGas() internal view {
        bytes32 appHash = keccak256("permit: 100 TST to app, nonce 7");
        bytes memory sigsL = SafeHarness.pack(_messageSig(0, safe, appHash), _messageSig(1, safe, appHash));
        bytes memory sigsS = SafeHarness.pack(_messageSigS(0, safeS, appHash), _messageSigS(1, safeS, appHash));
        (bool okL, uint256 checkL) = probe.check(address(safe), appHash, sigsL);
        (bool okS, uint256 checkS) = probe.check(address(safeS), appHash, sigsS);
        assertTrue(okL && okS);
        console.log("app's 2-of-3 check (cold): leanSphincs", checkL, ", leanSphincs-s", checkS);
        console.log("2-of-3 signature bytes:    leanSphincs", sigsL.length, ", leanSphincs-s", sigsS.length);
    }

    function _logEnrolGas() internal {
        uint64 next = 5; // a rotation: a tree from nonce 5 replaces the tree from 0
        bytes memory cd = OwnerSigner.enrollCalldata(_member(0), _tree(0, address(safe), next), address(safe), next);
        uint256 rotL = _txGas(address(owners[0]), cd);
        uint256 rotS = _txGas(address(ownersS[0]), _enrollCalldataS(0, address(safeS), next));
        console.log("enroll, rotation, tx gas:   leanSphincs", rotL, ", leanSphincs-s", rotS);

        ISafe twin = SafeHarness.createSafe(rel, _ownerList(), 2, 1);
        cd = OwnerSigner.enrollCalldata(_member(0), _tree(0, address(twin), 0), address(twin), 0);
        uint256 firstL = _txGas(address(owners[0]), cd);
        uint256 bytesL = lastCalldataBytes;
        ISafe twinS = SafeHarness.createSafe(rel, _ownerListS(), 2, 101);
        uint256 firstS = _txGas(address(ownersS[0]), _enrollCalldataS(0, address(twinS), 0));
        // the signatures, ABI-padded to whole words, and owner v2's device argument
        assertEq(bytesL - lastCalldataBytes, 5696 - 4192 + 32);
        console.log("enroll, first tree, tx gas: leanSphincs", firstL, ", leanSphincs-s", firstS);
        console.log("enroll calldata bytes:      leanSphincs", bytesL, ", leanSphincs-s", lastCalldataBytes);
    }

    /// The gas of a transaction to `to` with calldata `cd` (Forge runs each top-level call as its own transaction;
    /// see SafeWinterlockOwner.t.sol, _txGas)
    function _txGas(address to, bytes memory cd) internal returns (uint256) {
        lastCalldataBytes = cd.length;
        (bool ok,) = to.call(cd);
        assertTrue(ok, "measured transaction failed");
        return vm.lastCallGas().gasTotalUsed;
    }
}

contract SafeMessagesV141Test is SafeMessagesTest {
    function _version() internal pure override returns (string memory) {
        return "v1.4.1";
    }

    function _deploySignMessageLib() internal override returns (address) {
        return address(new SignMessageLibV141());
    }
}

contract SafeMessagesV150Test is SafeMessagesTest {
    function _version() internal pure override returns (string memory) {
        return "v1.5.0";
    }

    function _deploySignMessageLib() internal override returns (address) {
        return address(new SignMessageLibV150());
    }
}
