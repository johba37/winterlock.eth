// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {MiniAccount, ValidationProbe} from "./utils/Harness.sol";
import {WotsParams, MemberKeys, Ops} from "./utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./utils/StatelessSigner.sol";

/// D11: off-chain messages (ERC-1271, isValidSignatureWithSender) signed with members' stateless keys over a typed
/// wrap that binds the chain, the account and the validator; k-of-n in team accounts. The key comes from storage, and
/// the account asking on its own behalf (Kernel's enable mode) is refused.
contract WinterlockMessagesTest is Test {
    EntryPoint internal ep;
    WinterlockValidator internal val;
    MiniAccount internal solo; // 1-of-1: member 0
    MiniAccount internal team; // 2-of-3: members 0, 1, 2
    StatelessKey[3] internal sks; // stateless keys, kept: their keygen is costly
    address internal app = makeAddr("app"); // the contract asking the account (Permit2, a marketplace)

    uint256 internal constant H = 3;
    bytes4 internal constant OK = 0x1626ba7e;
    bytes4 internal constant NO = 0xffffffff;
    bytes32 internal constant HASH = keccak256("permit: 100 USDC to app, nonce 7");

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        ep = new EntryPoint();
        val = new WinterlockValidator(Ops.params(_p()), Ops.deployStatelessVerifier());
        for (uint256 i; i < 3; ++i) {
            sks[i] = StatelessSigner.testKey(_label(i));
        }
        solo = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(_member(0)));
        team = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(_members(), 2));
    }

    function _label(uint256 i) internal pure returns (string memory) {
        return string(abi.encode("message member", i));
    }

    function _member(uint256 i) internal view returns (MemberKeys memory) {
        return Ops.keys(_p(), _label(i), H, H, sks[i]);
    }

    function _members() internal view returns (MemberKeys[] memory ks) {
        ks = new MemberKeys[](3);
        for (uint256 i; i < 3; ++i) {
            ks[i] = _member(i);
        }
    }

    /// Member i's entry for `hash` checked by `account` (member index = i)
    function _entry(address account, uint256 i, bytes32 hash) internal view returns (bytes memory) {
        return Ops.messageEntry(val, account, _member(i), i, hash);
    }

    function _check(address account, bytes32 hash, bytes memory sig) internal returns (bytes4) {
        vm.prank(account);
        return val.isValidSignatureWithSender(app, hash, sig);
    }

    // --- 1-of-1 ---

    function test_messageSignatureAccepted() public {
        bytes memory sig = _entry(address(solo), 0, HASH);
        assertEq(sig.length, 1 + StatelessSigner.SIG_BYTES, "[member index][stateless signature]");
        assertEq(_check(address(solo), HASH, sig), OK);
    }

    /// The account asking on its own behalf (sender = the account) is refused, whatever the signature: that is how
    /// Kernel's enable mode asks before installing a module (test/integration/KernelWinterlock.t.sol). Any other
    /// sender is an app asking, and gets an answer.
    function test_accountAskingForItselfRefused() public {
        bytes memory sig = _entry(address(solo), 0, HASH);
        vm.prank(address(solo));
        assertEq(val.isValidSignatureWithSender(address(solo), HASH, sig), NO, "the account itself");
        assertEq(_check(address(solo), HASH, sig), OK, "an app");
        bytes memory both = bytes.concat(_entry(address(team), 0, HASH), _entry(address(team), 1, HASH));
        vm.prank(address(team));
        assertEq(val.isValidSignatureWithSender(address(team), HASH, both), NO, "a team quorum, the account itself");
        assertEq(_check(address(team), HASH, both), OK, "a team quorum, an app");
    }

    /// The wrap is EIP-712: domain Winterlock v1 with chain id and validator, WinterlockMessage(account, hash).
    function test_messageDigestIsTypedData() public view {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Winterlock"),
                keccak256("1"),
                block.chainid,
                address(val)
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(keccak256("WinterlockMessage(address account,bytes32 hash)"), address(solo), HASH));
        assertEq(val.domainSeparator(), domain);
        assertEq(val.messageDigest(address(solo), HASH), keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
    }

    function test_otherHashRejected() public {
        assertEq(_check(address(solo), keccak256("other"), _entry(address(solo), 0, HASH)), NO);
    }

    /// Same keys in another account: a signature for one account doesn't count for the other.
    function test_otherAccountRejected() public {
        MiniAccount twin = new MiniAccount{value: 1 ether}(ep, val, Ops.installData(_member(0)));
        bytes memory sig = _entry(address(solo), 0, HASH);
        assertEq(_check(address(twin), HASH, sig), NO);
        assertEq(_check(address(solo), HASH, sig), OK);
    }

    function test_otherChainRejected() public {
        bytes memory sig = _entry(address(solo), 0, HASH);
        vm.chainId(42161);
        assertEq(_check(address(solo), HASH, sig), NO);
    }

    /// Another validator (a later version, same account): its domain differs.
    function test_otherValidatorRejected() public {
        WinterlockValidator other = new WinterlockValidator(Ops.params(_p()), val.STATELESS_VERIFIER());
        vm.prank(address(solo));
        other.onInstall(Ops.installData(_member(0)));
        bytes memory sig = _entry(address(solo), 0, HASH); // for val
        vm.prank(address(solo));
        assertEq(other.isValidSignatureWithSender(app, HASH, sig), NO);
    }

    function test_malformedSignaturesRejected() public {
        bytes memory sig = _entry(address(solo), 0, HASH);
        assertEq(_check(address(solo), HASH, ""), NO, "empty");
        assertEq(_check(address(solo), HASH, bytes.concat(sig, hex"00")), NO, "trailing byte");
        bytes memory short = new bytes(sig.length - 1);
        for (uint256 i; i < short.length; ++i) {
            short[i] = sig[i];
        }
        assertEq(_check(address(solo), HASH, short), NO, "short");
        bytes memory wrongIndex = bytes.concat(sig);
        wrongIndex[0] = 0x01;
        assertEq(_check(address(solo), HASH, wrongIndex), NO, "no member 1");
        bytes memory flipped = bytes.concat(sig);
        flipped[1000] ^= 0x01;
        assertEq(_check(address(solo), HASH, flipped), NO, "signature byte");
        assertEq(_check(makeAddr("not installed"), HASH, sig), NO, "account without config");
    }

    /// Another key's signature under member 0: checked against member 0's stored key, so refused.
    function test_foreignKeyRejected() public {
        StatelessKey memory mallory = StatelessSigner.testKey("mallory");
        bytes memory sig =
            abi.encodePacked(uint8(0), StatelessSigner.sign(mallory, val.messageDigest(address(solo), HASH)));
        assertEq(_check(address(solo), HASH, sig), NO);
    }

    /// The stateless key signs certificates and messages. Neither can stand in for the other: a message signature is
    /// over the typed wrap, never over a raw hash, so an app that asks the member to sign a certificate digest as a
    /// "message" gets nothing it can use as a certificate; and a certificate's signature is not a message signature.
    function test_messagesAndCertificatesDontMix() public {
        StatelessKey memory none;
        MemberKeys memory attacker = Ops.forAccount(val, address(solo), 0, Ops.keys(_p(), "attacker tree", H, H, none));
        bytes32 certDigest = val.statelessCertificateDigest(address(solo), 0, attacker.ops.root, uint8(H), 0);

        // the member signs certDigest as an ERC-1271 message (valid as a message)
        bytes memory msgSig = _entry(address(solo), 0, certDigest);
        assertEq(_check(address(solo), certDigest, msgSig), OK);
        // ... which doesn't certify the attacker's tree
        bytes memory cert =
            abi.encodePacked(attacker.ops.root, uint8(H), uint64(0), _slice(msgSig, 1, StatelessSigner.SIG_BYTES));
        PackedUserOperation memory op = Ops.build(address(solo), 0, "", 900_000);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(attacker, 0, 0, 0, cert, h);
        vm.prank(address(solo));
        assertEq(val.validateUserOp(op, h), 1);
        assertEq(val.tree(address(solo), 0).root, bytes32(0));

        // and a certificate's signature is no message signature for its digest
        MemberKeys memory own = Ops.forAccount(val, address(solo), 0, _member(0));
        bytes memory ownCert = Ops.certificate(val, address(solo), 0, own);
        bytes32 ownDigest = val.statelessCertificateDigest(address(solo), 0, own.ops.root, uint8(H), 0);
        bytes memory asMessage = abi.encodePacked(uint8(0), _slice(ownCert, 41, StatelessSigner.SIG_BYTES));
        assertEq(_check(address(solo), ownDigest, asMessage), NO);
        // control: the same certificate enrols the member's own tree
        op.signature = Ops.entry(own, 0, 0, 0, ownCert, h);
        vm.prank(address(solo));
        assertEq(val.validateUserOp(op, h), 0);
    }

    function _slice(bytes memory b, uint256 from, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = b[from + i];
        }
    }

    // --- k-of-n ---

    function test_teamTwoOfThree() public {
        bytes memory a = _entry(address(team), 0, HASH);
        bytes memory b = _entry(address(team), 1, HASH);
        bytes memory c = _entry(address(team), 2, HASH);
        assertEq(_check(address(team), HASH, bytes.concat(a, c)), OK, "A and C");
        assertEq(_check(address(team), HASH, bytes.concat(b, c)), OK, "B and C");
        assertEq(_check(address(team), HASH, bytes.concat(a, b, c)), OK, "all three");
        assertEq(_check(address(team), HASH, b), NO, "B alone");
        assertEq(_check(address(team), HASH, bytes.concat(c, a)), NO, "out of order");
        assertEq(_check(address(team), HASH, bytes.concat(a, a)), NO, "A twice");
        // one invalid entry fails the whole signature, even with a quorum besides it
        bytes memory badB = bytes.concat(b);
        badB[2000] ^= 0x01;
        assertEq(_check(address(team), HASH, bytes.concat(a, badB, c)), NO, "A, forged B, C");
    }

    /// A member's signature under another member's index: checked against that member's stored key.
    function test_teamEntryUnderWrongIndexRejected() public {
        bytes memory a = _entry(address(team), 0, HASH);
        bytes memory aAsB = bytes.concat(a);
        aAsB[0] = 0x01;
        assertEq(_check(address(team), HASH, bytes.concat(a, aAsB)), NO);
    }

    // --- gas ---

    /// ERC-1271 gas in the validator, called by the account with the validator and verifier cold, as in a fresh
    /// transaction: 1-of-1 and 2-of-3.
    function test_gas_messages() public {
        ValidationProbe solo1 = new ValidationProbe();
        solo1.install(val, Ops.installData(_member(0)));
        ValidationProbe team2 = new ValidationProbe();
        team2.install(val, Ops.installData(_members(), 2));
        bytes memory one = Ops.messageEntry(val, address(solo1), _member(0), 0, HASH);
        bytes memory two = bytes.concat(
            Ops.messageEntry(val, address(team2), _member(0), 0, HASH),
            Ops.messageEntry(val, address(team2), _member(2), 2, HASH)
        );
        (bytes4 r1, uint256 g1) = _measure(solo1, one);
        (bytes4 r2, uint256 g2) = _measure(team2, two);
        assertEq(r1, OK);
        assertEq(r2, OK);
        console.log("isValidSignatureWithSender gas, 1-of-1", g1, ", bytes", one.length);
        console.log("isValidSignatureWithSender gas, 2-of-3", g2, ", bytes", two.length);
    }

    function _measure(ValidationProbe probe, bytes memory sig) internal returns (bytes4, uint256) {
        vm.cool(address(val));
        vm.cool(address(val.STATELESS_VERIFIER()));
        vm.prank(address(this));
        return probe.measureMessage(val, HASH, sig);
    }
}
