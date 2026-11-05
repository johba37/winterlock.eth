// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ISafe} from "safe-v1.5.0/interfaces/ISafe.sol";
import {IOwnerManager} from "safe-v1.5.0/interfaces/IOwnerManager.sol";

import {WinterlockOwner} from "../../src/safe/WinterlockOwner.sol";
import {ValidatorDeployment} from "../../script/DeployValidator.s.sol";
import {SafeOwnerDeployment} from "../../script/DeploySafeOwner.s.sol";
import {WotsParams, WotsKey, Ops} from "../utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "../utils/StatelessSigner.sol";
import {
    SafeHarness,
    SafeRelease,
    SafeTx,
    OwnerSignature,
    Member,
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

/// Winterlock as Safe owners: three members' WinterlockOwners own a 2-of-3 Safe, checked by Safe's own multisig path
/// (contract signatures, v = 0). Safe's contracts come from their release builds (setup.sh). Parameter set D6.
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
        return OwnerSigner.opsTree(_p(), _member(i), s, start, H, K);
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
        (,,, uint64 start) = owners[i].tree(address(s));
        bytes memory data = OwnerSigner.txSignature(_tree(i, address(s), start), start, slot, address(s), t, s.hash(t));
        return SafeHarness.contractSig(address(owners[i]), data);
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
            assertGt(a[i].code.length, 0);
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
            uint8(2), address(safe), bytes32(0), StatelessSigner.sign(sks[0], owners[0].messageDigest(address(safe), h))
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

    /// Transaction gas of execTransaction for a 2-of-3 Safe of WinterlockOwners against 2-of-3 ECDSA owners, both at
    /// steady state: nonce >= 1, and the recipient's ETH and token balances nonzero. See _txGas.
    function test_gas_execTransaction() public {
        (uint256 wlEth, uint256 wlErc20, uint256 sigBytes) = _winterlockGas();
        (uint256 wlBytes, uint256 wlCalldataGas) = (lastCalldataBytes, lastCalldataGas);
        (uint256 ecEth, uint256 ecErc20) = _ecdsaGas();
        console.log(string.concat("Safe ", rel.version, ", transaction gas"));
        console.log("ETH transfer, 2-of-3 ECDSA owners       ", ecEth);
        console.log("ETH transfer, 2-of-3 WinterlockOwners   ", wlEth);
        console.log("ERC-20 transfer, 2-of-3 ECDSA owners    ", ecErc20);
        console.log("ERC-20 transfer, 2-of-3 WinterlockOwners", wlErc20);
        console.log("contract signature per owner, bytes     ", sigBytes);
        console.log("as a confirmation (65 + 32 + data)      ", 97 + sigBytes);
        console.log("ERC-20 calldata, bytes, ECDSA owners    ", lastCalldataBytes, ", gas", lastCalldataGas);
        console.log("ERC-20 calldata, bytes, WinterlockOwners", wlBytes, ", gas", wlCalldataGas);
        assertEq(sigBytes, 1 + 20 + 320 + 1176 + 24 * H);
        assertLt(97 + sigBytes, 5000, "fits the Transaction Service's 5,000-byte confirmation");
    }

    function _winterlockGas() internal returns (uint256 eth, uint256 erc20, uint256 sigBytes) {
        SafeTx memory t = SafeHarness.transfer(recipient, 1 ether, 0);
        assertTrue(safe.exec(t, _signed(safe, t, 0, 1))); // nonce 0 -> 1
        t.nonce = 1;
        OwnerSignature memory a = _sign(0, safe, t, 0);
        sigBytes = a.data.length;
        eth = _txGas(address(safe), SafeHarness.execCalldata(t, SafeHarness.pack(a, _sign(1, safe, t, 0))));
        t = SafeHarness.call(address(token), abi.encodeCall(ERC20.transfer, (recipient, 1 ether)), 2);
        erc20 = _txGas(address(safe), SafeHarness.execCalldata(t, _signed(safe, t, 1, 2)));
        assertEq(safe.nonce(), 3);
        assertEq(token.balanceOf(recipient), 1 ether + 1);
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
        assertEq(m0.data.length, 1 + 20 + 32 + 5684);
    }

    /// Transaction gas of the one-time steps per member and chain: deploying the owner and enrolling a tree
    function test_gas_deployAndEnrol() public {
        bytes32 key = keccak256("a fresh member's key") | bytes32(uint256(1)); // both halves nonzero
        bytes memory init = SafeOwnerDeployment.initCode(Ops.params(_p()), key);
        uint256 deployGas = _txGas(ValidatorDeployment.DEPLOYER, abi.encodePacked(key, init));
        assertGt(SafeOwnerDeployment.predict(Ops.params(_p()), key).code.length, 0);

        // a rotation: a tree from nonce 5 replaces the tree from 0
        bytes memory cd = OwnerSigner.enrollCalldata(_member(0), _tree(0, address(safe), 5), address(safe), 5);
        uint256 rotateGas = _txGas(address(owners[0]), cd);
        (bytes32 root,,, uint64 start) = owners[0].tree(address(safe));
        assertEq(start, 5);
        assertTrue(root != bytes32(0));
        // a first enrolment: a new slot
        ISafe twin = SafeHarness.createSafe(rel, _ownerList(), 2, 1);
        cd = OwnerSigner.enrollCalldata(_member(0), _tree(0, address(twin), 0), address(twin), 0);
        uint256 enrolGas = _txGas(address(owners[0]), cd);
        console.log("deploy a WinterlockOwner, tx gas", deployGas);
        console.log("WinterlockOwner runtime bytes", address(owners[0]).code.length, ", init code bytes", init.length);
        console.log("enroll, first tree for a Safe, tx gas", enrolGas);
        console.log("enroll, rotation, tx gas", rotateGas);
        console.log("enroll calldata bytes", cd.length);
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
