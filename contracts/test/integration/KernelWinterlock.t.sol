// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {ECDSAValidator} from "kernel/validator/ECDSAValidator.sol";
import {IHook, IValidator as KernelValidator} from "kernel/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "kernel/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/utils/ExecLib.sol";
import {ValidationId, ExecMode} from "kernel/types/Types.sol";
import {ENABLE_TYPE_HASH, KERNEL_WRAPPER_TYPE_HASH, MAGIC_VALUE_SIG_REPLAYABLE} from "kernel/types/Constants.sol";

import {WinterlockValidator} from "../../src/WinterlockValidator.sol";
import {WotsParams, MemberKeys, Ops} from "../utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "../utils/StatelessSigner.sol";

/// Winterlock as the root validator of a ZeroDev Kernel v3.3 account, through EntryPoint v0.7.
/// Parameter set D6: 24-byte hashes, target sum 431.
/// Kernel, its factory and its ECDSA validator are deployed from Kernel's own production build
/// (profile "deploy": via-IR, 200 runs); run ./setup.sh once to create those artifacts.
contract KernelWinterlockTest is Test {
    EntryPoint internal ep;
    Kernel internal impl;
    KernelFactory internal factory;
    WinterlockValidator internal val;
    ECDSAValidator internal ecdsa;

    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");
    uint256 internal constant OWNER_PK = 0xA11CE;
    StatelessKey internal sk; // the member's stateless key, kept: its keygen is costly

    uint256 internal constant H = 4;
    string internal constant LABEL = "winterlock.test.kernel";

    bytes internal constant AA24 = "AA24 signature error";

    string internal constant KERNEL_ARTIFACT = "lib/kernel/out/Kernel.sol/Kernel.json";
    string internal constant FACTORY_ARTIFACT = "lib/kernel/out/KernelFactory.sol/KernelFactory.json";
    string internal constant ECDSA_ARTIFACT = "lib/kernel/out/ECDSAValidator.sol/ECDSAValidator.json";

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        ep = new EntryPoint();
        impl = Kernel(payable(vm.deployCode(KERNEL_ARTIFACT, abi.encode(address(ep)))));
        factory = KernelFactory(vm.deployCode(FACTORY_ARTIFACT, abi.encode(address(impl))));
        val = new WinterlockValidator(Ops.params(_p()), Ops.deployStatelessVerifier());
        ecdsa = ECDSAValidator(vm.deployCode(ECDSA_ARTIFACT));
        sk = StatelessSigner.testKey(LABEL);
    }

    // --- helpers ---

    /// The member's keys: its stateless key, and operation tree 0 from sequence 0, which the first operation
    /// certifies
    function _keys() internal view returns (MemberKeys memory) {
        return Ops.keys(_p(), LABEL, H, H, sk);
    }

    function _rootId() internal view returns (ValidationId) {
        return ValidatorLib.validatorToIdentifier(KernelValidator(address(val)));
    }

    function _initData() internal view returns (bytes memory) {
        return abi.encodeCall(
            Kernel.initialize, (_rootId(), IHook(address(0)), Ops.installData(_keys()), hex"", new bytes[](0))
        );
    }

    function _account() internal view returns (address) {
        return factory.getAddress(_initData(), bytes32(0));
    }

    function _transfer(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(Kernel.execute, (ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(recipient, value, "")));
    }

    function _wotsSign(PackedUserOperation memory op, uint256 slot) internal view {
        op.signature = Ops.wotsSignature(val, _keys(), slot, op, ep.getUserOpHash(op));
    }

    function _ecdsaSign(PackedUserOperation memory op) internal view {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(OWNER_PK, MessageHashUtils.toEthSignedMessageHash(ep.getUserOpHash(op)));
        op.signature = abi.encodePacked(r, s, v);
    }

    function _send(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(bundler, bundler);
        ep.handleOps(ops, bundler);
    }

    function _expectFail(bytes memory reason) internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, reason));
    }

    /// First op: deploys the account through the factory (initCode) and makes a transfer, signed with WOTS.
    function _deploy() internal returns (address account) {
        account = _account();
        vm.deal(account, 10 ether);
        PackedUserOperation memory op = Ops.build(account, 0, _transfer(1 ether), 1_000_000);
        op.initCode =
            abi.encodePacked(address(factory), abi.encodeCall(KernelFactory.createAccount, (_initData(), bytes32(0))));
        _wotsSign(op, 0);
        _send(op);
    }

    // --- tests ---

    function test_counterfactualDeployAndTransfer() public {
        address account = _deploy();
        assertGt(account.code.length, 0, "account not deployed");
        assertEq(recipient.balance, 1 ether);
        assertEq(ValidationId.unwrap(Kernel(payable(account)).rootValidator()), ValidationId.unwrap(_rootId()));
        assertTrue(val.isInitialized(account));
    }

    function test_sequentialTransfers() public {
        address account = _deploy();
        for (uint256 n = 1; n < 4; ++n) {
            PackedUserOperation memory op = Ops.build(account, ep.getNonce(account, 0), _transfer(1 ether), 400_000);
            _wotsSign(op, 0);
            _send(op);
        }
        assertEq(recipient.balance, 4 ether);
    }

    function test_slot1AtSameNonce() public {
        address account = _deploy();
        PackedUserOperation memory op = Ops.build(account, 1, _transfer(2 ether), 400_000);
        _wotsSign(op, 1);
        _send(op);
        assertEq(recipient.balance, 3 ether);
    }

    function test_ecdsaSignatureRejected() public {
        address account = _deploy();
        PackedUserOperation memory op = Ops.build(account, 1, _transfer(1 ether), 400_000);
        _ecdsaSign(op);
        _expectFail(AA24);
        _send(op);
    }

    /// Kernel's nonce key = mode (1) | type (1) | validator (20) | parallel key (2). Kernel would accept
    /// any parallel key for the root validator; Winterlock refuses all but its own lane, because
    /// sequence numbers repeat across lanes.
    function test_parallelNonceLaneRejected() public {
        address account = _deploy();
        uint256 nonce = (uint256(1) << 64) | ep.getNonce(account, 1);
        PackedUserOperation memory op = Ops.build(account, nonce, _transfer(1 ether), 400_000);
        op.signature = Ops.wotsSignature(val, _keys(), 0, op, ep.getUserOpHash(op));
        _expectFail(AA24);
        _send(op);
    }

    /// ERC-1271 without a valid stateless signature is refused (here: a WOTS-sized blob).
    function test_erc1271WithoutStatelessSignatureRefused() public {
        address account = _deploy();
        bytes32 h = keccak256("sign in with ethereum");
        bytes4 res = Kernel(payable(account)).isValidSignature(h, abi.encodePacked(bytes1(0x00), new bytes(1200)));
        assertEq(res, bytes4(0xffffffff));
    }

    // --- D11 and D12 on Kernel: the stateless key ---

    /// The hash Kernel hands its root validator for isValidSignature(hash): EIP-712 Kernel(bytes32 hash) in the
    /// account's domain, with chain id 0 in replayable mode
    function _kernelWrapped(address account, bytes32 hash, bool replayable) internal view returns (bytes32) {
        return _kernelTypedData(account, keccak256(abi.encode(KERNEL_WRAPPER_TYPE_HASH, hash)), replayable);
    }

    /// EIP-712 hash of `structHash` in the account's domain (Kernel, 0.3.3), with chain id 0 in replayable mode
    function _kernelTypedData(address account, bytes32 structHash, bool replayable) internal view returns (bytes32) {
        (, string memory name, string memory version,,,,) = Kernel(payable(account)).eip712Domain();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                replayable ? 0 : block.chainid,
                account
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    /// Kernel routes isValidSignature to its root validator with its own wrap of the hash (Kernel(bytes32 hash),
    /// bound to the account and chain); the member's stateless key signs Winterlock's wrap of that. The caller here is
    /// an app: Kernel names it as the sender.
    function test_erc1271ThroughKernel() public {
        address account = _deploy();
        bytes32 hash = keccak256("sign in with ethereum");
        bytes memory sig = abi.encodePacked(
            bytes1(0x00), // root validator
            Ops.messageEntry(val, account, _keys(), 0, _kernelWrapped(account, hash, false))
        );
        vm.cool(account);
        vm.cool(address(val));
        vm.cool(address(val.STATELESS_VERIFIER()));
        assertEq(Kernel(payable(account)).isValidSignature(hash, sig), bytes4(0x1626ba7e));
        console.log("Kernel isValidSignature gas, 1-of-1 (Kernel frame, cold)", vm.lastCallGas().gasTotalUsed);
        assertEq(Kernel(payable(account)).isValidSignature(keccak256("other"), sig), bytes4(0xffffffff));
        // signed over the raw hash instead of Kernel's wrap: refused
        bytes memory raw = abi.encodePacked(bytes1(0x00), Ops.messageEntry(val, account, _keys(), 0, hash));
        assertEq(Kernel(payable(account)).isValidSignature(hash, raw), bytes4(0xffffffff));
    }

    /// Kernel's replayable mode leaves the chain id out of its own wrap, so that one signature counts on every
    /// chain. Winterlock's wrap keeps the chain id, so the signature still counts on one chain only.
    function test_erc1271ReplayableModeStaysOnOneChain() public {
        address account = _deploy();
        bytes32 hash = keccak256("sign in with ethereum");
        bytes memory sig = abi.encodePacked(
            bytes1(0x00),
            MAGIC_VALUE_SIG_REPLAYABLE,
            Ops.messageEntry(val, account, _keys(), 0, _kernelWrapped(account, hash, true))
        );
        assertEq(Kernel(payable(account)).isValidSignature(hash, sig), bytes4(0x1626ba7e));
        vm.chainId(42161);
        assertEq(Kernel(payable(account)).isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    /// Recovery (D11, D12): the signer lost its state, so it no longer knows which one-time keys it used. From its
    /// seeds and the chain alone it certifies a fresh operation tree with the stateless key, starting at the account's
    /// current nonce. No one-time key is used twice, operations continue, and the old tree is revoked: it signs no
    /// more, with or without its certificate.
    function test_recoveryAfterStateLoss() public {
        MemberKeys memory k = _keys();
        address account = _deploy(); // nonce 0: tree 0 from sequence 0, with its certificate
        for (uint256 n = 1; n < 3; ++n) {
            PackedUserOperation memory used = Ops.build(account, n, _transfer(1 ether), 400_000);
            used.signature = Ops.wotsSignature(val, k, 0, used, ep.getUserOpHash(used));
            _send(used);
        }

        // State lost. The restored signer reads the nonce and certifies a fresh tree from there.
        uint64 nonce = uint64(ep.getNonce(account, 0));
        assertEq(nonce, 3);
        MemberKeys memory fresh = Ops.startingAt(_keys(), nonce);
        PackedUserOperation memory op = Ops.build(account, nonce, _transfer(1 ether), 1_000_000);
        op.signature = Ops.wotsSignature(val, fresh, 0, op, ep.getUserOpHash(op));
        assertEq(uint8(op.signature[1]), 0x80, "certificate");
        _send(op);
        assertEq(val.tree(account, 0).start, nonce);

        // operations continue on the fresh tree, without certificates
        op = Ops.build(account, nonce + 1, _transfer(1 ether), 400_000);
        op.signature = Ops.wotsSignature(val, fresh, 0, op, ep.getUserOpHash(op));
        assertEq(op.signature[1], 0x00);
        _send(op);
        assertEq(recipient.balance, 5 ether);

        // the old tree is revoked, although it still has unused keys for this nonce
        op = Ops.build(account, nonce + 2, _transfer(1 ether), 1_000_000);
        bytes32 h = ep.getUserOpHash(op);
        MemberKeys memory old = Ops.forAccount(val, account, 0, k);
        assertLt((nonce + 2) * 2, 1 << H, "the old tree has a key for this nonce");
        op.signature = Ops.entry(old, 0, 0, nonce + 2, "", h);
        _expectFail(AA24);
        _send(op);
        op.signature = Ops.entry(old, 0, 0, nonce + 2, Ops.certificate(val, account, 0, old), h);
        _expectFail(AA24);
        _send(op);
    }

    /// Lock-down: adding another validator needs a Winterlock signature, but once added it is a second
    /// way in. A wallet must show every installed validator, executor, hook and fallback.
    function test_addingEcdsaValidatorOpensAnEcdsaPath() public {
        address account = _deploy();
        bytes memory install = abi.encodeCall(
            Kernel.installModule,
            (
                1,
                address(ecdsa),
                abi.encodePacked(
                    address(0),
                    abi.encode(abi.encodePacked(vm.addr(OWNER_PK)), hex"", abi.encodePacked(Kernel.execute.selector))
                )
            )
        );

        // Signed with ECDSA: refused, since only the root (Winterlock) may install modules.
        PackedUserOperation memory op = Ops.build(account, 1, install, 400_000);
        op.accountGasLimits = bytes32((uint256(400_000) << 128) | 300_000); // installModule needs more than a transfer
        _ecdsaSign(op);
        _expectFail(AA24);
        _send(op);

        // Signed with Winterlock: accepted.
        _wotsSign(op, 0);
        _send(op);
        assertTrue(Kernel(payable(account)).isModuleInstalled(1, address(ecdsa), ""), "install failed");

        // From now on an ECDSA key can move funds through its own nonce lane.
        uint192 ecdsaLane = uint192(bytes24(abi.encodePacked(bytes1(0x00), bytes1(0x01), address(ecdsa), bytes2(0))));
        PackedUserOperation memory steal =
            Ops.build(account, ep.getNonce(account, ecdsaLane), _transfer(5 ether), 400_000);
        _ecdsaSign(steal);
        _send(steal);
        assertEq(recipient.balance, 6 ether);
    }

    // --- threshold mode on Kernel ---

    /// Members A, B, C of a team account (2 real leaves each)
    function _team() internal pure returns (MemberKeys[] memory keys) {
        keys = new MemberKeys[](3);
        for (uint256 i; i < 3; ++i) {
            keys[i] = Ops.keys(_p(), string(abi.encode("kernel team", i)), H, 2);
        }
    }

    function _teamInit(MemberKeys[] memory keys) internal view returns (bytes memory) {
        return abi.encodeCall(
            Kernel.initialize, (_rootId(), IHook(address(0)), Ops.installData(keys, 2), hex"", new bytes[](0))
        );
    }

    /// A 2-of-3 team account on Kernel: deployed and used by two members, never by one alone.
    function test_teamAccountTwoOfThree() public {
        MemberKeys[] memory keys = _team();
        bytes memory init = _teamInit(keys);
        address account = factory.getAddress(init, bytes32(0));
        vm.deal(account, 10 ether);

        // nonce 0: deploy and transfer, signed by A and C
        PackedUserOperation memory op = Ops.build(account, 0, _transfer(1 ether), 1_500_000);
        op.initCode =
            abi.encodePacked(address(factory), abi.encodeCall(KernelFactory.createAccount, (init, bytes32(0))));
        bytes32 h = ep.getUserOpHash(op);
        op.signature = bytes.concat(
            Ops.memberSignature(val, account, keys[0], 0, 0, 0, h),
            Ops.memberSignature(val, account, keys[2], 2, 0, 0, h)
        );
        _send(op);
        assertEq(recipient.balance, 1 ether);

        // nonce 1: B alone is not enough
        op = Ops.build(account, 1, _transfer(1 ether), 1_500_000);
        h = ep.getUserOpHash(op);
        bytes memory b = Ops.memberSignature(val, account, keys[1], 1, 0, 1, h);
        op.signature = b;
        _expectFail(AA24);
        _send(op);

        // nonce 1: B and C together are
        op.signature = bytes.concat(b, Ops.memberSignature(val, account, keys[2], 2, 0, 1, h));
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }

    /// App message signing on a 2-of-3 team account through Kernel.isValidSignature: two members' entries; one alone
    /// is refused.
    function test_erc1271TeamThroughKernel() public {
        MemberKeys[] memory keys = _team();
        address account = factory.createAccount(_teamInit(keys), bytes32(0));
        bytes32 hash = keccak256("sign in with ethereum");
        bytes32 wrapped = _kernelWrapped(account, hash, false);
        bytes memory a = Ops.messageEntry(val, account, keys[0], 0, wrapped);
        bytes memory c = Ops.messageEntry(val, account, keys[2], 2, wrapped);
        bytes memory sig = abi.encodePacked(bytes1(0x00), a, c);
        vm.cool(account);
        vm.cool(address(val));
        vm.cool(address(val.STATELESS_VERIFIER()));
        assertEq(Kernel(payable(account)).isValidSignature(hash, sig), bytes4(0x1626ba7e));
        console.log("Kernel isValidSignature gas, 2-of-3 (Kernel frame, cold)", vm.lastCallGas().gasTotalUsed);
        bytes memory cAlone = abi.encodePacked(bytes1(0x00), c);
        assertEq(Kernel(payable(account)).isValidSignature(hash, cAlone), bytes4(0xffffffff), "C alone");
    }

    // --- Kernel's enable mode: refused by design ---

    /// Kernel's EIP-712 "Enable" digest for installing validator `vId` without a hook, as
    /// ValidationManager._enableDigest computes it
    function _enableDigest(address account, ValidationId vId, bytes memory validatorData, bytes memory selectorData)
        internal
        view
        returns (bytes32)
    {
        Kernel kernel = Kernel(payable(account));
        uint32 current = kernel.currentNonce();
        uint32 nonce = kernel.validationConfig(vId).nonce == current ? current + 1 : current;
        bytes32 structHash = keccak256(
            abi.encode(
                ENABLE_TYPE_HASH,
                ValidationId.unwrap(vId),
                nonce,
                address(0),
                keccak256(validatorData),
                keccak256(""),
                keccak256(selectorData)
            )
        );
        return _kernelTypedData(account, structHash, false);
    }

    /// Kernel's enable mode installs a validator inside a UserOperation once the root validator approves Kernel's
    /// "Enable" digest through ERC-1271, asked with sender = the account. Here a 2-of-3 quorum signs that digest, as
    /// a phished "sign this message" would, to install Kernel's ECDSA validator with an attacker's key, which then
    /// validates the rest of the operation: a transfer. Winterlock refuses the account asking on its own behalf, so
    /// Kernel reverts with EnableNotApproved and nothing is installed. The same quorum signature is valid when an app
    /// asks: only the lock stands in the way.
    function test_enableModeRefused() public {
        MemberKeys[] memory keys = _team();
        address account = factory.createAccount(_teamInit(keys), bytes32(0)); // an ordinary transaction
        vm.deal(account, 10 ether);

        ValidationId vId = ValidatorLib.validatorToIdentifier(KernelValidator(address(ecdsa)));
        bytes memory validatorData = abi.encodePacked(vm.addr(OWNER_PK)); // the attacker's key
        bytes memory selectorData = abi.encodePacked(Kernel.execute.selector); // allowed to call execute
        bytes32 digest = _enableDigest(account, vId, validatorData, selectorData);
        bytes memory enableSig = bytes.concat(
            Ops.messageEntry(val, account, keys[0], 0, digest), Ops.messageEntry(val, account, keys[2], 2, digest)
        );
        vm.prank(account);
        assertEq(
            val.isValidSignatureWithSender(makeAddr("app"), digest, enableSig), bytes4(0x1626ba7e), "a valid quorum"
        );

        // nonce key: enable mode (0x01), validator type (0x01), the new validator, parallel key 0
        uint192 lane = ValidatorLib.encodeAsNonceKey(0x01, 0x01, bytes20(address(ecdsa)), 0);
        PackedUserOperation memory op = Ops.build(account, ep.getNonce(account, lane), _transfer(5 ether), 1_000_000);
        _ecdsaSign(op); // the new validator's signature of the operation
        op.signature = abi.encodePacked(
            address(0), // hook: none
            abi.encode(validatorData, bytes(""), selectorData, enableSig, op.signature)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("EnableNotApproved()")
            )
        );
        _send(op);

        assertFalse(Kernel(payable(account)).isModuleInstalled(1, address(ecdsa), ""), "not installed");
        assertFalse(ecdsa.isInitialized(account));
        assertEq(recipient.balance, 0);
        assertEq(ep.getNonce(account, lane) & type(uint64).max, 0, "lane unused");
    }
}
