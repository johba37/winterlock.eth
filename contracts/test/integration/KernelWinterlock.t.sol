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
import {KERNEL_WRAPPER_TYPE_HASH, MAGIC_VALUE_SIG_REPLAYABLE} from "kernel/types/Constants.sol";

import {WinterlockValidator} from "../../src/WinterlockValidator.sol";
import {WotsParams, WotsKey, MemberKeys, Ops} from "../utils/WotsSigner.sol";
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

    uint256 internal constant H = 4;

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
    }

    // --- helpers ---

    function _keys() internal pure returns (MemberKeys memory) {
        return Ops.keys(_p(), "winterlock.test.kernel", H, H);
    }

    function _rootId() internal view returns (ValidationId) {
        return ValidatorLib.validatorToIdentifier(KernelValidator(address(val)));
    }

    function _initData() internal view returns (bytes memory) {
        return abi.encodeCall(
            Kernel.initialize, (_rootId(), IHook(address(0)), Ops.installData(_keys().master), hex"", new bytes[](0))
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

    // --- D11 on Kernel: the stateless key ---

    string internal constant STATELESS_LABEL = "winterlock.test.kernel.stateless";

    function _sk() internal pure returns (StatelessKey memory) {
        return StatelessSigner.testKey(STATELESS_LABEL);
    }

    /// A member whose stateless public key is `pub` (passed in: keygen is costly)
    function _statelessMember(bytes32 pub) internal pure returns (MemberKeys memory k) {
        k = Ops.keys(_p(), STATELESS_LABEL, H, H);
        k.statelessKey = pub;
    }

    function _initFor(MemberKeys memory k) internal view returns (bytes memory) {
        return
            abi.encodeCall(Kernel.initialize, (_rootId(), IHook(address(0)), Ops.installData(k), hex"", new bytes[](0)));
    }

    /// Deploys k's account with its first operation (WOTS, master certificate), a transfer
    function _deployFor(MemberKeys memory k) internal returns (address account) {
        bytes memory init = _initFor(k);
        account = factory.getAddress(init, bytes32(0));
        vm.deal(account, 10 ether);
        PackedUserOperation memory op = Ops.build(account, 0, _transfer(1 ether), 1_000_000);
        op.initCode =
            abi.encodePacked(address(factory), abi.encodeCall(KernelFactory.createAccount, (init, bytes32(0))));
        op.signature = Ops.wotsSignature(val, k, 0, op, ep.getUserOpHash(op));
        _send(op);
    }

    /// The hash Kernel hands its root validator for isValidSignature(hash): EIP-712 Kernel(bytes32 hash) in the
    /// account's domain, with chain id 0 in replayable mode
    function _kernelWrapped(address account, bytes32 hash, bool replayable) internal view returns (bytes32) {
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
        return keccak256(abi.encodePacked("\x19\x01", domain, keccak256(abi.encode(KERNEL_WRAPPER_TYPE_HASH, hash))));
    }

    /// Kernel routes isValidSignature to its root validator with its own wrap of the hash (Kernel(bytes32 hash),
    /// bound to the account and chain); the member's stateless key signs Winterlock's wrap of that.
    function test_erc1271ThroughKernel() public {
        StatelessKey memory sk = _sk();
        MemberKeys memory k = _statelessMember(StatelessSigner.publicKey(sk));
        address account = _deployFor(k);
        bytes32 hash = keccak256("sign in with ethereum");
        bytes memory sig = abi.encodePacked(
            bytes1(0x00), // root validator
            Ops.messageEntry(val, account, k, sk, 0, _kernelWrapped(account, hash, false))
        );
        vm.cool(account);
        vm.cool(address(val));
        vm.cool(address(val.STATELESS_VERIFIER()));
        assertEq(Kernel(payable(account)).isValidSignature(hash, sig), bytes4(0x1626ba7e));
        console.log("Kernel isValidSignature gas (Kernel frame, cold)", vm.lastCallGas().gasTotalUsed);
        assertEq(Kernel(payable(account)).isValidSignature(keccak256("other"), sig), bytes4(0xffffffff));
        // signed over the raw hash instead of Kernel's wrap: refused
        bytes memory raw = abi.encodePacked(bytes1(0x00), Ops.messageEntry(val, account, k, sk, 0, hash));
        assertEq(Kernel(payable(account)).isValidSignature(hash, raw), bytes4(0xffffffff));
    }

    /// Kernel's replayable mode leaves the chain id out of its own wrap, so that one signature counts on every
    /// chain. Winterlock's wrap keeps the chain id, so the signature still counts on one chain only.
    function test_erc1271ReplayableModeStaysOnOneChain() public {
        StatelessKey memory sk = _sk();
        MemberKeys memory k = _statelessMember(StatelessSigner.publicKey(sk));
        address account = _deployFor(k);
        bytes32 hash = keccak256("sign in with ethereum");
        bytes memory sig = abi.encodePacked(
            bytes1(0x00),
            MAGIC_VALUE_SIG_REPLAYABLE,
            Ops.messageEntry(val, account, k, sk, 0, _kernelWrapped(account, hash, true))
        );
        assertEq(Kernel(payable(account)).isValidSignature(hash, sig), bytes4(0x1626ba7e));
        vm.chainId(42161);
        assertEq(Kernel(payable(account)).isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    /// Recovery (D11): the signer lost its state, so it no longer knows which one-time keys or master keys it
    /// used. From its seeds and the chain alone it certifies a fresh operation tree with the stateless key, starting
    /// at the account's current nonce. No one-time key is used twice, operations continue, and the old tree is
    /// revoked: it signs no more, with or without its certificate.
    function test_recoveryAfterStateLoss() public {
        StatelessKey memory sk = _sk();
        bytes32 pub = StatelessSigner.publicKey(sk);
        MemberKeys memory k = _statelessMember(pub);
        address account = _deployFor(k); // nonce 0: master key 0's tree
        for (uint256 n = 1; n < 3; ++n) {
            PackedUserOperation memory used = Ops.build(account, n, _transfer(1 ether), 400_000);
            used.signature = Ops.wotsSignature(val, k, 0, used, ep.getUserOpHash(used));
            _send(used);
        }

        // State lost. The restored signer reads the nonce and certifies a fresh tree from there.
        uint64 nonce = uint64(ep.getNonce(account, 0));
        assertEq(nonce, 3);
        MemberKeys memory fresh = Ops.statelessTree(_statelessMember(pub), nonce);
        PackedUserOperation memory op = Ops.build(account, nonce, _transfer(1 ether), 1_000_000);
        op.signature = Ops.statelessMemberSignature(val, account, fresh, sk, 0, 0, nonce, ep.getUserOpHash(op));
        assertEq(uint8(op.signature[1]), 0x40, "stateless certificate");
        _send(op);
        WinterlockValidator.Tree memory t = val.tree(account, 0);
        assertTrue(t.stateless);
        assertEq(t.start, nonce);
        assertEq(t.nextMaster, 1, "master key 0 stays spent");

        // operations continue on the fresh tree, without certificates
        op = Ops.build(account, nonce + 1, _transfer(1 ether), 400_000);
        op.signature = Ops.memberSignature(val, account, fresh, 0, 0, nonce + 1, ep.getUserOpHash(op));
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

    function _teamKey(uint256 i) internal pure returns (MemberKeys memory) {
        return Ops.keys(_p(), string(abi.encode("kernel team", i)), H, 2);
    }

    /// A 2-of-3 team account on Kernel: deployed and used by two members, never by one alone.
    function test_teamAccountTwoOfThree() public {
        MemberKeys[] memory keys = new MemberKeys[](3);
        for (uint256 i; i < 3; ++i) {
            keys[i] = _teamKey(i);
        }
        bytes memory init = abi.encodeCall(
            Kernel.initialize,
            (_rootId(), IHook(address(0)), Ops.installData(Ops.masters(keys), 2), hex"", new bytes[](0))
        );
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
        op.signature = Ops.memberSignature(val, account, keys[1], 1, 0, 1, h);
        _expectFail(AA24);
        _send(op);

        // nonce 1: B and C together are
        op.signature = bytes.concat(
            Ops.memberSignature(val, account, keys[1], 1, 0, 1, h),
            Ops.memberSignature(val, account, keys[2], 2, 0, 1, h)
        );
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }
}
