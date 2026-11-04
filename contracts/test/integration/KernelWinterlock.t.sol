// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
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

import {WinterlockValidator} from "../../src/WinterlockValidator.sol";
import {WotsParams, WotsKey, WotsTree, Ops} from "../utils/WotsSigner.sol";

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

    uint128 internal constant SEED = 0x5eed0000000000000000000000000003;
    bytes32 internal constant SK = keccak256("winterlock.test.kernel");
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
        val = new WinterlockValidator(Ops.params(_p()));
        ecdsa = ECDSAValidator(vm.deployCode(ECDSA_ARTIFACT));
    }

    // --- helpers ---

    function _key() internal pure returns (WotsKey memory) {
        return WotsTree.create(_p(), SEED, SK, H, H);
    }

    function _rootId() internal view returns (ValidationId) {
        return ValidatorLib.validatorToIdentifier(KernelValidator(address(val)));
    }

    function _initData() internal view returns (bytes memory) {
        return abi.encodeCall(
            Kernel.initialize,
            (_rootId(), IHook(address(0)), Ops.installData(_key()), hex"", new bytes[](0))
        );
    }

    function _account() internal view returns (address) {
        return factory.getAddress(_initData(), bytes32(0));
    }

    function _transfer(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(Kernel.execute, (ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(recipient, value, "")));
    }

    function _wotsSign(PackedUserOperation memory op, uint256 slot) internal view {
        uint256 keyIndex = uint256(uint64(op.nonce)) * 2 + slot;
        op.signature = Ops.wotsSignature(_key(), slot, keyIndex, ep.getUserOpHash(op));
    }

    function _ecdsaSign(PackedUserOperation memory op) internal view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, MessageHashUtils.toEthSignedMessageHash(ep.getUserOpHash(op)));
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
        op.initCode = abi.encodePacked(address(factory), abi.encodeCall(KernelFactory.createAccount, (_initData(), bytes32(0))));
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
        op.signature = Ops.wotsSignature(_key(), 0, 0, ep.getUserOpHash(op));
        _expectFail(AA24);
        _send(op);
    }

    /// Off-chain messages through ERC-1271 are refused until key slots for them exist.
    function test_erc1271Refused() public {
        address account = _deploy();
        bytes32 h = keccak256("sign in with ethereum");
        bytes4 res = Kernel(payable(account)).isValidSignature(h, abi.encodePacked(bytes1(0x00), new bytes(1200)));
        assertEq(res, bytes4(0xffffffff));
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
                    address(0), abi.encode(abi.encodePacked(vm.addr(OWNER_PK)), hex"", abi.encodePacked(Kernel.execute.selector))
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

    function _teamKey(uint256 i) internal pure returns (WotsKey memory) {
        return WotsTree.create(
            _p(), uint128(uint256(keccak256(abi.encode("kernel team seed", i)))), keccak256(abi.encode("kernel team sk", i)), H, 2
        );
    }

    /// A 2-of-3 team account on Kernel: deployed and used by two members, never by one alone.
    function test_teamAccountTwoOfThree() public {
        WotsKey[] memory keys = new WotsKey[](3);
        for (uint256 i; i < 3; ++i) {
            keys[i] = _teamKey(i);
        }
        bytes memory init = abi.encodeCall(
            Kernel.initialize, (_rootId(), IHook(address(0)), Ops.installData(keys, 2), hex"", new bytes[](0))
        );
        address account = factory.getAddress(init, bytes32(0));
        vm.deal(account, 10 ether);

        // nonce 0: deploy and transfer, signed by A and C
        PackedUserOperation memory op = Ops.build(account, 0, _transfer(1 ether), 1_500_000);
        op.initCode = abi.encodePacked(address(factory), abi.encodeCall(KernelFactory.createAccount, (init, bytes32(0))));
        bytes32 h = ep.getUserOpHash(op);
        op.signature = bytes.concat(Ops.memberSignature(keys[0], 0, 0, 0, h), Ops.memberSignature(keys[2], 2, 0, 0, h));
        _send(op);
        assertEq(recipient.balance, 1 ether);

        // nonce 1: B alone is not enough
        op = Ops.build(account, 1, _transfer(1 ether), 1_500_000);
        h = ep.getUserOpHash(op);
        op.signature = Ops.memberSignature(keys[1], 1, 0, 2, h);
        _expectFail(AA24);
        _send(op);

        // nonce 1: B and C together are
        op.signature = bytes.concat(Ops.memberSignature(keys[1], 1, 0, 2, h), Ops.memberSignature(keys[2], 2, 0, 2, h));
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }
}
