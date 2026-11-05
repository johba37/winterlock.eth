// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {IHook, IValidator as KernelValidator} from "kernel/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "kernel/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/utils/ExecLib.sol";
import {ExecMode} from "kernel/types/Types.sol";

import {WinterlockValidator} from "../../src/WinterlockValidator.sol";
import {ValidatorDeployment} from "../../script/DeployValidator.s.sol";
import {WotsParams, MemberKeys, Ops} from "../utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "../utils/StatelessSigner.sol";

/// D10 and D12 on Kernel v3.3: one account address on two chains, with a separate operation tree on each, both
/// certified by the member's stateless key. Each chain is the same deployment from a state snapshot, with its own
/// chain id. The validator comes from the deterministic deployment (script/DeployValidator.s.sol).
contract KernelMultichainTest is Test {
    uint256 internal constant SEPOLIA = 11155111;
    uint256 internal constant ARBITRUM_SEPOLIA = 421614;
    uint256 internal constant H = 3;
    string internal constant LABEL = "winterlock.test.multichain";

    EntryPoint internal ep;
    KernelFactory internal factory;
    WinterlockValidator internal val;
    address payable internal bundler = payable(makeAddr("bundler"));
    address internal recipient = makeAddr("recipient");
    StatelessKey internal sk; // the member's stateless key, kept: its keygen is costly

    bytes internal constant AA24 = "AA24 signature error";

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function setUp() public {
        ep = new EntryPoint();
        Kernel impl = Kernel(payable(vm.deployCode("lib/kernel/out/Kernel.sol/Kernel.json", abi.encode(address(ep)))));
        factory = KernelFactory(
            vm.deployCode("lib/kernel/out/KernelFactory.sol/KernelFactory.json", abi.encode(address(impl)))
        );
        if (ValidatorDeployment.DEPLOYER.code.length == 0) {
            vm.etch(ValidatorDeployment.DEPLOYER, ValidatorDeployment.DEPLOYER_CODE);
        }
        val = WinterlockValidator(ValidatorDeployment.deploy(Ops.params(_p())));
        sk = StatelessSigner.testKey(LABEL);
    }

    // --- helpers ---

    /// The member's keys on one chain: the same stateless key everywhere, and operation tree `t` from sequence 0
    /// (the signer gives every chain its own tree)
    function _keysOn(uint256 t) internal view returns (MemberKeys memory k) {
        k = Ops.keys(_p(), LABEL, H, H, sk);
        k.tree = t;
    }

    /// The root of operation tree t for `account` on the current chain
    function _rootOn(uint256 t, address account) internal view returns (bytes32) {
        return Ops.forAccount(val, account, 0, _keysOn(t)).ops.root;
    }

    /// The install data holds only the stateless public key, so it is the same on every chain
    function _initData() internal view returns (bytes memory) {
        return abi.encodeCall(
            Kernel.initialize,
            (
                ValidatorLib.validatorToIdentifier(KernelValidator(address(val))),
                IHook(address(0)),
                Ops.installData(_keysOn(0)),
                hex"",
                new bytes[](0)
            )
        );
    }

    function _transfer() internal view returns (bytes memory) {
        return abi.encodeCall(Kernel.execute, (ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(recipient, 1 ether, "")));
    }

    /// The first operation on a chain: deploys the account (initCode) and transfers
    function _deployOp() internal view returns (PackedUserOperation memory op) {
        address account = factory.getAddress(_initData(), bytes32(0));
        op = Ops.build(account, 0, _transfer(), 1_000_000);
        op.initCode =
            abi.encodePacked(address(factory), abi.encodeCall(KernelFactory.createAccount, (_initData(), bytes32(0))));
    }

    function _send(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(bundler, bundler);
        ep.handleOps(ops, bundler);
    }

    function _expectFail() internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, AA24));
    }

    /// Deploys the account with its first WOTS-signed operation, then sends a second one
    function _useAccount(MemberKeys memory k) internal returns (address account) {
        PackedUserOperation memory op = _deployOp();
        account = op.sender;
        vm.deal(account, 10 ether);
        op.signature = Ops.wotsSignature(val, k, 0, op, ep.getUserOpHash(op)); // with the certificate
        _send(op);
        op = Ops.build(account, 1, _transfer(), 400_000);
        op.signature = Ops.wotsSignature(val, k, 0, op, ep.getUserOpHash(op));
        _send(op);
        assertEq(recipient.balance, 2 ether);
    }

    // --- tests ---

    function test_validatorAddressIsDeterministic() public {
        uint256 params = Ops.params(_p());
        assertEq(address(val), ValidatorDeployment.predict(params));
        assertGt(address(val).code.length, 0);
        assertEq(ValidatorDeployment.deploy(params), address(val)); // deploying again is a no-op
        // the stateless verifier has its own deterministic address, shared by every parameter set
        assertEq(address(val.STATELESS_VERIFIER()), ValidatorDeployment.predictVerifier());
        assertGt(ValidatorDeployment.predictVerifier().code.length, 0);
        // each parameter set has its own address
        assertTrue(ValidatorDeployment.predict(Ops.params(WotsParams(16, 300, 4, 0))) != address(val));
    }

    /// The same account on two chains, each with its own operation tree, both certified by the stateless key.
    function test_sameAccountOnTwoChainsWithSeparateTrees() public {
        uint256 snap = vm.snapshotState();
        vm.chainId(SEPOLIA);
        address onSepolia = _useAccount(_keysOn(0));
        WinterlockValidator.Tree memory treeSepolia = val.tree(onSepolia, 0);
        assertEq(treeSepolia.root, _rootOn(0, onSepolia));

        vm.revertToState(snap);
        vm.chainId(ARBITRUM_SEPOLIA);
        assertEq(val.tree(onSepolia, 0).root, bytes32(0), "a fresh chain knows no tree");
        address onArbitrum = _useAccount(_keysOn(1));
        WinterlockValidator.Tree memory treeArbitrum = val.tree(onArbitrum, 0);
        assertEq(treeArbitrum.root, _rootOn(1, onArbitrum));

        assertEq(onSepolia, onArbitrum, "same address");
        assertTrue(treeSepolia.root != treeArbitrum.root, "separate trees");
        assertEq(treeSepolia.start, 0);
        assertEq(treeArbitrum.start, 0);
        // the tree seed binds the chain, so even one tree's secrets would give each chain its own tree
        assertTrue(treeSepolia.seed != treeArbitrum.seed, "seeds bind the chain");
        assertTrue(_rootOn(0, onArbitrum) != treeSepolia.root, "tree 0 differs on Arbitrum");
    }

    /// Anyone can read a certificate from one chain's history; it is worthless on another chain.
    function test_certificateFromOtherChainRejected() public {
        PackedUserOperation memory op = _deployOp();
        vm.deal(op.sender, 10 ether);
        MemberKeys memory k = _keysOn(0);
        vm.chainId(SEPOLIA);
        bytes memory sepoliaCertificate = Ops.certificate(val, op.sender, 0, k);
        MemberKeys memory sepoliaKeys = Ops.forAccount(val, op.sender, 0, k);

        vm.chainId(ARBITRUM_SEPOLIA);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(sepoliaKeys, 0, 0, 0, sepoliaCertificate, h); // Sepolia's tree and certificate
        _expectFail();
        _send(op);
        op.signature = Ops.wotsSignature(val, _keysOn(0), 0, op, h); // control: this chain's own certificate
        _send(op);
    }

    /// Once a chain has its tree, another chain's tree doesn't sign there, with or without a certificate.
    function test_treeOfOtherChainRejected() public {
        vm.chainId(ARBITRUM_SEPOLIA);
        address account = _useAccount(_keysOn(1));

        vm.chainId(SEPOLIA);
        MemberKeys memory sepoliaKeys = Ops.forAccount(val, account, 0, _keysOn(0)); // Sepolia's tree
        bytes memory sepoliaCertificate = Ops.certificate(val, account, 0, _keysOn(0));
        vm.chainId(ARBITRUM_SEPOLIA);

        PackedUserOperation memory op = Ops.build(account, 2, _transfer(), 600_000);
        bytes32 h = ep.getUserOpHash(op);
        op.signature = Ops.entry(sepoliaKeys, 0, 0, 2, "", h); // no certificate
        _expectFail();
        _send(op);
        op.signature = Ops.entry(sepoliaKeys, 0, 0, 2, sepoliaCertificate, h); // Sepolia's certificate
        _expectFail();
        _send(op);

        // Sepolia's tree secrets certified for this chain from start 0: this chain's tree starts at 0 too, and a
        // new certificate must start after it. A signer must never certify a second tree for one start; this shows
        // the chain refuses it even so.
        op.signature = Ops.memberSignature(val, account, _keysOn(0), 0, 0, 2, h);
        _expectFail();
        _send(op);
    }
}
