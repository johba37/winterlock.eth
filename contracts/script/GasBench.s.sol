// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SimpleAccount} from "account-abstraction/samples/SimpleAccount.sol";
import {SimpleAccountFactory} from "account-abstraction/samples/SimpleAccountFactory.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {IHook, IValidator as KernelValidator} from "kernel/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "kernel/utils/ValidationTypeLib.sol";
import {ExecLib} from "kernel/utils/ExecLib.sol";
import {ExecMode} from "kernel/types/Types.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {MiniAccount, EcdsaValidator, EcdsaThresholdValidator} from "../test/utils/Harness.sol";
import {WotsParams, WotsKey, WotsTree, Ops} from "../test/utils/WotsSigner.sol";

/// @notice Sends real handleOps transactions so receipts include intrinsic and calldata gas.
///         Each account sends ROUNDS ops (an ETH transfer to an existing address). Nonce 0 warms
///         storage up and is reported separately; later nonces are the steady state. Every row
///         names the ECDSA baseline it should be compared with.
///         Run through bench.sh against a local anvil.
contract GasBench is Script {
    uint256 internal constant ROUNDS = 6;
    uint256 internal constant OWNER_PK = 0xA11CE;

    string internal constant MINI_ECDSA = "MiniAccount + ECDSA";
    string internal constant MINI_ECDSA_2OF3 = "MiniAccount + ECDSA 2-of-3";
    string internal constant KERNEL_ECDSA = "Kernel + ECDSA";
    string internal constant KERNEL_ECDSA_2OF3 = "Kernel + ECDSA 2-of-3";

    EntryPoint internal ep;
    KernelFactory internal kf;
    address payable internal bundler;
    address internal recipient;
    string internal labels;
    uint256 internal sent;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        bundler = payable(vm.addr(pk));
        recipient = vm.addr(0xB0B);

        vm.startBroadcast(pk);
        ep = new EntryPoint();
        _pay(recipient, 1 ether);
        // ZeroDev Kernel v3.3 from its production build (./setup.sh): via-IR, 200 runs
        address kImpl = vm.deployCode("lib/kernel/out/Kernel.sol/Kernel.json", abi.encode(address(ep)));
        kf = KernelFactory(vm.deployCode("lib/kernel/out/KernelFactory.sol/KernelFactory.json", abi.encode(kImpl)));

        _benchSingleSigner();
        _benchParameterSets();
        _benchKernel();
        _benchThreshold();
        vm.stopBroadcast();

        require(recipient.balance == 1 ether + sent * 0.001 ether, "not every op executed");
        vm.writeFile("bench/labels.json", string.concat("[", labels, "]"));
    }

    // --- scenarios ---

    function _benchSingleSigner() internal {
        uint256[] memory owner = new uint256[](1);
        owner[0] = OWNER_PK;

        // Reference: eth-infinitism SimpleAccount
        SimpleAccount sa = new SimpleAccountFactory(ep).createAccount(vm.addr(OWNER_PK), 0);
        _pay(address(sa), 1 ether);
        for (uint256 n; n < ROUNDS; ++n) _ecdsaOp(address(sa), _callData(), owner, n, "SimpleAccount (ECDSA)", MINI_ECDSA);

        // Baseline: the minimal account with an ECDSA validator module
        MiniAccount ma = new MiniAccount{value: 1 ether}(ep, new EcdsaValidator(), abi.encode(vm.addr(OWNER_PK)));
        for (uint256 n; n < ROUNDS; ++n) _ecdsaOp(address(ma), _callData(), owner, n, MINI_ECDSA, "");
    }

    /// Hash size x encoding on the minimal account, all at tree height 20 (2^19 nonces)
    function _benchParameterSets() internal {
        WotsParams[6] memory sets = [
            WotsParams(32, 0),
            WotsParams(32, 560),
            WotsParams(24, 0),
            WotsParams(24, 431),
            WotsParams(16, 0),
            WotsParams(16, 300)
        ];
        for (uint256 t; t < sets.length; ++t) {
            WotsParams memory p = sets[t];
            WotsKey memory key = _key(p, "single", t, 4);
            MiniAccount wa = new MiniAccount{value: 1 ether}(ep, new WinterlockValidator(p.n, p.targetSum), Ops.installData(key));
            string memory name = string.concat("Winterlock ", _setName(p));
            for (uint256 n; n < ROUNDS; ++n) {
                PackedUserOperation memory op = Ops.build(address(wa), n, _callData(), 300_000);
                op.signature = Ops.wotsSignature(key, 0, n * 2, ep.getUserOpHash(op));
                _submit(op, name, MINI_ECDSA, n);
            }
        }
    }

    /// A production 7579 account: Kernel, ECDSA versus Winterlock as root validator
    function _benchKernel() internal {
        uint256[] memory owner = new uint256[](1);
        owner[0] = OWNER_PK;
        address kEcdsa = _kernel(
            vm.deployCode("lib/kernel/out/ECDSAValidator.sol/ECDSAValidator.json"), abi.encodePacked(vm.addr(OWNER_PK))
        );
        // Kernel's ECDSAValidator, signed the way the ZeroDev SDK signs (personal_sign of the userOpHash)
        for (uint256 n; n < ROUNDS; ++n) _ecdsaOp(kEcdsa, _kernelCallData(), owner, n, KERNEL_ECDSA, "");

        WotsParams[2] memory kSets = [WotsParams(24, 431), WotsParams(16, 300)];
        for (uint256 t; t < kSets.length; ++t) {
            WotsParams memory p = kSets[t];
            WotsKey memory key = _key(p, "kernel", t, 4);
            address kw = _kernel(address(new WinterlockValidator(p.n, p.targetSum)), Ops.installData(key));
            string memory name = string.concat("Kernel + Winterlock ", _setName(p));
            for (uint256 n; n < ROUNDS; ++n) {
                PackedUserOperation memory op = Ops.build(kw, n, _kernelCallData(), 500_000);
                op.signature = Ops.wotsSignature(key, 0, n * 2, ep.getUserOpHash(op));
                _submit(op, name, KERNEL_ECDSA, n);
            }
        }
    }

    /// 2-of-3: two members sign every op, on the minimal account and on Kernel (parameter set D6)
    function _benchThreshold() internal {
        (uint256[] memory signers, address[] memory owners) = _ecdsaOwners();
        EcdsaThresholdValidator tv = new EcdsaThresholdValidator();
        bytes memory ecdsaInit = abi.encode(uint8(2), owners);

        MiniAccount m2 = new MiniAccount{value: 1 ether}(ep, tv, ecdsaInit);
        for (uint256 n; n < ROUNDS; ++n) _ecdsaOp(address(m2), _callData(), signers, n, MINI_ECDSA_2OF3, "");
        address k2 = _kernel(address(tv), ecdsaInit);
        for (uint256 n; n < ROUNDS; ++n) _ecdsaOp(k2, _kernelCallData(), signers, n, KERNEL_ECDSA_2OF3, "");

        WotsParams memory p = WotsParams(24, 431);
        WinterlockValidator wv = new WinterlockValidator(p.n, p.targetSum);

        // each account gets its own member trees (one tree per member, account and chain)
        WotsKey[] memory miniKeys = _team(p, "team mini");
        MiniAccount mw = new MiniAccount{value: 1 ether}(ep, wv, Ops.installData(miniKeys, 2));
        _wotsTeamOps(address(mw), _callData(), miniKeys, "Winterlock 2-of-3 24-byte target 431", MINI_ECDSA_2OF3);

        WotsKey[] memory kernelKeys = _team(p, "team kernel");
        address kw = _kernel(address(wv), Ops.installData(kernelKeys, 2));
        _wotsTeamOps(kw, _kernelCallData(), kernelKeys, "Kernel + Winterlock 2-of-3 24-byte target 431", KERNEL_ECDSA_2OF3);
    }

    // --- helpers ---

    function _setName(WotsParams memory p) internal view returns (string memory) {
        return string.concat(
            vm.toString(p.n), "-byte ", p.targetSum == 0 ? "checksum" : string.concat("target ", vm.toString(p.targetSum))
        );
    }

    function _key(WotsParams memory p, string memory tag, uint256 i, uint256 k) internal pure returns (WotsKey memory) {
        return WotsTree.create(
            p, uint128(uint256(keccak256(abi.encode(tag, "seed", i)))), keccak256(abi.encode(tag, "sk", i)), 20, k
        );
    }

    /// Members A and B sign (real leaves for the benchmark nonces), C only needs a root.
    function _team(WotsParams memory p, string memory tag) internal pure returns (WotsKey[] memory keys) {
        keys = new WotsKey[](3);
        keys[0] = _key(p, tag, 0, 4);
        keys[1] = _key(p, tag, 1, 4);
        keys[2] = _key(p, tag, 2, 0);
    }

    function _wotsTeamOps(
        address account,
        bytes memory callData,
        WotsKey[] memory keys,
        string memory name,
        string memory base
    ) internal {
        for (uint256 n; n < ROUNDS; ++n) {
            PackedUserOperation memory op = Ops.build(account, n, callData, 800_000);
            bytes32 h = ep.getUserOpHash(op);
            op.signature = bytes.concat(Ops.memberSignature(keys[0], 0, 0, n * 2, h), Ops.memberSignature(keys[1], 1, 0, n * 2, h));
            _submit(op, name, base, n);
        }
    }

    /// Three ECDSA owners sorted by address; the first two sign.
    function _ecdsaOwners() internal pure returns (uint256[] memory signers, address[] memory owners) {
        uint256[3] memory pks = [uint256(0xA11CE), 0xB0B5, 0xCA7];
        for (uint256 i = 1; i < 3; ++i) {
            for (uint256 j = i; j > 0 && vm.addr(pks[j]) < vm.addr(pks[j - 1]); --j) {
                (pks[j], pks[j - 1]) = (pks[j - 1], pks[j]);
            }
        }
        owners = new address[](3);
        for (uint256 i; i < 3; ++i) {
            owners[i] = vm.addr(pks[i]);
        }
        signers = new uint256[](2);
        signers[0] = pks[0];
        signers[1] = pks[1];
    }

    function _kernel(address validator, bytes memory validatorData) internal returns (address account) {
        bytes memory init = abi.encodeCall(
            Kernel.initialize,
            (ValidatorLib.validatorToIdentifier(KernelValidator(validator)), IHook(address(0)), validatorData, hex"", new bytes[](0))
        );
        account = kf.createAccount(init, bytes32(0));
        _pay(account, 1 ether);
    }

    function _callData() internal view returns (bytes memory) {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", recipient, 0.001 ether, "");
    }

    function _kernelCallData() internal view returns (bytes memory) {
        return abi.encodeCall(Kernel.execute, (ExecMode.wrap(bytes32(0)), ExecLib.encodeSingle(recipient, 0.001 ether, "")));
    }

    /// ECDSA signatures (personal_sign of the userOpHash), in the order of `pks` (sorted by address)
    function _ecdsaOp(
        address account,
        bytes memory callData,
        uint256[] memory pks,
        uint256 n,
        string memory name,
        string memory base
    ) internal {
        PackedUserOperation memory op = Ops.build(account, n, callData, 400_000);
        bytes32 h = MessageHashUtils.toEthSignedMessageHash(ep.getUserOpHash(op));
        for (uint256 i; i < pks.length; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], h);
            op.signature = bytes.concat(op.signature, abi.encodePacked(r, s, v));
        }
        _submit(op, name, base, n);
    }

    function _submit(PackedUserOperation memory op, string memory name, string memory base, uint256 n) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ep.handleOps(ops, bundler);
        sent++;
        labels = string.concat(
            labels,
            bytes(labels).length == 0 ? "" : ",",
            '{"name":"',
            name,
            '","base":"',
            base,
            '","nonce":',
            vm.toString(n),
            ',"sigBytes":',
            vm.toString(op.signature.length),
            "}"
        );
    }

    function _pay(address to, uint256 amount) internal {
        (bool ok,) = payable(to).call{value: amount}("");
        require(ok, "pay failed");
    }
}
