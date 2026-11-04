// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SimpleAccount} from "account-abstraction/samples/SimpleAccount.sol";
import {SimpleAccountFactory} from "account-abstraction/samples/SimpleAccountFactory.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {WinterlockValidator} from "../src/WinterlockValidator.sol";
import {MiniAccount, EcdsaValidator} from "../test/utils/Harness.sol";
import {WotsParams, WotsKey, WotsTree, Ops} from "../test/utils/WotsSigner.sol";

/// @notice Sends real handleOps transactions so receipts include intrinsic and calldata gas.
///         Each account sends ROUNDS ops (an ETH transfer to an existing address). Nonce 0 warms
///         storage up and is reported separately; later nonces are the steady state.
///         Run through bench.sh against a local anvil.
contract GasBench is Script {
    uint256 internal constant ROUNDS = 6;
    uint256 internal constant OWNER_PK = 0xA11CE;

    EntryPoint internal ep;
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

        // Reference: eth-infinitism SimpleAccount (ECDSA)
        SimpleAccountFactory factory = new SimpleAccountFactory(ep);
        SimpleAccount sa = factory.createAccount(vm.addr(OWNER_PK), 0);
        _pay(address(sa), 1 ether);
        for (uint256 n; n < ROUNDS; ++n) _ecdsaOp(address(sa), n, "SimpleAccount (ECDSA)");

        // Baseline: the same minimal account with an ECDSA validator module
        EcdsaValidator ev = new EcdsaValidator();
        MiniAccount ma = new MiniAccount{value: 1 ether}(ep, ev, abi.encode(vm.addr(OWNER_PK)));
        for (uint256 n; n < ROUNDS; ++n) _ecdsaOp(address(ma), n, "MiniAccount + ECDSA validator");

        // Winterlock validator: hash size x encoding, all at tree height 20 (2^19 nonces)
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
            WinterlockValidator wv = new WinterlockValidator(p.n, p.targetSum);
            WotsKey memory key = WotsTree.create(
                p, uint128(uint256(keccak256(abi.encode("seed", t)))), keccak256(abi.encode("sk", t)), 20, 4
            );
            MiniAccount wa = new MiniAccount{value: 1 ether}(ep, wv, abi.encode(key.root, key.seed, uint8(20), uint192(0)));
            string memory name = string.concat(
                "Winterlock n=",
                vm.toString(p.n),
                p.targetSum == 0 ? " checksum" : string.concat(" target ", vm.toString(p.targetSum))
            );
            for (uint256 n; n < ROUNDS; ++n) _wotsOp(address(wa), key, n, name);
        }
        vm.stopBroadcast();

        require(recipient.balance == 1 ether + sent * 0.001 ether, "not every op executed");
        vm.writeFile("bench/labels.json", string.concat("[", labels, "]"));
    }

    function _callData() internal view returns (bytes memory) {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", recipient, 0.001 ether, "");
    }

    function _ecdsaOp(address account, uint256 n, string memory name) internal {
        PackedUserOperation memory op = Ops.build(account, n, _callData(), 100_000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, MessageHashUtils.toEthSignedMessageHash(ep.getUserOpHash(op)));
        op.signature = abi.encodePacked(r, s, v);
        _submit(op, name, n);
    }

    function _wotsOp(address account, WotsKey memory key, uint256 n, string memory name) internal {
        PackedUserOperation memory op = Ops.build(account, n, _callData(), 300_000);
        op.signature = Ops.wotsSignature(key, 0, n * 2, ep.getUserOpHash(op));
        _submit(op, name, n);
    }

    function _submit(PackedUserOperation memory op, string memory name, uint256 n) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ep.handleOps(ops, bundler);
        sent++;
        labels = string.concat(
            labels,
            bytes(labels).length == 0 ? "" : ",",
            '{"name":"', name, '","nonce":', vm.toString(n), ',"sigBytes":', vm.toString(op.signature.length), "}"
        );
    }

    function _pay(address to, uint256 amount) internal {
        (bool ok,) = payable(to).call{value: amount}("");
        require(ok, "pay failed");
    }
}
