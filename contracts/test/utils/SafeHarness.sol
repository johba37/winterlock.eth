// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ISafe} from "safe-v1.5.0/interfaces/ISafe.sol";
import {Enum} from "safe-v1.5.0/libraries/Enum.sol";
import {WinterlockOwner} from "../../src/safe/WinterlockOwner.sol";
import {WotsParams, WotsKey, WotsSigner, WotsTree} from "./WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./StatelessSigner.sol";

interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

/// EIP-1271 as apps ask a Safe (answered by its fallback handler)
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// The Safe contracts of one release, deployed from the release build (setup.sh: solc 0.7.6, optimizer off). The ABI
/// of the calls the tests make (setup, execTransaction, getTransactionHash, nonce, swapOwner, getOwners) is the same
/// in v1.4.1 and v1.5.0, so both are driven through v1.5.0's ISafe.
struct SafeRelease {
    string version; // "v1.4.1" or "v1.5.0"
    address singleton;
    ISafeProxyFactory factory;
    address fallbackHandler;
    address multiSendCallOnly;
}

/// The fields of a Safe transaction (Safe's SafeTx struct, with the data itself)
struct SafeTx {
    address to;
    uint256 value;
    bytes data;
    uint8 operation;
    uint256 safeTxGas;
    uint256 baseGas;
    uint256 gasPrice;
    address gasToken;
    address refundReceiver;
    uint256 nonce;
}

/// One owner's part of a Safe signatures blob: 65 bytes for an EOA (r, s, v), or contract signature data (v = 0)
struct OwnerSignature {
    address owner;
    bool isContract;
    bytes data;
}

library SafeHarness {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function artifact(string memory version, string memory name) internal pure returns (string memory) {
        return string.concat("lib/safe-smart-account-", version, "/build/forge-out/", name, ".sol/", name, ".json");
    }

    function deployRelease(string memory version) internal returns (SafeRelease memory r) {
        r.version = version;
        r.singleton = VM.deployCode(artifact(version, "Safe"));
        r.factory = ISafeProxyFactory(VM.deployCode(artifact(version, "SafeProxyFactory")));
        r.fallbackHandler = VM.deployCode(artifact(version, "CompatibilityFallbackHandler"));
        r.multiSendCallOnly = VM.deployCode(artifact(version, "MultiSendCallOnly"));
    }

    function setupData(SafeRelease memory r, address[] memory owners, uint256 threshold)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeCall(
            ISafe.setup, (owners, threshold, address(0), "", r.fallbackHandler, address(0), 0, payable(address(0)))
        );
    }

    /// A Safe proxy through the release's factory, as Safe's app creates one
    function createSafe(SafeRelease memory r, address[] memory owners, uint256 threshold, uint256 saltNonce)
        internal
        returns (ISafe)
    {
        return ISafe(payable(r.factory.createProxyWithNonce(r.singleton, setupData(r, owners, threshold), saltNonce)));
    }

    // --- transactions ---

    function transfer(address to, uint256 value, uint256 nonce) internal pure returns (SafeTx memory t) {
        t.to = to;
        t.value = value;
        t.nonce = nonce;
    }

    function call(address to, bytes memory data, uint256 nonce) internal pure returns (SafeTx memory t) {
        t.to = to;
        t.data = data;
        t.nonce = nonce;
    }

    function hash(ISafe safe, SafeTx memory t) internal view returns (bytes32) {
        return safe.getTransactionHash(
            t.to,
            t.value,
            t.data,
            Enum.Operation(t.operation),
            t.safeTxGas,
            t.baseGas,
            t.gasPrice,
            t.gasToken,
            t.refundReceiver,
            t.nonce
        );
    }

    /// The ten SafeTx words after the type hash, as a WinterlockOwner transaction signature carries them
    function words(SafeTx memory t) internal pure returns (bytes memory) {
        return abi.encode(
            t.to,
            t.value,
            keccak256(t.data),
            t.operation,
            t.safeTxGas,
            t.baseGas,
            t.gasPrice,
            t.gasToken,
            t.refundReceiver,
            t.nonce
        );
    }

    function execCalldata(SafeTx memory t, bytes memory signatures) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ISafe.execTransaction,
            (
                t.to,
                t.value,
                t.data,
                Enum.Operation(t.operation),
                t.safeTxGas,
                t.baseGas,
                t.gasPrice,
                t.gasToken,
                payable(t.refundReceiver),
                signatures
            )
        );
    }

    function exec(ISafe safe, SafeTx memory t, bytes memory signatures) internal returns (bool) {
        return safe.execTransaction(
            t.to,
            t.value,
            t.data,
            Enum.Operation(t.operation),
            t.safeTxGas,
            t.baseGas,
            t.gasPrice,
            t.gasToken,
            payable(t.refundReceiver),
            signatures
        );
    }

    /// A MultiSendCallOnly batch of calls (operation 0, no value), run by the Safe with a delegatecall
    function multiSend(SafeRelease memory r, address[] memory targets, bytes[] memory data, uint256 nonce)
        internal
        pure
        returns (SafeTx memory t)
    {
        bytes memory packed;
        for (uint256 i; i < targets.length; ++i) {
            packed = abi.encodePacked(packed, uint8(0), targets[i], uint256(0), data[i].length, data[i]);
        }
        t.to = r.multiSendCallOnly;
        t.data = abi.encodeWithSignature("multiSend(bytes)", packed);
        t.operation = 1; // delegatecall
        t.nonce = nonce;
    }

    // --- messages ---

    /// keccak256(message) of the SafeMessage that CompatibilityFallbackHandler checks when an app asks the Safe
    /// isValidSignature(bytes32 appHash, ...): the message is abi.encode(appHash)
    function messageHash(bytes32 appHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(appHash));
    }

    /// The SafeMessage hash for `msgHash` (keccak256 of the message), as the fallback handler computes it
    function safeMessageHash(ISafe safe, bytes32 msgHash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(keccak256("SafeMessage(bytes message)"), msgHash));
        return keccak256(abi.encodePacked(bytes2(0x1901), safe.domainSeparator(), structHash));
    }

    // --- signatures blob ---

    function ecdsa(uint256 pk, bytes32 safeTxHash) internal pure returns (OwnerSignature memory s) {
        (uint8 v, bytes32 r, bytes32 sv) = VM.sign(pk, safeTxHash);
        s.owner = VM.addr(pk);
        s.data = abi.encodePacked(r, sv, v);
    }

    function contractSig(address owner, bytes memory data) internal pure returns (OwnerSignature memory s) {
        s.owner = owner;
        s.isContract = true;
        s.data = data;
    }

    /// Safe's signatures blob: one 65-byte static part per owner in increasing owner order, then the contract
    /// signatures' data, each as [length: 32][data], with the offset of its length word in the static part's s
    /// (v = 0, r = the owner contract). Safe.checkNSignatures, v1.4.1 and v1.5.0.
    function pack(OwnerSignature[] memory sigs) internal pure returns (bytes memory out) {
        for (uint256 i = 1; i < sigs.length; ++i) {
            for (uint256 j = i; j > 0 && sigs[j - 1].owner > sigs[j].owner; --j) {
                (sigs[j - 1], sigs[j]) = (sigs[j], sigs[j - 1]);
            }
        }
        bytes memory dynamicPart;
        uint256 offset = 65 * sigs.length;
        for (uint256 i; i < sigs.length; ++i) {
            if (!sigs[i].isContract) {
                out = bytes.concat(out, sigs[i].data);
                continue;
            }
            out = abi.encodePacked(out, uint256(uint160(sigs[i].owner)), offset + dynamicPart.length, uint8(0));
            dynamicPart = abi.encodePacked(dynamicPart, sigs[i].data.length, sigs[i].data);
        }
        out = bytes.concat(out, dynamicPart);
    }

    function pack(OwnerSignature memory a, OwnerSignature memory b) internal pure returns (bytes memory) {
        OwnerSignature[] memory sigs = new OwnerSignature[](2);
        sigs[0] = a;
        sigs[1] = b;
        return pack(sigs);
    }
}

/// A member's keys for a WinterlockOwner: the stateless key (its public key is the owner's KEY) and the label its
/// operation-tree secrets derive from. Test use only: secrets come from public labels.
struct Member {
    string label;
    StatelessKey sk;
    WinterlockOwner owner;
}

/// Test signer for WinterlockOwner. An operation tree per Safe, chain and start, of height `h` with 2^k real keys
/// (WotsTree): its public seed comes from the owner (treeSeed), its secret seed from the label, the chain, the Safe and
/// the start, so every Safe and chain gets its own keys.
library OwnerSigner {
    /// Signature kind of a SafeMessage
    uint8 internal constant KIND_MESSAGE = 0x02;

    function opsTree(WotsParams memory p, Member memory m, address safe, uint64 start, uint256 h, uint256 k)
        internal
        view
        returns (WotsKey memory)
    {
        bytes32 skSeed = keccak256(abi.encode(m.label, "safe ops", block.chainid, safe, start));
        return WotsTree.create(p, m.owner.treeSeed(safe, start), skSeed, h, k);
    }

    /// The stateless key's signature of the certificate for `tree` (certified from `start`) of `safe` on this chain
    function certificate(Member memory m, WotsKey memory tree, address safe, uint64 start)
        internal
        view
        returns (bytes memory)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 digest = m.owner.certificateDigest(safe, tree.root, uint8(tree.height), start);
        return StatelessSigner.sign(m.sk, digest);
    }

    /// Calldata of WinterlockOwner.enroll for `tree`
    function enrollCalldata(Member memory m, WotsKey memory tree, address safe, uint64 start)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeCall(
            // forge-lint: disable-next-line(unsafe-typecast)
            WinterlockOwner.enroll,
            (safe, tree.root, uint8(tree.height), start, certificate(m, tree, safe, start))
        );
    }

    /// [slot][safe][SafeTx words][WOTS signature of safeTxHash by key (nonce - start) * 2 + slot][path]
    function txSignature(
        WotsKey memory tree,
        uint64 start,
        uint256 slot,
        address safe,
        SafeTx memory t,
        bytes32 safeTxHash
    ) internal pure returns (bytes memory) {
        return txSignatureWithKey(tree, (t.nonce - start) * 2 + slot, slot, safe, t, safeTxHash);
    }

    /// The same with any key index, for tests of keys used at the wrong nonce
    function txSignatureWithKey(
        WotsKey memory tree,
        uint256 keyIndex,
        uint256 slot,
        address safe,
        SafeTx memory t,
        bytes32 safeTxHash
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(slot),
            safe,
            SafeHarness.words(t),
            WotsSigner.sign(tree.p, tree.seed, tree.skSeed, keyIndex, safeTxHash),
            WotsTree.path(tree, keyIndex)
        );
    }

    /// [0x02][safe][keccak256(message)][stateless signature of messageDigest(safe, SafeMessage hash)]
    function messageSignature(Member memory m, address safe, bytes32 msgHash, bytes32 safeMsgHash)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            KIND_MESSAGE, safe, msgHash, StatelessSigner.sign(m.sk, m.owner.messageDigest(safe, safeMsgHash))
        );
    }
}
