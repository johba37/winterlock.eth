// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WotsParams, WotsKey, WotsSigner, WotsTree} from "../../test/utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "../../test/utils/StatelessSigner.sol";

/// @notice Signer for the live Safe owner test (bench/safe/live.py), called through eth_call on a LOCAL anvil only.
///         Every member's keys derive from a secret tag that the caller passes in: never call it on a remote node,
///         since the tag would leave the machine.
///         Per member: a stateless leanSphincs key (the WinterlockOwner's KEY, D12) and, per Safe and chain, an
///         operation tree of WOTS keys (D6) of height 10 whose first 16 keys are real (nonces 0 to 7, both slots),
///         built like the integration tests' trees (WotsTree). The tree's public seed and the digests that the
///         stateless key signs come from the WinterlockOwner on the target chain (treeSeed, certificateDigest,
///         messageDigest), passed in by the caller.
/// @dev    Costly in gas: a stateless keygen is about 50M, a stateless signature about 55M. Call it with a high gas
///         limit on a node without an eth_call gas cap or time limit.
contract SafeOwnerSignerHelper {
    uint256 internal constant HEIGHT = 10;
    uint256 internal constant REAL = 4;
    /// Kept subtree of the stateless key (StatelessSigner.keygen)
    uint256 internal constant KEPT = 10;
    uint256 internal constant SLOTS = 2;
    uint8 internal constant KIND_MESSAGE = 0x02;

    bytes32 internal constant SAFE_DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 internal constant SAFE_TX_TYPEHASH = keccak256(
        "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    );

    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0); // D6
    }

    function _statelessKey(bytes32 tag, uint256 member) internal pure returns (StatelessKey memory) {
        return StatelessSigner.keygen(keccak256(abi.encode("winterlock.safe-live.stateless", tag, member)), KEPT);
    }

    function _tree(bytes32 tag, uint256 member, uint256 chainId, address safe, uint64 start, uint128 seed)
        internal
        pure
        returns (WotsKey memory)
    {
        bytes32 skSeed = keccak256(abi.encode("winterlock.safe-live.ops", tag, member, chainId, safe, start));
        return WotsTree.create(_p(), seed, skSeed, HEIGHT, REAL);
    }

    /// The member's stateless public key (root ‖ P): its WinterlockOwner's KEY
    function publicKey(bytes32 tag, uint256 member) external pure returns (bytes32) {
        return StatelessSigner.publicKey(_statelessKey(tag, member));
    }

    /// Root and height of the member's operation tree for `safe` on `chainId` from `start`; `seed` is
    /// WinterlockOwner.treeSeed(safe, start) on that chain
    function tree(bytes32 tag, uint256 member, uint256 chainId, address safe, uint64 start, uint128 seed)
        external
        pure
        returns (bytes32 root, uint8 height)
    {
        WotsKey memory t = _tree(tag, member, chainId, safe, start, seed);
        // forge-lint: disable-next-line(unsafe-typecast)
        return (t.root, uint8(t.height));
    }

    /// The stateless key's signature of `digest` (WinterlockOwner.certificateDigest for an enrolment)
    function certificate(bytes32 tag, uint256 member, bytes32 digest) external pure returns (bytes memory) {
        return StatelessSigner.sign(_statelessKey(tag, member), digest);
    }

    /// Safe's transaction hash on `chainId` for the ten SafeTx words (Safe.getTransactionHash)
    function safeTxHash(uint256 chainId, address safe, bytes32[10] calldata words) public pure returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(SAFE_DOMAIN_TYPEHASH, chainId, safe));
        return keccak256(abi.encodePacked(bytes2(0x1901), domain, keccak256(abi.encode(SAFE_TX_TYPEHASH, words))));
    }

    /// WinterlockOwner transaction signature: [slot][safe][SafeTx words][WOTS signature of the SafeTx hash by key
    /// (nonce - start) * 2 + slot][path]. Each (nonce, slot) key must sign one SafeTx only: the caller keeps track.
    function txSignature(
        bytes32 tag,
        uint256 member,
        uint256 chainId,
        address safe,
        uint64 start,
        uint128 seed,
        uint256 slot,
        bytes32[10] calldata words
    ) external pure returns (bytes memory data, bytes32 hash) {
        require(slot < SLOTS, "slot");
        uint256 nonce = uint256(words[9]);
        require(nonce >= start, "nonce before tree");
        hash = safeTxHash(chainId, safe, words);
        WotsKey memory t = _tree(tag, member, chainId, safe, start, seed);
        uint256 keyIndex = (nonce - start) * SLOTS + slot;
        data = abi.encodePacked(
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(slot),
            safe,
            abi.encode(words),
            WotsSigner.sign(t.p, t.seed, t.skSeed, keyIndex, hash),
            WotsTree.path(t, keyIndex)
        );
    }

    /// WinterlockOwner SafeMessage signature: [0x02][safe][keccak256(message)][stateless signature of `digest`];
    /// `digest` is WinterlockOwner.messageDigest(safe, SafeMessage hash) on the target chain
    function messageSignature(bytes32 tag, uint256 member, address safe, bytes32 msgHash, bytes32 digest)
        external
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(KIND_MESSAGE, safe, msgHash, StatelessSigner.sign(_statelessKey(tag, member), digest));
    }
}
