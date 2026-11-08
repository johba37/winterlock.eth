/// @title  Winterlock frame account, v1: the member key, and one-time WOTS keys bound to the nonce
/// @notice An EIP-8141 account in the form Daisugi's prototype runs. Each account is a 109-byte clone: EIP-1167's
///         45 bytes pointing here, then the member's leanSphincs-keccak public key (pkSeed ‖ pkRoot, 64 bytes).
///
///         VERIFY (the protocol calls from ENTRY_POINT, 0xaa) accepts the transaction's one signature, scheme
///         ARBITRARY with an empty msg (so it signs TXPARAM_SIG_HASH), in either of two forms:
///           - 5,684 bytes: a member-key signature, checked by the stateless verifier (as in v0);
///           - 1 + 1,176 + 24·height bytes: [slot][WOTS signature][path], a one-time key of the enrolled tree. The
///             key is bound to the transaction's nonce: keyIndex = (nonce − start)·2 + slot, slot 0 or 1, and the
///             tree holds 2^(height−1) nonces from `start`. The protocol includes each nonce once, so each key signs
///             at most one included transaction; the second slot lets the signer replace a pending transaction
///             (a new fee changes the signature hash) without signing twice with one key.
///         and then approves execution and payment.
///
///         enroll(bytes32 root, uint8 height, uint64 start) stores the tree. Only the account can call it, in a
///         SENDER frame to itself, and only in a transaction the member key signed: the transaction's one
///         signature must be the 5,684-byte form. A one-time key can't install a tree.
///
///         Storage slot 0: root (24 bytes, high) ‖ start (40 bits) << 8 ‖ height (8 bits), as WinterlockOwner packs
///         a tree. The tree's public seed is the first 16 bytes of
///         keccak256(abi.encode(TREE_SEED_DOMAIN, chainid, account, start)); starts only grow, so seeds don't repeat.
/// @dev    Yul for `verbatim` (frame opcodes). Stack orders as in v0. In VERIFY the account reads only its own
///         storage and calls only the two verifiers (pure), as EIP-8141's public-mempool rules allow.
object "WinterlockFrameAccountV1" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            // 5,684 bytes: a member-key (leanSphincs-keccak) signature
            if eq(caller(), 0xaa) {
                verify()
            }
            if eq(caller(), address()) {
                enroll()
            }
            if calldatasize() { revert(0, 0) }
            stop()

            function verify() {
                if calldatasize() { revert(0, 0) }
                if iszero(eq(txparam(0x02), address())) { revert(0, 0) }                // TXPARAM_SENDER
                if iszero(eq(extcodesize(address()), 109)) { revert(0, 0) }            // run through a clone
                if iszero(eq(frameparam(txparam(0x0a), 0x02), 1)) { revert(0, 0) }     // this frame: VERIFY
                if iszero(eq(txparam(0x0b), 1)) { revert(0, 0) }                       // one signature
                if sigparam(0, 0x01) { revert(0, 0) }                                  // scheme ARBITRARY
                if sigparam(0, 0x02) { revert(0, 0) }                                  // msg empty: the sig hash
                let len := sigparam(0, 0x03)
                switch eq(len, 5684)
                case 1 { memberKey(len) }
                default { oneTimeKey(len) }
                approve(0, 0, 3)                                                       // execution and payment
            }

            // verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig) on the stateless verifier
            function memberKey(len) {
                mstore(0x00, shl(224, 0x2bf6eda8))
                extcodecopy(address(), 0x04, 45, 64)
                mstore(0x44, txparam(0x08))
                mstore(0x64, 0x80)
                mstore(0x84, len)
                sigdatacopy(0xa4, 0, len, 0)
                if iszero(staticcall(gas(), 0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254, 0x00, add(0xa4, len), 0x00, 0x20)) {
                    revert(0, 0)
                }
                if iszero(and(eq(returndatasize(), 0x20), eq(mload(0x00), 1))) { revert(0, 0) }
            }

            // computeRoot(uint256 params, uint128 seed, uint256 keyIndex, bytes32 message, bytes sig) on the shared
            // WOTS verifier, compared with the stored root
            function oneTimeKey(len) {
                let word := sload(0)
                if iszero(word) { revert(0, 0) }
                let height := and(word, 0xff)
                let start := and(shr(8, word), 0xffffffffff)
                if iszero(eq(len, add(1177, mul(24, height)))) { revert(0, 0) }
                let nonce := txparam(0x01)                                             // TXPARAM_NONCE
                if lt(nonce, start) { revert(0, 0) }
                let offset := sub(nonce, start)
                if shr(sub(height, 1), offset) { revert(0, 0) }                       // 2^(height−1) nonces
                sigdatacopy(0x00, 0, 1, 0)
                let slot := shr(248, mload(0x00))
                if gt(slot, 1) { revert(0, 0) }
                let keyIndex := add(shl(1, offset), slot)

                mstore(0x00, 0xf2d6da6e7909b8b34235dfee24c16677547667143bfca8f6803ffa8e1a4e6bab) // TREE_SEED_DOMAIN
                mstore(0x20, chainid())
                mstore(0x40, address())
                mstore(0x60, start)
                let seed := shr(128, keccak256(0x00, 0x80))

                let n := sub(len, 1)
                let padded := and(add(n, 31), not(31))
                mstore(0x00, shl(224, 0x1a926dff))
                mstore(0x04, 0x1af00000418)                                            // D6: n 24, w 16, keccak, sum 431
                mstore(0x24, seed)
                mstore(0x44, keyIndex)
                mstore(0x64, txparam(0x08))
                mstore(0x84, 0xa0)
                mstore(0xa4, n)
                mstore(add(0xa4, padded), 0)                                           // zero the last word's tail
                sigdatacopy(0xc4, 1, n, 0)
                if iszero(staticcall(gas(), 0x272138c7D3b508bd510bE5166fbE2461561e410D, 0x00, add(0xc4, padded), 0x00, 0x20)) {
                    revert(0, 0)
                }
                let root := mload(0x00)
                if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
                if iszero(root) { revert(0, 0) }
                if iszero(eq(root, and(word, not(0xffffffffffffffff)))) { revert(0, 0) }
            }

            function enroll() {
                // enroll(bytes32 root, uint8 height, uint64 start), from this account's own SENDER frame
                if iszero(eq(calldatasize(), 100)) { revert(0, 0) }
                if iszero(eq(shr(224, calldataload(0)), 0x58b1750e)) { revert(0, 0) }
                if iszero(eq(frameparam(txparam(0x0a), 0x02), 2)) { revert(0, 0) }     // a SENDER frame
                if iszero(eq(txparam(0x0b), 1)) { revert(0, 0) }
                if iszero(eq(sigparam(0, 0x03), 5684)) { revert(0, 0) }               // signed by the member key
                let root := calldataload(4)
                let height := calldataload(36)
                let start := calldataload(68)
                if or(iszero(root), and(root, 0xffffffffffffffff)) { revert(0, 0) }   // 24 bytes, high-aligned
                if or(iszero(height), gt(height, 40)) { revert(0, 0) }
                if gt(start, 0xffffffffff) { revert(0, 0) }
                let old := sload(0)
                if and(iszero(iszero(old)), iszero(gt(start, and(shr(8, old), 0xffffffffff)))) { revert(0, 0) }
                sstore(0, or(root, or(shl(8, start), height)))
                mstore(0x00, root)
                mstore(0x20, height)
                mstore(0x40, start)
                // Enrolled(bytes32 root, uint8 height, uint64 start)
                log1(0x00, 0x60, 0x566d0030ee9e12639ce9a6de6e23bf10804a6701b294687060e6c86b3ea7d8cf)
                stop()
            }

            function txparam(p) -> v { v := verbatim_1i_1o(hex"b0", p) }
            function frameparam(i, p) -> v { v := verbatim_2i_1o(hex"b3", i, p) }
            function sigparam(i, p) -> v { v := verbatim_2i_1o(hex"b4", i, p) }
            function sigdatacopy(m, o, l, i) { verbatim_4i_0o(hex"b5", m, o, l, i) }
            function approve(o, l, s) { verbatim_3i_0o(hex"aa", o, l, s) }
        }
    }
}
