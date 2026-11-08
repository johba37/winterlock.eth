/// @title  Winterlock frame account, v0: an EIP-8141 account guarded by a member's stateless key
/// @notice A native account for frame transactions (EIP-8141), in the form Daisugi's prototype runs (Nethermind,
///         branch daisugi/devnet-handoff). Each account is a 109-byte clone: EIP-1167's 45 bytes pointing here,
///         then the member's leanSphincs-keccak public key (pkSeed ‖ pkRoot, high-aligned words, 64 bytes).
///
///         In a VERIFY frame the protocol calls the account from ENTRY_POINT (0xaa). The account then requires:
///           - the transaction's sender is this account, and the current frame is a VERIFY frame;
///           - the transaction carries exactly one signature: scheme ARBITRARY, empty msg (so it signs the
///             transaction's canonical signature hash), 5,684 bytes;
///           - the stateless verifier accepts it for the key in the clone's code and TXPARAM_SIG_HASH;
///         and approves execution and payment. Any other call is a plain value transfer (no calldata) or reverts.
///
///         v0 checks the member key on every transaction: 5.7 KB and about 53k gas of verification. The WOTS fast
///         path (certified key trees, one-time keys bound to the nonce) is the next step.
/// @dev    Written in Yul for `verbatim`: solc has no names for the frame opcodes. Stack orders follow the EIP and
///         Daisugi's own account: TXPARAM(param); FRAMEPARAM(frameIndex, param); SIGPARAM(sigIndex, param);
///         SIGDATACOPY(memOffset, sigOffset, length, sigIndex); APPROVE(offset, length, scope); first argument on top.
object "WinterlockFrameAccount" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            // the vendored leanSphincs-keccak verifier, CREATE2 through the deterministic deployment proxy
            // with salt keccak256("Winterlock.stateless-verifier.v1") (script/DeployValidator.s.sol)
            let verifier := 0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254
            let sigLen := 5684

            if iszero(eq(caller(), 0xaa)) {
                if calldatasize() { revert(0, 0) }
                stop()
            }
            if calldatasize() { revert(0, 0) }
            if iszero(eq(txparam(0x02), address())) { revert(0, 0) }                 // TXPARAM_SENDER
            if iszero(eq(extcodesize(address()), 109)) { revert(0, 0) }             // run through a clone
            if iszero(eq(frameparam(txparam(0x0a), 0x02), 1)) { revert(0, 0) }      // this frame's mode: VERIFY
            if iszero(eq(txparam(0x0b), 1)) { revert(0, 0) }                        // one signature
            if sigparam(0, 0x01) { revert(0, 0) }                                   // scheme ARBITRARY (0)
            if sigparam(0, 0x02) { revert(0, 0) }                                   // msg empty: the sig hash
            if iszero(eq(sigparam(0, 0x03), sigLen)) { revert(0, 0) }               // length

            // verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig)
            mstore(0x00, shl(224, 0x2bf6eda8))
            extcodecopy(address(), 0x04, 45, 64)
            mstore(0x44, txparam(0x08))                                             // TXPARAM_SIG_HASH
            mstore(0x64, 0x80)
            mstore(0x84, sigLen)
            sigdatacopy(0xa4, 0, sigLen, 0)
            if iszero(staticcall(gas(), verifier, 0x00, add(0xa4, sigLen), 0x00, 0x20)) { revert(0, 0) }
            if iszero(and(eq(returndatasize(), 0x20), eq(mload(0x00), 1))) { revert(0, 0) }

            approve(0, 0, 3)                                                        // execution and payment

            function txparam(p) -> v { v := verbatim_1i_1o(hex"b0", p) }
            function frameparam(i, p) -> v { v := verbatim_2i_1o(hex"b3", i, p) }
            function sigparam(i, p) -> v { v := verbatim_2i_1o(hex"b4", i, p) }
            function sigdatacopy(m, o, l, i) { verbatim_4i_0o(hex"b5", m, o, l, i) }
            function approve(o, l, s) { verbatim_3i_0o(hex"aa", o, l, s) }
        }
    }
}
