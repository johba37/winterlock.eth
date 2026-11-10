/// @title  Winterlock frame account, v2: device keys, each with its own one-time keys
/// @notice An EIP-8141 account in the form Daisugi's prototype runs, with owner v2's device model
///         (docs/notes/owner-v2.md). Each account is a 109-byte clone: EIP-1167's 45 bytes pointing here, then
///         the member's leanSphincs-keccak key (pkSeed ‖ pkRoot, 64 bytes).
///
///         Devices: device 0 is the member key (from the recovery phrase, in the clone's code). Devices 1–3 hold
///         leanSphincs-keccak device keys made from their own seeds, without the phrase. The member key adds and
///         revokes them; each add starts a new generation of that device.
///
///         VERIFY accepts the transaction's one signature (scheme ARBITRARY, empty msg: it signs TXPARAM_SIG_HASH):
///           [2][device][leanSphincs signature: 5,684]        the device's key (device 0: the member key), while
///                                                            the device is active
///           [slot][device][WOTS: 1,176][path: 24 × height]   slot 0 or 1: a one-time key of the device's tree,
///                                                            keyIndex = (nonce − start)·2 + slot, while the device
///                                                            is active at the tree's generation
///         and approves execution and payment. Each device signs from its own tree, so two devices never share a
///         one-time key, even at the same nonce.
///
///         Management: SENDER frames from the account to itself, in a transaction signed by a device key (kind 2):
///           addDevice(uint8 device, bytes32 key)    the member key only; device 1–3, key = root ‖ P;
///                                                   generation + 1, active
///           revokeDevice(uint8 device)              the member key only; clears active, keeps the generation
///           enroll(uint8 device, bytes32 root, uint8 height, uint64 start)
///                                                   the device's own key only (the member key for device 0);
///                                                   within a generation, starts only grow
///         A one-time key can't manage anything.
///
///         Storage: tree of device d at slot d (root 24 B ‖ generation 16 ‖ start 40 ‖ height 8, owner v2's
///         packing); key of device d at 0x10 + d; generation | ACTIVE (1 << 16) at 0x20 + d. read(uint256 slot)
///         returns a slot, for RPCs without eth_getStorageAt. A tree's public seed is the first 16 bytes of
///         keccak256(abi.encode(TREE_SEED_DOMAIN, chainid, account, device, generation, start)).
/// @dev    Yul for `verbatim` (frame opcodes); stack orders as in v0. In VERIFY the account reads only its own
///         storage and code and calls only the two verifiers, as EIP-8141's public-mempool rules allow.
object "WinterlockFrameAccountV2" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) { verify() }
            if eq(caller(), address()) { manage() }
            if iszero(calldatasize()) { stop() }
            // read(uint256 slot)
            if and(eq(calldatasize(), 36), eq(shr(224, calldataload(0)), 0xed2e5a97)) {
                mstore(0x00, sload(calldataload(4)))
                return(0x00, 0x20)
            }
            revert(0, 0)

            function verify() {
                if calldatasize() { revert(0, 0) }
                if iszero(eq(txparam(0x02), address())) { revert(0, 0) }                // TXPARAM_SENDER
                if iszero(eq(extcodesize(address()), 109)) { revert(0, 0) }            // run through a clone
                if iszero(eq(frameparam(txparam(0x0a), 0x02), 1)) { revert(0, 0) }     // this frame: VERIFY
                if iszero(eq(txparam(0x0b), 1)) { revert(0, 0) }                       // one signature
                if sigparam(0, 0x01) { revert(0, 0) }                                  // scheme ARBITRARY
                if sigparam(0, 0x02) { revert(0, 0) }                                  // msg empty: the sig hash
                let len := sigparam(0, 0x03)
                if lt(len, 2) { revert(0, 0) }
                sigdatacopy(0x00, 0, 2, 0)
                let head := mload(0x00)
                let kind := byte(0, head)
                let device := byte(1, head)
                if gt(device, 3) { revert(0, 0) }
                switch kind
                case 2 { deviceKey(device, len) }
                default {
                    if gt(kind, 1) { revert(0, 0) }
                    oneTimeKey(device, kind, len)
                }
                approve(0, 0, 3)                                                       // execution and payment
            }

            // the generation of an active device; reverts if the device isn't active (device 0 always is, at 0)
            function generationOf(device) -> generation {
                if device {
                    let st := sload(add(0x20, device))
                    if iszero(and(st, 0x10000)) { revert(0, 0) }
                    generation := and(st, 0xffff)
                }
            }

            // verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig) on the stateless verifier
            function deviceKey(device, len) {
                if iszero(eq(len, 5686)) { revert(0, 0) }
                pop(generationOf(device))
                mstore(0x00, shl(224, 0x2bf6eda8))
                switch device
                case 0 { extcodecopy(address(), 0x04, 45, 64) }                         // the member key
                default {
                    let k := sload(add(0x10, device))                                  // root ‖ P
                    mstore(0x04, shl(128, k))                                          // pkSeed: P, high-aligned
                    mstore(0x24, and(k, not(0xffffffffffffffffffffffffffffffff)))      // pkRoot: root, high-aligned
                }
                mstore(0x44, txparam(0x08))
                mstore(0x64, 0x80)
                mstore(0x84, 5684)
                sigdatacopy(0xa4, 2, 5684, 0)
                if iszero(staticcall(gas(), 0x6Dc4DFBccDe0fbeC30b0a4078aB6f45496Fec254, 0x00, add(0xa4, 5684), 0x00, 0x20)) {
                    revert(0, 0)
                }
                if iszero(and(eq(returndatasize(), 0x20), eq(mload(0x00), 1))) { revert(0, 0) }
            }

            // computeRoot(uint256 params, uint128 seed, uint256 keyIndex, bytes32 message, bytes sig) on the shared
            // WOTS verifier, compared with the device's stored root
            function oneTimeKey(device, slot, len) {
                let generation := generationOf(device)
                let word := sload(device)
                if iszero(word) { revert(0, 0) }
                if iszero(eq(and(shr(48, word), 0xffff), generation)) { revert(0, 0) }  // the device's generation
                let height := and(word, 0xff)
                let start := and(shr(8, word), 0xffffffffff)
                if iszero(eq(len, add(1178, mul(24, height)))) { revert(0, 0) }
                let nonce := txparam(0x01)                                             // TXPARAM_NONCE
                if lt(nonce, start) { revert(0, 0) }
                let offset := sub(nonce, start)
                if shr(sub(height, 1), offset) { revert(0, 0) }                       // 2^(height−1) nonces
                let keyIndex := add(shl(1, offset), slot)

                mstore(0x00, 0x10dc16dc2ea563c3e54ece76e633d6a5cc5f10e4cc6d851cb540eb0984290223) // TREE_SEED_DOMAIN
                mstore(0x20, chainid())
                mstore(0x40, address())
                mstore(0x60, device)
                mstore(0x80, generation)
                mstore(0xa0, start)
                let seed := shr(128, keccak256(0x00, 0xc0))

                let n := sub(len, 2)
                let padded := and(add(n, 31), not(31))
                mstore(0x00, shl(224, 0x1a926dff))
                mstore(0x04, 0x1af00000418)                                            // D6: n 24, w 16, keccak, sum 431
                mstore(0x24, seed)
                mstore(0x44, keyIndex)
                mstore(0x64, txparam(0x08))
                mstore(0x84, 0xa0)
                mstore(0xa4, n)
                mstore(add(0xa4, padded), 0)                                           // zero the last word's tail
                sigdatacopy(0xc4, 2, n, 0)
                if iszero(staticcall(gas(), 0x272138c7D3b508bd510bE5166fbE2461561e410D, 0x00, add(0xc4, padded), 0x00, 0x20)) {
                    revert(0, 0)
                }
                let root := mload(0x00)
                if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
                if iszero(root) { revert(0, 0) }
                if iszero(eq(root, and(word, not(0xffffffffffffffff)))) { revert(0, 0) }
            }

            // SENDER frames from the account to itself, in a transaction a device key signed
            function manage() {
                if iszero(eq(frameparam(txparam(0x0a), 0x02), 2)) { revert(0, 0) }     // a SENDER frame
                if iszero(eq(txparam(0x0b), 1)) { revert(0, 0) }
                if iszero(eq(sigparam(0, 0x03), 5686)) { revert(0, 0) }               // a device-key signature
                sigdatacopy(0x00, 0, 2, 0)
                let head := mload(0x00)
                if iszero(eq(byte(0, head), 2)) { revert(0, 0) }
                let signer := byte(1, head)                                            // VERIFY checked it
                let device := calldataload(4)
                if gt(device, 3) { revert(0, 0) }
                switch shr(224, calldataload(0))
                case 0xce935112 {                                                      // enroll
                    if iszero(eq(calldatasize(), 132)) { revert(0, 0) }
                    if iszero(eq(device, signer)) { revert(0, 0) }                     // its own trees only
                    let generation := generationOf(device)
                    let root := calldataload(36)
                    let height := calldataload(68)
                    let start := calldataload(100)
                    if or(iszero(root), and(root, 0xffffffffffffffff)) { revert(0, 0) } // 24 bytes, high-aligned
                    if or(iszero(height), gt(height, 40)) { revert(0, 0) }
                    if gt(start, 0xffffffffff) { revert(0, 0) }
                    let old := sload(device)
                    if and(eq(and(shr(48, old), 0xffff), generation), iszero(iszero(old))) {
                        if iszero(gt(start, and(shr(8, old), 0xffffffffff))) { revert(0, 0) }
                    }
                    sstore(device, or(root, or(shl(48, generation), or(shl(8, start), height))))
                    mstore(0x00, device)
                    mstore(0x20, generation)
                    mstore(0x40, root)
                    mstore(0x60, height)
                    mstore(0x80, start)
                    // Enrolled(uint8 device, uint16 generation, bytes32 root, uint8 height, uint64 start)
                    log1(0x00, 0xa0, 0xa3cc4204c4829a0b520c0e49526c312eff54b6812ce2feef337e31fdf85a152b)
                }
                case 0x3ee1cb75 {                                                      // addDevice
                    if iszero(eq(calldatasize(), 68)) { revert(0, 0) }
                    if signer { revert(0, 0) }                                         // the member key only
                    if iszero(device) { revert(0, 0) }
                    let key := calldataload(36)
                    if iszero(key) { revert(0, 0) }
                    let generation := add(and(sload(add(0x20, device)), 0xffff), 1)
                    if gt(generation, 0xffff) { revert(0, 0) }
                    sstore(add(0x10, device), key)
                    sstore(add(0x20, device), or(generation, 0x10000))
                    mstore(0x00, device)
                    mstore(0x20, key)
                    mstore(0x40, generation)
                    // DeviceAdded(uint8 device, bytes32 key, uint16 generation)
                    log1(0x00, 0x60, 0x12a684d6781492ba1ed517103340a2d51b80f5dfa289e91d72fcb39a6dd065f8)
                }
                case 0x6e354d8b {                                                      // revokeDevice
                    if iszero(eq(calldatasize(), 36)) { revert(0, 0) }
                    if signer { revert(0, 0) }                                         // the member key only
                    if iszero(device) { revert(0, 0) }
                    let st := sload(add(0x20, device))
                    if iszero(and(st, 0x10000)) { revert(0, 0) }
                    sstore(add(0x20, device), and(st, 0xffff))
                    mstore(0x00, device)
                    mstore(0x20, and(st, 0xffff))
                    // DeviceRevoked(uint8 device, uint16 generation)
                    log1(0x00, 0x40, 0x1bac9421a2888ae3c2eebfd9f78a389eec4e60fa0a0455b7145ab5ce03da7ed0)
                }
                default { revert(0, 0) }
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
