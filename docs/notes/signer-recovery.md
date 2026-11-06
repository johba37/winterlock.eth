# Signer recovery, the seed at rest and moving devices (2026-11-05)

The minimal signer (`signer/`; decisions.md, Measurements, "minimal signer") listed these gaps before real use:
- a recovery phrase with a backup check
- a passphrase on the seed
- moving to another device

This note covers how they are built (`phrase.py`, `seedfile.py`, `device.py`, `move.py`, `cli_recovery.py`), the threat model, and what stays unprotected. It follows the product's intended flows (docs/ux/mvp-proposal.md, 4.1 and 4.9):
- the phrase is the only backup a member must keep
- "move" when the old device still works, with no fee
- "lost" restores with fresh trees, for a fee per network
- "someone may have my phrase" is a member replacement, not a recovery

## Recovery phrase

**24 BIP-39 English words that encode the 32-byte seed itself.** The seed is the phrase's BIP-39 entropy (`to_entropy`): 256 bits plus BIP-39's 8-bit checksum. It is not BIP-39's PBKDF2 seed, and there is no BIP-39 passphrase. Why:
- **The signer's only secret is 32 bytes.** 24 words carry exactly those bits, so a restore decodes rather than derives.
- **Existing signers get a phrase without changing anything.** Signers set up with a hex seed (the live Sepolia ones, for example) have a phrase with the same owner address and stateless key. `init --restore` also still accepts a 64-digit hex backup.
- **No second secret to back up.** A BIP-39 passphrase would be one, and a typo in it yields a different but valid identity, not an error. The passphrase on the seed file protects the device's copy instead.
- **There is precedent.** Cardano's Icarus scheme and substrate-bip39 also derive from the entropy. A wallet that imports these words derives unrelated keys (PBKDF2, then BIP-32), but must never see them: whoever holds the words holds the seed.

Encoding and checksum come from `mnemonic`, the reference implementation that BIP-39 cites. The tests check it against BIP-39's published vectors.

**Backup check.** `init` draws the seed, shows the phrase once, and asks for three words at random positions. There is no skip: a failed or abandoned check saves nothing, so the words written down are simply discarded. On a terminal, the screen and scrollback are cleared afterwards.
- `backup` shows the phrase again and checks it; `backup --check` only checks.
- Each check is recorded in the key log, and `status` shows its date. After 90 days, `status` asks for a new check.
- Typing the phrase for a restore or a move counts as a check.
- Input is forgiving: case, numbering, commas, and four-letter abbreviations, which are unique in the English list. A mistake is named (which word, or "checksum").

## Seed at rest

The `seed` file holds a JSON object:
- **KDF:** scrypt (hashlib, OpenSSL), n = 2^18, r = 8, p = 1. That is the Ethereum keystore's "standard" setting: 256 MiB and about 1.1 s per unlock on the development machine, so every guess at a stolen file costs as much.
- **Encryption:** ChaCha20-Poly1305 (pycryptodome) over the seed. The associated data is the header (KDF parameters, salt, nonce), so a changed parameter fails like a wrong passphrase.
- **Fresh randomness:** every write draws a new salt and nonce.
- **Passphrase:** NFKC-normalised as in BIP-39, at least 8 characters.

**When it is unlocked:** only for commands that sign, certify or export. `status`, `address` and `queue` read the identity from the key log and never ask.
- **Where the passphrase comes from:** a prompt, three tries. For scripts, `WINTERLOCK_PASSPHRASE`, which other processes of the same user can read.
- **Changing it:** `passphrase` changes it. `passphrase --forgot` sets a new one from the phrase and keeps the key log, so a forgotten passphrase costs no fresh trees.
- **Opt-out, for tests only:** `init --insecure-plaintext-seed` writes the old format (plain hex) and shows no phrase. `status` flags plain seed files, legacy ones included.

## Device states

New key-log records:
- **`device`:** a random device id, and how the log came here (init, restore, move-in, adopt, fresh-trees, or upgrade for logs from before). With `"retire": true`, every earlier tree is retired.
- **`backup`:** the phrase was checked.
- **`move-out`:** the device handed its log on.

The states:

| State | Meaning | Signs? |
|---|---|---|
| active | the bound, current copy | yes |
| locked | a move started and didn't finish; or the key log looks like a copy | nothing; the message says what to do |
| moved | handed to another device; the seed file is removed | never again |

A locked or moved key log takes no new records, except device records. WOTS signatures, stateless signatures, new trees and certificates are all refused at the `Member` level, so message signing added later inherits the rule.

**Copy and rollback detection** (offline, `device.py`). An anchor file outside the signer's directory (`$XDG_STATE_HOME/winterlock-signer/anchors`, or `WINTERLOCK_ANCHOR_DIR`) records, per device id:
- **Binding:** the machine (a hash of its machine id) and the key log's inode. A copied directory, or one restored from a backup, has another inode or machine, or no anchor at all.
- **Counter:** the key log's record count and last checksum, updated after every record. A key log shorter than its anchor, or holding another record at that position, was rolled back.

Remedies, which `status` and every refusal name:
- **`move` from the original**, if it still works.
- **`device fresh-trees`:** retires every tree, and `enroll` then certifies fresh ones. Always safe; it costs a fee per Safe and chain.
- **`device adopt`:** trusts the copy as complete and gives it its own device id. Refused when a rollback is detected, since the log provably misses records.

## Moving while the old device works

1. **New device: `move start`.** The member types the phrase and a new passphrase. The signer saves the seed and a move request, then shows its code (16 base32 characters, 80 random bits). The request's location is anchored too.
2. **Old device: `move export --code CODE --out FILE [--chain --rpc]`.**
   - With chain access, it first checks its log against the chain and the Transaction Service (below).
   - It appends a `move-out` record, fsynced. From then on it signs nothing.
   - It writes the bundle, reads it back and decrypts it, then removes its seed file.
3. **New device: `move import FILE [--chain --rpc]`.**
   - It opens the bundle with its seed and its pending request, and checks the log inside.
   - With chain access, it checks the log against the chain and the Transaction Service.
   - It installs the log under a temporary name and renames it into place, then binds it to this device and drops the request.
   - It deletes the bundle file, unless `--keep-bundle`.

**The bundle.** A public header (owner, request code, move id, export time, salt, nonce) and a ciphertext:
- **Encryption:** ChaCha20-Poly1305 under HKDF-SHA256(seed, salt, `winterlock.signer.move-bundle.v1`), with the header as associated data.
- **Contents:** the key log up to and including the `move-out` record. That record commits to the count and keccak hash of every record before it.
- **Who can read or make one:** only a holder of the phrase.
- **No key inside:** tree secrets need both the seed and the salts in the log.

**Online check** (on export and import, per chain):
- For each Safe with a live tree on the chain, it reads the enrolled tree and the Safe's nonce.
- It lists the log's approvals at pending nonces.
- It refuses if the Transaction Service holds a signature by the enrolled tree that the log doesn't record. This is the same rule as the existing per-signature stale-log check.
- An enrolled tree that the log doesn't know is reported: that Safe needs `enroll` before signing there.

| Failure | What happens |
|---|---|
| The same bundle imported on two devices | It opens only on the device whose request it answers. That device consumes the request on import. A request copied with its directory fails its anchor check. |
| Exporting twice | The first export locks the old device. Exporting again for the same code rewrites the same log and move id (the phrase stands in for the removed seed). Another code is refused, unless `--replace-request`, meant only for a new device that never imported and never will. |
| A changed, truncated or mixed-up bundle | Caught by the AEAD tag, each record's checksum, the move-out commitment, and the phrase's identity against the log's. Nothing is installed. |
| An interrupted export | The device stays locked, seed still present, and `status` says to run the export again. Running it again finishes the move. |
| An interrupted import | The request stays until the device record is written. Running the import again finishes it without duplicating records. |
| A stale bundle (a copy of the old log signed after the export) | Not visible offline. The online check refuses it if the copy's signature reached the Transaction Service. |
| A copied or rolled-back key log as the source | Export is refused: it would hand on a possibly stale log. |
| Changing one's mind | `move cancel` on the new device. Then `init --restore --lost`, if the old device turned out to be dead after all. |

## Lost device

`init --restore` asks what happened: the old device still works (a move), it is lost (a restore), or someone else may have the phrase or device. Flags `--move` and `--lost` skip the question.

**Lost:** today's behaviour, explained.
- **Fresh trees:** the key log starts empty, so the old trees are never used.
- **Cost:** a fresh tree per Safe and chain, one `enroll` each, about 0.25M gas (392,088 on Sepolia under Glamsterdam's pricing) and 5.9 KB of calldata.
- **Pending approvals:** the old device's approvals of pending transactions stop counting once the fresh tree is enrolled, and must be given again.
- **If the old device turns up again,** it sees that it was replaced: the Safe holds a newer tree that its key log didn't make. `status` marks its tree REPLACED, `propose` and `confirm` refuse, and `enroll` refuses too, since enrolling there would retire the restored device's tree. `enroll --take-over` overrides that, only for when the other device is gone for good. Each fresh tree starts after the one it replaces, so the two devices never share a key.
- **Message for the team:** the signer prints a short one, including "tell me if you see an approval I didn't make".
- **Report:** with `--chain` and `--rpc`, it lists per Safe the enrolled tree and the pending approvals that will stop counting. Safes are named with `--safe`, or found through the service's owner endpoint.

**Someone else may have the phrase or the device:** nothing is restored. The signer explains the remedy:
1. Tell the team.
2. They swap this member's owner out in a Safe transaction (`swapOwner`).
3. The member makes a new signer with a new phrase.

## Threat model

**Protected against:**
- Accidents that would reuse a one-time key:
  - a copied signer directory
  - a backup of the key log restored on its own
  - importing a bundle twice, or on two devices
  - exporting twice
  - an interrupted move on either side
  - a damaged, changed or mixed-up bundle
- Offline guessing on a stolen seed file, at scrypt's cost per guess. The seed never sits on disk in the clear, unless test mode or a legacy file.
- A moved device keeping its secret: its seed file is removed once the bundle has been verified.

**Assumed:**
- The member keeps the phrase offline.
- The device isn't compromised while the seed is unlocked.

**Not protected:**
- **A whole-machine rollback** (a VM snapshot, a full-disk image) brings back the key log and its anchors together. A rollback of the old device to before its export brings it back unlocked, with its seed. Only the Transaction Service check can catch the second copy, and only:
  - when its signatures were posted there
  - at a nonce that is still pending
  - before the other copy signs

  Peer-to-peer signatures (`--offline` files) are invisible to it. This remains the one way to reuse a key by accident.
- **Copying the new device's whole state** (the pending request and its anchor) before the import.
- **Anyone with the phrase.** They can restore, move or certify trees. The remedy is a member replacement.
- **Malware on an unlocked device.** It can read the seed from memory and sign.
- **`WINTERLOCK_PASSPHRASE`.** It is visible to the same user's processes.
- **Deleted seed files.** SSDs, copy-on-write file systems and backups may keep old blocks of the removed seed file (still encrypted).
- **Anchors are ordinary files.** Deliberate tampering defeats them. File systems without stable inode numbers (FAT, some network file systems) can look like copies, which `device adopt` resolves.
- **The overrides themselves.** `device adopt` and `--replace-request` can reuse keys if used against their warnings.

## Open

- **An encrypted key-log backup** would make restores cheaper (MVP open question). The bundle format could carry it. But a backup restored later is exactly a rollback, so it would need the online check to be mandatory, and it still misses offline signatures.
- **A hardware signer** needs its own derivation: firmware usually exposes BIP-32 nodes, not BIP-39 entropy.

## Tests

84 in all, 46 of them from before.
- `test_phrase.py` (13): BIP-39 vectors, parsing, the seed file, and unlocking.
- `test_device.py` (7): copies, rollbacks, adoption, fresh trees, and logs from before device records.
- `test_move.py` (10): the protocol and each failure mode above.
- `test_cli_recovery.py` (7): the command line with a scripted terminal.
- End to end on anvil (one new step):
  - a move of a member, checked against the chain and the mock Transaction Service
  - the moved device's earlier approval executing without a new tree
  - a simulated VM rollback caught by the export check and the import check
  - the lost-device report, added to the restore step
