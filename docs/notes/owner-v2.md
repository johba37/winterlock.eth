# The next owner version: design note (proposal, 2026-11-06)

**Status:** a proposal for review. Nothing is built. It changes WinterlockOwner's code, so every owner's address changes. Today that touches only test Safes on Sepolia.

## Why a new version

Two changes each move every owner's address (decisions.md, open questions), so they belong in one version:
1. **Permits for dapps that verify with viem.** viem refuses the empty signature that an on-chain approval answers with (D14).
2. **Several devices per member,** with a way to cut off a lost or stolen device on-chain.

The third candidate, alignment with the draft LeanSPHINCS ERC, has nothing to align with yet: the draft fixes no parameters, encodings or domains.

## The question behind "several devices"

Today every device of a member holds the recovery phrase, which gives the stateless key. That key certifies key trees, so whoever holds any device can certify new trees. **Revoking a device is pointless while the device holds the phrase:** a thief simply certifies again.

So several devices only add safety if everyday devices *don't* hold the phrase. This note proposes exactly that:

- **The member key** is today's stateless key, derived from the recovery phrase. It stays fixed in the member's proxy, and the owner's address follows from it, as now. It certifies and revokes device keys, and it can still sign everything itself. A member with one device works exactly as today.
- **Device keys:** each extra device makes its own leanSphincs-keccak key from its own random seed, with no phrase. The member key certifies it on-chain. From then on, the device key does for that device what the member key does today: it certifies the device's own key trees and signs messages.
- **Device trees:** each device has its own key trees, per Safe and chain, derived from its own seed. Two devices never share a one-time key, even at the same nonce.
- **Revoke:** the member key signs a revocation. Once it's mined, the device key and all its trees stop verifying, including confirmations it already gave for pending transactions.

The phrase can then live offline (paper, or a hardware wallet), while laptops and phones sign with device keys that can be revoked.

| | Member key (from the phrase) | Device key |
|---|---|---|
| Certify or revoke device keys | yes | no |
| Certify its own key trees | yes (device 0) | yes |
| Sign transactions (through its trees) | yes | yes |
| Sign messages | yes | yes |
| If it's lost | restore from the phrase, as today | the member key revokes it |
| If it's stolen | the member is compromised: the team swaps the member's owner, as today | revoke it; a thief can act only until then, and only within the Safe's threshold |

**This also answers the hardware question.** A Nano S+ needs about 1.5–2.5 minutes per leanSphincs-keccak signature (decisions.md, open questions). That's too slow for daily signing, but fine for a member key that only certifies or revokes a device now and then. Daily signing happens on device keys.

## Contract

**Devices.** Device 0 is the member key itself. Devices 1–3 are device keys, so a member has at most four. A small fixed number keeps the storage and the checks simple, and it is enough for laptop, phone and a spare.
- **Record per device** (two storage words): its key (32 bytes); a generation counter and an active flag.
- **`certifyDevice(device, generation, key, signature)`:**
  - the signature is the member key's, over the device certificate below
  - the generation must be the stored one plus one, so an old certificate can't come back
  - certifying a device that is active replaces its old key
- **`revokeDevice(device, generation, signature)`:** the member key's signature over the revocation below. It clears the active flag and keeps the generation.
- **Anyone may send either,** like `enroll` today.

**Trees.** `enroll(safe, device, root, height, start, signature)`:
- **Who signs the certificate:** the device's key, or the member key for device 0.
- **Storage:** one word per Safe and device, as today, plus the device's generation in 16 bits that are free today: root (up to 24 bytes) ‖ generation ‖ start ‖ height.
- **Start nonces only grow,** per Safe and device and within a generation.
- **Validity:** a tree verifies only while its device is active at the same generation.

**One verifier.** Device keys are leanSphincs-keccak keys, checked by the same stateless verifier as the member key, fixed in the implementation. A new stateless scheme needs a new owner version (decision 4).

**Signatures** (byte 0 is the kind; one byte more than today for the device):

| Kind | Layout | Valid when |
|---|---|---|
| Transaction, slot 0 or 1 | `[slot][device][safe: 20][SafeTx: 320][WOTS: 1,176][path: 24 × height]` | as today, under the device's tree; nonce-bound as today |
| Message | `[0x02][device][safe: 20][keccak(message): 32][stateless: 5,684]` | the device's key signed the message digest below |
| **Approved** (new) | `[0x03][safe: 20][keccak(message): 32]` | the hash is that Safe's SafeMessage hash, and `Safe.signedMessages(hash) != 0` |

**The approved kind** fixes permits for viem, as designed in [walletconnect.md](walletconnect.md):
- **How it works:** after the quorum approves a message through SignMessageLib, the signer answers the dapp with k approved signatures, 150 bytes each in Safe's encoding, instead of `0x`. viem accepts them (at least 32 bytes), and the Safe's `checkSignatures` passes through the owners.
- **No key needed:** anyone can build an approved signature, so it is exactly as strong as the empty signature it replaces. What counts is the quorum's approval on-chain.
- **Limits:** a Safe with ECDSA owners still can't use it for them.

**What the keys sign.** The domains move to `v2`. Every digest names the chain and the owner, as today, and now also the device and its generation:

| Digest | Signed by | Fields |
|---|---|---|
| Device certificate | member key | chain, owner, device, generation, key |
| Revocation | member key | chain, owner, device, generation |
| Tree certificate | device key (member key for device 0) | chain, owner, Safe, device, generation, root, height, start |
| Message | device key (member key for device 0) | chain, owner, Safe, device, generation, SafeMessage hash |
| Tree seed (derived, not signed) | — | chain, owner, Safe, device, generation, start |

**Certificates name the chain**, as tree certificates do today. So the member key signs each device once per chain.
- **The alternative,** one chain-free certificate for all chains, saves hardware time. But a revoked device's certificate could then be replayed on a chain the revocation hasn't reached yet, which needs ordering rules across chains.
- **Recommendation:** per chain. It's simpler, and devices are added rarely.

**Not taken: ERC-8403's root over authority leaves.** The open question in decisions.md suggested it. Working it through, a small table fits a Safe owner better:
- **Proofs:** with four entries, a table needs no membership proof in every signature.
- **Rotation:** each device rotates its trees on its own schedule. With one root over all of them, two devices rotating at once would race to write it.
- **Revocation:** a revoke must read current state anyway, which is ERC-8403's tier 2.

ERC-8403's shape suits the EIP-8141 account better, where the account itself holds the key set. The key hierarchy here (member key, device keys, trees) carries over to that account. There, device keys could be EIP-8288-native leanSPHINCS keys.

## Costs (estimates, checked when built)

- **Per signature:** one byte more. For devices 1–3, one more storage read (2.1k gas) for the device record. Device 0 costs no more than today.
- **Approved kind:** about 3k gas per owner, for a storage read in the Safe. That's far cheaper than any signature.
- **Certifying a device:** like an enrolment, a 5.9 KB transaction with one leanSphincs-keccak check. About 0.25M gas under Prague pricing. On Sepolia, with Glamsterdam's surcharge on new storage, about 0.5M (an enrolment there costs 0.39M).
- **Revoking a device:** about 0.2M.
- **The implementation's size is a hard limit.**
  - **Today:** 7.2 KB of code costs 11.4M gas to deploy on Sepolia, and the node's estimate × 1.2 has to stay under the 16.7M transaction cap. That leaves about 8.5–9 KB.
  - **If the new code doesn't fit:** move WOTS verification into a shared verifier contract, like the stateless one. That saves several KB, for a few thousand gas per signature.

## The signer

- **Today's commands stay the same for device 0.**
- **`device new`,** on a new device: makes a seed and a device key, and prints the key with a short check code.
- **`device certify` and `device revoke`,** on whatever holds the phrase: sign the device certificate or revocation and send it (any gas account), for each chain.
- **Each device keeps its own key log** for its own trees. The rules for moves and restores stay as they are.
- **The enroll guard becomes on-chain revocation.** After a restore or a lost device, revoke the old device instead of relying on its signer noticing that it was replaced.
- **Permits:** once the on-chain approval has executed, answer the dapp with the approved signatures instead of `0x`.

## Migration

- **Deploy:** a v2 implementation and factory on Sepolia, about 14M gas, which the deployer's balance covers. The stateless verifier stays as it is.
- **Test Safes:** each member swaps their v1 owner for their v2 owner in a WOTS-signed Safe transaction (`swapOwner`), as in the upgrade in place.
- **v1 stays usable:** the v1 contracts are immutable and keep working, so nothing breaks before the swap.
- **Not in this version:** the Kernel validator for individuals. It can follow with the same model.

## Decisions

Approved on 2026-11-06:
1. **Only the member key comes from the recovery phrase.** Device keys don't hold the phrase.
2. **At most four devices:** the member key plus three.
3. **Device certificates per chain.**
5. **The approved kind (`0x03`)** for permits checked with viem.
6. **A table, not an ERC-8403 root,** in the Safe owner.

Dropped:
4. **A verifier per device.** A shortlist of verifiers can't be enforced on-chain without either a fixed list, which removes the flexibility, or an admin, which adds a trusted party. And a bad verifier is no worse than a bad key, which the member key can certify anyway. The real guard is the pairing check: comparing the device key's check code on both devices before certifying.

The order:
1. the contracts and their tests, including a viem check of a permit against a forked Safe
2. the signer
3. deployment on Sepolia and swapping the test Safes' owners
4. a live run with a real dapp
5. the normative spec, written from this note and the code
