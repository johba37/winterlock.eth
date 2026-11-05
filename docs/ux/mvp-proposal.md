# Winterlock for teams: MVP proposal

Draft for design-partner conversations, 2026-11-05. The clickable mockup, `mockup.html`, uses a fictional team and sample figures.

## 1. Who it's for

Teams of three to seven who run a multisig and want off ECDSA before it's urgent:

- **Small protocol treasury, 2-of-3:** founders and an ops lead paying contributors and vendors weekly.
- **DAO working group or grants council, 3-of-5:** members in several time zones, some non-technical.
- **Small fund or foundation, 3-of-5:** fewer, larger transfers; an auditor reads along.

Roles: a **proposer** (daily), **co-signers** (a few approvals a week), a **security lead** (setup, add-ons, recovery), **viewers**.

Jobs to be done: hold funds no single person or ECDSA key can move; pay someone within hours without learning cryptography; see who needs to act; fix a mistake before it goes through; use one address on several networks; sign in and sign permits as the team; survive a lost laptop or member; show stakeholders there's no back door.

## 2. MVP scope

Ethereum Sepolia, Arbitrum Sepolia and Base Sepolia; Kernel v3.3 accounts; the D6 validator.

**The demo shows:** a 2-of-3 team set up on three laptops; a payment proposed, approved and included, with another queued behind it; a cancellation at the same position; the first payment on a new network; the team signing in to an app; key health and a refresh prompt; recovery after a lost laptop; the access check and a dangerous add-on install.

**Out of scope:** hardware and phone signers; upgrading an existing Safe in place (needs Safe7579 or the EIP-1271 owner adapter); on-chain member changes (designed, not built); social or time-delayed recovery; paymasters; notifications beyond email and in-app.

## 3. Five design decisions

1. **Two apps, one hard boundary.** The **team app** (web) shows public data. The **signer** (desktop) holds the phrase and the key log, and decodes every approval itself rather than trusting the web page. A hardware signer can later take its place.
2. **The signer prevents key reuse, not the user.** Nobody picks slots. The signer saves its key log before a signature leaves it and refuses, with an explanation, whatever it can't prove safe.
3. **A restore always starts fresh keys.** A signer restored from the phrase never resumes old single-use keys; it activates new ones with the member's reusable key, for a fee per network. Losing state costs money, never safety, so the phrase is the only backup a member must make.
4. **One mental model: queue positions with an approval key and a spare.** Safe users know the numbered queue. Winterlock adds one rule: at each position, each member can approve once, with one spare for a replacement or cancellation.
5. **One-time costs are announced and ride on real work.** Activation, refresh and recovery show their fee beforehand and travel inside the member's next approval. The quantum-safe premium sits in the fee breakdown, not on every screen.

## 4. Main flows

### 4.1 Team creation and onboarding

1. The creator names the team, invites members by link and sets the threshold. The app suggests 2-of-3 or 3-of-5 and warns that n-of-n locks the team out if one member is lost.
2. Each member installs the signer and opens the invite.
3. The signer creates a 24-word phrase; the member writes it down and confirms three words. No skip.
4. The signer generates **main keys** (64 network activations) and the **reusable key** in seconds. Per-network key sets come on first use.
5. Only public keys go to the team. The member names the device.
6. **The address appears once everyone has joined,** because it is derived from all members' keys. Each signer computes it; members compare it on a call. The invite screen shows who is still missing.
7. The team funds the address on any network. The first payment there deploys the account (4.6).

**Signer state (the key log)** stays on the device and is written before every approval. Members don't manage it as a backup: if it's lost, the phrase restores them with fresh keys (4.9). An encrypted copy that would make restores cheaper is an open question.

### 4.2 Proposing

Network, recipient, asset, amount; or a batch (several payments, one position, one fee); or a WalletConnect request. The review shows the decoded action, the queue position ("Arbitrum #3,341"), fee estimate and cap, and any activation riding along. The proposer approves in their signer at once. Each network has its own queue; #3,342 waits for #3,341.

### 4.3 Co-signing

- The proposal shows "1 of 2" and, per member, the state of their approval key and spare at this position.
- **Review in signer:** decoded action (raw on request), network, position, the key it will use, fee cap, and checks such as "no add-ons, no change to the team". Approving shows three steps: save key log, sign, send.
- **Peer-to-peer:** "Export approval" gives a file or QR code that any member can import and submit.

### 4.4 Submission and status

- At k approvals the team app sends the operation to a relay (auto-send is a team setting). Status runs *Ready → Sent → Included → Done*, or "Waiting for #3,341".
- **No "speed up".** Caps are generous; the account pays only the actual fee. If fees exceed the cap, the app keeps rebroadcasting and offers the **rescue relay**, which covers the difference. Advanced: download the operation and submit it yourself.
- **Approvals don't expire:** "Anyone holding this can submit it until the team cancels it."
- A **gas reserve** per network warns early; some relays refuse underfunded accounts during estimation.

### 4.5 Replace or cancel at the same position

- **Replace** opens the composer at the same position; **Cancel** proposes an empty operation there (small fee). Whichever version is included first wins; the other becomes void.
- A key matrix shows which keys each member has used here. If fewer than k members still have a key, no third version is offered.
- If the original is fully approved, cancelling is a race: the team queue stops handing it out, and the app warns that anyone holding it could still submit it.

### 4.6 First use on a new network

- **Trigger:** proposing on an inactive network, or funds arriving there.
- **Screen:** "Use Ridgeline Grants on Base. Same address." Three steps: each approving member's signer makes a Base key set (~10 s); their main keys sign an introduction valid only for this account, network and member; the first payment carries the introductions and deploys the account.
- **Cost:** account setup plus about 190k gas per approving member, once; later members pay with their first approval there.
- **Details** names the certificate (D10). Main keys: 2 → 3 of 64.

### 4.7 Message signing

- Sign-in and permit requests join a **Messages** list. Members sign with their **reusable key**: no position, no spare, any order; k must sign.
- The signer shows the asking domain, the decoded message, account, network, and validity: "A signed message can't be withdrawn."
- **Permits** show amount, spender and deadline. Above a team limit the app recommends an on-chain approval instead, which can be revoked.
- **Compatibility:** each reusable-key signature is several KB and a few hundred thousand gas to verify (3.7 KB and ~280k gas for D11's candidate). Sign-in checks are free off-chain, but a contract verifying a permit pays that gas and may refuse it.

### 4.8 Key health and refresh

- A key set covers a range of positions ("#0 to #4,095") and **is used up by the team's queue, whether or not a member signs,** so members run out together.
- At 80% the app shows time left ("~750 positions, ~2 months") and plans a staggered refresh, each riding on one member's next approval. At 95%, a banner.
- Main keys show "2 of 64 used", with a warning at 48.
- The team sees when each member last checked their phrase (90-day reminder), never the phrase.

### 4.9 Recovery after losing signer state

On a new device the member enters the phrase; the signer finds the team, then asks what happened:

- **"I still have it."** A move: the old device hands over its key log and locks itself. No fee.
- **"It's lost, broken or wiped."** The signer retires the old key sets for good and creates fresh ones introduced by the reusable key. Re-activation rides on the member's next approval per network (an estimated 350k gas: a few dollars on Ethereum, a cent on L2). The old device's approvals on pending proposals stop counting, so the app lists them to approve again. The team keeps working if k others remain.
- **"Someone else may have my phrase or device."** Not a recovery: the app asks the other members to remove and re-add this member (4.10).

Fresh keys mix in device randomness, so two restores never produce the same keys.

### 4.10 Adding or removing a member (design only)

On-chain this is still open (today: reinstall the module per network). Proposed UX: one "change team" proposal, applied on every active network with per-network status; new members onboard as in 4.1.

**Risk:** on a never-used network the address still deploys with the *original* members, so a removed member keeps a vote there until the team deploys and applies the change. The app must list "networks where the old team still applies".

## 5. Explaining it without jargon

| In the UI | What it is |
|---|---|
| Single-use key | WOTS+ one-time key |
| Queue position #3,341 | Account nonce, per network |
| Approval key, spare key | Slot 0, slot 1 (D4) |
| Key set for Arbitrum | Per-chain operation tree (D10) |
| Main keys (64 activations) | Master tree |
| Activation, refresh | Certificate (enrolment, rotation) |
| Reusable key | Stateless SPHINCS+-family key (D11) |
| Key log | Signer state: used slots and certificates |
| Relay, rescue relay | Bundler, rescue bundler (D5) |
| Team queue | Collection service (D8) |
| Add-on | ERC-7579 module |

Technical names appear only under "Details". Core copy:

- "Each approval uses a fresh single-use key that belongs to one queue position. It can't approve anything else, ever."
- "Your signer remembers which keys it has used. If it ever forgets, it starts fresh keys instead of guessing."
- "A 2-of-3 payment costs about twice a standard multisig: about a cent on Arbitrum, about a dollar more on Ethereum."

## 6. Safety rails

- No key-log write, no signature. One key never signs two things; the spare is used at most once per position; old key sets are refused after a restore.
- One active device per member; a second joins only by a move (the old one locks) or a restore (fresh keys).
- **Add-ons:** installing a module, hook, executor or fallback handler gets a full-screen red review in the signer ("This adds a second way into the treasury that doesn't need the team's approvals"), typing the team name, and a request that every member review it. The **Ways in** card lists every way in on every network; the expected count is one.
- Kernel's chain-agnostic (replayable) signatures are refused.
- A phrase check before the first approval, then every 90 days.

## 7. Information architecture

**Team app (web, read-mostly, works on a phone):** Overview (attention items, holdings, queue, ways in, gas reserve, key health) · Queue (a lane per network, proposal detail, composer) · Messages · Activity · Team and keys · Networks · Settings (relays, team queue, add-ons). Team switcher and network filter on top; sidebar on desktop, a scrolling row on a phone.

**Signer (desktop):** Requests (transactions, messages, activations, add-ons) · Keys and backup · Restore or move · Devices. Its windows have their own dark frame, so members learn to trust only that frame.

## 8. UX risks and open questions

**Risks:**

1. **Stale key logs.** A signer restored from a disk image or VM snapshot looks healthy but has forgotten keys it used: the one way to reuse a key. It should notice a chain or team queue ahead of its log and switch to recovery, but can't catch every case.
2. **Cost perception.** Each extra signer adds ~87k gas, so 2-of-3 is ~2.1–2.3× an ECDSA multisig. Trivial on L2; on Ethereum the first payment costs several dollars more.
3. **Messages are slow and heavy.** A sign-in needing k people can time out; some contracts may reject a signature of several KB.
4. **"Keep your Safe."** The landing page promises upgrading a Safe in place; the MVP creates a new Kernel account, so funds move.
5. **Smaller ones:** member changes aren't built and can drift between networks (4.10); one replacement per position is new to Safe users; no address exists until everyone joins; main keys run out after 64 activations, with no defined next step.

**Open questions:**

- Should a restore trust a write-ahead key-log backup to skip re-activation fees, or always start fresh keys, as proposed?
- D11: will the reusable key sign certificates? This recovery flow assumes it signs re-activation, which also removes the log of used main keys.
- Default key-set size per network: generation time against refresh frequency.
- Signer form: desktop app or browser extension? Browser page storage is evicted too easily.
- Should add-on installs need a higher on-chain threshold than payments?
- Which apps accept ERC-1271 signatures this large, and how should ERC-7739 wrapping look?
