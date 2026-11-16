# Quantum exposure check for Safe

How a Safe's owners would stand against an attacker able to derive a private key from its public key. A small TypeScript library on viem, and a static lookup page built on it. It only reads: no wallet, no signature, no server of its own.

No computer able to derive private keys from public keys exists today, and nobody knows when one will. An ECDSA key is open to such an attack only once its public key is known, and its public key becomes known when it signs. The check says, for each owner of a Safe, whether that has happened as far as it can see, and what that means for the Safe's threshold. There is no score and no date: it says what it checked, what it found and what it couldn't check.

## The model

**Each owner** gets one of four classes:

| Class | Owner | Evidence |
|---|---|---|
| **Exposed** (quantum-vulnerable) | A key (no code) that has sent a transaction on this network | its transaction count |
| | A key with a signature that shows its public key on any of this Safe's transactions (executed or queued) or messages at Safe's Transaction Service | the service's `signatureType`: `EOA`, `ETH_SIGN` or `SECP256R1` |
| | A key with an EIP-7702 delegation | signing the delegation showed its public key; the key still signs on its own |
| | Safe's passkey signer (`SafeWebAuthnSignerProxy` of factory v0.2.0 or v0.2.1) | its P-256 public key is in its code |
| | Safe's shared passkey signer (v0.2.1), set up for this Safe | its P-256 public key is in the Safe's storage |
| **Not known to be exposed** (quantum-vulnerable) | A key with no such evidence | none found. It may have signed on another network, for another Safe or off-chain: absence of evidence isn't safety |
| **Hash-based** | A Winterlock owner v2: a 77-byte clone of the pinned implementation at the address the pinned factory gives its member key | `memberKeyOf`, a port of `member_key_of` in `core/src/owner.rs`, tested against the core's vectors |
| **Can't tell** | Any other contract; the shared passkey signer not set up for this Safe; a Safe in a cycle, deeper than the depth limit or past the cap on Safes read; an owner the RPC endpoint didn't answer for | |

**A Safe among the owners** is read in turn, and counts by its own verdict: Exposed as exposed, Exposed as owners sign as not known to be exposed, Protected as hash-based, Can't tell as can't tell.

**The verdict**, for a Safe with threshold t, where V is the quantum-vulnerable owners (exposed or not) and U the ones the check can't classify, in this order:

1. **Can't tell** if the proxy or the singleton isn't one of Safe's official contracts on this network (the owners and threshold may then mean nothing), or the threshold is 0.
2. **Exposed** if at least t owners are exposed: an attacker able to derive private keys could sign for them and move the funds without anyone signing. It stands whether or not modules are enabled.
3. **Exposed as owners sign** if |V| >= t: each signature exposes a key. This too stands with modules.
4. **Protected by hash-based owners** if |V| + |U| < t and no module is enabled: every set of signatures that reaches the threshold includes a hash-based owner.
5. **Can't tell** otherwise: |V| < t <= |V| + |U|, or a module is enabled. Modules are listed, not analysed.

The guard, the module guard (Safe 1.5.0) and the fallback handler are reported as information.

**What would change the verdict** comes with it: how many of the vulnerable or unclassified owners would have to be hash-based for the threshold to be out of their reach ("with 2 of these 3 owners hash-based, the threshold could no longer be reached without a hash-based owner"), the threshold that would do the same with the owners as they are, the modules, and, for a protected Safe, what would undo it.

## What it reads, and its limits

- **The chain**, through one RPC endpoint, all at one block (two behind the latest, so that every node behind a load balancer has it): the Safe's code and singleton (storage slot 0), owners, threshold, nonce, the first 10 modules, guard, module guard and fallback handler slots; each owner's code and transaction count; the passkey signer's configuration and its factory's `getSigner`; the Safe's native balance and its balances of the tokens in `src/lib/chains.ts`. JSON-RPC batches keep this to a few requests.
- **Safe's Transaction Service**, only for a Safe with a key owner that hasn't sent a transaction (the chain settles every other owner): `GET /api/v1/safes/{address}/` (404 for a Safe it doesn't know; the lists below would answer an empty page), then `GET /api/v2/safes/{address}/multisig-transactions/` and `GET /api/v1/safes/{address}/messages/`, at most 5 pages of 200 each, one request every 600 ms.
- **Nesting:** Safes owning the Safe are followed 3 levels deep, 10 Safes in all; a cycle stops at the Safe already on the path.
- **CCIP-Read is off** (EIP-3668): the check makes its own viem client on the caller's endpoint, so a contract it reads can't make it fetch a URL of the contract's choosing.
- **Every limit hit is in the report** (`limits`): pages not read, the service unreachable, rate-limited or without a record of the Safe, Safes not read, modules beyond the first page.
- **Never covered:** what modules, a guard or the fallback handler can do; token approvals; signatures on other networks, for other Safes or off-chain (a key has the same address on every network); whether the signatures the service lists are genuine (it is taken at its word).
- **Not recognised:** Winterlock owner v1 (the earlier Sepolia test Safes' owners count as "can't tell"); Safe4337Module counts as a module like any other.

## The facts it relies on

Checked on 2026-11-16; `test/live.test.ts` re-checks the derived ones.

- **Safe's Transaction Service** (6.14.0 on all six networks): paths, the 200-per-page cap and the `signatureType` values from its source (`safe-global/safe-transaction-service`, `safe-global/safe-eth-py`'s `SafeSignatureType`) and live answers. Reads need no API key and are allowed from any origin; without a key the service allows 2 requests per second (Safe's documentation) and 5,000 per window (its `X-RateLimit-Limit` header). A transaction is returned only if trusted, which every transaction with an owner's signature is.
- **Official Safes:** singleton addresses per network from `safe-global/safe-deployments` (1.0.0 to 1.5.0; 1.0.0 to 1.2.0 only on Ethereum and Gnosis). Proxy code: each official factory's proxy, deployed in an `eth_call` (`proxyCreationCode()` plus the singleton) on Ethereum; for 1.0.0 to 1.3.0 this matches the factory's `proxyRuntimeCode()`, and the factories' code hashes match safe-deployments'.
- **Passkey signers:** factories, singletons and the shared signer from `safe-global/safe-modules-deployments` (`safe-passkey-module` v0.2.0, v0.2.1), the factories' `SINGLETON()` on Ethereum and Sepolia, and the contracts in `@safe-global/safe-passkey`.
- **Networks:** Ethereum (`eth`), Sepolia (`sep`), Base (`base`), Arbitrum One (`arb1`), OP Mainnet (`oeth`) and Gnosis (`gno`). Each service URL answered; each default RPC endpoint answered the right chain ID and JSON-RPC batches, with CORS for any site.
- **Tokens:** USDC and WETH addresses from the board's list (`hardware/board-signer/logic/src/decode.rs`), plus USDC on OP Mainnet from Circle's "USDC contract addresses" page. Gnosis has none: only xDAI is shown.

## The library

`src/lib/`: no DOM and no framework (it type-checks against Node's types alone). The pure part (`model.ts`: classes, verdict, what would change; `winterlock.ts`; `input.ts`; `explain.ts`: the sentences) is separate from the reading (`read.ts`, `service.ts`), and both readers are injectable.

```ts
import { createPublicClient, http } from 'viem'
import { chainByShortName, checkSafe, explain } from './src/lib'

const chain = chainByShortName('sep')!
const report = await checkSafe('0xA5dA2Ab05Cb7EE8D3FBbB486Dee542dcCb5197E6', {
  client: createPublicClient({ transport: http(chain.rpc, { batch: true }) }),
  chainId: chain.id,
  service: { url: chain.service },   // or null; `fetch` can be injected
  tokens: chain.tokens,
})
report.verdict.kind                  // 'protected'
explain.verdictText(report)          // the verdict in sentences
```

## The page

`index.html` and `src/page/`: the form, the route `#/eth:0x...` (shareable: it loads a result directly), and the report. It takes an address with its network, an EIP-3770 address (`eth:0x...`) or a link from Safe's app. The RPC endpoint is set per network and kept in the browser only.

It talks to two servers only, the RPC endpoint and Safe's Transaction Service, and says so next to the form: both see which Safe was looked up. Its Content Security Policy (`vite.config.ts`) allows scripts, styles and fonts from the page itself only, with no inline script or style; `connect-src` is open to `https:` (and localhost) because the RPC endpoint is the reader's choice. It has the landing page's colours and fonts (`../fonts`, with their licences in `dist/fonts/`), light and dark.

```sh
npm install
npm run dev              # http://localhost:5173
npm run build            # type checks, then dist/ (relative paths, for IPFS)
npm test                 # offline: a fake chain and a fake service
npm run test:live        # read-only calls to public endpoints (EXPOSURE_LIVE=1)
npx playwright test      # the built page in headless Chromium; EXPOSURE_LIVE=1 adds live Sepolia lookups
```

The build is about 380 KB: 300 KB of script (95 KB compressed), 52 KB of fonts, 9 KB of style.
