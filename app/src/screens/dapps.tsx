// A Safe's dapps over WalletConnect: paste a dapp's link, approve its session, and confirm or refuse
// its transactions (lib/walletconnect.ts). The bar at the top of every screen says when a dapp is
// waiting.

import { useEffect, useState } from 'preact/hooks'
import type { Address } from 'viem'
import { useApp, useDevice } from '../app'
import { chainById } from '../lib/chains'
import { type DappInfo, txFor } from '../lib/dapp'
import { type DappTxRecord, all } from '../lib/db'
import { execute } from '../lib/flows'
import { decode, tokensOf } from '../lib/safe'
import { type DappDone, type DappProposal, type DappRequest, PROJECT_ID, useWc, wcModule } from '../lib/wc-state'
import { ErrorLine, Explorer, Panel, Progress, Screen, useAction } from '../ui'
import { Describe, useTokens } from './safe'

const same = (a: { chain: number; safe: Address }, chain: number, safe: Address) => a.chain === chain && a.safe.toLowerCase() === safe.toLowerCase()

/** Ticks every second while mounted, for countdowns. */
function useNow(): number {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  return now
}

const clock = (ms: number) => new Date(ms).toLocaleTimeString('en-GB')

function Dapp(props: { d: DappInfo }) {
  return (
    <p data-testid="dapp-claim">
      <strong>{props.d.name}</strong>
      {props.d.url ? (
        <>
          {' '}
          at <code>{props.d.url}</code>
        </>
      ) : (
        ' (no URL)'
      )}{' '}
      <span class="tag amber">not verified</span>
      <br />
      <span class="muted small">As the dapp describes itself: WalletConnect doesn’t prove who is on the other end.</span>
    </p>
  )
}

export function DappsScreen(props: { chain: number; safe: Address }) {
  const app = useApp()
  const wc = useWc()
  const [uri, setUri] = useState('')
  const [given, setGiven] = useState<DappTxRecord[]>([])
  const act = useAction()
  const now = useNow()
  const c = chainById(props.chain)
  const here = (x: { chain: number; safe: Address }) => same(x, props.chain, props.safe)

  useEffect(() => {
    if (PROJECT_ID) wcModule().then((m) => m.start(app.env).catch(() => {}))
  }, [])
  useEffect(() => {
    all<DappTxRecord>(app.env.db, 'dapp').then((rows) => setGiven(rows.filter(here).sort((a, b) => b.at - a.at)))
  }, [wc.done.length, wc.done.filter((d) => d.executed).length])

  async function doPair(e: Event) {
    e.preventDefault()
    const ok = await act.run(async (step) => {
      step('Pairing with the dapp through WalletConnect’s relay')
      await (await wcModule()).pair(uri, { chain: props.chain, safe: props.safe })
      return true
    })
    if (ok) setUri('')
  }

  const pairing = wc.pairing && here(wc.pairing.target) ? wc.pairing : undefined
  const proposals = wc.proposals.filter((p) => !p.target || here(p.target))
  const requests = wc.requests.filter(here)
  const done = wc.done.filter(here)
  const sessions = wc.sessions.filter(here)
  const log = wc.log.filter((e) => !e.safe || (e.chain === props.chain && e.safe.toLowerCase() === props.safe.toLowerCase()))
  return (
    <Screen title="Dapps" back={`/safe/${props.chain}/${props.safe}`} testid="dapps">
      <Panel>
        <p class="small">
          Dapps connect to this Safe on {c.name} through WalletConnect. They see the Safe as their account; each transaction they ask for shows here, and nothing is signed until
          you confirm it.
        </p>
        {!PROJECT_ID && <p class="error">This build of the app has no WalletConnect project ID, so it can’t reach dapps.</p>}
        {wc.status === 'starting' && <p class="muted small">Connecting to WalletConnect’s relay…</p>}
        {wc.status === 'failed' && wc.error && <p class="error">{wc.error}</p>}
      </Panel>
      {PROJECT_ID && (
        <form class="panel" onSubmit={doPair} data-testid="wc-form">
          <h2>Connect a dapp</h2>
          <ol class="steps small">
            <li>In the dapp, connect a wallet and choose WalletConnect.</li>
            <li>Copy its link (Copy link, or the copy icon by the QR code).</li>
            <li>Paste it here.</li>
          </ol>
          <label>
            The dapp’s link
            <input data-testid="wc-uri" autocomplete="off" autocapitalize="none" spellcheck={false} value={uri} onInput={(e) => setUri((e.target as HTMLInputElement).value)} placeholder="wc:…" />
          </label>
          <ErrorLine error={act.error} />
          {act.busy ? (
            <Progress step={act.step} started={act.started} />
          ) : pairing ? (
            <p class="muted small" data-testid="wc-waiting">
              Waiting for the dapp’s proposal…
              {now - pairing.since > 30_000 && ' Nothing yet: the link may be used or expired. Copy a fresh one from the dapp.'}
            </p>
          ) : (
            <button type="submit" data-testid="wc-pair" disabled={!uri.trim()}>
              Connect
            </button>
          )}
        </form>
      )}
      {proposals.map((p) => (
        <ProposalCard key={p.id} p={p} chain={props.chain} safe={props.safe} />
      ))}
      {requests.map((r) => (
        <RequestCard key={r.id} r={r} now={now} />
      ))}
      {done.map((d) => (
        <DoneCard key={d.id} d={d} />
      ))}
      <Panel title="Connected dapps" testid="wc-sessions">
        {sessions.length === 0 && <p class="muted">None.</p>}
        <ul class="list">
          {sessions.map((s) => (
            <SessionRow key={s.topic} topic={s.topic} dapp={s.dapp} expiry={s.expiry} others={s.others} />
          ))}
        </ul>
      </Panel>
      {given.length > 0 && (
        <Panel title="Proposed for dapps" testid="wc-given">
          <ul class="list">
            {given.map((g) => (
              <li key={g.safeTxHash}>
                <a class="item" href={`#/safe/${props.chain}/${props.safe}/tx/${g.safeTxHash}`} data-testid="wc-given-item" data-hash={g.safeTxHash}>
                  <span class="small mono">NONCE {String(g.nonce).padStart(3, '0')}</span>
                  <span class="small">
                    {g.calls === 1 ? 'A transaction' : `A batch of ${g.calls} calls`} for {g.dapp.name}
                    {g.answered ? '' : ' (the dapp didn’t get the answer)'}
                    {g.execution ? (g.execution.success ? ', executed' : ', executed, but its call failed') : ''}
                  </span>
                </a>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {log.length > 0 && (
        <Panel title="Answered by the app" testid="wc-log">
          <ul class="list small">
            {log.map((e, i) => (
              <li key={`${e.at}${i}`} class="item">
                <span class="muted">
                  {clock(e.at)}, {e.dapp}
                </span>
                <span>{e.text}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </Screen>
  )
}

function ProposalCard(props: { p: DappProposal; chain: number; safe: Address }) {
  const dev = useDevice()
  const act = useAction()
  const c = chainById(props.chain)
  async function approve() {
    await act.run(async (step) => {
      step('Connecting the dapp')
      await (await wcModule()).approve(props.p.id, dev, { chain: props.chain, safe: props.safe })
      return true
    })
  }
  async function reject() {
    await act.run(async () => (await wcModule()).reject(props.p.id))
  }
  return (
    <Panel title="A dapp asks to connect" tone="warn" testid="wc-proposal">
      <Dapp d={props.p.dapp} />
      {props.p.dapp.description && <p class="small">{props.p.dapp.description}</p>}
      <p>
        It would see this Safe as its account: <code>{props.safe}</code> on {c.name}.
      </p>
      <ErrorLine error={act.error} />
      {act.busy ? (
        <Progress step={act.step} started={act.started} />
      ) : (
        <div class="actions row">
          <button type="button" data-testid="wc-approve" onClick={approve}>
            Connect
          </button>
          <button type="button" class="secondary" data-testid="wc-reject" onClick={reject}>
            Refuse
          </button>
        </div>
      )}
    </Panel>
  )
}

function RequestCard(props: { r: DappRequest; now: number }) {
  const dev = useDevice()
  const act = useAction()
  const r = props.r
  const { tokens, want } = useTokens(r.chain)
  const decoding = decode(txFor(r.calls, 0n), r.safe)
  useEffect(() => {
    for (const t of tokensOf(decoding.decoded)) want(t)
  }, [r.id])
  const expired = r.expired || (r.expiry !== undefined && props.now >= r.expiry)
  async function confirm() {
    await act.run((step) => wcModule().then((m) => m.confirmRequest(dev, r.id, step)))
  }
  async function refuse() {
    await act.run(async () => (await wcModule()).refuseRequest(r.id))
  }
  const left = r.expiry !== undefined ? Math.max(0, Math.floor((r.expiry - props.now) / 1000)) : undefined
  return (
    <Panel title={r.calls.length === 1 ? 'A dapp asks for a transaction' : `A dapp asks for ${r.calls.length} calls in one transaction`} tone="warn" testid="wc-request">
      <div data-testid="wc-request-body" data-id={r.id} data-method={r.method} data-expired={String(expired)}>
        <Dapp d={r.dapp} />
        <Describe d={decoding.decoded} tokens={tokens} safe={r.safe} />
        {decoding.warnings.length > 0 && (
          <ul class="warnings small">
            {decoding.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        )}
        <p class="muted small">
          From the Safe <code>{r.safe}</code> on {chainById(r.chain).name}, at the Safe’s next free nonce, with no refund fields ({r.method}).
        </p>
        {expired ? (
          <p class="error" data-testid="wc-expired">
            The dapp stopped waiting{r.expiry ? ` at ${clock(r.expiry)}` : ''}: it would no longer get the answer. Dismiss this and ask again from the dapp.
          </p>
        ) : (
          left !== undefined && (
            <p class="small">
              The dapp waits until {clock(r.expiry!)} ({Math.floor(left / 60)}:{String(left % 60).padStart(2, '0')} left). Proposing and the other members’ confirmations may take
              longer: the dapp gets the SafeTx hash once it is proposed.
            </p>
          )
        )}
      </div>
      <ErrorLine error={act.error} />
      {act.busy || r.busy ? (
        <Progress step={act.step} started={act.started} />
      ) : (
        <div class="actions row">
          {!expired && (
            <button type="button" data-testid="wc-confirm" onClick={confirm}>
              Sign and propose
            </button>
          )}
          <button type="button" class="secondary" data-testid="wc-refuse" onClick={refuse}>
            {expired ? 'Dismiss' : 'Refuse'}
          </button>
        </div>
      )}
    </Panel>
  )
}

function DoneCard(props: { d: DappDone }) {
  const app = useApp()
  const dev = useDevice()
  const act = useAction()
  const d = props.d
  const c = chainById(d.chain)
  async function doExecute() {
    await act.run(async (step) => {
      const r = await execute(app.env, dev, d.chain, d.safe, d.hash, step)
      await (await wcModule()).executed(d.hash, r.tx)
      return r
    })
  }
  return (
    <Panel tone="ok" testid="wc-done">
      <p class="okline" data-testid="wc-done-text" data-hash={d.hash} data-answered={String(d.answered)} data-executed={d.executed ?? ''}>
        Proposed for {d.dapp.name} at nonce {d.nonce}, with your confirmation.{' '}
        {d.answered ? 'The dapp got the SafeTx hash.' : 'The dapp’s request had expired, so it didn’t get the answer; the proposal stands.'}
        {d.note ? ` ${d.note}` : ''}
      </p>
      {d.executed ? (
        <p class="okline" data-testid="wc-executed" data-tx={d.executed}>
          Executed: <Explorer base={c.explorer} tx={d.executed} />
        </p>
      ) : d.ready ? (
        <>
          <ErrorLine error={act.error} />
          {act.busy ? (
            <Progress step={act.step} started={act.started} />
          ) : (
            <div class="actions row">
              <button type="button" data-testid="wc-execute" onClick={doExecute}>
                Execute (paid by your gas account)
              </button>
            </div>
          )}
        </>
      ) : (
        <p class="small">The other members confirm it in this app or Safe’s app; once enough have, anyone executes it.</p>
      )}
      <p class="small">
        <a href={`#/safe/${d.chain}/${d.safe}/tx/${d.hash}`}>See it</a>
      </p>
    </Panel>
  )
}

function SessionRow(props: { topic: string; dapp: DappInfo; expiry: number; others: string[] }) {
  const act = useAction()
  async function disconnect() {
    await act.run(async () => (await wcModule()).disconnect(props.topic))
  }
  return (
    <li class="item" data-testid="wc-session" data-topic={props.topic}>
      <Dapp d={props.dapp} />
      <span class="muted small">
        Session until {new Date(props.expiry * 1000).toLocaleString('en-GB')}.
        {props.others.length > 0 && ` The dapp also asked for ${props.others.join(', ')}: the app refuses requests there.`}
      </span>
      <ErrorLine error={act.error} />
      <button type="button" class="secondary" data-testid="wc-disconnect" disabled={act.busy} onClick={disconnect}>
        Disconnect
      </button>
    </li>
  )
}

/** On every screen: a dapp waits for the member (a request, or a session to approve). */
export function DappBar() {
  const wc = useWc()
  const waiting = wc.requests.filter((r) => !r.expired)
  const proposal = wc.proposals.find((p) => p.target)
  const first: { chain: number; safe: Address } | undefined = waiting[0] ?? proposal?.target
  if (!first) return null
  const path = `/safe/${first.chain}/${first.safe}/dapps`
  if (decodeURIComponent(location.hash.replace(/^#/, '')) === path) return null
  const n = waiting.length
  return (
    <a class="dappbar" href={`#${path}`} data-testid="wc-bar">
      {n > 0 ? `A dapp is waiting for you: ${n} request${n === 1 ? '' : 's'}` : 'A dapp asks to connect'}
    </a>
  )
}
