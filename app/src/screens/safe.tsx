// A Safe: joining it (owner address, enrolment), its queue, a transaction, and a new transfer.

import { useEffect, useState } from 'preact/hooks'
import { type Address, getAddress, toHex } from 'viem'
import { short } from '../lib/chain'
import { useApp, useMember } from '../app'
import { link, useLink } from '../board/link'
import { type BoardSafeView, approveHashOf, boardConfirm, boardPropose, boardSafeView } from '../lib/board-flows'
import { BoardTreePanel } from './board'
import { ctxFor, fmtEth } from '../lib/chain'
import { chainById } from '../lib/chains'
import type { Hex } from '../lib/db'
import {
  type Collected,
  type QueueItem,
  type SafeView,
  collect,
  confirm,
  enrol,
  execute,
  parseAddress,
  propose,
  queue,
  safeTxHash,
  safeView,
  service,
  tokenInfo,
} from '../lib/flows'
import { type Decoded, decode, formatUnits, fromService, parseSignature, parseUnits, signatureDevice } from '../lib/safe'
import type { ServiceTx } from '../lib/service'
import { Addr, ErrorLine, Explorer, Panel, Progress, Screen, go, useAction } from '../ui'

function useTokens(chain: number) {
  const app = useApp()
  const [tokens, setTokens] = useState<Record<string, { symbol: string; decimals: number }>>({})
  async function want(token: Address) {
    const k = token.toLowerCase()
    if (tokens[k]) return
    try {
      const info = await tokenInfo(await ctxFor(app.env.db, chain), token)
      setTokens((t) => ({ ...t, [k]: info }))
    } catch {
      /* shown raw */
    }
  }
  return { tokens, want }
}

export function Describe(props: { d: Decoded; tokens: Record<string, { symbol: string; decimals: number }>; safe: Address }) {
  const d = props.d
  if (d.kind === 'cancel') return <p>Cancel: an empty transaction that only uses up this nonce.</p>
  if (d.kind === 'eth')
    return (
      <p data-testid="tx-summary">
        Send <strong>{formatUnits(d.value, 18)} ETH</strong> to <code>{d.to}</code>
      </p>
    )
  if (d.kind === 'erc20') {
    const t = props.tokens[d.token.toLowerCase()]
    return (
      <p data-testid="tx-summary">
        Send <strong>{t ? `${formatUnits(d.amount, t.decimals)} ${t.symbol}` : `${d.amount} units of token ${d.token}`}</strong> to <code>{d.to}</code>
        {t && (
          <span class="muted small">
            {' '}
            (token <code>{d.token}</code>)
          </span>
        )}
      </p>
    )
  }
  if (d.kind === 'approve')
    return (
      <p data-testid="tx-summary">
        <span class="tag amber">approval</span> Approves transaction <code>{d.hash.slice(0, 10)}…</code> of the Safe at <code>{d.to}</code> (approveHash): the board shows that
        transaction before it signs.
      </p>
    )
  if (d.kind === 'self')
    return (
      <p data-testid="tx-summary">
        <span class="tag red">Safe settings</span> The Safe calls itself: <code>{d.what}</code>
      </p>
    )
  return (
    <div data-testid="tx-summary">
      <p>
        <span class="tag red">raw call</span> Calls <code>{d.to}</code>
        {d.value > 0n && <> with {formatUnits(d.value, 18)} ETH</>}, function <code>{d.selector}</code>. The app can’t say what it does.
      </p>
      <details>
        <summary class="small">Raw data ({(d.data.length - 2) / 2} bytes)</summary>
        <code class="small">{d.data}</code>
      </details>
    </div>
  )
}

export function SafeScreen(props: { chain: number; safe: Address }) {
  const app = useApp()
  const member = useMember()
  const board = app.board
  const ls = useLink()
  const unlocked = ls.phase === 'connected' && ls.status?.state === 'unlocked'
  const [view, setView] = useState<SafeView | null>(null)
  const [bview, setBview] = useState<BoardSafeView | null>(null)
  const [items, setItems] = useState<QueueItem[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [k, setK] = useState(0)
  const [done, setDone] = useState<string | null>(null)
  const act = useAction()
  const { tokens, want } = useTokens(props.chain)
  const c = chainById(props.chain)

  useEffect(() => {
    let live = true
    setLoadError(null)
    ;(async () => {
      try {
        let nonce: number
        if (board) {
          const bv = await boardSafeView(app.env, board, props.chain, props.safe, unlocked ? (link.client ?? null) : null)
          if (!live) return
          setBview(bv)
          nonce = bv.state.nonce
        } else {
          const v = await safeView(app.env, app.device!, props.chain, props.safe)
          if (!live) return
          setView(v)
          nonce = v.state.nonce
        }
        const q = await queue(app.env, member, props.chain, props.safe, nonce)
        if (!live) return
        setItems(q)
        for (const it of q) if (it.decoding.decoded.kind === 'erc20') want(it.decoding.decoded.token)
      } catch (e) {
        if (live) setLoadError(short(e))
      }
    })()
    return () => {
      live = false
    }
  }, [k, unlocked])

  async function doEnrol() {
    const r = await act.run((step) => enrol(app.env, app.device!, props.chain, props.safe, step))
    if (r) setDone(`Enrolled a key tree for nonces ${r.tree.start} to ${r.tree.start + 2 ** (r.tree.height - 1) - 1} (${r.gasUsed.toLocaleString()} gas).`)
    setK(k + 1)
  }

  const low = view?.left !== undefined && view.capacity !== undefined && view.left < view.capacity / 5
  const state = view?.state ?? bview?.state
  const isOwner = view?.isOwner ?? bview?.isOwner
  return (
    <Screen title="Safe" back="/" testid="safe">
      <Panel>
        <Addr label={`Safe on ${c.name}`} value={props.safe} testid="safe-address" full />
        {state && (
          <p class="small" data-testid="safe-state">
            {state.threshold} of {state.owners.length} owners, next nonce <code>{state.nonce}</code>, Safe v{state.version}
          </p>
        )}
        {loadError && <p class="error">{loadError}</p>}
      </Panel>
      {state && !isOwner && (
        <Panel title="Ask your team to add you" tone="warn" testid="not-owner">
          <p>Your owner address isn’t an owner of this Safe yet. One of its current owners adds it in Safe’s app:</p>
          <ol class="steps">
            <li>
              Open the Safe in Safe’s app:{' '}
              <a href={`${c.safeApp}/settings/setup?safe=${c.shortName}:${props.safe}`} target="_blank" rel="noreferrer noopener">
                Settings, Setup
              </a>
              .
            </li>
            <li>Add a new owner (Safe’s app calls owners signers): paste your owner address, below, and choose the threshold the team agrees on.</li>
            <li>The Safe’s owners sign and execute that change as usual.</li>
          </ol>
          <Addr value={member.owner} full />
          <button type="button" class="secondary" data-testid="check-again" onClick={() => setK(k + 1)}>
            Check again
          </button>
        </Panel>
      )}
      {bview && <BoardTreePanel view={bview} chain={props.chain} safe={props.safe} onDone={() => setK(k + 1)} />}
      {view && view.device.kind !== 'active' && (
        <Panel title="This device can’t sign here" tone="warn">
          <p>{view.device.text}</p>
          {(view.device.kind === 'pending' || view.device.kind === 'no-owner') && <a href="#/">Send this device’s certificate from the home screen.</a>}
        </Panel>
      )}
      {view && view.device.kind === 'active' && (
        <Panel title="Key tree" tone={view.tree && !low ? 'plain' : 'warn'} testid="tree-panel">
          {view.tree ? (
            <p data-testid="tree-state" data-left={view.left}>
              {view.left} of {view.capacity} nonces left for this device on this Safe (nonces {view.tree.start} to {view.tree.start + view.capacity! - 1}).
              {low && ' Running low: enrol a fresh key tree soon.'}
            </p>
          ) : (
            <p data-testid="tree-state" data-left="0">
              {view.treeProblem ?? 'No key tree yet.'} A key tree gives this device 512 one-time keys for this Safe, two per nonce. Enrolling sends one transaction from your gas account.
            </p>
          )}
          <ErrorLine error={act.error} />
          {done && <p class="okline">{done}</p>}
          {act.busy ? (
            <Progress step={act.step} started={act.started} />
          ) : (
            (!view.tree || low) && (
              <button type="button" data-testid="enrol" onClick={doEnrol}>
                {view.tree ? 'Enrol a fresh key tree' : 'Enrol'}
              </button>
            )
          )}
        </Panel>
      )}
      <Panel title="Waiting for signatures" testid="queue">
        {items === null && !loadError && <p class="muted">Reading Safe’s Transaction Service…</p>}
        {items?.length === 0 && <p class="muted">Nothing pending.</p>}
        <ul class="list">
          {items?.map((it) => (
            <li key={it.hash}>
              <a class="item" href={`#/safe/${props.chain}/${props.safe}/tx/${it.hash}`} data-testid="queue-item" data-hash={it.hash}>
                <span class="small mono">NONCE {String(it.tx.nonce).padStart(3, '0')}</span>
                <Describe d={it.decoding.decoded} tokens={tokens} safe={props.safe} />
                {!it.hashOk && <span class="error">The service’s hash differs from the one computed here: don’t sign.</span>}
                <span class="small">
                  {it.confirmations} of {state?.threshold ?? '?'} signatures{it.mine ? ', including yours' : ''}
                </span>
              </a>
            </li>
          ))}
        </ul>
        <div class="actions row">
          <button type="button" data-testid="new-transfer" disabled={!isOwner} onClick={() => go(`/safe/${props.chain}/${props.safe}/send`)}>
            New transfer
          </button>
          <button type="button" class="secondary" data-testid="refresh" onClick={() => setK(k + 1)}>
            Refresh
          </button>
        </div>
      </Panel>
      <p class="muted small">
        Balances and history: <a href={`${c.safeApp}/home?safe=${c.shortName}:${props.safe}`} target="_blank" rel="noreferrer noopener">Safe’s app</a>.
      </p>
    </Screen>
  )
}

export function TxScreen(props: { chain: number; safe: Address; hash: Hex }) {
  const app = useApp()
  const dev = useMember()
  const board = app.board
  const [rec, setRec] = useState<ServiceTx | null>(null)
  const [hashOk, setHashOk] = useState<boolean | null>(null)
  const [col, setCol] = useState<Collected | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [k, setK] = useState(0)
  const [done, setDone] = useState<{ text: string; tx?: string } | null>(null)
  const act = useAction()
  const { tokens, want } = useTokens(props.chain)
  const c = chainById(props.chain)

  useEffect(() => {
    ;(async () => {
      try {
        const r = await service(props.chain).transaction(props.hash)
        setRec(r)
        const t = fromService(r)
        setHashOk((await safeTxHash(app.env.core, props.chain, props.safe, t)).toLowerCase() === props.hash.toLowerCase())
        const d = decode(t, props.safe).decoded
        if (d.kind === 'erc20') want(d.token)
        setCol(await collect(app.env, props.chain, props.safe, props.hash, r))
      } catch (e) {
        setLoadError(short(e))
      }
    })()
  }, [k])

  async function doConfirm() {
    const r = await act.run((step, signal) =>
      board ? boardConfirm(app.env, board, link.need(), props.chain, props.safe, props.hash, step, { signal }) : confirm(app.env, app.device!, props.chain, props.safe, props.hash, step),
    )
    if (r) setDone({ text: r.note ?? `Confirmed with your ${r.slot === 0 ? 'first' : 'second and last'} one-time key for this nonce${board ? ', on the board' : ''}.` })
    setK(k + 1)
  }
  async function doExecute() {
    const r = await act.run((step) => execute(app.env, dev, props.chain, props.safe, props.hash, step))
    if (r) setDone({ text: `Executed (${r.gasUsed.toLocaleString()} gas).`, tx: r.tx })
    setK(k + 1)
  }

  const t = rec ? fromService(rec) : null
  const decoding = t ? decode(t, props.safe) : null
  const mineValid = col?.sigs.some((s) => s.owner.toLowerCase() === dev.owner.toLowerCase())
  const ready = col && t && col.sigs.length >= col.threshold && Number(t.nonce) === col.nonce
  return (
    <Screen title="Transaction" back={`/safe/${props.chain}/${props.safe}`} testid="tx">
      {loadError && <p class="error">{loadError}</p>}
      {rec && t && decoding && (
        <>
          <Panel>
            <p class="small mono">NONCE {String(t.nonce).padStart(3, '0')}</p>
            <Describe d={decoding.decoded} tokens={tokens} safe={props.safe} />
            {board && t.operation === 1 && <p class="error small">The board refuses delegate calls: it won’t sign this.</p>}
            {board && approveHashOf(t) && <p class="small muted">The app fetches the approved transaction’s fields from Safe’s service and sends them along: the board checks their hash and shows them.</p>}
            {decoding.warnings.length > 0 && (
              <ul class="warnings small">
                {decoding.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            )}
            <dl class="kv small">
              <dt>SafeTx hash</dt>
              <dd>
                <code>{props.hash}</code> {hashOk === true ? <span class="tag green">computed here</span> : hashOk === false ? <span class="tag red">differs</span> : null}
              </dd>
              {rec.proposer && (
                <>
                  <dt>Proposed by</dt>
                  <dd>
                    <code>{rec.proposer}</code>
                  </dd>
                </>
              )}
              {rec.isExecuted && rec.transactionHash && (
                <>
                  <dt>Executed</dt>
                  <dd>
                    <Explorer base={c.explorer} tx={rec.transactionHash} />
                  </dd>
                </>
              )}
            </dl>
          </Panel>
          <Panel title="Signatures" testid="signatures">
            {(rec.confirmations ?? []).length === 0 && <p class="muted">None yet.</p>}
            <ul class="list">
              {[...(rec.confirmations ?? []).map((cf) => ({ owner: cf.owner, signature: cf.signature, held: false })), ...(col?.held ? [{ owner: dev.owner, signature: col.held, held: true }] : [])].map((cf) => {
                let dev_: number | undefined
                let verdict: boolean | undefined
                try {
                  const p = parseSignature(cf.signature!)
                  dev_ = signatureDevice(p.data)
                  verdict = col?.verdicts.get(toHex(p.data).toLowerCase())
                } catch {
                  /* unknown form */
                }
                return (
                  <li key={`${cf.owner}${cf.held}`} class="item small">
                    <code>{cf.owner}</code>
                    <span>
                      {cf.owner.toLowerCase() === dev.owner.toLowerCase() ? 'you' : 'another owner'}
                      {dev_ !== undefined ? (dev_ === 0 ? ', member key' : `, device ${dev_}`) : ''}
                      {cf.held ? ', kept on this device (the service kept an earlier one)' : ''}{' '}
                      {verdict === true ? <span class="tag green">counts</span> : verdict === false ? <span class="tag red">no longer counts</span> : col ? null : '…'}
                    </span>
                  </li>
                )
              })}
            </ul>
            {col && (
              <p data-testid="sig-count" data-valid={col.sigs.length} data-threshold={col.threshold}>
                {col.sigs.length} of {col.threshold} needed
              </p>
            )}
          </Panel>
          {!rec.isExecuted && (
            <Panel>
              <ErrorLine error={act.error} />
              {done && (
                <p class="okline" data-testid="done" data-tx={done.tx}>
                  {done.text} {done.tx && <Explorer base={c.explorer} tx={done.tx} />}
                </p>
              )}
              {act.busy ? (
                <Progress step={act.step} started={act.started} onCancel={board ? act.cancel : undefined} />
              ) : (
                <div class="actions">
                  {!mineValid && hashOk && (
                    <button type="button" data-testid="confirm" onClick={doConfirm}>
                      {board ? 'Confirm on the board' : 'Confirm with this device'}
                    </button>
                  )}
                  {ready && (
                    <button type="button" data-testid="execute" onClick={doExecute}>
                      Execute (paid by your gas account)
                    </button>
                  )}
                  {col && !ready && Number(t.nonce) !== col.nonce && <p class="muted small">The Safe executes nonce {col.nonce} first.</p>}
                </div>
              )}
            </Panel>
          )}
          {rec.isExecuted && done?.tx && (
            <p class="okline" data-testid="done" data-tx={done.tx}>
              {done.text} <Explorer base={c.explorer} tx={done.tx} />
            </p>
          )}
        </>
      )}
    </Screen>
  )
}

export function Send(props: { chain: number; safe: Address }) {
  const app = useApp()
  const board = app.board
  const [asset, setAsset] = useState<'eth' | 'token'>('eth')
  const [token, setToken] = useState('')
  const [info, setInfo] = useState<{ symbol: string; decimals: number } | null>(null)
  const [to, setTo] = useState('')
  const [amount, setAmount] = useState('')
  const [review, setReview] = useState<{ to: Address; amount: bigint; token?: Address } | null>(null)
  const [balance, setBalance] = useState<bigint | null>(null)
  const [done, setDone] = useState<{ text: string; hash: string } | null>(null)
  const act = useAction()

  useEffect(() => {
    ;(async () => {
      try {
        setBalance(await (await ctxFor(app.env.db, props.chain)).client.getBalance({ address: props.safe }))
      } catch {
        /* not shown */
      }
    })()
  }, [])

  useEffect(() => {
    setInfo(null)
    if (asset !== 'token') return
    let t: Address
    try {
      t = parseAddress(token)
    } catch {
      return
    }
    ;(async () => {
      try {
        setInfo(await tokenInfo(await ctxFor(app.env.db, props.chain), t))
      } catch {
        setInfo(null)
      }
    })()
  }, [asset, token])

  function next(e: Event) {
    e.preventDefault()
    act.setError(null)
    try {
      const recipient = parseAddress(to)
      if (asset === 'token') {
        if (!info) throw new Error('That token doesn’t answer as an ERC-20 token on this network.')
        setReview({ to: recipient, amount: parseUnits(amount, info.decimals), token: getAddress(parseAddress(token)) })
      } else {
        setReview({ to: recipient, amount: parseUnits(amount, 18) })
      }
    } catch (err) {
      act.setError(short(err))
    }
  }

  async function sign() {
    const r = await act.run((step, signal) =>
      board ? boardPropose(app.env, board, link.need(), props.chain, props.safe, review!, step, { signal }) : propose(app.env, app.device!, props.chain, props.safe, review!, step),
    )
    if (r) setDone({ text: `Proposed at nonce ${r.nonce} and signed with your ${r.slot === 0 ? 'first' : 'second'} one-time key for it. The other owners confirm it in Safe’s app or this app.`, hash: r.hash })
  }

  return (
    <Screen title="New transfer" back={`/safe/${props.chain}/${props.safe}`} testid="send">
      {!review ? (
        <form class="panel" onSubmit={next}>
          {balance !== null && <p class="small">The Safe holds {fmtEth(balance)} ETH.</p>}
          <label>
            What
            <select data-testid="asset" value={asset} onChange={(e) => setAsset((e.target as HTMLSelectElement).value as 'eth' | 'token')}>
              <option value="eth">ETH</option>
              <option value="token">An ERC-20 token</option>
            </select>
          </label>
          {asset === 'token' && (
            <label>
              Token contract
              <input data-testid="token-input" autocomplete="off" spellcheck={false} value={token} onInput={(e) => setToken((e.target as HTMLInputElement).value)} placeholder="0x…" />
              {info && (
                <span class="muted small">
                  {info.symbol}, {info.decimals} decimals
                </span>
              )}
            </label>
          )}
          <label>
            To
            <input data-testid="to-input" autocomplete="off" spellcheck={false} value={to} onInput={(e) => setTo((e.target as HTMLInputElement).value)} placeholder="0x…" />
          </label>
          <label>
            Amount{asset === 'eth' ? ' in ETH' : info ? ` in ${info.symbol}` : ''}
            <input data-testid="amount-input" inputMode="decimal" autocomplete="off" value={amount} onInput={(e) => setAmount((e.target as HTMLInputElement).value)} placeholder="0.01" />
          </label>
          <ErrorLine error={act.error} />
          <button type="submit" data-testid="review">
            Review
          </button>
        </form>
      ) : (
        <Panel title="Check before you sign">
          <p data-testid="review-summary">
            Send{' '}
            <strong>
              {review.token && info ? `${formatUnits(review.amount, info.decimals)} ${info.symbol}` : `${formatUnits(review.amount, 18)} ETH`}
            </strong>{' '}
            from the Safe to <code>{review.to}</code>
          </p>
          <p class="muted small">
            {board ? 'The board shows it and signs it with a one-time key once you confirm there' : 'This device signs with a one-time key'}, and the app posts the proposal to Safe’s Transaction Service. Nothing moves until enough owners confirm and
            someone executes it.
          </p>
          <ErrorLine error={act.error} />
          {done ? (
            <>
              <p class="okline" data-testid="done" data-hash={done.hash}>
                {done.text}
              </p>
              <button type="button" onClick={() => go(`/safe/${props.chain}/${props.safe}/tx/${done.hash}`)}>
                See it
              </button>
              <button type="button" class="secondary" onClick={() => go(`/safe/${props.chain}/${props.safe}`)}>
                Back to the Safe
              </button>
            </>
          ) : act.busy ? (
            <Progress step={act.step} started={act.started} onCancel={board ? act.cancel : undefined} />
          ) : (
            <div class="actions row">
              <button type="button" data-testid="sign-propose" onClick={sign}>
                {board ? 'Sign on the board and propose' : 'Sign and propose'}
              </button>
              <button type="button" class="secondary" onClick={() => setReview(null)}>
                Change
              </button>
            </div>
          )}
        </Panel>
      )}
    </Screen>
  )
}
