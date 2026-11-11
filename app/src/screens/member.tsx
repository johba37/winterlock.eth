// The member's screens once this browser holds a device: home, joining a Safe, devices and
// revoking, settings.

import { useEffect, useRef, useState } from 'preact/hooks'
import type { Address } from 'viem'
import { short } from '../lib/chain'
import { useApp, useDevice } from '../app'
import { memberSession } from '../core/client'
import { ctxFor, fmtEth, forgetContexts, rpcUrlFor, usableCtx } from '../lib/chain'
import { CHAINS, chainById, enabledChains, safeUrl } from '../lib/chains'
import { type CertRecord, type SafeRecord, certs, putSetting, safes, wipe } from '../lib/db'
import { type DeviceOnChain, addSafe, deviceState, devicesOn, parseAddress, revokeDevice, submitCertificates } from '../lib/flows'
import { persisted } from '../lib/platform'
import { Addr, ErrorLine, Explorer, Panel, Progress, Qr, Screen, go, useAction } from '../ui'

interface ChainStatus {
  chain: number
  name: string
  balance?: bigint
  state?: DeviceOnChain
  cert?: CertRecord
  error?: string
}

function useChainStatus(reloadKey: number) {
  const app = useApp()
  const dev = useDevice()
  const [rows, setRows] = useState<ChainStatus[] | null>(null)
  useEffect(() => {
    let live = true
    ;(async () => {
      const cs = await certs(app.env.db)
      const out: ChainStatus[] = []
      for (const c of enabledChains()) {
        const row: ChainStatus = { chain: c.id, name: c.name, cert: cs.find((x) => x.chain === c.id) }
        try {
          const ctx = await usableCtx(app.env.db, app.env.core, c.id)
          row.balance = await ctx.client.getBalance({ address: dev.gasAddress })
          row.state = await deviceState(app.env, dev, ctx)
        } catch (e) {
          row.error = short(e)
        }
        out.push(row)
      }
      if (live) setRows(out)
    })()
    return () => {
      live = false
    }
  }, [reloadKey, dev.publicKey])
  return rows
}

export function Home() {
  const app = useApp()
  const dev = useDevice()
  const [k, setK] = useState(0)
  const rows = useChainStatus(k)
  const [list, setList] = useState<SafeRecord[]>([])
  const [report, setReport] = useState<string[] | null>(null)
  const act = useAction()
  useEffect(() => {
    safes(app.env.db).then(setList)
  }, [k])

  async function send() {
    const r = await act.run(async (step) => {
      try {
        return await submitCertificates(app.env, dev, step)
      } catch (e) {
        setReport((e as { report?: string[] }).report ?? null)
        throw e
      }
    })
    if (r) setReport(r)
    setK(k + 1)
  }

  const pending = rows?.some((r) => r.state?.kind === 'pending' || (r.state?.kind === 'no-owner' && r.cert?.status === 'pending'))
  return (
    <Screen title="Winterlock" testid="home">
      <Panel title={`Device ${dev.device} of your membership`}>
        <Addr label="Your owner address: the Safe’s owners add this" value={dev.owner} testid="owner-address" full />
      </Panel>
      {rows === null && <p class="muted">Reading the chain…</p>}
      {rows?.map((r) => (
        <Panel key={r.chain} title={r.name} tone={r.state?.kind === 'active' ? 'plain' : 'warn'} testid={`chain-${r.chain}`}>
          {r.error && <p class="error">{r.error}</p>}
          {r.state && (
            <p data-testid="device-state" data-kind={r.state.kind}>
              {r.state.kind === 'active' ? (
                <span class="tag green">active</span>
              ) : r.state.kind === 'pending' || r.state.kind === 'no-owner' ? (
                <span class="tag amber">not sent yet</span>
              ) : (
                <span class="tag red">{r.state.kind}</span>
              )}{' '}
              {r.state.text}
            </p>
          )}
          {r.balance !== undefined && (
            <p class="small">
              Gas account: <span data-testid="gas-balance">{fmtEth(r.balance)}</span> ETH{' '}
              {r.balance < 10n ** 14n && (
                <a href="#/settings" class="small">
                  fund it
                </a>
              )}
            </p>
          )}
        </Panel>
      ))}
      {pending && (
        <Panel title="Send this device’s certificate" tone="warn">
          <p>Your member key certified this device. Sending the certificate makes it count on-chain (and creates your owner contract the first time). It’s paid by your gas account.</p>
          <ErrorLine error={act.error} />
          {act.busy ? (
            <Progress step={act.step} started={act.started} />
          ) : (
            <button type="button" data-testid="send-certificate" onClick={send}>
              Send the certificate
            </button>
          )}
        </Panel>
      )}
      {report && (
        <Panel testid="certificate-report">
          {report.map((l) => (
            <p key={l} class="small">
              {l}
            </p>
          ))}
        </Panel>
      )}
      <Panel title="Your Safes">
        {list.length === 0 && <p class="muted">None yet.</p>}
        <ul class="list">
          {list.map((s) => (
            <li key={`${s.chain}${s.safe}`}>
              <a class="item" href={`#/safe/${s.chain}/${s.safe}`} data-testid="safe-link">
                <code>{s.safe}</code>
                <span class="muted small">{chainById(s.chain).name}</span>
              </a>
            </li>
          ))}
        </ul>
        <div class="actions">
          <button type="button" class="secondary" data-testid="go-join" onClick={() => go('/join')}>
            Join a Safe
          </button>
        </div>
      </Panel>
      <nav class="nav">
        <a href="#/devices" data-testid="go-devices">
          Devices
        </a>
        <a href="#/settings" data-testid="go-settings">
          Settings
        </a>
      </nav>
    </Screen>
  )
}

export function Join() {
  const app = useApp()
  const [chain, setChain] = useState(enabledChains()[0].id)
  const [text, setText] = useState('')
  const act = useAction()
  async function submit(e: Event) {
    e.preventDefault()
    const r = await act.run(async (step) => {
      const safe = parseAddress(text)
      step('Reading the Safe')
      await addSafe(app.env, chain, safe)
      return safe
    })
    if (r) go(`/safe/${chain}/${r}`)
  }
  return (
    <Screen title="Join a Safe" back="/" testid="join">
      <form class="panel" onSubmit={submit}>
        <p>Your team’s Safe already exists: the app doesn’t create Safes. Enter its address.</p>
        <label>
          Network
          <select value={chain} onChange={(e) => setChain(Number((e.target as HTMLSelectElement).value))}>
            {CHAINS.map((c) => (
              <option key={c.id} value={c.id} disabled={!c.enabled}>
                {c.name}
                {c.enabled ? '' : ' (not yet)'}
              </option>
            ))}
          </select>
        </label>
        <label>
          Safe address
          <input data-testid="safe-input" autocomplete="off" autocapitalize="none" spellcheck={false} value={text} onInput={(e) => setText((e.target as HTMLInputElement).value)} placeholder="0x… or sep:0x…" />
        </label>
        <ErrorLine error={act.error} />
        {act.busy ? (
          <Progress step={act.step} started={act.started} />
        ) : (
          <button type="submit" data-testid="join-submit" disabled={!text.trim()}>
            Continue
          </button>
        )}
      </form>
    </Screen>
  )
}

export function Settings() {
  const app = useApp()
  const dev = app.device ?? app.board
  const [k, setK] = useState(0)
  const [urls, setUrls] = useState<Record<number, string>>({})
  const [editing, setEditing] = useState<number | null>(null)
  const [draft, setDraft] = useState('')
  const [stored, setStored] = useState<boolean | undefined>()
  const [balances, setBalances] = useState<Record<number, bigint | string>>({})
  const act = useAction()

  useEffect(() => {
    ;(async () => {
      const u: Record<number, string> = {}
      for (const c of CHAINS) u[c.id] = await rpcUrlFor(app.env.db, c.id)
      setUrls(u)
      setStored(await persisted())
      if (dev) {
        const b: Record<number, bigint | string> = {}
        for (const c of enabledChains()) {
          try {
            b[c.id] = await (await ctxFor(app.env.db, c.id)).client.getBalance({ address: dev.gasAddress })
          } catch (e) {
            b[c.id] = short(e)
          }
        }
        setBalances(b)
      }
    })()
  }, [k])

  async function save(chainId: number, value: string | null) {
    const r = await act.run(async (step) => {
      if (value !== null) {
        const u = new URL(value.trim())
        if (u.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(u.hostname)) throw new Error('Use an https:// URL.')
      }
      await putSetting(app.env.db, `rpc:${chainId}`, value?.trim() ?? null)
      forgetContexts()
      step('Checking the RPC')
      await ctxFor(app.env.db, chainId)
      return true
    })
    if (r) {
      setEditing(null)
      setDraft('')
      setK(k + 1)
    }
  }

  return (
    <Screen title="Settings" back="/" testid="settings">
      {dev && (
        <Panel title="Gas account" testid="gas-panel">
          <p class="small">
            An ordinary account that pays for your transactions: your owner contract, certificates, key trees and executions.{' '}
            {app.board ? 'The board derives its key from your seed and gave it to this app.' : 'Every device you pair from your phrase holds it.'} It isn’t an owner of any Safe.
          </p>
          <Addr value={dev.gasAddress} testid="gas-address" full />
          {enabledChains().map((c) => (
            <p key={c.id} class="small">
              {c.name}: <span data-testid={`gas-balance-${c.id}`}>{typeof balances[c.id] === 'bigint' ? `${fmtEth(balances[c.id] as bigint)} ETH` : (balances[c.id] ?? '…')}</span>
            </p>
          ))}
          <Qr text={`ethereum:${dev.gasAddress}@${enabledChains()[0].id}`} size={180} />
          <p class="muted small">Send a little {enabledChains()[0].name} ETH here. A few transactions cost well under 0.001 ETH on Sepolia.</p>
        </Panel>
      )}
      <Panel title="Networks">
        {CHAINS.map((c) => (
          <div key={c.id} class="kv" data-testid={`rpc-${c.id}`}>
            <dt>{c.name}</dt>
            <dd>
              {c.enabled ? <span class="tag green">on</span> : <span class="tag">off for now</span>}{' '}
              <span class="small">
                RPC <code data-testid={`rpc-host-${c.id}`}>{urls[c.id] ? safeUrl(urls[c.id]) : '…'}</code>
              </span>{' '}
              {editing === c.id ? null : (
                <button type="button" class="link" data-testid={`rpc-edit-${c.id}`} onClick={() => setEditing(c.id)}>
                  Change
                </button>
              )}
              {editing === c.id && (
                <form
                  class="actions"
                  onSubmit={(e) => {
                    e.preventDefault()
                    save(c.id, draft)
                  }}
                >
                  <input type="url" data-testid={`rpc-input-${c.id}`} autocomplete="off" value={draft} onInput={(e) => setDraft((e.target as HTMLInputElement).value)} placeholder="https://…" />
                  <div class="actions row">
                    <button type="submit" data-testid={`rpc-save-${c.id}`}>
                      Save
                    </button>
                    <button type="button" class="secondary" onClick={() => save(c.id, null)}>
                      Use the public default
                    </button>
                  </div>
                </form>
              )}
            </dd>
          </div>
        ))}
        <p class="muted small">An RPC URL may hold an API key: the app shows only its host. Safe’s Transaction Service: api.safe.global.</p>
        <ErrorLine error={act.error} />
        <Progress step={act.step} />
      </Panel>
      <Panel title="This browser">
        <p class="small">
          Storage: {stored === true ? 'kept (persistent)' : stored === false ? 'not marked persistent: the browser may delete it under pressure' : 'unknown'}
        </p>
        {app.device && (
          <p class="small">
            <a href="#/devices">Devices</a>
          </p>
        )}
        {app.board && (
          <p class="small">
            <a href="#/board">Board</a>
          </p>
        )}
      </Panel>
    </Screen>
  )
}

export function Devices() {
  const app = useApp()
  const dev = useDevice()
  const [rows, setRows] = useState<Record<number, { device: number; key: string; generation: number; active: boolean }[] | null | string>>({})
  const [confirmForget, setConfirmForget] = useState(false)
  useEffect(() => {
    ;(async () => {
      const out: typeof rows = {}
      for (const c of enabledChains()) {
        try {
          out[c.id] = await devicesOn(app.env, dev, await usableCtx(app.env.db, app.env.core, c.id))
        } catch (e) {
          out[c.id] = short(e)
        }
      }
      setRows(out)
    })()
  }, [])

  return (
    <Screen title="Devices" back="/" testid="devices">
      <p class="small">
        Device 0 is your member key: it exists only while you type your phrase. Devices 1 to 3 are keys of your browsers and phones. This one is device <strong>{dev.device}</strong>.
      </p>
      {enabledChains().map((c) => {
        const r = rows[c.id]
        return (
          <Panel key={c.id} title={c.name}>
            {r === undefined && <p class="muted">Reading…</p>}
            {typeof r === 'string' && <p class="error">{r}</p>}
            {r === null && <p class="muted">Your owner contract doesn’t exist here yet.</p>}
            {Array.isArray(r) && (
              <ul class="list">
                {r.map((d) => (
                  <li key={d.device} class="item" data-testid={`device-row-${d.device}`} data-active={String(d.active)}>
                    <span>
                      <strong>Device {d.device}</strong>
                      {d.device === dev.device && d.key.toLowerCase() === dev.publicKey.toLowerCase() ? ' (this one)' : ''}{' '}
                      {d.generation === 0 ? <span class="tag">never used</span> : d.active ? <span class="tag green">active</span> : <span class="tag red">revoked</span>}
                    </span>
                    {d.generation > 0 && (
                      <span class="muted small">
                        generation {d.generation}, key <code>{d.key.slice(0, 12)}…</code>
                      </span>
                    )}
                    {d.active && (
                      <button type="button" class="secondary" data-testid={`revoke-${d.device}`} onClick={() => go(`/revoke/${d.device}`)}>
                        Revoke device {d.device}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        )
      })}
      <Panel title="Forget this device" tone="warn">
        <p class="small">Deletes this device’s key, key log and gas key from this browser. Revoke it first if it was certified: forgetting doesn’t revoke. You can pair this browser again with your phrase.</p>
        {confirmForget ? (
          <div class="actions row">
            <button
              type="button"
              class="danger"
              data-testid="forget-confirm"
              onClick={async () => {
                await wipe(app.env.db)
                await app.reload()
                go('/')
              }}
            >
              Delete it from this browser
            </button>
            <button type="button" class="secondary" onClick={() => setConfirmForget(false)}>
              Keep it
            </button>
          </div>
        ) : (
          <button type="button" class="secondary" data-testid="forget" onClick={() => setConfirmForget(true)}>
            Forget this device
          </button>
        )}
      </Panel>
    </Screen>
  )
}

export function Revoke(props: { target: number }) {
  const app = useApp()
  const dev = useDevice()
  const [text, setText] = useState('')
  const [report, setReport] = useState<string[] | null>(null)
  const area = useRef<HTMLTextAreaElement>(null)
  const act = useAction()
  const self = props.target === dev.device

  async function submit(e: Event) {
    e.preventDefault()
    const typed = text
    const r = await act.run(async (step) => {
      const s = memberSession()
      try {
        step('Reading your phrase')
        await s.call('fromPhrase', { text: typed })
      } catch (err) {
        s.end()
        throw err
      }
      setText('')
      if (area.current) area.current.value = ''
      return revokeDevice(app.env, dev, s, props.target, step)
    })
    if (r) setReport(r)
  }

  return (
    <Screen title={`Revoke device ${props.target}`} back="/devices" testid="revoke">
      {report ? (
        <Panel tone="ok" testid="revoke-report">
          {report.map((l) => (
            <p key={l} class="small">
              {l}
            </p>
          ))}
          <p class="small">Everything device {props.target} signed stops counting, including its confirmations of transactions not yet executed: confirm those again from another device.</p>
          <button type="button" onClick={() => go('/devices')}>
            Done
          </button>
        </Panel>
      ) : (
        <form class="panel" onSubmit={submit}>
          {self && <p class="error">This is the device you are using. Once revoked, it signs nothing.</p>}
          <p>Your member key signs the revocation, so type your 24 words. The app forgets them once it has signed.</p>
          <label>
            Recovery phrase
            <textarea ref={area} data-testid="phrase-input" autocomplete="off" autocapitalize="none" spellcheck={false} value={text} disabled={act.busy} onInput={(e) => setText((e.target as HTMLTextAreaElement).value)} />
          </label>
          <ErrorLine error={act.error} />
          {act.busy ? (
            <Progress step={act.step} started={act.started} />
          ) : (
            <button type="submit" class="danger" data-testid="revoke-submit" disabled={!text.trim()}>
              Revoke device {props.target}
            </button>
          )}
        </form>
      )}
    </Screen>
  )
}

export function ExplorerTx(props: { chain: number; tx: string }) {
  return <Explorer base={chainById(props.chain).explorer} tx={props.tx} />
}

export type { Address }
