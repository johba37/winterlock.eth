// The screens with a board (docs/notes/signer-app.md, decision 7): connecting one (USB or the
// virtual board), setting it up or recovering it on the board, the board's bar and the virtual
// board's screen and buttons, the member's home, the board's details, and a Safe's key tree.

import { useEffect, useRef, useState } from 'preact/hooks'
import type { Address } from 'viem'
import { useApp, useBoard } from '../app'
import type { BoardTree } from '../board/client'
import { type LinkState, link, useLink } from '../board/link'
import { choosePort, serialSupported } from '../board/serial'
import { BOTH, LEFT, RIGHT } from '../board/runner'
import type { Screen as OledScreen, VirtualTransport } from '../board/virtual'
import { type BoardSafeView, adoptBoard, boardEnrol, boardMismatch, recoverBoard, setupBoard } from '../lib/board-flows'
import { fmtEth, short, usableCtx, ownerDeployed } from '../lib/chain'
import { chainById, enabledChains } from '../lib/chains'
import { type BoardRecord, type SafeRecord, safes, wipe } from '../lib/db'
import { forgetWc } from '../lib/wc-state'
import { mayHoldKeys, persist } from '../lib/platform'
import { Addr, ErrorLine, Panel, Progress, Screen, go, useAction } from '../ui'

// --- the virtual board: its screen and buttons ---

const AMBER = [255, 196, 64]
const ICE = [176, 226, 255]

/** The 128x64 frame (one bit a pixel, row-major), drawn as the two-colour OLED modules show it:
 * the top 16 rows yellow, the rest blue-white. */
function Oled(props: { screen: OledScreen | null }) {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const c = ref.current
    const g = c?.getContext('2d')
    if (!c || !g) return
    const img = g.createImageData(128, 64)
    const px = props.screen?.pixels
    for (let y = 0; y < 64; y++) {
      for (let x = 0; x < 128; x++) {
        const on = px ? (px[y * 16 + (x >> 3)] & (0x80 >> (x & 7))) !== 0 : false
        const i = 4 * (y * 128 + x)
        const col = y < 16 ? AMBER : ICE
        img.data[i] = on ? col[0] : 6
        img.data[i + 1] = on ? col[1] : 8
        img.data[i + 2] = on ? col[2] : 10
        img.data[i + 3] = 255
      }
    }
    g.putImageData(img, 0, 0)
  }, [props.screen])
  return (
    <canvas
      ref={ref}
      class="oled"
      width={128}
      height={64}
      role="img"
      aria-label={props.screen?.text.replace(/\n/g, ' / ') ?? 'the board’s screen, off'}
      data-testid="oled"
      data-text={props.screen?.text ?? ''}
      data-seq={props.screen?.seq ?? 0}
    />
  )
}

function typing(e: KeyboardEvent): boolean {
  const t = e.target as HTMLElement | null
  return !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)
}

function VirtualBoardPanel(props: { t: VirtualTransport }) {
  const [screen, setScreen] = useState<OledScreen | null>(props.t.screen)
  const [busy, setBusy] = useState(false)
  useEffect(() => props.t.onScreen(setScreen), [props.t])
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (typing(e) || e.altKey || e.ctrlKey || e.metaKey) return
      const ev = e.key === 'ArrowLeft' ? LEFT : e.key === 'ArrowRight' ? RIGHT : e.key === 'ArrowDown' || e.key === 'b' ? BOTH : 0
      if (!ev) return
      e.preventDefault()
      props.t.button(ev as 1 | 2 | 3)
    }
    addEventListener('keydown', on)
    return () => removeEventListener('keydown', on)
  }, [props.t])
  return (
    <div class="vboard" data-testid="virtual-board">
      <p class="vboard-label">
        <strong>Development board.</strong> Its keys live in this browser.
      </p>
      <Oled screen={screen} />
      <div class="vboard-buttons">
        <button type="button" class="secondary" data-testid="vb-left" onClick={() => props.t.button(LEFT)} title="Left (←): back, no">
          ◀ Left
        </button>
        <button type="button" class="secondary" data-testid="vb-both" onClick={() => props.t.button(BOTH)} title="Both held (↓ or B): confirm">
          Both
        </button>
        <button type="button" class="secondary" data-testid="vb-right" onClick={() => props.t.button(RIGHT)} title="Right (→): next, yes">
          Right ▶
        </button>
      </div>
      <p class="muted small">
        Keys: ← and → for the buttons, ↓ or B for both held.{' '}
        <button
          type="button"
          class="link"
          data-testid="vb-restart"
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            try {
              await props.t.restart()
            } finally {
              setBusy(false)
            }
          }}
        >
          Restart it
        </button>
      </p>
    </div>
  )
}

// --- the board's bar ---

export function linkLine(s: LinkState): { text: string; tone: 'ok' | 'warn' | 'plain' } {
  if (s.phase === 'none') return { text: 'No board connected.', tone: 'warn' }
  if (s.phase === 'connecting') return { text: 'Connecting to the board…', tone: 'plain' }
  if (s.phase === 'disconnected') return { text: `The board is disconnected: ${s.why}`, tone: 'warn' }
  const st = s.status
  if (!st) return { text: `${s.label}: connected.`, tone: 'plain' }
  if (st.state === 'locked') return { text: 'The board is locked: enter your PIN on the board.', tone: 'warn' }
  if (st.state === 'blank') return { text: 'The board is blank: set it up or recover it.', tone: 'warn' }
  if (st.state === 'damaged') return { text: 'The board’s storage is damaged: erase it from its menu.', tone: 'warn' }
  return { text: `Board unlocked: ${s.label}.`, tone: 'ok' }
}

async function connect(kind: 'serial' | 'virtual', all = false) {
  if (kind === 'virtual') return link.connectVirtual()
  if (await link.connectGranted().catch(() => false)) return
  const port = await choosePort(all)
  await link.connectSerial(port)
}

/** On every screen while the app uses a board: the link, and the virtual board itself. */
export function BoardDock() {
  const app = useApp()
  const s = useLink()
  const rec = app.board
  const [err, setErr] = useState<string | null>(null)
  const [open, setOpen] = useState(true)
  const vt = s.phase === 'connected' || s.phase === 'connecting' ? link.virtual : undefined
  const line = linkLine(s)
  const mismatch = rec && s.phase === 'connected' && s.status && s.status.state !== 'locked' ? boardMismatch(rec, s.status) : null
  const kind = rec?.link ?? (s.phase !== 'none' ? s.kind : 'serial')
  return (
    <aside class={`dock ${vt ? 'with-board' : ''} ${open ? '' : 'closed'}`} data-testid="board-dock">
      <div class={`dock-bar ${line.tone}`}>
        <span data-testid="link-state" data-phase={s.phase} data-state={s.phase === 'connected' ? (s.status?.state ?? '') : ''}>
          {mismatch ?? line.text}
        </span>
        {(s.phase === 'none' || s.phase === 'disconnected') && rec && kind === 'virtual' && !__VIRTUAL_BOARD__ && (
          <span class="small" data-testid="virtual-missing">
            {' '}
            This browser’s board is the virtual one, which only development builds of the app have.
          </span>
        )}
        {(s.phase === 'none' || s.phase === 'disconnected') && rec && (kind !== 'virtual' || __VIRTUAL_BOARD__) && (
          <button
            type="button"
            class="link"
            data-testid="connect-board"
            onClick={async () => {
              setErr(null)
              try {
                await connect(kind)
              } catch (e) {
                setErr(short(e))
              }
            }}
          >
            {kind === 'virtual' ? 'Start the virtual board' : 'Connect'}
          </button>
        )}
        {vt && (
          <button type="button" class="link" onClick={() => setOpen(!open)}>
            {open ? 'Hide' : 'Show the board'}
          </button>
        )}
      </div>
      {err && <p class="error small">{err}</p>}
      {vt && open && <VirtualBoardPanel t={vt} />}
    </aside>
  )
}

// --- onboarding with a board ---

export function BoardStart() {
  const app = useApp()
  const s = useLink()
  const [all, setAll] = useState(false)
  const [done, setDone] = useState<BoardRecord | null>(null)
  const act = useAction()
  const kind = s.phase === 'none' ? null : s.kind
  const st = s.phase === 'connected' ? s.status : null

  async function connectTo(k: 'serial' | 'virtual') {
    await persist()
    await act.run(async () => {
      if (k === 'virtual') await link.connectVirtual()
      else await link.connectSerial(await choosePort(all))
    })
  }

  async function run(what: 'setup' | 'recover' | 'adopt') {
    const r = await act.run(async (step, signal) => {
      const c = link.need()
      if (what === 'setup') {
        step(
          'Follow the board. It shows 24 words, four a page: write them on paper, in order. Then it asks for three of them, and for a PIN of 4 to 8 digits, twice. Then it makes your member key (about 12 s on the board)',
        )
        return setupBoard(app.env, c, kind!, { signal })
      }
      if (what === 'recover') {
        step('Follow the board. Enter your 24 words on it, letter by letter (four letters pick a word), then a new PIN twice. Then it makes your member key (about 12 s)')
        return recoverBoard(app.env, c, kind!, { signal })
      }
      step('Reading the board')
      return adoptBoard(app.env, c, kind!, 'existing')
    })
    if (r) setDone(r)
    await link.refresh()
  }

  if (done)
    return (
      <Screen title="Your board is ready" testid="board-done">
        <Panel tone="ok">
          <p class="okline">The board holds your member key. It signs every enrolment and confirmation after showing it to you.</p>
          <Addr label="Your owner address: check that the board shows the same" value={done.owner} testid="owner-address" full />
          <p class="small">The app holds only your gas account’s key, which the board gave it. Fund the gas account (Settings) to pay for your transactions.</p>
        </Panel>
        <div class="actions">
          <button
            type="button"
            data-testid="done-home"
            onClick={async () => {
              await app.reload()
              go('/')
            }}
          >
            Continue
          </button>
        </div>
      </Screen>
    )

  return (
    <Screen title="Use a board" back="/" testid="board-start">
      {s.phase !== 'connected' && (
        <>
          <Panel>
            <p>
              The board is a small device with a screen and two buttons. It makes and keeps your member key, asks for its PIN at every start, and shows you every transaction before it signs. Connect it by
              USB, in Chrome or Edge on a computer.
            </p>
          </Panel>
          {!mayHoldKeys() && <p class="error">On iPhone and iPad no browser can reach a board.</p>}
          <div class="actions">
            <button type="button" data-testid="connect-usb" disabled={!serialSupported() || act.busy} onClick={() => connectTo('serial')}>
              Connect a board by USB
            </button>
            {!serialSupported() && <p class="muted small">This browser has no Web Serial: use Chrome or Edge on a computer.</p>}
            <label class="small row-label">
              <input type="checkbox" checked={all} onChange={(e) => setAll((e.target as HTMLInputElement).checked)} /> Show all serial ports (if your board’s USB chip isn’t listed)
            </label>
            {__VIRTUAL_BOARD__ && (
              <>
                <button type="button" class="secondary" data-testid="connect-virtual" disabled={act.busy || !mayHoldKeys()} onClick={() => connectTo('virtual')}>
                  Use the virtual board (development)
                </button>
                <p class="muted small">The virtual board runs the board’s own code in this browser, for development and tests. Its keys live in this browser: it is not a signer.</p>
              </>
            )}
          </div>
        </>
      )}
      {s.phase === 'connected' && st && (
        <Panel title={st.state === 'blank' ? 'A new or erased board' : st.state === 'locked' ? 'Unlock the board' : st.state === 'damaged' ? 'The board’s storage is damaged' : 'A board that is set up'} testid="board-state" tone={st.state === 'damaged' ? 'warn' : 'plain'}>
          {st.state === 'blank' && <p>Set it up to make a new member key, or recover your member key on it from your 24 words.</p>}
          {st.state === 'locked' && <p data-testid="enter-pin">Enter your PIN on the board: left and right change the digit, both held take it.</p>}
          {st.state === 'damaged' && <p>It signs nothing. Erase it from its menu (hold both buttons), then recover it from your 24 words.</p>}
          {st.state === 'unlocked' && st.owner && <Addr label="Its owner address" value={st.owner} full />}
          <ErrorLine error={act.error} />
          {act.busy ? (
            <Progress step={act.step} started={act.started} onCancel={act.cancel} />
          ) : (
            <div class="actions">
              {st.state === 'blank' && (
                <>
                  <button type="button" data-testid="board-setup" onClick={() => run('setup')}>
                    Set up this board
                  </button>
                  <button type="button" class="secondary" data-testid="board-recover" onClick={() => run('recover')}>
                    Recover it from my 24 words
                  </button>
                </>
              )}
              {st.state === 'unlocked' && (
                <button type="button" data-testid="board-adopt" onClick={() => run('adopt')}>
                  Use this board
                </button>
              )}
            </div>
          )}
        </Panel>
      )}
      {s.phase !== 'connected' && <ErrorLine error={act.error} />}
    </Screen>
  )
}

// --- home ---

interface ChainRow {
  chain: number
  name: string
  balance?: bigint
  deployed?: boolean
  error?: string
}

export function BoardHome() {
  const app = useApp()
  const rec = useBoard()
  const s = useLink()
  const [rows, setRows] = useState<ChainRow[] | null>(null)
  const [list, setList] = useState<SafeRecord[]>([])
  useEffect(() => {
    safes(app.env.db).then(setList)
    let live = true
    ;(async () => {
      const out: ChainRow[] = []
      for (const c of enabledChains()) {
        const row: ChainRow = { chain: c.id, name: c.name }
        try {
          const ctx = await usableCtx(app.env.db, app.env.core, c.id)
          row.balance = await ctx.client.getBalance({ address: rec.gasAddress })
          row.deployed = await ownerDeployed(ctx, app.env.core, rec.owner, rec.memberKey)
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
  }, [rec.owner])
  const st = s.phase === 'connected' ? s.status : null
  return (
    <Screen title="Winterlock" testid="home">
      <Panel title="Your board">
        <Addr label="Your owner address: the Safe’s owners add this" value={rec.owner} testid="owner-address" full />
        <p class="small muted">Your member key is on the board{rec.link === 'virtual' ? ' (the virtual board in this browser)' : ''}. It signs every enrolment and confirmation after showing it.</p>
        {st?.state === 'locked' && (
          <p class="small" data-testid="enter-pin">
            <span class="tag amber">locked</span> Enter your PIN on the board.
          </p>
        )}
      </Panel>
      {rows === null && <p class="muted">Reading the chain…</p>}
      {rows?.map((r) => (
        <Panel key={r.chain} title={r.name} testid={`chain-${r.chain}`}>
          {r.error && <p class="error">{r.error}</p>}
          {r.deployed !== undefined && (
            <p class="small" data-testid="owner-state" data-deployed={String(r.deployed)}>
              {r.deployed ? (
                <>
                  <span class="tag green">owner contract</span> Your owner contract exists.
                </>
              ) : (
                <>
                  <span class="tag amber">no owner contract yet</span> Your first enrolment creates it.
                </>
              )}
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
      <Panel title="Your Safes">
        {list.length === 0 && <p class="muted">None yet.</p>}
        <ul class="list">
          {list.map((x) => (
            <li key={`${x.chain}${x.safe}`}>
              <a class="item" href={`#/safe/${x.chain}/${x.safe}`} data-testid="safe-link">
                <code>{x.safe}</code>
                <span class="muted small">{chainById(x.chain).name}</span>
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
        <a href="#/board" data-testid="go-board">
          Board
        </a>
        <a href="#/settings" data-testid="go-settings">
          Settings
        </a>
      </nav>
    </Screen>
  )
}

// --- the board's details ---

export function BoardInfo() {
  const app = useApp()
  const rec = useBoard()
  const s = useLink()
  const [trees, setTrees] = useState<BoardTree[] | null>(null)
  const [confirmForget, setConfirmForget] = useState(false)
  const act = useAction()
  const st = s.phase === 'connected' ? s.status : null
  useEffect(() => {
    if (st?.state !== 'unlocked') return
    link.client
      ?.trees()
      .then(setTrees)
      .catch(() => setTrees(null))
  }, [st?.state, st?.trees])
  const mismatch = st && st.state !== 'locked' ? boardMismatch(rec, st) : null
  return (
    <Screen title="Board" back="/" testid="board-info">
      <Panel title={rec.link === 'virtual' ? 'The virtual board' : 'Your board, on USB'}>
        {st ? (
          <dl class="kv small" data-testid="board-status">
            <dt>State</dt>
            <dd>{st.state}</dd>
            <dt>Firmware</dt>
            <dd>
              <code>{st.version}</code>
            </dd>
            <dt>Key trees</dt>
            <dd>{st.trees}</dd>
            <dt>Storage</dt>
            <dd>
              {Math.round(st.storageUsed / 1024).toLocaleString()} of {Math.round(st.storageSize / 1024).toLocaleString()} KB
            </dd>
            <dt>Stateless signatures</dt>
            <dd>{st.statelessSignatures}</dd>
            {st.recovered && (
              <>
                <dt>Recovered</dt>
                <dd>yes: its earlier key trees are gone, enrol each Safe again</dd>
              </>
            )}
          </dl>
        ) : (
          <p class="muted">{linkLine(s).text}</p>
        )}
        {mismatch && <p class="error">{mismatch}</p>}
        <ErrorLine error={act.error} />
        {act.busy ? (
          <Progress step={act.step} started={act.started} onCancel={act.cancel} />
        ) : (
          <div class="actions row">
            {st?.state === 'blank' && (
              <button
                type="button"
                data-testid="board-recover"
                onClick={async () => {
                  await act.run(async (step, signal) => {
                    step('Follow the board: enter your 24 words on it, then a new PIN twice')
                    const c = link.need()
                    const id = await c.recover({ signal })
                    if (id.memberKey.toLowerCase() !== rec.memberKey.toLowerCase()) throw new Error(`Those words give another member (owner ${id.owner}), not yours.`)
                  })
                  await link.refresh()
                }}
              >
                Recover it from my 24 words
              </button>
            )}
            {s.phase === 'connected' ? (
              <button type="button" class="secondary" data-testid="disconnect" onClick={() => link.disconnect()}>
                Disconnect
              </button>
            ) : (
              <button type="button" class="secondary" onClick={() => act.run(() => connect(rec.link))}>
                Connect
              </button>
            )}
          </div>
        )}
      </Panel>
      {trees && (
        <Panel title="Key trees on the board">
          {trees.length === 0 && <p class="muted">None: enrol from a Safe’s screen.</p>}
          <ul class="list">
            {trees.map((t) => (
              <li key={t.root} class="item small">
                <span>
                  {chainById(t.chain)?.name ?? `chain ${t.chain}`} <code>{t.safe}</code>
                </span>
                <span class="muted">
                  nonces {t.start} to {t.start + 2 ** (t.height - 1) - 1}, {t.used} of {2 ** t.height} keys used{t.certified ? '' : ', not certified'}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      <Panel title="Forget this board here" tone="warn">
        <p class="small">Deletes what this browser holds: the gas key, your list of Safes and your dapps’ sessions. The board keeps your member key{rec.link === 'virtual' ? ' (the virtual board’s storage stays in this browser)' : ''}.</p>
        {confirmForget ? (
          <div class="actions row">
            <button
              type="button"
              class="danger"
              data-testid="forget-confirm"
              onClick={async () => {
                await link.disconnect()
                // dapps too: their sessions end, and the SDK's storage goes
                await forgetWc(app.env).catch(() => {})
                await wipe(app.env.db)
                await app.reload()
                go('/')
              }}
            >
              Forget it here
            </button>
            <button type="button" class="secondary" onClick={() => setConfirmForget(false)}>
              Keep it
            </button>
          </div>
        ) : (
          <button type="button" class="secondary" data-testid="forget" onClick={() => setConfirmForget(true)}>
            Forget this board here
          </button>
        )}
      </Panel>
    </Screen>
  )
}

// --- a Safe's key tree, with a board ---

export function BoardTreePanel(props: { view: BoardSafeView; chain: number; safe: Address; onDone(): void }) {
  const app = useApp()
  const rec = useBoard()
  const s = useLink()
  const v = props.view
  const [done, setDone] = useState<{ text: string; tx: string } | null>(null)
  const act = useAction()
  const low = v.left !== undefined && v.capacity !== undefined && v.left < v.capacity / 5
  const usable = !!v.onchain.root && !!v.tree && (v.left ?? 0) > 0
  const unlocked = s.phase === 'connected' && s.status?.state === 'unlocked'

  async function doEnrol() {
    const r = await act.run((step, signal) => boardEnrol(app.env, rec, link.need(), props.chain, props.safe, step, { signal }))
    if (r) setDone({ text: `Enrolled a key tree for nonces ${r.start} to ${r.start + 2 ** (r.height - 1) - 1}${r.created ? ', and created your owner contract' : ''} (${r.gasUsed.toLocaleString()} gas).`, tx: r.hash })
    props.onDone()
  }

  return (
    <Panel title="Key tree" tone={usable && !low ? 'plain' : 'warn'} testid="tree-panel">
      {v.onchain.root ? (
        <p data-testid="tree-state" data-left={usable ? v.left : 0}>
          {v.left} of {v.capacity} nonces left for your owner on this Safe (nonces {v.onchain.start} to {v.onchain.start + v.capacity! - 1}).
          {low && ' Running low: enrol a fresh key tree soon.'}
          {v.boardTrees === null && ' Connect and unlock the board to sign.'}
        </p>
      ) : (
        <p data-testid="tree-state" data-left="0">
          No key tree yet. The board makes one for this Safe: 512 nonces, two one-time keys each. It signs the tree’s certificate with your member key, and your gas account sends it
          {v.deployed ? '' : ', creating your owner contract'}.
        </p>
      )}
      {v.treeProblem && <p class="error">{v.treeProblem}</p>}
      {v.pending && <p class="small">The board signed a certificate (from nonce {v.pending.start}) that isn’t sent yet: enrolling sends it.</p>}
      <ErrorLine error={act.error} />
      {done && (
        <p class="okline" data-testid="enrolled" data-tx={done.tx}>
          {done.text}
        </p>
      )}
      {act.busy ? (
        <Progress step={act.step} started={act.started} onCancel={act.cancel} />
      ) : (
        (!usable || low || v.pending) && (
          <button type="button" data-testid="enrol" disabled={!unlocked && !v.pending} onClick={doEnrol}>
            {v.pending ? 'Send the certificate' : v.onchain.root ? 'Enrol a fresh key tree' : 'Enrol'}
          </button>
        )
      )}
      {!unlocked && !act.busy && <p class="muted small">{linkLine(s).text}</p>}
    </Panel>
  )
}
