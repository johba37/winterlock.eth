// Before this browser holds a device: welcome, create a member, pair this device, install on iOS.

import { useEffect, useRef, useState } from 'preact/hooks'
import { useApp } from '../app'
import { type MemberSession, memberSession } from '../core/client'
import { createDevice, pairDevice } from '../lib/flows'
import { isIOS, mayHoldKeys, persist } from '../lib/platform'
import { Addr, ErrorLine, Panel, Progress, Screen, go, useAction } from '../ui'

export function Welcome() {
  return (
    <Screen title="Winterlock signer" testid="welcome">
      <Panel>
        <p>
          <strong>Sign for your team’s Safe with keys a quantum computer can’t break.</strong> Each member has an owner in the Safe; this app holds a key for one of
          the member’s devices.
        </p>
        <p class="muted small">Research prototype on the Sepolia test network. The contracts are not audited: use test funds only.</p>
      </Panel>
      {!mayHoldKeys() && <InstallFirst />}
      <div class="actions">
        <button type="button" data-testid="go-create" disabled={!mayHoldKeys()} onClick={() => go('/create')}>
          I’m new: create my recovery phrase
        </button>
        <button type="button" class="secondary" data-testid="go-pair" disabled={!mayHoldKeys()} onClick={() => go('/pair')}>
          I have a recovery phrase: pair this device
        </button>
        <button type="button" class="secondary" data-testid="go-board" onClick={() => go('/board')}>
          Use a board
        </button>
      </div>
      <p class="muted small">With a board, the board makes and keeps your member key and signs every transaction after showing it; this app holds no key but the gas account’s.</p>
      <p class="small">
        <a href="#/settings">Settings</a>
      </p>
    </Screen>
  )
}

function InstallFirst() {
  return (
    <Panel title="Install the app first" tone="warn">
      <p>On iPhone and iPad, Safari deletes a website’s data after seven days without a visit, which would delete this device’s key. Installed apps keep theirs.</p>
      <p>
        <a href="#/install">How to install it</a>
      </p>
    </Panel>
  )
}

export function Install() {
  return (
    <Screen title="Install on iPhone or iPad" back="/" testid="install">
      <Panel>
        <ol class="steps">
          <li>Open this page in Safari.</li>
          <li>
            Tap the <strong>Share</strong> button (the square with an arrow pointing up).
          </li>
          <li>
            Scroll down and tap <strong>Add to Home Screen</strong>, then <strong>Add</strong>.
          </li>
          <li>
            Open <strong>Winterlock</strong> from your home screen. From then on, always open it from there: the installed app and the Safari tab keep separate data.
          </li>
        </ol>
      </Panel>
      {isIOS() ? null : <p class="muted small">On this device the app works in the browser; installing it is optional.</p>}
    </Screen>
  )
}

function randomPositions(): number[] {
  const out = new Set<number>()
  const r = new Uint32Array(1)
  while (out.size < 3) {
    crypto.getRandomValues(r)
    out.add((r[0] % 24) + 1)
  }
  return [...out].sort((a, b) => a - b)
}

type CreateStage = 'intro' | 'show' | 'check' | 'working' | 'done'

export function Create() {
  const app = useApp()
  const [stage, setStage] = useState<CreateStage>('intro')
  const [words, setWords] = useState<string[]>([])
  const [positions, setPositions] = useState<number[]>([])
  const [answers, setAnswers] = useState<string[]>(['', '', ''])
  const [wrong, setWrong] = useState<string | null>(null)
  const [report, setReport] = useState<{ owner: string } | null>(null)
  const session = useRef<MemberSession | null>(null)
  const act = useAction()

  // leaving the screen ends the session: nothing is saved before the check passes
  useEffect(() => () => session.current?.end(), [])

  async function start() {
    await persist()
    session.current?.end()
    session.current = memberSession()
    const ws = await act.run(() => session.current!.call<string[]>('newPhrase'))
    if (ws) {
      setWords(ws)
      setStage('show')
    }
  }

  function hide() {
    setPositions(randomPositions())
    setAnswers(['', '', ''])
    setWrong(null)
    setStage('check')
  }

  async function check(e: Event) {
    e.preventDefault()
    const s = session.current!
    for (let i = 0; i < 3; i++) {
      if (!(await s.call<boolean>('checkWord', { position: positions[i], answer: answers[i] }))) {
        setWrong(`Word ${positions[i]} doesn’t match your phrase. Check your written copy.`)
        return
      }
    }
    setWords([])
    setAnswers(['', '', ''])
    setStage('working')
    const dev = await act.run((step) => createDevice(app.env, session.current!, step))
    session.current = null
    if (dev) {
      setReport({ owner: dev.owner })
      setStage('done')
    } else setStage('check')
  }

  if (stage === 'intro')
    return (
      <Screen title="Create your recovery phrase" back="/" testid="create-intro">
        <Panel>
          <p>The app makes your recovery phrase: 24 words that are your membership. With them you pair your other devices and revoke a lost one.</p>
          <ol class="steps">
            <li>Have paper and a pen ready. Don’t take a photo or a screenshot.</li>
            <li>Write down the 24 words in order. The app shows them once.</li>
            <li>Then it asks for three of them, from your written copy.</li>
          </ol>
          <p>
            <strong>Anyone who has the words can act as you.</strong> Keep the paper somewhere safe and private.
          </p>
        </Panel>
        <ErrorLine error={act.error} />
        <div class="actions">
          <button type="button" data-testid="show-phrase" onClick={start} disabled={act.busy}>
            Show my recovery phrase
          </button>
        </div>
      </Screen>
    )

  if (stage === 'show')
    return (
      <Screen title="Your recovery phrase" testid="create-show">
        <Panel tone="warn">
          <p>Write these 24 words down, in order. You’ll need three of them in a moment.</p>
          <ol class="words" data-testid="phrase-words">
            {words.map((w) => (
              <li key={w + Math.random()}>{w}</li>
            ))}
          </ol>
        </Panel>
        <div class="actions">
          <button type="button" data-testid="written-down" onClick={hide}>
            I wrote them down: hide them
          </button>
        </div>
      </Screen>
    )

  if (stage === 'check' || stage === 'working')
    return (
      <Screen title="Check your written copy" testid="create-check">
        <form class="panel" onSubmit={check}>
          <p>The phrase is hidden. Type these words from your written copy.</p>
          {positions.map((p, i) => (
            <label key={p}>
              Word {p}
              <input
                data-testid={`check-word-${i}`}
                autocomplete="off"
                autocapitalize="none"
                spellcheck={false}
                value={answers[i]}
                disabled={stage === 'working'}
                onInput={(e) => {
                  const a = [...answers]
                  a[i] = (e.target as HTMLInputElement).value
                  setAnswers(a)
                }}
              />
            </label>
          ))}
          <ErrorLine error={wrong ?? act.error} />
          {stage === 'working' ? (
            <Progress step={act.step} started={act.started} />
          ) : (
            <div class="actions row">
              <button type="submit" data-testid="check-submit">
                Check
              </button>
              {wrong && (
                <button type="button" class="secondary" onClick={() => setStage('show')}>
                  Show the phrase again
                </button>
              )}
            </div>
          )}
        </form>
        <p class="muted small">There is no skip: if you leave now, nothing is saved and the words you wrote down are void.</p>
      </Screen>
    )

  return (
    <Screen title="Your phrase is set" testid="create-done">
      <Panel tone="ok">
        <p class="okline">Checked. This browser now holds device 1 of your membership; the phrase and your member key are gone from it.</p>
        <Addr label="Your owner address (the Safe’s owners add this)" value={report!.owner} testid="owner-address" full />
      </Panel>
      <Panel title="Next">
        <ol class="steps">
          <li>Fund your gas account with a little ETH (Settings shows its address and a QR code). It pays for your transactions.</li>
          <li>Send this device’s certificate (on the home screen).</li>
          <li>Ask your team to add your owner address to the Safe, then join it here.</li>
        </ol>
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
}

export function Pair() {
  const app = useApp()
  const [text, setText] = useState('')
  const [report, setReport] = useState<string[] | null>(null)
  const [paired, setPaired] = useState<{ device: number; owner: string } | null>(null)
  const area = useRef<HTMLTextAreaElement>(null)
  const act = useAction()

  async function submit(e: Event) {
    e.preventDefault()
    await persist()
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
      // the phrase is in the session now: clear it from the page
      setText('')
      if (area.current) area.current.value = ''
      try {
        return await pairDevice(app.env, s, step)
      } catch (err) {
        const rep = (err as { report?: string[] }).report
        if (rep) {
          // the device is stored; only sending its certificate failed
          setReport(rep)
          throw new Error(`${(err as Error).message} You can send the certificate later from the home screen.`)
        }
        throw err
      }
    })
    if (r) {
      setPaired({ device: r.device.device, owner: r.device.owner })
      setReport(r.report)
    }
  }

  // the app's state reloads only on Continue: until then this screen shows what happened
  if (report)
    return (
      <Screen title={paired ? 'This device is paired' : 'This device is stored'} testid="pair-done">
        <Panel tone={paired ? 'ok' : 'warn'}>
          {paired && (
            <p class="okline">
              Device {paired.device} of owner {paired.owner.slice(0, 10)}…
            </p>
          )}
          <ul class="list" data-testid="pair-report">
            {report.map((l) => (
              <li key={l} class="small">
                {l}
              </li>
            ))}
          </ul>
          <p class="muted small">The phrase and your member key are gone from this browser.</p>
        </Panel>
        <ErrorLine error={act.error} />
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
    <Screen title="Pair this device" back="/" testid="pair">
      <form class="panel" onSubmit={submit}>
        <p>Type your 24 words. The app makes a key for this device, your member key certifies it, and then the app forgets the phrase.</p>
        <label>
          Recovery phrase
          <textarea
            ref={area}
            data-testid="phrase-input"
            autocomplete="off"
            autocapitalize="none"
            spellcheck={false}
            value={text}
            disabled={act.busy}
            onInput={(e) => setText((e.target as HTMLTextAreaElement).value)}
            placeholder="1. word  2. word  …"
          />
        </label>
        <p class="muted small">Case, numbering and commas don’t matter; the first four letters of a word are enough.</p>
        <ErrorLine error={act.error} />
        {act.busy ? (
          <Progress step={act.step} started={act.started} />
        ) : (
          <div class="actions">
            <button type="submit" data-testid="pair-submit" disabled={!text.trim()}>
              Pair this device
            </button>
          </div>
        )}
      </form>
      <p class="muted small">Pairing sends one transaction from your gas account, which your phrase also gives this device.</p>
    </Screen>
  )
}
