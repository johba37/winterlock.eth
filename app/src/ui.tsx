// Small shared pieces of the screens.

import type { ComponentChildren } from 'preact'
import { useEffect, useState } from 'preact/hooks'
import qrcode from 'qrcode-generator'
import { short } from './lib/chain'

export function go(path: string) {
  location.hash = path
}

export function Screen(props: { title: string; back?: string; children: ComponentChildren; testid?: string }) {
  return (
    <main class="screen" data-testid={props.testid}>
      <header class="bar">
        {props.back !== undefined ? (
          <a class="back" href={`#${props.back}`} aria-label="Back">
            ‹
          </a>
        ) : (
          <Mark />
        )}
        <h1>{props.title}</h1>
      </header>
      <div class="body">{props.children}</div>
    </main>
  )
}

/** The Permanent Way mark (docs/brand/mark.svg). */
export function Mark() {
  return (
    <svg class="mark" viewBox="0 0 32 32" aria-hidden="true">
      <path class="ink" d="M1 8.5H31V12.5H1ZM1 19.5H31V23.5H1ZM11.82 2H16.02L14.3 7.2H10.1ZM7.93 13.8H12.13L10.67 18.2H6.47ZM4.3 24.8H8.5L6.78 30H2.58ZM21.22 2H25.42L23.7 7.2H19.5ZM13.7 24.8H17.9L16.18 30H11.98Z" />
      <path class="lamp" d="M17.33 13.8H21.53L20.07 18.2H15.87Z" />
    </svg>
  )
}

export function Panel(props: { title?: string; children: ComponentChildren; tone?: 'warn' | 'ok' | 'plain'; testid?: string }) {
  return (
    <section class={`panel ${props.tone ?? 'plain'}`} data-testid={props.testid}>
      {props.title && <h2>{props.title}</h2>}
      {props.children}
    </section>
  )
}

export function Addr(props: { value: string; label?: string; testid?: string; full?: boolean }) {
  const [copied, setCopied] = useState(false)
  const v = props.value
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(v)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* no clipboard: the text is selectable */
    }
  }
  return (
    <div class="addr">
      {props.label && <span class="label">{props.label}</span>}
      <code data-testid={props.testid} data-value={v} class={props.full ? 'full' : ''}>
        {props.full ? v : `${v.slice(0, 8)}…${v.slice(-6)}`}
      </code>
      <button type="button" class="link" onClick={copy}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

export function Qr(props: { text: string; size?: number }) {
  const q = qrcode(0, 'M')
  q.addData(props.text)
  q.make()
  const n = q.getModuleCount()
  const cells: string[] = []
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) cells.push(`M${c + 4} ${r + 4}h1v1h-1z`)
  return (
    <svg class="qr" viewBox={`0 0 ${n + 8} ${n + 8}`} width={props.size ?? 200} height={props.size ?? 200} role="img" aria-label={props.text}>
      <rect width={n + 8} height={n + 8} fill="#fff" />
      <path d={cells.join('')} fill="#000" />
    </svg>
  )
}

export interface StepState {
  label: string
  done?: number
  total?: number
}

export function Progress(props: { step: StepState | null; started?: number }) {
  const [, tick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => tick((x) => x + 1), 500)
    return () => clearInterval(t)
  }, [])
  if (!props.step) return null
  const { label, done, total } = props.step
  const pct = total ? Math.round((100 * (done ?? 0)) / total) : undefined
  const secs = props.started ? Math.floor((Date.now() - props.started) / 1000) : undefined
  return (
    <div class="progress" role="status" aria-live="polite" data-testid="progress">
      <p>
        {label}
        {pct !== undefined ? ` (${pct}%)` : '…'}
      </p>
      <div class={`track ${pct === undefined ? 'busy' : ''}`}>
        <div class="fill" style={{ width: pct !== undefined ? `${pct}%` : undefined }} />
      </div>
      {secs !== undefined && secs > 1 && <p class="muted small">{secs} s</p>}
    </div>
  )
}

/** Runs an action with progress and an error line. */
export function useAction() {
  const [step, setStep] = useState<StepState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [started, setStarted] = useState<number | undefined>()
  async function run<T>(f: (step: (label: string, p?: { done: number; total: number }) => void) => Promise<T>): Promise<T | undefined> {
    setError(null)
    setBusy(true)
    setStarted(Date.now())
    try {
      return await f((label, p) => setStep({ label, done: p?.done, total: p?.total }))
    } catch (e) {
      setError(short(e))
      return undefined
    } finally {
      setBusy(false)
      setStep(null)
    }
  }
  return { step, error, busy, run, started, setError }
}

export function ErrorLine(props: { error: string | null }) {
  return props.error ? (
    <p class="error" role="alert" data-testid="error">
      {props.error}
    </p>
  ) : null
}

export function Explorer(props: { base: string; tx?: string; address?: string }) {
  const href = props.tx ? `${props.base}/tx/${props.tx}` : `${props.base}/address/${props.address}`
  const v = (props.tx ?? props.address)!
  return (
    <a href={href} target="_blank" rel="noreferrer noopener">
      <code>{`${v.slice(0, 10)}…${v.slice(-6)}`}</code>
    </a>
  )
}
