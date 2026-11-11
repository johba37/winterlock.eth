// The app's one link to a board: which board (USB or the virtual one), whether it is connected,
// and what it last said about itself. The screens read it through useLink(); the flows take its
// client.
//
// - BOOTED (the board started again): the status is read again; the board asks for its PIN.
// - Locked: the status is read every 1.5 s until the member has entered the PIN on the board.
// - Unplugged: the link is closed; when the same port comes back (Web Serial's connect event) it
//   is opened again by itself.
// - Busy when the link opens: a request from before (a page reloaded while the board waited for
//   the member) that no one will read; a serial port has one tab at a time, so it is cancelled.

import { useEffect, useState } from 'preact/hooks'
import { BoardClient, type BoardStatus } from './client'
import { SerialTransport, grantedPorts } from './serial'
import type { LinkKind, Transport } from './transport'
import { VirtualTransport } from './virtual'

export type LinkState =
  | { phase: 'none' }
  | { phase: 'connecting'; kind: LinkKind }
  | { phase: 'connected'; kind: LinkKind; label: string; status: BoardStatus | null; error?: string }
  | { phase: 'disconnected'; kind: LinkKind; why: string }

type Listener = (s: LinkState) => void

export class BoardLink {
  state: LinkState = { phase: 'none' }
  client: BoardClient | undefined
  transport: Transport | undefined
  private listeners = new Set<Listener>()
  private poll: ReturnType<typeof setInterval> | undefined
  private lastPort: SerialPort | undefined
  private onSerialConnect = (e: Event) => {
    const port = e.target as SerialPort
    if (this.state.phase === 'disconnected' && this.state.kind === 'serial' && (port === this.lastPort || !this.lastPort)) {
      void this.connectSerial(port).catch(() => {})
    }
  }

  constructor() {
    if (typeof navigator !== 'undefined') navigator.serial?.addEventListener('connect', this.onSerialConnect)
  }

  private set(s: LinkState) {
    this.state = s
    for (const l of this.listeners) l(s)
    clearInterval(this.poll)
    if (s.phase === 'connected' && s.status?.state === 'locked') {
      this.poll = setInterval(() => {
        if (!this.client?.busy) void this.refresh()
      }, 1500)
    }
  }

  subscribe(f: Listener) {
    this.listeners.add(f)
    return () => {
      this.listeners.delete(f)
    }
  }

  get virtual(): VirtualTransport | undefined {
    return this.transport instanceof VirtualTransport ? this.transport : undefined
  }

  /** The client, if a board is connected. */
  need(): BoardClient {
    if (this.state.phase !== 'connected' || !this.client?.connected) throw new Error('No board is connected: connect it first (the board’s bar).')
    return this.client
  }

  private async attach(t: Transport) {
    await this.disconnect()
    this.set({ phase: 'connecting', kind: t.kind })
    const c = new BoardClient(t)
    c.onBooted((status) => {
      if (this.client === c) this.set({ phase: 'connected', kind: t.kind, label: t.label, status })
    })
    c.onClosed((why) => {
      if (this.client !== c) return
      this.client = undefined
      this.set({ phase: 'disconnected', kind: t.kind, why })
    })
    this.client = c
    this.transport = t
    try {
      await c.connect()
      let status = await c.status()
      if (status.busy) {
        await c.cancel().catch(() => {})
        status = await c.status()
      }
      this.set({ phase: 'connected', kind: t.kind, label: t.label, status })
    } catch (e) {
      if (this.client === c) {
        this.client = undefined
        await c.close().catch(() => {})
        await t.close().catch(() => {})
        this.set({ phase: 'disconnected', kind: t.kind, why: (e as Error).message })
      }
      throw e
    }
  }

  async connectVirtual() {
    await this.attach(new VirtualTransport())
  }

  async connectSerial(port: SerialPort) {
    this.lastPort = port
    await this.attach(new SerialTransport(port))
  }

  /** A port this site may already use, without the chooser: true if one opened. */
  async connectGranted(): Promise<boolean> {
    const ports = await grantedPorts()
    const port = ports.find((p) => p === this.lastPort) ?? ports[0]
    if (!port) return false
    await this.connectSerial(port)
    return true
  }

  async refresh(): Promise<BoardStatus | null> {
    const c = this.client
    const s = this.state
    if (!c || s.phase !== 'connected') return null
    try {
      const status = await c.status()
      if (this.client === c) this.set({ ...s, status, error: undefined })
      return status
    } catch (e) {
      if (this.client === c && this.state.phase === 'connected') this.set({ ...this.state, error: (e as Error).message })
      return null
    }
  }

  async disconnect() {
    clearInterval(this.poll)
    const c = this.client
    this.client = undefined
    this.transport = undefined
    if (c) await c.close().catch(() => {})
    this.set({ phase: 'none' })
  }
}

export const link = new BoardLink()

export function useLink(): LinkState {
  const [s, setS] = useState(link.state)
  useEffect(() => link.subscribe(setS), [])
  return s
}
