// The board's firmware in Espressif's QEMU, its serial port on TCP (as tools/qemu_flows.py runs it),
// with the member's hands: the test image's hooks (TEST_BUTTONS, TEST_SCREEN) sent on the same
// port, with ids from 0xF000 that the app's client never uses. Everything QEMU sends goes to
// `onData` as well (the page's fake serial port), the bootloader's text and these answers included.

import { type ChildProcess, spawn } from 'node:child_process'
import { copyFileSync } from 'node:fs'
import { Socket, createServer } from 'node:net'
import { Deframer, T, encode } from '../src/board/frame'
import { parseError, parseScreen, parseStatus, type BoardStatus } from '../src/board/client'

function freePort(): Promise<number> {
  return new Promise((res) => {
    const s = createServer()
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as any).port
      s.close(() => res(p))
    })
  })
}

export class QemuBoard {
  private proc: ChildProcess | undefined
  private sock: Socket | undefined
  private d = new Deframer()
  private nextId = 0xf000
  private waiting = new Map<number, (f: { type: number; payload: Uint8Array }) => void>()
  booted: BoardStatus[] = []
  onData: (b: Uint8Array) => void = () => {}
  /** bytes the page wrote to the board, and the board's bytes (frames, the bootloader's and the
   * test build's text), for the log */
  written = 0
  read = 0

  constructor(
    readonly qemu: string,
    readonly flash: string,
  ) {}

  /** A fresh flash file from the test image. */
  static fromImage(qemu: string, image: string, flash: string) {
    copyFileSync(image, flash)
    return new QemuBoard(qemu, flash)
  }

  /** Powers the board on: QEMU starts once the serial port's TCP client connects. */
  async start() {
    const port = await freePort()
    this.d = new Deframer()
    this.proc = spawn(this.qemu, ['-nographic', '-machine', 'esp32', '-drive', `file=${this.flash},if=mtd,format=raw`, '-serial', `tcp:127.0.0.1:${port},server=on,wait=on`, '-monitor', 'none'], {
      stdio: 'ignore',
    })
    for (let i = 0; ; i++) {
      try {
        this.sock = await new Promise<Socket>((res, rej) => {
          const s = new Socket()
          s.once('error', rej)
          s.connect(port, '127.0.0.1', () => res(s))
        })
        break
      } catch {
        if (i > 300) throw new Error('QEMU’s serial port never opened')
        await new Promise((r) => setTimeout(r, 100))
      }
    }
    this.sock.on('data', (b: Buffer) => {
      const u = new Uint8Array(b)
      this.read += u.length
      this.onData(u)
      this.d.push(u)
      let f
      while ((f = this.d.next())) {
        if (f.type === T.EV_BOOTED) this.booted.push(parseStatus(f.payload))
        const w = this.waiting.get(f.id)
        if (w && f.id >= 0xf000) {
          this.waiting.delete(f.id)
          w(f)
        }
      }
    })
    this.sock.on('error', () => {})
  }

  /** Pulls the power: QEMU killed at once (what it wrote to the flash file stays). */
  async kill() {
    const p = this.proc
    this.proc = undefined
    this.sock?.destroy()
    this.sock = undefined
    if (p && p.exitCode === null) {
      const gone = new Promise((r) => p.once('exit', r))
      p.kill('SIGKILL')
      await gone
    }
  }

  write(b: Uint8Array) {
    this.written += b.length
    this.sock?.write(b)
  }

  /** Waits for the board's BOOTED event (its firmware runs). */
  async waitBooted(n: number, timeoutMs = 120_000) {
    const end = Date.now() + timeoutMs
    while (this.booted.length < n) {
      if (Date.now() > end) throw new Error('the board didn’t say it started')
      await new Promise((r) => setTimeout(r, 100))
    }
    return this.booted[n - 1]
  }

  private request(type: number, payload: Uint8Array, timeoutMs: number): Promise<{ type: number; payload: Uint8Array }> {
    const id = this.nextId++
    return new Promise((res, rej) => {
      const t = setTimeout(() => {
        this.waiting.delete(id)
        rej(new Error(`no answer to test request ${type} in ${timeoutMs / 1000} s`))
      }, timeoutMs)
      this.waiting.set(id, (f) => {
        clearTimeout(t)
        if (f.type === T.A_ERROR) rej(new Error(`the board refused a test request: ${parseError(f.payload).text}`))
        else res(f)
      })
      this.sock!.write(encode(type, id, payload))
    })
  }

  /** Presses buttons ("L", "R", "B" for both) and returns the screen's text after them. */
  async press(keys: string, timeoutMs = 900_000): Promise<string[]> {
    const ev = Uint8Array.from(keys, (c) => ({ L: 1, R: 2, B: 3 })[c as 'L' | 'R' | 'B']!)
    return parseScreen((await this.request(T.TEST_BUTTONS, ev, timeoutMs)).payload)
  }

  async screen(): Promise<string[]> {
    return parseScreen((await this.request(T.TEST_SCREEN, new Uint8Array(), 30_000)).payload)
  }

  /** Waits until the screen's first line matches. */
  async until(re: RegExp, timeoutMs = 120_000): Promise<string[]> {
    const end = Date.now() + timeoutMs
    for (;;) {
      const s = await this.screen()
      if (re.test(s[0])) return s
      if (Date.now() > end) throw new Error(`the board shows ${JSON.stringify(s)}`)
      await new Promise((r) => setTimeout(r, 300))
    }
  }
}

export const pinKeys = (digits: number[]) => digits.map((d) => 'R'.repeat(d) + 'B').join('') + 'LB'

/** Setup on the board's screens (qemu_flows.py's setup): the words read, three picked, a PIN twice. */
export async function setupOnQemu(q: QemuBoard, pin: number[]): Promise<string[]> {
  let s = await q.until(/^New board/)
  s = await q.press('R')
  const words: string[] = []
  for (let p = 0; p < 6; p++) {
    if (!s[0].startsWith('Your words')) throw new Error(s.join(' / '))
    for (const l of s.slice(1, 5)) words.push(l.trim().split(/\s+/)[1])
    s = await q.press('R')
  }
  if (s[0] !== 'All written?') throw new Error(s.join(' / '))
  s = await q.press('B')
  for (let i = 0; i < 3; i++) {
    const pos = Number(s[0].match(/^Word (\d+)\?/)![1])
    const choices = s.slice(1, 5).map((l) => l.slice(2))
    s = await q.press('R'.repeat(choices.indexOf(words[pos - 1])) + 'B')
  }
  if (s[0] !== 'Choose a PIN') throw new Error(s.join(' / '))
  await q.press('R' + pinKeys(pin) + pinKeys(pin))
  return words
}

/** A request's pages, then both held on the last (and again for a second confirmation). */
export async function confirmOnQemu(q: QemuBoard): Promise<string[][]> {
  let s = await q.until(/^(Send|Approve|NOT DECODED|Cancel|Enrol key tree)/)
  const pages = [s]
  while (!/hold both: (sign|enrol)$/.test(s.at(-1)!)) {
    s = await q.press('R')
    pages.push(s)
  }
  s = await q.press('B')
  if (s[0] === 'Not decoded') s = await q.press('B')
  return pages
}
