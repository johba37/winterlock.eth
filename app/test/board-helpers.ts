// The virtual board in Node: the board's WebAssembly behind the same runner the worker uses, on a
// link that delivers bytes in this thread, and the member's hands on its buttons (by reading its
// screen text, as qemu_flows.py does through the test hooks).

import { readFileSync } from 'node:fs'
import * as boardWasm from '../src/wasm/board.js'
import { BOTH, LEFT, MemorySectors, RIGHT, type SectorStore, VirtualBoardRunner } from '../src/board/runner'
import type { Transport, TransportEvents } from '../src/board/transport'

boardWasm.initSync({ module: readFileSync(new URL('../src/wasm/board_bg.wasm', import.meta.url)) })

export { boardWasm }

/** The virtual board on a direct link. */
export class DirectBoard implements Transport {
  readonly kind = 'virtual' as const
  readonly label = 'virtual board (Node)'
  runner!: VirtualBoardRunner
  private events: TransportEvents | undefined
  /** Every frame the board sent, in order, with the number of flash saves done when it left. */
  sent: { bytes: Uint8Array; saves: number }[] = []
  /** Called as each frame leaves, before the client sees it. */
  onFrame?: (bytes: Uint8Array) => void

  constructor(readonly store: SectorStore = new MemorySectors()) {}

  async open(events: TransportEvents) {
    this.events = events
    await this.boot()
  }

  private async boot() {
    this.runner = new VirtualBoardRunner(boardWasm, this.store, {
      frame: (b) => {
        this.sent.push({ bytes: b, saves: (this.store as MemorySectors).saves ?? 0 })
        this.onFrame?.(b)
        this.events?.data(b)
      },
      screen: () => {},
      fatal: (m) => {
        throw new Error(`the virtual board stopped: ${m}`)
      },
    })
    await this.runner.start()
  }

  async write(bytes: Uint8Array) {
    void this.runner.receive(bytes)
  }

  async close() {
    this.runner.stop()
    this.events?.closed('closed')
  }

  /** The reset button: the board starts again from what it stored. */
  async restart() {
    this.runner.stop()
    await this.boot()
  }

  lines(): string[] {
    return this.runner.text.split('\n')
  }

  title(): string {
    return this.lines()[0].replace(/ \[.*\]$/, '')
  }

  /** "L", "R", "B" for both. */
  async press(keys: string) {
    for (const k of keys) await this.runner.button(k === 'L' ? LEFT : k === 'R' ? RIGHT : BOTH)
  }

  /** Waits until the screen's title is `t` (the board works through the request queue). */
  async until(t: string | RegExp, tries = 200) {
    for (let i = 0; i < tries; i++) {
      if (typeof t === 'string' ? this.title() === t : t.test(this.title())) return
      await new Promise((r) => setTimeout(r, 5))
    }
    throw new Error(`the board shows ${JSON.stringify(this.lines())}, not ${t}`)
  }
}

export const PIN = [2, 0, 2, 6]

export function pinKeys(digits: number[]): string {
  return digits.map((d) => 'R'.repeat(d) + 'B').join('') + 'LB'
}

/** Goes through setup on the board's screens; returns the 24 words read off them. */
export async function setupOnBoard(b: DirectBoard, pin = PIN): Promise<string[]> {
  await b.until('New board')
  await b.press('R')
  const words: string[] = []
  for (let p = 0; p < 6; p++) {
    if (b.title() !== 'Your words') throw new Error(`not the words: ${b.lines()}`)
    for (const l of b.lines().slice(1, 5)) words.push(l.trim().split(/\s+/)[1])
    await b.press('R')
  }
  if (b.title() !== 'All written?') throw new Error(b.lines().join(' / '))
  await b.press('B')
  for (let i = 0; i < 3; i++) {
    const pos = Number(b.title().match(/^Word (\d+)\?/)![1])
    const choices = b.lines().slice(1, 5).map((l) => l.slice(2))
    const at = choices.indexOf(words[pos - 1])
    if (at < 0) throw new Error(`word ${pos} isn't among ${choices}`)
    await b.press('R'.repeat(at) + 'B')
  }
  if (b.title() !== 'Choose a PIN') throw new Error(b.lines().join(' / '))
  await b.press('R' + pinKeys(pin) + pinKeys(pin))
  return words
}

export async function unlockOnBoard(b: DirectBoard, pin = PIN) {
  await b.until('Enter PIN')
  await b.press(pinKeys(pin))
}

/** Types a word on the recovery wheel, reading the letter shown in brackets. */
export async function typeWord(b: DirectBoard, word: string) {
  let typed = ''
  for (let guard = 0; guard < 400; guard++) {
    const lines = b.lines()
    if (lines.at(-1)!.endsWith('both: ok')) {
      if (lines[2] !== word) throw new Error(`the board picked ${lines[2]}, not ${word}`)
      await b.press('B')
      return
    }
    const shown = lines[2].match(/\[(.*)\]$/)![1]
    const want = typed === word ? `=${word}` : word[typed.length]
    if (shown === want) {
      await b.press('B')
      if (want.length === 1) typed += want
    } else await b.press('R')
  }
  throw new Error(`couldn't type ${word}`)
}

/** Steps through a request's pages and holds both on the last (and again if it asks). Returns the
 * titles of the pages it saw. */
export async function confirmOnBoard(b: DirectBoard): Promise<string[]> {
  await b.until(/^(Send|Approve|NOT DECODED|Cancel|Enrol key tree)$/)
  const seen = [b.lines()[0]]
  for (let i = 0; i < 20 && !/hold both: (sign|enrol)$/.test(b.lines().at(-1)!); i++) {
    await b.press('R')
    seen.push(b.lines()[0])
  }
  await b.press('B')
  if (b.title() === 'Not decoded') {
    seen.push('Not decoded')
    await b.press('B')
  }
  return seen
}
