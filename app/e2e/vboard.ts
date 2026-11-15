// The member's hands on the virtual board in the page: its buttons (clicks, or the keyboard), and
// its screen read from the drawn OLED's text (data-text), as qemu_flows.py reads a test build's.

import { type Page, expect } from '@playwright/test'

export const PIN = [2, 0, 2, 6]

export class VBoard {
  constructor(readonly page: Page) {}

  private oled() {
    return this.page.getByTestId('oled')
  }

  async seq(): Promise<number> {
    return Number(await this.oled().getAttribute('data-seq'))
  }

  async lines(): Promise<string[]> {
    return ((await this.oled().getAttribute('data-text')) ?? '').split('\n')
  }

  async title(): Promise<string> {
    return (await this.lines())[0].replace(/ \[.*\]$/, '')
  }

  /** Waits for a title (string or pattern). */
  async until(t: string | RegExp, timeout = 60_000) {
    await expect
      .poll(async () => await this.title(), { timeout, message: `the virtual board's screen to show ${t}` })
      .toMatch(typeof t === 'string' ? new RegExp(`^${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) : t)
  }

  /** One press: L, R or B (both held), by click or by key; waits until the board drew after it. */
  async press(keys: string, via: 'click' | 'key' = 'click') {
    for (const k of keys) {
      const before = await this.seq()
      if (via === 'key') await this.page.keyboard.press(k === 'L' ? 'ArrowLeft' : k === 'R' ? 'ArrowRight' : 'ArrowDown')
      else await this.page.getByTestId(k === 'L' ? 'vb-left' : k === 'R' ? 'vb-right' : 'vb-both').click()
      await expect.poll(() => this.seq(), { timeout: 30_000 }).toBeGreaterThan(before)
    }
  }

  async pin(digits: number[], via: 'click' | 'key' = 'click') {
    await this.press(digits.map((d) => 'R'.repeat(d) + 'B').join('') + 'L', via)
    await this.press('B', via)
  }

  /** Setup on the board: reads the words, picks the three asked, sets the PIN twice. */
  async setup(pin = PIN): Promise<string[]> {
    await this.until('New board')
    await this.press('R')
    const words: string[] = []
    for (let p = 0; p < 6; p++) {
      expect(await this.title()).toBe('Your words')
      for (const l of (await this.lines()).slice(1, 5)) words.push(l.trim().split(/\s+/)[1])
      await this.press('R', p % 2 ? 'key' : 'click')
    }
    expect(await this.title()).toBe('All written?')
    await this.press('B', 'key')
    for (let i = 0; i < 3; i++) {
      const pos = Number((await this.title()).match(/^Word (\d+)\?/)![1])
      const choices = (await this.lines()).slice(1, 5).map((l) => l.slice(2))
      const at = choices.indexOf(words[pos - 1])
      expect(at, `word ${pos} among the choices`).toBeGreaterThanOrEqual(0)
      await this.press('R'.repeat(at) + 'B')
    }
    expect(await this.title()).toBe('Choose a PIN')
    await this.press('R')
    await this.pin(pin, 'key')
    expect(await this.title()).toBe('PIN again')
    await this.pin(pin)
    return words
  }

  async unlock(pin = PIN) {
    await this.until('Enter PIN')
    await this.pin(pin)
    await this.until('Winterlock')
  }

  /** Steps through a request's pages and holds both on the last (and again if it asks). Returns
   * each page's first line. */
  async confirm(): Promise<string[]> {
    await this.until(/^(Send|Approve|NOT DECODED|Cancel|Enrol key tree)$/)
    const seen = [(await this.lines())[0]]
    for (let i = 0; i < 20 && !/hold both: (sign|enrol)$/.test((await this.lines()).at(-1)!); i++) {
      await this.press('R')
      seen.push((await this.lines())[0])
    }
    await this.press('B')
    if ((await this.title()) === 'Not decoded') {
      seen.push('Not decoded')
      await this.press('B')
    }
    return seen
  }

  /** Leaves a result screen ("Signed", "Enrolled", "Refused") for home. */
  async dismiss(title: string | RegExp, timeout = 120_000) {
    await this.until(title, timeout)
    await this.press('R')
  }
}
