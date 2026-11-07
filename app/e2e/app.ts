// The app as a member uses it, one browser profile per device (a persistent Chromium context, so
// a profile can be copied like a restored or synced browser), with screenshots of each screen at
// phone and desktop sizes.

import { type BrowserContext, type Page, chromium, expect } from '@playwright/test'
import { cpSync, mkdirSync } from 'node:fs'
import { join as path } from 'node:path'
import { log, redact, rpcUrl } from './env'

export const PHONE = { width: 390, height: 844 }
export const DESKTOP = { width: 1280, height: 860 }

export interface Device {
  name: string
  ctx: BrowserContext
  page: Page
}

export function dir(): string {
  const d = process.env.E2E_DIR
  if (!d) throw new Error('set E2E_DIR to a scratch directory for the live run')
  return d
}

export function profile(name: string) {
  return path(dir(), 'profiles', name)
}

export async function open(name: string, baseURL: string): Promise<Device> {
  mkdirSync(profile(name), { recursive: true })
  const ctx = await chromium.launchPersistentContext(profile(name), { headless: true, viewport: PHONE, baseURL })
  const page = ctx.pages()[0] ?? (await ctx.newPage())
  page.on('pageerror', (e) => log(`  [${name}] page error: ${e.message}`))
  page.on('console', (m) => {
    if (m.type() === 'error') log(`  [${name}] console: ${redact(m.text()).slice(0, 300)}`)
  })
  await page.goto('/')
  return { name, ctx, page }
}

export async function close(d: Device) {
  await d.ctx.close()
}

/** Copies a closed profile, as a browser restored from a backup or synced to another machine. */
export function copyProfile(from: string, to: string) {
  cpSync(profile(from), profile(to), { recursive: true })
}

const shot = new Set<string>()

/** The current screen at phone and desktop sizes, once per name. */
export async function screens(d: Device, name: string) {
  if (shot.has(name)) return
  shot.add(name)
  const out = path(dir(), 'screenshots')
  mkdirSync(out, { recursive: true })
  await d.page.waitForTimeout(300)
  await d.page.screenshot({ path: path(out, `${name}-phone.png`), fullPage: true })
  await d.page.setViewportSize(DESKTOP)
  await d.page.waitForTimeout(200)
  await d.page.screenshot({ path: path(out, `${name}-desktop.png`), fullPage: true })
  await d.page.setViewportSize(PHONE)
}

const t = (p: Page, id: string) => p.getByTestId(id)

/** The progress line's last text, for the log. */
async function waitDone(p: Page, done: string, timeout = 10 * 60_000) {
  const ok = t(p, done)
  const err = t(p, 'error')
  await expect(ok.or(err).first()).toBeVisible({ timeout })
  if (await err.isVisible()) throw new Error(`the app says: ${await err.textContent()}`)
}

export async function createMember(d: Device): Promise<{ words: string[]; owner: string }> {
  const p = d.page
  await screens(d, '01-welcome')
  await t(p, 'go-create').click()
  await screens(d, '02-create-intro')
  await t(p, 'show-phrase').click()
  await t(p, 'phrase-words').waitFor()
  const words = await t(p, 'phrase-words').locator('li').allTextContents()
  await screens(d, '03-create-phrase')
  await t(p, 'written-down').click()
  const labels = await p.locator('form label').allTextContents()
  // one wrong word first: the app names it and offers the phrase again
  const first = Number(labels[0].match(/Word (\d+)/)![1])
  await t(p, 'check-word-0').fill(words.find((w) => w !== words[first - 1])!)
  for (let i = 1; i < 3; i++) await t(p, `check-word-${i}`).fill(words[Number(labels[i].match(/Word (\d+)/)![1]) - 1])
  await t(p, 'check-submit').click()
  await expect(t(p, 'error')).toContainText(`Word ${first}`)
  await screens(d, '04-create-check-wrong')
  await t(p, 'check-word-0').fill(words[first - 1].slice(0, 4).toUpperCase())
  await screens(d, '05-create-check')
  await t(p, 'check-submit').click()
  await t(p, 'create-done').waitFor({ timeout: 120_000 })
  await screens(d, '06-create-done')
  const owner = (await t(p, 'owner-address').getAttribute('data-value'))!
  await t(p, 'done-home').click()
  await t(p, 'home').waitFor()
  return { words, owner }
}

export async function setRpc(d: Device) {
  const p = d.page
  await p.goto('/#/settings')
  await t(p, 'rpc-edit-11155111').click()
  await t(p, 'rpc-input-11155111').fill(rpcUrl())
  await t(p, 'rpc-save-11155111').click()
  await expect(t(p, 'rpc-host-11155111')).toHaveText('https://eth-sepolia.g.alchemy.com', { timeout: 30_000 })
}

export async function gasAddress(d: Device): Promise<`0x${string}`> {
  await d.page.goto('/#/settings')
  return (await t(d.page, 'gas-address').getAttribute('data-value')) as `0x${string}`
}

export async function sendCertificate(d: Device): Promise<string[]> {
  const p = d.page
  await p.goto('/#/')
  await t(p, 'send-certificate').click()
  await waitDone(p, 'certificate-report')
  const lines = await t(p, 'certificate-report').locator('p').allTextContents()
  await expect(t(p, 'chain-11155111').getByTestId('device-state')).toHaveAttribute('data-kind', 'active', { timeout: 60_000 })
  await screens(d, '08-home-active')
  return lines
}

export async function pair(d: Device, words: string[]): Promise<string[]> {
  const p = d.page
  await t(p, 'go-pair').click()
  // typed loosely: numbered, upper case, abbreviated
  await t(p, 'phrase-input').fill(words.map((w, i) => `${i + 1}. ${i % 3 === 0 ? w.slice(0, 4).toUpperCase() : w}`).join('\n'))
  await screens(d, '09-pair')
  await t(p, 'pair-submit').click()
  await waitDone(p, 'pair-report')
  await screens(d, '10-pair-done')
  return t(p, 'pair-report').locator('li').allTextContents()
}

export async function join(d: Device, safe: string) {
  const p = d.page
  await p.goto('/#/join')
  await t(p, 'safe-input').fill(`sep:${safe}`)
  await screens(d, '11-join')
  await t(p, 'join-submit').click()
  await t(p, 'safe').waitFor()
  await expect(t(p, 'safe-state')).toBeVisible({ timeout: 60_000 })
}

export async function enrol(d: Device): Promise<string> {
  const p = d.page
  await t(p, 'enrol').click()
  await expect(t(p, 'tree-state')).toHaveAttribute('data-left', /^[1-9]/, { timeout: 10 * 60_000 })
  const text = (await p.locator('.okline').first().textContent()) ?? ''
  await screens(d, '13-safe-enrolled')
  return text
}

export async function proposeEth(d: Device, safe: string, to: string, amount: string): Promise<string> {
  const p = d.page
  await p.goto(`/#/safe/11155111/${safe}/send`)
  await t(p, 'to-input').fill(to)
  await t(p, 'amount-input').fill(amount)
  await screens(d, '14-send')
  await t(p, 'review').click()
  await screens(d, '15-send-review')
  await t(p, 'sign-propose').click()
  await waitDone(p, 'done', 5 * 60_000)
  await screens(d, '16-send-done')
  return (await t(p, 'done').getAttribute('data-hash'))!
}

export async function openTx(d: Device, safe: string, hash: string) {
  const p = d.page
  await p.goto(`/#/safe/11155111/${safe}/tx/${hash}`)
  await t(p, 'sig-count').waitFor({ timeout: 120_000 })
}

export async function confirmTx(d: Device, safe: string, hash: string): Promise<string> {
  const p = d.page
  await openTx(d, safe, hash)
  await screens(d, '17-tx-to-confirm')
  if (!(await t(p, 'confirm').isVisible())) return 'already confirmed by this owner (a run that stopped after confirming)'
  await t(p, 'confirm').click()
  await waitDone(p, 'done', 5 * 60_000)
  return (await t(p, 'done').textContent()) ?? ''
}

/** Confirms, expecting the app to refuse; returns its words. */
export async function confirmRefused(d: Device, safe: string, hash: string): Promise<string> {
  const p = d.page
  await openTx(d, safe, hash)
  await t(p, 'confirm').click()
  await expect(t(p, 'error')).toBeVisible({ timeout: 5 * 60_000 })
  return (await t(p, 'error').textContent()) ?? ''
}

export async function executeTx(d: Device, safe: string, hash: string): Promise<string> {
  const p = d.page
  await openTx(d, safe, hash)
  await expect(t(p, 'execute')).toBeVisible({ timeout: 120_000 })
  await screens(d, '18-tx-ready')
  await t(p, 'execute').click()
  // the line of an earlier confirmation may still be there: wait for the execution's
  const done = p.locator('[data-testid="done"][data-tx^="0x"]')
  await expect(done.or(t(p, 'error')).first()).toBeVisible({ timeout: 10 * 60_000 })
  if (await t(p, 'error').isVisible()) throw new Error(`the app says: ${await t(p, 'error').textContent()}`)
  await screens(d, '19-tx-executed')
  return (await done.getAttribute('data-tx'))!
}

export async function revoke(d: Device, target: number, words: string[]): Promise<string[]> {
  const p = d.page
  await p.goto('/#/devices')
  await t(p, `revoke-${target}`).click()
  await t(p, 'phrase-input').fill(words.join(' '))
  await screens(d, '21-revoke')
  await t(p, 'revoke-submit').click()
  await waitDone(p, 'revoke-report', 10 * 60_000)
  await screens(d, '22-revoke-done')
  return t(p, 'revoke-report').locator('p').allTextContents()
}

/** The rows of one of the app's IndexedDB stores in this device's profile. */
export async function idb<T = any>(d: Device, store: string): Promise<T[]> {
  return d.page.evaluate(async (name) => {
    const db: IDBDatabase = await new Promise((res, rej) => {
      const r = indexedDB.open('winterlock')
      r.onsuccess = () => res(r.result)
      r.onerror = () => rej(r.error)
    })
    return new Promise<any[]>((res, rej) => {
      const q = db.transaction(name).objectStore(name).getAll()
      q.onsuccess = () => res(q.result)
      q.onerror = () => rej(q.error)
    })
  }, store)
}
