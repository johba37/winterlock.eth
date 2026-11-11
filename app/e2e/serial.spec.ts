// The app's Web Serial code against the board's real firmware: the test image in Espressif's QEMU,
// its serial port on TCP, bridged into the page by a stand-in for navigator.serial (fake-serial.js)
// whose port reads and writes QEMU's bytes, bootloader text and all. The member's hands are the test
// image's hooks (TEST_BUTTONS), sent by this process on the same port.
//
//   the chooser's filters; setup on the board (QEMU) through the app; the reset button (QEMU
//   restarted, the port open: BOOTED, locked, the PIN); an unplug (QEMU killed, the port lost) and
//   a replug (the port's connect event: the app opens it again by itself); then on a local chain,
//   an enrolment (deployAndEnroll) and a transfer signed by the firmware, executed.
//
// Needs QEMU (QEMU, Espressif's qemu-system-xtensa) and the firmware's test image
// (BOARD_TEST_IMAGE: winterlock-board-test-qemu.bin), and for the chain part what local.ts needs.

import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { type Page, expect, test } from '@playwright/test'
import { type Address, getAddress, hexToBytes, toHex } from 'viem'
import * as core from '../src/wasm/core.js'
import { FakeService } from './fake-service'
import { BOB, LocalChain, boardRecord, haveChainTools, joinSafe, shot as shotIn, tid as t, useLocalRpc, waitDone } from './local'
import { QemuBoard, confirmOnQemu, pinKeys, setupOnQemu } from './qemu'

const here = dirname(fileURLToPath(import.meta.url))
const QEMU = process.env.QEMU ?? 'qemu-system-xtensa'
const IMAGE = process.env.BOARD_TEST_IMAGE ?? ''
const OUT = join(process.env.E2E_DIR ?? join(here, '..', 'test-results'), 'serial')
const shot = (p: Page, name: string) => shotIn(p, OUT, name)
const PIN = [2, 0, 2, 6]

core.initSync({ module: readFileSync(new URL('../src/wasm/core_bg.wasm', import.meta.url)) })

test('Web Serial against the firmware in QEMU', async ({ page, baseURL }) => {
  test.skip(!IMAGE || !existsSync(IMAGE), 'needs BOARD_TEST_IMAGE (and QEMU)')
  test.setTimeout(60 * 60_000)
  mkdirSync(OUT, { recursive: true })
  const log = (...a: unknown[]) => console.log('  ', ...a)
  const since = (t0: number) => `${((Date.now() - t0) / 1000).toFixed(1)} s`
  page.on('pageerror', (e) => log(`page error: ${e.message}`))

  const q = QemuBoard.fromImage(QEMU, IMAGE, join(OUT, 'flash.bin'))
  const requested: unknown[] = []
  const signals: unknown[] = []
  const bauds: number[] = []
  // QEMU's bytes into the page's port, in order
  let pushing = Promise.resolve()
  const attach = () => {
    q.onData = (b) => {
      const bytes = Array.from(b)
      pushing = pushing.then(() => page.evaluate((x) => (window as any).__fakeSerial.push(x), bytes).catch(() => {}))
    }
  }
  await page.exposeBinding('__serialRequested', (_s, f) => void requested.push(f))
  await page.exposeBinding('__serialOpen', (_s, baud: number) => void bauds.push(baud))
  await page.exposeBinding('__serialSignals', (_s, x) => void signals.push(x))
  await page.exposeBinding('__serialWrite', (_s, bytes: number[]) => q.write(Uint8Array.from(bytes)))
  await page.addInitScript({ path: join(here, 'fake-serial.js') })

  const chain = haveChainTools() ? new LocalChain() : null
  try {
    if (chain) await chain.start()
    attach()
    let t0 = Date.now()
    await q.start()
    await q.waitBooted(1)
    log(`QEMU booted the test image in ${since(t0)}`)

    if (chain) await useLocalRpc(page, baseURL!, chain.url)
    else await page.goto(`${baseURL}/#/`)

    await test.step('connect by USB: the chooser’s filters, 115200 baud, the board’s status', async () => {
      await page.goto(`${baseURL}/#/board`)
      await t(page, 'connect-usb').click()
      await expect(t(page, 'board-state')).toContainText('A new or erased board', { timeout: 30_000 })
      expect(requested[0]).toEqual([
        { usbVendorId: 0x10c4, usbProductId: 0xea60 },
        { usbVendorId: 0x1a86, usbProductId: 0x7523 },
        { usbVendorId: 0x1a86, usbProductId: 0x55d4 },
        { usbVendorId: 0x0403, usbProductId: 0x6001 },
      ])
      expect(bauds).toEqual([115200])
      expect(signals[0]).toEqual({ dataTerminalReady: false, requestToSend: false })
      await expect(t(page, 'link-state')).toContainText('blank')
    })

    let owner: Address
    await test.step('setup on the board, through the app', async () => {
      t0 = Date.now()
      await t(page, 'board-setup').click()
      const words = await setupOnQemu(q, PIN)
      await expect(t(page, 'board-done')).toBeVisible({ timeout: 600_000 })
      log(`setup through the app: ${since(t0)} from SETUP to the app's done screen (the member key in QEMU included)`)
      owner = getAddress((await t(page, 'owner-address').getAttribute('data-value'))!)
      // the core, from the words the board showed: the same member key and owner
      const seed = core.phrase_to_seed(words.join(' '))
      const kb = core.KeyBuilder.member(seed)
      while (kb.done() < kb.total()) kb.step(256)
      const mk = kb.finish()
      const rec = await boardRecord(page)
      expect(rec.memberKey).toBe(toHex(mk.public_key()))
      expect(owner).toBe(getAddress(toHex(mk.owner())))
      expect(toHex(core.gas_key(seed))).toBe(rec.gasKey)
      expect(rec.link).toBe('serial')
      await shot(page, '01-board-ready-usb')
      await q.press('RR')
      await t(page, 'done-home').click()
      await expect(t(page, 'home')).toBeVisible()
    })

    await test.step('the reset button: BOOTED on the open port, locked, the PIN on the board', async () => {
      await q.kill()
      await q.start()
      await expect(t(page, 'link-state')).toHaveAttribute('data-state', 'locked', { timeout: 120_000 })
      await expect(t(page, 'link-state')).toHaveAttribute('data-phase', 'connected')
      await expect(t(page, 'enter-pin')).toBeVisible()
      await shot(page, '02-locked-after-reset')
      await q.until(/^Enter PIN/)
      await q.press(pinKeys(PIN))
      await expect(t(page, 'link-state')).toHaveAttribute('data-state', 'unlocked', { timeout: 30_000 })
    })

    await test.step('unplugged, then plugged in again: the app opens the port by itself', async () => {
      await q.kill()
      await page.evaluate(() => (window as any).__fakeSerial.unplug())
      await expect(t(page, 'link-state')).toHaveAttribute('data-phase', 'disconnected', { timeout: 10_000 })
      await expect(t(page, 'link-state')).toContainText('unplugged')
      await shot(page, '03-unplugged')
      const booted = q.booted.length
      await q.start()
      await q.waitBooted(booted + 1)
      await page.evaluate(() => (window as any).__fakeSerial.plug())
      await expect(t(page, 'link-state')).toHaveAttribute('data-state', 'locked', { timeout: 60_000 })
      expect(bauds).toEqual([115200, 115200])
      await q.until(/^Enter PIN/)
      await q.press(pinKeys(PIN))
      await expect(t(page, 'link-state')).toHaveAttribute('data-state', 'unlocked', { timeout: 30_000 })
    })

    if (!chain) {
      log('no anvil or Python signer: the chain part is skipped')
      return
    }

    let safe: Address
    await test.step('on a local chain: enrol on the firmware, through the app (deployAndEnroll)', async () => {
      const rec = await boardRecord(page)
      await chain.setBalance(rec.gasAddress, 10n ** 19n)
      safe = await chain.createSafe([owner], 7n)
      await joinSafe(page, baseURL!, safe)
      await expect(t(page, 'enrol')).toBeEnabled({ timeout: 30_000 })
      t0 = Date.now()
      await t(page, 'enrol').click()
      const pages = await confirmOnQemu(q)
      expect(pages[0][0]).toMatch(/^Enrol key tree/)
      await expect(t(page, 'tree-state')).toHaveAttribute('data-left', '512', { timeout: 1_800_000 })
      log(`enrolment on the firmware in QEMU, sent from the gas account: ${since(t0)} (tree and certificate in QEMU included)`)
      await shot(page, '04-enrolled-usb')
      await q.press('R')
    })

    await test.step('a transfer signed by the firmware, proposed and executed', async () => {
      const svc = new FakeService(chain.client() as any)
      await svc.install(page)
      await page.goto(`${baseURL}/#/safe/11155111/${safe}/send`)
      await t(page, 'to-input').fill(BOB)
      await t(page, 'amount-input').fill('0.125')
      await t(page, 'review').click()
      t0 = Date.now()
      await t(page, 'sign-propose').click()
      const pages = await confirmOnQemu(q)
      await waitDone(page, t(page, 'done'), 600_000)
      log(`transfer confirmed on the firmware (${pages.map((p) => p[0]).join(' / ')}): ${since(t0)}`)
      await q.press('R')
      const hash = (await t(page, 'done').getAttribute('data-hash'))!
      await page.goto(`${baseURL}/#/safe/11155111/${safe}/tx/${hash}`)
      const before = await chain.client().getBalance({ address: BOB })
      await t(page, 'execute').click()
      await waitDone(page, page.locator('[data-testid="done"][data-tx^="0x"]'))
      expect((await chain.client().getBalance({ address: BOB })) - before).toBe(125n * 10n ** 15n)
      // the signature the service holds is the firmware's, and the core reads it as its tree's
      const sig = hexToBytes(svc.txs.get(hash.toLowerCase())!.confirmations[0].signature)
      expect(sig[97 + 1]).toBe(0) // device 0: the member key's tree
      await shot(page, '05-executed-usb')
    })
    log(`over the fake port: the app wrote ${q.written.toLocaleString()} bytes; the board sent ${q.read.toLocaleString()}, the bootloader's and the test build's text included`)
  } finally {
    await q.kill()
    chain?.stop()
  }
})
