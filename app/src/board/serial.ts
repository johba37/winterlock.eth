// A board on USB, through Web Serial (Chrome and Edge on desktops): its USB serial chip at 115200
// baud, 8N1. The port carries the bootloader's text at every start as well as the board's frames;
// the client's reader finds the frames among it.
//
// The chooser lists the usual USB serial chips of ESP32 boards; "all ports" lists everything.
// DTR and RTS are set low once the port is open, as the Python client does: on the usual ESP32
// boards they drive the reset and BOOT lines (only the real board can tell how each system's
// driver toggles them on open).

import type { Transport, TransportEvents } from './transport'

export const CHIPS: { usbVendorId: number; usbProductId: number; name: string }[] = [
  { usbVendorId: 0x10c4, usbProductId: 0xea60, name: 'CP2102' },
  { usbVendorId: 0x1a86, usbProductId: 0x7523, name: 'CH340' },
  { usbVendorId: 0x1a86, usbProductId: 0x55d4, name: 'CH9102' },
  { usbVendorId: 0x0403, usbProductId: 0x6001, name: 'FTDI FT232R' },
]

export const BAUD = 115200

export function serialSupported(): boolean {
  return typeof navigator !== 'undefined' && !!navigator.serial
}

function serial(): Serial {
  if (!navigator.serial) throw new Error('This browser has no Web Serial: use Chrome or Edge on a computer.')
  return navigator.serial
}

const hex4 = (n?: number) => (n === undefined ? '?' : n.toString(16).padStart(4, '0'))

export function chipName(info: SerialPortInfo): string {
  const c = CHIPS.find((x) => x.usbVendorId === info.usbVendorId && x.usbProductId === info.usbProductId)
  return c ? c.name : info.usbVendorId === undefined ? 'a serial port' : `USB ${hex4(info.usbVendorId)}:${hex4(info.usbProductId)}`
}

/** The browser's port chooser (needs a click): the usual chips, or every port. */
export async function choosePort(allPorts = false): Promise<SerialPort> {
  return serial().requestPort(allPorts ? {} : { filters: CHIPS.map(({ usbVendorId, usbProductId }) => ({ usbVendorId, usbProductId })) })
}

/** Ports this site was allowed before, connected now. */
export async function grantedPorts(): Promise<SerialPort[]> {
  if (!serialSupported()) return []
  const ports = await serial().getPorts()
  return ports.filter((p) => p.connected !== false)
}

export class SerialTransport implements Transport {
  readonly kind = 'serial' as const
  private reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  private reading: Promise<void> | undefined
  private closing = false
  private events: TransportEvents | undefined
  private onDisconnect = (e: Event) => {
    if (e.target === this.port) this.lost('the board was unplugged')
  }

  constructor(readonly port: SerialPort) {}

  get label() {
    return `USB serial (${chipName(this.port.getInfo())})`
  }

  async open(events: TransportEvents) {
    this.events = events
    this.closing = false
    try {
      await this.port.open({ baudRate: BAUD, dataBits: 8, stopBits: 1, parity: 'none', flowControl: 'none', bufferSize: 64 * 1024 })
    } catch (e) {
      throw new Error(`The serial port didn’t open (${(e as Error).message}). Another tab or program may hold it: close that first.`)
    }
    try {
      await this.port.setSignals({ dataTerminalReady: false, requestToSend: false })
    } catch {
      /* not every driver takes it */
    }
    serial().addEventListener('disconnect', this.onDisconnect)
    this.reading = this.read()
  }

  private async read() {
    // a recoverable error (a framing or overrun error) gives a new readable; a lost device doesn't
    while (!this.closing && this.port.readable) {
      const r = this.port.readable.getReader()
      this.reader = r
      try {
        for (;;) {
          const { value, done } = await r.read()
          if (done) break
          if (value?.length) this.events?.data(value)
        }
      } catch {
        /* the next loop decides: a new readable, or the end */
      } finally {
        r.releaseLock()
        this.reader = undefined
      }
    }
    if (!this.closing) this.lost('the board’s serial port closed')
  }

  private lost(why: string) {
    if (this.closing) return
    this.closing = true
    serial().removeEventListener('disconnect', this.onDisconnect)
    const ev = this.events
    this.events = undefined
    this.port.close().catch(() => {})
    ev?.closed(why)
  }

  async write(bytes: Uint8Array) {
    const w = this.port.writable?.getWriter()
    if (!w) throw new Error('the serial port isn’t open')
    try {
      await w.write(bytes)
    } finally {
      w.releaseLock()
    }
  }

  async close() {
    this.closing = true
    serial().removeEventListener('disconnect', this.onDisconnect)
    this.events = undefined
    try {
      await this.reader?.cancel()
    } catch {
      /* already gone */
    }
    await this.reading?.catch(() => {})
    try {
      await this.port.close()
    } catch {
      /* unplugged: nothing to close */
    }
  }
}
