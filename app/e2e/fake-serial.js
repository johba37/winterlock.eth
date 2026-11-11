// A stand-in for Web Serial in the page, whose one port is bridged to the test process (and from
// there to the board's firmware in QEMU, on QEMU's TCP serial port): the app's own Web Serial code
// runs unchanged on it. Plain JavaScript, added to the page before the app loads
// (page.addInitScript); the test process answers through these bindings (exposeBinding) and drives
// the port with window.__fakeSerial.push(bytes), .unplug() and .plug().
//
//   page -> test: __serialOpen(baud), __serialWrite(bytes as number[]), __serialSignals(signals),
//                 __serialRequested(filters)
//
// It behaves as Chrome's does where the app depends on it: open() on an open or unplugged port
// fails; an unplugged port's readable errors with a NetworkError and becomes null, and a
// "disconnect" event whose target is the port reaches navigator.serial; plugging it back in fires
// "connect" the same way.
;(() => {
  const w = window
  const serial = new EventTarget()
  const fire = (type, port) => {
    const ev = new Event(type)
    Object.defineProperty(ev, 'target', { value: port })
    serial.dispatchEvent(ev)
  }
  class FakePort extends EventTarget {
    constructor() {
      super()
      this.readable = null
      this.writable = null
      this.connected = true
      this.ctl = null
    }
    getInfo() {
      return { usbVendorId: 0x10c4, usbProductId: 0xea60 }
    }
    async open(o) {
      if (!this.connected) throw new DOMException('Failed to open serial port.', 'NetworkError')
      if (this.readable) throw new DOMException('The port is already open.', 'InvalidStateError')
      await w.__serialOpen(o.baudRate)
      this.readable = new ReadableStream({
        start: (c) => {
          this.ctl = c
        },
        cancel: () => {
          this.ctl = null
        },
      })
      this.writable = new WritableStream({
        write: async (chunk) => {
          if (!this.connected) throw new DOMException('The device has been lost.', 'NetworkError')
          await w.__serialWrite(Array.from(chunk))
        },
      })
    }
    async close() {
      try {
        this.ctl?.close()
      } catch {}
      this.ctl = null
      this.readable = null
      this.writable = null
    }
    async setSignals(s) {
      await w.__serialSignals(s)
    }
    push(bytes) {
      try {
        this.ctl?.enqueue(new Uint8Array(bytes))
      } catch {}
    }
    unplug() {
      this.connected = false
      try {
        this.ctl?.error(new DOMException('The device has been lost.', 'NetworkError'))
      } catch {}
      this.ctl = null
      this.readable = null
      this.writable = null
      fire('disconnect', this)
    }
    plug() {
      this.connected = true
      fire('connect', this)
    }
  }
  const port = new FakePort()
  let granted = false
  serial.requestPort = async (o) => {
    await w.__serialRequested((o && o.filters) || [])
    granted = true
    return port
  }
  serial.getPorts = async () => (granted ? [port] : [])
  Object.defineProperty(navigator, 'serial', { value: serial, configurable: true })
  w.__fakeSerial = { push: (b) => port.push(b), unplug: () => port.unplug(), plug: () => port.plug() }
})()
