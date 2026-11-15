// The parts of the Web Serial API (WICG) the app uses: in Chrome and Edge on desktops, not in
// TypeScript's DOM library.

interface SerialPortFilter {
  usbVendorId?: number
  usbProductId?: number
}

interface SerialPortInfo {
  usbVendorId?: number
  usbProductId?: number
}

interface SerialOptions {
  baudRate: number
  dataBits?: number
  stopBits?: number
  parity?: 'none' | 'even' | 'odd'
  bufferSize?: number
  flowControl?: 'none' | 'hardware'
}

interface SerialOutputSignals {
  dataTerminalReady?: boolean
  requestToSend?: boolean
  break?: boolean
}

interface SerialPort extends EventTarget {
  readonly readable: ReadableStream<Uint8Array> | null
  readonly writable: WritableStream<Uint8Array> | null
  readonly connected?: boolean
  open(options: SerialOptions): Promise<void>
  close(): Promise<void>
  getInfo(): SerialPortInfo
  setSignals(signals: SerialOutputSignals): Promise<void>
  forget?(): Promise<void>
}

interface Serial extends EventTarget {
  getPorts(): Promise<SerialPort[]>
  requestPort(options?: { filters?: SerialPortFilter[] }): Promise<SerialPort>
}

interface Navigator {
  readonly serial?: Serial
}

interface WorkerNavigator {
  readonly serial?: Serial
}
