// What the board client needs from a link to a board: bytes out, bytes in, and word when the link
// goes away. Two implementations: Web Serial to a real board (serial.ts) and the virtual board, the
// board's own logic in WebAssembly in a worker (virtual.ts). Tests add their own.

export type LinkKind = 'serial' | 'virtual'

export interface TransportEvents {
  /** Bytes from the board, as they came: frames, and on a real board the bootloader's text too. */
  data(bytes: Uint8Array): void
  /** The link closed: unplugged, closed by the app, or the board's worker stopped. */
  closed(why: string): void
}

export interface Transport {
  readonly kind: LinkKind
  /** A name for the screen: "USB serial (CP2102)", "virtual board". */
  readonly label: string
  open(events: TransportEvents): Promise<void>
  write(bytes: Uint8Array): Promise<void>
  close(): Promise<void>
}
