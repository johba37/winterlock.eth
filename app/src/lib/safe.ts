// Safe transactions (safe.py): the fields, the core's encoding of them, the contract-signature
// form the Transaction Service takes, Safe's signature blob, and a decoder that shows what a
// transaction does. The SafeTx hash itself is always the core's.

import { type Address, decodeFunctionData, encodeFunctionData, getAddress, hexToBytes, isAddress, numberToHex, padHex, parseAbi, size, toFunctionSelector, toHex, zeroAddress } from 'viem'
import type { Hex } from './db'

export interface SafeTx {
  to: Address
  value: bigint
  data: Hex
  operation: 0 | 1
  safeTxGas: bigint
  baseGas: bigint
  gasPrice: bigint
  gasToken: Address
  refundReceiver: Address
  nonce: bigint
}

export function safeTx(fields: Partial<SafeTx> & { to: Address; nonce: bigint }): SafeTx {
  return {
    value: 0n,
    data: '0x',
    operation: 0,
    safeTxGas: 0n,
    baseGas: 0n,
    gasPrice: 0n,
    gasToken: zeroAddress,
    refundReceiver: zeroAddress,
    ...fields,
    to: getAddress(fields.to),
  }
}

/** As Safe's Transaction Service returns it. */
export function fromService(x: any): SafeTx {
  const op = Number(x.operation ?? 0)
  if (op !== 0 && op !== 1) throw new Error('operation must be 0 or 1')
  return {
    to: getAddress(x.to),
    value: BigInt(x.value ?? 0),
    data: (x.data ?? '0x') as Hex,
    operation: op,
    safeTxGas: BigInt(x.safeTxGas ?? 0),
    baseGas: BigInt(x.baseGas ?? 0),
    gasPrice: BigInt(x.gasPrice ?? 0),
    gasToken: getAddress(x.gasToken ?? zeroAddress),
    refundReceiver: getAddress(x.refundReceiver ?? zeroAddress),
    nonce: BigInt(x.nonce),
  }
}

/** As the Transaction Service takes it. */
export function toService(t: SafeTx) {
  return {
    to: t.to,
    value: t.value.toString(),
    data: t.data,
    operation: t.operation,
    safeTxGas: t.safeTxGas.toString(),
    baseGas: t.baseGas.toString(),
    gasPrice: t.gasPrice.toString(),
    gasToken: t.gasToken,
    refundReceiver: t.refundReceiver,
    nonce: Number(t.nonce),
  }
}

const word = (v: bigint) => hexToBytes(padHex(numberToHex(v), { size: 32 }))

/** The core's encoding: to ‖ value ‖ operation ‖ safeTxGas ‖ baseGas ‖ gasPrice ‖ gasToken ‖
 * refundReceiver ‖ nonce ‖ data (core-wasm, decode_tx). */
export function encodeForCore(t: SafeTx): Uint8Array {
  const data = hexToBytes(t.data)
  const out = new Uint8Array(221 + data.length)
  out.set(hexToBytes(t.to), 0)
  out.set(word(t.value), 20)
  out[52] = t.operation
  out.set(word(t.safeTxGas), 53)
  out.set(word(t.baseGas), 85)
  out.set(word(t.gasPrice), 117)
  out.set(hexToBytes(t.gasToken), 149)
  out.set(hexToBytes(t.refundReceiver), 169)
  out.set(word(t.nonce), 189)
  out.set(data, 221)
  return out
}

// --- signatures ---

/** One owner's standalone contract signature (v = 0): r = owner, s = 65, v = 0, then the data's
 * length and the data. The form the Transaction Service takes. */
export function contractSignature(owner: Address, data: Uint8Array): Hex {
  const out = new Uint8Array(97 + data.length)
  out.set(hexToBytes(padHex(owner, { size: 32 })), 0)
  out.set(word(65n), 32)
  out[64] = 0
  out.set(word(BigInt(data.length)), 65)
  out.set(data, 97)
  return toHex(out)
}

export interface ParsedSignature {
  owner?: Address
  data: Uint8Array
  contract: boolean
}

/** A standalone signature as the service returns it (safe.py's parse_signature). */
export function parseSignature(sig: Hex): ParsedSignature {
  const b = hexToBytes(sig)
  if (b.length >= 97 && b[64] === 0 && BigInt(toHex(b.slice(32, 64))) === 65n) {
    const n = Number(BigInt(toHex(b.slice(65, 97))))
    if (b.length !== 97 + n) throw new Error('contract signature length mismatch')
    return { owner: getAddress(toHex(b.slice(12, 32))), data: b.slice(97), contract: true }
  }
  if (b.length === 65) return { data: b, contract: false }
  throw new Error('unknown signature form')
}

/** The device number in an owner's transaction or message signature data, if it is one. */
export function signatureDevice(data: Uint8Array): number | undefined {
  if (data.length < 22 || data[0] === 0x03) return undefined
  return data[1] <= 3 ? data[1] : undefined
}

/** Safe's signatures blob, owners in increasing order (safe.py's pack). */
export function pack(sigs: { owner: Address; data: Uint8Array; contract: boolean }[]): Hex {
  const sorted = [...sigs].sort((a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : 1))
  const seen = new Set<string>()
  const parts: Uint8Array[] = []
  const dynamic: Uint8Array[] = []
  let dynLen = 0
  for (const s of sorted) {
    const o = s.owner.toLowerCase()
    if (seen.has(o)) throw new Error('an owner signs twice')
    seen.add(o)
    if (s.contract) {
      const head = new Uint8Array(65)
      head.set(hexToBytes(padHex(s.owner, { size: 32 })), 0)
      head.set(word(BigInt(65 * sorted.length + dynLen)), 32)
      parts.push(head)
      const d = new Uint8Array(32 + s.data.length)
      d.set(word(BigInt(s.data.length)), 0)
      d.set(s.data, 32)
      dynamic.push(d)
      dynLen += d.length
    } else {
      parts.push(s.data)
    }
  }
  const all = [...parts, ...dynamic]
  const out = new Uint8Array(all.reduce((n, p) => n + p.length, 0))
  let i = 0
  for (const p of all) {
    out.set(p, i)
    i += p.length
  }
  return toHex(out)
}

// --- ABI ---

export const SAFE_ABI = parseAbi([
  'function nonce() view returns (uint256)',
  'function getThreshold() view returns (uint256)',
  'function getOwners() view returns (address[])',
  'function VERSION() view returns (string)',
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)',
  'event ExecutionSuccess(bytes32 indexed txHash, uint256 payment)',
  'event ExecutionFailure(bytes32 indexed txHash, uint256 payment)',
])

export const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function balanceOf(address) view returns (uint256)',
])

export function execCalldata(t: SafeTx, signatures: Hex): Hex {
  return encodeFunctionData({
    abi: SAFE_ABI,
    functionName: 'execTransaction',
    args: [t.to, t.value, t.data, t.operation, t.safeTxGas, t.baseGas, t.gasPrice, t.gasToken, t.refundReceiver, signatures],
  })
}

/** The signatures blob of an execTransaction call, if `input` is one. */
export function execSignatures(input: Hex): Hex | undefined {
  try {
    const d = decodeFunctionData({ abi: SAFE_ABI, data: input })
    return d.functionName === 'execTransaction' ? (d.args[9] as Hex) : undefined
  } catch {
    return undefined
  }
}

/** An owner's contract signature data inside Safe's signatures blob, if it signed. */
export function blobSignatureOf(blob: Hex, owner: Address, threshold?: number): Uint8Array | undefined {
  const b = hexToBytes(blob)
  const k = threshold ?? Math.floor(b.length / 65)
  for (let i = 0; i < k && 65 * i + 65 <= b.length; i++) {
    const s = b.slice(65 * i, 65 * i + 65)
    if (s[64] !== 0) continue
    const who = toHex(s.slice(12, 32))
    if (!isAddress(who) || who.toLowerCase() !== owner.toLowerCase()) continue
    const off = Number(BigInt(toHex(s.slice(32, 64))))
    if (off + 32 > b.length) return undefined
    const n = Number(BigInt(toHex(b.slice(off, off + 32))))
    if (off + 32 + n > b.length) return undefined
    return b.slice(off + 32, off + 32 + n)
  }
  return undefined
}

// --- batches: Safe's MultiSendCallOnly ---

/** Safe v1.4.1's MultiSendCallOnly at its canonical address, and its release build's code hashes,
 * with and without the trailing CBOR metadata (signer/winterlock_signer/safe_libs.json). A batch is
 * a delegatecall to it; the app builds and decodes no other. */
export const MULTISEND = {
  address: getAddress('0x9641d764fc13c8B624c04430C7356C1C7C8102e2'),
  codeHash: '0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939' as Hex,
  codeWithoutMetadataHash: '0x020e0dff866e014dea0b8ad5e465ff39eb98d31aa3c7168371bbafa9fd01b68d' as Hex,
}

const MULTISEND_ABI = parseAbi(['function multiSend(bytes transactions) payable'])

export interface Call {
  to: Address
  value: bigint
  data: Hex
}

/** Runtime code without Solidity's CBOR metadata, whose length is in the last two bytes
 * (safelibs.py's strip_metadata). */
export function stripMetadata(code: Uint8Array): Uint8Array {
  if (code.length < 2) return code
  const n = ((code[code.length - 2] << 8) | code[code.length - 1]) + 2
  return n > code.length || n > 128 ? code : code.slice(0, code.length - n)
}

/** The calldata of multiSend(bytes) for calls: per call, operation 0 ‖ to ‖ value ‖ length ‖ data. */
export function multiSendData(calls: Call[]): Hex {
  const parts = calls.map((c) => {
    const data = hexToBytes(c.data)
    const out = new Uint8Array(85 + data.length)
    out[0] = 0
    out.set(hexToBytes(c.to), 1)
    out.set(word(c.value), 21)
    out.set(word(BigInt(data.length)), 53)
    out.set(data, 85)
    return out
  })
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let i = 0
  for (const p of parts) {
    all.set(p, i)
    i += p.length
  }
  return encodeFunctionData({ abi: MULTISEND_ABI, functionName: 'multiSend', args: [toHex(all)] })
}

/** A batch's SafeTx: a delegatecall to MultiSendCallOnly. */
export function batchTx(calls: Call[], nonce: bigint): SafeTx {
  return safeTx({ to: MULTISEND.address, data: multiSendData(calls), operation: 1, nonce })
}

/** The calls of a batch, if `t` is a delegatecall to MultiSendCallOnly v1.4.1 at its canonical
 * address whose payload parses exactly, with calls only; otherwise undefined. */
export function batchCalls(t: SafeTx): Call[] | undefined {
  if (t.operation !== 1 || t.value !== 0n || t.to.toLowerCase() !== MULTISEND.address.toLowerCase()) return undefined
  let payload: Uint8Array
  try {
    const d = decodeFunctionData({ abi: MULTISEND_ABI, data: t.data })
    if (encodeFunctionData({ abi: MULTISEND_ABI, functionName: 'multiSend', args: d.args as [Hex] }) !== t.data.toLowerCase()) return undefined
    payload = hexToBytes(d.args[0] as Hex)
  } catch {
    return undefined
  }
  const calls: Call[] = []
  for (let i = 0; i < payload.length; ) {
    if (payload.length - i < 85 || payload[i] !== 0) return undefined
    const to = getAddress(toHex(payload.slice(i + 1, i + 21)))
    const value = BigInt(toHex(payload.slice(i + 21, i + 53)))
    const n = BigInt(toHex(payload.slice(i + 53, i + 85)))
    if (n > BigInt(payload.length - i - 85)) return undefined
    calls.push({ to, value, data: toHex(payload.slice(i + 85, i + 85 + Number(n))) })
    i += 85 + Number(n)
  }
  return calls.length ? calls : undefined
}

// --- what a transaction does ---

export type Decoded =
  | { kind: 'cancel' }
  | { kind: 'eth'; to: Address; value: bigint }
  | { kind: 'erc20'; token: Address; to: Address; amount: bigint }
  | { kind: 'allowance'; token: Address; spender: Address; amount: bigint }
  | { kind: 'batch'; calls: { call: Call; decoding: Decoding }[] }
  | { kind: 'self'; what: string; to: Address; value: bigint; data: Hex }
  | { kind: 'approve'; to: Address; hash: Hex }
  | { kind: 'raw'; to: Address; value: bigint; data: Hex; selector: Hex }

export const MAX_UINT256 = 2n ** 256n - 1n

/** The tokens a decoded transaction names, for their symbols and decimals. */
export function tokensOf(d: Decoded): Address[] {
  if (d.kind === 'erc20' || d.kind === 'allowance') return [d.token]
  if (d.kind === 'batch') return d.calls.flatMap((c) => tokensOf(c.decoding.decoded))
  return []
}

const SAFE_SELF = parseAbi([
  'function addOwnerWithThreshold(address owner, uint256 threshold)',
  'function removeOwner(address prevOwner, address owner, uint256 threshold)',
  'function swapOwner(address prevOwner, address oldOwner, address newOwner)',
  'function changeThreshold(uint256 threshold)',
  'function enableModule(address module)',
  'function disableModule(address prevModule, address module)',
  'function setGuard(address guard)',
  'function setFallbackHandler(address handler)',
])

/** Whether a call from the Safe changes who or what controls it: a call to itself with one of
 * these selectors (safe.py's DANGEROUS, and disableModule). */
export function controlsSafe(c: { to: Address; data: Hex }, safe: Address): boolean {
  if (c.to.toLowerCase() !== safe.toLowerCase() || size(c.data) < 4) return false
  const sel = c.data.slice(0, 10).toLowerCase()
  return SAFE_SELF.some((f) => toFunctionSelector(f) === sel)
}

export interface Decoding {
  decoded: Decoded
  warnings: string[]
}

/** What a transaction does, decoded here rather than taken from a service (safe.py's decode). */
export function decode(t: SafeTx, safe: Address): Decoding {
  const warnings: string[] = []
  const calls = batchCalls(t)
  if (t.operation === 1 && !calls) warnings.push('DELEGATECALL: the called code runs as the Safe itself and can change anything in it')
  if (t.gasPrice || t.baseGas || t.safeTxGas || BigInt(t.gasToken) || BigInt(t.refundReceiver)) {
    warnings.push('Refund fields are set: the Safe pays whoever executes it')
  }
  if (calls) {
    // each call decoded as the Safe making it; their warnings are the batch's
    const inner = calls.map((call) => ({ call, decoding: decode(safeTx({ ...call, nonce: t.nonce }), safe) }))
    inner.forEach((c, i) => warnings.push(...c.decoding.warnings.map((w) => `Call ${i + 1}: ${w}`)))
    return { decoded: { kind: 'batch', calls: inner }, warnings }
  }
  const self = t.to.toLowerCase() === safe.toLowerCase()
  if (self && t.value === 0n && t.data === '0x' && t.operation === 0) return { decoded: { kind: 'cancel' }, warnings }
  if (t.data === '0x' || size(t.data) === 0) return { decoded: { kind: 'eth', to: t.to, value: t.value }, warnings }
  if (t.operation === 0 && t.value === 0n) {
    try {
      const d = decodeFunctionData({ abi: ERC20_ABI, data: t.data })
      const exact = (name: 'transfer' | 'approve') =>
        d.functionName === name && encodeFunctionData({ abi: ERC20_ABI, functionName: name, args: d.args as [Address, bigint] }) === t.data.toLowerCase()
      if (exact('transfer')) {
        return { decoded: { kind: 'erc20', token: t.to, to: getAddress(d.args[0] as Address), amount: d.args[1] as bigint }, warnings }
      }
      if (exact('approve')) {
        const amount = d.args[1] as bigint
        if (amount === MAX_UINT256) warnings.push('Unlimited allowance: the spender may take all of this token the Safe holds, now and later')
        return { decoded: { kind: 'allowance', token: t.to, spender: getAddress(d.args[0] as Address), amount }, warnings }
      }
    } catch {
      /* not a transfer or an allowance */
    }
  }
  if (!self && t.operation === 0 && t.value === 0n && size(t.data) === 36 && t.data.slice(0, 10).toLowerCase() === '0xd4d9bdcd') {
    // approveHash(bytes32) on another Safe: this Safe approves one of that Safe's transactions
    warnings.push('This approves a transaction of another Safe: check that one too')
    return { decoded: { kind: 'approve', to: t.to, hash: `0x${t.data.slice(10)}` as Hex }, warnings }
  }
  if (self) {
    try {
      const d = decodeFunctionData({ abi: SAFE_SELF, data: t.data })
      warnings.push('This changes who or what controls the Safe')
      return { decoded: { kind: 'self', what: d.functionName, to: t.to, value: t.value, data: t.data }, warnings }
    } catch {
      /* raw below */
    }
  }
  warnings.push('Not decoded: check the raw call before signing')
  return { decoded: { kind: 'raw', to: t.to, value: t.value, data: t.data, selector: t.data.slice(0, 10) as Hex }, warnings }
}

/** Wei as ETH, exactly (safe.py's fmt_eth, without the wei). */
export function formatUnits(v: bigint, decimals: number): string {
  const neg = v < 0n
  const a = neg ? -v : v
  const base = 10n ** BigInt(decimals)
  const whole = a / base
  const frac = (a % base).toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${neg ? '-' : ''}${whole.toLocaleString('en-US')}${frac ? '.' + frac : ''}`
}

/** "0.01" in units of `decimals` as an integer; refuses more decimals than the token has. */
export function parseUnits(s: string, decimals: number): bigint {
  const t = s.trim().replace(/,/g, '')
  if (!/^\d*(\.\d*)?$/.test(t) || t === '' || t === '.') throw new Error('Enter an amount such as 0.01')
  const [w, f = ''] = t.split('.')
  if (f.length > decimals) throw new Error(`At most ${decimals} decimals`)
  return BigInt(w || '0') * 10n ** BigInt(decimals) + BigInt((f + '0'.repeat(decimals)).slice(0, decimals) || '0')
}
