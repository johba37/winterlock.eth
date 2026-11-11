// Safe transactions (safe.py): the fields, the core's encoding of them, the contract-signature
// form the Transaction Service takes, Safe's signature blob, and a decoder that shows what a
// transaction does. The SafeTx hash itself is always the core's.

import { type Address, decodeFunctionData, encodeFunctionData, getAddress, hexToBytes, isAddress, numberToHex, padHex, parseAbi, size, toHex, zeroAddress } from 'viem'
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

// --- what a transaction does ---

export type Decoded =
  | { kind: 'cancel' }
  | { kind: 'eth'; to: Address; value: bigint }
  | { kind: 'erc20'; token: Address; to: Address; amount: bigint }
  | { kind: 'self'; what: string; to: Address; value: bigint; data: Hex }
  | { kind: 'approve'; to: Address; hash: Hex }
  | { kind: 'raw'; to: Address; value: bigint; data: Hex; selector: Hex }

const SAFE_SELF = parseAbi([
  'function addOwnerWithThreshold(address owner, uint256 threshold)',
  'function removeOwner(address prevOwner, address owner, uint256 threshold)',
  'function swapOwner(address prevOwner, address oldOwner, address newOwner)',
  'function changeThreshold(uint256 threshold)',
  'function enableModule(address module)',
  'function setGuard(address guard)',
  'function setFallbackHandler(address handler)',
])

export interface Decoding {
  decoded: Decoded
  warnings: string[]
}

/** What a transaction does, decoded here rather than taken from a service (safe.py's decode). */
export function decode(t: SafeTx, safe: Address): Decoding {
  const warnings: string[] = []
  if (t.operation === 1) warnings.push('DELEGATECALL: the called code runs as the Safe itself and can change anything in it')
  if (t.gasPrice || t.baseGas || t.safeTxGas || BigInt(t.gasToken) || BigInt(t.refundReceiver)) {
    warnings.push('Refund fields are set: the Safe pays whoever executes it')
  }
  const self = t.to.toLowerCase() === safe.toLowerCase()
  if (self && t.value === 0n && t.data === '0x' && t.operation === 0) return { decoded: { kind: 'cancel' }, warnings }
  if (t.data === '0x' || size(t.data) === 0) return { decoded: { kind: 'eth', to: t.to, value: t.value }, warnings }
  if (t.operation === 0 && t.value === 0n) {
    try {
      const d = decodeFunctionData({ abi: ERC20_ABI, data: t.data })
      if (d.functionName === 'transfer' && encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: d.args as [Address, bigint] }) === t.data.toLowerCase()) {
        return { decoded: { kind: 'erc20', token: t.to, to: getAddress(d.args[0] as Address), amount: d.args[1] as bigint }, warnings }
      }
    } catch {
      /* not a transfer */
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
