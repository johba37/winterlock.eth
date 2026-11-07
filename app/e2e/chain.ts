// The live run's own transactions, outside the app: funding test accounts, and a fresh test Safe
// made by script as a team would have it before the app joins (Safe v1.4.1, SafeL2, canonical
// factory on Sepolia), owned by an ECDSA test key that then adds the members' owners with
// addOwnerWithThreshold, as Safe's app would.

import { type Address, type Hex, createPublicClient, createWalletClient, encodeFunctionData, getAddress, http, parseAbi, zeroAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { log, rpcUrl, secrets } from './env'

// Safe v1.4.1 canonical deployments on Sepolia (signer/tools/live_check.py)
export const SAFE_141 = {
  singleton: '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762' as Address,
  factory: '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67' as Address,
  fallbackHandler: '0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99' as Address,
}

const SAFE = parseAbi([
  'function setup(address[] owners, uint256 threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)',
  'function nonce() view returns (uint256)',
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function addOwnerWithThreshold(address owner, uint256 threshold)',
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)',
])
const FACTORY = parseAbi(['function createProxyWithNonce(address singleton, bytes initializer, uint256 saltNonce) returns (address proxy)'])
const OWNER = parseAbi(['function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)'])

export function client() {
  return createPublicClient({ chain: sepolia, transport: http(rpcUrl(), { retryCount: 3 }) })
}

function wallet(key: Hex) {
  return createWalletClient({ chain: sepolia, account: privateKeyToAccount(key), transport: http(rpcUrl(), { retryCount: 3 }) })
}

export const funder = () => privateKeyToAccount(secrets().fund)

export async function send(key: Hex, to: Address, data: Hex = '0x', value = 0n): Promise<{ hash: Hex; gasUsed: bigint }> {
  const w = wallet(key)
  const hash = await w.sendTransaction({ to, data, value })
  const r = await client().waitForTransactionReceipt({ hash, timeout: 600_000, pollingInterval: 3000 })
  if (r.status !== 'success') throw new Error(`reverted: ${hash}`)
  return { hash, gasUsed: r.gasUsed }
}

export async function fund(to: Address, value: bigint) {
  const r = await send(secrets().fund, to, '0x', value)
  log(`  funded ${to} with ${value} wei: ${r.hash}`)
  return r
}

export async function balance(a: Address) {
  return client().getBalance({ address: a })
}

/** A new Safe owned by `owner` alone (threshold 1). */
export async function createSafe(owner: Address, salt: bigint): Promise<{ safe: Address; hash: Hex; gasUsed: bigint }> {
  const init = encodeFunctionData({ abi: SAFE, functionName: 'setup', args: [[owner], 1n, zeroAddress, '0x', SAFE_141.fallbackHandler, zeroAddress, 0n, zeroAddress] })
  const c = client()
  const { result } = await c.simulateContract({ account: funder(), address: SAFE_141.factory, abi: FACTORY, functionName: 'createProxyWithNonce', args: [SAFE_141.singleton, init, salt] })
  const r = await send(secrets().fund, SAFE_141.factory, encodeFunctionData({ abi: FACTORY, functionName: 'createProxyWithNonce', args: [SAFE_141.singleton, init, salt] }))
  const code = await c.getCode({ address: result })
  if (!code || code === '0x') throw new Error('Safe creation failed')
  return { safe: getAddress(result), ...r }
}

/** addOwnerWithThreshold signed by the Safe's ECDSA owner (threshold 1) and executed by the funder. */
export async function addOwner(safe: Address, ecdsaKey: Hex, newOwner: Address, threshold: bigint) {
  const c = client()
  const data = encodeFunctionData({ abi: SAFE, functionName: 'addOwnerWithThreshold', args: [newOwner, threshold] })
  const nonce = await c.readContract({ address: safe, abi: SAFE, functionName: 'nonce' })
  const hash = await c.readContract({ address: safe, abi: SAFE, functionName: 'getTransactionHash', args: [safe, 0n, data, 0, 0n, 0n, 0n, zeroAddress, zeroAddress, nonce] })
  const sig = await privateKeyToAccount(ecdsaKey).sign({ hash })
  const exec = encodeFunctionData({ abi: SAFE, functionName: 'execTransaction', args: [safe, 0n, data, 0, 0n, 0n, 0n, zeroAddress, zeroAddress, sig] })
  return send(secrets().fund, safe, exec)
}

export async function owners(safe: Address) {
  const c = client()
  return {
    owners: (await c.readContract({ address: safe, abi: SAFE, functionName: 'getOwners' })).map((o) => getAddress(o)),
    threshold: Number(await c.readContract({ address: safe, abi: SAFE, functionName: 'getThreshold' })),
    nonce: Number(await c.readContract({ address: safe, abi: SAFE, functionName: 'nonce' })),
  }
}

/** What an owner contract answers for a signature, by eth_call: the magic value or not. */
export async function ownerAccepts(owner: Address, hash: Hex, data: Hex): Promise<string> {
  try {
    return await client().readContract({ address: owner, abi: OWNER, functionName: 'isValidSignature', args: [hash, data] })
  } catch (e) {
    return `reverted: ${(e as Error).message.split('\n')[0]}`
  }
}

export async function receipt(hash: Hex) {
  return client().getTransactionReceipt({ hash })
}

/** Waits until Safe's service knows the Safe with these owners. */
export async function waitIndexed(safe: Address, want: Address[], tries = 45) {
  const base = 'https://api.safe.global/tx-service/sep/api'
  for (let i = 0; i < tries; i++) {
    const r = await fetch(`${base}/v1/safes/${safe}/`)
    if (r.status === 200) {
      const j = await r.json()
      const have = (j.owners as string[]).map((o) => o.toLowerCase())
      if (want.every((w) => have.includes(w.toLowerCase()))) return { polls: i + 1, info: j }
    }
    await new Promise((res) => setTimeout(res, 20_000))
  }
  throw new Error('the service never indexed the Safe with its owners')
}
