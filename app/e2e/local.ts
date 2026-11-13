// A local chain for the board runs (board.spec.ts, serial.spec.ts): anvil with Sepolia's chain id,
// owner v2's shared contracts at their pinned addresses and a Safe v1.4.1 release (local_chain.py),
// Safes made by script, and the app's steps that both runs share. Spends nothing.
//
// Needs Foundry's anvil (ANVIL, default ~/.foundry/bin/anvil), the Python signer's virtualenv
// (WINTERLOCK_PYTHON) and Safe v1.4.1's build (SAFE_141_BUILD).

import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import { createServer } from 'node:net'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { type Locator, type Page, expect } from '@playwright/test'
import { type Address, type Hex, createPublicClient, createWalletClient, encodeFunctionData, getAddress, http, keccak256, parseAbi, toHex, zeroAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const here = dirname(fileURLToPath(import.meta.url))
const repo = resolve(here, '../..')
export const PYTHON = process.env.WINTERLOCK_PYTHON ?? resolve(repo, 'signer/.venv/bin/python')
export const ANVIL = process.env.ANVIL ?? join(homedir(), '.foundry/bin/anvil')
// anvil's first default account: a public test key, local chains only
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
export const BOB = getAddress(keccak256(toHex('board run: recipient')).slice(0, 42))
export const haveChainTools = () => existsSync(ANVIL) && existsSync(PYTHON)

export const SAFE_ABI = parseAbi([
  'function setup(address[] owners, uint256 threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)',
  'function nonce() view returns (uint256)',
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)',
  'function approvedHashes(address owner, bytes32 hash) view returns (uint256)',
  'function approveHash(bytes32 hashToApprove)',
])
const FACTORY_ABI = parseAbi(['function createProxyWithNonce(address singleton, bytes initializer, uint256 saltNonce) returns (address proxy)'])
export const OWNER_FACTORY = parseAbi(['function predict(bytes32 key) view returns (address)'])

export function freePort(): Promise<number> {
  return new Promise((res) => {
    const s = createServer()
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as any).port
      s.close(() => res(p))
    })
  })
}

export interface Deployed {
  factory: Address
  safe: { singleton: Address; factory: Address; fallback_handler: Address }
}

export class LocalChain {
  private proc: ChildProcess | undefined
  url = ''
  deployed!: Deployed

  async start() {
    const port = await freePort()
    this.url = `http://127.0.0.1:${port}`
    this.proc = spawn(ANVIL, ['--port', String(port), '--chain-id', '11155111', '--silent', '--disable-code-size-limit', '--disable-block-gas-limit'], { stdio: 'ignore' })
    for (let i = 0; ; i++) {
      try {
        await this.client().getChainId()
        break
      } catch {
        if (i > 100) throw new Error('anvil didn’t start')
        await new Promise((r) => setTimeout(r, 100))
      }
    }
    const r = spawnSync(PYTHON, ['-I', join(here, 'local_chain.py'), this.url], { encoding: 'utf8' })
    if (r.status !== 0) throw new Error(`local_chain.py: ${r.stderr}`)
    this.deployed = JSON.parse(r.stdout)
  }

  stop() {
    this.proc?.kill()
  }

  client() {
    return createPublicClient({ transport: http(this.url) })
  }

  private wallet() {
    const url = this.url
    return createWalletClient({
      account: privateKeyToAccount(ANVIL_KEY),
      transport: http(url),
      chain: { id: 11155111, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [url] } } },
    })
  }

  async send(to: Address, data: Hex, value = 0n) {
    const hash = await this.wallet().sendTransaction({ to, data, value })
    const r = await this.client().waitForTransactionReceipt({ hash })
    if (r.status !== 'success') throw new Error(`reverted: ${hash}`)
    return r
  }

  async setBalance(a: Address, wei: bigint) {
    await this.client().request({ method: 'anvil_setBalance' as any, params: [a, toHex(wei)] as any })
  }

  /** A Safe v1.4.1 (SafeL2) with these owners, threshold 1, holding 1 ETH. */
  async createSafe(owners: Address[], salt: bigint): Promise<Address> {
    const d = this.deployed.safe
    const init = encodeFunctionData({ abi: SAFE_ABI, functionName: 'setup', args: [owners, 1n, zeroAddress, '0x', d.fallback_handler, zeroAddress, 0n, zeroAddress] })
    const args = [d.singleton, init, salt] as const
    const { result } = await this.client().simulateContract({ account: privateKeyToAccount(ANVIL_KEY), address: d.factory, abi: FACTORY_ABI, functionName: 'createProxyWithNonce', args })
    await this.send(d.factory, encodeFunctionData({ abi: FACTORY_ABI, functionName: 'createProxyWithNonce', args }))
    await this.setBalance(result, 10n ** 18n)
    return getAddress(result)
  }

  async nonceOf(safe: Address) {
    return Number(await this.client().readContract({ address: safe, abi: SAFE_ABI, functionName: 'nonce' }))
  }

  hashOf(safe: Address, to: Address, value: bigint, data: Hex, operation: number, nonce: number) {
    return this.client().readContract({ address: safe, abi: SAFE_ABI, functionName: 'getTransactionHash', args: [to, value, data, operation, 0n, 0n, 0n, zeroAddress, zeroAddress, BigInt(nonce)] })
  }
}

export const tid = (p: Page, id: string) => p.getByTestId(id)

export async function shot(p: Page, dir: string, name: string) {
  mkdirSync(dir, { recursive: true })
  await p.screenshot({ path: join(dir, `${name}.png`), fullPage: true })
}

/** Waits for the action's result, or fails with the app's error. */
export async function waitDone(p: Page, ok: Locator, timeout = 180_000) {
  await expect(ok.or(tid(p, 'error')).first()).toBeVisible({ timeout })
  if (await tid(p, 'error').isVisible()) throw new Error(`the app says: ${await tid(p, 'error').textContent()}`)
}

/** The app's RPC for Sepolia set to the local chain (Settings). */
export async function useLocalRpc(p: Page, baseURL: string, url: string) {
  await p.goto(`${baseURL}/#/settings`)
  await tid(p, 'rpc-edit-11155111').click()
  await tid(p, 'rpc-input-11155111').fill(url)
  await tid(p, 'rpc-save-11155111').click()
  await expect(tid(p, 'rpc-host-11155111')).toHaveText(new URL(url).origin)
}

/** The app's stored board record (IndexedDB). */
export function boardRecord(p: Page): Promise<any> {
  return p.evaluate(
    () =>
      new Promise<any>((res, rej) => {
        const r = indexedDB.open('winterlock')
        r.onsuccess = () => {
          const q = r.result.transaction('device').objectStore('device').get('this')
          q.onsuccess = () => res(q.result)
          q.onerror = () => rej(q.error)
        }
      }),
  )
}

/** Join a Safe from the app's Join screen; waits for its Safe screen. */
export async function joinSafe(p: Page, baseURL: string, safe: Address) {
  await p.goto(`${baseURL}/#/join`)
  await tid(p, 'safe-input').fill(`sep:${safe}`)
  await tid(p, 'join-submit').click()
  await expect(tid(p, 'tree-state')).toBeVisible({ timeout: 60_000 })
}
