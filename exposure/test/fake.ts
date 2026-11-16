// An offline chain and Safe Transaction Service for the tests: an EIP-1193 provider that answers
// the reads the check makes, and a fetch that serves the service's pages.

import { type Address, type Hex, createPublicClient, custom, decodeFunctionData, encodeFunctionResult, getAddress, keccak256, pad, parseAbi, toHex } from 'viem'
import { PASSKEY_FACTORIES, PASSKEY_SHARED_SIGNER, SENTINEL, SLOTS } from '../src/lib/known'
import { WINTERLOCK_IMPLEMENTATION, ownerAddress, proxyRuntime } from '../src/lib/winterlock'

/** The runtime code of SafeProxyFactory 1.4.1's proxies (read from the factory on Ethereum). */
export const PROXY_141: Hex =
  '0x608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea264697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f31441364736f6c63430007060033'
/** The runtime code of ProxyFactory 1.0.0's proxies. */
export const PROXY_100: Hex =
  '0x608060405273ffffffffffffffffffffffffffffffffffffffff600054163660008037600080366000845af43d6000803e6000811415603d573d6000fd5b3d6000f3fea165627a7a723058201e7d648b83cfac072cbccefc2ffc62a6999d4a050ee87a721942de1da9670db80029'
export const SAFE_L2_141: Address = '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762'
export const SAFE_100: Address = '0xb6029EA3B2c51D09a50B53CA8012FeEB05bDa35A'
export const SOME_CODE: Hex = '0x6080604052348015600f57600080fd5b50600436106028576000'

const SAFE_ABI = parseAbi([
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function getModulesPaginated(address start, uint256 pageSize) view returns (address[] array, address next)',
  'function getModules() view returns (address[])',
])
const ERC20_ABI = parseAbi(['function balanceOf(address owner) view returns (uint256)'])
const PASSKEY_SIGNER_ABI = parseAbi(['function getConfiguration() view returns (uint256 x, uint256 y, uint176 verifiers)'])
const PASSKEY_FACTORY_ABI = parseAbi(['function getSigner(uint256 x, uint256 y, uint176 verifiers) view returns (address)'])
const SHARED_SIGNER_ABI = parseAbi(['function getConfiguration(address account) view returns ((uint256 x, uint256 y, uint176 verifiers) signer)'])

type Call = (data: Hex) => Hex

export interface Account {
  code?: Hex
  nonce?: number
  balance?: bigint
  storage?: Record<string, Hex>
  call?: Call
}

export class Revert extends Error {
  constructor(readonly data: Hex = '0x') {
    super('execution reverted')
  }
}

/** An address from a label, for readable tests. */
export function addr(label: string): Address {
  return getAddress(keccak256(toHex(label)).slice(0, 42))
}

export class FakeChain {
  accounts = new Map<string, Account>()
  requests: { method: string; params: unknown[] }[] = []
  block = 1_000n
  /** Addresses whose reads fail, as if the endpoint gave up on them. */
  failing = new Set<string>()

  constructor(public chainId = 11155111) {}

  set(address: Address, a: Account): Address {
    this.accounts.set(address.toLowerCase(), { ...this.accounts.get(address.toLowerCase()), ...a })
    return address
  }

  get(address: string): Account {
    return this.accounts.get(address.toLowerCase()) ?? {}
  }

  client() {
    return createPublicClient({ transport: custom({ request: (r: { method: string; params?: unknown[] }) => this.request(r) }) })
  }

  async request({ method, params = [] }: { method: string; params?: unknown[] }): Promise<unknown> {
    this.requests.push({ method, params })
    const p = params as any[]
    if (p[0] && typeof p[0] === 'string' && this.failing.has(p[0].toLowerCase())) throw new Error('endpoint gave up')
    switch (method) {
      case 'eth_chainId':
        return toHex(this.chainId)
      case 'eth_blockNumber':
        return toHex(this.block)
      case 'eth_getCode':
        return this.get(p[0]).code ?? '0x'
      case 'eth_getTransactionCount':
        return toHex(this.get(p[0]).nonce ?? 0)
      case 'eth_getBalance':
        return toHex(this.get(p[0]).balance ?? 0n)
      case 'eth_getStorageAt':
        return this.get(p[0]).storage?.[(p[1] as string).toLowerCase()] ?? pad('0x0')
      case 'eth_call': {
        const { to, data } = p[0] as { to: Address; data: Hex }
        const call = this.get(to).call
        if (!call || !this.get(to).code) return '0x'
        try {
          return call(data)
        } catch (e) {
          if (e instanceof Revert) throw Object.assign(new Error('execution reverted'), { code: 3, data: e.data })
          throw e
        }
      }
    }
    throw new Error(`fake chain: ${method} not supported`)
  }

  /** A Safe: an official 1.4.1 proxy on the official SafeL2 singleton, unless told otherwise. */
  safe(
    address: Address,
    o: { owners: Address[]; threshold: number; modules?: Address[]; singleton?: Address; code?: Hex; guard?: Address; fallbackHandler?: Address; balance?: bigint; v100?: boolean },
  ): Address {
    const storage: Record<string, Hex> = { [SLOTS.singleton]: pad(o.singleton ?? (o.v100 ? SAFE_100 : SAFE_L2_141)) }
    if (o.guard) storage[SLOTS.guard] = pad(o.guard)
    if (o.fallbackHandler) storage[SLOTS.fallbackHandler] = pad(o.fallbackHandler)
    const modules = o.modules ?? []
    return this.set(address, {
      code: o.code ?? (o.v100 ? PROXY_100 : PROXY_141),
      nonce: 1,
      balance: o.balance ?? 0n,
      storage,
      call: (data) => {
        const { functionName, args } = decodeFunctionData({ abi: SAFE_ABI, data })
        switch (functionName) {
          case 'getOwners':
            return encodeFunctionResult({ abi: SAFE_ABI, functionName, result: o.owners })
          case 'getThreshold':
            return encodeFunctionResult({ abi: SAFE_ABI, functionName, result: BigInt(o.threshold) })
          case 'nonce':
            return encodeFunctionResult({ abi: SAFE_ABI, functionName, result: 7n })
          case 'getModulesPaginated': {
            if (o.v100) throw new Revert()
            const size = Number(args[1])
            const page = modules.slice(0, size)
            const next = modules.length > size ? modules[size - 1] : SENTINEL
            return encodeFunctionResult({ abi: SAFE_ABI, functionName, result: [page, next] })
          }
          case 'getModules':
            return encodeFunctionResult({ abi: SAFE_ABI, functionName, result: modules })
        }
      },
    })
  }

  key(address: Address, nonce = 0): Address {
    return this.set(address, { nonce })
  }

  /** A Winterlock owner v2 for a member key, at its real address. */
  winterlock(key: Hex): Address {
    return this.set(ownerAddress(key), { code: proxyRuntime(WINTERLOCK_IMPLEMENTATION, key) })
  }

  /** Safe's passkey signer from factory v0.2.1, with the factory answering for it. */
  passkey(address: Address, x = 11n, y = 22n, verifiers = 0x100n): Address {
    const factory = PASSKEY_FACTORIES[1]
    const code: Hex = `0x6080${pad(factory.singleton).slice(2)}${pad(toHex(x)).slice(2)}`
    this.set(address, {
      code,
      call: (data) => {
        decodeFunctionData({ abi: PASSKEY_SIGNER_ABI, data })
        return encodeFunctionResult({ abi: PASSKEY_SIGNER_ABI, functionName: 'getConfiguration', result: [x, y, verifiers] })
      },
    })
    const signers = this.passkeyFactorySigners
    signers.set(`${x}:${y}:${verifiers}`, address)
    this.set(factory.address, {
      code: SOME_CODE,
      call: (data) => {
        const { args } = decodeFunctionData({ abi: PASSKEY_FACTORY_ABI, data })
        const a = signers.get(`${args[0]}:${args[1]}:${args[2]}`) ?? addr(`elsewhere ${args[0]}`)
        return encodeFunctionResult({ abi: PASSKEY_FACTORY_ABI, functionName: 'getSigner', result: a })
      },
    })
    return address
  }

  private passkeyFactorySigners = new Map<string, Address>()

  /** Safe's shared passkey signer; `configured` lists the Safes that set a key up. */
  sharedSigner(configured: Address[]): Address {
    return this.set(PASSKEY_SHARED_SIGNER, {
      code: SOME_CODE,
      call: (data) => {
        const { args } = decodeFunctionData({ abi: SHARED_SIGNER_ABI, data })
        const on = configured.some((s) => s.toLowerCase() === (args[0] as string).toLowerCase())
        return encodeFunctionResult({ abi: SHARED_SIGNER_ABI, functionName: 'getConfiguration', result: on ? { x: 5n, y: 6n, verifiers: 0x100n } : { x: 0n, y: 0n, verifiers: 0n } })
      },
    })
  }

  token(address: Address, balances: Record<string, bigint>): Address {
    return this.set(address, {
      code: SOME_CODE,
      call: (data) => {
        const { args } = decodeFunctionData({ abi: ERC20_ABI, data })
        return encodeFunctionResult({ abi: ERC20_ABI, functionName: 'balanceOf', result: balances[(args[0] as string).toLowerCase()] ?? 0n })
      },
    })
  }
}

export interface ServiceSafe {
  transactions?: { safeTxHash?: Hex; nonce: number; isExecuted: boolean; confirmations: { owner: Address; signatureType: string }[] }[]
  messages?: { messageHash?: Hex; confirmations: { owner: Address; signatureType: string }[] }[]
}

export const SERVICE_URL = 'https://service.test/api'

/** Safe's Transaction Service: the Safes it knows, paged as the real one pages them. */
export class FakeService {
  safes = new Map<string, ServiceSafe>()
  urls: string[] = []
  /** Answer 429 from this request number on (0-based). */
  rateLimitFrom = Infinity

  add(safe: Address, s: ServiceSafe) {
    this.safes.set(safe.toLowerCase(), s)
  }

  fetch = async (input: string | URL | Request): Promise<Response> => {
    const url = new URL(String(input))
    this.urls.push(url.pathname + url.search)
    if (this.urls.length - 1 >= this.rateLimitFrom) return new Response('{"error_msg":"Too many requests per second"}', { status: 429 })
    const path = url.pathname.replace(/^\/api/, '')
    let m = /^\/v1\/safes\/(0x[0-9a-fA-F]{40})\/$/.exec(path)
    if (m) {
      if (m[1] !== getAddress(m[1])) return new Response('{}', { status: 422 })
      return this.safes.has(m[1].toLowerCase()) ? Response.json({ address: m[1] }) : new Response('{"detail":"Not found."}', { status: 404 })
    }
    m = /^\/v2\/safes\/(0x[0-9a-fA-F]{40})\/multisig-transactions\/$/.exec(path) ?? /^\/v1\/safes\/(0x[0-9a-fA-F]{40})\/messages\/$/.exec(path)
    if (!m) return new Response('not found', { status: 404 })
    const s = this.safes.get(m[1].toLowerCase()) ?? {}
    const list: unknown[] = path.includes('messages') ? (s.messages ?? []) : (s.transactions ?? [])
    const limit = Math.min(200, Number(url.searchParams.get('limit') ?? 100))
    const offset = Number(url.searchParams.get('offset') ?? 0)
    const results = list.slice(offset, offset + limit)
    const next = offset + limit < list.length ? `${url.origin}${url.pathname}?limit=${limit}&offset=${offset + limit}` : null
    return Response.json({ count: list.length, next, previous: null, results })
  }
}
