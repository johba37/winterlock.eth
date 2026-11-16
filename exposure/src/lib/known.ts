// Safe's official contracts, as far as this check needs them. Sources, read 2026-11-16:
// - Singletons and fallback handlers: safe-global/safe-deployments, src/assets/v1.x.x/*.json, with
//   each deployment's networkAddresses for the six chains in chains.ts.
// - Proxy code: each official proxy factory's own proxy, deployed in an eth_call on Ethereum
//   (proxyCreationCode() followed by abi.encode(singleton)); for 1.0.0 to 1.3.0 that matches the
//   factory's proxyRuntimeCode(). The factories' code hashes match safe-deployments' codeHash.
// - Passkey signers: safe-global/safe-modules-deployments, safe-passkey-module v0.2.0 and v0.2.1;
//   each factory's SINGLETON() read on Ethereum and Sepolia; the contracts from the
//   @safe-global/safe-passkey package. Safe4337Module from safe-4337-module v0.2.0 and v0.3.0.
// test/known.test.ts checks these tables for internal consistency; test/live.test.ts re-reads
// the proxy code and the passkey singletons from the chain when EXPOSURE_LIVE=1.

import type { Address, Hex } from 'viem'

export interface Singleton {
  address: Address
  version: string
  l2: boolean
  /** The chains (of chains.ts) where safe-deployments lists this address. */
  chains: readonly number[]
}

const ALL = [1, 11155111, 8453, 42161, 10, 100] as const
const MAINNET_GNOSIS = [1, 100] as const

export const SINGLETONS: readonly Singleton[] = [
  { address: '0xb6029EA3B2c51D09a50B53CA8012FeEB05bDa35A', version: '1.0.0', l2: false, chains: MAINNET_GNOSIS },
  { address: '0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F', version: '1.1.1', l2: false, chains: MAINNET_GNOSIS },
  { address: '0x6851D6fDFAfD08c0295C392436245E5bc78B0185', version: '1.2.0', l2: false, chains: MAINNET_GNOSIS },
  { address: '0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552', version: '1.3.0', l2: false, chains: ALL },
  { address: '0x69f4D1788e39c87893C980c06EdF4b7f686e2938', version: '1.3.0', l2: false, chains: ALL },
  { address: '0x3E5c63644E683549055b9Be8653de26E0B4CD36E', version: '1.3.0', l2: true, chains: ALL },
  { address: '0xfb1bffC9d739B8D520DaF37dF666da4C687191EA', version: '1.3.0', l2: true, chains: ALL },
  { address: '0x41675C099F32341bf84BFc5382aF534df5C7461a', version: '1.4.1', l2: false, chains: ALL },
  { address: '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762', version: '1.4.1', l2: true, chains: ALL },
  { address: '0xFf51A5898e281Db6DfC7855790607438dF2ca44b', version: '1.5.0', l2: false, chains: ALL },
  { address: '0xEdd160fEBBD92E350D4D398fb636302fccd67C7e', version: '1.5.0', l2: true, chains: ALL },
]

/** keccak256 of the runtime code of the proxies Safe's official factories deploy. */
export const PROXY_CODE_HASHES: Readonly<Record<Hex, string>> = {
  '0xf8fffcb9b9c73fbc4ffb6dc52f0001fa998951e0d4177894b1b899f7732b6eaf': '1.0.0',
  '0xaea7d4252f6245f301e540cfbee27d3a88de543af8e49c5c62405d5499fab7e5': '1.1.1',
  '0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000': '1.3.0',
  '0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c': '1.4.1',
  '0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f': '1.5.0',
}

/** The official proxy factories, for the live re-check of PROXY_CODE_HASHES. */
export const PROXY_FACTORIES: readonly { address: Address; version: string; singleton: Address }[] = [
  { address: '0x12302fE9c02ff50939BaAaaf415fc226C078613C', version: '1.0.0', singleton: '0xb6029EA3B2c51D09a50B53CA8012FeEB05bDa35A' },
  { address: '0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B', version: '1.1.1', singleton: '0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F' },
  { address: '0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2', version: '1.3.0', singleton: '0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552' },
  { address: '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67', version: '1.4.1', singleton: '0x41675C099F32341bf84BFc5382aF534df5C7461a' },
  { address: '0x14F2982D601c9458F93bd70B218933A6f8165e7b', version: '1.5.0', singleton: '0xFf51A5898e281Db6DfC7855790607438dF2ca44b' },
]

/** Safe's passkey signer factories: each deploys SafeWebAuthnSignerProxy contracts that hold a
 * P-256 public key (x, y) as immutables and delegate to the factory's SINGLETON. */
export const PASSKEY_FACTORIES: readonly { address: Address; version: string; singleton: Address }[] = [
  { address: '0xF7488fFbe67327ac9f37D5F722d83Fc900852Fbf', version: '0.2.0', singleton: '0x270D7E4a57E6322f336261f3EaE2BADe72E68d72' },
  { address: '0x1d31F259eE307358a26dFb23EB365939E8641195', version: '0.2.1', singleton: '0x4E27b51350e6c2083EE19011120F50DAfEc5CA50' },
]

/** SafeWebAuthnSharedSigner v0.2.1: one owner address for every Safe, the key in the Safe's storage. */
export const PASSKEY_SHARED_SIGNER: Address = '0x94a4F6affBd8975951142c3999aEAB7ecee555c2'

/** Names for addresses the report shows (modules, fallback handlers), information only. */
export const NAMES: Readonly<Record<string, string>> = {
  '0xd5d82b6addc9027b22dca772aa68d5d74cdbdf44': 'DefaultCallbackHandler 1.1.1',
  '0xf48f2b2d2a534e402487b3ee7c18c33aec0fe5e4': 'CompatibilityFallbackHandler 1.3.0',
  '0x017062a1de2fe6b99be3d9d37841fed19f573804': 'CompatibilityFallbackHandler 1.3.0',
  '0xfd0732dc9e303f09fcef3a7388ad10a83459ec99': 'CompatibilityFallbackHandler 1.4.1',
  '0x3efcbb83a4a7afcb4f68d501e2c2203a38be77f4': 'CompatibilityFallbackHandler 1.5.0',
  '0x85a8ca358d388530ad0fb95d0cb89dd44fc242c3': 'ExtensibleFallbackHandler 1.5.0',
  '0x54e86d004d71a8d2112ec75face57d730b0433f3': 'TokenCallbackHandler 1.5.0',
  '0xa581c4a4db7175302464ff3c06380bc3270b4037': 'Safe4337Module 0.2.0',
  '0x75cf11467937ce3f2f357ce24ffc3dbf8fd5c226': 'Safe4337Module 0.3.0',
}

export function nameOf(address: Address): string | undefined {
  return NAMES[address.toLowerCase()]
}

/** Storage slots: the singleton (slot 0 of every Safe proxy) and Safe's managers. */
export const SLOTS = {
  singleton: '0x0000000000000000000000000000000000000000000000000000000000000000',
  /** keccak256("guard_manager.guard.address"), Safe 1.3.0 and later */
  guard: '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8',
  /** keccak256("fallback_manager.handler.address"), Safe 1.1.0 and later */
  fallbackHandler: '0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5',
  /** keccak256("module_manager.module_guard.address"), Safe 1.5.0 */
  moduleGuard: '0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947',
} as const satisfies Record<string, Hex>

export const SENTINEL: Address = '0x0000000000000000000000000000000000000001'

export function officialSingleton(chainId: number, address: Address): Singleton | undefined {
  const a = address.toLowerCase()
  return SINGLETONS.find((s) => s.address.toLowerCase() === a && s.chains.includes(chainId))
}
