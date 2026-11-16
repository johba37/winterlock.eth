// The networks the check knows: Safe's Transaction Service for each (checked 2026-11-16: each
// answered /api/v1/about/ as "Safe Transaction Service" 6.14.0) and a public RPC endpoint
// (checked the same day: the right chain ID, JSON-RPC batches, and Access-Control-Allow-Origin
// for any site). The short names are EIP-3770's, the prefixes Safe's app uses in its URLs.
//
// Tokens: only addresses checked against the issuer's or the chain's own documentation, with
// their decimals read on-chain. All but OP Mainnet's USDC come from the board's list
// (hardware/board-signer/logic/src/decode.rs); USDC on OP Mainnet is from Circle's "USDC
// contract addresses" page (developers.circle.com, 2026-11-16).

import type { Address } from 'viem'

export interface Token {
  address: Address
  symbol: string
  decimals: number
}

export interface Chain {
  id: number
  /** EIP-3770 short name, as in Safe's app: eth:0x... */
  shortName: string
  name: string
  /** The native currency's symbol. */
  native: string
  /** Safe's Transaction Service, up to and including /api. */
  service: string
  /** A public JSON-RPC endpoint; the page lets the reader set another. */
  rpc: string
  explorer: string
  tokens: Token[]
  testnet: boolean
}

const service = (shortName: string) => `https://api.safe.global/tx-service/${shortName}/api`

export const CHAINS: readonly Chain[] = [
  {
    id: 1,
    shortName: 'eth',
    name: 'Ethereum',
    native: 'ETH',
    service: service('eth'),
    rpc: 'https://ethereum-rpc.publicnode.com',
    explorer: 'https://etherscan.io',
    tokens: [
      { address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', symbol: 'USDC', decimals: 6 },
      { address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', symbol: 'WETH', decimals: 18 },
    ],
    testnet: false,
  },
  {
    id: 11155111,
    shortName: 'sep',
    name: 'Sepolia',
    native: 'ETH',
    service: service('sep'),
    rpc: 'https://ethereum-sepolia-rpc.publicnode.com',
    explorer: 'https://sepolia.etherscan.io',
    tokens: [{ address: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238', symbol: 'USDC', decimals: 6 }],
    testnet: true,
  },
  {
    id: 8453,
    shortName: 'base',
    name: 'Base',
    native: 'ETH',
    service: service('base'),
    rpc: 'https://mainnet.base.org',
    explorer: 'https://basescan.org',
    tokens: [
      { address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', symbol: 'USDC', decimals: 6 },
      { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH', decimals: 18 },
    ],
    testnet: false,
  },
  {
    id: 42161,
    shortName: 'arb1',
    name: 'Arbitrum One',
    native: 'ETH',
    service: service('arb1'),
    rpc: 'https://arb1.arbitrum.io/rpc',
    explorer: 'https://arbiscan.io',
    tokens: [
      { address: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', symbol: 'USDC', decimals: 6 },
      { address: '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', symbol: 'WETH', decimals: 18 },
    ],
    testnet: false,
  },
  {
    id: 10,
    shortName: 'oeth',
    name: 'OP Mainnet',
    native: 'ETH',
    service: service('oeth'),
    rpc: 'https://mainnet.optimism.io',
    explorer: 'https://optimistic.etherscan.io',
    tokens: [{ address: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', symbol: 'USDC', decimals: 6 }],
    testnet: false,
  },
  {
    id: 100,
    shortName: 'gno',
    name: 'Gnosis',
    native: 'xDAI',
    service: service('gno'),
    rpc: 'https://rpc.gnosischain.com',
    explorer: 'https://gnosisscan.io',
    tokens: [],
    testnet: false,
  },
]

export function chainById(id: number): Chain | undefined {
  return CHAINS.find((c) => c.id === id)
}

export function chainByShortName(shortName: string): Chain | undefined {
  const s = shortName.toLowerCase()
  return CHAINS.find((c) => c.shortName === s)
}
