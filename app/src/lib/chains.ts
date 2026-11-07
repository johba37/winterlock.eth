// The chains the app knows. Sepolia is on for development; Arbitrum One, where the first round
// runs, is configured but off until the contracts are deployed there and the round starts.
// Before the app uses a chain it checks that the pinned owner v2 contracts have code there
// (deterministic deployment: the same addresses as on Sepolia).

export interface ChainConfig {
  id: number
  name: string
  enabled: boolean
  /** Public endpoint, used unless the member sets their own in Settings. */
  defaultRpc: string
  /** Safe's Transaction Service. */
  service: string
  /** Safe's app, for adding an owner. */
  safeApp: string
  explorer: string
  /** The prefix Safe's app uses in its URLs, such as sep:0x... */
  shortName: string
}

export const CHAINS: ChainConfig[] = [
  {
    id: 11155111,
    name: 'Sepolia',
    enabled: true,
    defaultRpc: 'https://ethereum-sepolia-rpc.publicnode.com',
    service: 'https://api.safe.global/tx-service/sep/api',
    safeApp: 'https://app.safe.global',
    explorer: 'https://sepolia.etherscan.io',
    shortName: 'sep',
  },
  {
    id: 42161,
    name: 'Arbitrum One',
    enabled: false,
    defaultRpc: 'https://arb1.arbitrum.io/rpc',
    service: 'https://api.safe.global/tx-service/arb1/api',
    safeApp: 'https://app.safe.global',
    explorer: 'https://arbiscan.io',
    shortName: 'arb1',
  },
]

export const enabledChains = () => CHAINS.filter((c) => c.enabled)

export function chainById(id: number): ChainConfig {
  const c = CHAINS.find((x) => x.id === id)
  if (!c) throw new Error(`unknown chain ${id}`)
  return c
}

/** scheme://host only: an RPC URL may carry an API key in its path (rpc.py's safe_url). */
export function safeUrl(url: string): string {
  try {
    const u = new URL(url)
    return `${u.protocol}//${u.host}`
  } catch {
    return 'an invalid URL'
  }
}
