// The live run's secrets, from the git-ignored .env (WINTERLOCK_ENV_FILE). Nothing here is ever
// printed: log() redacts every value it loaded.

import { readFileSync } from 'node:fs'

export interface Secrets {
  alchemy: string
  fund: `0x${string}`
  safeApiKey?: string
}

let loaded: Record<string, string> | undefined

function load(): Record<string, string> {
  if (loaded) return loaded
  const path = process.env.WINTERLOCK_ENV_FILE
  if (!path) throw new Error('set WINTERLOCK_ENV_FILE to the .env with ALCHEMY_API_KEY and FRESH_EYES_GAS_KEY')
  loaded = {}
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/)
    if (m) loaded[m[1]] = m[2].replace(/^["']|["']$/g, '')
  }
  return loaded
}

export function secrets(): Secrets {
  const e = load()
  for (const k of ['ALCHEMY_API_KEY', 'FRESH_EYES_GAS_KEY']) if (!e[k]) throw new Error(`${k} missing from WINTERLOCK_ENV_FILE`)
  const fund = (e.FRESH_EYES_GAS_KEY.startsWith('0x') ? e.FRESH_EYES_GAS_KEY : `0x${e.FRESH_EYES_GAS_KEY}`) as `0x${string}`
  return { alchemy: e.ALCHEMY_API_KEY, fund, safeApiKey: e.SAFE_API_KEY }
}

/** WalletConnect's project ID, for runs that pair through Reown's relay; undefined without one. */
export function projectId(): string | undefined {
  if (!process.env.WINTERLOCK_ENV_FILE) return undefined
  return load().WALLETCONNECT_PROJECT_ID || undefined
}

export function rpcUrl(): string {
  return `https://eth-sepolia.g.alchemy.com/v2/${secrets().alchemy}`
}

/** Every loaded value of 8 characters or more, and the same without 0x. */
export function redact(text: string): string {
  let t = String(text)
  for (const v of Object.values(load())) {
    if (!v || v.length < 8) continue
    t = t.split(v).join('<redacted>')
    if (v.startsWith('0x')) t = t.split(v.slice(2)).join('<redacted>')
  }
  return t
}

export function log(...a: unknown[]) {
  console.log(redact(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)))).join(' ')))
}

/** Python's environment: the signer reads SAFE_API_KEY and the gas key by name. */
export function pythonEnv(): NodeJS.ProcessEnv {
  const e = load()
  return { ...process.env, SAFE_API_KEY: e.SAFE_API_KEY ?? '', FRESH_EYES_GAS_KEY: e.FRESH_EYES_GAS_KEY }
}
