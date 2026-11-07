// The Python signer as the Safe's other Winterlock member: the reference implementation, run from
// its command line (signer/). WINTERLOCK_PYTHON names the virtualenv's python (default
// signer/.venv/bin/python under the repository).

import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { log, pythonEnv, redact, rpcUrl } from './env'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..')

function python(): string {
  const p = process.env.WINTERLOCK_PYTHON ?? resolve(repo, 'signer/.venv/bin/python')
  if (!existsSync(p)) throw new Error(`no Python signer virtualenv at ${p}: set WINTERLOCK_PYTHON`)
  return p
}

export interface Run {
  code: number
  out: string
}

/** One signer command with --home and --yes; output redacted. */
export function signer(home: string, args: string[], ok: number[] = [0]): Run {
  const r = spawnSync(python(), ['-m', 'winterlock_signer', '--home', home, '--yes', ...args], {
    cwd: resolve(repo, 'signer'),
    env: pythonEnv(),
    encoding: 'utf8',
    timeout: 15 * 60_000,
  })
  const out = redact(`${r.stdout ?? ''}${r.stderr ?? ''}`)
  for (const line of out.trim().split('\n')) log(`    python: ${line}`)
  if (!ok.includes(r.status ?? -1)) throw new Error(`python signer ${args[0]} exited ${r.status}`)
  return { code: r.status ?? -1, out }
}

export const chainArgs = () => ['--chain', '11155111', '--rpc', rpcUrl(), '--gas-key-env', 'FRESH_EYES_GAS_KEY']
