// After a run: no file the run wrote outside the browser profiles may hold a value of the .env
// (an error report can quote a URL with an API key). The profiles hold the RPC URL as a setting,
// as a member's browser would.

import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { redact } from './env'

function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    if (name === 'profiles') continue
    const p = join(dir, name)
    const s = statSync(p)
    if (s.isDirectory()) out.push(...walk(p))
    else if (s.size < 20_000_000 && !/\.(png|jpe?g|webm|zip)$/.test(name)) out.push(p)
  }
  return out
}

export default async function scrub() {
  const dir = process.env.E2E_DIR
  if (!dir || !process.env.WINTERLOCK_ENV_FILE) return
  for (const f of walk(dir)) {
    const text = readFileSync(f, 'utf8')
    const clean = redact(text)
    if (clean !== text) {
      writeFileSync(f, clean)
      console.log(`scrubbed ${f}`)
    }
  }
}
