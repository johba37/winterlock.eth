// The core's timings in the app's own device worker (bench.html, dev server only): the member
// key, a height-10 key tree, a stateless signature and a one-time signature.
import { core } from './core/client'

const out = document.getElementById('out')!
const runs = Number(new URL(location.href).searchParams.get('runs') ?? 3)
const results: unknown[] = []
for (let i = 0; i < runs; i++) results.push(await core().call('bench', { runs: 5 }))
const r = JSON.stringify({ userAgent: navigator.userAgent, cores: navigator.hardwareConcurrency, results }, null, 1)
out.textContent = r
;(window as unknown as { benchDone: unknown }).benchDone = JSON.parse(r)
