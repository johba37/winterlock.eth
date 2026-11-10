// Signing time of SLH-DSA-SHA2-128s with RustCrypto slh-dsa compiled to WebAssembly, under Node (one thread).
//   cargo build --release --lib --target wasm32-unknown-unknown
//   wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/slh_dsa_bench.wasm
//   node wasm-bench.mjs [signatures]
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';

const { keygen, sign } = createRequire(import.meta.url)('./pkg/slh_dsa_bench.js');
const n = Number(process.argv[2] ?? 7);
let t = performance.now();
const sk = keygen(randomBytes(48));
const kg = performance.now() - t;
const times = [];
for (let i = 0; i < n; i++) {
  const rand = i % 2 ? new Uint8Array(0) : randomBytes(16);
  t = performance.now();
  const sig = sign(sk, randomBytes(32), new Uint8Array(0), rand);
  times.push(performance.now() - t);
  if (sig.length !== 7856) throw new Error('signature length');
}
times.sort((a, b) => a - b);
console.log(`RustCrypto slh-dsa 0.2.0-rc.5, wasm32 under Node ${process.version}, SLH-DSA-SHA2-128s: keygen ` +
  `${kg.toFixed(0)} ms, sign median ${times[n >> 1].toFixed(0)} ms (min ${times[0].toFixed(0)}, ` +
  `max ${times[n - 1].toFixed(0)}, n = ${n})`);
