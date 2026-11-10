// Signing time of SLH-DSA-SHA2-128s in noble post-quantum 0.7.1 under Node (one thread).
//   npm run bench [-- signatures]
import { slh_dsa_sha2_128s as slh } from '@noble/post-quantum/slh-dsa.js';
import { randomBytes } from 'node:crypto';

const n = Number(process.argv[2] ?? 5);
let t = performance.now();
const { secretKey, publicKey } = slh.keygen(randomBytes(48));
const keygen = performance.now() - t;
const times = [];
for (let i = 0; i < n; i++) {
  const msg = randomBytes(32);
  t = performance.now();
  const sig = slh.sign(msg, secretKey);
  times.push(performance.now() - t);
  if (!slh.verify(sig, msg, publicKey)) throw new Error('rejected');
}
times.sort((a, b) => a - b);
const sig = slh.sign(randomBytes(32), secretKey);
t = performance.now();
for (let i = 0; i < 20; i++) slh.verify(sig, randomBytes(32), publicKey);
const verify = (performance.now() - t) / 20;
console.log(`noble post-quantum 0.7.1, Node ${process.version}, SLH-DSA-SHA2-128s: keygen ${keygen.toFixed(0)} ms, ` +
  `sign median ${times[n >> 1].toFixed(0)} ms (min ${times[0].toFixed(0)}, max ${times[n - 1].toFixed(0)}, n = ${n}), ` +
  `verify ${verify.toFixed(1)} ms`);
