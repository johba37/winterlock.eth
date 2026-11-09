// SLH-DSA-SHA2-128s known answers from noble post-quantum 0.7.1, an independent implementation of FIPS 205.
//   npm ci --ignore-scripts && npm run vectors      (writes ../../fixtures/noble-sha2-128s.json)
// Fresh keys from random seeds, recorded with each vector. noble's own verify gives every verdict; invalid vectors
// are valid signatures paired with another message, context or key.
import { slh_dsa_sha2_128s as slh } from '@noble/post-quantum/slh-dsa.js';
import { randomBytes } from 'node:crypto';

const hex = (b) => '0x' + Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const vectors = [];

function add(reason, seed, pk, message, context, signature, internal = false) {
  const valid = internal
    ? slh.internal.verify(signature, message, pk)
    : slh.verify(signature, message, pk, { context });
  vectors.push({
    source: 'noble post-quantum 0.7.1', internal, seed: hex(seed), pk: hex(pk), message: hex(message),
    context: hex(context), signature: hex(signature), valid, reason,
  });
  return valid;
}

function key() {
  const seed = randomBytes(48);
  return { seed, ...slh.keygen(seed) };
}

const empty = new Uint8Array(0);
const k1 = key(), k2 = key(), k3 = key(), k4 = key();
const hash = randomBytes(32); // what an ERC-1271 check passes
const long = randomBytes(1000);
const ctx255 = randomBytes(255);
const ctx = enc('winterlock');

const s1 = slh.sign(hash, k1.secretKey);
add('a 32-byte hash, empty context, hedged', k1.seed, k1.publicKey, hash, empty, s1);
const s1d = slh.sign(hash, k1.secretKey, { extraEntropy: false });
add('a 32-byte hash, empty context, deterministic', k1.seed, k1.publicKey, hash, empty, s1d);
const s2 = slh.sign(long, k2.secretKey, { context: ctx });
add('a 1,000-byte message, a 10-byte context, hedged', k2.seed, k2.publicKey, long, ctx, s2);
const s3 = slh.sign(empty, k3.secretKey, { context: ctx255 });
add('an empty message, a 255-byte context, hedged', k3.seed, k3.publicKey, empty, ctx255, s3);
const s4 = slh.internal.sign(hash, k4.secretKey);
add('internal interface: M\' = a 32-byte hash', k4.seed, k4.publicKey, hash, empty, s4, true);

// invalid: noble says false
const other = randomBytes(32);
if (add('another message', k1.seed, k1.publicKey, other, empty, s1)) throw new Error('noble accepted');
if (add('another context', k2.seed, k2.publicKey, long, enc('winterlocK'), s2)) throw new Error('noble accepted');
if (add('no context', k2.seed, k2.publicKey, long, empty, s2)) throw new Error('noble accepted');
if (add('another key', k2.seed, k2.publicKey, hash, empty, s1)) throw new Error('noble accepted');
if (add('pure signature, internal interface', k1.seed, k1.publicKey, hash, empty, s1, true)) throw new Error('noble accepted');

process.stdout.write(JSON.stringify({
  source: 'noble post-quantum 0.7.1 (npm @noble/post-quantum, MIT), tools/noble/gen.mjs',
  parameterSet: 'SLH-DSA-SHA2-128s',
  vectors,
}, null, 1) + '\n');
