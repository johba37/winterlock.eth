// Signatures for the gas benchmark: one fresh SLH-DSA-SHA2-128s key from noble post-quantum 0.7.1, 16 hedged
// signatures over random 32-byte hashes (what an ERC-1271 check passes), empty context.
//   npm run gas-vectors      (writes ../../fixtures/noble-sha2-128s-gas.json)
// Verification gas depends on the signature (the WOTS+ chain lengths), so the benchmark reports a spread.
import { slh_dsa_sha2_128s as slh } from '@noble/post-quantum/slh-dsa.js';
import { randomBytes } from 'node:crypto';

const hex = (b) => '0x' + Buffer.from(b).toString('hex');
const seed = randomBytes(48);
const { secretKey, publicKey } = slh.keygen(seed);
const vectors = [];
for (let i = 0; i < 16; i++) {
  const hash = randomBytes(32);
  const signature = slh.sign(hash, secretKey);
  if (!slh.verify(signature, hash, publicKey)) throw new Error('noble rejected its own signature');
  vectors.push({
    source: 'noble post-quantum 0.7.1', internal: false, seed: hex(seed), pk: hex(publicKey), message: hex(hash),
    context: '0x', signature: hex(signature), valid: true, reason: `gas sample ${i}: a 32-byte hash, hedged`,
  });
}
process.stdout.write(JSON.stringify({
  source: 'noble post-quantum 0.7.1 (npm @noble/post-quantum, MIT), tools/noble/gas.mjs',
  parameterSet: 'SLH-DSA-SHA2-128s',
  vectors,
}, null, 1) + '\n');
