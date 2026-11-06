// Checks EIP-712 signatures of a contract account with viem's verifyTypedData, as a dapp that verifies with viem
// does: test_e2e_walletconnect.py runs it on its anvil. Reads one JSON object from stdin:
//   {"rpc": URL, "address": the account, "typedData": eth_signTypedData_v4's JSON, "signatures": {name: hex}}
// and prints {"viem": version, "results": {name: true | false | "threw: ..."}}.
// Run with NODE_PATH pointing at a node_modules that holds viem (not part of this repository).
const { createPublicClient, http } = require('viem');

function bigints(types, type, value) {
  // viem takes integers as bigint or number; eth_signTypedData_v4's JSON may carry them as strings
  if (/^u?int\d*$/.test(type)) return BigInt(value);
  if (type.endsWith(']')) return value.map((v) => bigints(types, type.slice(0, type.lastIndexOf('[')), v));
  if (types[type]) {
    return Object.fromEntries(types[type].map((f) => [f.name, bigints(types, f.type, value[f.name])]));
  }
  return value;
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const { rpc, address, typedData, signatures } = JSON.parse(input);
  const client = createPublicClient({ transport: http(rpc) });
  const types = Object.fromEntries(Object.entries(typedData.types).filter(([k]) => k !== 'EIP712Domain'));
  const message = bigints(types, typedData.primaryType, typedData.message);
  const domain = { ...typedData.domain };
  if (domain.chainId !== undefined) domain.chainId = Number(domain.chainId);
  const results = {};
  for (const [name, signature] of Object.entries(signatures)) {
    try {
      results[name] = await client.verifyTypedData({ address, domain, types, primaryType: typedData.primaryType,
                                                     message, signature });
    } catch (e) {
      results[name] = `threw: ${e.shortMessage || e.message}`;
    }
  }
  const version = require('viem/package.json').version;
  process.stdout.write(JSON.stringify({ viem: version, results }) + '\n');
}

main().catch((e) => { process.stdout.write(JSON.stringify({ fatal: String((e && e.stack) || e) }) + '\n'); process.exit(1); });
