// A dapp on the official WalletConnect SDK (@walletconnect/sign-client), for the optional interoperability test
// (tests/test_walletconnect.py, JsDappInterop). It connects through the relay URL given, prints the pairing URI, waits
// for the session, sends the requests given as JSON on the command line, and prints each answer as a JSON line.
// Run with NODE_PATH pointing at a node_modules that holds @walletconnect/sign-client (not part of this repository).
//   node js_dapp.js RELAY_URL STORAGE_FILE CHAIN_ID '[{"method": ..., "params": [...]}, ...]'
const { SignClient } = require('@walletconnect/sign-client');

async function main() {
  const [relayUrl, storage, chainId, requestsJson] = process.argv.slice(2);
  const client = await SignClient.init({
    relayUrl,
    telemetryEnabled: false,
    storageOptions: { database: storage },
    metadata: { name: 'JS dapp', description: 'interop test', url: 'https://app.example', icons: [] },
  });
  const chain = `eip155:${chainId}`;
  const { uri, approval } = await client.connect({
    optionalNamespaces: {
      eip155: {
        chains: [chain],
        methods: ['eth_sendTransaction', 'personal_sign', 'eth_signTypedData_v4', 'wallet_getCapabilities'],
        events: ['chainChanged', 'accountsChanged'],
      },
    },
  });
  console.log(JSON.stringify({ uri }));
  const session = await approval();
  console.log(JSON.stringify({ session: session.namespaces, peer: session.peer.metadata.name }));
  for (const req of JSON.parse(requestsJson)) {
    try {
      const result = await client.request({ topic: session.topic, chainId: chain, request: req });
      console.log(JSON.stringify({ method: req.method, result }));
    } catch (e) {
      console.log(JSON.stringify({ method: req.method, error: { code: e.code, message: e.message } }));
    }
  }
  await client.disconnect({ topic: session.topic, reason: { code: 6000, message: 'done' } });
  console.log(JSON.stringify({ done: true }));
  process.exit(0);
}

main().catch((e) => { console.log(JSON.stringify({ fatal: String(e && e.stack || e) })); process.exit(1); });
