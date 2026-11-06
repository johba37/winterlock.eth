// The dapp side of tools/live_walletconnect.py: a dapp on the official WalletConnect SDK (@walletconnect/sign-client)
// that connects through Reown's relay with a project ID, and checks what the wallet answers with viem against the
// chain, as a dapp would. It reads the scenario (the Safe, the sign-in text, the transfer, the Permit2 typed data)
// from a JSON file the Python side writes, and prints one JSON line per event.
// Run with NODE_PATH pointing at a node_modules that holds @walletconnect/sign-client and viem (not part of this
// repository):
//   WALLETCONNECT_PROJECT_ID=... SEPOLIA_RPC=... node live_dapp.js SCENARIO.json STORAGE_FILE
const fs = require('fs');
const { SignClient } = require('@walletconnect/sign-client');
const { createPublicClient, http, hashMessage, hashTypedData, toHex } = require('viem');
const { sepolia } = require('viem/chains');

const ERC1271 = [{
  name: 'isValidSignature', type: 'function', stateMutability: 'view',
  inputs: [{ name: 'hash', type: 'bytes32' }, { name: 'signature', type: 'bytes' }],
  outputs: [{ name: '', type: 'bytes4' }],
}];
const out = (o) => console.log(JSON.stringify(o));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function erc1271(chain, safe, hash, signature) {
  try {
    return await chain.readContract({ address: safe, abi: ERC1271, functionName: 'isValidSignature',
                                      args: [hash, signature] });
  } catch (e) {
    return `reverted: ${e.shortMessage || e.message}`;
  }
}

async function main() {
  const [scenarioPath, storage] = process.argv.slice(2);
  const sc = JSON.parse(fs.readFileSync(scenarioPath, 'utf8'));
  const chain = createPublicClient({ chain: sepolia, transport: http(process.env.SEPOLIA_RPC) });
  const caip = `eip155:${sc.chainId}`;
  const client = await SignClient.init({
    projectId: process.env.WALLETCONNECT_PROJECT_ID,
    telemetryEnabled: false,
    storageOptions: { database: storage },
    metadata: { name: 'Winterlock live test', description: 'a scripted dapp', url: `https://${sc.domain}`, icons: [] },
  });
  const { uri, approval } = await client.connect({
    optionalNamespaces: {
      eip155: {
        chains: [caip],
        methods: ['eth_sendTransaction', 'personal_sign', 'eth_signTypedData_v4', 'eth_getTransactionReceipt'],
        events: ['chainChanged', 'accountsChanged'],
      },
    },
  });
  out({ uri });
  const t0 = Date.now();
  const session = await approval();
  out({ step: 'session', ms: Date.now() - t0, accounts: session.namespaces.eip155.accounts,
        isTheSafe: session.namespaces.eip155.accounts.includes(`${caip}:${sc.safe}`),
        methods: session.namespaces.eip155.methods, wallet: session.peer.metadata.name });
  const ask = (method, params, expiry) => client.request({ topic: session.topic, chainId: caip,
                                                          request: { method, params }, expiry });
  const step = async (name, fn) => {
    const s = Date.now();
    try {
      const r = await fn();
      out(Object.assign({ step: name, ms: Date.now() - s }, r));
    } catch (e) {
      out({ step: name, ms: Date.now() - s, error: { code: e.code, message: e.message } });
    }
  };
  const safe = sc.safe;

  // (no eth_chainId or eth_accounts request: the SDK refuses methods outside the session; dapps read both from it)
  // a sign-in: the wallet gathers k members' stateless signatures and answers with the Safe's combined signature
  await step('sign-in', async () => {
    const s = Date.now();
    const sig = await ask('personal_sign', [toHex(sc.signIn), safe], 900);
    const answered = Date.now() - s;
    const viemOk = await chain.verifyMessage({ address: safe, message: sc.signIn, signature: sig });
    const viemOther = await chain.verifyMessage({ address: safe, message: sc.signIn + ' ', signature: sig });
    return { answeredMs: answered, bytes: (sig.length - 2) / 2, viemVerifyMessage: viemOk, viemOtherMessage: viemOther,
             isValidSignature: await erc1271(chain, safe, hashMessage(sc.signIn), sig) };
  });

  // a transfer: the wallet proposes a SafeTx and answers with its hash; the dapp asks the wallet for the receipt
  await step('transaction', async () => {
    const h = await ask('eth_sendTransaction', [{ from: safe, to: sc.transfer.to, value: toHex(BigInt(sc.transfer.value)) }]);
    out({ step: 'transaction-proposed', safeTxHash: h });
    const s = Date.now();
    for (let polls = 1; Date.now() - s < sc.receiptWaitMs; polls++) {
      const receipt = await ask('eth_getTransactionReceipt', [h]);
      if (receipt) {
        const onChain = await chain.getTransactionReceipt({ hash: receipt.transactionHash });
        return { safeTxHash: h, polls, waitedMs: Date.now() - s, status: receipt.status,
                 transactionHash: receipt.transactionHash, matchesChain: onChain.status === 'success'
                   && onChain.blockHash === receipt.blockHash, gasUsed: Number(onChain.gasUsed) };
      }
      await sleep(sc.receiptPollMs);
    }
    return { safeTxHash: h, error: 'no receipt in time' };
  });

  // a Permit2 permit: the wallet approves it on-chain through SignMessageLib and answers 0x
  await step('permit2', async () => {
    const s = Date.now();
    const sig = await ask('eth_signTypedData_v4', [safe, JSON.stringify(sc.permit2)], 900);
    const answered = Date.now() - s;
    const { types, domain, message, primaryType } = sc.permit2;
    const t = Object.fromEntries(Object.entries(types).filter(([k]) => k !== 'EIP712Domain'));
    const hash = hashTypedData({ domain, types: t, primaryType, message });
    let viemOk;
    try {
      viemOk = await chain.verifyTypedData({ address: safe, domain, types: t, primaryType, message, signature: sig });
    } catch (e) {
      viemOk = `threw: ${e.shortMessage || e.message}`;
    }
    return { answeredMs: answered, signature: sig, viemVerifyTypedData: viemOk,
             isValidSignature: await erc1271(chain, safe, hash, sig) };
  });

  await client.disconnect({ topic: session.topic, reason: { code: 6000, message: 'done' } });
  out({ done: true });
  process.exit(0);
}

main().catch((e) => { out({ fatal: String((e && e.stack) || e) }); process.exit(1); });
