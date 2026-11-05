#!/usr/bin/env bash
# Stage 2 bundler acceptance: hosted bundlers (Pimlico, Candide, Alchemy) on a public testnet (default Arbitrum
# Sepolia; CHAIN_ID=11155111 for Ethereum Sepolia), against the canonical EntryPoint v0.7 and ZeroDev's deployed
# Kernel v3.3. Only the Winterlock validators are ours. ONLY="name,name" limits the scenarios (driver.py).
#
# Needs bench/bundlers/.env (git-ignored): PIMLICO_API_KEY, ALCHEMY_API_KEY, DEPLOYER_PRIVATE_KEY of a funded
# throwaway testnet key. WOTS signing runs on a local anvil: the signer helper derives keys from public tags
# and never goes on a public chain.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.foundry/bin:$PATH"
set -a
# shellcheck disable=SC1091
. bench/bundlers/.env
set +a

CHAIN_ID="${CHAIN_ID:-421614}"
case "$CHAIN_ID" in
  421614) ALCHEMY_NET=arb-sepolia ;;
  11155111) ALCHEMY_NET=eth-sepolia ;;
  *) echo "unknown chain $CHAIN_ID"; exit 1 ;;
esac
RPC="${NODE_RPC:-https://$ALCHEMY_NET.g.alchemy.com/v2/$ALCHEMY_API_KEY}"
DEPLOYMENT="bench/bundlers/deployment-$CHAIN_ID.json"
SIGNER_PORT=8547
SIGNER_RPC="http://127.0.0.1:$SIGNER_PORT"
ANVIL_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil's test key, local only

[ "$(cast chain-id --rpc-url "$RPC")" = "$CHAIN_ID" ] || { echo "RPC is not chain $CHAIN_ID"; exit 1; }
echo "deployer $DEPLOYER_ADDRESS: $(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC" -e) ETH"

anvil --port "$SIGNER_PORT" --disable-block-gas-limit --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null || true' EXIT
timeout 30 bash -c "until cast chain-id --rpc-url $SIGNER_RPC >/dev/null 2>&1; do :; done"
HELPER=$(forge create test/utils/SignerHelper.sol:WotsSignerHelper --rpc-url "$SIGNER_RPC" --private-key "$ANVIL_PK" \
  --broadcast --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["deployedTo"])')

if [ ! -f "$DEPLOYMENT" ]; then
  echo "deploying the Winterlock validators on chain $CHAIN_ID"
  DEPLOYMENT_FILE="$DEPLOYMENT" forge script script/TestnetSetup.s.sol --rpc-url "$RPC" --broadcast --slow --quiet >/dev/null
fi

declare -A URLS=(
  [pimlico]="https://api.pimlico.io/v2/$CHAIN_ID/rpc?apikey=${PIMLICO_API_KEY:-}"
  [candide]="https://api.candide.dev/public/v3/$CHAIN_ID"
  [alchemy]="https://$ALCHEMY_NET.g.alchemy.com/v2/${ALCHEMY_API_KEY:-}"
)
ARGS=()
for name in ${BUNDLERS:-pimlico candide alchemy}; do
  # skip bundlers that don't answer or don't serve EntryPoint v0.7 here (missing key, network not enabled)
  if curl -sf -X POST -H 'content-type: application/json' -A winterlock-bench \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_supportedEntryPoints","params":[]}' "${URLS[$name]}" \
      | grep -qi 0x0000000071727De22E5E9d8BAf0edAc6f37da032; then
    ARGS+=(--bundler "$name=${URLS[$name]}")
  else
    echo "skipping $name: no EntryPoint v0.7 on chain $CHAIN_ID (key or network not enabled?)"
  fi
done
[ ${#ARGS[@]} -gt 0 ] || { echo "no bundler available"; exit 1; }

python3 bench/bundlers/driver.py --rpc "$RPC" --deployment "$DEPLOYMENT" --funder "$DEPLOYER_PRIVATE_KEY" \
  --signer-rpc "$SIGNER_RPC" --signer-helper "$HELPER" --fund "${FUND:-0.003ether}" --transfer-wei 1000000000000 \
  --fees bundler --out "bench/bundlers/results-$CHAIN_ID.json" ${ONLY:+--only "$ONLY"} "${ARGS[@]}"
