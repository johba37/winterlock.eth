#!/usr/bin/env bash
# D10 live: the same Winterlock account (Kernel v3.3, D6) on Ethereum Sepolia and Arbitrum Sepolia, deployed on
# each by its first WOTS-signed operation through Pimlico, with a separate operation tree per chain.
#
# Needs bench/bundlers/.env (git-ignored): PIMLICO_API_KEY, ALCHEMY_API_KEY (node RPC), DEPLOYER_PRIVATE_KEY of a
# funded throwaway testnet key. Adds a secret MULTICHAIN_TAG, from which the test keys derive; delete that line
# for a fresh account. The validator must already be at its deterministic address on both chains
# (script/DeployValidator.s.sol). Signing runs on a local anvil.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.foundry/bin:$PATH"
ENV_FILE=bench/bundlers/.env
grep -q '^MULTICHAIN_TAG=' "$ENV_FILE" ||
  echo "MULTICHAIN_TAG=$(python3 -c 'import secrets; print(secrets.token_hex(16))')" >>"$ENV_FILE"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

SEPOLIA_NODE="${SEPOLIA_RPC:-https://eth-sepolia.g.alchemy.com/v2/$ALCHEMY_API_KEY}"
ARBITRUM_NODE="${ARB_SEPOLIA_RPC:-https://arb-sepolia.g.alchemy.com/v2/$ALCHEMY_API_KEY}"
SIGNER_PORT=8547
SIGNER_RPC="http://127.0.0.1:$SIGNER_PORT"
ANVIL_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil's test key, local only

anvil --port "$SIGNER_PORT" --disable-block-gas-limit --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null || true' EXIT
timeout 30 bash -c "until cast chain-id --rpc-url $SIGNER_RPC >/dev/null 2>&1; do :; done"
HELPER=$(forge create test/utils/SignerHelper.sol:WotsSignerHelper --rpc-url "$SIGNER_RPC" --private-key "$ANVIL_PK" \
  --broadcast --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["deployedTo"])')

python3 bench/bundlers/multichain.py --funder "$DEPLOYER_PRIVATE_KEY" --tag "$MULTICHAIN_TAG" \
  --signer-rpc "$SIGNER_RPC" --signer-helper "$HELPER" \
  --chain "sepolia=$SEPOLIA_NODE,https://api.pimlico.io/v2/11155111/rpc?apikey=$PIMLICO_API_KEY" \
  --chain "arbitrum-sepolia=$ARBITRUM_NODE,https://api.pimlico.io/v2/421614/rpc?apikey=$PIMLICO_API_KEY"
