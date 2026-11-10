#!/usr/bin/env bash
# Whole transactions on a throwaway anvil: deploys both verifiers and sends verify(pk, message, signature) for each
# gas sample; tools/txgas.py splits every receipt into 21,000 + calldata + execution.
#   ./gas.sh                      # Prague, as contracts/bench.sh
#   HARDFORK=osaka ./gas.sh
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"

PORT="${PORT:-8548}"
HARDFORK="${HARDFORK:-prague}"
RPC="http://127.0.0.1:$PORT"

forge build --quiet
anvil --port "$PORT" --hardfork "$HARDFORK" --gas-limit 60000000 --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null' EXIT
timeout 15 bash -c "until cast chain-id --rpc-url $RPC >/dev/null 2>&1; do :; done"
echo "hardfork: $HARDFORK"
python3 tools/txgas.py "$RPC"
