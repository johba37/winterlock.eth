#!/usr/bin/env bash
# Gas benchmark: starts a throwaway anvil, sends real handleOps transactions, prints a table from receipts.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"

PORT="${PORT:-8547}"
HARDFORK="${HARDFORK:-prague}"
RPC="http://127.0.0.1:$PORT"
# anvil's first default account; local chain only
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

anvil --port "$PORT" --hardfork "$HARDFORK" --gas-limit 60000000 --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null' EXIT
timeout 15 bash -c "until cast chain-id --rpc-url $RPC >/dev/null 2>&1; do :; done"

[ -f lib/kernel/out/Kernel.sol/Kernel.json ] || ./setup.sh
mkdir -p bench
forge script script/GasBench.s.sol --rpc-url "$RPC" --broadcast --slow --quiet --gas-estimate-multiplier 400 --disable-block-gas-limit >/dev/null
echo "hardfork: $HARDFORK"
python3 bench/report.py broadcast/GasBench.s.sol/31337/run-latest.json bench/labels.json
# Optional: price the same transactions on an OP Stack L2, e.g. L2_RPC=https://mainnet.base.org ./bench.sh
if [ -n "${L2_RPC:-}" ]; then
  python3 bench/l2.py broadcast/GasBench.s.sol/31337/run-latest.json bench/labels.json "$RPC" "$L2_RPC"
fi
