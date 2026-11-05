#!/usr/bin/env bash
# Stage 1 bundler acceptance: geth --dev + Alto + Rundler in Docker, real ERC-7562 checks (safe mode).
# Everything runs locally; containers are removed on exit.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.foundry/bin:$PATH"

GETH_PORT=8550
ALTO_PORT=4337
RUNDLER_PORT=3010
RPC="http://127.0.0.1:$GETH_PORT"
# geth 1.17 dev chains run future forks (Amsterdam, Bogota) from genesis; 1.16.9 matches mainnet (Osaka)
GETH_IMAGE="${GETH_IMAGE:-ethereum/client-go:v1.16.9}"
ALTO_IMAGE="${ALTO_IMAGE:-ghcr.io/pimlicolabs/alto:latest}"
RUNDLER_IMAGE="${RUNDLER_IMAGE:-alchemyplatform/rundler:v0.11.0}"

# anvil's well-known test keys; local dev chain only
DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ALTO_EXECUTOR_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
ALTO_UTILITY_PK=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RUNDLER_PK=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6

cleanup() {
  if [ "${KEEP_LOGS:-}" != "" ]; then
    mkdir -p bench/bundlers/logs
    for c in wl-geth wl-alto wl-rundler; do docker logs "$c" > "bench/bundlers/logs/$c.log" 2>&1 || true; done
  fi
  docker rm -f wl-geth wl-alto wl-rundler >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

[ -f lib/kernel/out/FactoryStaker.sol/FactoryStaker.json ] || ./setup.sh

echo "starting geth --dev"
# no eth_call gas cap or time limit: the signer helper's stateless keygen and signing take 50-150M gas per call
docker run -d --name wl-geth --network host "$GETH_IMAGE" \
  --dev --dev.period 1 --dev.gaslimit 30000000 \
  --http --http.addr 127.0.0.1 --http.port "$GETH_PORT" --http.api eth,net,web3,debug,txpool \
  --rpc.gascap 0 --rpc.evmtimeout 0 --rpc.txfeecap 0 --rpc.allow-unprotected-txs \
  --nodiscover --maxpeers 0 --port 30399 --authrpc.port 8561 >/dev/null
timeout 60 bash -c "until cast chain-id --rpc-url $RPC >/dev/null 2>&1; do :; done"

DEV=$(cast rpc eth_accounts --rpc-url "$RPC" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])')
for pk in $DEPLOYER_PK $ALTO_EXECUTOR_PK $ALTO_UTILITY_PK $RUNDLER_PK; do
  cast send --unlocked --from "$DEV" --value 1000ether "$(cast wallet address --private-key "$pk")" --rpc-url "$RPC" >/dev/null
done

# Deterministic deployment proxy (0x4e59b448...), which Alto uses for its simulation contract: the
# well-known keyless, pre-EIP-155 deployment transaction
cast send --unlocked --from "$DEV" --value 0.1ether 0x3fab184622dc19b6109349b94811493bf2a45362 --rpc-url "$RPC" >/dev/null
cast publish --rpc-url "$RPC" 0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222 >/dev/null
timeout 30 bash -c "until [ \"\$(cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url $RPC)\" != 0x ]; do :; done"

# The canonical EntryPoint v0.7 at 0x0000000071727De22E5E9d8BAf0edAc6f37da032: bundlers infer the EntryPoint
# version from its address. The deterministic-deployment call data comes from Alto's own local deployer.
echo "deploying the canonical EntryPoint v0.7"
CONSTANTS=$(docker run --rm --entrypoint sh "$ALTO_IMAGE" -c 'cat scripts/localDeployer/constants.ts')
createcall() { python3 -c 'import re,sys; print(re.search(sys.argv[1] + r"[^\"]*\"(0x[0-9a-fA-F]+)\"", sys.stdin.read()).group(1))' "$1" <<<"$CONSTANTS"; }
CREATECALL=$(createcall ENTRY_POINT_V07_CREATECALL)
cast send --private-key "$DEPLOYER_PK" --rpc-url "$RPC" 0x4e59b44847b379578588920ca78fbf26c0b4956c "$CREATECALL" >/dev/null
# Alto also expects EntryPointSimulations, deployed the same way; its address follows from CREATE2
SIMCALL=$(createcall ENTRY_POINT_SIMULATIONS_CREATECALL)
cast send --private-key "$DEPLOYER_PK" --rpc-url "$RPC" 0x4e59b44847b379578588920ca78fbf26c0b4956c "$SIMCALL" >/dev/null
SIMULATIONS=$(cast create2 --deployer 0x4e59b44847b379578588920ca78fbf26c0b4956c --salt "${SIMCALL:0:66}" --init-code "0x${SIMCALL:66}" | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
[ "$(cast code "$SIMULATIONS" --rpc-url "$RPC")" != 0x ] || { echo "EntryPointSimulations missing"; exit 1; }
EP=0x0000000071727De22E5E9d8BAf0edAc6f37da032
[ "$(cast code $EP --rpc-url "$RPC")" != 0x ] || { echo "canonical EntryPoint missing"; exit 1; }

echo "deploying Kernel, staked factory, validators"
ENTRY_POINT=$EP PRIVATE_KEY=$DEPLOYER_PK forge script script/BundlerSetup.s.sol --rpc-url "$RPC" --broadcast --slow --quiet \
  --disable-block-gas-limit --gas-estimate-multiplier 200 >/dev/null

# ALTO_SAFE_MODE=false skips Alto's ERC-7562 tracing but keeps its estimation, size, gas and PVG checks
echo "starting Alto (safe mode: ${ALTO_SAFE_MODE:-true})"
docker run -d --name wl-alto --network host "$ALTO_IMAGE" \
  --entrypoints "$EP" --executor-private-keys "$ALTO_EXECUTOR_PK" --utility-private-key "$ALTO_UTILITY_PK" \
  --rpc-url "$RPC" --port "$ALTO_PORT" --safe-mode "${ALTO_SAFE_MODE:-true}" --min-entity-stake 1 --min-entity-unstake-delay 1 \
  --entrypoint-simulation-contract-v7 "$SIMULATIONS" >/dev/null

echo "starting Rundler (safe mode)"
# Rundler's built-in "dev" spec (base ethereum, id 1337) plus our EntryPoint; a spec's base cannot itself have a base
cat > bench/bundlers/rundler-chain.toml <<EOF
base = "ethereum"
name = "Ethereum Devnet"
id = 1337
bundle_max_send_interval_millis = 250
block_gas_limit = 30000000
entry_point_address_v0_7 = "$EP"
EOF
docker run -d --name wl-rundler --network host -v "$PWD/bench/bundlers/rundler-chain.toml:/chain.toml:ro" \
  "$RUNDLER_IMAGE" node --chain_spec /chain.toml --node_http "$RPC" \
  --signer.private_keys "${RUNDLER_PK#0x}" --rpc.host 127.0.0.1 --rpc.port "$RUNDLER_PORT" \
  --metrics.host 127.0.0.1 --metrics.port 9476 >/dev/null

for url in "http://127.0.0.1:$ALTO_PORT" "http://127.0.0.1:$RUNDLER_PORT"; do
  timeout 120 bash -c "until curl -sf -X POST -H 'content-type: application/json' \
    --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_supportedEntryPoints\",\"params\":[]}' $url >/dev/null; do :; done" \
    || { echo "bundler at $url did not come up"; exit 1; }
done
echo "bundlers up"

# BUNDLERS selects which bundlers the driver tests (default: both)
ARGS=()
[[ "${BUNDLERS:-alto,rundler}" == *alto* ]] && ARGS+=(--bundler "alto=http://127.0.0.1:$ALTO_PORT")
[[ "${BUNDLERS:-alto,rundler}" == *rundler* ]] && ARGS+=(--bundler "rundler=http://127.0.0.1:$RUNDLER_PORT")
python3 bench/bundlers/driver.py --rpc "$RPC" --deployment bench/bundlers/deployment.json --funder "$DEPLOYER_PK" "${ARGS[@]}"
