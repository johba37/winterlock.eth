#!/usr/bin/env bash
# One-time setup: submodules, plus ZeroDev Kernel built with its own production profile
# (via-IR, 200 runs). Our default profile would make Kernel exceed the 24 KB contract size limit.
# Safe's contracts (v1.4.1 and v1.5.0) are built with their release settings: solc 0.7.6, optimizer off
# (CHANGELOG.md of each release), into each submodule's build/ directory, which Safe's .gitignore covers.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"
git submodule update --init --recursive
(cd lib/kernel && FOUNDRY_PROFILE=deploy forge build src/Kernel.sol src/factory/KernelFactory.sol src/factory/FactoryStaker.sol src/validator/ECDSAValidator.sol)
for v in v1.4.1 v1.5.0; do
  (cd "lib/safe-smart-account-$v" && forge build --root . --contracts contracts --use 0.7.6 --optimize false \
    --evm-version istanbul --out build/forge-out --cache-path build/forge-cache \
    contracts/Safe.sol contracts/SafeL2.sol contracts/proxies/SafeProxyFactory.sol \
    contracts/handler/CompatibilityFallbackHandler.sol contracts/libraries/MultiSendCallOnly.sol \
    contracts/libraries/SignMessageLib.sol)
done
