#!/usr/bin/env bash
# One-time setup: submodules, plus ZeroDev Kernel built with its own production profile
# (via-IR, 200 runs). Our default profile would make Kernel exceed the 24 KB contract size limit.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"
git submodule update --init --recursive
(cd lib/kernel && FOUNDRY_PROFILE=deploy forge build src/Kernel.sol src/factory/KernelFactory.sol src/validator/ECDSAValidator.sol)
