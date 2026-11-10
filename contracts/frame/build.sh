#!/usr/bin/env bash
# Builds the EIP-8141 frame accounts (Yul, for `verbatim`) with solc 0.8.28 and pins their creation code in
# accounts.json, which bench/daisugi/daisugi.py deploys and derives addresses from. Forge can't build these: its Yul
# mode takes one file per run. `./build.sh --check` fails if a source no longer gives its pinned code.
set -euo pipefail
cd "$(dirname "$0")"
SOLC=${SOLC:-$HOME/.local/share/svm/0.8.28/solc-0.8.28}
"$SOLC" --version | grep -q "0.8.28" || { echo "need solc 0.8.28 (SOLC=...)"; exit 1; }
python3 - "$SOLC" "${1:-}" <<'PY'
import json, subprocess, sys
solc, mode = sys.argv[1], sys.argv[2]
out = {}
for version, name in (("v0", "WinterlockFrameAccount"), ("v1", "WinterlockFrameAccountV1"),
                      ("v2", "WinterlockFrameAccountV2")):
    r = subprocess.run([solc, "--strict-assembly", "--evm-version", "prague", "--optimize", "--optimize-runs", "200",
                        "--bin", f"{name}.yul"], capture_output=True, text=True, check=True).stdout.splitlines()
    code = "0x" + r[r.index("Binary representation:") + 1].strip()
    out[version] = {"source": f"{name}.yul", "salt": f"Winterlock.frame-account.{version}", "creation_code": code}
if mode == "--check":
    pinned = json.load(open("accounts.json"))
    bad = [v for v in out if pinned.get(v, {}).get("creation_code") != out[v]["creation_code"]]
    sys.exit(f"sources differ from accounts.json: {bad}") if bad else print("accounts.json matches the sources")
else:
    json.dump(out, open("accounts.json", "w"), indent=1)
    print("\n".join(f"{v}: {len(o['creation_code']) // 2 - 1} bytes of creation code" for v, o in out.items()))
PY
