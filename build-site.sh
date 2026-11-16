#!/usr/bin/env bash
# Assembles the landing site as it is published at winterlock.eth:
#   index.html, fonts/, img/   the landing page
#   check/                     the exposure check (exposure/), built
# Usage: ./build-site.sh [out-dir]   (default: site-dist, which must not exist yet)
# Needs Node and npm. The result is the folder to pin to IPFS; nothing else in the repository
# belongs in it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/site-dist}"
if [ -e "$out" ]; then
  echo "$out exists already: remove it, or name another folder" >&2
  exit 1
fi
(cd "$here/exposure" && npm ci --silent && npm run build --silent)
mkdir -p "$out"
cp "$here/index.html" "$out/"
cp -r "$here/fonts" "$out/fonts"
cp -r "$here/img" "$out/img"
cp -r "$here/exposure/dist" "$out/check"
echo "site in $out: $(find "$out" -type f | wc -l) files, $(du -sh "$out" | cut -f1)"
