#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f frontend/dist/dashaudit/browser/index.html ]]; then
  echo "Build manquant. Exécuter bash scripts/build.sh." >&2
  exit 1
fi
exec python3 -m backend.server
