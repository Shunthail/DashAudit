#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# -lt 2 || $# -gt 3 || "$1" != "--authorized" ]]; then
  echo "Usage: bash scripts/audit.sh --authorized https://votre-site.fr [--cves]" >&2
  exit 1
fi
shift
exec python3 -m backend.cli "$@"
