#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -d frontend/node_modules ]]; then
  (cd frontend && npm ci --cache .cache/npm)
fi
python3 -m backend.server &
backend_pid=$!
cleanup() {
  kill "$backend_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sleep 0.3
if ! kill -0 "$backend_pid" 2>/dev/null; then
  echo "Le backend n’a pas démarré. Vérifier que le port 8000 est libre." >&2
  exit 1
fi
cd frontend
npm start
