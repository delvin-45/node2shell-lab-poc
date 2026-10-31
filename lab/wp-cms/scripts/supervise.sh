#!/bin/sh
# Restart the Node process after a network-triggered decoder crash.
# Disabled by default so the denial-of-service control can observe a dead service.
set -eu

if [ "${N2S_SUPERVISE:-0}" != "1" ]; then
  exec node /app/server.js
fi

while :; do
  node /app/server.js || true
  echo "supervisor: node exited, restarting" >&2
  # Keep a visible down window so the operator and the PoC can distinguish a
  # fresh process from the process that just crashed.
  sleep 1
done
