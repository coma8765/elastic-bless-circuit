#!/bin/sh
set -eu
# Render and other one-shot commands do not need TUN or a daemon.
if [ "${1:-}" != node-agent ] || { [ "${2:-}" != run ] && [ "${2:-}" != control ]; }; then exec "$@"; fi
mkdir -p /run/tailscale /var/lib/tailscale
rm -f /run/node/ready
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --port=41641 &
mesh=$!
i=0
while [ ! -S /var/run/tailscale/tailscaled.sock ]; do
  kill -0 "$mesh" 2>/dev/null || exit 1
  i=$((i + 1)); [ "$i" -lt 100 ] || exit 1
  sleep 0.1
done
"$@" &
agent=$!
trap 'kill "$agent" "$mesh" 2>/dev/null || true; wait "$agent" || true; wait "$mesh" || true' EXIT
trap 'exit 0' TERM INT
while kill -0 "$agent" 2>/dev/null && kill -0 "$mesh" 2>/dev/null; do sleep 1; done
exit 1
