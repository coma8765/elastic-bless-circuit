#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# BUILD_IMAGES is an allowlisted space-separated subset. Control uses the common
# node image as its base; remote exits can receive only a prebuilt node image.
engine=${CONTAINER_ENGINE:-podman}
targets=${BUILD_IMAGES:-"node control headscale gateway"}
case "$engine" in podman|docker) ;; *) echo "Unsupported CONTAINER_ENGINE" >&2; exit 1;; esac
node_needed=false
control_needed=false
headscale_needed=false
gateway_needed=false
for target in $targets; do
  case "$target" in
    node) node_needed=true ;;
    control) node_needed=true; control_needed=true ;;
    headscale) headscale_needed=true ;;
    gateway) gateway_needed=true ;;
    *) echo "Unsupported BUILD_IMAGES entry: $target" >&2; exit 1 ;;
  esac
done
if [ "$node_needed" = true ]; then
  if [ "$engine" = podman ]; then
    podman build --format oci -t localhost/vless-node:build -f infra/Dockerfile.common .
    podman build --format docker -t localhost/vless-node:dev -f infra/Dockerfile.release .
  else
    # Docker preserves HEALTHCHECK natively and does not accept Podman --format.
    docker build -t localhost/vless-node:dev -f infra/Dockerfile.common .
  fi
fi
if [ "$control_needed" = true ]; then
  if [ "$engine" = podman ]; then
    podman build --format docker -t localhost/vless-control:dev -f infra/Dockerfile.control .
  else
    docker build -t localhost/vless-control:dev -f infra/Dockerfile.control .
  fi
fi
if [ "$control_needed" = true ] && [ "${PANEL_CLIENT_MODE:-grouped}" = single ]; then
  if [ "$engine" = podman ]; then
    podman build --format docker -t localhost/vless-control:single -f infra/Dockerfile.control.single .
  else
    docker build -t localhost/vless-control:single -f infra/Dockerfile.control.single .
  fi
fi
if [ "$headscale_needed" = true ]; then
  if [ "$engine" = podman ]; then
    podman build --format oci -t localhost/vless-headscale:dev -f infra/Dockerfile.headscale .
  else
    docker build -t localhost/vless-headscale:dev -f infra/Dockerfile.headscale .
  fi
fi
if [ "$gateway_needed" = true ]; then
  if [ "$engine" = podman ]; then
    podman build --format oci -t localhost/vless-gateway:dev -f infra/Dockerfile.gateway .
  else
    docker build -t localhost/vless-gateway:dev -f infra/Dockerfile.gateway .
  fi
fi
