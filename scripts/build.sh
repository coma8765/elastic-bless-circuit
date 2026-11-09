#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
podman build --format oci -t localhost/vless-node:build -f infra/Dockerfile.common .
podman build --format docker -t localhost/vless-node:dev -f infra/Dockerfile.release .
podman build --format docker -t localhost/vless-control:dev -f infra/Dockerfile.control .
podman build --format oci -t localhost/vless-headscale:dev -f infra/Dockerfile.headscale .
podman build --format oci -t localhost/vless-gateway:dev -f infra/Dockerfile.gateway .
