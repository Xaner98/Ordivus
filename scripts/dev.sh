#!/bin/sh
# Runs a command in a throwaway Python container with the repo mounted at /src.
# Usage: scripts/dev.sh pytest -q | scripts/dev.sh ruff check --fix
# Integration tests reach containers published on the Docker host via ORDIVUS_TEST_HOST.
set -eu
cd "$(dirname "$0")/.."
docker build -q -t ordivus-dev -f scripts/Dockerfile.dev . >/dev/null
# Published ports via the bridge gateway; host.docker.internal is slow and drops connections on Docker Desktop.
gateway=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo host.docker.internal)
exec docker run --rm -v "$PWD":/src -w /src \
  -e ORDIVUS_TEST_HOST="${ORDIVUS_TEST_HOST:-$gateway}" ordivus-dev \
  sh -c 'pip install -q --no-deps --root-user-action=ignore -e . >/dev/null 2>&1 && exec "$@"' sh "$@"
