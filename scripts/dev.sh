#!/bin/sh
# Runs a command in a throwaway Python container with the repo mounted at /src.
# Usage: scripts/dev.sh pytest -q | scripts/dev.sh ruff check --fix
# Host network: the test containers publish their ports on 127.0.0.1 only (scripts/test-containers.sh);
# host.docker.internal is slow and drops connections on Docker Desktop.
set -eu
cd "$(dirname "$0")/.."
docker build -q -t ordivus-dev -f scripts/Dockerfile.dev . >/dev/null
exec docker run --rm --network host -v "$PWD":/src -w /src \
  -e ORDIVUS_TEST_HOST="${ORDIVUS_TEST_HOST:-127.0.0.1}" ordivus-dev \
  sh -c 'pip install -q --no-deps --root-user-action=ignore -e . >/dev/null 2>&1 && exec "$@"' sh "$@"
