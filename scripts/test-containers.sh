#!/bin/sh
# Starts (or stops) the throwaway target systems the integration tests expect.
# Usage: scripts/test-containers.sh up | down
# Passwords below are fixed test values for disposable local containers, never for real systems.
# Ports are published only on 127.0.0.1, never on all interfaces (scripts/dev.sh uses --network host).
set -eu

port() { echo "-p 127.0.0.1:$1"; }

up() {
  name=$1; shift
  if docker container inspect "ordivus-it-$name" >/dev/null 2>&1; then
    echo "ordivus-it-$name already running"; return
  fi
  docker run -d --rm --name "ordivus-it-$name" "$@" >/dev/null && echo "started ordivus-it-$name"
}

case "${1:-up}" in
  up)
    # $(port ...) is intentionally unquoted: it expands to '-p' plus its argument.
    up postgresql $(port 15432:5432) -e POSTGRES_PASSWORD=ordivus-it postgres:17-alpine
    up mysql $(port 13306:3306) -e MYSQL_ROOT_PASSWORD=ordivus-root mysql:8.4
    up clickhouse $(port 18123:8123) -e CLICKHOUSE_USER=admin -e CLICKHOUSE_PASSWORD=adminpw-it \
      -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 clickhouse/clickhouse-server:25.8
    up arcadedb $(port 12480:2480) -e JAVA_OPTS="-Darcadedb.server.rootPassword=ordivus-root-pw" \
      arcadedata/arcadedb:26.12.1-SNAPSHOT@sha256:8732d33df7c4a91628e6ce8e8aaa4706efe1750f5c95fdc096f8ca88e7430b5c
    up redis $(port 16379:6379) redis:8-alpine redis-server \
      --user admin on '>adminpw-it' '~*' '&*' '+@all' --requirepass defaultpw-it
    up openbao $(port 18200:8200) \
      openbao/openbao:2.7.3@sha256:ba4b133eb9586630024e71a617e66f37f29cc3534cdd46a6233e098ceded8dc9 \
      server -dev -dev-root-token-id=ordivus-it-root -dev-listen-address=0.0.0.0:8200
    echo "MySQL and ArcadeDB need up to a minute until they accept connections."
    ;;
  down)
    for name in postgresql mysql clickhouse arcadedb redis openbao; do
      docker rm -f "ordivus-it-$name" >/dev/null 2>&1 && echo "removed ordivus-it-$name" || true
    done
    ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
