#!/bin/sh
# Starts (or stops) the throwaway target systems the integration tests expect.
# Usage: scripts/test-containers.sh up | down
# Passwords below are fixed test values for disposable local containers, never for real systems.
set -eu

up() {
  name=$1; shift
  if docker container inspect "ordivus-it-$name" >/dev/null 2>&1; then
    echo "ordivus-it-$name already running"; return
  fi
  docker run -d --rm --name "ordivus-it-$name" "$@" >/dev/null && echo "started ordivus-it-$name"
}

case "${1:-up}" in
  up)
    up postgresql -p 15432:5432 -e POSTGRES_PASSWORD=ordivus-it postgres:17-alpine
    up mysql -p 13306:3306 -e MYSQL_ROOT_PASSWORD=ordivus-root mysql:8.4
    up clickhouse -p 18123:8123 -e CLICKHOUSE_USER=admin -e CLICKHOUSE_PASSWORD=adminpw-it \
      -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 clickhouse/clickhouse-server:25.8
    up arcadedb -p 12480:2480 -e JAVA_OPTS="-Darcadedb.server.rootPassword=ordivus-root-pw" \
      arcadedata/arcadedb:latest
    up redis -p 16379:6379 redis:8-alpine redis-server \
      --user admin on '>adminpw-it' '~*' '&*' '+@all' --requirepass defaultpw-it
    up openbao -p 18200:8200 openbao/openbao:latest \
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
