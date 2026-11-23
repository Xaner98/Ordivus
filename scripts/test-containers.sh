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
    up mariadb $(port 13307:3306) -e MARIADB_ROOT_PASSWORD=ordivus-root mariadb:11.4
    up mongodb $(port 17017:27017) -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=ordivus-root mongo:8.0
    up rabbitmq $(port 15673:15672) -e RABBITMQ_DEFAULT_USER=admin -e RABBITMQ_DEFAULT_PASS=adminpw-it rabbitmq:4.1-management
    up keycloak $(port 18080:8080) -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=adminpw-it \
      quay.io/keycloak/keycloak:26.4 start-dev
    up grafana $(port 13000:3000) -e GF_SECURITY_ADMIN_USER=admin -e GF_SECURITY_ADMIN_PASSWORD=adminpw-it grafana/grafana:12.2.0
    # Kafka: single-node KRaft, SASL_PLAINTEXT with SCRAM, StandardAuthorizer, super user admin bootstrapped at format.
    # Listens on 19092 inside the container too, so the advertised address works for the broker itself.
    up kafka $(port 19092:19092) --entrypoint sh apache/kafka:4.1.0 -c '
      jaas="org.apache.kafka.common.security.scram.ScramLoginModule required username=\"admin\" password=\"adminpw-it\";"
      cat > /tmp/server.properties <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:9093
listeners=SASL_PLAINTEXT://:19092,CONTROLLER://localhost:9093
advertised.listeners=SASL_PLAINTEXT://127.0.0.1:19092
listener.security.protocol.map=SASL_PLAINTEXT:SASL_PLAINTEXT,CONTROLLER:SASL_PLAINTEXT
controller.listener.names=CONTROLLER
inter.broker.listener.name=SASL_PLAINTEXT
sasl.enabled.mechanisms=SCRAM-SHA-512,SCRAM-SHA-256
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-512
sasl.mechanism.controller.protocol=SCRAM-SHA-512
listener.name.sasl_plaintext.scram-sha-512.sasl.jaas.config=$jaas
listener.name.sasl_plaintext.scram-sha-256.sasl.jaas.config=$jaas
listener.name.controller.sasl.enabled.mechanisms=SCRAM-SHA-512
listener.name.controller.scram-sha-512.sasl.jaas.config=$jaas
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
allow.everyone.if.no.acl.found=false
super.users=User:admin
log.dirs=/tmp/kraft-logs
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
EOF
      /opt/kafka/bin/kafka-storage.sh format -t "$(/opt/kafka/bin/kafka-storage.sh random-uuid)" \
        -c /tmp/server.properties --add-scram "SCRAM-SHA-512=[name=admin,password=adminpw-it]" &&
      exec /opt/kafka/bin/kafka-server-start.sh /tmp/server.properties'
    echo "MySQL, MariaDB, ArcadeDB, Keycloak and Kafka need up to a minute until they accept connections."
    ;;
  down)
    for name in postgresql mysql clickhouse arcadedb redis openbao mariadb mongodb rabbitmq keycloak grafana kafka; do
      docker rm -f "ordivus-it-$name" >/dev/null 2>&1 && echo "removed ordivus-it-$name" || true
    done
    ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
