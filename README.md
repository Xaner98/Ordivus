# Ordivus

A lightweight, stateless, Kubernetes-native configuration engine for heterogeneous infrastructure. One engine. Every platform.

**Ordivus** manages users, roles, permissions, databases and policies in the systems you already run – declaratively, statelessly and with the same three commands for every system:

```sh
ordivus plan  -f ./config    # What would change?
ordivus drift -f ./config    # Does reality deviate? Are there foreign objects?
ordivus apply -f ./config    # Execute and verify permitted changes
```

Existing systems can be onboarded with `ordivus export`, which writes their current state as configuration ([docs/export.md](docs/export.md)).

You describe the desired state in YAML. On every run, Ordivus reads the actual state directly from the target system, shows every difference and changes only what is permitted. There is no state file, no database of its own and no permanently running controller.

> **Status:** Alpha (`0.1.0`). Interfaces and the configuration format may change before `1.0`.

## Why Ordivus?

- **One workflow for many systems.** PostgreSQL, MySQL, MariaDB, ClickHouse, MongoDB, ArcadeDB, Redis, Kafka, RabbitMQ, OpenBao, Keycloak and Grafana with the same configuration shape, the same commands, the same exit codes and the same report format.
- **Stateless.** The truth lives in your configuration and in the target system. That is why Ordivus also sees objects someone created by hand.
- **Safe by default.** Undeclared objects are only reported, never silently deleted. Deleting requires an explicitly bounded scope *and* a separately managed operator policy. Anything that cannot be read completely counts as unknown – not as empty.
- **Secrets stay secret.** Passwords never appear in the configuration, and never in reports or logs. Ordivus generates missing passwords in a cryptographically secure way and stores them *create-if-absent* in your secret store (file/Kubernetes Secret or OpenBao).
- **Fits your automation.** GitLab CI, Jenkins, Argo CD, Flux, Kubernetes CronJobs or simply your terminal. Ordivus is a CLI process that starts, works and exits.
- **Runs anywhere.** Locally, in CI, on a VM or as a Kubernetes Job; target systems inside or outside a cluster.

## Supported systems

| Adapter | Managed resources | Docs |
|---|---|---|
| PostgreSQL | Databases, roles, users, memberships, grants (database, schema, tables of a schema) | [docs/adapters/postgresql.md](docs/adapters/postgresql.md) |
| MySQL | Databases, roles, accounts (`user@host`), role assignments, grants | [docs/adapters/mysql.md](docs/adapters/mysql.md) |
| ClickHouse | Databases, roles, users, grants | [docs/adapters/clickhouse.md](docs/adapters/clickhouse.md) |
| ArcadeDB | Databases, users with groups per database | [docs/adapters/arcadedb.md](docs/adapters/arcadedb.md) |
| Redis | ACL users (keys, channels, commands) | [docs/adapters/redis.md](docs/adapters/redis.md) |
| OpenBao | ACL policies | [docs/adapters/openbao.md](docs/adapters/openbao.md) |
| MariaDB | Databases, roles, accounts, role assignments, grants | [docs/adapters/mariadb.md](docs/adapters/mariadb.md) |
| MongoDB | Custom roles, users with roles | [docs/adapters/mongodb.md](docs/adapters/mongodb.md) |
| RabbitMQ | Virtual hosts, users with tags and permissions | [docs/adapters/rabbitmq.md](docs/adapters/rabbitmq.md) |
| Keycloak | Realms, realm roles, groups, OIDC clients (incl. client secret) | [docs/adapters/keycloak.md](docs/adapters/keycloak.md) |
| Kafka | SCRAM users, ACLs | [docs/adapters/kafka.md](docs/adapters/kafka.md) |
| Grafana | Teams, folders with permissions, service accounts | [docs/adapters/grafana.md](docs/adapters/grafana.md) |

Every adapter reads the server version on connect, reports it as `serverVersion` and refuses versions below its documented minimum.

Secret sources: files or mounted Kubernetes Secrets, [OpenBao KV v2](docs/credentials/openbao.md) and – for development only – environment variables.

## Installation

Requirement: Python 3.13 or newer.

```sh
pip install "ordivus[postgresql,mysql,mariadb,mongodb,redis,kafka] @ git+https://github.com/Xaner98/Ordivus.git"
ordivus --version
```

The extras install the client libraries. ClickHouse, ArcadeDB, OpenBao, RabbitMQ, Keycloak and Grafana need no additional packages. Install only what you need, e.g. `ordivus[postgresql]`.

As a container image (contains all adapters, runs as a non-root user with a read-only file system):

```sh
git clone https://github.com/Xaner98/Ordivus.git && cd Ordivus
docker build -t ordivus .
docker run --rm ordivus --version
```

For Kubernetes there is a Helm chart with prepared job templates for `plan`, `drift` and `apply`: [docs/kubernetes.md](docs/kubernetes.md).

## Quickstart

The [quickstart](docs/quickstart.md) sets up a PostgreSQL instance in Docker in five minutes and manages a user with an automatically generated password in it. The short version:

```yaml
# config/ordivus.yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata: {name: demo-postgres}
spec:
  adapter: postgresql
  endpoint: {host: localhost, port: 5432, user: postgres}
  authentication: {credentialRef: admin}
---
apiVersion: ordivus.dev/v1alpha1
kind: CredentialProvider
metadata: {name: secrets}
spec: {type: file, directory: ./secrets}
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata: {name: admin}
spec: {providerRef: secrets, path: admin}
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata: {name: app-password}
spec: {providerRef: secrets, path: app}
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata: {name: app}
spec:
  targetRef: demo-postgres
  credentials: {credentialRef: app-password}
```

```sh
ordivus plan  -f config    # shows: CREATE_SECRET app, CREATE DatabaseUser app
ordivus apply -f config    # creates ./secrets/app and creates the user
ordivus apply -f config    # nothing left to do
```

## Documentation

- [Concepts](docs/concepts.md) – stateless, additive/authoritative, unknown stays unknown, passwords
- [Configuration](docs/configuration.md) – file structure, engine kinds, operator policy, exit codes, report format
- [Quickstart](docs/quickstart.md)
- [Export](docs/export.md) – onboard existing systems: live state as configuration
- [Rules](docs/rules.md) – built-in compliance checks against the live state (e.g. superuser logins, sudo policies)
- [Kubernetes and CI/CD](docs/kubernetes.md) – Helm chart, job templates, GitLab, Jenkins, Argo CD, Flux
- Adapters: [PostgreSQL](docs/adapters/postgresql.md) · [MySQL](docs/adapters/mysql.md) · [ClickHouse](docs/adapters/clickhouse.md) · [ArcadeDB](docs/adapters/arcadedb.md) · [Redis](docs/adapters/redis.md) · [OpenBao](docs/adapters/openbao.md) · [MariaDB](docs/adapters/mariadb.md) · [MongoDB](docs/adapters/mongodb.md) · [RabbitMQ](docs/adapters/rabbitmq.md) · [Keycloak](docs/adapters/keycloak.md) · [Kafka](docs/adapters/kafka.md) · [Grafana](docs/adapters/grafana.md)
- Secret sources: [OpenBao KV v2](docs/credentials/openbao.md)
- [Development and contributing](docs/development.md)
- Examples: [`examples/`](examples/)

## What Ordivus is not

Not a replacement for Terraform, Helm, Ansible, Argo CD or Flux; not a secret manager; not a tool for schema migrations or data migration; not a distributed transaction across multiple systems. Ordivus takes care of the administrative desired state *inside* your systems and works together with the tools you already have.

## License

[Apache License 2.0](LICENSE)
