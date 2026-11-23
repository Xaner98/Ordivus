# Development and contributing

## Structure

```text
src/ordivus/
├── cli.py               # thin CLI: arguments, exit codes, output
├── core/                # engine as a library
│   ├── config.py        # load YAML/JSON (YAML 1.2), digest
│   ├── engine.py        # desired model, discovery, comparison, execution
│   ├── policy.py        # operator policy
│   └── report.py        # JSON/text report
├── adapters/            # one module per target system, contract in base.py
└── credentials/         # credential providers (file, env, openbao-kv-v2)
charts/ordivus/          # Helm chart
tests/unit|integration|e2e/
```

## Local environment

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[postgresql,mysql,redis,dev]'
.venv/bin/pytest -q tests/unit
.venv/bin/ruff check
```

Alternatively, without a local Python: `scripts/dev.sh <command>` runs any command in a Python container, e.g. `scripts/dev.sh pytest -q`.

## Integration tests

The integration tests run against real target systems in Docker and are skipped if a system is not reachable. Expected containers and ports:

| System | Container | Host port |
|---|---|---|
| PostgreSQL | `postgres:17-alpine` | 15432 |
| MySQL | `mysql:8.4` | 13306 |
| ClickHouse | `clickhouse/clickhouse-server:25.8` | 18123 |
| ArcadeDB | `arcadedata/arcadedb:26.12.1-SNAPSHOT` (pinned by digest) | 12480 |
| Redis | `redis:8-alpine` | 16379 |
| OpenBao | `openbao/openbao:2.7.3` (pinned by digest, dev mode) | 18200 |

`scripts/test-containers.sh up` starts all six containers with the test credentials the tests expect; `scripts/test-containers.sh down` removes them again. `ORDIVUS_TEST_HOST` sets the hostname under which the containers are reachable (default `localhost`). The ports are published only on `127.0.0.1`, not on all interfaces; `scripts/dev.sh` therefore starts its container with `--network host` and `ORDIVUS_TEST_HOST=127.0.0.1` (the bridge gateway address cannot be used as a bind address under Docker Desktop, and `host.docker.internal` is slow).

Kubernetes E2E against a local cluster (e.g. Docker Desktop):

```sh
docker build -t ordivus:dev .
ORDIVUS_E2E=1 tests/e2e/run.sh
```

## Dependencies and lock file

In `pyproject.toml`, every dependency has an upper bound below the next major version. The production image installs exclusively from `requirements.lock` (`pip install --require-hashes`, wheels only) and then the Ordivus package itself with `--no-deps`; the build backend (setuptools) is also in the lock with a hash. After every change to the dependencies, regenerate the lock and commit it along with the change:

```sh
scripts/dev.sh sh -c 'pip install -q pip-tools && pip-compile -q --strip-extras --generate-hashes --all-build-deps \
  --allow-unsafe --extra postgresql --extra mysql --extra redis --no-emit-index-url -o requirements.lock pyproject.toml'
```

The base image is pinned by digest in the `Dockerfile` (`ARG PYTHON_IMAGE`). To update: `docker buildx imagetools inspect python:3.14-slim` and enter the digest. To check: `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.67.2 image --ignore-unfixed --severity HIGH,CRITICAL ordivus:dev`.

## Writing an adapter

1. Read `src/ordivus/adapters/base.py` – the contract is fully documented there.
2. Derive a class from `Adapter`, set `id` and `kinds`, implement the methods.
3. Register it in `pyproject.toml` under `[project.entry-points."ordivus.adapters"]`. External packages can register in the same group without changing Ordivus.
4. Add integration tests against a real system, an example under `examples/<adapter>/` and a page under `docs/adapters/`.

Mandatory for every adapter: read-only sessions mutate nothing, incomplete discovery is reported as `partial`/`forbidden`, identifiers are quoted safely, secrets appear in no error message.

## Pull requests

- Tests and `ruff check` must pass.
- Behavior changes at security boundaries (deleting, passwords, read-only, policy) need a test that demonstrates the new behavior.
- Please do not report vulnerabilities as a public issue; use a private security advisory on GitHub instead.
