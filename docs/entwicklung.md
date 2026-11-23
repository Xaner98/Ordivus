# Entwicklung und Beiträge

## Aufbau

```text
src/ordivus/
├── cli.py               # dünne CLI: Argumente, Exit-Codes, Ausgabe
├── core/                # Engine als Bibliothek
│   ├── config.py        # YAML/JSON laden (YAML 1.2), Digest
│   ├── engine.py        # Sollmodell, Discovery, Vergleich, Ausführung
│   ├── policy.py        # Operator Policy
│   └── report.py        # JSON-/Text-Report
├── adapters/            # ein Modul je Zielsystem, Vertrag in base.py
└── credentials/         # Credential Provider (file, env, openbao-kv-v2)
charts/ordivus/          # Helm Chart
tests/unit|integration|e2e/
```

## Lokale Umgebung

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[postgresql,mysql,redis,dev]'
.venv/bin/pytest -q tests/unit
.venv/bin/ruff check
```

Alternativ ohne lokales Python: `scripts/dev.sh <befehl>` führt jeden Befehl in einem Python-Container aus, z. B. `scripts/dev.sh pytest -q`.

## Integrationstests

Die Integrationstests laufen gegen echte Zielsysteme in Docker und werden übersprungen, wenn ein System nicht erreichbar ist. Erwartete Container und Ports:

| System | Container | Host-Port |
|---|---|---|
| PostgreSQL | `postgres:17-alpine` | 15432 |
| MySQL | `mysql:8.4` | 13306 |
| ClickHouse | `clickhouse/clickhouse-server:25.8` | 18123 |
| ArcadeDB | `arcadedata/arcadedb:26.12.1-SNAPSHOT` (per Digest gepinnt) | 12480 |
| Redis | `redis:8-alpine` | 16379 |
| OpenBao | `openbao/openbao:2.7.3` (per Digest gepinnt, dev mode) | 18200 |

`scripts/test-containers.sh up` startet alle sechs Container mit den Test-Zugangsdaten, die die Tests erwarten; `scripts/test-containers.sh down` entfernt sie wieder. Mit `ORDIVUS_TEST_HOST` legen Sie fest, unter welchem Hostnamen die Container erreichbar sind (Standard `localhost`). Die Ports sind nur auf `127.0.0.1` veröffentlicht, nicht auf allen Schnittstellen; `scripts/dev.sh` startet seinen Container deshalb mit `--network host` und `ORDIVUS_TEST_HOST=127.0.0.1` (die Bridge-Gateway-Adresse lässt sich unter Docker Desktop nicht als Bind-Adresse verwenden, `host.docker.internal` ist langsam).

Kubernetes-E2E gegen einen lokalen Cluster (z. B. Docker Desktop):

```sh
docker build -t ordivus:dev .
ORDIVUS_E2E=1 tests/e2e/run.sh
```

## Abhängigkeiten und Lock-Datei

In `pyproject.toml` haben alle Abhängigkeiten eine Obergrenze unterhalb der nächsten Major-Version. Das Produktions-Image installiert ausschließlich aus `requirements.lock` (`pip install --require-hashes`, nur Wheels) und danach das Ordivus-Paket selbst mit `--no-deps`; auch das Build-Backend (setuptools) steht mit Hash im Lock. Nach jeder Änderung der Abhängigkeiten den Lock neu erzeugen und mitcommitten:

```sh
scripts/dev.sh sh -c 'pip install -q pip-tools && pip-compile -q --strip-extras --generate-hashes --all-build-deps \
  --allow-unsafe --extra postgresql --extra mysql --extra redis --no-emit-index-url -o requirements.lock pyproject.toml'
```

Das Basis-Image ist im `Dockerfile` per Digest gepinnt (`ARG PYTHON_IMAGE`). Aktualisieren: `docker buildx imagetools inspect python:3.14-slim` und den Digest eintragen. Prüfen: `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.67.2 image --ignore-unfixed --severity HIGH,CRITICAL ordivus:dev`.

## Einen Adapter schreiben

1. `src/ordivus/adapters/base.py` lesen – der Vertrag ist dort vollständig dokumentiert.
2. Eine Klasse von `Adapter` ableiten, `id` und `kinds` setzen, die Methoden implementieren.
3. In `pyproject.toml` unter `[project.entry-points."ordivus.adapters"]` registrieren. Externe Pakete können sich in derselben Gruppe registrieren, ohne Ordivus zu ändern.
4. Integrationstests gegen ein echtes System, ein Beispiel unter `examples/<adapter>/` und eine Seite unter `docs/adapters/` ergänzen.

Pflicht für jeden Adapter: Read-only-Sessions mutieren nichts, unvollständige Discovery wird als `partial`/`forbidden` gemeldet, Identifier werden sicher gequotet, Secrets erscheinen in keiner Fehlermeldung.

## Pull Requests

- Tests und `ruff check` müssen grün sein.
- Verhaltensänderungen an Sicherheitsgrenzen (Löschen, Passwörter, Read-only, Policy) brauchen einen Test, der das neue Verhalten belegt.
- Sicherheitslücken bitte nicht als öffentliches Issue melden, sondern über einen privaten Security Advisory auf GitHub.
