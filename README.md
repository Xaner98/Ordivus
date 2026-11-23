# Ordivus

A lightweight, stateless, Kubernetes-native configuration engine for heterogeneous infrastructure. One engine. Every platform.

**Ordivus** verwaltet Benutzer, Rollen, Berechtigungen, Datenbanken und Policies in den Systemen, die Sie bereits betreiben – deklarativ, zustandslos und mit denselben drei Befehlen für jedes System:

```sh
ordivus plan  -f ./config    # Was würde sich ändern?
ordivus drift -f ./config    # Weicht die Realität ab? Gibt es fremde Objekte?
ordivus apply -f ./config    # Erlaubte Änderungen ausführen und prüfen
```

Sie beschreiben den gewünschten Zustand in YAML. Ordivus liest bei jedem Lauf den Istzustand direkt aus dem Zielsystem, zeigt jeden Unterschied und ändert nur, was erlaubt ist. Es gibt keine State-Datei, keine eigene Datenbank und keinen dauerhaft laufenden Controller.

> **Status:** Alpha (`0.1.0`). Schnittstellen und Konfigurationsformat können sich bis `1.0` ändern.

## Warum Ordivus?

- **Ein Workflow für viele Systeme.** PostgreSQL, MySQL, ClickHouse, ArcadeDB, Redis und OpenBao mit derselben Konfigurationsform, denselben Befehlen, denselben Exit-Codes und demselben Report-Format.
- **Zustandslos.** Die Wahrheit liegt in Ihrer Konfiguration und im Zielsystem. Ordivus sieht deshalb auch Objekte, die jemand von Hand angelegt hat.
- **Sicher als Standard.** Nicht deklarierte Objekte werden nur gemeldet, nie stillschweigend gelöscht. Löschen braucht einen ausdrücklich abgegrenzten Scope *und* eine getrennt verwaltete Operator Policy. Was nicht vollständig lesbar ist, gilt als unbekannt – nicht als leer.
- **Secrets bleiben geheim.** Passwörter stehen nie in der Konfiguration und nie in Reports oder Logs. Fehlende Passwörter erzeugt Ordivus kryptografisch sicher und legt sie *create-if-absent* in Ihrem Secret Store ab (Datei/Kubernetes Secret oder OpenBao).
- **Passt in Ihre Automatisierung.** GitLab CI, Jenkins, Argo CD, Flux, Kubernetes CronJobs oder einfach Ihr Terminal. Ordivus ist ein CLI-Prozess, der startet, arbeitet und endet.
- **Läuft überall.** Lokal, in CI, auf einer VM oder als Kubernetes Job; Zielsysteme innerhalb oder außerhalb eines Clusters.

## Unterstützte Systeme

| Adapter | Verwaltete Ressourcen | Doku |
|---|---|---|
| PostgreSQL | Datenbanken, Rollen, Benutzer, Mitgliedschaften, Grants (Datenbank, Schema, Tabellen eines Schemas) | [docs/adapters/postgresql.md](docs/adapters/postgresql.md) |
| MySQL | Datenbanken, Rollen, Accounts (`user@host`), Rollenzuweisungen, Grants | [docs/adapters/mysql.md](docs/adapters/mysql.md) |
| ClickHouse | Datenbanken, Rollen, Benutzer, Grants | [docs/adapters/clickhouse.md](docs/adapters/clickhouse.md) |
| ArcadeDB | Datenbanken, Benutzer mit Gruppen je Datenbank | [docs/adapters/arcadedb.md](docs/adapters/arcadedb.md) |
| Redis | ACL-Benutzer (Keys, Channels, Commands) | [docs/adapters/redis.md](docs/adapters/redis.md) |
| OpenBao | ACL-Policies | [docs/adapters/openbao.md](docs/adapters/openbao.md) |

Secret-Quellen: Dateien bzw. gemountete Kubernetes Secrets, [OpenBao KV v2](docs/credentials/openbao.md) und – nur zur Entwicklung – Umgebungsvariablen.

## Installation

Voraussetzung: Python 3.13 oder neuer.

```sh
pip install "ordivus[postgresql,mysql,redis] @ git+https://github.com/Xaner98/Ordivus.git"
ordivus --version
```

Die Extras installieren die Datenbanktreiber. ClickHouse, ArcadeDB und OpenBao benötigen keine zusätzlichen Pakete. Installieren Sie nur, was Sie brauchen, z. B. `ordivus[postgresql]`.

Als Container-Image (enthält alle Adapter, läuft als Nicht-Root-Benutzer mit schreibgeschütztem Dateisystem):

```sh
git clone https://github.com/Xaner98/Ordivus.git && cd Ordivus
docker build -t ordivus .
docker run --rm ordivus --version
```

Für Kubernetes gibt es ein Helm Chart mit vorbereiteten Job-Vorlagen für `plan`, `drift` und `apply`: [docs/kubernetes.md](docs/kubernetes.md).

## Schnellstart

Der [Schnellstart](docs/schnellstart.md) richtet in fünf Minuten eine PostgreSQL-Instanz in Docker ein und verwaltet darin einen Benutzer mit automatisch erzeugtem Passwort. Die Kurzfassung:

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
ordivus plan  -f config    # zeigt: CREATE_SECRET app, CREATE DatabaseUser app
ordivus apply -f config    # erzeugt ./secrets/app und legt den Benutzer an
ordivus apply -f config    # nichts mehr zu tun
```

## Dokumentation

- [Konzepte](docs/konzepte.md) – zustandslos, additive/authoritative, unbekannt bleibt unbekannt, Passwörter
- [Konfiguration](docs/konfiguration.md) – Aufbau der Dateien, Engine-Kinds, Operator Policy, Exit-Codes, Report-Format
- [Schnellstart](docs/schnellstart.md)
- [Kubernetes und CI/CD](docs/kubernetes.md) – Helm Chart, Job-Vorlagen, GitLab, Jenkins, Argo CD, Flux
- Adapter: [PostgreSQL](docs/adapters/postgresql.md) · [MySQL](docs/adapters/mysql.md) · [ClickHouse](docs/adapters/clickhouse.md) · [ArcadeDB](docs/adapters/arcadedb.md) · [Redis](docs/adapters/redis.md) · [OpenBao](docs/adapters/openbao.md)
- Secret-Quellen: [OpenBao KV v2](docs/credentials/openbao.md)
- [Entwicklung und Beiträge](docs/entwicklung.md)
- Beispiele: [`examples/`](examples/)

## Was Ordivus nicht ist

Kein Ersatz für Terraform, Helm, Ansible, Argo CD oder Flux; kein Secret Manager; kein Werkzeug für Schema-Migrationen oder Datenmigration; keine verteilte Transaktion über mehrere Systeme. Ordivus kümmert sich um den administrativen Sollzustand *innerhalb* Ihrer Systeme und arbeitet mit den Werkzeugen zusammen, die Sie schon haben.

## Lizenz

[Apache License 2.0](LICENSE)
