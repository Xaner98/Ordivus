# Schnellstart

In diesem Schnellstart starten Sie PostgreSQL in Docker und lassen Ordivus darin einen Anwendungsbenutzer mit automatisch erzeugtem Passwort anlegen. Danach sehen Sie, wie Ordivus Abweichungen und fremde Objekte erkennt.

Sie brauchen Docker und entweder Python 3.13+ oder das Ordivus-Container-Image (siehe [README](../README.md#installation)).

## 1. PostgreSQL starten

```sh
docker network create ordivus-demo
docker run -d --name demo-postgres --network ordivus-demo -p 5432:5432 \
  -e POSTGRES_PASSWORD=admin-demo-pw postgres:17-alpine
```

## 2. Arbeitsverzeichnis anlegen

```sh
mkdir -p ordivus-demo/config ordivus-demo/secrets && cd ordivus-demo
printf 'admin-demo-pw' > secrets/admin
chmod 700 secrets && chmod 600 secrets/admin
```

`secrets/` spielt hier die Rolle Ihres Secret Stores. Im Cluster wäre das ein gemountetes Kubernetes Secret, in Produktion bevorzugt OpenBao.

## 3. Konfiguration schreiben

`config/ordivus.yaml`:

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: demo-postgres
spec:
  adapter: postgresql
  endpoint:
    host: localhost          # im Container-Image: demo-postgres
    port: 5432
    user: postgres
  authentication:
    credentialRef: admin
---
apiVersion: ordivus.dev/v1alpha1
kind: CredentialProvider
metadata:
  name: secrets
spec:
  type: file
  directory: ./secrets       # im Container-Image: /work/secrets
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata:
  name: admin
spec:
  providerRef: secrets
  path: admin
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata:
  name: app-password
spec:
  providerRef: secrets
  path: app
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseRole
metadata:
  name: app_readonly
spec:
  targetRef: demo-postgres
---
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata:
  name: app
spec:
  targetRef: demo-postgres
  memberOf: [app_readonly]
  connectionLimit: 10
  credentials:
    credentialRef: app-password
```

Prüfen, ohne eine Verbindung aufzubauen:

```sh
ordivus config validate -f config
```

## 4. Planen und anwenden

```sh
ordivus plan -f config
```

Der Plan zeigt drei Aktionen: das Passwort-Secret `app` anlegen, die Rolle `app_readonly` und den Benutzer `app`. Es wurde noch nichts verändert – auch `secrets/app` existiert noch nicht.

Ordivus warnt außerdem, dass die Verbindung nicht per TLS abgesichert ist. Für diese lokale Demo ist das in Ordnung; in Produktion konfigurieren Sie `endpoint.tls` (siehe [PostgreSQL-Adapter](adapters/postgresql.md)).

```sh
ordivus apply -f config
ls secrets/            # admin  app
ordivus apply -f config   # zweiter Lauf: nichts mehr zu tun
```

Der neue Benutzer kann sich mit dem erzeugten Passwort anmelden:

```sh
docker exec -e PGPASSWORD="$(cat secrets/app)" demo-postgres \
  psql -h 127.0.0.1 -U app -d postgres -c 'select current_user'
```

## 5. Drift erkennen

Ändern Sie etwas von Hand und legen Sie einen fremden Benutzer an:

```sh
docker exec demo-postgres psql -U postgres -c "ALTER ROLE app CONNECTION LIMIT 99"
docker exec demo-postgres psql -U postgres -c "CREATE ROLE handmade LOGIN"
ordivus drift -f config
```

`drift` meldet das geänderte Verbindungslimit als behebbare Abweichung und `handmade` als `UNMANAGED`. Ein `apply` setzt das Limit zurück auf 10, lässt `handmade` aber in Ruhe – nicht deklarierte Objekte löscht Ordivus nur in einem ausdrücklich freigegebenen `authoritative`-Scope.

Für CI-Pipelines gibt es Schwellen: `ordivus drift -f config --fail-on actionable` endet mit Exit-Code 10, sobald behebbare Abweichungen vorliegen.

## Mit dem Container-Image

Statt `ordivus` lokal zu installieren, können Sie jeden Befehl im Image ausführen. Setzen Sie dafür in der Konfiguration `host: demo-postgres` und `directory: /work/secrets`:

```sh
docker run --rm --network ordivus-demo -v "$PWD":/work -w /work ordivus plan -f config
```

Das Image läuft als Benutzer mit UID 10001; damit `apply` die Secret-Datei anlegen kann, muss `secrets/` für diese UID beschreibbar sein (z. B. `docker run --user "$(id -u)" …`).

## Aufräumen

```sh
docker rm -f demo-postgres && docker network rm ordivus-demo
```

## Wie geht es weiter?

- [Konzepte](konzepte.md) – was additive und authoritative bedeuten, wie Passwörter geprüft werden
- [Konfiguration](konfiguration.md) – alle gemeinsamen Felder, Operator Policy, Exit-Codes
- [Kubernetes und CI/CD](kubernetes.md)
