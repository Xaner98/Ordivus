# ArcadeDB-Adapter (`arcadedb`, Beta)

Verwaltet Datenbanken und Server-Benutzer einer ArcadeDB-Instanz über die HTTP-API
(`/api/v1`). Keine zusätzliche Abhängigkeit: Der Adapter nutzt nur die Python-Standardbibliothek.

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: analytics-arcadedb
spec:
  adapter: arcadedb
  endpoint:
    host: arcadedb.data-platform.svc.cluster.local
    port: 2480            # Default 2480
    tls:                  # vorhanden → https; ohne tls → http
      caFile: /trust/ca.pem   # optional, sonst System-CAs
  username: root          # Default root
  authentication:
    credentialRef: arcadedb-root   # Passwort des Admin-Benutzers
  scope:                  # optional; Objekte außerhalb werden nicht gelesen/gemeldet
    databases:
      include: ["analytics_*"]
    users:
      include: ["graph_*"]
```

Die Verbindung wird beim Start mit `GET /api/v1/server?mode=basic` geprüft (401/403 → Target-Fehler,
Exit-Code 13). Authentifizierung per HTTP Basic Auth; das Passwort erscheint nie in URLs, Logs
oder Fehlermeldungen.

## Kinds

Reihenfolge beim Anlegen: `Database`, dann `DatabaseUser`; Löschungen umgekehrt.

### `Database`

Keine Felder. Der Name ist `metadata.name` und muss `[A-Za-z0-9_][A-Za-z0-9_-]*` (max. 128 Zeichen)
entsprechen, weil ArcadeDBs Server-Kommandos (`create database <name>`) Freitext ohne Quoting sind.
Andere Namen werden bei der Validierung abgelehnt; vorhandene Datenbanken mit anderen Namen
werden zwar gemeldet, aber als nicht verwaltbar markiert (nie gelöscht).

```yaml
kind: Database
metadata:
  name: knowledge_graph
spec:
  targetRef: analytics-arcadedb
```

### `DatabaseUser`

| Feld | Typ | Bedeutung |
|---|---|---|
| `databases` | Mapping Datenbank → Liste von Gruppen | ArcadeDBs Zuordnung pro Datenbank (`*` = alle Datenbanken). Gruppen z. B. `admin`, `crud`, `readonly` oder eigene Gruppen aus `server-groups.json`. |
| `credentials` | Engine-Feld | **Pflicht beim Anlegen**: ArcadeDB legt keine Benutzer ohne Passwort (min. 8 Zeichen) an. |

```yaml
kind: DatabaseUser
metadata:
  name: graph_writer
spec:
  targetRef: analytics-arcadedb
  databases:
    knowledge_graph: [crud]
  credentials:
    credentialRef: graph-writer-password
    passwordPolicy: verify
```

Vergleichssemantik:

- `databases` fehlt → Zuordnung wird nicht verwaltet (weder gelesen noch zurückgesetzt).
- `databases: {}` → Benutzer soll keiner Datenbank zugeordnet sein.
- Gruppenlisten werden sortiert und dedupliziert; Reihenfolge ist bedeutungslos.
- `databases` wird als Ganzes verglichen und bei Abweichung per `PUT /api/v1/server/users`
  vollständig ersetzt (ArcadeDB kennt kein teilweises Ändern der Zuordnung).
- Benutzernamen dürfen beliebige druckbare Zeichen enthalten (auch Anführungszeichen, Klammern,
  Leerzeichen), nicht aber mit `apitoken:` beginnen. Namen werden nur als JSON-Wert bzw.
  URL-kodierter Query-Parameter übertragen.

Passwörter:

- Anlegen: `POST /api/v1/server/users` mit Passwort aus dem Credential.
- `SET_PASSWORD`: `PUT /api/v1/server/users?name=…` setzt das Passwort in-place.
- `verify`: Login-Versuch als der Benutzer gegen `GET /api/v1/server?mode=basic`:
  200 → gleich, 401 → abweichend, alles andere (z. B. 403, Timeout) → `unknown`.
  Benutzernamen mit `:` sind per Basic Auth nicht prüfbar → immer `unknown`.

## Discovery

| Kind | Quelle | Status |
|---|---|---|
| `Database` | `GET /api/v1/databases` | `complete` nur bei `username: root`; andere Benutzer sehen nur ihre Datenbanken → `partial` |
| `DatabaseUser` | `GET /api/v1/server/users` (Namen + Datenbank/Gruppen, nie Passwort-Hashes) | `complete`; ohne root-Rechte 403 → `forbidden` |

Bei `partial`/`forbidden` gibt es weder `CREATE` noch `DELETE` für das jeweilige Kind.

## Benötigte Rechte

ArcadeDB erlaubt Server-Kommandos und Benutzerverwaltung **nur dem Benutzer `root`**. Für `apply`
ist deshalb `username: root` nötig. Mit einem anderen Benutzer ist nur ein eingeschränkter
`plan`/`drift` möglich (Datenbanken `partial`, Benutzer `forbidden`).

## Geschützte Objekte

- Benutzer `root` und der Benutzer, mit dem Ordivus sich verbindet, sind Systemobjekte:
  nicht deklariert → `IGNORE`; nie gelöscht, nie geändert.
- `DELETE` nur in `authoritative`-Modus mit Operator-Freigabe (`allowAuthoritative`, `allowDelete`)
  und vollständiger Discovery.

## Read-only-Garantie

`plan`/`drift` öffnen Read-only-Sessions. Der Adapter verweigert darin jede HTTP-Methode außer `GET`
sowie jeden `apply`-Aufruf (`PermanentError`), bevor ein Request das Netz erreicht.

## Fehlerabbildung

| Ursache | Fehler |
|---|---|
| Timeout, Verbindungsfehler, HTTP 5xx/429 | `TransientError` |
| HTTP 401/403 | `AuthorizationError` |
| übrige 4xx, ungültiges JSON, unlesbares `caFile` | `PermanentError` |

Idempotenz: `create database` bei existierender bzw. `drop database` bei fehlender Datenbank gilt
nach erneutem Lesen als Erfolg; Löschen eines nicht (mehr) vorhandenen Benutzers (404) ebenso.

## Einschränkungen

- Benutzer sind **serverweit**, nicht pro Datenbank; `scope.users` filtert nur nach Namen.
- Gruppen (`server-groups.json`) und API-Tokens werden nicht verwaltet; nicht vorhandene Gruppen-
  oder Datenbanknamen in `databases` werden von ArcadeDB ohne Fehler übernommen.
- Benötigt eine ArcadeDB-Version mit `/api/v1/server/users` (getestet mit 26.12); ältere Versionen
  liefern dort 404 → Discovery-Fehler (`unknown`), keine Änderungen.
- Keine Sperre (`lock`): parallele Läufe gegen dieselbe Instanz sind nicht gegeneinander abgesichert.
- HA-Cluster: Änderungen repliziert ArcadeDB selbst; nicht separat getestet.
