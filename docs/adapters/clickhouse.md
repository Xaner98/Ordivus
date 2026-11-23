# ClickHouse-Adapter

Adapter-ID `clickhouse`. Verwaltet Datenbanken, Rollen, Benutzer und Grants über **SQL-basiertes Access Management** (`CREATE USER`, `GRANT` …) und das HTTP-Interface von ClickHouse. Keine zusätzliche Python-Abhängigkeit.

Kinds in Ausführungsreihenfolge: `Database`, `DatabaseRole`, `DatabaseUser`, `Grant` (Löschungen in umgekehrter Reihenfolge).

Ein vollständiges Beispiel liegt in [`examples/clickhouse/`](../../examples/clickhouse/ordivus.yaml).

## Target

```yaml
kind: Target
metadata:
  name: analytics-clickhouse
spec:
  adapter: clickhouse
  endpoint:
    host: clickhouse.data-platform.svc.cluster.local
    port: 8443            # Default 8123 (http) bzw. 8443 (mit tls)
    user: ordivus         # Default "default"; darf kein ':' enthalten
    timeoutSeconds: 30    # Default 30
    tls:                  # vorhanden ⇒ https mit Zertifikatsprüfung
      caFile: /trust/ca.pem   # optional, sonst System-CAs
  authentication:
    credentialRef: clickhouse-admin   # Passwort des Benutzers endpoint.user
  scope:
    databases:
      include: ["reporting*"]         # Glob; optional
```

- Anmeldung per HTTP Basic Auth im Header; SQL steht ausschließlich im POST-Body, nie in der URL.
- Fehler werden über den Header `X-ClickHouse-Exception-Code` eingeordnet: Rechte-/Anmeldefehler (497, 516, 192) → `AuthorizationError` (Kind `forbidden`), Timeouts/Netz/Überlast → `TransientError`, alles andere → `PermanentError`.
- `plan` und `drift` senden bei **jeder** Anfrage die Einstellung `readonly=2`; ClickHouse lehnt dann jedes DDL/DCL ab (Code 164 `READONLY`). Zusätzlich verweigert der Adapter `apply` auf einer Read-only-Session.

## Kind `Database`

```yaml
kind: Database
metadata:
  name: reporting          # Datenbankname
spec:
  targetRef: analytics-clickhouse
  engine: Atomic           # optional, nur beim Anlegen
```

`engine` ist ein reiner Engine-Name ohne Parameter (`Atomic`, `Memory`, `Lazy` …). Eine abweichende Engine an einer bestehenden Datenbank erscheint im Plan als `UPDATE` und scheitert im `apply` mit „engine is create-only“; Ordivus baut Datenbanken nie um. **`DELETE` einer Datenbank ist `DROP DATABASE` und löscht alle Tabellen darin.**

## Kind `DatabaseRole`

```yaml
kind: DatabaseRole
metadata:
  name: reporting_reader
spec:
  targetRef: analytics-clickhouse
```

Keine weiteren Felder. Rollen, die an andere Rollen vergeben sind, werden nicht modelliert.

## Kind `DatabaseUser`

```yaml
kind: DatabaseUser
metadata:
  name: reporting_app
spec:
  targetRef: analytics-clickhouse
  roles: [reporting_reader]          # vergebene Rollen (GRANT role TO user)
  defaultRoles: [reporting_reader]   # beim Login aktive Rollen; [] = NONE
  hostIp: ["10.0.0.0/8"]             # HOST IP …
  hostNames: ["app.example"]         # HOST NAME …
  credentials:
    credentialRef: reporting-app-password
    passwordPolicy: verify
```

Alle Felder sind optional; nicht angegebene Felder werden nicht verwaltet (nie zurückgesetzt).

- `roles`: Änderungen werden als `GRANT`/`REVOKE` der Differenz ausgeführt.
- `defaultRoles`: verglichen wird die effektive Menge aus `system.role_grants.granted_role_is_default`. Ohne Angabe gilt ClickHouse-Standard `DEFAULT ROLE ALL`.
- `hostIp`/`hostNames`: Listen, sortiert verglichen. `::/0` bedeutet „von überall“ (ClickHouse speichert `ANY` so; eine Liste mit `::/0` wird zu `["::/0"]` normalisiert). Ändert sich eines der Felder, wird die gesamte Host-Liste neu gesetzt; nicht deklarierte Einträge (auch `REGEXP`/`LIKE`) bleiben dabei erhalten. Adressen werden schon bei der Validierung geprüft. Ohne Angabe wird ein neuer Benutzer mit `HOST ANY` angelegt.
- Ein neuer Benutzer wird zuerst mit `HOST NONE` angelegt und erst danach freigeschaltet, damit er nie kurz von überall erreichbar ist.

### Passwörter

- Passwörter werden als `IDENTIFIED WITH sha256_password BY '…'` gesetzt. Das Statement enthält außer Name und Passwort keine variablen Teile: ClickHouse maskiert Passwörter in `system.query_log` und im Server-Log, **außer** ein Statement scheitert schon beim Parsen – dann stünde es im Klartext im Log.
- `passwordPolicy: verify` prüft per Anmeldeversuch (`SELECT 1` als dieser Benutzer, ebenfalls mit `readonly=2`): Fehler 516 `AUTHENTICATION_FAILED` ⇒ falsches Passwort (`SET_PASSWORD`), Erfolg ⇒ passt, alles andere ⇒ `UNKNOWN`.
  **Achtung:** Ist der Benutzer per `hostIp`/`hostNames` auf Adressen beschränkt, von denen Ordivus nicht kommt, meldet ClickHouse ebenfalls 516. Dann würde bei jedem Lauf `SET_PASSWORD` geplant. In diesem Fall `passwordPolicy: set-on-create` oder `enforce` verwenden.
- Ein Benutzer **ohne** `spec.credentials` wird mit einem zufälligen, nirgends gespeicherten Passwort angelegt (nicht mit `no_password`); anmelden kann er sich erst, wenn jemand ein Passwort setzt.
- Benutzernamen mit `:` lassen sich per Basic Auth nicht prüfen (`UNKNOWN`).

## Kind `Grant`

```yaml
kind: Grant
metadata:
  name: reporting-reader-select   # frei wählbar, nicht Teil des Schlüssels
spec:
  targetRef: analytics-clickhouse
  grantee: reporting_reader       # Benutzer oder Rolle
  database: reporting             # optional; ohne Angabe *.*
  table: events                   # optional, nur mit database
  privileges: [SELECT, SHOW TABLES]
```

Ein Grant-Objekt ist die Menge der Privilegien eines Grantees auf genau einem Objekt. Die ID im Report lautet z. B. `` `reporting_reader` ON `reporting`.* ``. Weichen die Privilegien ab, werden nur die Differenzen per `GRANT`/`REVOKE` geändert.

**Normalisierung und Fallstricke:** ClickHouse speichert Privilegien in einer eigenen Form (`system.grants`) – Gruppen werden aufgefächert, vollständige Gruppen wieder zusammengefasst. Ordivus vergleicht Großschreibung mit einfachen Leerzeichen, sortiert und ohne Duplikate. Damit der Vergleich stabil ist:

- Privilegien so angeben, wie `SHOW GRANTS` sie zeigt. Wer z. B. alle vier `SHOW …`-Unterrechte einzeln deklariert, erhält dauerhaft ein `UPDATE`, weil ClickHouse sie zu `SHOW` zusammenfasst.
- `ALL`/`ALL PRIVILEGES` werden abgelehnt (expandiert serverseitig je nach Version).
- Spalten-Grants (`SELECT(col)`), Teil-Revokes und `WITH GRANT OPTION` modelliert der Adapter nicht. Solche Einträge erscheinen als eigene, nicht änderbare Objekte (`manageable: false`) mit Zusatz in der ID, z. B. `(with grant option)`, und werden nie gelöscht.
- Privilegien von Rollen, die ein Benutzer erbt, gehören zur Rolle, nicht zum Benutzer.

## Discovery und Scope

| Kind | Quelle |
|---|---|
| `Database` | `system.databases` |
| `DatabaseRole` | `system.roles` (`storage`) |
| `DatabaseUser` | `system.users` (`storage`, `host_*`), `system.role_grants` |
| `Grant` | `system.grants` |

`spec.scope.databases.include` (Globs) beschränkt `Database` und datenbankbezogene Grants; globale Grants (`*.*`) gehören immer dazu. Benutzer und Rollen sind nicht datenbankgebunden und werden über `ReconciliationPolicy.spec.scope.DatabaseUser`/`DatabaseRole` (exact/glob) eingegrenzt. Fehlen die Rechte für eine Systemtabelle, ist das Kind `forbidden`, nie „leer“.

## Geschützte Systemobjekte

- Datenbanken `system`, `information_schema`, `INFORMATION_SCHEMA`, `default` sind Systemobjekte (`IGNORE`, nie gelöscht).
- Der Benutzer, als der Ordivus verbunden ist (`currentUser()`), und seine Grants sind Systemobjekte – Schutz vor Selbstaussperrung.
- Benutzer und Rollen aus Konfigurationsdateien sind nicht änderbar (siehe unten).

## users.xml-Verwaltung wird nicht empfohlen

Benutzer, Rollen und Rechte aus den Server-Konfigurationsdateien (`users.xml`, `users.d/`) lassen sich per SQL nicht ändern. Ordivus empfiehlt diese Art der Verwaltung **ausdrücklich nicht**; verwenden Sie SQL-basiertes Access Management (`access_management`, Storage `local_directory` oder `replicated`).

Der Adapter erkennt die Herkunft über die Spalte `storage` in `system.users`/`system.roles`. Nur `local_directory` und `replicated` gelten als änderbar; alles andere (`users_xml` …) bekommt `manageable: false`:

| Situation | Ergebnis |
|---|---|
| nicht deklariert, additive | `UNMANAGED` |
| nicht deklariert, authoritative im Scope | `UNDESIRABLE` („not manageable by adapter“), **nie `DELETE`**, auch mit `allowDelete` |
| deklariert | `BLOCKED` („not manageable by adapter“), nie stilles `NOOP` |
| Grants solcher Benutzer/Rollen | ebenfalls `manageable: false` |

Die Engine meldet eine Deklaration solcher Objekte immer als `BLOCKED`, auch wenn alle Felder übereinstimmen.

Typischer Fall: der per `CLICKHOUSE_USER` im offiziellen Container angelegte Admin. Für Ordivus legt man besser einen eigenen SQL-Benutzer an (siehe Rechte) und verbindet sich als dieser.

## Benötigte Rechte

Der Verbindungsbenutzer braucht:

- Lesen: `SHOW USERS, SHOW ROLES` (bzw. `SHOW ACCESS`) und Zugriff auf `system.databases`, `system.users`, `system.roles`, `system.role_grants`, `system.grants`.
- Schreiben: `ACCESS MANAGEMENT` (bzw. `CREATE/ALTER/DROP USER`, `CREATE/DROP ROLE`, `ROLE ADMIN`), `CREATE DATABASE`, `DROP DATABASE` (nur für Löschungen) und jedes Privileg, das er vergeben soll, **`WITH GRANT OPTION`**.

Beispiel (als Admin mit `access_management`):

```sql
CREATE USER ordivus IDENTIFIED WITH sha256_password BY '…';
GRANT CURRENT GRANTS ON *.* TO ordivus WITH GRANT OPTION;
```

## Cluster

`ON CLUSTER` wird **noch nicht** unterstützt. Ein Target ist genau ein Knoten. Per SQL angelegte Benutzer existieren ohne `ON CLUSTER` nur auf diesem Knoten – außer der Cluster nutzt **replizierten Access Storage** (`user_directories/replicated` über Keeper); dann wirkt ein Target auf einen Knoten für alle. Ohne replizierten Storage muss jeder Knoten als eigenes Target konfiguriert werden; abweichende Knoten meldet Ordivus derzeit nicht als Cluster-Drift. Datenbanken werden ebenfalls nur auf dem verbundenen Knoten angelegt (oder über `Replicated`-Datenbank-Engine).

## Grenzen

- Keine Sperre während `apply` (ClickHouse hat keine Advisory Locks); parallele `apply`-Läufe gegen dasselbe Target vermeiden.
- Nicht modelliert: Settings-Profile, Quotas, Row Policies, Rolle-an-Rolle-Grants, `GRANT OPTION`, Spalten-Grants, Authentifizierung außer `sha256_password` (LDAP, Kerberos, Zertifikate).
- `Database.engine` ohne Parameter; Engine-Wechsel wird nie ausgeführt.
