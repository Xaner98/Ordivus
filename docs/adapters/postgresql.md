# PostgreSQL-Adapter

Verwaltet Rollen, Benutzer, Datenbanken und eine robuste Teilmenge von Grants in PostgreSQL
(getestet mit PostgreSQL 17). Installation: `pip install 'ordivus[postgresql]'` (psycopg ≥ 3.2).

Kinds in Ausführungsreihenfolge: `DatabaseRole`, `DatabaseUser`, `Database`, `Grant`. Löschungen
laufen umgekehrt (Grants, dann Datenbanken, dann Benutzer und Rollen). Rollen kommen vor Datenbanken,
weil `CREATE DATABASE … OWNER` die Rolle bereits braucht. Innerhalb davon folgt die Reihenfolge
`memberOf`: eine Elternrolle (auch ein `DatabaseUser`) entsteht vor ihren Mitgliedern, gelöscht wird
umgekehrt. Zyklische Mitgliedschaften werden `BLOCKED`.

Vollständiges Beispiel: [`examples/postgresql/`](../../examples/postgresql/ordivus.yaml).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: analytics-postgres
spec:
  adapter: postgresql
  endpoint:
    host: postgres.data-platform.svc.cluster.local
    port: 5432               # Default 5432
    database: postgres       # Verbindungsdatenbank, Default "postgres"
    user: ordivus_admin      # Pflicht: Rolle, als die Ordivus sich anmeldet
    tls:
      mode: verify-full      # disable | allow | prefer (libpq-Default) | require | verify-ca | verify-full
      caFile: /trust/ca.pem  # → sslrootcert
  authentication:
    credentialRef: postgres-admin   # Passwort von endpoint.user
  scope:
    databases:
      include: ["analytics", "reporting_*"]   # Globs; ohne Angabe: alle Datenbanken
    roles:
      include: ["analytics_*"]                # gilt für DatabaseRole, DatabaseUser und Grant-Empfänger
```

Für Produktion `tls.mode: verify-full` mit einer `caFile` aus der Laufzeitumgebung verwenden: Ein
umgeleiteter Host scheitert dann am Zertifikat, bevor das Passwort gesendet wird. Jeder andere Modus
als `verify-ca`/`verify-full` (auch der Default `prefer`) gilt als unsichere Verbindung: Warnung und
`insecureTransport: true` im Report, mit Operator Policy `requireTls: true` Abbruch (Exit-Code 11).

## Kind `DatabaseRole` und `DatabaseUser`

In PostgreSQL sind Benutzer und Rollen dasselbe Objekt. `DatabaseUser` ist eine Rolle **mit**
`LOGIN`, `DatabaseRole` eine Rolle **ohne** `LOGIN`. Die Discovery ordnet jede Rolle anhand von
`rolcanlogin` genau einem Kind zu. Denselben Namen in beiden Kinds zu deklarieren ist ein Fehler
(siehe [Grenzen](#grenzen)).

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata:
  name: analytics-app
spec:
  targetRef: analytics-postgres
  name: analytics_app            # optional, Default metadata.name
  memberOf: [analytics_readonly] # Mitgliedschaften (genau diese Menge)
  connectionLimit: 20            # -1 = unbegrenzt
  createdb: false
  createrole: false
  credentials:                   # nur DatabaseUser
    credentialRef: analytics-app-password
    passwordPolicy: verify       # verify (Default) | enforce | set-on-create
```

| Feld | Bedeutung |
|---|---|
| `name` | Rollenname, max. 63 Byte, beliebige Zeichen. Default `metadata.name` |
| `memberOf` | Liste von Rollen; Ordivus vergibt und entzieht Mitgliedschaften, bis genau diese Menge besteht |
| `connectionLimit` | `CONNECTION LIMIT`, Ganzzahl ≥ -1 |
| `createdb`, `createrole` | `CREATEDB`/`NOCREATEDB`, `CREATEROLE`/`NOCREATEROLE` |
| `superuser` | **nicht verwaltbar** – die Angabe ist ein Validierungsfehler |

Nicht angegebene Felder werden nicht verwaltet, also auch nicht zurückgesetzt.

`spec.name` ist nötig, wenn mehrere Targets gleichnamige Rollen haben, denn `metadata.name` muss je
Kind über die ganze Konfiguration eindeutig sein.

### Passwörter

Passwörter werden **clientseitig** in einen SCRAM-SHA-256-Verifier umgerechnet
(`PQencryptPasswordConn`); der Klartext erreicht weder den Server noch dessen Statement-Log.
`passwordPolicy: verify` prüft per Anmeldeversuch als der Benutzer gegen `endpoint.host` und
`endpoint.database`:

- Anmeldung gelingt → Passwort stimmt.
- Server meldet `password authentication failed` (SQLSTATE 28P01) → `SET_PASSWORD`.
- Alles andere (kein `pg_hba.conf`-Eintrag, kein `CONNECT`-Recht, Netzwerk) → `unknown`, es wird nichts geändert.

Weil libpq bei Verbindungsfehlern keinen SQLSTATE liefert, erkennt Ordivus 28P01 am Servertext. Ist
`lc_messages` des Servers nicht Englisch, ist das Ergebnis stets `unknown` (sicher, aber ohne
Passwort-Drift-Erkennung); dann `enforce` verwenden oder `lc_messages = 'C'` setzen. Jeder
Fehlversuch erscheint im Server-Log als fehlgeschlagene Anmeldung.

## Kind `Database`

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Database
metadata:
  name: analytics
spec:
  targetRef: analytics-postgres
  owner: analytics_app   # ALTER DATABASE … OWNER TO
  encoding: UTF8         # nur bei Anlage (TEMPLATE template0)
```

| Feld | Bedeutung |
|---|---|
| `name` | Datenbankname, Default `metadata.name` |
| `owner` | Eigentümerrolle; Änderungen werden per `ALTER DATABASE … OWNER TO` umgesetzt |
| `encoding` | Nur bei `CREATE`. Den Namen verwenden, den PostgreSQL meldet (z. B. `UTF8`, `LATIN1`); eine Abweichung an einer bestehenden Datenbank ist ein Fehler, keine Neuanlage |

`DELETE` einer Datenbank ist ein schlichtes `DROP DATABASE` ohne `FORCE`: Bestehende Verbindungen
lassen die Operation fehlschlagen.

## Kind `Grant`

Ein Grant ist das Tripel *Empfänger × Objekt × Privilegien*. Der natürliche Schlüssel ist
`[grantee, database, on, schema]` (als JSON, z. B. `["analytics_readonly","analytics","schema","public"]`);
`metadata.name` ist frei wählbar.

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Grant
metadata:
  name: analytics-readonly-tables
spec:
  targetRef: analytics-postgres
  grantee: analytics_readonly
  database: analytics
  on: tables-in-schema       # database | schema | tables-in-schema
  schema: public             # Pflicht außer bei on: database
  privileges: [SELECT]
```

| `on` | Objekt | erlaubte `privileges` |
|---|---|---|
| `database` | die Datenbank `database` | `CONNECT`, `CREATE`, `TEMPORARY` (`TEMP`) |
| `schema` | Schema `schema` in `database` | `CREATE`, `USAGE` |
| `tables-in-schema` | alle Tabellen, Views, Materialized Views, Foreign Tables in `schema` | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, `MAINTAIN` (ab PG 17) |

Semantik:

- `privileges` ist **genau** die Menge, die der Empfänger auf dem Objekt hat: Ordivus vergibt
  fehlende und entzieht nicht deklarierte Privilegien dieses Objekts. Groß-/Kleinschreibung egal.
- `tables-in-schema`: Ein Privileg gilt als vorhanden, wenn der Empfänger es auf **jeder** Tabelle des
  Schemas hat (als Eigentümer einer Tabelle zählt er dort als berechtigt). Neue Tabellen nach dem Lauf
  sind beim nächsten Lauf Drift; `ALTER DEFAULT PRIVILEGES` wird nicht verwaltet.
- `DELETE` eines Grants entzieht `ALL PRIVILEGES` auf dem Objekt.
- Nicht unterstützt: `ALL`, `WITH GRANT OPTION`, Grants an `PUBLIC`, Spalten-, Sequenz-, Funktions-
  und Einzeltabellen-Grants, Default Privileges.

## Discovery und Scope

- Rollen und Datenbanken stammen aus `pg_roles` und `pg_database` (für jede Anmelderolle lesbar).
- Grants liegen je Datenbank. Ordivus öffnet für **jede** Datenbank im Scope (`datallowconn`, keine
  Templates) eine eigene Read-only-Verbindung. Scheitert eine davon (z. B. fehlendes `CONNECT`), ist
  das Inventar für `Grant` `partial` mit Begründung; deklarierte Grants werden dann `UNKNOWN`, nie
  `CREATE`, und nichts wird gelöscht.
- `spec.scope` des Targets begrenzt, was Ordivus überhaupt sieht. Objekte außerhalb erscheinen nicht
  im Report und können nicht gelöscht werden. Ein deklarierter Grant auf eine Datenbank außerhalb des
  Scopes schlägt im `apply` fehl. Was im authoritative-Modus gelöscht werden darf, regelt zusätzlich
  die `ReconciliationPolicy` (`scope.resourceKinds`, `scope.<Kind>.glob/exact`).
- `plan`/`drift` verbinden sich mit `default_transaction_read_only=on`; zusätzlich verweigert der
  Adapter jede Operation auf einer Read-only-Session.
- `apply` hält während des Laufs einen `pg_try_advisory_lock` mit festem Schlüssel (abgeleitet aus
  „ordivus“) in `endpoint.database`. Ist er belegt, bricht der zweite Lauf mit einem vorübergehenden
  Fehler ab, statt zu warten.

## Geschützte Systemobjekte

Nie gelöscht oder geändert, nicht deklarierte werden als `IGNORE` gezählt:

- Rollen mit Präfix `pg_` und der Bootstrap-Superuser (OID 10, meist `postgres`),
- die Datenbanken `postgres`, `template0`, `template1`,
- Grants an diese Rollen und die impliziten Rechte des Objekteigentümers.

Nicht verwaltbar (`manageable: false`, nie gelöscht, Änderungen `BLOCKED`): Superuser-Rollen und die
Rolle, als die Ordivus angemeldet ist (`endpoint.user`).

## Benötigte Rechte

**Read-only-Identität (`plan`/`drift`):** `LOGIN` und `CONNECT` auf jeder Datenbank im Scope
(Default über `PUBLIC`). Weitere Rechte sind nicht nötig. Für `passwordPolicy: verify` muss sich
Ordivus zusätzlich als jeder verwaltete Benutzer an `endpoint.database` anmelden dürfen
(`pg_hba.conf`, `CONNECT`).

**Apply-Identität:** `CREATEROLE` (in PG 16+ zusätzlich `ADMIN OPTION` auf Rollen, deren Mitglieder
vergeben werden, bzw. die Rolle hat sie selbst angelegt), `CREATEDB`, Mitgliedschaft in den
Eigentümerrollen für `CREATE DATABASE … OWNER`/`ALTER … OWNER TO`, und für Grants das Recht, die
Privilegien weiterzugeben (Eigentümer der Objekte oder `WITH GRANT OPTION`). Ein Superuser kann alles,
ist aber nicht nötig; bei verwalteten Diensten (RDS, Cloud SQL) die dortige Admin-Rolle verwenden.

## Grenzen

- Derselbe Name als `DatabaseRole` und `DatabaseUser` ist ein Konfigurationsfehler (Exit-Code 12),
  schon bei `config validate`.
- `REVOKE` entzieht nur Rechte, die die Apply-Identität selbst vergeben hat. Von anderen Rollen
  vergebene Rechte bleiben bestehen; die Operation wird dann als `unverified` gemeldet.
- `tables-in-schema` auf einem Schema **ohne Tabellen** ist nicht beobachtbar und bleibt bei jedem
  Lauf `CREATE` (der `GRANT` selbst ist dann wirkungslos).
- `DROP ROLE` scheitert, wenn die Rolle noch Objekte besitzt oder Rechte hält; Ordivus führt kein
  `REASSIGN OWNED`/`DROP OWNED` aus.
- Identifier über 63 Byte sind ein Validierungsfehler (PostgreSQL würde sie stillschweigend kürzen).
