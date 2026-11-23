# MySQL-Adapter

Verwaltet Datenbanken, Rollen, Benutzer und Grants in **MySQL 8** (getestet mit MySQL 8.4).
Installation: `pip install 'ordivus[mysql]'` (PyMySQL ≥ 1.1). Vollständiges Beispiel: `examples/mysql/`.

Kinds in Ausführungsreihenfolge: `Database`, `DatabaseRole`, `DatabaseUser`, `Grant`
(Löschungen in umgekehrter Reihenfolge).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: shop-mysql
spec:
  adapter: mysql
  endpoint:
    host: mysql.shop.svc.cluster.local
    port: 3306                 # Default 3306
    user: ordivus_admin        # Konto, als das Ordivus sich anmeldet
    tls:
      mode: verify-full        # disable | require | verify-ca | verify-full (Default)
      caFile: /trust/ca.pem    # ohne caFile gelten die System-CAs
  authentication:
    credentialRef: mysql-admin # Passwort von endpoint.user
  scope:                       # optional; ohne Eintrag wird alles inventarisiert
    databases: {include: ["shop", "shop_*"]}
    users:     {include: ["shop_*"]}
    roles:     {include: ["shop_*"]}
```

| TLS-Modus | Verhalten |
|---|---|
| `disable` | kein TLS. Nur für lokale Tests. Ohne TLS scheitert außerdem die Passwortprüfung bei `caching_sha2_password` meist (Ergebnis `unknown`) |
| `require` | TLS, Zertifikat wird **nicht** geprüft |
| `verify-ca` | Zertifikat gegen `caFile` geprüft, Hostname nicht: jedes Zertifikat derselben CA wird akzeptiert |
| `verify-full` | Zertifikat und Hostname geprüft (Default, empfohlen) |

Alles außer `verify-full` gilt als unsichere Verbindung, auch `verify-ca`: Warnung und `insecureTransport: true` im Report, mit
Operator Policy `requireTls: true` Abbruch vor dem Verbinden (Exit-Code 11).

## Discovery und Scope

- `spec.scope` begrenzt die Inventarisierung. Die Globs (`fnmatch`, Groß-/Kleinschreibung beachtet) gelten für den
  Datenbanknamen bzw. den **Benutzernamen ohne Host**. Objekte außerhalb des Scopes sieht Ordivus nicht, sie werden
  also auch nie gelöscht.
- Ein Grant liegt im Scope, wenn sein Grantee im Scope `users` oder `roles` liegt und (bei Datenbank-/Tabellen-Grants)
  seine Datenbank im Scope `databases`.
- Der Authority-Scope für den `authoritative`-Modus kommt zusätzlich aus der `ReconciliationPolicy`
  (`scope.DatabaseUser.glob` usw.). Die Globs dort gelten für die Ressourcen-ID, also `name@host` bei Konten und
  `name@host ON <objekt>` bei Grants.
- Die Datenbankliste ist nur `complete`, wenn `endpoint.user` das Privileg `SHOW DATABASES` **direkt** besitzt
  (nicht über eine Rolle). Sonst meldet Ordivus `partial`: Es legt dann keine Datenbank an und löscht keine.

## Kind `Database`

```yaml
kind: Database
metadata:
  name: shop
spec:
  targetRef: shop-mysql
  name: shop                    # optional, Default metadata.name (max. 64 Zeichen)
  characterSet: utf8mb4         # optional
  collation: utf8mb4_0900_ai_ci # optional
```

Ressourcen-ID: der Datenbankname. Wenn du nur `characterSet` angibst, setzt MySQL bei einer Änderung dessen
Default-Collation. Felder, die du weglässt, verwaltet Ordivus nicht.

## Kind `DatabaseRole`

```yaml
kind: DatabaseRole
metadata:
  name: shop-reader
spec:
  targetRef: shop-mysql
  identity:
    username: shop_reader
    host: "%"            # Default "%"
```

Ressourcen-ID: `shop_reader@%`. Eine Rolle hat keine weiteren Felder. Ihre Rechte vergibst du mit `Grant`.

## Kind `DatabaseUser`

```yaml
kind: DatabaseUser
metadata:
  name: shop-app
spec:
  targetRef: shop-mysql
  identity:
    username: shop_app        # max. 32 Zeichen
    host: "10.20.%"           # Default "%"; wird kleingeschrieben
  roles: [shop_reader]        # gewährte Rollen; "name" = name@%, sonst "name@host"
  defaultRoles: [shop_reader] # Teilmenge von roles; [] = SET DEFAULT ROLE NONE
  accountLocked: false
  credentials:
    credentialRef: shop-app-password
    passwordPolicy: verify    # verify (Default) | enforce | set-on-create
```

Ressourcen-ID: `shop_app@10.20.%`. Bei Kontonamen trennt das **letzte** `@` Name und Host, damit funktionieren auch
E-Mail-Adressen als Benutzernamen (`me@example.com@%`).

- `roles` wird exakt abgeglichen: fehlende Rollen werden gewährt, nicht deklarierte entzogen.
- Rollen in `roles`/`defaultRoles` werden in der Planung geprüft (siehe [Privilegierte Rechte](#privilegierte-rechte-allowprivilegedgrants)):
  Systemkonten (`root` usw.) und das eigene Login sind als Rolle immer gesperrt (`BLOCKED`).
- Ein Benutzer ohne `credentials` muss `accountLocked: true` setzen. MySQL würde ihn sonst ohne Passwort anlegen,
  und dann könnte sich jeder ohne Passwort anmelden. Ordivus lehnt das beim Anlegen ab.
- `passwordPolicy: verify` meldet sich **wirklich** als der Benutzer an (siehe [Passwortprüfung](#passwortprüfung-verify)).
  Fehler 1045 (Zugriff verweigert) bedeutet nur dann „Passwort falsch“ (→ `SET_PASSWORD`), wenn das Konto den Host
  `%` hat und es keinen weiteren Eintrag mit demselben Namen und kein anonymes Konto gibt (sonst meldet Ordivus
  sich gar nicht erst an). Alles andere ergibt
  `unknown` („password unverifiable“; in `apply` Status `incomplete`, Exit 13).

### User oder Rolle?

In MySQL sind Rollen ebenfalls Konten in `mysql.user`. Ordivus behandelt ein Konto als **Rolle**, wenn es gesperrt
ist (`account_locked = 'Y'`), das Passwort als abgelaufen gilt (`password_expired = 'Y'`) und
`authentication_string` leer ist. Genau so legt `CREATE ROLE` ein Konto an. Alle anderen Konten sind Benutzer. Wenn
du ein Konto (`name@host`) gleichzeitig als `DatabaseRole` und als `DatabaseUser` deklarierst, ist das ein
Konfigurationsfehler (Exit-Code 12), schon bei `config validate`. Ist ein `DatabaseUser` in `roles` eines anderen
Benutzers eingetragen, legt Ordivus ihn zuerst an.

## Kind `Grant`

```yaml
kind: Grant
metadata:
  name: shop-reader-select
spec:
  targetRef: shop-mysql
  grantee: shop_reader         # "name" = name@%, oder "name@host"
  on: database                 # global | database | table
  database: shop               # Pflicht bei database und table
  table: orders                # nur bei table
  privileges: [SELECT, SHOW VIEW]
```

Ressourcen-ID: ``shop_reader@% ON `shop`.*``. Bei `global` heißt das Objekt `*.*`, bei `table` `` `db`.`tabelle` ``.

- Ordivus normalisiert Privilegnamen: Großschreibung, einfache Leerzeichen, sortiert, ohne Duplikate.
  Die Liste wird **exakt** abgeglichen, nicht deklarierte Privilegien auf derselben Ebene werden entzogen.
- `GRANT OPTION` kannst du wie ein normales Privileg in die Liste schreiben (privilegiert, siehe unten).
- Grants auf die Systemdatenbanken `mysql`, `sys`, `information_schema` und `performance_schema` werden immer
  abgelehnt (Konfigurationsfehler): Schreibrechte auf `mysql.*` entsprechen `root`.
- Datenbanken außerhalb von `spec.scope.databases` sind gesperrt (`BLOCKED`); `apply` prüft das ein zweites Mal.
- `ALL`, `ALL PRIVILEGES` und `USAGE` werden abgelehnt. MySQL speichert `ALL PRIVILEGES` als Einzelprivilegien, je
  nach Server-Version und Plugins als andere Menge. Ein deklariertes `ALL` würde deshalb dauerhaft als Drift
  erscheinen. Liste die Privilegien explizit auf.
- Globale Grants enthalten auch dynamische Privilegien (`mysql.global_grants`, z. B. `BACKUP_ADMIN`).
- Tabellen-Grants setzen voraus, dass die Tabelle existiert.
- Datenbanknamen in Grants auf Datenbankebene sind in MySQL Muster (`_` und `%` sind Wildcards). Ordivus escapt
  sie (`app\_db`), ein Grant auf `app_db` gilt also nur für `app_db`, nicht für `appXdb`. Beim Lesen werden die
  Escapes entfernt. Vorhandene, nicht escapte Wildcard-Grants erscheinen als eigenes Objekt mit der Endung
  `(wildcard pattern)` und `manageable: false`; sie werden nie geändert oder gelöscht.

## Privilegierte Rechte (`allowPrivilegedGrants`)

Ohne die Operator-Policy `allowPrivilegedGrants: true` (Default `false`, siehe `docs/konfiguration.md`) sperrt
Ordivus in der Planung (`BLOCKED`, in `apply` Exit 11):

- jeden Grant mit `on: global` (`*.*`),
- die Privilegien `SUPER`, `CREATE USER`, `SYSTEM_USER`, `FILE`, `PROXY`, `SHUTDOWN`, `PROCESS`, `RELOAD`,
  `GRANT OPTION`, `CREATE ROLE`, `DROP ROLE`, `REPLICATION SLAVE`, `REPLICATION CLIENT`, `CREATE TABLESPACE`,
  `SHOW DATABASES` und alle `*_ADMIN` (z. B. `ROLE_ADMIN`, `BACKUP_ADMIN`) auf jeder Ebene,
- als Rolle (`roles`/`defaultRoles`) ein **Benutzerkonto** statt einer Rolle,
- als Rolle eine Rolle, die selbst oder über weitere Rollen globale Rechte, Rechte auf einer Systemdatenbank (auch
  auf einzelnen Tabellen, Spalten oder Routinen dort, z. B. `GRANT UPDATE ON mysql.user`, und über Wildcard-Muster
  wie `` `m%`.* ``) oder ein `PROXY`-Recht (`mysql.proxies_priv`, z. B. `GRANT PROXY ON root@'%'`) hat.

MySQL vergleicht Kontonamen mit aufgefülltem Leerraum (`'root '` ist `root`) und Hosts ohne Groß-/Kleinschreibung.
Deshalb sind Leerzeichen am Anfang oder Ende von Benutzernamen, Hosts, Rollen- und Grantee-Angaben sowie Datenbank-
und Tabellennamen ein Konfigurationsfehler. Zusätzlich löst die Planung jede Kontoangabe über `mysql.user` mit
MySQLs eigenem Vergleich auf und prüft die tatsächlich getroffene Zeile, nicht den Text.

Immer gesperrt, auch mit `allowPrivilegedGrants: true`: Systemkonten und das eigene Login als Rolle, als Grantee
oder als deklariertes Konto. Eine Rolle, die es noch nicht gibt, ist erlaubt: Sie entsteht über eine deklarierte
`DatabaseRole` (ohne Rechte) vor der Zuweisung.

## Geschützte Systemobjekte

Diese Objekte sind `system`. Ordivus ändert und löscht sie nie, und sie erscheinen nicht als unmanaged:

- Konten: `root` (auf **jedem** Host, also auch `root@%`), `mysql.sys`, `mysql.session`, `mysql.infoschema` und
  ihre Grants.
- Datenbanken: `mysql`, `sys`, `information_schema`, `performance_schema`.

Das eigene Konto (`endpoint.user`) und seine Grants gelten als nicht verwaltbar: Ordivus löscht sie nie und ändert
sie nicht. Rollen, die das eigene Konto (auch über weitere Rollen) hält, und ihre Grants sind `system`: Ordivus
entzieht oder löscht sie nie, damit es sich nicht selbst aussperrt.

## Rechte der Ordivus-Identität

**plan/drift (Read-only-Identität, empfohlen):**

```sql
CREATE USER 'ordivus_ro'@'%' IDENTIFIED BY '...';
GRANT SELECT ON mysql.* TO 'ordivus_ro'@'%';
GRANT SHOW DATABASES ON *.* TO 'ordivus_ro'@'%';
```

Für `passwordPolicy: verify` muss Ordivus sich außerdem als der verwaltete Benutzer anmelden können, also über den
Netzpfad und einen passenden Host-Eintrag.

**apply:** zusätzlich `CREATE USER`, `CREATE ROLE`, `DROP ROLE`, `CREATE`, `ALTER`, `DROP` (Datenbanken), jedes
Privileg, das du vergeben willst, jeweils `WITH GRANT OPTION`, außerdem `ROLE_ADMIN` für Rollenzuweisungen.
`SYSTEM_USER` brauchst du nur, wenn Ordivus Konten mit `SYSTEM_USER` verändern soll.

### Read-only-Schutz

Read-only-Sessions (`plan`, `drift`) sind doppelt abgesichert:

1. Der Adapter verweigert in einer Read-only-Session jede Operation, bevor er SQL sendet.
2. Die Session läuft mit `SET SESSION TRANSACTION READ ONLY`. MySQL 8.4 weist damit auch `CREATE USER`, `GRANT`
   und `CREATE DATABASE` ab (Fehler 1792).

Eine Sicherheitsgrenze ist beides nicht, denn eine Session kann den Modus selbst zurücksetzen. Echten Schutz bietet
nur eine Read-only-Identität mit den Rechten oben.

## Passwortprüfung (`verify`)

`verify` prüft das Passwort mit einem echten Login-Versuch. Ein falsches Passwort ist ein fehlgeschlagener Login am
Server. Damit `plan`/`drift` kein Konto sperren, meldet Ordivus sich **nicht** an (Ergebnis `unknown`), wenn

- irgendein Eintrag mit diesem Benutzernamen (auf jedem Host) oder ein anonymes Konto `FAILED_LOGIN_ATTEMPTS`
  gesetzt hat (`mysql.user.User_attributes` → `Password_locking`): der Login könnte diesen Eintrag treffen,
- es neben dem Konto weitere Einträge mit demselben Namen oder anonyme Konten gibt oder
- das Plugin oder die Komponente `connection_control` aktiv ist (verzögert Logins nach Fehlversuchen).

Fehlt die Bibliothek `cryptography` (nötig für `caching_sha2_password` ohne TLS), ist das Ergebnis ebenfalls
`unknown`. Gibt es Sperr-Richtlinien oder Login-Audits, die Fehlversuche melden, nimm `passwordPolicy: enforce`.

## Passwörter in Server-Logs

Ordivus sendet Passwörter als `IDENTIFIED BY '...'` (MySQL hasht serverseitig). MySQL 8 schreibt solche Statements
ins General Log und in `performance_schema` umgeschrieben (`IDENTIFIED BY <secret>`; mit MySQL 8.4 getestet). Der
Klartext erreicht aber den Server-Prozess und kann über Statements, die MySQL nicht umschreiben kann, oder
Debug-/Audit-Plugins anderer Hersteller sichtbar werden. Lass `general_log` aus und prüfe Audit-Plugins, bevor
Ordivus Passwörter setzt.

## Locking

`apply` holt `GET_LOCK('ordivus', 10)` auf dem Server. Ist der Lock nach 10 Sekunden nicht frei, bricht der Lauf mit
einem temporären Fehler ab (Exit 13). Der Lock gilt serverweit für alle Ordivus-Läufe.

## Grenzen

- Nicht unterstützt: Spaltenrechte (`mysql.columns_priv`), Routinen-/Proxy-Rechte, `WITH GRANT OPTION` für dynamische
  Privilegien, Rollen-Hierarchien (Rollen an Rollen), Ressourcenlimits, Passwort-Ablauf, Auth-Plugins außer dem
  Server-Default, `partial_revokes`.
- `SHOW DATABASES` über eine Rolle wird nicht erkannt, das Datenbankinventar ist dann `partial`.
- `passwordPolicy: verify` erzeugt pro abweichendem Benutzer und Lauf einen fehlgeschlagenen Login (außer bei den
  oben genannten Sperr-Mechanismen). Bei mehreren Host-Einträgen für denselben Namen ist das Ergebnis `unknown`.
- `enforce` scheitert bei aktivem `password_history`, wenn das Passwort gleich bleibt.
- Groß-/Kleinschreibung von Datenbanknamen hängt von `lower_case_table_names` ab. Ordivus vergleicht exakt.
