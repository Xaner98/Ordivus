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
| `verify-ca` | Zertifikat gegen `caFile` geprüft, Hostname nicht |
| `verify-full` | Zertifikat und Hostname geprüft (Default, empfohlen) |

`disable` und `require` gelten als unsichere Verbindung: Warnung und `insecureTransport: true` im Report, mit
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
- Ein Benutzer ohne `credentials` muss `accountLocked: true` setzen. MySQL würde ihn sonst ohne Passwort anlegen,
  und dann könnte sich jeder ohne Passwort anmelden. Ordivus lehnt das beim Anlegen ab.
- `passwordPolicy: verify` meldet sich als der Benutzer an. Fehler 1045 (Zugriff verweigert) bedeutet „Passwort
  falsch“ und führt zu `SET_PASSWORD`. Gesperrte Konten, `1130` (Host nicht erlaubt), Netzwerkfehler oder ein
  anderer Host-Eintrag, der den Login übernimmt (`CURRENT_USER()` ≠ deklariertes Konto), ergeben `unknown`.

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
- `GRANT OPTION` kannst du wie ein normales Privileg in die Liste schreiben.
- `ALL`, `ALL PRIVILEGES` und `USAGE` werden abgelehnt. MySQL speichert `ALL PRIVILEGES` als Einzelprivilegien, je
  nach Server-Version und Plugins als andere Menge. Ein deklariertes `ALL` würde deshalb dauerhaft als Drift
  erscheinen. Liste die Privilegien explizit auf.
- Globale Grants enthalten auch dynamische Privilegien (`mysql.global_grants`, z. B. `BACKUP_ADMIN`).
- Tabellen-Grants setzen voraus, dass die Tabelle existiert.
- Datenbanknamen in Grants auf Datenbankebene sind in MySQL Muster (`_` und `%` sind Wildcards). Ordivus escapt
  sie (`app\_db`), ein Grant auf `app_db` gilt also nur für `app_db`, nicht für `appXdb`. Beim Lesen werden die
  Escapes entfernt. Vorhandene, nicht escapte Wildcard-Grants erscheinen als eigenes Objekt mit der Endung
  `(wildcard pattern)` und `manageable: false`; sie werden nie geändert oder gelöscht.

## Geschützte Systemobjekte

Diese Objekte sind `system`. Ordivus ändert und löscht sie nie, und sie erscheinen nicht als unmanaged:

- Konten: `root` (auf **jedem** Host, also auch `root@%`), `mysql.sys`, `mysql.session`, `mysql.infoschema` und
  ihre Grants.
- Datenbanken: `mysql`, `sys`, `information_schema`, `performance_schema`.

Das eigene Konto (`endpoint.user`) und seine Grants gelten als nicht verwaltbar: Ordivus löscht sie nie und ändert
sie nicht.

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

## Locking

`apply` holt `GET_LOCK('ordivus', 10)` auf dem Server. Ist der Lock nach 10 Sekunden nicht frei, bricht der Lauf mit
einem temporären Fehler ab (Exit 13). Der Lock gilt serverweit für alle Ordivus-Läufe.

## Grenzen

- Nicht unterstützt: Spaltenrechte (`mysql.columns_priv`), Routinen-/Proxy-Rechte, `WITH GRANT OPTION` für dynamische
  Privilegien, Rollen-Hierarchien (Rollen an Rollen), Ressourcenlimits, Passwort-Ablauf, Auth-Plugins außer dem
  Server-Default, `partial_revokes`.
- `SHOW DATABASES` über eine Rolle wird nicht erkannt, das Datenbankinventar ist dann `partial`.
- `passwordPolicy: verify` erzeugt pro abweichendem Benutzer und Lauf einen fehlgeschlagenen Login. Das zählt bei
  `FAILED_LOGIN_ATTEMPTS` mit. Gibt es für denselben Benutzernamen mehrere Host-Einträge, kann ein Fehlschlag zu
  einem anderen Eintrag gehören. Deklariere in dem Fall `enforce` oder nur einen Host-Eintrag.
- `enforce` scheitert bei aktivem `password_history`, wenn das Passwort gleich bleibt.
- Groß-/Kleinschreibung von Datenbanknamen hängt von `lower_case_table_names` ab. Ordivus vergleicht exakt.
