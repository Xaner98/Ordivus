# Redis-Adapter

Verwaltet **ACL-Benutzer** in Redis 7 und neuer (getestet mit Redis 8) als Kind `DatabaseUser`.
Installation: `pip install 'ordivus[redis]'` (redis-py ≥ 5).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: cache-redis
spec:
  adapter: redis
  endpoint:
    host: redis.cache.svc.cluster.local
    port: 6379              # Default 6379
    tls:                    # vorhanden → TLS (rediss); ohne caFile gelten die System-CAs
      caFile: /trust/ca.pem
  username: ordivus-admin   # ACL-Benutzer, als der Ordivus sich anmeldet; Default "default"
  persist: aclSave          # none (Default) | aclSave | configRewrite
  authentication:
    credentialRef: redis-admin   # Passwort des Admin-Benutzers
```

| Feld | Bedeutung |
|---|---|
| `endpoint.host` | Pflicht |
| `endpoint.port` | Default `6379` |
| `endpoint.tls.caFile` | CA-Datei; der Block `tls` schaltet TLS ein, Hostname wird geprüft |
| `username` | Admin-Benutzer; Default `default` |
| `persist` | siehe [Persistenz](#persistenz) |

`spec.scope` wird nicht unterstützt; Einschränkungen für den authoritative-Modus kommen aus der
`ReconciliationPolicy` (`scope.DatabaseUser.glob`).

## Kind `DatabaseUser`

`metadata.name` ist der Redis-Benutzername.

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata:
  name: app-sessions
spec:
  targetRef: cache-redis
  enabled: true                               # Default true (ACL-Flag on/off)
  keys: ["session:*", "%R~config:*"]          # Schlüsselmuster
  channels: ["session-events"]                # Pub/Sub-Kanalmuster
  commands: ["+@read", "+@write", "-@dangerous", "+ping"]
  credentials:
    credentialRef: app-sessions-password
    passwordPolicy: verify
```

| Feld | Typ | Redis-Regel | Hinweise |
|---|---|---|---|
| `enabled` | bool | `on` / `off` | Default `true`, wird immer verwaltet |
| `keys` | Liste | `~muster`, `%R~muster`, `%W~muster` | `muster`, `~muster` und `%RW~muster` sind gleichbedeutend |
| `channels` | Liste | `&muster` | ein führendes `&` ist optional |
| `commands` | Liste | `+befehl`, `-befehl`, `+befehl\|sub`, `+@kategorie`, `allcommands`, `nocommands` | Groß-/Kleinschreibung egal |
| `credentials` | – | `>passwort` | Engine-Feld, siehe [Passwörter](#passwörter) |

`selectors` (Redis-7-Selektoren in Klammern) werden **nicht** unterstützt und bei der Validierung
abgelehnt. Vorhandene Selektoren werden in der Discovery als Feld `selectors` angezeigt, aber nie
verglichen oder verändert.

### Nur deklarierte Felder

Wie überall in Ordivus gilt: ein nicht gesetztes Feld heißt **nicht** „zurücksetzen“. Ein
`UPDATE` schreibt nur die geänderten Feldgruppen und setzt dabei genau diese Gruppe zurück:

| Feld | gesendete Regeln |
|---|---|
| `enabled` | `on` bzw. `off` |
| `keys` | `resetkeys` + Muster |
| `channels` | `resetchannels` + Muster |
| `commands` | `-@all` bzw. `+@all` + Regeln |

Ist z. B. nur `commands` deklariert, bleiben Schlüssel- und Kanalmuster am Server unverändert.
Das ist die sicherere Variante gegenüber `ACL SETUSER name reset …`, das bei jedem Update alle
nicht deklarierten Rechte (und das Passwort) löschen würde.

Ausnahme **CREATE**: Ein neuer Benutzer wird mit `ACL SETUSER name reset <Regeln>` angelegt. Für
nicht deklarierte Felder gilt dann der Redis-Default nach `reset`: keine Schlüssel, keine Befehle
(`-@all`), Kanäle laut `acl-pubsub-default` (seit Redis 7: keine), kein Passwort (Anmeldung
unmöglich), keine Selektoren.

### Normalisierung

Redis fasst Regeln beim Speichern zusammen; `ACL GETUSER` liefert die zusammengefasste Form.
Ordivus normalisiert Soll und Ist mit denselben Regeln, damit ein zweiter Lauf `NOOP` ergibt:

- `keys`: gleiche Muster werden zusammengeführt (`%R~a` + `%W~a` = `a`), Ergebnis sortiert.
  `*` mit vollen Rechten ersetzt alle anderen Muster.
- `channels`: Duplikate entfernt, sortiert; `*` ersetzt alle anderen.
- `commands`: Reihenfolge bleibt (sie ist bedeutsam). Die Liste beginnt immer mit `-@all` (Default)
  oder `+@all`. `allcommands`/`nocommands`/`+@all`/`-@all` verwerfen alle vorherigen Regeln; eine
  Regel ersetzt frühere Regeln für denselben Befehl bzw. dieselbe Kategorie; `+config` ersetzt auch
  frühere Regeln für `config|…`. Alles in Kleinbuchstaben.

Beispiel: `["+@read", "-get", "+get"]` wird zu `["-@all", "+@read", "+get"]`.

Diese Nachbildung beruht auf beobachtetem Verhalten von Redis 8 und ist in den
Integrationstests abgesichert. Fasst eine andere Version anders zusammen, zeigt `plan` dauerhaft ein
`UPDATE` für `commands`; Abhilfe: Regeln in der Form deklarieren, die `ACL GETUSER` zurückgibt.

### Eingabeprüfung

Jede Regel geht als eigenes Argument an `ACL SETUSER` (kein Zusammenbauen von Strings). Zusätzlich:

- Benutzernamen: nur ASCII-Buchstaben, Ziffern und `. _ @ : -`, Beginn mit Buchstabe oder Ziffer,
  höchstens 128 Zeichen. Namen wie `>pw`, `#hash`, mit Leerzeichen oder Umlauten werden abgelehnt.
- `commands`: nur die Formen aus der Tabelle oben. Regeln wie `>secret`, `nopass`, `on`, `reset`
  sind damit ausgeschlossen.
- `keys`/`channels`: keine Leer- oder Steuerzeichen. Unicode ist erlaubt. Ordivus setzt das Präfix
  `~`/`&` selbst, deshalb bleiben Muster wie `>pw` oder `#x` wörtliche Muster und werden nie als
  Passwort- oder Hash-Regel gelesen.

## Passwörter

`spec.credentials` verwaltet genau ein Passwort pro Benutzer.

- **Setzen** (`CREATE`, `SET_PASSWORD`): `resetpass` + `>passwort`; alle früheren Passwörter und
  ein `nopass`-Flag werden entfernt.
- **Prüfen** (`passwordPolicy: verify`): `ACL GETUSER` liefert SHA-256-Hashes der Passwörter.
  Ordivus vergleicht `sha256(secret)` mit dieser Liste, **ohne Login-Versuch**. Ein Benutzer mit
  `nopass` gilt als „Passwort weicht ab“ und bekommt ein `SET_PASSWORD`.
- Die Hashes werden bei der Prüfung über die Session gelesen und nirgends gespeichert, auch nicht in
  Reports oder Attributen.

## Geschützte Benutzer

`default` und der Benutzer aus `spec.username` sind Systemobjekte: nicht deklariert → `IGNORE`, nie
gelöscht; deklariert → `BLOCKED`. Der Adapter verweigert Änderungen an ihnen auch
direkt.

## Privilegierte Rechte (`allowPrivilegedGrants`)

Privilegiert ist jeder Befehl (auch Subcommand) der Redis-Kategorien **`@admin`** und
**`@dangerous`**, wie der Server sie per `ACL CAT admin` / `ACL CAT dangerous` meldet – u. a.
`config`, `acl`, `module`, `debug`, `shutdown`, `monitor`, `replicaof`/`slaveof`, `save`/`bgsave`,
`flushall`/`flushdb`, `keys`, `sort`, `migrate`, `restore`, `cluster …`, `client kill`. Ordivus wertet
die deklarierten `commands` in Reihenfolge aus (wie Redis); erlauben sie danach einen dieser Befehle,
ist die Ressource ohne `allowPrivilegedGrants: true` `BLOCKED`. Das gilt für `+@all`/`allcommands`,
`+@admin`, `+@dangerous`, einzelne Befehle wie `+config` und auch für Kategorien, die solche Befehle
enthalten: `+@read` erlaubt `keys` und ist damit privilegiert, `+@read +@write -@dangerous` nicht.

Gesperrt werden nur **hinzukommende** Rechte: Hat ein bestehender Benutzer einen privilegierten
Befehl schon, blockiert dessen Beibehaltung nicht. Nicht deklarierte Admin-Benutzer bleiben
`UNMANAGED`. Lässt sich `ACL CAT` nicht lesen, ist die Ressource ebenfalls `BLOCKED`.

## Benötigte Rechte

Der Admin-Benutzer braucht mindestens:

```
+ping +acl|users +acl|getuser            # plan/drift
+acl|setuser +acl|deluser                # apply
+config|get +info +acl|save              # persist: aclSave
+info +config|rewrite                    # persist: configRewrite
```

Für `plan`/`drift` reicht ein Benutzer mit den ersten drei Rechten. Unabhängig davon verweigert der
Adapter jede Änderung über eine Read-only-Session.

## Persistenz

Achtung: `ACL SETUSER`/`ACL DELUSER` ändern nur den **Speicher** von Redis. Nach einem Neustart sind
die Änderungen weg, wenn sie nicht gesichert werden. `spec.persist` steuert, was Ordivus nach
**jeder** Änderung tut:

| Wert | Wirkung | Voraussetzung |
|---|---|---|
| `none` (Default) | nichts; Persistenz liegt beim Betreiber | – |
| `aclSave` | `ACL SAVE` | Server mit `aclfile` konfiguriert |
| `configRewrite` | `CONFIG REWRITE` (Benutzer landen in `redis.conf`) | Server mit Konfigurationsdatei, ohne `aclfile` |

Die Voraussetzung wird bei `apply` vor der ersten Änderung geprüft; fehlt sie, bricht der Lauf für
dieses Target ab, ohne etwas zu ändern. `plan`/`drift` prüfen sie nicht.

Wird Redis aus einer ACL-Datei oder `redis.conf` gestartet, die Ordivus nicht schreibt (z. B. ein
ConfigMap im Kubernetes), überschreibt der nächste Neustart die Änderungen. Dann muss die Quelle
selbst gepflegt werden; Ordivus meldet die Abweichung beim nächsten `drift`.

## Einschränkungen

- Keine Selektoren, keine Flags außer `on`/`off` (z. B. `skip-sanitize-payload` wird nicht verwaltet).
- Mehrere Passwörter pro Benutzer werden nicht unterstützt; `SET_PASSWORD` ersetzt alle.
- Redis Cluster: ACLs sind pro Knoten. Jeder Knoten muss als eigenes Target konfiguriert werden.
- Kein Lock: zwei gleichzeitige `apply`-Läufe gegen denselben Server sind nicht gegeneinander
  abgesichert.
- `verify` braucht `ACL GETUSER`; ist das nicht erlaubt, ist das Ergebnis `UNKNOWN` (kein Login-Fallback).
- Ohne `tls` gilt die Verbindung als unsicher (Warnung, `insecureTransport: true`; mit Operator Policy
  `requireTls: true` Abbruch, Exit-Code 11).

## Valkey

Valkey 7.2+/8 bietet dieselben ACL-Befehle und sollte funktionieren, ist aber **ungetestet**.
