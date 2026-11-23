# Konfiguration

Eine Ordivus-Konfiguration ist eine Datei oder ein Verzeichnis mit YAML- bzw. JSON-Dateien (`*.yaml`, `*.yml`, `*.json`, rekursiv). Dateien und Verzeichnisse, deren Name mit `.` beginnt, werden übersprungen (z. B. `..data` in ConfigMap-Mounts). Jede Datei darf mehrere Dokumente enthalten, getrennt durch `---`. Jedes Dokument hat dieselbe äußere Form:

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: <Kind>
metadata:
  name: <eindeutiger Name je Kind>
spec:
  ...
```

Unbekannte Felder sind Fehler, nicht stille Ignorierung. Fehlermeldungen nennen Datei und Zeile. Adapter prüfen außerdem dokumentübergreifend je Target (z. B. derselbe Name als `DatabaseRole` und `DatabaseUser`); solche Fehler nennen die Stelle des Target-Dokuments.

Prüfen ohne Verbindung zu einem Zielsystem:

```sh
ordivus config validate -f ./config
```

Die Ausgabe enthält die Anzahl je Kind und einen `configDigest` (SHA-256 über den kanonischen Inhalt). Der Digest ist unabhängig von Dateiaufteilung und Schlüsselreihenfolge und eignet sich, um im Audit nachzuweisen, welche Konfiguration ein Lauf verwendet hat.

## YAML-Besonderheiten

Ordivus liest YAML mit der Semantik des **YAML-1.2-Core-Schemas**:

- `no`, `yes`, `on`, `off`, `y`, `n` bleiben Zeichenketten (in YAML 1.1 wären es Booleans). Ein Benutzer namens `no` bleibt also `no`.
- Nur `true`/`false` sind Booleans, nur `null`/`~`/leer ist null.
- `0777` ist die Zahl 777, Oktal schreibt man `0o777`. Datumsangaben und Werte wie `1:30` bleiben Zeichenketten.
- **Anker und Aliase (`&`, `*`) sind nicht erlaubt**, doppelte Schlüssel ebenfalls. Maximale Dateigröße: 1 MiB.

## Kinds der Engine

### Target – ein Zielsystem

```yaml
kind: Target
metadata:
  name: analytics-postgres
spec:
  adapter: postgresql             # welcher Adapter
  authentication:
    credentialRef: postgres-admin # Admin-Credential (siehe Credential)
  # alle weiteren Felder (endpoint, tls, scope …) sind adapterspezifisch,
  # siehe docs/adapters/<adapter>.md
```

### CredentialProvider – woher Secrets kommen

```yaml
kind: CredentialProvider
metadata:
  name: local-secrets
spec:
  type: file
  directory: /var/run/secrets/ordivus   # eine Datei je Secret
```

| `type` | Zweck |
|---|---|
| `file` | Eine Datei je Secret in `directory`. Passt zu gemounteten Kubernetes Secrets und zu Dateien, die eine CI-Pipeline bereitstellt. Neue Secrets werden mit Rechten `0600` angelegt. |
| `openbao-kv-v2` | OpenBao (oder Vault-kompatibel) KV v2, siehe [credentials/openbao.md](credentials/openbao.md). |
| `env` | Umgebungsvariablen, **nur im Profil `development`**, nur lesend. |

### Credential – ein einzelnes Secret

```yaml
kind: Credential
metadata:
  name: reporting-password
spec:
  providerRef: local-secrets
  path: reporting-password        # file: Dateiname; openbao: KV-Pfad; env: Variablenname
  lifecycle:
    generator:                    # optional, nur für neu erzeugte Passwörter
      length: 40                  # mindestens 16, Standard 32
      alphabet: alphanumeric      # oder alphanumeric-symbol-safe
```

### Ressourcen

Ressourcen-Kinds (`Database`, `DatabaseUser`, `DatabaseRole`, `Grant`, `OpenBaoPolicy` …) kommen von den Adaptern. Gemeinsam ist allen:

```yaml
kind: DatabaseUser
metadata:
  name: reporting-reader
spec:
  targetRef: analytics-postgres   # Pflicht
  credentials:                    # nur bei Kinds mit Passwort
    credentialRef: reporting-password
    passwordPolicy: verify        # verify (Standard) | enforce | set-on-create
  # weitere Felder: siehe docs/adapters/<adapter>.md
```

| `passwordPolicy` | Verhalten |
|---|---|
| `verify` | Bei jedem Lauf prüfen, ob das Passwort am Zielsystem noch stimmt; bei Abweichung setzt `apply` es neu. |
| `enforce` | `apply` setzt das Passwort bei jedem Lauf, ohne zu prüfen. |
| `set-on-create` | Nur bei Anlage setzen, danach nicht mehr anfassen. |

In allen drei Fällen gilt: Fehlt das Secret im Provider, erzeugt `apply` ein neues und setzt es am Benutzer.

### ReconciliationPolicy – Modus, Scope, Ausnahmen je Target

```yaml
kind: ReconciliationPolicy
metadata:
  name: analytics-governance
spec:
  targetRef: analytics-postgres
  mode: authoritative             # additive (Standard) | authoritative
  scope:
    resourceKinds: [DatabaseUser, DatabaseRole]   # Pflicht bei authoritative
    DatabaseUser:
      glob: ["app_*"]             # nur diese Benutzer gehören Ordivus
  exclusions:
    DatabaseUser:
      exact: [app_legacy]
      glob: ["app_tmp_*"]
```

- Höchstens eine ReconciliationPolicy je Target.
- Nicht deklarierte Objekte **außerhalb** des Scopes bleiben `UNMANAGED`, innerhalb `UNDESIRABLE`.
- `authoritative` wirkt nur, wenn die Operator Policy es erlaubt; gelöscht wird nur mit `allowDelete: true`.

## Operator Policy

Die Operator Policy ist **keine** Ressource der Konfiguration, sondern eine eigene Datei, die getrennt verwaltet und mit `--policy` übergeben wird – typischerweise aus einem anderen Repository oder einem geschützten Volume.

```yaml
allowTargets: ["*"]          # oder Liste von Target-Namen
allowAuthoritative: false
allowDelete: false
allowPasswordReset: true
profile: standard            # standard | development
requireTls: false            # true: Targets ohne TLS bzw. ohne Zertifikatsprüfung verweigern
```

`requireTls`: Was als unsicher gilt, legt der Adapter fest (Klartext, TLS aus, keine Zertifikatsprüfung; bei PostgreSQL alles außer `verify-ca`/`verify-full`). Mit `true` bricht der Lauf vor der ersten Verbindung mit Exit-Code 11 ab; mit `false` gibt es eine Warnung auf stderr und `"insecureTransport": true` am Target im Report.

Ohne `--policy` gelten genau diese Werte. Eine angegebene, aber fehlende oder fehlerhafte Policy-Datei bricht den Lauf ab (Exit-Code 11).

## Exit-Codes

| Code | Bedeutung |
|---:|---|
| 0 | Erfolgreich, Schwellenwerte eingehalten |
| 1 | Interner Fehler (Bug, bitte melden) |
| 2 | Ungültiger Aufruf (Argumente) |
| 10 | Drift-/Änderungsschwelle überschritten (`--fail-on`) |
| 11 | Policy-Verstoß oder nicht erlaubte Operation; bei `apply` auch jede `BLOCKED`-Operation (die übrigen laufen trotzdem) |
| 12 | Konfigurationsfehler |
| 13 | Zielsystem, Credential oder Netzwerk nicht verfügbar |
| 14 | Teilweise ausgeführt oder nach `apply` nicht bestätigt – bitte prüfen |
| 130 / 143 | Abgebrochen (SIGINT / SIGTERM) |

Schwellen: `ordivus plan --fail-on changes`, `ordivus drift --fail-on actionable|unmanaged|any`. Ohne `--fail-on` enden `plan` und `drift` mit 0, auch wenn Abweichungen gefunden wurden.

## Report

`--format human` (Standard) liefert lesbaren Text. `--format json` schreibt **JSON Lines**: Der Report ist eine Zeile mit `"type": "report"`, Log-Ereignisse gehen nach stderr. So lässt sich der Report auch aus zusammengeführten Logs (z. B. `kubectl logs`) herausfiltern:

```sh
ordivus drift -f ./config --format json | grep '"type": *"report"' > report.json
```

Operationen an nicht veränderbaren oder geschützten Objekten tragen `"manageable": false` bzw. `"system": true`. Passwörter erscheinen nur als `CREATE_SECRET` und `SET_PASSWORD` (Wert immer `<redacted>`), nie unter den Änderungen eines `CREATE`. Kann ein Credential Provider den Zustand eines Secrets nicht bestimmen, steht der Grund als `reason` an der Credential-Operation (`UNKNOWN`, bzw. `BLOCKED`, wenn nur ein manueller Eingriff hilft).

Mit `--output DATEI` landet der Report in einer Datei. Ordivus speichert Reports nicht selbst; das Aufzeichnen übernimmt das aufrufende System (CI-Artefakt, Log-Sammlung).
