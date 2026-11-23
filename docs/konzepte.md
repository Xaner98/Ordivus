# Konzepte

Ordivus verwaltet **administrative Konfiguration** in Systemen, die Sie bereits betreiben: Benutzer, Rollen, Berechtigungen, Datenbanken und Policies in PostgreSQL, MySQL, ClickHouse, ArcadeDB, Redis, OpenBao und weiteren Systemen. Sie beschreiben den gewünschten Zustand in YAML-Dateien; Ordivus liest bei jedem Lauf den tatsächlichen Zustand direkt aus dem Zielsystem, zeigt die Unterschiede und wendet erlaubte Änderungen an.

## Zustandslos

Ordivus speichert nichts zwischen zwei Läufen: keine State-Datei, keine eigene Datenbank, keine Markierungen in den Zielsystemen. Die Wahrheit ist immer zweierlei:

- **Soll:** Ihre Konfigurationsdateien.
- **Ist:** das Zielsystem, live gelesen.

Deshalb sieht Ordivus auch Objekte, die jemand von Hand oder mit einem anderen Werkzeug angelegt hat.

## Drei Befehle

| Befehl | Zweck | Ändert etwas? |
|---|---|---|
| `ordivus plan` | Was würde `apply` jetzt tun? | nein |
| `ordivus drift` | Weicht der Istzustand vom Soll ab? Gibt es fremde Objekte? | nein |
| `ordivus apply` | Erlaubte Änderungen ausführen und danach prüfen | ja |

`plan` und `drift` verändern weder Zielsysteme noch Secret Stores – auch kein „nur kurz“ erzeugtes Passwort. Für echte Sicherheit sollten diese Befehle zusätzlich mit einer Identität laufen, die am Zielsystem nur lesen darf.

## Was mit nicht deklarierten Objekten passiert

| Situation | Ergebnis |
|---|---|
| deklariert, fehlt | `CREATE` |
| deklariert, gleich | `NOOP` |
| deklariert, abweichend | `UPDATE` (nur die deklarierten Felder) |
| nicht deklariert, Modus `additive` (Standard) | `UNMANAGED` – nur gemeldet |
| nicht deklariert, Modus `authoritative` im Scope | `UNDESIRABLE` – gelöscht wird erst, wenn die Operator Policy Löschen erlaubt |
| ausgeschlossen oder Systemobjekt | `IGNORE` – nur gezählt; deklariertes Systemobjekt → `BLOCKED` |
| Zielsystem nicht vollständig lesbar | `UNKNOWN` – nie Löschen, nie Anlegen |
| vom Adapter nicht veränderbar (z. B. ClickHouse-Benutzer aus `users.xml`) | `UNMANAGED`, Kennzeichen `manageable: false`; deklariert → `BLOCKED` (auch ohne Abweichung) |

Ein nicht gesetztes Feld heißt **nicht** „zurücksetzen“: Verglichen werden nur Felder, die Sie deklariert haben.

## Unbekannt bleibt unbekannt

Fehlen Leserechte, läuft eine Abfrage in einen Timeout oder liefert ein Zielsystem nur einen Teil seiner Objekte, meldet Ordivus `partial`, `forbidden` oder `unknown` – niemals „leer“. Darauf beruhen alle Schutzmechanismen gegen falsches Löschen. Umgekehrt meldet `apply` ein Target mit einer deklarierten, aber nicht prüfbaren Ressource als `incomplete` (Exit-Code 13), nie als `in_sync`.

## Passwörter

Passwörter stehen nie in der Konfiguration, sondern in einem **Credential Provider** (Datei/gemountetes Kubernetes Secret, OpenBao KV v2, Umgebungsvariable nur zur Entwicklung).

- Fehlt das Secret, erzeugt `apply` ein kryptografisch zufälliges Passwort, legt es *create-if-absent* im Provider ab und setzt es am Benutzer. `plan` zeigt dies vorher als `CREATE_SECRET`.
- Standard für bestehende Benutzer ist `passwordPolicy: verify`: Ordivus prüft bei jedem Lauf am Zielsystem, ob das Passwort noch stimmt (Anmeldeversuch oder Hash-Vergleich, je nach Adapter), und setzt es bei Abweichung neu. Prüft ein Adapter per Anmeldeversuch, zählen fehlgeschlagene Versuche bei Sperrrichtlinien des Zielsystems mit; dort ist `enforce` die bessere Wahl (Details je Adapter).
- Alternativen: `enforce` (bei jedem `apply` setzen) und `set-on-create` (nur bei Anlage).
- Ist der Zustand eines Secrets nicht sicher feststellbar (z. B. fehlende Leserechte), wird **kein** Passwort verändert.

Secrets erscheinen nie im Klartext in Reports, Logs oder Fehlermeldungen.

## Zwei Arten von Policies

- **Operator Policy** (`--policy datei.yaml`): von Ihrem Plattform- oder Security-Team getrennt verwaltet. Sie legt fest, was überhaupt erlaubt ist: welche Targets, ob `authoritative`, ob Löschen, ob Passwort-Resets und ob die Konfiguration privilegierte Rechte vergeben darf (`allowPrivilegedGrants`, Standard nein). Die Konfiguration kann nie mehr Rechte vergeben, als die Operator Policy zulässt.
- **ReconciliationPolicy** (in der Konfiguration): kann nur *einschränken* – Modus, Scope, Ausnahmen. Ein `mode: authoritative` in der Konfiguration ist ein Antrag, keine Berechtigung.

## Wo Ordivus läuft

Überall, wo Python und eine Netzwerkverbindung zum Zielsystem vorhanden sind: auf dem Laptop, in einer CI-Pipeline, auf einer VM oder als Kubernetes Job. Zielsysteme dürfen innerhalb oder außerhalb eines Clusters liegen. Im Cluster ist der Betrieb bevorzugt, weil die Kommunikation dann clusterintern bleibt.

Ordivus ist kein dauerhaft laufender Dienst. Wann ein Lauf startet, entscheidet Ihre Pipeline, Ihr GitOps-Werkzeug oder ein CronJob.

## Gleichzeitige Läufe

Adapter, deren Zielsystem eine eigene Sperre bietet (z. B. PostgreSQL Advisory Locks, MySQL `GET_LOCK`), sperren während `apply`. Für Systeme ohne Sperrmechanismus sollten Sie parallele `apply`-Läufe gegen dasselbe Ziel organisatorisch vermeiden.
