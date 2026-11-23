# Credential Provider `openbao-kv-v2`

Liest und erzeugt verwaltete Passwörter in einer OpenBao-KV-v2-Secret-Engine. Der Provider ist
unabhängig vom [Policy-Adapter `openbao`](../adapters/openbao.md): eigene Konfiguration, eigene
Identität, eigene OpenBao-Policies.

Kompatibilität mit der KV-v2-API von HashiCorp Vault ist naheliegend, aber **nicht getestet**.

## Konfiguration

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: CredentialProvider
metadata:
  name: central-openbao
spec:
  type: openbao-kv-v2
  endpoint: https://openbao.internal.example:8200
  mount: secret            # Default: secret
  namespace: team-a        # optional, Header X-Vault-Namespace
  tls:
    caFile: /etc/ordivus/openbao-ca.pem   # optional, sonst System-CAs
  auth:
    method: kubernetes     # token | kubernetes | approle | jwt
    role: ordivus-apply
---
apiVersion: ordivus.dev/v1alpha1
kind: Credential
metadata:
  name: reporting-password
spec:
  providerRef: central-openbao
  path: tenants/acme/reporting   # KV-Pfad relativ zum Mount
```

- **Ein Credential pro KV-Pfad** (F-04). Das Feld heißt fest `password`; weitere Felder im
  Dokument werden nicht gelesen und nie geschrieben.
- Pfadsegmente `.`/`..` und leere Segmente sind verboten.
- `endpoint` mit `http://` markiert den Provider als *development-only*: ein Lauf verlangt dann
  das Operator-Profil `development` (Klartext-HTTP nur für lokale Tests).

### Authentifizierung (`spec.auth`)

| `method` | Felder | Login |
|---|---|---|
| `token` | `tokenFile` | Token aus Datei; **nie** inline in der Config |
| `kubernetes` | `role`, `jwtFile` (Default `/var/run/secrets/kubernetes.io/serviceaccount/token`), `mount` (Default `kubernetes`) | `auth/<mount>/login` mit ServiceAccount-JWT (im Cluster, bevorzugt projizierte Tokens mit eigener Audience) |
| `approle` | `roleId`, `secretIdFile`, `mount` (Default `approle`) | `auth/<mount>/login`; für CI/VMs außerhalb des Clusters |
| `jwt` | `role`, `jwtFile`, `mount` (Default `jwt`) | `auth/<mount>/login`; z. B. CI-ID-Token (GitLab `id_tokens`, GitHub OIDC) außerhalb des Clusters |

Der Login erfolgt erst beim ersten Zugriff; das Token lebt nur im Speicher des Laufs und wird
nicht erneuert (Läufe sind kurz; TTL der Rolle entsprechend wählen). Tokens stehen nur im Header
`X-Vault-Token`, nie in URLs, Logs oder Fehlermeldungen.

## Zustände: present / absent / unknown

| Beobachtung | Zustand |
|---|---|
| `GET <mount>/metadata/<path>` = 200, aktuelle Version weder gelöscht noch zerstört | `present` |
| Metadata 404 **und** `sys/capabilities-self` bestätigt `read` auf `<mount>/metadata/<path>` **und** `<mount>/data/<path>` | `absent` |
| Metadata 404 ohne bestätigtes Leserecht auf beiden Pfaden | `unknown` |
| 403, 401, 5xx, Timeout, Netzwerk-/TLS-Fehler | `unknown` |
| Metadata 200, aktuelle Version gelöscht (`deletion_time`) oder zerstört | `unknown` + Warnung „manual action required“ |

Ein Rechtefehler ergibt nie `absent`. Bei `unknown` blockiert die Engine das Anlegen des
Benutzers und fasst weder Secret noch Passwort an.

**Gelöschte aktuelle Version:** Der Wert ist weg, `cas=0` würde scheitern, ein Neuanlegen mit
höherer Version wäre ein stilles Überschreiben der Historie. Ordivus meldet deshalb `unknown`
(Credential-Op `UNKNOWN`) und schreibt eine Warnung ins Log. Auflösung manuell: Version
wiederherstellen (`undelete`) oder Metadaten bewusst löschen (`DELETE <mount>/metadata/<path>`),
danach erkennt der nächste Lauf `absent`.

## Erzeugen: create-if-absent mit CAS

Nur `apply` schreibt (`plan`/`drift` generieren nicht einmal einen Wert). Geschrieben wird mit
`POST <mount>/data/<path>` und `options.cas = 0`: OpenBao akzeptiert das nur, wenn der Pfad noch
keine Version hat. Bei einem CAS-Konflikt (paralleler Lauf war schneller) liest Ordivus den
vorhandenen Wert und verwendet ihn – ein bestehendes Secret wird **nie** überschrieben.

## Benötigte OpenBao-Policies

Read-only-Identität (`plan`/`drift`, `passwordPolicy: verify` braucht den Wert):

```hcl
path "secret/metadata/tenants/acme/*" { capabilities = ["read"] }
path "secret/data/tenants/acme/*"     { capabilities = ["read"] }
```

Apply-Identität (zusätzlich anlegen; kein `update`, kein `delete` nötig):

```hcl
path "secret/metadata/tenants/acme/*" { capabilities = ["read"] }
path "secret/data/tenants/acme/*"     { capabilities = ["read", "create"] }
```

`sys/capabilities-self` ist über die eingebaute Policy `default` erlaubt; wer Tokens ohne
`default` ausgibt, muss `path "sys/capabilities-self" { capabilities = ["update"] }` ergänzen –
sonst bleibt jedes fehlende Secret `unknown`.

## Grenzen

- Nur KV v2, nur Feld `password`, keine Multi-Field-Dokumente.
- Keine Token-Erneuerung, kein Lease-Handling.
- Kein Retry; Netzwerkfehler sind `unknown` bzw. Abbruch des Ziels.
- Der Grund für `unknown` steht nur im Log, nicht im Report (Engine-Vertrag kennt keinen Grund).
