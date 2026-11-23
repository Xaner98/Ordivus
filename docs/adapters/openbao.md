# Adapter `openbao` – ACL-Policies

Verwaltet OpenBao-ACL-Policies deklarativ (`plan`/`drift`/`apply`). Getrennt vom
[Credential Provider `openbao-kv-v2`](../credentials/openbao.md): eigenes Target, eigenes Token.
HashiCorp-Vault-Kompatibilität ist **nicht getestet**.

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: security-openbao
spec:
  adapter: openbao
  endpoint:
    url: https://openbao.internal.example:8200
  tls:
    caFile: /etc/ordivus/openbao-ca.pem      # optional
  protectedPolicies: [break-glass, ordivus-readonly, ordivus-apply]
  authentication:
    credentialRef: openbao-policy-admin      # Secret = OpenBao-Token
```

Das Token kommt wie jedes Admin-Credential über `authentication.credentialRef` (z. B. aus einer
gemounteten Datei über den Provider `file`). Es sollte **nicht** dieselbe Identität sein, die der
Credential Provider nutzt.

## Kind `OpenBaoPolicy`

```yaml
kind: OpenBaoPolicy
metadata:
  name: analytics-readonly
spec:
  targetRef: security-openbao
  policyName: analytics-readonly     # Schlüssel; nur Kleinbuchstaben (OpenBao normalisiert Namen)
  rules:
    - path: secret/data/analytics/*
      capabilities: [read]
```

Alternativ `spec.policy` mit rohem HCL-Text (genau eins von `rules`/`policy`).

**Rendering von `rules`:** Pfade in deklarierter Reihenfolge, Capabilities sortiert und
dedupliziert, zwei Leerzeichen Einrückung, Leerzeile zwischen Blöcken:

```hcl
path "secret/data/analytics/*" {
  capabilities = ["read"]
}
```

**Vergleich:** Beobachteter und gewünschter Text werden kanonisiert (einheitliche Zeilenenden,
Leerraum am Zeilenende und Leerzeilen am Anfang/Ende entfernt) und dann verglichen. Jede andere
Abweichung ist `UPDATE`. Semantisch gleiche, aber anders formatierte Policies (Einrückung,
Reihenfolge, Kommentare) erscheinen daher **einmal** als `UPDATE`; danach steht der Ordivus-Text in
OpenBao und der Lauf konvergiert zu `NOOP`. Ein semantischer HCL-Vergleich findet nicht statt.

Discovery: `GET sys/policies/acl?list=true`, dann `GET sys/policies/acl/<name>` je Policy.
Fehlt das Recht (403), ist das Inventar `forbidden` – nie „leer“.

## Schutzregeln (Self-Escalation / Self-Lockout, §11.4, F-32)

Nie geändert oder gelöscht werden:

- `root`, `default`,
- alle Namen aus `protectedPolicies` (z. B. Break-Glass- und Ordivus-eigene Policies),
- alle Policies des verwendeten Tokens (`GET auth/token/lookup-self`: `policies` und
  `identity_policies`) – Ordivus kann sich so weder neue Rechte geben noch aussperren.

Deklariert und abweichend → `BLOCKED`; nicht deklariert → `IGNORE`, auch im authoritative Mode.
Eine geschützte Policy, die noch nicht existiert, würde als `CREATE` geplant; `apply` verweigert
sie dann mit einem Fehler.

Diese Sperre ist eine zweite Verteidigungslinie. Die eigentliche Grenze ist die OpenBao-Policy
des Apply-Tokens: Schreibrechte nur auf einen Namensbereich, z. B.

```hcl
path "sys/policies/acl"        { capabilities = ["list"] }
path "sys/policies/acl/app-*"  { capabilities = ["create", "read", "update", "delete"] }
```

Achtung: Wer Policies schreiben darf, die anderen Identitäten zugeordnet sind, kann darüber
indirekt Rechte vergeben. Policy-Namensbereich und Zuordnung (Auth-Rollen, Gruppen) getrennt
kontrollieren; Break-Glass-Runbook bereithalten.

## Read-only

`plan`/`drift` öffnen eine Read-only-Session; `apply` wird darin verweigert. Das ist nur eine
Programm-Sperre – die echte Garantie ist ein Read-only-Token:

```hcl
path "sys/policies/acl"   { capabilities = ["list"] }
path "sys/policies/acl/*" { capabilities = ["read"] }
```

## Grenzen

- Nur ACL-Policies; keine Namespaces, keine Sentinel-/EGP-/RGP-Policies, keine Auth-Methoden oder
  Rollen-Zuordnungen.
- Kein `X-Vault-Namespace` am Target (nur Root-Namespace).
- Textvergleich statt semantischem HCL-Vergleich (siehe oben).
- `http://`-Endpoints werden nicht abgelehnt; in Produktion `https://` mit Zertifikatsprüfung.
