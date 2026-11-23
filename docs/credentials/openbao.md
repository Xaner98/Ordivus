# Credential provider `openbao-kv-v2`

Reads and generates managed passwords in an OpenBao KV v2 secrets engine. The provider is
independent of the [policy adapter `openbao`](../adapters/openbao.md): its own configuration, its own
identity, its own OpenBao policies.

Compatibility with the KV v2 API of HashiCorp Vault is likely, but **not tested**.

## Configuration

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: CredentialProvider
metadata:
  name: central-openbao
spec:
  type: openbao-kv-v2
  endpoint: https://openbao.internal.example:8200
  mount: secret            # default: secret
  namespace: team-a        # optional, header X-Vault-Namespace
  tls:
    caFile: /etc/ordivus/openbao-ca.pem   # optional, otherwise system CAs
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
  path: tenants/acme/reporting   # KV path relative to the mount
```

- **One credential per KV path** (F-04). The field is always named `password`; other fields in the
  document are never read and never written.
- Path segments `.`/`..` and empty segments are forbidden.
- An `endpoint` with `http://` marks the provider as *development-only*: a run then requires
  the operator profile `development` (plain-text HTTP only for local tests).

### Authentication (`spec.auth`)

| `method` | Fields | Login |
|---|---|---|
| `token` | `tokenFile` | Token from a file; **never** inline in the config |
| `kubernetes` | `role`, `jwtFile` (default `/var/run/secrets/kubernetes.io/serviceaccount/token`), `mount` (default `kubernetes`) | `auth/<mount>/login` with ServiceAccount JWT (in the cluster, preferably projected tokens with their own audience) |
| `approle` | `roleId`, `secretIdFile`, `mount` (default `approle`) | `auth/<mount>/login`; for CI/VMs outside the cluster |
| `jwt` | `role`, `jwtFile`, `mount` (default `jwt`) | `auth/<mount>/login`; e.g. CI ID tokens (GitLab `id_tokens`, GitHub OIDC) outside the cluster |

Login happens only on first access; the token lives only in the memory of the run and is
not renewed (runs are short; choose the role's TTL accordingly). Tokens appear only in the
`X-Vault-Token` header, never in URLs, logs or error messages.

## States: present / absent / unknown / conflict

| Observation | State |
|---|---|
| `GET <mount>/metadata/<path>` = 200, current version neither deleted nor destroyed | `present` |
| Metadata 404, `sys/internal/ui/mounts/<mount>` confirms KV v2 **and** `sys/capabilities-self` confirms `read` on `<mount>/metadata/<path>` **and** `<mount>/data/<path>` | `absent` |
| Metadata 404 on a KV v1 mount or mount type cannot be determined | `unknown` |
| Metadata 404 without confirmed read permission on both paths | `unknown` |
| 403, 401, 5xx, timeout, network/TLS error | `unknown` |
| Metadata 200, current version deleted (`deletion_time`) or destroyed | `conflict` |

A permission error never results in `absent`. With `unknown`, the engine blocks creating the
user and touches neither the secret nor the password.

**Deleted current version:** the value is gone, `cas=0` would fail, and re-creating it with a
higher version would silently overwrite the history. Ordivus therefore reports the
credential op as `BLOCKED` ("manual action required", `apply` ends with exit code 11) and
writes a warning to the log. Resolve it manually: restore the version
(`undelete`) or deliberately delete the metadata (`DELETE <mount>/metadata/<path>`);
the next run then detects `absent`.

## Generation: create-if-absent with CAS

Only `apply` writes (`plan`/`drift` do not even generate a value). Writes use
`POST <mount>/data/<path>` with `options.cas = 0`: OpenBao accepts this only if the path has no
version yet. On a CAS conflict (a parallel run was faster), Ordivus reads the
existing value and uses it – an existing secret is **never** overwritten.

## Required OpenBao policies

Read-only identity (`plan`/`drift`; `passwordPolicy: verify` needs the value):

```hcl
path "secret/metadata/tenants/acme/*" { capabilities = ["read"] }
path "secret/data/tenants/acme/*"     { capabilities = ["read"] }
```

Apply identity (additionally create; no `update`, no `delete` needed):

```hcl
path "secret/metadata/tenants/acme/*" { capabilities = ["read"] }
path "secret/data/tenants/acme/*"     { capabilities = ["read", "create"] }
```

`sys/capabilities-self` is allowed by the built-in `default` policy; if you issue tokens without
`default`, you must add `path "sys/capabilities-self" { capabilities = ["update"] }` –
otherwise every missing secret stays `unknown`.

## Limitations

- KV v2 only, field `password` only, no multi-field documents.
- No token renewal, no lease handling.
- No retry; network errors are `unknown` or abort the target.
- The reason for `unknown`/`conflict` is shown as `reason` on the credential op in the report.
