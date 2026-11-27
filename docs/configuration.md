# Configuration

An Ordivus configuration is a file or a directory of YAML or JSON files (`*.yaml`, `*.yml`, `*.json`, recursive). Files and directories whose name starts with `.` are skipped (e.g. `..data` in ConfigMap mounts). Each file may contain multiple documents, separated by `---`. Every document has the same outer shape:

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: <Kind>
metadata:
  name: <unique name per kind>
spec:
  ...
```

Unknown fields are errors, not silently ignored. Error messages name the file and line. Adapters also validate across documents per target (e.g. the same name as `DatabaseRole` and `DatabaseUser`); such errors point to the location of the target document.

Validate without connecting to a target system:

```sh
ordivus config validate -f ./config
```

The output contains the count per kind and a `configDigest` (SHA-256 over the canonical content). The digest is independent of how files are split and of key order, and is suitable for proving in an audit which configuration a run used.

## YAML specifics

Ordivus reads YAML with the semantics of the **YAML 1.2 core schema**:

- `no`, `yes`, `on`, `off`, `y`, `n` stay strings (in YAML 1.1 they would be booleans). A user named `no` therefore stays `no`.
- Only `true`/`false` are booleans, only `null`/`~`/empty is null.
- `0777` is the number 777; octal is written `0o777`. Dates and values like `1:30` stay strings.
- **Anchors and aliases (`&`, `*`) are not allowed**, and neither are duplicate keys. Maximum file size: 1 MiB; only regular files are read.
- Only JSON-compatible values: keys must be strings; tags such as `!!timestamp`, `!!set`, `!!binary`, `!!omap` or `!!pairs` are configuration errors (exit code 12) with file and line, as are structures nested too deeply.

## Engine kinds

### Target – a target system

```yaml
kind: Target
metadata:
  name: analytics-postgres
spec:
  adapter: postgresql             # which adapter
  authentication:
    credentialRef: postgres-admin # admin credential (see Credential)
  # all other fields (endpoint, tls, scope …) are adapter-specific,
  # see docs/adapters/<adapter>.md
```

### CredentialProvider – where secrets come from

```yaml
kind: CredentialProvider
metadata:
  name: local-secrets
spec:
  type: file
  directory: /var/run/secrets/ordivus   # one file per secret
```

| `type` | Purpose |
|---|---|
| `file` | One file per secret in `directory`. Fits mounted Kubernetes Secrets and files provided by a CI pipeline. New secrets are created atomically (temp file, `fsync`, then linked under the target name) with permissions `0600`. Symlinks are followed only if they point to a regular file; a broken symlink or a special file counts as `unknown`, never as missing. |
| `openbao-kv-v2` | OpenBao (or Vault-compatible) KV v2, see [credentials/openbao.md](credentials/openbao.md). |
| `env` | Environment variables, **only in the `development` profile**, read-only. |

### Credential – a single secret

```yaml
kind: Credential
metadata:
  name: reporting-password
spec:
  providerRef: local-secrets
  path: reporting-password        # file: file name; openbao: KV path; env: variable name
  lifecycle:
    generator:                    # optional, only for newly generated passwords
      length: 40                  # 16 to 1024, default 32
      alphabet: alphanumeric      # or alphanumeric-symbol-safe
```

### Resources

Resource kinds (`Database`, `DatabaseUser`, `DatabaseRole`, `Grant`, `OpenBaoPolicy` …) come from the adapters. Common to all of them:

```yaml
kind: DatabaseUser
metadata:
  name: reporting-reader
spec:
  targetRef: analytics-postgres   # required
  credentials:                    # only for kinds with a password
    credentialRef: reporting-password
    passwordPolicy: verify        # verify (default) | enforce | set-on-create
  # further fields: see docs/adapters/<adapter>.md
```

| `passwordPolicy` | Behavior |
|---|---|
| `verify` | On every run, check whether the password is still correct on the target system; if it differs, `apply` resets it. |
| `enforce` | `apply` sets the password on every run without checking. |
| `set-on-create` | Set only on creation, never touch it afterwards. |

In all three cases: if the secret is missing in the provider, `apply` generates a new one and sets it on the user.

### ReconciliationPolicy – mode, scope, exclusions per target

```yaml
kind: ReconciliationPolicy
metadata:
  name: analytics-governance
spec:
  targetRef: analytics-postgres
  mode: authoritative             # additive (default) | authoritative
  scope:
    resourceKinds: [DatabaseUser, DatabaseRole]   # required for authoritative
    DatabaseUser:
      glob: ["app_*"]             # only these users belong to Ordivus
  exclusions:
    DatabaseUser:
      exact: [app_legacy]
      glob: ["app_tmp_*"]
```

- At most one ReconciliationPolicy per target.
- Undeclared objects **outside** the scope stay `UNMANAGED`, inside it they become `UNDESIRABLE`.
- `authoritative` takes effect only if the operator policy permits it; deletion happens only with `allowDelete: true`.

### Rules – compliance checks against the live state

```yaml
kind: Rules
metadata:
  name: access-compliance
spec:
  targetRef: analytics-postgres   # optional; without it: every target of the rule's adapter
  rules:
    - id: postgresql.superuser-login
      allow: [postgres]           # accepted names, exact match
    - id: postgresql.createrole-login
      enabled: false              # optional, default true
```

Built-in rules evaluated against **everything discovered** on a target, declared or not, in `plan`, `drift` and `apply`. Rules are off unless configured. Results go into `rules` and `violations` in the report; they do not change the exit code unless `--fail-on violations` is set. See [Rules](rules.md) for the rule list and evaluation semantics.

## Operator policy

The operator policy is **not** a resource of the configuration but a separate file that is managed separately and passed with `--policy` – typically from another repository or a protected volume.

```yaml
allowTargets: ["*"]          # or a list of target names
allowAuthoritative: false
allowDelete: false
allowPasswordReset: true
allowPrivilegedGrants: false # true: allow privileged permissions (superuser roles, user management …)
profile: standard            # standard | development
requireTls: false            # true: refuse targets without TLS or without certificate verification
```

`allowPrivilegedGrants`: the configuration may not grant more permissions than the operator permits. Without this approval, declared resources that would grant privileged permissions become `BLOCKED` (exit code 11 for `apply`; the remaining operations run). Each adapter defines what counts as privileged (e.g. membership in superuser or `pg_*` roles, `CREATE USER`, `SUPER`, `ACCESS MANAGEMENT`, `+@admin`, group `admin`); the lists are in the respective [adapter documentation](adapters/). Protected system objects, Ordivus's own admin login and its roles stay untouchable even with `true`.

`requireTls`: the adapter defines what counts as insecure (plain text, TLS off, no certificate or hostname verification; for PostgreSQL and MySQL everything except `verify-full`). With `true`, the run aborts before the first connection with exit code 11; with `false`, there is a warning on stderr and `"insecureTransport": true` on the target in the report.

Without `--policy`, exactly these values apply. A policy file that is specified but missing or invalid aborts the run (exit code 11).

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Successful, thresholds met |
| 1 | Internal error (bug, please report) |
| 2 | Invalid invocation (arguments) |
| 10 | Drift/change threshold exceeded (`--fail-on`) |
| 11 | Policy violation or disallowed operation; for `apply` also any `BLOCKED` operation (the others still run) |
| 12 | Configuration error |
| 13 | Target system, credential or network unavailable; for `apply` also when a declared resource could not be verified (target status `incomplete`) |
| 14 | Partially executed or not confirmed after `apply` – please check (also: target aborted after first changes, or an operation skipped with status `conflict`; target status `partial`) |
| 130 / 143 | Aborted (SIGINT / SIGTERM) |

Thresholds: `ordivus plan --fail-on changes|violations`, `ordivus drift --fail-on actionable|unmanaged|unknown|violations|any`. `unknown` triggers as soon as something could not be determined (`UNKNOWN` operations or target status `incomplete`); `any` includes it. `violations` triggers on any rule violation and on any configured rule that could not be fully evaluated ([Rules](rules.md)); `any` includes it as well. Without `--fail-on`, `plan` and `drift` exit with 0 even if differences were found.

Target status in the report: `in_sync`, `drift_detected`, `incomplete` (inventory incomplete, or a declared resource or its password not verifiable), and for `apply` also `applied`, `partial`, `error` and `skipped` (not run because a target's lock was held by a concurrent `apply`). An `apply` never reports `in_sync` as long as a declared resource is `UNKNOWN`, and in authoritative mode also not as long as the inventory is incomplete (then `incomplete`, exit 13). A remaining `BLOCKED` operation gives `drift_detected` in `apply` just as in `plan`. An unexpected error (e.g. an adapter bug) only marks that target as failed; the remaining targets continue. stderr then shows only the error type; a traceback is shown only with `ORDIVUS_DEBUG=1` (may contain secrets, for debugging only).

## Proxy

The HTTP adapters (OpenBao, ClickHouse, ArcadeDB, RabbitMQ, Keycloak, Grafana) and the credential provider `openbao-kv-v2` honor the environment variables `HTTP_PROXY`/`HTTPS_PROXY` (or lowercase) and `NO_PROXY`. If a target is reached via a proxy, Ordivus writes a warning to stderr once per target (`… is reached via proxy …`). Over `http://`, the proxy sees credentials and tokens in plain text; with `https://` it sees only the destination. Therefore add internal targets to `NO_PROXY`. Database drivers (PostgreSQL, MySQL, Redis) do not use a proxy.

## Report

`--format human` (default) produces readable text. `--format json` writes **JSON Lines**: the report is a line with `"type": "report"`, log events go to stderr. This also lets you filter the report out of merged logs (e.g. `kubectl logs`):

```sh
ordivus drift -f ./config --format json | grep '"type": *"report"' > report.json
```

Operations on non-modifiable or protected objects carry `"manageable": false` or `"system": true`. Passwords appear only as `CREATE_SECRET` and `SET_PASSWORD` (value always `<redacted>`), never among the changes of a `CREATE`. If a credential provider cannot determine the state of a secret, or if a secret is empty, the reason is given as `reason` on the credential operation (`UNKNOWN`, or `BLOCKED` if only manual intervention helps); an empty secret is never set as a password. All text in the report and in the logs is checked against the secrets read during the run and replaced (`<redacted>`).

Report schema version `1.1` added the top-level lists `rules` (per configured rule and target: `status` `complete` or `incomplete`, `violations` count, `reason` if incomplete) and `violations` (`rule`, `target`, `kind`, `id`, `severity`, `message`) plus `summary.violations`; both lists are empty without a `Rules` document. Fields of `1.0` are unchanged.

With `--output FILE`, the report goes to a file (newly created with permissions `0600`; a symlink as the destination is rejected). Ordivus overwrites an existing file only if it is a regular file owned by the calling user; it then also gets `0600`. If writing fails, the error appears on stderr and the run's exit code is preserved (e.g. 14 after a partial `apply`); only an otherwise successful run then exits with 1. Ordivus does not store reports itself; recording them is up to the calling system (CI artifact, log collection).
