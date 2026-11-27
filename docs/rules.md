# Rules

Drift answers "does reality deviate from the configuration?". Rules answer a second question: **"does reality violate a rule?"** Ordivus evaluates built-in compliance rules against the **observed state** of a target – every object the adapter discovers, whether it is declared in the configuration or not. Together with the inventory of all targets this gives a cross-system view of who has which access.

Rules are simple, built-in checks with a stable id. There is no rule language, no OPA and no user code. Rules are **off** unless a `Rules` document configures them.

## Configuration

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Rules
metadata:
  name: access-compliance
spec:
  targetRef: analytics-postgres   # optional
  rules:
    - id: postgresql.superuser-login
      allow: [postgres]
    - id: postgresql.table-write-grant
      allow: [etl_writer]
    - id: postgresql.createrole-login
      enabled: false
```

| Field | Meaning |
|---|---|
| `spec.targetRef` | Optional. Only this target. Without it, each rule applies to **every** target whose adapter matches the rule id prefix (`postgresql.*` → all `postgresql` targets). |
| `spec.rules[].id` | Rule id from the list below. |
| `spec.rules[].enabled` | Optional boolean, default `true`. |
| `spec.rules[].allow` | Optional list of accepted names (exact match); what is compared is stated per rule. |

Configuration errors (exit code 12, with file and line): unknown rule id, unknown field, wrong types, a `targetRef` that does not exist, a rule whose adapter does not match the referenced target, and the same rule configured more than once for a target (also across several `Rules` documents, also with `enabled: false`). There may be several `Rules` documents.

## Rule list

| Id | Kind read | Severity | Violation | `allow` matches |
|---|---|---|---|---|
| `postgresql.superuser-login` | `DatabaseUser` | critical | A login role has `SUPERUSER`. | role name |
| `postgresql.createrole-login` | `DatabaseUser` | high | A login role has `CREATEROLE`. | role name |
| `postgresql.table-write-grant` | `Grant` | high | A role holds `INSERT`, `UPDATE`, `DELETE` or `TRUNCATE` on all tables of a schema (`on: tables-in-schema`). | grantee |
| `openbao.sudo-capability` | `OpenBaoPolicy` | high | An ACL policy grants `sudo` on any path. | policy name |
| `openbao.wildcard-write` | `OpenBaoPolicy` | critical | An ACL policy grants `create`, `update`, `patch`, `delete` or `sudo` on a wildcard path that covers the whole namespace or all of `sys/` (`*`, `+/*`, `sys/*`, `s*`, a leading `{{template}}` …). | policy name |

Notes:

- PostgreSQL rules see what the adapter discovers: the target `scope` (`roles`, `databases`) limits them like the inventory. Roles that are not login roles are `DatabaseRole`, not `DatabaseUser`, and are not checked by the login rules. Privileges inherited through role membership are not followed; `postgresql.table-write-grant` checks direct grants only, and the adapter reports a `tables-in-schema` grant only when the role holds the privilege on every table of the schema (grants on single tables are not inventoried).
- System objects are checked too (e.g. the bootstrap superuser `postgres` or Ordivus's own login). Accept them explicitly with `allow`.
- The built-in OpenBao `root` policy has no policy text and is never reported; the built-in `default` policy does not violate either rule.

Example for OpenBao:

```yaml
kind: Rules
metadata:
  name: vault-compliance
spec:
  rules:
    - id: openbao.sudo-capability
      allow: [platform-admin]
    - id: openbao.wildcard-write
```

## Evaluation

- `plan` and `drift` evaluate rules on the discovery they already perform: no extra queries and no writes.
- `apply` evaluates rules on the state observed **before** its changes (the same discovery the plan is built from). Run `drift` afterwards to check the result.
- Every configured rule appears in the report's `rules` list once per target, with `status` `complete` or `incomplete`, the number of `violations`, and a `reason` if incomplete.

```json
"rules": [{"rule": "postgresql.superuser-login", "target": "analytics-postgres", "status": "complete", "violations": 1}],
"violations": [{"rule": "postgresql.superuser-login", "target": "analytics-postgres", "kind": "DatabaseUser",
                "id": "ops_admin", "severity": "critical", "message": "login role has SUPERUSER"}]
```

The human format lists violations per target as `VIOLATION [severity] <rule> <kind>/<id>: <message>` and unevaluated rules as `RULE <rule> not fully evaluated: <reason>`; the summary line shows `violations=<n>`. Messages contain only object names and privileges, never secrets.

## Unknown stays unknown

A rule is `incomplete` – never "no violations" – when:

- the discovery of the kind it reads is `partial`, `forbidden`, `unknown` or `unsupported` (violations found in the visible part are still reported),
- an object cannot be checked safely (an OpenBao policy whose text is not plain `path "…" { capabilities = [...] }` blocks),
- the target could not be read at all (`target error`) or was not run (`target skipped`).

## Exit codes

Violations do not change the exit code by default. With `--fail-on violations` (`plan` and `drift`), the run exits with **10** if there is at least one violation **or** at least one configured rule is `incomplete` – a gate must not pass when compliance could not be shown. `drift --fail-on any` includes this. Higher exit codes (13 target error, 14 partial execution …) take precedence as usual.
