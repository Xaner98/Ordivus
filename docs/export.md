# Exporting existing systems (`ordivus export`)

`ordivus export` reads the live state of your targets and writes it as Ordivus configuration. Use it to onboard systems that already exist: export once, review the result, commit it, and from then on manage the objects with `plan`/`apply`.

```sh
ordivus export -f ./targets                          # all targets, all kinds, YAML to stdout
ordivus export -f ./targets --target prod-pg -o prod-pg.yaml
ordivus export -f ./targets --kind DatabaseUser --kind Grant
```

| Option | Meaning |
|---|---|
| `-f`, `--file` | Configuration file or directory with the `Target`, `CredentialProvider` and `Credential` documents used to connect (same loading and validation as `plan`; resource documents in it are allowed and ignored) |
| `--target NAME` | Only this target (repeatable; default: all) |
| `--kind KIND` | Only this resource kind (repeatable; default: all kinds of each adapter) |
| `-o`, `--output FILE` | Write the configuration to `FILE` (created with permissions `0600`, same rules as the report file) instead of stdout |
| `--policy FILE` | Operator policy; `allowTargets`, `requireTls` and `profile` are checked before the first connection, as for `plan` |

The YAML goes to stdout (or `--output`); warnings and a one-line summary go to stderr.

## Read-only

`export` behaves exactly like `plan`: it opens the same read-only sessions, never writes to a target, and never reads or writes secret stores except for the admin credentials of the targets themselves. It respects each target's `spec.scope`, and objects matched by the `exclusions` of a `ReconciliationPolicy` in the given configuration are left out (they would be `IGNORE` in a plan anyway).

## Output

- One multi-document YAML stream with one document per discovered object, in the same shape the configuration loader accepts: `apiVersion`, `kind`, `metadata.name`, `spec.targetRef` plus the adapter's fields.
- `metadata.name` is the object's resource ID as shown in reports (e.g. `app@%` for a MySQL account, `orders.app` for a MongoDB user, a JSON key for a PostgreSQL grant). You may rename documents afterwards as long as the spec still names the object (for kinds where the name comes from `metadata.name`, add `spec.name` first, see the adapter page).
- Deterministic: targets by name, then in the adapter's kind order, then by ID; keys are sorted. Re-exporting an unchanged system gives an identical file, so it diffs cleanly in git.
- Strings that a YAML 1.1 reader or the YAML 1.2 core schema would read as something else (`no`, `on`, `0777`, `1e3`, `0o17`, `~`, …) are quoted, so the file means the same to every common YAML tool. Multi-line text (e.g. OpenBao policies) is written as a literal block.
- Engine documents (`Target`, `Credential`, …) are not part of the output; keep using your existing ones.

## What is left out

- **System and protected objects** (built-in roles and databases, the Ordivus login and its roles, protected policies, the `master` realm, …): the same objects a plan would report as `IGNORE` or `BLOCKED` are skipped. Protected ones are listed on stderr.
- **Objects the adapter cannot manage** (e.g. ClickHouse users from `users.xml`, MySQL wildcard database grants, Keycloak non-OIDC clients) are skipped with a warning.
- **Objects that cannot be expressed exactly** are skipped with a warning naming the reason. Before writing a document, `export` runs it through the adapter's own validation and normalization and compares the result with the object it read. A document that would not plan as `NOOP` is never written, because applying it would change the object.

Objects with privileged permissions (see `allowPrivilegedGrants` in each adapter page) are exported, with a warning on stderr: `plan`/`apply` will report them as `BLOCKED` unless the operator policy allows privileged grants.

## Credentials and passwords

`export` never writes passwords, password hashes, client secrets or SCRAM details, and it never writes `spec.credentials`. For every object of a kind that can carry a password (`DatabaseUser`, `MessagingUser`, `KafkaUser`, `KeycloakClient`, …) stderr says:

```
WARNING: target prod-pg: DatabaseUser 'app': password not exported; add spec.credentials.credentialRef to manage it
```

Why no placeholder `credentialRef`: a reference to a secret that does not exist yet means "create a new secret and set it on the user" (`CREATE_SECRET` + `SET_PASSWORD`). A placeholder that someone wires to a real secret store would therefore reset the existing password on the next `apply`. Without `spec.credentials`, Ordivus does not manage the password at all, which cannot break a running application.

To manage a password after the export, store the **current** password in the secret store first, then add `credentials: {credentialRef: <name>, passwordPolicy: verify}`; `plan` then confirms it with a login (`NOOP`) instead of resetting it.

**MongoDB:** MongoDB users cannot exist without a password, so the configuration loader requires `spec.credentials` on every `DatabaseUser`. An exported MongoDB configuration therefore fails validation (exit code 12) until you add credentials as described above. That is intentional: it forces a decision instead of guessing.

## Incomplete exports and exit codes

`export` exports everything it can see and never pretends completeness. If a target cannot be reached, a kind's discovery is `partial`, `forbidden` or `unknown`, an object cannot be expressed, or the same kind and name was found on two exported targets (export them separately in that case), stderr shows a warning and the command exits with **13**. The output still contains every object that could be exported.

| Code | Meaning |
|---:|---|
| 0 | Complete export |
| 11 | Operator policy refused a target (before any connection) |
| 12 | Configuration error, unknown `--target` or `--kind` |
| 13 | Export incomplete (see warnings on stderr) |

## Limitations

- ClickHouse users with `HOST REGEXP` or `HOST LIKE` restrictions are skipped (not expressible in `DatabaseUser`).
- Redis users with selectors are skipped (selectors are not supported, see the Redis page).
- PostgreSQL superusers and the Ordivus login are not manageable and therefore skipped.
- Fields an adapter does not model (e.g. Kafka SCRAM mechanisms, MongoDB `mechanisms`) are not part of the output.
- OpenBao policies are exported as `policy` text, not as structured `rules`.
