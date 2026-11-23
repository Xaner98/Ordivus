# Concepts

Ordivus manages **administrative configuration** in systems you already run: users, roles, permissions, databases and policies in PostgreSQL, MySQL, MariaDB, ClickHouse, MongoDB, ArcadeDB, Redis, Kafka, RabbitMQ, OpenBao, Keycloak, Grafana and other systems. You describe the desired state in YAML files; on every run, Ordivus reads the actual state directly from the target system, shows the differences and applies permitted changes.

## Stateless

Ordivus stores nothing between two runs: no state file, no database of its own, no markers in the target systems. The truth always has two parts:

- **Desired:** your configuration files.
- **Actual:** the target system, read live.

That is why Ordivus also sees objects someone created by hand or with another tool.

## Three commands

| Command | Purpose | Changes anything? |
|---|---|---|
| `ordivus plan` | What would `apply` do right now? | no |
| `ordivus drift` | Does the actual state deviate from the desired state? Are there foreign objects? | no |
| `ordivus apply` | Execute permitted changes and verify them afterwards (one re-read per resource kind after all operations) | yes |

`plan` and `drift` change neither target systems nor secret stores – not even a password generated "just briefly". For real safety, also run these commands with an identity that has read-only access to the target system.

## What happens to undeclared objects

| Situation | Result |
|---|---|
| declared, missing | `CREATE` |
| declared, equal | `NOOP` |
| declared, different | `UPDATE` (only the declared fields) |
| not declared, mode `additive` (default) | `UNMANAGED` – only reported |
| not declared, mode `authoritative` within the scope | `UNDESIRABLE` – deleted only once the operator policy permits deleting |
| excluded or system object | `IGNORE` – only counted; declared system object → `BLOCKED` |
| target system not fully readable | `UNKNOWN` – never delete, never create |
| not modifiable by the adapter (e.g. ClickHouse users from `users.xml`) | `UNMANAGED`, flag `manageable: false`; declared → `BLOCKED` (even without a difference) |

An unset field does **not** mean "reset": only fields you have declared are compared.

## Unknown stays unknown

If read permissions are missing, a query runs into a timeout or a target system returns only part of its objects, Ordivus reports `partial`, `forbidden` or `unknown` – never "empty". All safeguards against wrongful deletion rely on this. Conversely, `apply` reports a target with a declared but unverifiable resource as `incomplete` (exit code 13), never as `in_sync`.

## Passwords

Passwords never appear in the configuration; they live in a **credential provider** (file/mounted Kubernetes Secret, OpenBao KV v2, environment variable for development only).

- If the secret is missing, `apply` generates a cryptographically random password, stores it *create-if-absent* in the provider and sets it on the user. `plan` shows this beforehand as `CREATE_SECRET`.
- The default for existing users is `passwordPolicy: verify`: on every run, Ordivus checks on the target system whether the password is still correct (login attempt or hash comparison, depending on the adapter) and resets it if it differs. If an adapter checks via login attempt, failed attempts count towards the target system's lockout policies; there, `enforce` is the better choice (details per adapter).
- Alternatives: `enforce` (set on every `apply`) and `set-on-create` (only on creation).
- If the state of a secret cannot be determined reliably (e.g. missing read permissions), **no** password is changed.

Secrets never appear in plain text in reports, logs or error messages.

## Two kinds of policies

- **Operator policy** (`--policy file.yaml`): managed separately by your platform or security team. It defines what is permitted at all: which targets, whether `authoritative`, whether deleting, whether password resets and whether the configuration may grant privileged permissions (`allowPrivilegedGrants`, default no). The configuration can never grant more permissions than the operator policy allows.
- **ReconciliationPolicy** (in the configuration): can only *restrict* – mode, scope, exclusions. A `mode: authoritative` in the configuration is a request, not a permission.

## Where Ordivus runs

Anywhere Python and a network connection to the target system are available: on a laptop, in a CI pipeline, on a VM or as a Kubernetes Job. Target systems may be inside or outside a cluster. Running in the cluster is preferred because communication then stays inside the cluster.

Ordivus is not a permanently running service. Your pipeline, your GitOps tool or a CronJob decides when a run starts.

## Concurrent runs

Adapters whose target system offers its own lock (e.g. PostgreSQL advisory locks, MySQL `GET_LOCK`) lock during `apply`. For systems without a locking mechanism, avoid parallel `apply` runs against the same target by organizational means.

Before writing anything, `apply` connects to every target whose adapter supports locking and acquires all locks; each lock is released when its target is done. If any lock is held by another `apply`, no target is written: that target fails with exit code 13, all other targets are reported with target status `skipped` and the reason.

Right before a `DELETE` or `SET_PASSWORD`, `apply` reads the object again. If it no longer matches what the plan saw (gone, now protected, or for `DELETE` changed attributes or an incomplete inventory), the operation is not executed and reported with status `conflict`; the target becomes `partial` (exit code 14). Run `plan` again to see the new state.
