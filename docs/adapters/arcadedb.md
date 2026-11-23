# ArcadeDB adapter (`arcadedb`, beta)

Manages databases and server users of an ArcadeDB instance through the HTTP API
(`/api/v1`). No additional dependency: the adapter uses only the Python standard library.

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: analytics-arcadedb
spec:
  adapter: arcadedb
  endpoint:
    host: arcadedb.data-platform.svc.cluster.local
    port: 2480            # default 2480
    tls:                  # present → https; without tls → http (insecure, see requireTls)
      caFile: /trust/ca.pem   # optional, otherwise system CAs
  username: root          # default root
  authentication:
    credentialRef: arcadedb-root   # password of the admin user
  scope:                  # optional; objects outside are not read/reported
    databases:
      include: ["analytics_*"]
    users:
      include: ["graph_*"]
```

The connection is checked at startup with `GET /api/v1/server?mode=basic` (401/403 → target error,
exit code 13). Authentication uses HTTP Basic Auth; the password never appears in URLs, logs
or error messages.

## Kinds

Creation order: `Database`, then `DatabaseUser`; deletions in reverse.

### `Database`

No fields. The name is `metadata.name` and must match `[A-Za-z0-9_][A-Za-z0-9_-]*` (max. 128 characters),
because ArcadeDB's server commands (`create database <name>`) are free text without quoting.
Other names are rejected during validation; existing databases with other names
are reported but marked as not manageable (never deleted).

```yaml
kind: Database
metadata:
  name: knowledge_graph
spec:
  targetRef: analytics-arcadedb
```

### `DatabaseUser`

| Field | Type | Meaning |
|---|---|---|
| `databases` | Mapping database → list of groups | ArcadeDB's per-database assignment. Groups e.g. `crud`, `readonly`, `admin` or custom groups from `server-groups.json`. `*` (all databases, including future ones) is rejected; with `spec.scope.databases` on the target, every database must be in scope (otherwise config error). |
| `credentials` | Engine field | **Required on creation**: ArcadeDB does not create users without a password (min. 8 characters). |

```yaml
kind: DatabaseUser
metadata:
  name: graph_writer
spec:
  targetRef: analytics-arcadedb
  databases:
    knowledge_graph: [crud]
  credentials:
    credentialRef: graph-writer-password
    passwordPolicy: verify
```

Comparison semantics:

- `databases` missing → the assignment is not managed (neither read nor reset).
- `databases: {}` → the user should not be assigned to any database.
- Group lists are sorted and deduplicated; order is irrelevant.
- `databases` is compared as a whole and, on deviation, replaced completely via `PUT /api/v1/server/users`
  (ArcadeDB does not support partial changes to the assignment).
- User names may contain any printable characters (including quotes, brackets,
  spaces), but must not start with `apitoken:`. Names are only transmitted as a JSON value or
  URL-encoded query parameter.

Passwords:

- Create: `POST /api/v1/server/users` with the password from the credential.
- `SET_PASSWORD`: `PUT /api/v1/server/users?name=…` sets the password in place.
- `verify`: login attempt as the user against `GET /api/v1/server?mode=basic`:
  200 → equal, 401 → different, anything else (e.g. 403, timeout) → `unknown`.
  User names containing `:` cannot be checked via Basic Auth → always `unknown`.

## Discovery

| Kind | Source | Status |
|---|---|---|
| `Database` | `GET /api/v1/databases` | `complete` only with `username: root`; other users see only their databases → `partial` |
| `DatabaseUser` | `GET /api/v1/server/users` (names + database/groups, never password hashes) | `complete`; without root privileges 403 → `forbidden` |

With `partial`/`forbidden` there is neither `CREATE` nor `DELETE` for the respective kind.

## Required privileges

ArcadeDB allows server commands and user management **only for the user `root`**. `apply`
therefore requires `username: root`. With a different user, only a limited
`plan`/`drift` is possible (databases `partial`, users `forbidden`).

## Protected objects

- The user `root` and the user Ordivus connects as are system objects:
  not declared → `IGNORE`; never deleted, never changed. Declared → `BLOCKED`, even if they
  are never discovered because of `scope.users` (otherwise a `CREATE` would overwrite the existing `root`).
- `DELETE` only in `authoritative` mode with operator approval (`allowAuthoritative`, `allowDelete`)
  and complete discovery.

## Privileged grants (`allowPrivilegedGrants`)

Without `allowPrivilegedGrants: true` in the operator policy, a `DatabaseUser` that is to receive the group
**`admin`** in any database is `BLOCKED` (schema, security and configuration of the
database). `root` and Ordivus' own login stay blocked even with approval.

## Read-only guarantee

`plan`/`drift` open read-only sessions. In them, the adapter refuses every HTTP method except `GET`
as well as every `apply` call (`PermanentError`) before a request reaches the network.

## Error mapping

| Cause | Error |
|---|---|
| Timeout, connection error, HTTP 5xx/429 | `TransientError` |
| HTTP 401/403 | `AuthorizationError` |
| other 4xx, invalid JSON, unreadable `caFile` | `PermanentError` |

Idempotency: `create database` for an existing database or `drop database` for a missing one counts
as success after re-reading; deleting a user that does not exist (any more) (404) likewise.

## Limitations

- Users are **server-wide**, not per database; `scope.users` filters by name only.
- Groups (`server-groups.json`) and API tokens are not managed; non-existent group
  or database names in `databases` are accepted by ArcadeDB without error.
- Requires an ArcadeDB version with `/api/v1/server/users` (tested with 26.12); older versions
  return 404 there → discovery error (`unknown`), no changes.
- No locking (`lock`): parallel runs against the same instance are not protected against each other.
- HA cluster: ArcadeDB replicates changes itself; not tested separately.
