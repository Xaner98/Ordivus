# PostgreSQL adapter

Manages roles, users, databases and a robust subset of grants in PostgreSQL.
Installation: `pip install 'ordivus[postgresql]'` (psycopg ≥ 3.2).

**Supported versions:** PostgreSQL 13 and later; tested with PostgreSQL 17. Ordivus reads the
server version when connecting and refuses older servers before discovery
(`PostgreSQL 12.5 is not supported (minimum PostgreSQL 13)`, exit code 13). The version appears as
`serverVersion` of the target in the report.

Kinds in execution order: `DatabaseRole`, `DatabaseUser`, `Database`, `Grant`. Deletions
run in reverse (grants, then databases, then users and roles). Roles come before databases
because `CREATE DATABASE … OWNER` already needs the role. Within that, the order follows
`memberOf`: a parent role (including a `DatabaseUser`) is created before its members and deleted
after them. Cyclic memberships become `BLOCKED`.

Complete example: [`examples/postgresql/`](../../examples/postgresql/ordivus.yaml).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: analytics-postgres
spec:
  adapter: postgresql
  endpoint:
    host: postgres.data-platform.svc.cluster.local
    port: 5432               # Default 5432
    database: postgres       # Connection database, default "postgres"
    user: ordivus_admin      # Required: role Ordivus logs in as
    tls:
      mode: verify-full      # disable | allow | prefer (libpq default) | require | verify-ca | verify-full
      caFile: /trust/ca.pem  # → sslrootcert
  authentication:
    credentialRef: postgres-admin   # Password of endpoint.user
  scope:
    databases:
      include: ["analytics", "reporting_*"]   # Globs; if omitted: all databases
    roles:
      include: ["analytics_*"]                # applies to DatabaseRole, DatabaseUser and grant recipients
```

For production, use `tls.mode: verify-full` with a `caFile` from the runtime environment: a
redirected host then fails on the certificate before the password is sent. Any mode other
than `verify-full` (including the default `prefer`) counts as an insecure connection: warning and
`insecureTransport: true` in the report, abort with operator policy `requireTls: true` (exit code 11).
`verify-ca` also counts as insecure: it checks the CA but not the hostname, so it accepts any
certificate from the same CA (e.g. that of another server).

## Kind `DatabaseRole` and `DatabaseUser`

In PostgreSQL, users and roles are the same object. `DatabaseUser` is a role **with**
`LOGIN`, `DatabaseRole` a role **without** `LOGIN`. Discovery assigns each role to exactly one kind based on
`rolcanlogin`. Declaring the same name in both kinds is an error
(see [Limitations](#limitations)).

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata:
  name: analytics-app
spec:
  targetRef: analytics-postgres
  name: analytics_app            # optional, default metadata.name
  memberOf: [analytics_readonly] # Memberships (exactly this set)
  connectionLimit: 20            # -1 = unlimited
  createdb: false
  createrole: false
  credentials:                   # DatabaseUser only
    credentialRef: analytics-app-password
    passwordPolicy: verify       # verify (default) | enforce | set-on-create
```

| Field | Meaning |
|---|---|
| `name` | Role name, max. 63 bytes, any characters. Default `metadata.name` |
| `memberOf` | List of roles; Ordivus grants and revokes memberships until exactly this set exists |
| `connectionLimit` | `CONNECTION LIMIT`, integer ≥ -1 |
| `createdb`, `createrole` | `CREATEDB`/`NOCREATEDB`, `CREATEROLE`/`NOCREATEROLE` |
| `superuser` | **not manageable** – specifying it is a validation error; it is observed and checked by [rules](../rules.md) |

Fields you omit are not managed, and therefore not reset either.

### Privileged permissions (`allowPrivilegedGrants`)

Without operator policy `allowPrivilegedGrants: true`, a role or user becomes `BLOCKED`
(exit code 11 in `apply`) if the declaration grants any of the following permissions:

- `createrole: true`,
- `memberOf` a predefined `pg_*` role (e.g. `pg_execute_server_program`,
  `pg_read_server_files`, `pg_write_server_files`, `pg_read_all_data`),
- `memberOf` a role that, itself or through its own memberships (transitively), has
  `SUPERUSER`, `CREATEROLE`, `REPLICATION` or `BYPASSRLS`, is in a `pg_*` role, or
  has `LOGIN` (membership in another user account inherits its permissions and objects).

Grants (kind `Grant`) are `BLOCKED` without approval if they allow the recipient to have code executed under
another identity:

- `TRIGGER` on `tables-in-schema`: a trigger runs as the user who writes to the table.
  If a superuser (or a maintenance job) writes to the table, it executes the recipient's code with
  superuser permissions.
- `MAINTAIN` on `tables-in-schema` (PostgreSQL 17): `VACUUM`/`ANALYZE`/`REINDEX`/`REFRESH` evaluate
  index and function expressions triggered by other roles.
- `CREATE` on `schema`: the recipient can create functions, operators or tables that are found in
  other roles' `search_path` (such as `public`) before the intended objects.
- `CREATE` on `database`: the recipient can create a schema named after another role;
  because of `"$user"` at the start of the default `search_path`, it comes first for that role (same effect).

**Always** `BLOCKED`, even with approval: `memberOf` that (transitively) grants the role of the Ordivus login
(`endpoint.user`) or the bootstrap superuser (OID 10, usually `postgres`), and – once
`spec.scope.roles` is set – `memberOf` a role outside this scope (including `pg_*`). The check runs against
the live state of the roles at run time; a parent role that does not exist yet is checked at its own
declaration.

`spec.name` is required when several targets have roles with the same name, because `metadata.name` must be
unique per kind across the whole configuration.

### Passwords

Passwords are converted **client-side** into a SCRAM-SHA-256 verifier
(`PQencryptPasswordConn`); the plaintext reaches neither the server nor its statement log.
`passwordPolicy: verify` checks by attempting a login as the user against `endpoint.host` and
`endpoint.database`:

- Login succeeds → password matches.
- Server reports `password authentication failed` (SQLSTATE 28P01) → `SET_PASSWORD`.
- Anything else (no `pg_hba.conf` entry, no `CONNECT` permission, network) → `unknown`, nothing is changed.

Because libpq returns no SQLSTATE on connection errors, Ordivus detects 28P01 from the server text. If the
server's `lc_messages` is not English, the result is always `unknown` (safe, but without
password drift detection); in that case use `enforce` or set `lc_messages = 'C'`. Every
failed attempt appears in the server log as a failed login.

## Kind `Database`

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Database
metadata:
  name: analytics
spec:
  targetRef: analytics-postgres
  owner: analytics_app   # ALTER DATABASE … OWNER TO
  encoding: UTF8         # only on creation (TEMPLATE template0)
```

| Field | Meaning |
|---|---|
| `name` | Database name, default `metadata.name` |
| `owner` | Owner role; changes are applied via `ALTER DATABASE … OWNER TO` |
| `encoding` | Only on `CREATE`. Use the name PostgreSQL reports (e.g. `UTF8`, `LATIN1`); a mismatch on an existing database is an error, not a re-creation |

`DELETE` of a database is a plain `DROP DATABASE` without `FORCE`: Ordivus first closes its own
connections to that database; any other existing connections make the operation fail.

## Kind `Grant`

A grant is the triple *recipient × object × privileges*. The natural key is
`[grantee, database, on, schema]` (as JSON, e.g. `["analytics_readonly","analytics","schema","public"]`);
`metadata.name` can be chosen freely.

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Grant
metadata:
  name: analytics-readonly-tables
spec:
  targetRef: analytics-postgres
  grantee: analytics_readonly
  database: analytics
  on: tables-in-schema       # database | schema | tables-in-schema
  schema: public             # Required except for on: database
  privileges: [SELECT]
```

| `on` | Object | allowed `privileges` |
|---|---|---|
| `database` | the database `database` | `CONNECT`, `CREATE`, `TEMPORARY` (`TEMP`) |
| `schema` | schema `schema` in `database` | `CREATE`, `USAGE` |
| `tables-in-schema` | all tables, views, materialized views, foreign tables in `schema` | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, `MAINTAIN` (PG 17+; `BLOCKED` on older servers) |

Semantics:

- `privileges` is **exactly** the set the recipient has on the object: Ordivus grants
  missing privileges and revokes undeclared privileges on this object. Case-insensitive.
- `tables-in-schema`: a privilege counts as present if the recipient has it on **every** table in the
  schema (as the owner of a table, it counts as authorized there). New tables created after the run
  show up as drift on the next run; `ALTER DEFAULT PRIVILEGES` is not managed. A recipient that holds
  privileges only on some tables of a schema (single-table grants) has no `tables-in-schema` grant
  there: it is neither reported nor ever deleted.
- `DELETE` of a grant revokes exactly the observed privileges on the object (for `tables-in-schema`:
  those held on every table); single-table grants of other privileges stay.
- Not supported: `ALL`, `WITH GRANT OPTION`, grants to `PUBLIC`, column, sequence, function
  and single-table grants, default privileges.
- Grants on system schemas (`pg_catalog`, `information_schema`, all `pg_*`) are a
  validation error: discovery does not see these schemas, so such grants would be invisible.

## Discovery and scope

- Roles and databases come from `pg_roles` and `pg_database` (readable by any login role).
- Grants live per database. Ordivus opens a separate connection for **every** database in scope
  (`datallowconn`, no templates): read-only in `plan`/`drift`; in `apply` the same connection serves
  discovery and writes. At most 8 stay open per run (the least recently used one is closed). If one of
  them fails (e.g. missing `CONNECT`), the inventory for `Grant` is `partial` with a reason and a
  warning naming the database is logged; declared grants then become `UNKNOWN`, never `CREATE`, and
  nothing is deleted.
- The target's `spec.scope` limits what Ordivus sees at all. Objects outside it do not appear
  in the report and cannot be deleted. A declared grant on a database outside the
  scope fails in `apply`. What may be deleted in authoritative mode is additionally governed by
  the `ReconciliationPolicy` (`scope.resourceKinds`, `scope.<Kind>.glob/exact`).
- `plan`/`drift` connect with `default_transaction_read_only=on`; in addition, the
  adapter refuses any operation on a read-only session.
- `apply` holds a `pg_try_advisory_lock` with a fixed key (derived from
  "ordivus") in `endpoint.database` for the duration of the run. If it is taken, the second run aborts with a transient
  error instead of waiting.

## Protected system objects

Never deleted or changed; undeclared ones are counted as `IGNORE`:

- roles with prefix `pg_` and the bootstrap superuser (OID 10, usually `postgres`),
- the databases `postgres`, `template0`, `template1`,
- roles the Ordivus login is a member of (transitively), including the grants to them and to the
  login itself: revoking or deleting them would lock Ordivus out. On PostgreSQL 16+ only memberships
  with `INHERIT` or `SET` count; the `ADMIN`-only membership PostgreSQL gives a `CREATEROLE` login
  in every role it creates does not protect that role,
- grants to these roles and the implicit permissions of the object owner.

Not manageable (`manageable: false`, never deleted, changes `BLOCKED`): superuser roles and the
role Ordivus is logged in as (`endpoint.user`).

## Required permissions

**Read-only identity (`plan`/`drift`):** `LOGIN` and `CONNECT` on every database in scope
(by default via `PUBLIC`). No further permissions are needed. For `passwordPolicy: verify`,
Ordivus must additionally be allowed to log in to `endpoint.database` as each managed user
(`pg_hba.conf`, `CONNECT`).

**Apply identity:** `CREATEROLE` (in PG 16+ additionally `ADMIN OPTION` on roles whose memberships
are granted, or the role created them itself), `CREATEDB`, membership in the
owner roles for `CREATE DATABASE … OWNER`/`ALTER … OWNER TO`, and for grants the right to pass on the
privileges (owner of the objects or `WITH GRANT OPTION`). A superuser can do everything
but is not required; on managed services (RDS, Cloud SQL) use the admin role provided there. A
non-superuser `CREATEROLE` login is supported, including on PostgreSQL 16+ where it becomes an
`ADMIN`-only member of the roles it creates.

## Limitations

- The same name as both `DatabaseRole` and `DatabaseUser` is a configuration error (exit code 12),
  already during `config validate`.
- `REVOKE` only revokes permissions that the apply identity granted itself. Permissions granted by other roles
  remain; the operation is then reported as `unverified`.
- `tables-in-schema` on a schema **without tables** is not observable and stays `CREATE` on every
  run (the `GRANT` itself has no effect then).
- `DROP ROLE` fails if the role still owns objects or holds permissions; Ordivus does not run
  `REASSIGN OWNED`/`DROP OWNED`.
- Identifiers longer than 63 bytes are a validation error (PostgreSQL would silently truncate them).
