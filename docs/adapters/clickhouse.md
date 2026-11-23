# ClickHouse adapter

Adapter ID `clickhouse`. Manages databases, roles, users and grants via **SQL-driven access management** (`CREATE USER`, `GRANT` …) and the ClickHouse HTTP interface. No additional Python dependency.

Kinds in execution order: `Database`, `DatabaseRole`, `DatabaseUser`, `Grant` (deletions in reverse order).

A complete example is in [`examples/clickhouse/`](../../examples/clickhouse/ordivus.yaml).

## Supported versions

- Minimum: **ClickHouse 25.8** (LTS). `connect` reads `version()`; older servers fail with "ClickHouse <v> is not supported (minimum 25.8)" before any discovery. The version appears as `serverVersion` in the report.
- Tested: 25.8 (`clickhouse/clickhouse-server:25.8`). Newer releases are expected to work; the adapter relies only on `system.privileges`, `system.grants`, `system.users`, `system.roles`, `system.role_grants`.

## Target

```yaml
kind: Target
metadata:
  name: analytics-clickhouse
spec:
  adapter: clickhouse
  endpoint:
    host: clickhouse.data-platform.svc.cluster.local
    port: 8443            # Default 8123 (http) or 8443 (with tls)
    user: ordivus         # Default "default"; must not contain ':'
    timeoutSeconds: 30    # Default 30
    tls:                  # present ⇒ https with certificate verification
      caFile: /trust/ca.pem   # optional, otherwise system CAs
  authentication:
    credentialRef: clickhouse-admin   # Password of user endpoint.user
  scope:
    databases:
      include: ["reporting*"]         # Glob; optional
```

- Login via HTTP Basic Auth in the header; SQL is sent only in the POST body, never in the URL.
- `host` is a plain hostname or IP address (no `/`, `@`, `?`, `#`, spaces). Ordivus never follows redirects (the Basic Auth header would otherwise go to the redirect target); a redirect is an error.
- Errors are classified via the `X-ClickHouse-Exception-Code` header: permission/login errors (497, 516, 192) → `AuthorizationError` (kind `forbidden`), timeouts/network/overload → `TransientError`, everything else → `PermanentError`.
- `plan` and `drift` send the setting `readonly=2` with **every** request; ClickHouse then rejects any DDL/DCL (code 164 `READONLY`). In addition, the adapter refuses `apply` on a read-only session.
- Exception: if the login's settings profile already enforces `readonly` ≥ 1 (read via `getSetting('readonly')` on connect), the setting is not sent – ClickHouse rejects any attempt to change `readonly` for such a login, even to the same restriction. The server already blocks writes then. A read-only login is therefore a good choice for `plan`/`drift`-only targets.

## Kind `Database`

```yaml
kind: Database
metadata:
  name: reporting          # Database name
spec:
  targetRef: analytics-clickhouse
  engine: Atomic           # optional, only on creation
```

`engine` is a plain engine name without parameters (`Atomic`, `Memory`, `Lazy` …). A different engine on an existing database appears in the plan as `UPDATE` and fails in `apply` with "engine is create-only"; Ordivus never rebuilds databases. **`DELETE` of a database is `DROP DATABASE` and deletes all tables in it.**

## Kind `DatabaseRole`

```yaml
kind: DatabaseRole
metadata:
  name: reporting_reader
spec:
  targetRef: analytics-clickhouse
```

No further fields. Roles granted to other roles are not modeled.

## Kind `DatabaseUser`

```yaml
kind: DatabaseUser
metadata:
  name: reporting_app
spec:
  targetRef: analytics-clickhouse
  roles: [reporting_reader]          # granted roles (GRANT role TO user)
  defaultRoles: [reporting_reader]   # roles active at login; [] = NONE
  hostIp: ["10.0.0.0/8"]             # HOST IP …
  hostNames: ["app.example"]         # HOST NAME …
  credentials:
    credentialRef: reporting-app-password
    passwordPolicy: verify
```

All fields are optional; fields you omit are not managed (never reset).

- `roles`: changes are applied as `GRANT`/`REVOKE` of the difference.
- `defaultRoles`: the effective set from `system.role_grants.granted_role_is_default` is compared. If omitted, the ClickHouse default `DEFAULT ROLE ALL` applies.
- `hostIp`/`hostNames`: lists, compared sorted. `hostIp` is normalized the way ClickHouse stores it: host bits cleared (`10.0.0.1/8` → `10.0.0.0/8`), no `/32`/`/128` suffix, lowercase IPv6. `::/0` or `0.0.0.0/0` means "from anywhere" (ClickHouse stores `ANY` as `::/0`; such a list is normalized to `["::/0"]`). Loopback addresses (`127.0.0.0/8`, `::1`, `::ffff:127.…`) are rejected: ClickHouse stores them as host name `localhost`, so declare `hostNames: [localhost]`. If either field changes, the entire host list is set anew; undeclared entries (including `REGEXP`/`LIKE`) are preserved. Addresses are checked during validation. If omitted, a new user is created with `HOST ANY`.
- A new user is first created with `HOST NONE` and only enabled afterwards, so it is never briefly reachable from anywhere.

### Passwords

- Passwords are set as `IDENTIFIED WITH sha256_password BY '…'`. Apart from name and password, the statement contains no variable parts: ClickHouse masks passwords in `system.query_log` and in the server log, **unless** a statement already fails during parsing – then it would appear in plaintext in the log.
- `passwordPolicy: verify` checks by attempting a login (`SELECT 1` as this user): error 516 `AUTHENTICATION_FAILED` ⇒ wrong password (`SET_PASSWORD`), success ⇒ matches, anything else ⇒ `UNKNOWN`.
  **Caution:** If the user is restricted via `hostIp`/`hostNames` to addresses Ordivus does not connect from, ClickHouse also reports 516. Then `SET_PASSWORD` would be planned on every run. In that case use `passwordPolicy: set-on-create` or `enforce`.
- A user **without** `spec.credentials` is created with a random password that is stored nowhere (not with `no_password`); it can only log in once someone sets a password.
- User names containing `:` cannot be verified via Basic Auth (`UNKNOWN`).
- **Multiple authentication methods** (ClickHouse 24.9+): `ALTER USER … IDENTIFIED WITH …` replaces *all* methods of a user (further passwords, SSH keys, certificates, LDAP …). `SET_PASSWORD` therefore fails ("would replace all of them, refusing") unless the user has exactly one password method (`sha256_password`, `plaintext_password`, `double_sha1_password`, `bcrypt_password` or `no_password`). `verify` succeeds if *any* method accepts the password.

## Kind `Grant`

```yaml
kind: Grant
metadata:
  name: reporting-reader-select   # free choice, not part of the key
spec:
  targetRef: analytics-clickhouse
  grantee: reporting_reader       # user or role
  database: reporting             # optional; if omitted *.*
  table: events                   # optional, only with database
  privileges: [SELECT, SHOW TABLES]
```

A grant object is the set of privileges of one grantee on exactly one object. The ID in the report is e.g. `` `reporting_reader` ON `reporting`.* ``. If the privileges differ, only the differences are changed via `GRANT`/`REVOKE`.

**Normalization and pitfalls:** ClickHouse stores privileges in its own form (`system.grants`) – groups are expanded, complete groups are collapsed again. Ordivus compares uppercase with single spaces, sorted and without duplicates. To keep the comparison stable:

- Specify privileges the way `SHOW GRANTS` shows them. Declarations ClickHouse would store differently are `BLOCKED` in the plan with the reason, instead of producing a permanent `UPDATE`:
  - aliases (`UPDATE` is stored as `ALTER UPDATE`, `SHUTDOWN` as `SYSTEM SHUTDOWN` …): declare the canonical name from `system.privileges`;
  - a privilege together with its group in the same grant (`ALTER`, `ALTER UPDATE`): ClickHouse keeps only the group;
  - all sub-privileges of a group (e.g. all `ALTER INDEX` children): declare the group.
  Groups that ClickHouse collapses only on certain object levels (e.g. all table-level `ALTER …` on a table) are not detected.
- **Grants covered by a broader grant** are `BLOCKED`: if the grantee holds `SELECT` on `db.*` or `*.*`, ClickHouse stores no separate `SELECT` on `db.t` (granting it is a no-op, `system.grants` never shows it). Ordivus reports this ("already granted … on a broader object") instead of planning `CREATE` on every run; remove the narrower declaration or manage the broader grant. If the grantee has partial revokes on that database or `*.*`, the check is skipped (ClickHouse then shows narrower grants individually).
- When a grant's privileges change, `REVOKE` runs before `GRANT`, so that replacing a group by one of its sub-privileges (`ALTER` → `ALTER UPDATE`) does not revoke the new privilege again.
- `ALL`/`ALL PRIVILEGES`, `NONE`/`USAGE`/`NO PRIVILEGES` and `CURRENT GRANTS` are always rejected during validation: they expand server-side (`CURRENT GRANTS` = all permissions of the Ordivus login, i.e. full access including user management).
- Grants on the system databases `system`, `information_schema` and `INFORMATION_SCHEMA` are always rejected.
- Unknown privilege names (not in `system.privileges`, not even as an alias) are `BLOCKED`.
- Source privileges such as `FILE`, `S3`, `URL` are stored by ClickHouse 25.x as `READ`/`WRITE` on the respective source object; discovery does not model the source object, so such grants end up as `unverified` after creation.
- The adapter does not model column grants (`SELECT(col)`), partial revokes and `WITH GRANT OPTION`. Such entries appear as separate, non-changeable objects (`manageable: false`) with a suffix in the ID, e.g. `(with grant option)`, and are never deleted.
- Privileges a user inherits from roles belong to the role, not to the user.

## Privileged permissions (`allowPrivilegedGrants`)

Without the operator policy `allowPrivilegedGrants: true`, the following declarations are `BLOCKED` (exit 11 in `apply`). The check runs in the plan against the server's `system.privileges`, i.e. aliases (`SHUTDOWN`, `INTROSPECTION FUNCTIONS` …) and all sub-privileges of a group count as well:

- Groups including all sub-privileges: `ACCESS MANAGEMENT` (including `CREATE/ALTER/DROP USER`, `CREATE/ALTER/DROP ROLE`, `ROLE ADMIN`, row policies, quotas, settings profiles, `SHOW ACCESS`), `SYSTEM` (all `SYSTEM …`), `SOURCES`, `READ`/`WRITE` (sources), `INTROSPECTION`, `NAMED COLLECTION ADMIN` (including `SHOW NAMED COLLECTIONS SECRETS`), `displaySecretsInShowAndSelect`, `KILL QUERY`, `KILL TRANSACTION`, `SET DEFINER`, `CLUSTER`, `TABLE ENGINE`, `MOVE PARTITION BETWEEN SHARDS`, `CREATE FUNCTION`, `DROP FUNCTION`.
- Every direct sub-privilege of `ALL` at the global level, i.e. all sources such as `FILE`, `URL`, `REMOTE`, `S3`, `HDFS`, `MYSQL`, `POSTGRES`, `JDBC`, `KAFKA` … (including future ones).
- Every global grant (`*.*`, i.e. without `database`), including `SELECT`.
- `DatabaseUser.roles`/`defaultRoles` with a role that (directly or via other roles) carries a privileged or global grant, a grant on a system database (`system`, `information_schema`/`INFORMATION_SCHEMA`) or `WITH GRANT OPTION`, or that the Ordivus login itself has.

Always blocked, even with `allowPrivilegedGrants`: grants to the Ordivus login and to its roles, unknown privileges and everything outside the scope (see below). The adapter does not model `WITH GRANT OPTION`.

## Discovery and scope

| Kind | Source |
|---|---|
| `Database` | `system.databases` |
| `DatabaseRole` | `system.roles` (`storage`) |
| `DatabaseUser` | `system.users` (`storage`, `host_*`), `system.role_grants` |
| `Grant` | `system.grants` |

`spec.scope.databases.include` (globs) restricts `Database` and database-scoped grants. If a scope is set, global grants (`*.*`) are **not** part of it: they are neither inventoried nor created. Declared databases and grants outside the scope are `BLOCKED` in the plan ("outside spec.scope.databases"), and `apply` itself refuses them as well – otherwise objects would be created that discovery never sees. Users and roles are not bound to a database and are restricted via `ReconciliationPolicy.spec.scope.DatabaseUser`/`DatabaseRole` (exact/glob). If the permissions for a system table are missing, the kind is `forbidden`, never "empty".

## Protected system objects

- Databases `system`, `information_schema`, `INFORMATION_SCHEMA`, `default` are system objects (`IGNORE`, never deleted).
- The user Ordivus is connected as (`currentUser()`), its roles (including transitively via other roles) and their grants are system objects – protection against self-lockout: never revoked, deleted or changed.
- Users and roles from configuration files cannot be changed (see below).

## users.xml management is not recommended

Users, roles and permissions from the server configuration files (`users.xml`, `users.d/`) cannot be changed via SQL. Ordivus **explicitly does not** recommend this kind of management; use SQL-driven access management (`access_management`, storage `local_directory` or `replicated`).

The adapter detects the origin via the `storage` column in `system.users`/`system.roles`. Only `local_directory` and `replicated` count as changeable; everything else (`users_xml` …) gets `manageable: false`:

| Situation | Result |
|---|---|
| not declared, additive | `UNMANAGED` |
| not declared, authoritative in scope | `UNDESIRABLE` ("not manageable by adapter"), **never `DELETE`**, even with `allowDelete` |
| declared | `BLOCKED` ("not manageable by adapter"), never a silent `NOOP` |
| grants of such users/roles | also `manageable: false` |

The engine always reports a declaration of such objects as `BLOCKED`, even if all fields match.

Typical case: the admin created via `CLICKHOUSE_USER` in the official container. For Ordivus, it is better to create a dedicated SQL user (see permissions) and connect as that user.

## Required permissions

The connection user needs:

- Read: `SHOW USERS, SHOW ROLES` (or `SHOW ACCESS`) and access to `system.databases`, `system.users`, `system.roles`, `system.role_grants`, `system.grants`, `system.privileges` (for the permission check in the plan).
- Write: `ACCESS MANAGEMENT` (or `CREATE/ALTER/DROP USER`, `CREATE/DROP ROLE`, `ROLE ADMIN`), `CREATE DATABASE`, `DROP DATABASE` (only for deletions) and every privilege it is to grant, **`WITH GRANT OPTION`**.

Example (as admin with `access_management`):

```sql
CREATE USER ordivus IDENTIFIED WITH sha256_password BY '…';
GRANT CURRENT GRANTS ON *.* TO ordivus WITH GRANT OPTION;
```

## Cluster

`ON CLUSTER` is **not yet** supported. A target is exactly one node. Without `ON CLUSTER`, users created via SQL exist only on that node – unless the cluster uses **replicated access storage** (`user_directories/replicated` via Keeper); then a target on one node affects all of them. Without replicated storage, each node must be configured as its own target; Ordivus currently does not report diverging nodes as cluster drift. Databases are likewise only created on the connected node (or via the `Replicated` database engine).

## Limitations

- No lock during `apply` (ClickHouse has no advisory locks); avoid parallel `apply` runs against the same target.
- Not modeled: settings profiles, quotas, row policies, role-to-role grants, `GRANT OPTION`, column grants, source objects of `READ`/`WRITE`, authentication other than `sha256_password` (LDAP, Kerberos, certificates).
- `Database.engine` without parameters; an engine change is never executed.
- `ordivus export` skips users with `HOST REGEXP`/`HOST LIKE` restrictions (not expressible in `DatabaseUser`).
