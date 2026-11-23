# MySQL adapter

Manages databases, roles, users and grants in **MySQL 8** (tested with MySQL 8.4).
Installation: `pip install 'ordivus[mysql]'` (PyMySQL ≥ 1.1). Complete example: `examples/mysql/`.

Kinds in execution order: `Database`, `DatabaseRole`, `DatabaseUser`, `Grant`
(deletions in reverse order).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: shop-mysql
spec:
  adapter: mysql
  endpoint:
    host: mysql.shop.svc.cluster.local
    port: 3306                 # Default 3306
    user: ordivus_admin        # Account Ordivus logs in as
    tls:
      mode: verify-full        # disable | require | verify-ca | verify-full (default)
      caFile: /trust/ca.pem    # without caFile, the system CAs apply
  authentication:
    credentialRef: mysql-admin # Password of endpoint.user
  scope:                       # optional; without an entry, everything is inventoried
    databases: {include: ["shop", "shop_*"]}
    users:     {include: ["shop_*"]}
    roles:     {include: ["shop_*"]}
```

| TLS mode | Behavior |
|---|---|
| `disable` | no TLS. For local tests only. Without TLS, password verification with `caching_sha2_password` also usually fails (result `unknown`) |
| `require` | TLS, certificate is **not** verified |
| `verify-ca` | Certificate verified against `caFile`, hostname not: any certificate from the same CA is accepted |
| `verify-full` | Certificate and hostname verified (default, recommended) |

Everything except `verify-full` counts as an insecure connection, including `verify-ca`: warning and `insecureTransport: true` in the report, with
operator policy `requireTls: true` abort before connecting (exit code 11).

## Discovery and scope

- `spec.scope` limits the inventory. The globs (`fnmatch`, case-sensitive) apply to the
  database name or the **user name without host**. Ordivus does not see objects outside the scope, so they
  are never deleted either.
- A grant is in scope if its grantee is in the `users` or `roles` scope and (for database/table grants)
  its database is in the `databases` scope.
- The authority scope for `authoritative` mode additionally comes from the `ReconciliationPolicy`
  (`scope.DatabaseUser.glob` etc.). The globs there apply to the resource ID, i.e. `name@host` for accounts and
  `name@host ON <object>` for grants.
- The database list is only `complete` if `endpoint.user` holds the `SHOW DATABASES` privilege **directly**
  (not via a role). Otherwise Ordivus reports `partial`: it then creates no databases and deletes none.

## Kind `Database`

```yaml
kind: Database
metadata:
  name: shop
spec:
  targetRef: shop-mysql
  name: shop                    # optional, default metadata.name (max. 64 characters)
  characterSet: utf8mb4         # optional
  collation: utf8mb4_0900_ai_ci # optional
```

Resource ID: the database name. If you only specify `characterSet`, MySQL sets its
default collation on a change. Ordivus does not manage fields you omit.

## Kind `DatabaseRole`

```yaml
kind: DatabaseRole
metadata:
  name: shop-reader
spec:
  targetRef: shop-mysql
  identity:
    username: shop_reader
    host: "%"            # Default "%"
```

Resource ID: `shop_reader@%`. A role has no further fields. You grant its permissions with `Grant`.

## Kind `DatabaseUser`

```yaml
kind: DatabaseUser
metadata:
  name: shop-app
spec:
  targetRef: shop-mysql
  identity:
    username: shop_app        # max. 32 characters
    host: "10.20.%"           # Default "%"; lowercased
  roles: [shop_reader]        # granted roles; "name" = name@%, otherwise "name@host"
  defaultRoles: [shop_reader] # subset of roles; [] = SET DEFAULT ROLE NONE
  accountLocked: false
  credentials:
    credentialRef: shop-app-password
    passwordPolicy: verify    # verify (default) | enforce | set-on-create
```

Resource ID: `shop_app@10.20.%`. In account names, the **last** `@` separates name and host, so
email addresses also work as user names (`me@example.com@%`).

- `roles` is reconciled exactly: missing roles are granted, undeclared ones revoked.
- Roles in `roles`/`defaultRoles` are checked during planning (see [Privileged permissions](#privileged-permissions-allowprivilegedgrants)):
  system accounts (`root` etc.) and Ordivus's own login are always blocked as roles (`BLOCKED`).
- A user without `credentials` must set `accountLocked: true`. Otherwise MySQL would create it without a password,
  and then anyone could log in without a password. Ordivus rejects this on creation.
- `passwordPolicy: verify` **actually** logs in as the user (see [Password verification](#password-verification-verify)).
  Error 1045 (access denied) only means "wrong password" (→ `SET_PASSWORD`) if the account has host
  `%` and there is no other entry with the same name and no anonymous account (otherwise Ordivus
  does not attempt the login at all). Everything else results in
  `unknown` ("password unverifiable"; in `apply` status `incomplete`, exit 13).

### User or role?

In MySQL, roles are also accounts in `mysql.user`. Ordivus treats an account as a **role** if it is locked
(`account_locked = 'Y'`), its password is marked expired (`password_expired = 'Y'`) and
`authentication_string` is empty. This is exactly how `CREATE ROLE` creates an account. All other accounts are users. If
you declare an account (`name@host`) as both `DatabaseRole` and `DatabaseUser`, that is a
configuration error (exit code 12), already during `config validate`. If a `DatabaseUser` is listed in another
user's `roles`, Ordivus creates it first.

## Kind `Grant`

```yaml
kind: Grant
metadata:
  name: shop-reader-select
spec:
  targetRef: shop-mysql
  grantee: shop_reader         # "name" = name@%, or "name@host"
  on: database                 # global | database | table
  database: shop               # Required for database and table
  table: orders                # table only
  privileges: [SELECT, SHOW VIEW]
```

Resource ID: ``shop_reader@% ON `shop`.*``. For `global` the object is `*.*`, for `table` `` `db`.`table` ``.

- Ordivus normalizes privilege names: uppercase, single spaces, sorted, without duplicates.
  The list is reconciled **exactly**; undeclared privileges on the same level are revoked.
- You can write `GRANT OPTION` into the list like a normal privilege (privileged, see below).
- Grants on the system databases `mysql`, `sys`, `information_schema` and `performance_schema` are always
  rejected (configuration error): write permissions on `mysql.*` are equivalent to `root`.
- Databases outside `spec.scope.databases` are blocked (`BLOCKED`); `apply` checks this a second time.
- `ALL`, `ALL PRIVILEGES` and `USAGE` are rejected. MySQL stores `ALL PRIVILEGES` as individual privileges,
  as a different set depending on server version and plugins. A declared `ALL` would therefore permanently show up as drift.
  List the privileges explicitly.
- Global grants also include dynamic privileges (`mysql.global_grants`, e.g. `BACKUP_ADMIN`).
- Table grants require the table to exist.
- Database names in database-level grants are patterns in MySQL (`_` and `%` are wildcards). Ordivus escapes
  them (`app\_db`), so a grant on `app_db` applies only to `app_db`, not to `appXdb`. The escapes are
  removed when reading. Existing, unescaped wildcard grants appear as separate objects with the suffix
  `(wildcard pattern)` and `manageable: false`; they are never changed or deleted.

## Privileged permissions (`allowPrivilegedGrants`)

Without the operator policy `allowPrivilegedGrants: true` (default `false`, see `docs/configuration.md`),
Ordivus blocks during planning (`BLOCKED`, exit 11 in `apply`):

- every grant with `on: global` (`*.*`),
- the privileges `SUPER`, `CREATE USER`, `SYSTEM_USER`, `FILE`, `PROXY`, `SHUTDOWN`, `PROCESS`, `RELOAD`,
  `GRANT OPTION`, `CREATE ROLE`, `DROP ROLE`, `REPLICATION SLAVE`, `REPLICATION CLIENT`, `CREATE TABLESPACE`,
  `SHOW DATABASES` and all `*_ADMIN` (e.g. `ROLE_ADMIN`, `BACKUP_ADMIN`) on any level,
- a **user account** instead of a role used as a role (`roles`/`defaultRoles`),
- a role used as a role that, itself or through further roles, has global permissions, permissions on a system database (also
  on individual tables, columns or routines there, e.g. `GRANT UPDATE ON mysql.user`, and via wildcard patterns
  such as `` `m%`.* ``) or a `PROXY` permission (`mysql.proxies_priv`, e.g. `GRANT PROXY ON root@'%'`).

MySQL compares account names with padded whitespace (`'root '` is `root`) and hosts case-insensitively.
Therefore leading or trailing spaces in user names, hosts, role and grantee specifications, and database
and table names are a configuration error. In addition, planning resolves every account specification via `mysql.user` using
MySQL's own comparison and checks the row actually matched, not the text.

Always blocked, even with `allowPrivilegedGrants: true`: system accounts and Ordivus's own login as a role, as a grantee
or as a declared account. A role that does not exist yet is allowed: it is created from a declared
`DatabaseRole` (without permissions) before the assignment.

## Protected system objects

These objects are `system`. Ordivus never changes or deletes them, and they do not appear as unmanaged:

- Accounts: `root` (on **every** host, so also `root@%`), `mysql.sys`, `mysql.session`, `mysql.infoschema` and
  their grants.
- Databases: `mysql`, `sys`, `information_schema`, `performance_schema`.

Ordivus's own account (`endpoint.user`) and its grants count as not manageable: Ordivus never deletes or changes
them. Roles held by Ordivus's own account (including via further roles) and their grants are `system`: Ordivus
never revokes or deletes them, so it does not lock itself out.

## Permissions of the Ordivus identity

**plan/drift (read-only identity, recommended):**

```sql
CREATE USER 'ordivus_ro'@'%' IDENTIFIED BY '...';
GRANT SELECT ON mysql.* TO 'ordivus_ro'@'%';
GRANT SHOW DATABASES ON *.* TO 'ordivus_ro'@'%';
```

For `passwordPolicy: verify`, Ordivus must also be able to log in as the managed user, i.e. via the
network path and a matching host entry.

**apply:** additionally `CREATE USER`, `CREATE ROLE`, `DROP ROLE`, `CREATE`, `ALTER`, `DROP` (databases), every
privilege you want to grant, each `WITH GRANT OPTION`, and `ROLE_ADMIN` for role assignments.
You only need `SYSTEM_USER` if Ordivus is to modify accounts with `SYSTEM_USER`.

### Read-only protection

Read-only sessions (`plan`, `drift`) are protected twice:

1. The adapter refuses every operation in a read-only session before it sends SQL.
2. The session runs with `SET SESSION TRANSACTION READ ONLY`. MySQL 8.4 then also rejects `CREATE USER`, `GRANT`
   and `CREATE DATABASE` (error 1792).

Neither is a security boundary, because a session can reset the mode itself. Only a read-only identity
with the permissions above offers real protection.

## Password verification (`verify`)

`verify` checks the password with a real login attempt. A wrong password is a failed login on the
server. So that `plan`/`drift` do not lock an account, Ordivus does **not** log in (result `unknown`) if

- any entry with this user name (on any host) or an anonymous account has `FAILED_LOGIN_ATTEMPTS`
  set (`mysql.user.User_attributes` → `Password_locking`): the login could hit that entry,
- there are further entries with the same name or anonymous accounts besides the account, or
- the `connection_control` plugin or component is active (delays logins after failed attempts).

If the `cryptography` library is missing (required for `caching_sha2_password` without TLS), the result is also
`unknown`. If there are lockout policies or login audits that report failed attempts, use `passwordPolicy: enforce`.

## Passwords in server logs

Ordivus sends passwords as `IDENTIFIED BY '...'` (MySQL hashes server-side). MySQL 8 writes such statements
to the general log and to `performance_schema` in rewritten form (`IDENTIFIED BY <secret>`; tested with MySQL 8.4). The
plaintext does, however, reach the server process and can become visible through statements MySQL cannot rewrite, or
through third-party debug/audit plugins. Keep `general_log` off and review audit plugins before
Ordivus sets passwords.

## Locking

`apply` acquires `GET_LOCK('ordivus', 10)` on the server. If the lock is not free after 10 seconds, the run aborts with
a transient error (exit 13). The lock applies server-wide to all Ordivus runs.

## Limitations

- Not supported: column permissions (`mysql.columns_priv`), routine/proxy permissions, `WITH GRANT OPTION` for dynamic
  privileges, role hierarchies (roles granted to roles), resource limits, password expiry, auth plugins other than the
  server default, `partial_revokes`.
- `SHOW DATABASES` via a role is not detected; the database inventory is then `partial`.
- `passwordPolicy: verify` produces one failed login per mismatching user and run (except with the
  lockout mechanisms mentioned above). With several host entries for the same name, the result is `unknown`.
- `enforce` fails with active `password_history` if the password stays the same.
- Case sensitivity of database names depends on `lower_case_table_names`. Ordivus compares exactly.
