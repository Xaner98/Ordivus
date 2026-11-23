# MariaDB adapter

Manages databases, roles, users and grants in **MariaDB** (tested with MariaDB 11.4).
Installation: `pip install 'ordivus[mariadb]'` (PyMySQL ≥ 1.1). Complete example: `examples/mariadb/`.

The adapter is built on the [MySQL adapter](mysql.md) and shares its kinds, config shape, safety rules and
most behavior. This page describes the MariaDB-specific parts. For everything not mentioned here (TLS modes, scope,
`Database`, grant levels and normalization, wildcard handling, protected objects, password logging), see
[mysql.md](mysql.md).

Kinds in execution order: `Database`, `DatabaseRole`, `DatabaseUser`, `Grant`
(deletions in reverse order).

## Supported versions

| | |
|---|---|
| Minimum | MariaDB 10.6 |
| Tested | MariaDB 11.4 |

The minimum follows from the privilege layout: Ordivus decodes global privileges from the bitmask in
`mysql.global_priv`, and the split privileges (`SET USER`, `CONNECTION ADMIN`, `BINLOG MONITOR`, ...) have
existed since 10.5. 10.6 is the oldest long-term release with this layout. Ordivus reads `VERSION()` on connect and reports it as
`serverVersion` (e.g. `MariaDB 11.4.4`). Older servers fail with
`MariaDB <version> is not supported (minimum 10.6.0)`. A MySQL server is rejected with a pointer to the
`mysql` adapter.

## Target

Same as MySQL, with `adapter: mariadb`:

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: shop-mariadb
spec:
  adapter: mariadb
  endpoint:
    host: mariadb.shop.svc.cluster.local
    port: 3306
    user: ordivus_admin
    tls:
      mode: verify-full        # disable | require | verify-ca | verify-full (default)
  authentication:
    credentialRef: mariadb-admin
  scope:
    databases: {include: ["shop"]}
    users:     {include: ["shop_*"]}
    roles:     {include: ["shop_*"]}
```

## Roles have no host

In MariaDB, a role is a name without a host (`CREATE ROLE shop_reader`). This changes how account references
are written:

| Reference | MySQL adapter | MariaDB adapter |
|---|---|---|
| `shop_reader` | account `shop_reader@%` | **role** `shop_reader` |
| `shop_app@%` | account `shop_app@%` | user account `shop_app@%` |

- `DatabaseRole`: `identity.username` only; `identity.host` is a configuration error. Resource ID: `shop_reader`.
- `DatabaseUser.roles` / `defaultRoles`: role names only (no `@`).
- `Grant.grantee`: a name without `@` is a role, `name@host` is a user account. **Write user grantees with
  their host** (`shop_app@%`). For the same reason, role names must not contain `@`.

```yaml
kind: DatabaseRole
metadata:
  name: shop-reader
spec:
  targetRef: shop-mariadb
  identity:
    username: shop_reader     # resource ID: shop_reader
---
kind: Grant
metadata:
  name: shop-reader-select
spec:
  targetRef: shop-mariadb
  grantee: shop_reader         # role
  on: database
  database: shop
  privileges: [SELECT, SHOW VIEW]
```

MariaDB applies `GRANT ... TO 'name'` to the user account `name@'%'` if no role with that name exists.
`apply` therefore checks that the role exists right before a grant to a role and otherwise fails the
operation instead of granting to the user account.

## Kind `DatabaseUser`

Same fields as MySQL. Differences:

- `defaultRoles` may contain **at most one** role (MariaDB has a single default role per account);
  `[]` means `SET DEFAULT ROLE NONE`.
- Roles are granted one statement per role (`GRANT role TO user`).
- Users without `credentials` must set `accountLocked: true`, as in MySQL.
- Accounts are created with `IDENTIFIED BY`, i.e. with the server's default authentication plugin
  (usually `mysql_native_password`). Ordivus does not manage the plugin (`ed25519` etc.).

## Discovery

| Data | Source |
|---|---|
| Accounts, role flag, lock status | `mysql.global_priv` (`is_role`, `account_locked` in the JSON column) |
| Global privileges | bitmask `access` in `mysql.global_priv`, translated to the names `SHOW GRANTS` prints |
| Role assignments | `mysql.roles_mapping` |
| Default role | `mysql.user.default_role` |
| Database, table privileges | `mysql.db`, `mysql.tables_priv` (as MySQL) |

Global privileges use MariaDB's names, e.g. `BINLOG MONITOR` (not `REPLICATION CLIENT`), `SLAVE MONITOR`,
`READ_ONLY ADMIN`. Declare them under these names, otherwise every run reports drift. A privilege bit unknown to
Ordivus (newer server) shows up as `UNKNOWN PRIVILEGE BIT <n>`; Ordivus never revokes it.

The read-only identity needs the same permissions as on MySQL (`SELECT ON mysql.*`, `SHOW DATABASES`).

## Privileged permissions (`allowPrivilegedGrants`)

The MySQL rules apply. In addition, these MariaDB privileges are privileged: every privilege ending in
`ADMIN` (`CONNECTION ADMIN`, `READ_ONLY ADMIN`, `FEDERATED ADMIN`, `BINLOG ADMIN`, `REPLICATION SLAVE ADMIN`,
`REPLICATION MASTER ADMIN`), `SET USER`, `BINLOG MONITOR`, `BINLOG REPLAY`, `SLAVE MONITOR`
(`REPLICA MONITOR`) and `REPLICATION REPLICA`. A role that holds global privileges, privileges on a system database or a proxy
privilege (directly or through other roles) also counts as privileged.

MariaDB has no `SYSTEM_USER` privilege: any account with `CREATE USER` can change `root`. Ordivus protects
the system accounts itself (see below). Give the Ordivus identity no more than it needs.

## Protected system objects

- Accounts: `root` (on every host), `mariadb.sys`, `mysql` (Unix-socket account of some distributions) and the
  pseudo role `PUBLIC` (also written `public`; granting to it would grant to everyone). They can never be a
  grantee, role or declared account, not even with `allowPrivilegedGrants`.
- Databases: `mysql`, `sys`, `information_schema`, `performance_schema`.
- Ordivus's own login is not manageable. Its **default role** and the roles inside it are `system`
  (never revoked or dropped), because only these are active in Ordivus's session.

`CREATE ROLE` automatically grants the new role to its creator (with admin option). Ordivus's login therefore
holds every role it created. These grants are needed: granting a role to users requires the admin option on it. They do not make a role
protected, so Ordivus can still drop roles it created in `authoritative` mode.

## Read-only protection

As MySQL: the adapter refuses all operations in `plan`/`drift` sessions, and the session runs with
`SET SESSION TRANSACTION READ ONLY` (MariaDB rejects `CREATE USER`, `CREATE ROLE`, `GRANT`, `CREATE DATABASE`
with error 1792; tested with 11.4).

## Password verification (`verify`)

`verify` logs in as the user, as on MySQL. Ordivus does **not** try the login (result `unknown`) if

- the server variable `max_password_errors` is set (not the default 4294967295): a failed login could block
  the account until `FLUSH PRIVILEGES`, or
- there are several entries with the user name or anonymous accounts.

Accounts using `ed25519` need PyNaCl on the Ordivus side for the login; without it, the result is `unknown`.

## Locking

`apply` acquires `GET_LOCK('ordivus', 10)`, as on MySQL.

## Limitations

- All [MySQL limitations](mysql.md#limitations) apply.
- Accounts with an empty host (`'name'@''`) are not supported; their IDs would look like role names.
- Role names containing `@` cannot be managed.
- Authentication plugins are not managed. `SET_PASSWORD` uses `ALTER USER ... IDENTIFIED BY`; for accounts
  on another plugin (such as `ed25519`), this can switch them to the server default plugin (not tested). Use
  `set-on-create` for such accounts.
- `SHOW DATABASES` through a role is not detected; the database inventory is then `partial`.
- User names longer than 32 characters are rejected (MariaDB allows 128).
