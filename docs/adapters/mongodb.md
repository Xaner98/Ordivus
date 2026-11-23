# MongoDB adapter

Manages **custom roles** and **users** in MongoDB 6.0 and newer (tested with MongoDB 8.0).
Installation: `pip install 'ordivus[mongodb]'` (pymongo ≥ 4.10). Complete example: `examples/mongodb/`.

Kinds in execution order: `DatabaseRole`, `DatabaseUser` (deletions in reverse order).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: shop-mongodb
spec:
  adapter: mongodb
  endpoint:
    host: mongodb-0.mongodb.data.svc.cluster.local
    port: 27017               # default 27017
    replicaSet: rs0           # optional, see "Replica sets"
    user: ordivus_admin       # user Ordivus logs in as (SCRAM)
    authDatabase: admin       # authentication database of that user; default admin
    tls:                      # present → TLS; certificate and hostname are verified
      caFile: /trust/ca.pem   # without caFile, the system CAs apply
  authentication:
    credentialRef: mongodb-admin   # password of endpoint.user
  scope:                      # optional; without it, everything is inventoried
    databases: {include: ["shop", "shop_*"]}
```

| Field | Meaning |
|---|---|
| `endpoint.host` | Required. A single host name or IPv4 address (no `,`, `:`, no URI) |
| `endpoint.port` | Default `27017` |
| `endpoint.replicaSet` | Name of the replica set; without it, Ordivus talks to exactly this node (`directConnection`) |
| `endpoint.user` / `authDatabase` | Login of Ordivus; SCRAM-SHA-256 (or SCRAM-SHA-1, negotiated by pymongo) |
| `endpoint.tls.caFile` | CA file; the `tls` block enables TLS |
| `scope.databases.include` | Globs (`fnmatch`, case-sensitive) on the database of a user or role |

Without `tls` the connection counts as insecure (warning, `insecureTransport: true`; with operator policy
`requireTls: true` abort, exit code 11). Timeouts: 10 s for connecting and server selection, 30 s per operation.

`mongodb+srv://` URIs, multiple seed hosts, x509/LDAP/Kerberos logins for Ordivus itself and
`tlsAllowInvalidCertificates` are not supported.

### Replica sets

With `replicaSet`, `host:port` is used as the seed; pymongo discovers the other members and sends all
commands to the primary. Users and roles are replicated, so one target per replica set is enough. Without
`replicaSet`, a secondary is read normally but `apply` fails with `NotWritablePrimary` (transient error).
For sharded clusters, configure the `mongos` as target (users live on the config servers). Users that exist
only locally on a shard are not visible through `mongos`.

## Resource IDs

The ID is MongoDB's own `_id` form `<database>.<name>`, e.g. `shop.shop_app`. Database names never contain a
dot, so names may (`admin.svc.reporting` is the user `svc.reporting` in `admin`).

## Kind `DatabaseRole`

A **custom role** (built-in roles such as `read` cannot be declared).

```yaml
kind: DatabaseRole
metadata:
  name: shop-orders-writer
spec:
  targetRef: shop-mongodb
  database: shop               # required; config and local are not allowed
  name: ordersWriter           # optional, default metadata.name
  privileges:
    - resource: {db: shop, collection: orders}   # collection "" = all collections of the database
      actions: [find, insert, update]
  roles: [read]                # "name" = role in the same database, or {role: x, db: y}
```

| Field | Notes |
|---|---|
| `privileges` | Resources `{db, collection}` (`db: ""` = every database) or `{cluster: true}`. Privileges on the same resource are merged, actions sorted (as MongoDB stores them) |
| `roles` | Inherited roles. Sorted, without duplicates |

MongoDB rules that Ordivus checks during validation: a role outside `admin` may only target its own database
in `privileges` and may only inherit roles of its own database. Cross-database and cluster privileges need a
role in `admin`.

`authenticationRestrictions` are not managed.

## Kind `DatabaseUser`

```yaml
kind: DatabaseUser
metadata:
  name: shop-app
spec:
  targetRef: shop-mongodb
  database: shop               # authentication database; required
  name: shop_app               # optional, default metadata.name
  roles: [ordersWriter, {role: read, db: reporting}]
  credentials:
    credentialRef: shop-app-password
    passwordPolicy: verify
```

- `roles` is reconciled exactly (`updateUser` replaces the role list). Unset = not managed.
- `credentials` is required: MongoDB SCRAM users always have a password (configuration error otherwise).
- Users are created with `mechanisms: [SCRAM-SHA-256]` only. Passwords are sent to the server in the
  `createUser`/`updateUser` command (`passwordDigestor: server`, required for SCRAM-SHA-256); MongoDB redacts
  them in its logs. Use TLS.
- Discovery shows the field `mechanisms` for information; it is never compared or changed.
- Users in `$external` (x509, LDAP, Kerberos) are shown as `manageable: false` and never changed.
- `customData` is not managed.

## Passwords

- **Set** (`CREATE`, `SET_PASSWORD`): `createUser`/`updateUser` with `pwd` and `mechanisms: [SCRAM-SHA-256]`;
  `SET_PASSWORD` thereby also removes an existing SCRAM-SHA-1 credential.
- **Verify** (`passwordPolicy: verify`): Ordivus opens a **separate connection** and authenticates as the user
  (SCRAM-SHA-256, or SCRAM-SHA-1 if the user has only that). `AuthenticationFailed` (code 18) means "wrong
  password" → `SET_PASSWORD`. Everything else (network, TLS, users without SCRAM credentials) is `unknown`
  ("password unverifiable"; in `apply` status `incomplete`, exit 13). The check needs network access from
  Ordivus to the server as that user; it does not use the admin session.
- MongoDB has no account lockout after failed logins, so `verify` cannot lock users. Failed attempts are logged
  by the server (`Authentication failed`) and may trigger alerts in audit/monitoring.

## Discovery and scope

- Users: `usersInfo` with `forAllDBs: true`. Roles: `find` on `admin.system.roles` (`rolesInfo` has no
  `forAllDBs`; roles of databases without data are only visible there). Built-in roles are not inventoried.
- If those are not permitted, Ordivus reads each database listed literally in `scope.databases.include` on its
  own (`usersInfo`/`rolesInfo`). The kind is `partial` if one of them is not readable or a glob is in the
  scope (globs cannot be enumerated: databases that hold only users do not appear in `listDatabases`), and
  `forbidden` without any readable database or without a scope. `partial` means: no `CREATE`, no `DELETE`.
- Objects outside the scope are invisible. Declared resources in databases outside the scope, and role
  references to such databases, are `BLOCKED` (even with `allowPrivilegedGrants`); `apply` checks again.

## Privileged permissions (`allowPrivilegedGrants`)

Without operator policy `allowPrivilegedGrants: true`, a declared user or role is `BLOCKED` if it
grants – directly or through inherited roles – any of:

- the built-in roles `root`, `__queryableBackup`, `userAdminAnyDatabase`, `readWriteAnyDatabase`,
  `dbAdminAnyDatabase`, `readAnyDatabase`, `clusterAdmin`, `clusterManager`, `hostManager`, `backup`,
  `restore` (reads/writes `system.users`), `directShardOperations`;
- any built-in role on `admin`, `config` or `local` except `read` and `clusterMonitor`
  (e.g. `dbOwner`/`userAdmin` on `admin` = root);
- a privilege on the cluster resource, on `anyResource`, on every database (`db: ""`), on `admin`, `config`
  or `local`, or on a `system.*` collection;
- the actions `anyAction`, `internal`, `impersonate`, `createUser`, `dropUser`, `changePassword`,
  `changeCustomData`, `createRole`, `dropRole`, `grantRole`, `revokeRole`, `setAuthenticationRestriction`,
  `useUUID`, `forceUUID` on any resource.

Existing custom roles that a declaration refers to are resolved on the server (`rolesInfo`, transitively); if
that is not possible, the resource is `BLOCKED` as well. Unlike Redis, the check does not distinguish between
new and already existing privileges: a declaration that keeps a privileged role still needs the approval.
`userAdmin`/`dbOwner` on a normal database are not considered privileged (they only allow administration of
that database), but the action list above applies to custom roles.

Always blocked, even with `allowPrivilegedGrants: true`: granting `__system`, and the protected objects below.

## Protected objects

- Ordivus's own login (`endpoint.user` in `authDatabase`) and every user named `__system`: `system`; declared →
  `BLOCKED`, never changed or deleted.
- Custom roles held by Ordivus's own login (also via further roles, from `connectionStatus`): `system`.
  Ordivus never changes or deletes them, so it does not lock itself out.
- Built-in role names cannot be declared as `DatabaseRole` (`BLOCKED`).

## Required privileges

**plan/drift (read-only identity, recommended):** a role in `admin`:

```javascript
db.getSiblingDB("admin").createRole({role: "ordivusInventory", roles: [], privileges: [
  {resource: {cluster: true}, actions: ["viewUser"]},             // usersInfo forAllDBs
  {resource: {db: "", collection: ""}, actions: ["viewRole"]},    // rolesInfo for the privilege check
  {resource: {db: "admin", collection: "system.roles"}, actions: ["find"]}]})
```

This role is itself privileged in the sense above (cluster and `admin` resources), so a declaration of it via
Ordivus needs `allowPrivilegedGrants`. With less (e.g. `viewUser`/`viewRole` only on single databases),
see the per-database fallback under [Discovery and scope](#discovery-and-scope).

**apply:** additionally `createUser`, `dropUser`, `createRole`, `dropRole`, `grantRole`, `revokeRole` and
`changePassword` on the managed databases (built-in: `userAdminAnyDatabase`, or `userAdmin` per database plus
the read privileges above). To grant a role or privilege, MongoDB also requires `grantRole` on the database of
that role.

### Read-only protection

MongoDB has no read-only session mode. The adapter refuses every operation in a read-only session before
it sends a command, and the discovery uses only read commands. Only a read-only identity is a real
boundary.

## Error messages

pymongo errors contain the server reply, and MongoDB repeats the full command in some messages
(e.g. `not authorized ... to execute command { createUser: ... }`). Ordivus reports only the error code, its
name and the server message up to the first `{`, removes known secret values and limits the text to 300
characters.

## Supported versions

Minimum **6.0**: the adapter refuses older servers in `connect` (`buildInfo`). The commands used exist since
4.x, but versions before 6.0 are end of life and have not been checked; 6.0 is the oldest line whose
behavior (SCRAM-SHA-256 default, error codes 13/18/334, role restrictions) matches the documentation used
here. Tested only with **MongoDB 8.0** (Community). Atlas and Percona Server for MongoDB should work but are
untested; Atlas manages database users via its own API, changes via `createUser` are not possible there.

## Locking

No lock. MongoDB has no cheap native lock without writing a document, and Ordivus never writes markers into
target systems. Avoid concurrent `apply` runs against the same target by organizational means.

## Limitations

- Not managed: `authenticationRestrictions`, `customData`, user `mechanisms`, privileges on `system_buckets`
  resources, built-in roles.
- `passwordPolicy: verify` needs a direct network path to the server as the user.
- No `mongodb+srv`, no multiple seed hosts, no login of Ordivus via x509/LDAP/Kerberos.
- TLS and replica set mode are not covered by the integration tests (single node without TLS).
- Users exported with `ordivus export` have no `spec.credentials`; add them before `plan` (see [export](../export.md#credentials-and-passwords)).
