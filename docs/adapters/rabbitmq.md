# RabbitMQ adapter (`rabbitmq`, beta)

Manages virtual hosts, users, user tags and per-vhost permissions of a RabbitMQ broker through the
management plugin's HTTP API (`/api`). No additional dependency: the adapter uses only the Python
standard library. The `rabbitmq_management` plugin must be enabled.

## Supported versions

| Version | Status |
|---|---|
| RabbitMQ 4.1 | tested (4.1.8) |
| RabbitMQ 3.13 – 4.0 | expected to work (same management API for everything used here), not tested |
| < 3.13 | rejected at connect: `RabbitMQ <version> is not supported (minimum 3.13)` |

The minimum is 3.13 because all older series are end of life and because the adapter relies on
tags being returned as a list and on `GET /api/whoami`/`/api/permissions` behaving as in current
releases. The version is read from `GET /api/overview` (`rabbitmq_version`) and reported as
`serverVersion` (e.g. `RabbitMQ 4.1.8`).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: events-rabbitmq
spec:
  adapter: rabbitmq
  endpoint:
    host: rabbitmq.messaging.svc.cluster.local
    port: 15671           # management API port; default 15672
    tls:                  # present → https; without tls → http (insecure, see requireTls)
      caFile: /trust/ca.pem   # optional, otherwise system CAs
  username: ordivus       # required: the management user Ordivus logs in as
  authentication:
    credentialRef: rabbitmq-admin   # password of that user
  scope:                  # optional; objects outside are not read/reported
    vhosts:
      include: ["orders", "billing"]
    users:
      include: ["orders-*"]
```

At connect the adapter calls `GET /api/overview` (version check) and `GET /api/whoami` (own tags).
401/403 → target error (exit code 13). Authentication is HTTP Basic Auth; the password never appears
in URLs, logs or error messages. Redirects are never followed; a management API mounted under a
`path_prefix` is not supported.

## Kinds

Creation order: `VirtualHost`, then `MessagingUser`; deletions in reverse.

### `VirtualHost`

No fields. The vhost name is `metadata.name` and may contain any printable characters, including `/`
(sent URL-encoded, `/` → `%2F`). Description, tags, default queue type, limits and
`protected_from_deletion` are not managed.

```yaml
kind: VirtualHost
metadata:
  name: orders
spec:
  targetRef: events-rabbitmq
```

> **Deleting a vhost is destructive.** `DELETE /api/vhosts/<name>` removes every queue, exchange,
> binding, policy and **all messages** in it, plus all user permissions on it. RabbitMQ has no undo.
> Ordivus only deletes a vhost through the normal deletion path: `mode: authoritative`, the vhost in
> the policy's `scope`, operator approvals `allowAuthoritative` **and** `allowDelete`, and complete
> discovery. The deletion is logged as a warning. Exclude vhosts that hold data you care about via
> `exclusions` or keep `VirtualHost` out of `scope.resourceKinds`.

### `MessagingUser`

| Field | Type | Meaning |
|---|---|---|
| `tags` | List of strings | User tags, e.g. `management`; see [Privileged tags](#privileged-tags-allowprivilegedgrants). Order and duplicates are irrelevant. |
| `permissions` | Mapping vhost → `{configure, write, read}` | One regex triple per vhost (all three required; `"^$"` = nothing, `".*"` = everything). The regexes are passed to RabbitMQ unchanged. With `spec.scope.vhosts`, every vhost must be in scope (otherwise config error). |
| `credentials` | Engine field | Password, see below. Optional: a user created without it has no password and cannot log in with one (e.g. x509-only users). |

```yaml
kind: MessagingUser
metadata:
  name: orders-publisher
spec:
  targetRef: events-rabbitmq
  tags: []
  permissions:
    orders: {configure: "^$", write: "^orders\\.", read: "^$"}
  credentials:
    credentialRef: orders-publisher-password
    passwordPolicy: verify
```

Comparison semantics:

- A missing field is not managed (neither read nor reset). `tags: []` means "no tags";
  `permissions: {}` means "no permissions on any vhost in scope".
- `permissions` is compared per vhost: on deviation, changed vhosts get `PUT /api/permissions/<vhost>/<user>`,
  vhosts no longer declared get `DELETE`. Permissions on vhosts outside `scope.vhosts` are neither
  read nor touched.
- Changing `tags` re-sends the user's current `password_hash` (RabbitMQ would otherwise clear the
  password). `password_hash` is read only for that call and never appears in attrs, reports or logs.

Passwords:

- Create: `PUT /api/users/<name>` with the password from the credential (RabbitMQ hashes it).
- `SET_PASSWORD`: `PUT /api/users/<name>` with the new password and the current tags (tags unchanged).
- `verify`: login attempt as the user against `GET /api/whoami`:
  - 200 → equal;
  - 401 `Not management user` → equal (authentication succeeded, the user just lacks a management tag;
    this covers ordinary AMQP-only users);
  - 401 `Not_Authorized` → different (also for users without a password);
  - anything else (e.g. `User can only log in via localhost` for loopback users such as `guest`,
    timeouts, 5xx) → `unknown`.
  - User names containing `:` cannot be checked via Basic Auth → always `unknown`.

  Note that each failed check counts as a failed login in RabbitMQ's logs/auth-attempt metrics.

## Discovery

| Kind | Source | Status |
|---|---|---|
| `VirtualHost` | `GET /api/vhosts` | `complete` only if the login has the `administrator` tag; otherwise RabbitMQ shows only vhosts the login has permissions on → `partial` |
| `MessagingUser` | `GET /api/users` + `GET /api/permissions` | `complete`; without `administrator` 401 → `forbidden` |

With `partial`/`forbidden` there is neither `CREATE` nor `DELETE` for the respective kind.
Only users of RabbitMQ's internal database are listed (users from LDAP/OAuth backends are invisible).

## Required privileges

Managing users, permissions and vhosts requires the **`administrator`** tag on the Ordivus login
(and, for `plan`, at least `management`). Ordivus does not need any vhost permissions itself.

## Protected objects

- **Own login** (`spec.username`): system object; not declared → `IGNORE`; declared → `BLOCKED`
  (also if outside `scope.users`), even with `allowPrivilegedGrants`. Never changed or deleted.
- **Default vhost `/`**: system object, never created, changed or deleted; declaring it as
  `VirtualHost` → `BLOCKED`. Users may still get permissions on `/` via `permissions`.
- Vhosts with RabbitMQ's `protected_from_deletion` flag (4.x) are system objects as well.
- **`guest`**: not special-cased. If it exists it is an ordinary user: `UNMANAGED` in additive mode,
  `UNDESIRABLE`/`DELETE` in authoritative mode when in scope (deleting it is usually desirable in
  production; exclude it via `exclusions` if something depends on it). RabbitMQ only lets `guest`
  log in from localhost by default, so `verify` for it is usually `unknown`.

## Privileged tags (`allowPrivilegedGrants`)

Without `allowPrivilegedGrants: true` in the operator policy, a `MessagingUser` with any of these
tags is `BLOCKED`:

| Tag | Why privileged |
|---|---|
| `administrator` | full control: users, permissions, vhosts, policies, definitions export (incl. password hashes) |
| `policymaker` | policies and runtime parameters (shovels, federation upstreams with URIs to other brokers) in its vhosts |
| `monitoring` | reads all vhosts, connections (client IPs, user names), channels and node data |
| `impersonator` | may publish messages with a forged `user-id` |

`management` and custom tags are not privileged. Permissions (`configure`/`write`/`read`) are never
treated as privileged; they are confined to the vhost.

## Read-only guarantee

`plan`/`drift` open read-only sessions. In them, the adapter refuses every HTTP method except `GET`
as well as every `apply` call (`PermanentError`) before a request reaches the network.

## Error mapping

| Cause | Error |
|---|---|
| Timeout, connection error, HTTP 5xx/429 | `TransientError` |
| HTTP 401/403 | `AuthorizationError` |
| other 4xx (e.g. permission on a missing vhost), invalid JSON, unreadable `caFile`, redirect | `PermanentError` |

Idempotency: creating an existing vhost is a no-op `PUT`; deleting a vhost, user or permission that
no longer exists (404) counts as success.

## Limitations

- Topic permissions, user limits, vhost limits/metadata, policies, queues, exchanges and bindings are
  not managed.
- A tag change reads the current password hash and writes it back; a password changed by someone
  else between those two calls would be reverted (narrow race).
- Reverse proxies that decode `%2F` in paths break vhost names containing `/` (including `/`).
- No locking (`lock`): parallel runs against the same broker are not protected against each other.
- Clusters: definitions are cluster-wide; any node's management API can be used. Not tested
  separately.
