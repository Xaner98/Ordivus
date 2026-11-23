# Kafka adapter

Manages **SCRAM users** (kind `KafkaUser`) and **ACLs** (kind `KafkaAcl`) through the Kafka Admin API.
Installation: `pip install 'ordivus[kafka]'` (kafka-python ≥ 3, < 4).

Topics, quotas, broker/topic configs and delegation tokens are deliberately out of scope: they are
application or capacity configuration, not access administration.

Kinds in execution order: `KafkaUser`, `KafkaAcl`; deletions run in reverse.

Complete example: [`examples/kafka/`](../../examples/kafka/ordivus.yaml).

## Supported versions

| Version | Status |
|---|---|
| Kafka 4.1 (KRaft) | tested (integration tests) |
| Kafka 2.7 – 4.0, ZooKeeper or KRaft | expected to work, untested |
| below 2.7 | refused at connect: `Kafka 2.6 is not supported (minimum 2.7)` |

The minimum is a feature gate, not a guess: managing SCRAM credentials through the Admin API
(`DescribeUserScramCredentials`/`AlterUserScramCredentials`, KIP-554) exists since Kafka 2.7. The
version is derived from the broker's `ApiVersions` response and reported as `serverVersion`
(e.g. `Kafka 4.1`; the patch level is not visible through the protocol).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: events-kafka
spec:
  adapter: kafka
  bootstrapServers: ["kafka-0.kafka.svc.cluster.local:9093"]
  securityProtocol: SASL_SSL        # default; SASL_PLAINTEXT counts as insecure transport
  mechanism: SCRAM-SHA-512          # mechanism Ordivus logs in with; default SCRAM-SHA-512
  username: ordivus-admin
  tls:
    caFile: /trust/ca.pem           # optional; without it the system CAs apply
  scram:                            # credentials Ordivus writes for managed users
    mechanism: SCRAM-SHA-512        # default SCRAM-SHA-512
    iterations: 8192                # 4096-16384, default 4096
  superUsers: ["User:kafka-admin", "User:ordivus-admin"]
  scope:
    principals: {include: ["User:app-*"]}
    resources: {include: ["orders.*"]}
  authentication:
    credentialRef: kafka-admin      # password of spec.username
```

| Field | Meaning |
|---|---|
| `bootstrapServers` | Required, list of `host:port` |
| `securityProtocol` | `SASL_SSL` (default) or `SASL_PLAINTEXT`. Plain `PLAINTEXT`/`SSL` without SASL are not supported |
| `mechanism` | `SCRAM-SHA-512` (default) or `SCRAM-SHA-256` for Ordivus' own login |
| `username` | Required; the SCRAM user Ordivus logs in as |
| `tls.caFile` | CA file (only with `SASL_SSL`); the hostname is always verified |
| `scram` | Mechanism and iteration count for credentials Ordivus writes |
| `superUsers` | Copy of the broker setting `super.users`, see [Super users](#super-users) |
| `scope` | Globs on the full principal (`User:app-*`) and on resource names |

Every request has a 10 s timeout; an unreachable broker ends the target with `TransientError`
instead of hanging. A wrong admin password is reported as `AuthorizationError` (Ordivus performs one
SCRAM login before opening the admin client, because the client library would only report a bootstrap
timeout).

`spec.scope`: objects outside the scope are neither listed nor changed. A declared `KafkaUser` or
`KafkaAcl` whose principal (or ACL resource name) is outside the scope is `BLOCKED`, also with
`allowPrivilegedGrants`.

## Kind `KafkaUser`

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: KafkaUser
metadata:
  name: app-orders
spec:
  targetRef: events-kafka
  name: app-orders          # optional; default metadata.name
  credentials:
    credentialRef: app-orders-password
    passwordPolicy: verify
```

A Kafka SCRAM user exists only as a credential, i.e. only with a password. A new `KafkaUser`
without `spec.credentials` is therefore `BLOCKED`; declaring an existing user without credentials is
allowed (e.g. to keep it in authoritative mode). User names must not contain whitespace, `,`, `=`, `:` or
`*`.

Discovery shows the existing credentials as attribute `credentials` (`{"SCRAM-SHA-512": 4096}`); it is
never compared directly.

### Passwords, mechanism and iterations

Ordivus derives the salted password client side (PBKDF2 with a random salt) and sends only the
salted value; the plaintext never reaches the broker.

- **Set** (`CREATE`, `SET_PASSWORD`): writes the credential for `spec.scram.mechanism` with
  `spec.scram.iterations` and deletes credentials of the other mechanism.
- **Verify** (`passwordPolicy: verify`): first compares the existing credentials with
  `spec.scram`; any difference (other or additional mechanism, other iteration count) counts as
  "password differs" and leads to `SET_PASSWORD`. Otherwise Ordivus attempts a **SCRAM login as the
  user** against the first reachable bootstrap server:
  - login succeeds → password matches,
  - the broker answers `SASL_AUTHENTICATION_FAILED` → `SET_PASSWORD`,
  - anything else (mechanism not enabled on the listener, protocol error) → `UNKNOWN`
    ("password unverifiable"), nothing is changed. Network errors make the target fail with
    `TransientError`.
  Every failed attempt appears in the broker log as a failed authentication.
- **Enforce** resets on every run; **set-on-create** never touches existing users.

Mechanism and iterations are configured per target, not per user: Kafka can only write a SCRAM
credential together with the password, and Ordivus passes a password only with `CREATE`/`SET_PASSWORD`.
A change of `spec.scram` is therefore applied by the next password reset (`verify` detects it
automatically, `set-on-create` never applies it).

## Kind `KafkaAcl`

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: KafkaAcl
metadata:
  name: app-orders-produce
spec:
  targetRef: events-kafka
  principal: User:app-orders
  resourceType: TOPIC       # TOPIC | GROUP | CLUSTER | TRANSACTIONAL_ID | DELEGATION_TOKEN | USER
  resourceName: orders.     # 'kafka-cluster' for CLUSTER; '*' = all resources of the type
  patternType: PREFIXED     # LITERAL (default) | PREFIXED
  operations: [WRITE, DESCRIBE]
  permission: ALLOW         # ALLOW (default) | DENY
  host: "*"                 # default '*'
```

Kafka stores ACLs as immutable bindings *principal × resource pattern × host × permission ×
operation*. Ordivus groups them like PostgreSQL grants: the natural key is
`[principal, resourceType, patternType, resourceName, permission, host]` (as JSON, e.g.
`["User:app-orders","TOPIC","PREFIXED","orders.","ALLOW","*"]`), and `operations` is the compared
attribute. `metadata.name` can be chosen freely. Enum values are case-insensitive and normalized to
upper case.

- `CREATE` creates one binding per operation.
- `UPDATE` creates the added and deletes the removed operations of the key; other keys stay untouched.
- `DELETE` (authoritative, `allowDelete`) deletes all bindings of the key.
- Undeclared keys are `UNMANAGED` (additive) or `UNDESIRABLE`/`DELETE` (authoritative).

ALLOW and DENY of the same principal and resource are different keys and therefore two documents.

## Privileged grants (`allowPrivilegedGrants`)

Without operator policy `allowPrivilegedGrants: true`, these declarations are `BLOCKED`:

- `KafkaAcl` with `permission: ALLOW` and
  - `resourceType: CLUSTER` (any operation, e.g. `DESCRIBE` lists all users and ACLs, `ALTER` changes them),
  - an operation `ALL`, `ALTER`, `ALTER_CONFIGS` or `CLUSTER_ACTION` on any resource,
  - `resourceName: '*'` with `ALL`, `WRITE`, `CREATE`, `DELETE`, `ALTER` or `ALTER_CONFIGS`,
  - `resourceType: USER` (allows creating delegation tokens for other users, i.e. impersonation);
- `KafkaAcl` with `permission: DENY` for a wildcard principal (`User:*`): it also applies to the Ordivus login;
- `KafkaAcl` for a principal listed in `superUsers`, and a `KafkaUser` whose `User:<name>` is listed there
  (writing a super user's password hands over the cluster).

**Always** `BLOCKED`, even with approval: the Ordivus login (`User:<spec.username>`) as `KafkaUser` and
as ACL principal, and anything outside `spec.scope`.

### Super users

Kafka reports `super.users` as a sensitive config (value hidden), so Ordivus cannot read it. Copy the
broker setting into `spec.superUsers`. Listed principals and the Ordivus login are system objects:
undeclared → `IGNORE`, never deleted; their users and ACLs are never changed. If the list is incomplete,
an ACL for an unlisted super user is treated like any other ACL (super users bypass ACLs, so such an ACL
has no effect, but its creation would not be blocked).

## Required permissions

**Read-only identity (`plan`/`drift`):** `DESCRIBE` on the `Cluster` resource (lists ACLs and SCRAM
credentials). Without it, both kinds are reported as `forbidden` and nothing is planned for them.

**Apply identity:** additionally `ALTER` on the `Cluster` resource (`CreateAcls`, `DeleteAcls`,
`AlterUserScramCredentials`). Note that `ALTER` on the cluster allows granting any ACL, including to
itself; it is effectively an administrator. A super user works as well.

Regardless of the permissions, the adapter refuses every change over a read-only session.

## Limitations

- Only SCRAM-SHA-256/512. PLAIN, GSSAPI, OAUTHBEARER and mTLS principals cannot be used for Ordivus'
  login; ACLs for such principals can still be managed (any `Type:name` principal).
- No lock: two concurrent `apply` runs against the same cluster are not protected against each other.
- One target per cluster: SCRAM credentials and ACLs are cluster-wide (KRaft metadata or ZooKeeper);
  Ordivus talks to one broker of `bootstrapServers`.
- Deleting a `KafkaUser` deletes its SCRAM credentials only, not its ACLs (declare/delete them as
  `KafkaAcl`).
- `verify` needs a login as each managed user through the same listener as Ordivus; if the listener
  does not offer `spec.scram.mechanism`, the result is `UNKNOWN`.
- The SCRAM login check uses internals of kafka-python (hence the `< 4` pin).
- Without TLS (`SASL_PLAINTEXT`) the connection counts as insecure (warning, `insecureTransport: true`;
  with operator policy `requireTls: true` abort, exit code 11). The SCRAM exchange itself never sends the
  password, but `SET_PASSWORD` sends the salted password, which is enough to log in as that user.
