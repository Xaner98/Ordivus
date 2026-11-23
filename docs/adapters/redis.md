# Redis adapter

Manages **ACL users** in Redis 7.0 and newer and Valkey as kind `DatabaseUser`.
Installation: `pip install 'ordivus[redis]'` (redis-py ≥ 5).

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: cache-redis
spec:
  adapter: redis
  endpoint:
    host: redis.cache.svc.cluster.local
    port: 6379              # default 6379
    tls:                    # present → TLS (rediss); without caFile the system CAs apply
      caFile: /trust/ca.pem
  username: ordivus-admin   # ACL user Ordivus logs in as; default "default"
  persist: aclSave          # none (default) | aclSave | configRewrite
  authentication:
    credentialRef: redis-admin   # password of the admin user
```

| Field | Meaning |
|---|---|
| `endpoint.host` | Required |
| `endpoint.port` | Default `6379` |
| `endpoint.tls.caFile` | CA file; the `tls` block enables TLS, the hostname is verified |
| `username` | Admin user; default `default` |
| `persist` | see [Persistence](#persistence) |

`spec.scope` is not supported; restrictions for authoritative mode come from the
`ReconciliationPolicy` (`scope.DatabaseUser.glob`).

## Kind `DatabaseUser`

`metadata.name` is the Redis user name.

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: DatabaseUser
metadata:
  name: app-sessions
spec:
  targetRef: cache-redis
  enabled: true                               # default true (ACL flag on/off)
  keys: ["session:*", "%R~config:*"]          # key patterns
  channels: ["session-events"]                # Pub/Sub channel patterns
  commands: ["+@read", "+@write", "-@dangerous", "+ping"]
  credentials:
    credentialRef: app-sessions-password
    passwordPolicy: verify
```

| Field | Type | Redis rule | Notes |
|---|---|---|---|
| `enabled` | bool | `on` / `off` | Default `true`, always managed |
| `keys` | List | `~pattern`, `%R~pattern`, `%W~pattern` | `pattern`, `~pattern` and `%RW~pattern` are equivalent |
| `channels` | List | `&pattern` | a leading `&` is optional |
| `commands` | List | `+command`, `-command`, `+command\|sub`, `+@category`, `allcommands`, `nocommands` | case-insensitive |
| `credentials` | – | `>password` | Engine field, see [Passwords](#passwords) |

`selectors` (Redis 7 selectors in parentheses) are **not** supported and are rejected during
validation. Existing selectors are shown in discovery as the field `selectors`, but never
compared or changed.

### Declared fields only

As everywhere in Ordivus: an unset field does **not** mean "reset". An
`UPDATE` writes only the changed field groups and resets exactly those groups:

| Field | rules sent |
|---|---|
| `enabled` | `on` or `off` |
| `keys` | `resetkeys` + patterns |
| `channels` | `resetchannels` + patterns |
| `commands` | `-@all` or `+@all` + rules |

If, for example, only `commands` is declared, key and channel patterns on the server stay unchanged.
This is safer than `ACL SETUSER name reset …`, which on every update would delete all
undeclared permissions (and the password).

Exception **CREATE**: a new user is created with `ACL SETUSER name reset <rules>`. For
undeclared fields, the Redis default after `reset` then applies: no keys, no commands
(`-@all`), channels according to `acl-pubsub-default` (since Redis 7: none), no password (login
impossible), no selectors.

### Normalization

Redis merges rules when storing them; `ACL GETUSER` returns the merged form.
Ordivus normalizes desired and actual state with the same rules so that a second run yields `NOOP`:

- `keys`: identical patterns are merged (`%R~a` + `%W~a` = `a`), result sorted.
  `*` with full permissions replaces all other patterns.
- `channels`: duplicates removed, sorted; `*` replaces all others.
- `commands`: order is kept (it is significant). The list always starts with `-@all` (default)
  or `+@all`. `allcommands`/`nocommands`/`+@all`/`-@all` discard all previous rules; a
  rule replaces earlier rules for the same command or category; `+config` also replaces
  earlier rules for `config|…`. Everything in lower case.

Example: `["+@read", "-get", "+get"]` becomes `["-@all", "+@read", "+get"]`.

This emulation is based on observed behavior of Redis 8 and is covered by the
integration tests. If another version merges differently, `plan` permanently shows an
`UPDATE` for `commands`; remedy: declare rules in the form `ACL GETUSER` returns.

### Input validation

Each rule is passed to `ACL SETUSER` as a separate argument (no string concatenation). In addition:

- User names: only ASCII letters, digits and `. _ @ : -`, starting with a letter or digit,
  at most 128 characters. Names such as `>pw`, `#hash`, or names with spaces or umlauts are rejected.
- `commands`: only the forms from the table above. Rules such as `>secret`, `nopass`, `on`, `reset`
  are thereby excluded.
- `keys`/`channels`: no whitespace or control characters. Unicode is allowed. Ordivus sets the prefix
  `~`/`&` itself, so patterns such as `>pw` or `#x` remain literal patterns and are never read as
  a password or hash rule.

## Passwords

`spec.credentials` manages exactly one password per user.

- **Set** (`CREATE`, `SET_PASSWORD`): `resetpass` + `>password`; all previous passwords and
  a `nopass` flag are removed.
- **Verify** (`passwordPolicy: verify`): `ACL GETUSER` returns SHA-256 hashes of the passwords.
  Ordivus compares `sha256(secret)` with this list, **without a login attempt**. A user with
  `nopass` counts as "password differs" and gets a `SET_PASSWORD`.
- The hashes are read over the session during verification and stored nowhere, not even in
  reports or attributes.

## Protected users

`default` and the user from `spec.username` are system objects: not declared → `IGNORE`, never
deleted; declared → `BLOCKED`. The adapter also refuses changes to them
directly.

## Privileged grants (`allowPrivilegedGrants`)

Privileged is every command (including subcommands) of the Redis categories **`@admin`** and
**`@dangerous`**, as reported by the server via `ACL CAT admin` / `ACL CAT dangerous` – among others
`config`, `acl`, `module`, `debug`, `shutdown`, `monitor`, `replicaof`/`slaveof`, `save`/`bgsave`,
`flushall`/`flushdb`, `keys`, `sort`, `migrate`, `restore`, `cluster …`, `client kill`. Ordivus evaluates
the declared `commands` in order (like Redis); if they then allow one of these commands,
the resource is `BLOCKED` without `allowPrivilegedGrants: true`. This applies to `+@all`/`allcommands`,
`+@admin`, `+@dangerous`, single commands such as `+config`, and also to categories that contain such commands:
`+@read` allows `keys` and is therefore privileged, `+@read +@write -@dangerous` is not.
A subcommand rule `+command|sub` is privileged as soon as `command` is privileged – even if
`ACL CAT` (as with module commands, e.g. `ft.config`) lists only the command without subcommands:
`+ft.config|set`, `+config|set` and `+acl|setuser` are `BLOCKED` without approval.

Only **added** permissions are blocked: if an existing user already has a privileged
command, keeping it does not block. Undeclared admin users stay
`UNMANAGED`. If `ACL CAT` cannot be read, the resource is also `BLOCKED`.

## Required privileges

The admin user needs at least:

```
+ping +info +acl|users +acl|getuser      # plan/drift
+acl|setuser +acl|deluser                # apply
+config|get +acl|save                    # persist: aclSave
+config|get +config|rewrite              # persist: configRewrite
```

For `plan`/`drift`, a user with the first four permissions is sufficient. Independently of that, the
adapter refuses every change over a read-only session.

## Persistence

Caution: `ACL SETUSER`/`ACL DELUSER` change only Redis' **memory**. After a restart,
the changes are gone unless they are saved. `spec.persist` controls what Ordivus does after
**every** change:

| Value | Effect | Prerequisite |
|---|---|---|
| `none` (default) | nothing; persistence is up to the operator | – |
| `aclSave` | `ACL SAVE` | server configured with `aclfile` |
| `configRewrite` | `CONFIG REWRITE` (users end up in `redis.conf`) | server with a configuration file, **without** `aclfile` |

The prerequisite is checked during `apply` before the first change; if it is missing, the run aborts for
this target without changing anything. `plan`/`drift` do not check it. With `aclfile` configured,
`CONFIG REWRITE` does not write users at all (they would be lost on restart while `apply` reports success),
so `configRewrite` is rejected there with a hint to use `aclSave`.

If Redis is started from an ACL file or `redis.conf` that Ordivus does not write (e.g. a
ConfigMap in Kubernetes), the next restart overwrites the changes. In that case you must maintain the source
itself; Ordivus reports the deviation on the next `drift`.

## Limitations

- No selectors, no flags other than `on`/`off` (e.g. `skip-sanitize-payload` is not managed).
- Multiple passwords per user are not supported; `SET_PASSWORD` replaces all of them.
- Redis Cluster: ACLs are per node. Each node must be configured as a separate target.
- No lock: two concurrent `apply` runs against the same server are not protected against
  each other.
- `verify` needs `ACL GETUSER`; if that is not allowed, the result is `UNKNOWN` (no login fallback).
- Without `tls` the connection counts as insecure (warning, `insecureTransport: true`; with operator policy
  `requireTls: true` abort, exit code 11).

## Supported versions

The server version is read with `INFO server` at connect and reported as `serverVersion`
(`Redis 8.0.2`, `Valkey 8.1.0`; Valkey is detected by `server_name:valkey`).

| Server | Status |
|---|---|
| Redis 8.x | tested (integration tests) |
| Redis 7.0 | checked manually (7.0.15) |
| Valkey 8.x | checked manually (8.1) |
| Redis < 7.0 | rejected at connect: `Redis 6.2.24 is not supported (minimum Redis 7.0)` (exit code 13) |

The minimum is Redis 7.0 because the adapter relies on its ACL model (selectors, `ACL GETUSER`
returning keys/channels as rule strings). Valkey reports a Redis-compatible `redis_version`
(7.2.4), which is used for the minimum check. redis-py 5 to 8 is supported; `ACL GETUSER` is parsed
the same for RESP2 (flat list) and RESP3 (map) replies.
