# Keycloak adapter (`keycloak`, beta)

Manages realms, realm roles, top-level groups and OpenID Connect clients of a Keycloak server through
the Admin REST API. No additional dependency: the adapter uses only the Python standard library.

> **Deleting a `KeycloakRealm` deletes everything in it** – users, credentials, sessions, clients, roles,
> groups, identity providers. Ordivus only deletes a realm in `authoritative` mode with `KeycloakRealm` in
> `scope.resourceKinds`, operator approval (`allowAuthoritative`, `allowDelete`) and a complete inventory.
> Keep `KeycloakRealm` out of `resourceKinds` unless you really want undeclared realms removed.

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: shop-keycloak
spec:
  adapter: keycloak
  endpoint:
    host: keycloak.iam.svc.cluster.local
    port: 8443            # default 8443 with tls, 8080 without
    path: /auth           # optional, Keycloak's --http-relative-path
    tls:                  # present → https; without tls → http (insecure, see requireTls)
      caFile: /trust/ca.pem   # optional, otherwise system CAs
  login:
    realm: shop           # default master
    clientId: ordivus     # client credentials grant (service account) …
    # username: admin     # … or password grant via the client admin-cli (exactly one of both)
  authentication:
    credentialRef: keycloak-ordivus   # client secret (clientId) or password (username)
  scope:                  # optional; objects outside are not read/reported
    realms:
      include: ["shop"]
    roles:                # also groups, clients; matched against the object name
      include: ["app-*"]
```

Ordivus requests an access token from `/realms/<login.realm>/protocol/openid-connect/token`. The
secret is sent only in that request's form body; the token only in the `Authorization` header. Tokens
are renewed shortly before they expire and once after a `401`. A rejected login is a target error
(exit code 13). Note that every run is a login: Keycloak records a login event and, for the password
grant, a short-lived user session – this is not a configuration change.

Resource ids are `<realm>/<name>` (roles, groups) and `<realm>/<clientId>` (clients); a realm's id is its
name. `ReconciliationPolicy` globs match these ids, e.g. `KeycloakRealmRole: {glob: ["shop/app-*"]}`.

## Kinds

Creation order: `KeycloakRealm`, `KeycloakRealmRole`, `KeycloakGroup`, `KeycloakClient`; deletions in
reverse. Roles referenced in `composites`/`realmRoles` are created first.

Only declared fields are compared and changed. Because Keycloak's `PUT` replaces whole representations,
Ordivus reads the current representation, changes only the declared fields and writes it back; role
attributes, client scopes, protocol mappers, realm settings etc. that you do not declare stay as they are.
Lists (`composites`, `realmRoles`, `redirectUris`, `webOrigins`) are compared as sorted sets.

### `KeycloakRealm`

`metadata.name` is the realm name (`[A-Za-z0-9][A-Za-z0-9_.-]*`, max. 100).

| Field | Type |
|---|---|
| `enabled` | bool – **Keycloak creates realms disabled** unless you declare `enabled: true` |
| `displayName` | string |
| `registrationAllowed`, `resetPasswordAllowed`, `rememberMe`, `verifyEmail`, `loginWithEmailAllowed` | bool |
| `sslRequired` | `none` \| `external` \| `all` |

### `KeycloakRealmRole`

| Field | Type | Meaning |
|---|---|---|
| `realm` | string, required | realm of the role |
| `name` | string | role name, default `metadata.name` |
| `description` | string | |
| `composites` | list of realm role names | realm roles contained in this role (same realm). Client-role composites are neither read nor changed. |

### `KeycloakGroup`

Top-level groups only (no subgroups, no `/` in the name).

| Field | Type | Meaning |
|---|---|---|
| `realm` | string, required | |
| `name` | string | group name, default `metadata.name` |
| `realmRoles` | list of realm role names | realm role mappings of the group. Client role mappings, attributes and members are not managed. |

### `KeycloakClient`

OpenID Connect clients. Existing SAML clients are reported as not manageable.

| Field | Type |
|---|---|
| `realm` | string, required |
| `clientId` | string, default `metadata.name` |
| `enabled`, `publicClient`, `standardFlowEnabled`, `directAccessGrantsEnabled`, `serviceAccountsEnabled` | bool |
| `protocol` | only `openid-connect` |
| `redirectUris`, `webOrigins` | list of strings |
| `credentials` | engine field: client secret of a confidential client |

Client secret (`spec.credentials`, only with `publicClient: false`; `publicClient: true` with credentials is a
config error):

- Create: the secret from the credential is passed when the client is created.
- `SET_PASSWORD`: the secret is written into the client representation (read–merge–`PUT`).
- `verify`: `GET …/clients/<id>/client-secret` is compared in constant time with the credential.
  No login attempt, so no brute-force lockout. A client without a readable secret (public, JWT
  authentication) → `unknown`.
- `enforce` / `set-on-create` behave as described in [configuration](../configuration.md).

Service accounts' own role mappings are not managed.

## Discovery

| Kind | Source | `complete` requires |
|---|---|---|
| `KeycloakRealm` | `GET /admin/realms` (login in master) or the login realm itself | login in master with the realm role `admin`; a login in another realm always sees only its realm → `partial` |
| `KeycloakRealmRole` | `GET …/roles` (paged), composites via `roles-by-id/<id>/composites` | `view-realm` or `manage-realm` |
| `KeycloakGroup` | `GET …/groups?briefRepresentation=false` (paged, top level) | `view-users` or `manage-users` |
| `KeycloakClient` | `GET …/clients` (paged; secrets are never put into the report) | `view-clients` or `manage-clients` |

Keycloak **filters** some lists by the caller's permissions instead of answering 403. Ordivus therefore
reads its own effective role mappings (the access token of `admin-cli` contains no roles) and reports a kind
as `partial` when the required admin roles in a realm are missing or cannot be read. A 401/403 response is
`forbidden`. With `partial`/`forbidden` there is neither `CREATE` nor `DELETE` for the kind.

A login in a realm other than `master` can only manage that realm; resources in other realms are a
config error.

## Required permissions

Recommended: a dedicated confidential client with service account in the managed realm, e.g. `ordivus`,
with these client roles of `realm-management`:

| Purpose | Roles |
|---|---|
| `plan`/`drift` | `view-realm`, `view-users`, `view-clients` |
| `apply` | additionally `manage-realm`, `manage-users` (groups), `manage-clients` |

`view-users` is also needed so that Ordivus can read its own role mappings. Creating or deleting realms
requires a login in `master` with the `admin` role (only then is the realm list complete) – use this
only where needed.

For `plan`/`drift` in CI, use a separate identity with only the `view-*` roles.

## Protected objects

System objects are never changed or deleted (not declared → `IGNORE`, declared → `BLOCKED`, even with
`allowPrivilegedGrants`):

- the `master` realm,
- built-in roles `default-roles-<realm>`, `offline_access`, `uma_authorization`, and `admin`/`create-realm` in master,
- built-in clients `account`, `account-console`, `admin-cli`, `broker`, `realm-management`,
  `security-admin-console`, all realm administration clients (`<realm>-realm` in master),
- Ordivus' own login client and every realm role the Ordivus login holds in its login realm (if these
  cannot be read, all roles of the login realm are protected).

## Privileged grants (`allowPrivilegedGrants`)

Without `allowPrivilegedGrants: true` in the operator policy these become `BLOCKED`:

- any role mapping in the `master` realm (`realmRoles` of a group, `composites` of a role),
- a group or composite that contains, directly or through other composites, a role with realm
  administration client roles (`realm-management`, or `<realm>-realm` in master) – or a role whose
  client composites cannot be classified or whose realm's roles could not be read,
- a `KeycloakClient` whose existing service account holds such roles (declaring it would let the
  configuration control an admin identity, e.g. its secret).

## Read-only guarantee

`plan`/`drift` open read-only sessions. In them, the adapter refuses every HTTP method except `GET` (and
the token request) as well as every `apply` call (`PermanentError`) before a request reaches the network.

## Error mapping

| Cause | Error |
|---|---|
| Timeout, connection error, HTTP 5xx/429 | `TransientError` |
| HTTP 401/403, rejected login | `AuthorizationError` |
| other 4xx, invalid JSON, redirects, unreadable `caFile` | `PermanentError` |

Error messages contain Keycloak's `errorMessage`/`error` field, never request bodies, tokens or secrets.
Creating an object that already exists (409) and deleting one that is gone (404) count as success, the
result is verified by re-reading.

## Supported versions

Minimum **Keycloak 24**, tested with **26.4**. The version is read from `GET /admin/serverinfo`
(`systemInfo.version`) and reported as `serverVersion` ("Keycloak 26.4.7"); older versions abort the
target. Below 24 the admin API differs in details the adapter relies on (top-level group listing, the
`realm_client` attribute of administration clients), and those versions are no longer supported upstream.
If the version is not readable (non-master logins may lack `view-system`), a warning is logged.

## Limitations

- **Users are not managed** – they usually come from an identity provider or user federation. Nor are
  group memberships, subgroups, client roles, client scopes, protocol mappers, identity providers or
  authentication flows.
- Composites and role mappings of client roles are only evaluated for the privilege check, never changed.
- Fine-grained admin permissions (FGAP) are not evaluated; with FGAP-only permissions discovery is `partial`.
- No locking (`lock`): parallel runs against the same realm are not protected against each other.
