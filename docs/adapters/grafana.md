# Grafana adapter (`grafana`, beta)

Manages teams, folders (with team/role permissions) and service accounts of **one Grafana
organisation** through the HTTP API. No additional dependency: the adapter uses only the Python
standard library.

**Supported versions:** Grafana 10.0 or newer (tested: 12.2.0). The version is read from
`buildInfo.version` of `GET /api/frontend/settings` on connect and reported as `serverVersion`
(e.g. `Grafana 12.2.0`); older or unreadable versions are rejected as a target error. The minimum
is 10.0 because the adapter relies on APIs that are stable from there on: the access-control
endpoints for folder permissions (`/api/access-control/folders/…`), the service-account API and the
basic role `None`. Grafana 9.x is end of life.

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: observability-grafana
spec:
  adapter: grafana
  endpoint:
    host: grafana.monitoring.svc.cluster.local
    port: 3000            # default 3000
    tls:                  # present → https; without tls → http (insecure, see requireTls)
      caFile: /trust/ca.pem   # optional, otherwise system CAs
  orgId: 1                # default 1; sent as X-Grafana-Org-Id
  # username: admin       # optional: basic auth with the secret as password
  authentication:
    credentialRef: grafana-admin-token
  scope:                  # optional; objects outside are not read/reported
    teams:
      include: ["platform-*"]           # by team name
    folders:
      include: ["platform-*"]           # by folder uid
    serviceAccounts:
      include: ["platform-*"]           # by service account name
```

Authentication:

- **Service account token (preferred):** without `username`, the secret is sent as
  `Authorization: Bearer <token>`. The token is bound to its organisation; `orgId` must match.
- **Basic auth:** with `username`, the secret is the user's password.

Every request carries `X-Grafana-Org-Id: <orgId>`. On connect the adapter checks via `GET /api/org`
that Grafana really answers for this organisation (mismatch → target error). Grafana rejects requests
for organisations the identity does not belong to. The token or password never appears in URLs,
logs or error messages.

Declared resources must lie inside `spec.scope` (otherwise config error): Ordivus would never see
an existing object outside the scope and would try to create it again.

## Kinds

Creation order: `GrafanaTeam`, `GrafanaFolder`, `GrafanaServiceAccount`; deletions in reverse.
Only declared fields are compared and changed; a field you leave out is not managed.

### `GrafanaTeam`

| Field | Type | Meaning |
|---|---|---|
| `email` | string | Team email. |
| `members` | list of logins | **Complete** member list (regular members and team admins). Users must already exist in the organisation; Ordivus never creates users. An unknown login makes the team `BLOCKED`. |

`metadata.name` is the team name.

```yaml
kind: GrafanaTeam
metadata:
  name: platform-sre
spec:
  targetRef: observability-grafana
  email: sre@example.com
  members: [alice, bob]
```

Notes:

- Grafana adds the creating identity to a new team. If `members` is declared, Ordivus removes it
  again right after creation; without `members` it stays.
- New members are added as regular members. Existing team admins listed in `members` keep their
  team-admin flag; team admins not listed are removed from the team.
- Teams with `isProvisioned: true` are reported as not manageable (`manageable: false`).

### `GrafanaFolder`

| Field | Type | Meaning |
|---|---|---|
| `title` | string | **Required.** Folder title. |
| `permissions` | list | Direct permissions for teams and basic roles: `{team: <name>, permission: View\|Edit\|Admin}` or `{role: Viewer\|Editor, permission: View\|Edit\|Admin}`. |

`metadata.name` is the folder **uid** (`[A-Za-z0-9_-]`, max. 40 characters).

```yaml
kind: GrafanaFolder
metadata:
  name: platform-dashboards
spec:
  targetRef: observability-grafana
  title: Platform
  permissions:
    - team: platform-sre
      permission: Edit
    - role: Viewer
      permission: View
```

Comparison semantics for `permissions`:

- `permissions` missing → permissions are not managed.
- Declared → the list of **direct team and basic-role entries** must match exactly; other team/role
  entries are removed (`POST /api/access-control/folders/<uid>/…` with an empty permission).
  Permissions for individual users and service accounts, inherited entries (from parent folders) and
  Grafana's fixed `Admin` role entry are never read as part of this list and never changed.
- On creation Grafana adds default entries (`Editor: Edit`, `Viewer: View`, the creator as `Admin`).
  If `permissions` is declared, Ordivus brings the team/role entries to the declared state right after
  creation; the creator's user entry stays.
- A team named in `permissions` must exist when the folder is applied (declared in the same run is fine:
  teams are created first).

New folders are created at the top level. Nested folders are discovered and can be managed (title,
permissions), but Ordivus does not set or change the parent.

> **Deleting a folder deletes everything in it.** A folder `DELETE` (only in `authoritative` mode
> with `allowAuthoritative` and `allowDelete`) also deletes **all dashboards and
> subfolders** inside it, without a backup. Ordivus does not pass `forceDeleteRules`, so Grafana
> refuses to delete a folder that still contains **alert rules** (`HTTP 400 folder is not empty` →
> the operation fails, nothing is deleted). Restrict authoritative folder management with
> `scope.folders` and `ReconciliationPolicy` scope/exclusions.

### `GrafanaServiceAccount`

| Field | Type | Meaning |
|---|---|---|
| `role` | `None`, `Viewer`, `Editor`, `Admin` | Organisation role of the service account. |
| `isDisabled` | bool | Disabled service accounts cannot authenticate. |

`metadata.name` is the service account name.

```yaml
kind: GrafanaServiceAccount
metadata:
  name: platform-ci
spec:
  targetRef: observability-grafana
  role: Editor
  isDisabled: false
```

**Tokens are out of scope.** A service-account token is a secret that Grafana shows exactly once, at
creation, and can never be read back. Ordivus could therefore neither verify a token nor detect drift,
and creating tokens would require writing a secret on every run that cannot be reconciled
(no `verify` possible, only "create another one"). Create tokens with a separate, audited process and
store them in your secret store. Deleting a service account (authoritative mode) also revokes all its
tokens.

## Discovery

| Kind | Source | `complete` only if the identity has |
|---|---|---|
| `GrafanaTeam` | `GET /api/teams/search` (paged), `GET /api/teams/<id>/members` | `teams:read` on `teams:*` |
| `GrafanaFolder` | `GET /api/search?type=dash-folder` (paged, all levels), `GET /api/folders/<uid>`, `GET /api/access-control/folders/<uid>` | `folders:read` on `folders:*` |
| `GrafanaServiceAccount` | `GET /api/serviceaccounts/search` (paged) | `serviceaccounts:read` on `serviceaccounts:*` |

Grafana's search APIs silently return only the objects the identity may see. The adapter therefore
reads the identity's own permissions (`GET /api/access-control/user/permissions`) on connect and
reports a kind as `partial` unless the identity can read all objects of that kind; then there is
neither `CREATE` nor `DELETE` for it. HTTP 401/403 → `forbidden`.

## Required permissions

- `plan`/`drift`: a service account with org role **Viewer** plus read access to all teams, folders
  and service accounts – in practice org role **Admin** is the simplest choice; resolving team members
  needs `org.users:read`.
- `apply`: org role **Admin** in the target organisation (team, folder, folder-permission and
  service-account administration). Grafana server admin is **not** required and not recommended.

Use a separate read-only identity for `plan`/`drift` where possible.

## Protected objects

- The built-in **General** folder (`general`) and the virtual `sharedwithme` folder: declared →
  `BLOCKED`, never changed or deleted.
- **Ordivus' own service account** (when authenticating with a service-account token): reported as a
  system object (`IGNORE`), declared → `BLOCKED`, even with `allowPrivilegedGrants`.
- External service accounts managed by plugins (`isExternal`) are system objects.
- Folders managed by Git Sync/provisioning (`managedBy` set) and provisioned teams are reported as not
  manageable (`UNMANAGED`, declared → `BLOCKED`).
- `DELETE` only in `authoritative` mode with operator approval (`allowAuthoritative`, `allowDelete`)
  and complete discovery.

## Privileged grants (`allowPrivilegedGrants`)

Without `allowPrivilegedGrants: true` in the operator policy, these are `BLOCKED`:

- `GrafanaServiceAccount` with `role: Admin` (organisation administration).
- `GrafanaFolder` with any `permission: Admin` entry (holders may change the folder's permissions and
  hand out access themselves).

The adapter does not manage anything that requires Grafana **server admin** (users, organisations,
server settings). Team membership is not treated as privileged; note that adding a user to a team
grants all folder permissions of that team.

## Read-only guarantee

`plan`/`drift` open read-only sessions. In them, the adapter refuses every HTTP method except `GET`
as well as every `apply` call (`PermanentError`) before a request reaches the network.

## Error mapping

| Cause | Error |
|---|---|
| Timeout, connection error, HTTP 5xx/429 | `TransientError` |
| HTTP 401/403 | `AuthorizationError` |
| other 4xx, invalid JSON, unexpected response shape, unreadable `caFile`, redirect | `PermanentError` |

Error messages contain the method, path, status and at most 200 characters of Grafana's `message`
field – never the token or password. Idempotency: deleting a team, folder, service account or team
member that no longer exists (404) counts as success.

## Limitations

- One organisation per target; for several organisations declare one target per `orgId`.
- Grafana served under a sub-path (`root_url` with path, e.g. behind `/grafana`) is not supported.
- No users, organisations, dashboards, data sources, alerting or service-account tokens.
- Folder permissions only for teams and the basic roles `Viewer`/`Editor`; user-level permissions
  are left untouched. No parent (`parentUid`) management.
- Team and service-account names are matched case-sensitively.
- Team sync (Enterprise, `externalUID`) is not considered; synced members may be re-added by Grafana.
- No locking (`lock`): parallel runs against the same organisation are not protected against each other.
