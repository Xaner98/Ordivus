# Adapter `openbao` – ACL policies

Manages OpenBao ACL policies declaratively (`plan`/`drift`/`apply`). Separate from the
[credential provider `openbao-kv-v2`](../credentials/openbao.md): its own target, its own token.
HashiCorp Vault compatibility is **not tested**.

## Target

```yaml
apiVersion: ordivus.dev/v1alpha1
kind: Target
metadata:
  name: security-openbao
spec:
  adapter: openbao
  endpoint:
    url: https://openbao.internal.example:8200
  tls:
    caFile: /etc/ordivus/openbao-ca.pem      # optional
  protectedPolicies: [break-glass, ordivus-readonly, ordivus-apply]
  authentication:
    credentialRef: openbao-policy-admin      # secret = OpenBao token
```

Like every admin credential, the token comes via `authentication.credentialRef` (e.g. from a
mounted file via the `file` provider). It should **not** be the same identity that the
credential provider uses.

## Kind `OpenBaoPolicy`

```yaml
kind: OpenBaoPolicy
metadata:
  name: analytics-readonly
spec:
  targetRef: security-openbao
  policyName: analytics-readonly     # key; [a-z0-9][a-z0-9_.-]* (OpenBao trims and lowercases names)
  rules:
    - path: secret/data/analytics/*
      capabilities: [read]
```

Alternatively `spec.policy` with raw HCL text (exactly one of `rules`/`policy`).

**Rendering of `rules`:** paths in declared order, capabilities sorted and
deduplicated, two-space indentation, blank line between blocks:

```hcl
path "secret/data/analytics/*" {
  capabilities = ["read"]
}
```

**Comparison:** observed and desired text are canonicalized (uniform line endings,
trailing whitespace and leading/trailing blank lines removed) and then compared. Any other
deviation is `UPDATE`. Semantically equal but differently formatted policies (indentation,
order, comments) therefore appear **once** as `UPDATE`; after that, the Ordivus text is in
OpenBao and the run converges to `NOOP`. No semantic HCL comparison takes place.

Discovery: `GET sys/policies/acl?list=true`, then `GET sys/policies/acl/<name>` per policy.
If the permission is missing (403), the inventory is `forbidden` – never "empty".

## Protection rules (self-escalation / self-lockout, §11.4, F-32)

The following are never changed or deleted:

- `root`, `default`,
- all names from `protectedPolicies` (e.g. break-glass and Ordivus' own policies),
- all policies of the token in use (`GET auth/token/lookup-self`: `policies` and
  `identity_policies`) – this way Ordivus can neither grant itself new permissions nor lock itself out.

OpenBao strips surrounding whitespace and lowercases names (`" Default"` is `default`). Therefore
`policyName` must already be in normal form `[a-z0-9][a-z0-9_.-]*` (otherwise config error), and
`protectedPolicies` is normalized the same way before every comparison (`Break-Glass` protects `break-glass`).

Declared → `BLOCKED` (even without deviation and even if it does not exist yet); not
declared → `IGNORE`, even in authoritative mode. `apply` then ends with exit code 11; the other
policies are still written.

This lock is a second line of defense. The actual boundary is the OpenBao policy
of the apply token: write permissions only on a name range, e.g.

```hcl
path "sys/policies/acl"        { capabilities = ["list"] }
path "sys/policies/acl/app-*"  { capabilities = ["create", "read", "update", "delete"] }
```

Caution: anyone who may write policies that are assigned to other identities can
grant permissions indirectly through them. Control the policy name range and the assignment (auth roles, groups)
separately; keep a break-glass runbook ready.

## Privileged policies (`allowPrivilegedGrants`)

Without operator policy `allowPrivilegedGrants: true`, an `OpenBaoPolicy` is `BLOCKED` (in `apply`
exit 11) if it

- grants the capability `sudo` anywhere,
- allows a path under `sys/` with any capability other than `deny` – also via patterns that
  can match `sys/`: `*`, `s*`, `sy*`, `sys*`, `+/…` or templates such as `{{identity.entity.name}}/…`,
- writes under `auth/` or `identity/` (`create`, `update`, `patch`, `delete`), e.g. creating users
  of an auth method, generating tokens or changing entities/groups. Reading (`read`, `list`)
  stays allowed. Exempt are exactly the paths `auth/token/renew-self`, `auth/token/revoke-self`
  and `auth/token/lookup-self` with `read`/`update`: they only affect the token itself. A pattern such as
  `auth/token/*` stays privileged.

`spec.rules` is checked exactly. Ordivus reads raw HCL in `spec.policy` conservatively: only
blocks `path "…" { capabilities = [ "…", … ] }` and comments (`#`, `//`, `/* */`) are allowed. Anything else
(further block parameters such as `allowed_parameters`, JSON syntax, unknown escapes) Ordivus cannot
assess safely; the policy then counts as privileged. The check does not account for namespaces (paths such as `ns1/sys/…`),
since the adapter only manages the root namespace.

## Read-only

`plan`/`drift` open a read-only session; `apply` is refused in it. This is only a
program-level lock – the real guarantee is a read-only token:

```hcl
path "sys/policies/acl"   { capabilities = ["list"] }
path "sys/policies/acl/*" { capabilities = ["read"] }
```

## Limitations

- ACL policies only; no namespaces, no Sentinel/EGP/RGP policies, no auth methods or
  role assignments.
- No `X-Vault-Namespace` on the target (root namespace only).
- Text comparison instead of semantic HCL comparison (see above).
- `http://` endpoints are not rejected; in production use `https://` with certificate verification.
