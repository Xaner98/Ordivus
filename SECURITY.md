# Security

## Reporting vulnerabilities

Please do **not** report vulnerabilities as a public issue; report them confidentially via [GitHub Security Advisories](https://github.com/Xaner98/Ordivus/security/advisories/new). Describe the affected version, the configuration and a way to reproduce the problem. You will receive a response as soon as the report has been reviewed.

## Supported versions

Ordivus is alpha software (`0.x`). Security fixes are released only for the latest version.

## Security model in brief

Ordivus works with administrative credentials. It enforces these boundaries itself:

- `plan` and `drift` change neither target systems nor secret stores. Additionally recommended: an identity that has read-only access to the target system.
- Undeclared objects are only reported. Deleting requires a positively bounded scope, complete discovery and the operator policy `allowDelete: true`.
- The configuration cannot grant privileges beyond the operator policy: highly privileged roles, grants and ACL rules (e.g. superuser memberships, `GRANT OPTION`, admin commands) are blocked as long as the operator policy does not set `allowPrivilegedGrants: true`. System objects, Ordivus's own admin login and its roles are always protected.
- Unknown states (missing permissions, timeouts, partial inventories) never lead to deleting, creating or password changes.
- Secrets do not appear in reports, logs or error messages; HTTP clients follow no redirects and send tokens only to the configured endpoint (or via a proxy set through `HTTP(S)_PROXY`; Ordivus reports this as a warning, see [docs/configuration.md](docs/configuration.md#proxy)).

Outside of Ordivus, the responsibility lies with you for:

- **Reviewing the configuration.** Whoever may change the configuration determines which objects are created within the permitted bounds – including the endpoints credentials are sent to. Use TLS with CA verification (`verify-full`) and `requireTls: true` in the operator policy.
- **Protecting the operator policy and the credentials.** Both belong in separately managed, read-only sources.
- **Who may start jobs.** In Kubernetes, anyone who can create jobs or pods in the namespace of the apply template is part of the trust boundary. See [docs/kubernetes.md](docs/kubernetes.md) on separate namespaces and the optional admission policy.
- **Adapter plugins.** Plugins are executable Python code and not a sandbox. Install only trusted packages.
