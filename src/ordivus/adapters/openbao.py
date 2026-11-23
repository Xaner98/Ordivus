"""Resource-Adapter ``openbao``: ACL-Policies als Zielressourcen (§7.8, §11.4, F-32).

Target-Spec: ``{endpoint: {url}, tls: {caFile?}, protectedPolicies: [names]}``; das Admin-Token
kommt als Secret über ``spec.authentication.credentialRef``. Kind ``OpenBaoPolicy`` mit
``spec.policyName`` und entweder ``spec.rules`` oder ``spec.policy`` (HCL-Text).

Geschützt (nie ändern/löschen): ``root``, ``default``, ``protectedPolicies`` und alle Policies
des eigenen Tokens (Self-Escalation/Self-Lockout). Vom Credential Provider ``openbao-kv-v2``
bewusst getrennt.
"""

import json
import re
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import quote

from ordivus import openbao_http
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    UPDATE,
    Adapter,
    Discovery,
    Op,
    PermanentError,
    Resource,
)

KIND = "OpenBaoPolicy"
SYSTEM_POLICIES = frozenset({"root", "default"})
CAPABILITY = re.compile(r"^[a-z_]+$")


def canonical(text: str) -> str:
    """Vergleichsform: einheitliche Zeilenenden, ohne Leerraum am Zeilenende und Leerzeilen am Rand."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n")


def render(rules: list[dict]) -> str:
    """HCL aus ``rules``: Pfade in deklarierter Reihenfolge, Capabilities sortiert und dedupliziert."""
    return "\n\n".join(
        f"path {json.dumps(r['path'], ensure_ascii=False)} {{\n"
        f"  capabilities = {json.dumps(sorted(set(r['capabilities'])))}\n}}" for r in rules)


@dataclass
class Session:
    url: str
    token: str
    ctx: object
    write: bool
    protected: frozenset[str]

    def call(self, method, path, body=None, what=""):
        return openbao_http.check(*openbao_http.request(self.url, method, path, self.token, body, ctx=self.ctx),
                                  what or f"{method} {path}")


class OpenBaoAdapter(Adapter):
    id = "openbao"
    kinds = (KIND,)

    def validate(self, doc):
        spec = doc.get("spec") or {}
        if doc["kind"] == "Target":
            errors = [f"unknown field spec.{k}" for k in spec if k not in {"endpoint", "tls", "protectedPolicies"}]
            endpoint = spec.get("endpoint")
            if not isinstance(endpoint, dict) or set(endpoint) != {"url"} or \
                    not str(endpoint["url"]).startswith(("https://", "http://")):
                errors.append("spec.endpoint must be a mapping with an http(s) url")
            tls = spec.get("tls", {})
            if not isinstance(tls, dict) or set(tls) - {"caFile"} or not all(isinstance(v, str) for v in tls.values()):
                errors.append("spec.tls must be a mapping with optional string caFile")
            protected = spec.get("protectedPolicies", [])
            if not isinstance(protected, list) or not all(isinstance(p, str) and p for p in protected):
                errors.append("spec.protectedPolicies must be a list of policy names")
            return errors
        errors = [f"unknown field spec.{k}" for k in spec if k not in {"policyName", "rules", "policy"}]
        name = spec.get("policyName")
        if not isinstance(name, str) or not name or name != name.lower() or "/" in name:
            errors.append("spec.policyName must be a non-empty lowercase name without '/' (OpenBao lowercases names)")
        if ("rules" in spec) == ("policy" in spec):
            return [*errors, "exactly one of spec.rules or spec.policy is required"]
        if "policy" in spec:
            return errors if isinstance(spec["policy"], str) and spec["policy"].strip() else \
                [*errors, "spec.policy must be non-empty HCL text"]
        rules = spec["rules"]
        if not isinstance(rules, list) or not rules:
            return [*errors, "spec.rules must be a non-empty list"]
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict) or set(rule) != {"path", "capabilities"}:
                errors.append(f"spec.rules[{i}] must have exactly 'path' and 'capabilities'")
            elif not isinstance(rule["path"], str) or not rule["path"] or "\n" in rule["path"]:
                errors.append(f"spec.rules[{i}].path must be a non-empty single-line string")
            elif not isinstance(rule["capabilities"], list) or not rule["capabilities"] or not all(
                    isinstance(c, str) and CAPABILITY.match(c) for c in rule["capabilities"]):
                errors.append(f"spec.rules[{i}].capabilities must be a non-empty list of capability names")
        return errors

    def desired(self, doc):
        spec = doc["spec"]
        text = spec["policy"] if "policy" in spec else render(spec["rules"])
        return Resource(KIND, spec["policyName"], {"policy": canonical(text)})

    @contextmanager
    def connect(self, target, secret, write):
        if secret is None:
            raise PermanentError("openbao target requires spec.authentication.credentialRef (admin token)")
        session = Session(target["endpoint"]["url"], secret.reveal(), openbao_http.tls_context(target.get("tls")),
                          write, frozenset())
        me = session.call("GET", "auth/token/lookup-self", what="token lookup-self").get("data") or {}
        own = set(me.get("policies") or []) | set(me.get("identity_policies") or [])
        session.protected = SYSTEM_POLICIES | set(target.get("protectedPolicies", [])) | own
        yield session

    def discover(self, session, kind, scope):
        names = session.call("GET", "sys/policies/acl?list=true", what="list acl policies")["data"]["keys"]
        resources = []
        for name in sorted(names):
            data = session.call("GET", f"sys/policies/acl/{quote(name, safe='')}", what=f"read policy {name!r}")
            resources.append(Resource(KIND, name, {"policy": canonical(data["data"].get("policy") or "")},
                                      system=name in session.protected))
        return Discovery(COMPLETE, resources)

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        if op.id in session.protected:  # zweite Sperre neben system=True, z. B. für noch fehlende geschützte Namen
            raise PermanentError(f"policy {op.id!r} is protected")
        path = f"sys/policies/acl/{quote(op.id, safe='')}"
        if op.action in (CREATE, UPDATE):
            session.call("PUT", path, {"policy": op.desired.attrs["policy"]}, f"write policy {op.id!r}")
        elif op.action == DELETE:
            session.call("DELETE", path, what=f"delete policy {op.id!r}")
        else:
            raise PermanentError(f"action {op.action} not supported for {KIND}")
