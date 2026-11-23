"""Resource-Adapter ``openbao``: ACL-Policies als Zielressourcen (§7.8, §11.4, F-32).

Target-Spec: ``{endpoint: {url}, tls: {caFile?}, protectedPolicies: [names]}``; das Admin-Token
kommt als Secret über ``spec.authentication.credentialRef``. Kind ``OpenBaoPolicy`` mit
``spec.policyName`` und entweder ``spec.rules`` oder ``spec.policy`` (HCL-Text).

Geschützt (nie ändern/löschen): ``root``, ``default``, ``protectedPolicies`` und alle Policies
des eigenen Tokens (Self-Escalation/Self-Lockout). Vom Credential Provider ``openbao-kv-v2``
bewusst getrennt.
"""

import json
import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import quote

from ordivus import openbao_http
from ordivus.adapters import common
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
MIN_VERSION = (2, 0)
log = logging.getLogger("ordivus")
SYSTEM_POLICIES = frozenset({"root", "default"})
CAPABILITY = re.compile(r"^[a-z_]+$")
# OpenBao trimmt und kleinschreibt Namen serverseitig (" Default" == "default"): nur die Normalform zulassen
POLICY_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]*")


def normalize(name: str) -> str:
    """Wie OpenBao Policy-Namen speichert: ohne Rand-Leerraum, kleingeschrieben."""
    return name.strip().lower()


def canonical(text: str) -> str:
    """Vergleichsform: einheitliche Zeilenenden, ohne Leerraum am Zeilenende und Leerzeilen am Rand."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n")


# Ohne allowPrivilegedGrants gesperrt: sudo überall, jeder Pfad unter sys/, Schreibrechte unter auth/ und identity/
WRITE = frozenset({"create", "update", "patch", "delete", "sudo"})
GUARDED = (("sys/", None), ("auth/", WRITE), ("identity/", WRITE))  # (Präfix, Capabilities; None = alle)
# wirken nur auf das eigene Token: exakt diese Pfade (kein Glob) mit read/update sind nicht privilegiert
SELF_TOKEN = frozenset({"auth/token/renew-self", "auth/token/revoke-self", "auth/token/lookup-self"})
# Konservativer HCL-Parser: nur ``path "…" { capabilities = [...] }`` und Kommentare; alles andere = unklar
STRING = r'"(?:[^"\\\n]|\\.)*"'
HCL_BLOCK = re.compile(r"path\s+(" + STRING + r")\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}")
HCL_COMMENT = re.compile(STRING + r"|(?:#|//)[^\n]*|/\*.*?\*/", re.S)  # Strings zuerst: "#" darin ist kein Kommentar
HCL_CAPS = re.compile(r'\s*"([a-z_]+)"\s*(,\s*"([a-z_]+)"\s*)*,?\s*')


def may_match(pattern: str, prefix: str) -> bool:
    """Ob der Policy-Pfad ``pattern`` (``*`` am Ende, ``+`` = ein Segment) einen Pfad unter ``prefix`` trifft."""
    i = 0
    for ch in pattern:
        if i == len(prefix) or ch == "*":
            return True
        if ch == "+":
            i = prefix.find("/", i)  # Segment-Wildcard: bis zum nächsten / im Präfix
            if i == -1:
                return True
            continue
        if ch != prefix[i]:
            return False
        i += 1
    return i == len(prefix)


def parse(text: str) -> list[tuple[str, list[str]]] | None:
    """[(Pfad, Capabilities)] oder None, wenn der Text nicht sicher verstanden wird (dann gilt er als privilegiert)."""
    rest = HCL_COMMENT.sub(lambda m: m.group(0) if m.group(0).startswith('"') else " ", text)
    rules = []
    for m in HCL_BLOCK.finditer(rest):
        try:
            path = json.loads(m.group(1))
        except ValueError:  # HCL-Escape, das JSON nicht kennt
            return None
        if not HCL_CAPS.fullmatch(m.group(2)):
            return None
        rules.append((path, re.findall(r'"([a-z_]+)"', m.group(2))))
    return rules if HCL_BLOCK.sub("", rest).strip() == "" else None


def privileged(text: str) -> str | None:
    """Grund, warum die Policy privilegiert ist, sonst None."""
    rules = parse(text)
    if rules is None:
        return "policy text is not plain 'path \"...\" { capabilities = [...] }' blocks and cannot be checked"
    for path, caps in rules:
        if "sudo" in caps:
            return f"path {path!r} grants sudo"
        # Templates ({{identity.entity.name}} …) können zu beliebigen Segmenten werden: wie * behandeln
        pattern = re.sub(r"\{\{.*?\}\}", "*", path).lstrip("/")
        grants = set(caps) - {"deny"}
        if pattern in SELF_TOKEN and grants <= {"read", "update"}:
            continue
        for prefix, guarded in GUARDED:
            if may_match(pattern, prefix) and grants & (guarded or grants):
                return f"path {path!r} may match {prefix}* with {sorted(grants)}"
    return None


def _data(body: dict, what: str) -> dict:
    data = body.get("data")
    if not isinstance(data, dict):
        raise PermanentError(f"{what}: unexpected response (no 'data' object)")
    return data


def server_version(status: dict) -> str | None:
    """Produkt und Version aus ``sys/seal-status``; zu alte OpenBao-Versionen → PermanentError.

    HashiCorp Vault (``build_date`` statt ``commit_date``) wird nur gemeldet: die genutzte API
    (``sys/policies/acl``, ``auth/token/lookup-self``) ist dort gleich, aber ungetestet.
    """
    version = status.get("version")
    if not isinstance(version, str) or not version:
        return None
    if "build_date" in status and "commit_date" not in status:
        log.warning("target is HashiCorp Vault %s, not OpenBao: untested", version)
        return f"Vault {version}"
    m = re.match(r"v?(\d+)\.(\d+)", version)
    if m and tuple(map(int, m.groups())) < MIN_VERSION:
        raise PermanentError(f"OpenBao {version} is not supported (minimum {'.'.join(map(str, MIN_VERSION))})")
    return f"OpenBao {version}"


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
    version: str | None = None

    def call(self, method, path, body=None, what=""):
        return openbao_http.check(*openbao_http.request(self.url, method, path, self.token, body, ctx=self.ctx),
                                  what or f"{method} {path}")


class OpenBaoAdapter(Adapter):
    id = "openbao"
    api_version = 1
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
        if not isinstance(name, str) or not POLICY_NAME.fullmatch(name):
            errors.append("spec.policyName must match [a-z0-9][a-z0-9_.-]* (OpenBao trims and lowercases names)")
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

    def export(self, resource):
        return {"policyName": resource.id, "policy": resource.attrs["policy"]}

    def insecure_transport(self, target):
        return target["endpoint"]["url"].startswith("http://")

    def check(self, session, resource, allow_privileged=False):
        # auch noch nicht existierende geschützte Namen schon im Plan sperren, nicht erst beim Schreiben
        if normalize(resource.id) in session.protected:
            return f"policy {resource.id!r} is protected"
        if not allow_privileged and (why := privileged(resource.attrs["policy"])):
            return f"privileged policy ({why}) requires operator policy allowPrivilegedGrants"
        return None

    @contextmanager
    def connect(self, target, secret, write):
        if secret is None:
            raise PermanentError("openbao target requires spec.authentication.credentialRef (admin token)")
        session = Session(target["endpoint"]["url"], secret.reveal(), common.tls_context(target.get("tls")),
                          write, frozenset())
        session.version = server_version(session.call("GET", "sys/seal-status", what="seal-status"))
        me = _data(session.call("GET", "auth/token/lookup-self", what="token lookup-self"), "token lookup-self")
        own = set()
        for key in ("policies", "identity_policies"):
            names = me.get(key) or []
            if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                raise PermanentError(f"token lookup-self: unexpected {key!r}")
            own |= set(names)
        session.protected = frozenset(map(normalize, SYSTEM_POLICIES | set(target.get("protectedPolicies", [])) | own))
        yield session

    def server_version(self, session):
        return session.version

    def discover(self, session, kind, scope):
        what = "list acl policies"
        names = _data(session.call("GET", "sys/policies/acl?list=true", what=what), what).get("keys")
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise PermanentError(f"{what}: unexpected response (no 'keys' list)")
        resources = []
        for name in sorted(names):
            what = f"read policy {name!r}"
            policy = _data(session.call("GET", f"sys/policies/acl/{quote(name, safe='')}", what=what), what).get(
                "policy") or ""
            if not isinstance(policy, str):
                raise PermanentError(f"{what}: unexpected response ('policy' is not text)")
            resources.append(Resource(KIND, name, {"policy": canonical(policy)},
                                      system=normalize(name) in session.protected))
        return Discovery(COMPLETE, resources)

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        # zweite Sperre neben system=True, z. B. für noch fehlende geschützte Namen
        if normalize(op.id) in session.protected or not POLICY_NAME.fullmatch(op.id):
            raise PermanentError(f"policy {op.id!r} is protected")
        path = f"sys/policies/acl/{quote(op.id, safe='')}"
        if op.action in (CREATE, UPDATE):
            session.call("PUT", path, {"policy": op.desired.attrs["policy"]}, f"write policy {op.id!r}")
        elif op.action == DELETE:
            session.call("DELETE", path, what=f"delete policy {op.id!r}")
        else:
            raise PermanentError(f"action {op.action} not supported for {KIND}")
