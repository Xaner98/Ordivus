"""RabbitMQ-Adapter über die Management-HTTP-API (nur Standardbibliothek).

Target-Spec: ``endpoint: {host, port (15672), tls: {caFile}}``, ``username`` (Pflicht),
optional ``scope: {vhosts: {include: [glob]}, users: {include: [glob]}}``.
Kinds: ``VirtualHost`` (keine Felder), ``MessagingUser`` (``tags: [..]``,
``permissions: {vhost: {configure, write, read}}``).

Rechte sind Attribute des Benutzers (wie ArcadeDBs ``databases``): je vhost genau ein Regex-Tripel.
Achtung RabbitMQ: ``PUT /api/users/<name>`` ohne ``password``/``password_hash`` löscht das Passwort
eines bestehenden Benutzers. Tag-Änderungen senden daher den aktuellen Hash mit, Passwortänderungen
die aktuellen Tags.
"""

import base64
import http.client
import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import quote

from ordivus import net
from ordivus.adapters import common
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    PARTIAL,
    SET_PASSWORD,
    UPDATE,
    Adapter,
    Discovery,
    Op,
    PermanentError,
    Resource,
    Secret,
    TransientError,
)

VHOST, USER = "VirtualHost", "MessagingUser"
DEFAULT_VHOST = "/"
MIN_VERSION = (3, 13)
# administrator: alles inkl. Benutzerverwaltung; policymaker: Policies/Parameter (Shovel/Federation
# mit Ziel-URIs) in den eigenen vhosts; monitoring: liest alle vhosts, Verbindungen, Kanäle, Knoten;
# impersonator: darf fremde user-id in Nachrichten setzen
PRIVILEGED_TAGS = frozenset({"administrator", "policymaker", "monitoring", "impersonator"})
PERMISSION_FIELDS = ("configure", "write", "read")
TIMEOUT = 30
log = logging.getLogger("ordivus")


@dataclass
class Session:
    base: str
    context: ssl.SSLContext | None
    username: str
    auth: str
    write: bool
    version: str | None = None
    tags: list = field(default_factory=list)


def _base(target: dict) -> tuple[str, ssl.SSLContext | None]:
    endpoint = target["endpoint"]
    tls = endpoint.get("tls")
    host = endpoint["host"]
    host = f"[{host}]" if ":" in host else host
    scheme = "https" if tls is not None else "http"
    return f"{scheme}://{host}:{endpoint.get('port', 15672)}", None if tls is None else common.tls_context(tls)


def _basic(username: str, password: Secret | None) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password.reveal() if password else ''}".encode()).decode()


def _path(*parts: str) -> str:
    """API-Pfad mit vollständig kodierten Segmenten (vhost ``/`` → ``%2F``)."""
    return "/api/" + "/".join(quote(p, safe="") for p in parts)


def _call(base, context, auth, method, path, body=None):
    """Ein HTTP-Aufruf; liefert (Status, JSON). Wirft AdapterError ohne Secret-Inhalte."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=data, method=method, headers={
        "Authorization": auth, "Content-Type": "application/json", "Accept": "application/json"})
    where = f"{method} {path}"
    try:
        with net.urlopen(request, TIMEOUT, context) as response:
            return response.status, json.loads(net.read(response) or b"null")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(net.read(e) or b"null")
        except ValueError:
            payload = None
        return e.code, payload
    except (TimeoutError, urllib.error.URLError, ConnectionError, http.client.HTTPException) as e:
        raise TransientError(f"{where}: {type(e).__name__}: {getattr(e, 'reason', e)}") from None
    except ValueError as e:
        raise PermanentError(f"{where}: invalid JSON response ({type(e).__name__})") from None


def _reason(payload) -> str | None:
    return payload.get("reason") or payload.get("error") if isinstance(payload, dict) else None


def _list(payload, where: str) -> list[dict]:
    """Liste von Objekten mit ``name``/``user``; jede andere Form ist ein Fehler, nie eine leere Liste."""
    if not isinstance(payload, list) or not all(isinstance(x, dict) for x in payload):
        raise PermanentError(f"{where}: unexpected response (no list of objects)")
    return payload


def _tags(tags) -> list[str]:
    return sorted(set(tags))


def _permissions(perms: dict) -> dict:
    return {v: {f: p[f] for f in PERMISSION_FIELDS} for v, p in sorted(perms.items())}


def version_check(version) -> str | None:
    """``rabbitmq_version`` aus ``/api/overview`` → ``"RabbitMQ x.y.z"``; zu alt → PermanentError."""
    if not isinstance(version, str) or not version:
        return None
    m = re.match(r"(\d+)\.(\d+)", version)
    if m and tuple(map(int, m.groups())) < MIN_VERSION:
        raise PermanentError(f"RabbitMQ {version} is not supported (minimum {'.'.join(map(str, MIN_VERSION))})")
    return f"RabbitMQ {version}"


def _scope_errors(scope) -> list[str]:
    if not isinstance(scope, dict):
        return ["spec.scope must be a mapping"]
    errors = []
    for key, value in scope.items():
        if key not in ("vhosts", "users"):
            errors.append(f"unknown field spec.scope.{key}")
        elif not isinstance(value, dict) or set(value) - {"include"} or not isinstance(
                value.get("include", []), list) or not all(isinstance(g, str) for g in value.get("include", [])):
            errors.append(f"spec.scope.{key} must be {{include: [glob, ...]}}")
    return errors


class RabbitMQAdapter(Adapter):
    id = "rabbitmq"
    api_version = 1
    kinds = (VHOST, USER)
    password_kinds = (USER,)

    def validate(self, doc):
        spec, kind = doc.get("spec") or {}, doc["kind"]
        if kind == "Target":
            errors = [f"unknown field spec.{k}" for k in spec if k not in ("endpoint", "username", "scope")]
            errors += common.validate_endpoint(spec.get("endpoint"))
            if not isinstance(spec.get("username"), str) or not spec.get("username"):
                errors.append("spec.username is required (the management user Ordivus logs in as)")
            return errors + _scope_errors(spec.get("scope", {}))
        name = doc["metadata"]["name"]
        errors = [] if name.isprintable() else ["metadata.name must be printable"]
        if kind == VHOST:
            return errors + [f"unknown field spec.{k}" for k in spec]
        errors += [f"unknown field spec.{k}" for k in spec if k not in ("tags", "permissions")]
        tags = spec.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(t, str) and t and "," not in t for t in tags):
            errors.append("spec.tags must be a list of non-empty tag names without ','")
        perms = spec.get("permissions", {})
        if not isinstance(perms, dict) or not all(
                isinstance(v, str) and v and isinstance(p, dict) and set(p) == set(PERMISSION_FIELDS)
                and all(isinstance(x, str) for x in p.values()) for v, p in perms.items()):
            errors.append("spec.permissions must map vhost names to {configure, write, read} regex strings")
        return errors

    def desired(self, doc):
        spec = doc.get("spec") or {}
        attrs = {}
        if "tags" in spec:
            attrs["tags"] = _tags(spec["tags"])
        if "permissions" in spec:
            attrs["permissions"] = _permissions(spec["permissions"])
        return Resource(doc["kind"], doc["metadata"]["name"], attrs)

    def validate_target(self, target, resources):
        return [f"{USER} {r.id!r}: vhost {v!r} is outside spec.scope.vhosts"
                for r in resources if r.kind == USER
                for v in r.attrs.get("permissions", {}) if not common.in_scope(target.get("scope"), "vhosts", v)]

    def insecure_transport(self, target):
        return target["endpoint"].get("tls") is None  # ohne tls: http://

    def check(self, session, resource, allow_privileged=False):
        if resource.kind == VHOST:
            return f"vhost {DEFAULT_VHOST!r} is a protected system object" if resource.id == DEFAULT_VHOST else None
        if resource.id == session.username:  # auch außerhalb des Scopes, also nie entdeckt
            return f"user {resource.id!r} is the Ordivus login and protected"
        privileged = sorted(set(resource.attrs.get("tags", [])) & PRIVILEGED_TAGS)
        if privileged and not allow_privileged:
            return f"privileged tag(s) {privileged} not permitted by operator policy allowPrivilegedGrants"
        return None

    @contextmanager
    def connect(self, target, secret, write):
        base, context = _base(target)
        session = Session(base, context, target["username"], _basic(target["username"], secret), write)
        overview = self._request(session, "GET", "/api/overview")
        session.version = version_check(overview.get("rabbitmq_version") if isinstance(overview, dict) else None)
        me = self._request(session, "GET", "/api/whoami")
        if not isinstance(me, dict) or not isinstance(me.get("tags"), list):
            raise PermanentError("GET /api/whoami: unexpected response")
        session.tags = me["tags"]
        yield session

    def server_version(self, session):
        return session.version

    def _request(self, session, method, path, body=None, ok=()):
        if method != "GET" and not session.write:  # Read-only-Session: niemals schreibende Requests
            raise PermanentError(f"{method} {path} refused on read-only session")
        status, payload = _call(session.base, session.context, session.auth, method, path, body)
        if 200 <= status < 300 or status in ok:
            return payload
        reason = _reason(payload)
        raise net.status_error(status, f"{method} {path}: HTTP {status}" + (f": {str(reason)[:200]}" if reason else ""))

    def discover(self, session, kind, scope):
        if kind == VHOST:
            vhosts = _list(self._request(session, "GET", "/api/vhosts"), "list vhosts")
            if not all(isinstance(v.get("name"), str) for v in vhosts):
                raise PermanentError("list vhosts: unexpected response (vhost without name)")
            resources = [Resource(kind, v["name"], system=v["name"] == DEFAULT_VHOST or
                                  v.get("protected_from_deletion") is True)
                         for v in vhosts if common.in_scope(scope, "vhosts", v["name"])]
            if "administrator" not in session.tags:  # andere sehen nur vhosts mit eigenen Rechten
                return Discovery(PARTIAL, resources, "only administrators see all vhosts")
            return Discovery(COMPLETE, resources)
        users = _list(self._request(session, "GET", "/api/users"), "list users")
        perms = _list(self._request(session, "GET", "/api/permissions"), "list permissions")
        if not all(isinstance(u.get("name"), str) and isinstance(u.get("tags"), list) for u in users) or not all(
                isinstance(p.get("user"), str) and isinstance(p.get("vhost"), str)
                and all(isinstance(p.get(f), str) for f in PERMISSION_FIELDS) for p in perms):
            raise PermanentError("list users: unexpected response (user without name/tags or malformed permission)")
        by_user = {}
        for p in perms:
            if common.in_scope(scope, "vhosts", p["vhost"]):
                by_user.setdefault(p["user"], {})[p["vhost"]] = p
        # password_hash bleibt hier: nie in attrs
        return Discovery(COMPLETE, [
            Resource(kind, u["name"], {"tags": _tags(u["tags"]),
                                       "permissions": _permissions(by_user.get(u["name"], {}))},
                     system=u["name"] == session.username)
            for u in users if common.in_scope(scope, "users", u["name"])])

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        if op.kind == VHOST:
            if op.id == DEFAULT_VHOST:  # zweite Sperre neben check()/system
                raise PermanentError(f"vhost {op.id!r} is protected")
            if op.action == CREATE:
                self._request(session, "PUT", _path("vhosts", op.id), {})
            elif op.action == DELETE:
                log.warning("deleting vhost %r: this destroys all its queues, exchanges, bindings and messages", op.id)
                self._request(session, "DELETE", _path("vhosts", op.id), ok=(404,))
            else:
                raise PermanentError(f"{op.action} not supported for {VHOST}")
            return
        if op.id == session.username:
            raise PermanentError(f"user {op.id!r} is protected")
        path = _path("users", op.id)
        if op.action == CREATE:
            body = {"tags": op.desired.attrs.get("tags", [])}
            if op.password is not None:  # ohne Passwort: Benutzer ohne Passwort-Login (z. B. nur x509)
                body["password"] = op.password.reveal()
            self._request(session, "PUT", path, body)
            self._set_permissions(session, op.id, {}, op.desired.attrs.get("permissions", {}))
        elif op.action == UPDATE:
            if "tags" in op.changes:
                current = self._request(session, "GET", path)
                self._request(session, "PUT", path, {"password_hash": current["password_hash"],
                                                     "hashing_algorithm": current["hashing_algorithm"],
                                                     "tags": op.changes["tags"][1]})
            if "permissions" in op.changes:
                old, new = op.changes["permissions"]
                self._set_permissions(session, op.id, old or {}, new)
        elif op.action == SET_PASSWORD:
            current = self._request(session, "GET", path)
            self._request(session, "PUT", path, {"password": op.password.reveal(), "tags": current["tags"]})
        elif op.action == DELETE:
            self._request(session, "DELETE", path, ok=(404,))

    def _set_permissions(self, session, user, old, new):
        for vhost, perm in new.items():
            if old.get(vhost) != perm:
                self._request(session, "PUT", _path("permissions", vhost, user), perm)
        for vhost in old.keys() - new.keys():
            self._request(session, "DELETE", _path("permissions", vhost, user), ok=(404,))

    def verify_password(self, session, target, resource, password):
        if ":" in resource.id:  # Basic Auth trennt am ersten ':'; Login mit diesem Namen nicht prüfbar
            return None
        base, context = _base(target)
        status, payload = _call(base, context, _basic(resource.id, password), "GET", "/api/whoami")
        reason = _reason(payload)
        if status == 200 or (status == 401 and reason == "Not management user"):  # angemeldet, nur ohne UI-Tag
            return True
        return False if status == 401 and reason == "Not_Authorized" else None
