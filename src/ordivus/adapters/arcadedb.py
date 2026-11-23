"""ArcadeDB-Adapter über die HTTP-API (nur Standardbibliothek).

Target-Spec: ``endpoint: {host, port (2480), tls: {caFile}}``, ``username`` (Default ``root``),
optional ``scope: {databases: {include: [glob]}, users: {include: [glob]}}``.
Kinds: ``Database`` (keine Felder), ``DatabaseUser`` (``databases: {db: [gruppe, ...]}``).

Benutzer sind serverweit; ``databases`` ist ArcadeDBs Zuordnung Datenbank → Gruppen (``*`` = alle).
Benutzerverwaltung über ``/api/v1/server/users`` (GET/POST/PUT/DELETE), Datenbanken über
``GET /api/v1/databases`` und die Server-Kommandos ``create database``/``drop database``.
Server-Kommandos sind Freitext ohne Quoting, daher sind Datenbanknamen auf ``[A-Za-z0-9_-]`` begrenzt.
"""

import base64
import fnmatch
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass

from ordivus import net
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    PARTIAL,
    SET_PASSWORD,
    UPDATE,
    Adapter,
    AuthorizationError,
    Discovery,
    Op,
    PermanentError,
    Resource,
    Secret,
    TransientError,
)

DB_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,127}")
ROOT = "root"
PRIVILEGED_GROUPS = frozenset({"admin"})  # admin: Schema, Benutzerrechte und Konfiguration der Datenbank
HOST_FORBIDDEN = frozenset("/@?#")
TIMEOUT = 30


@dataclass
class Session:
    base: str
    context: ssl.SSLContext | None
    username: str
    auth: str
    write: bool


def _base(target: dict) -> tuple[str, ssl.SSLContext | None]:
    endpoint = target["endpoint"]
    tls = endpoint.get("tls")
    try:
        context = None if tls is None else ssl.create_default_context(cafile=tls.get("caFile"))
    except (OSError, ssl.SSLError) as e:
        raise PermanentError(f"cannot load tls.caFile: {type(e).__name__}") from None
    host = endpoint["host"]
    host = f"[{host}]" if ":" in host else host
    return f"{'https' if tls is not None else 'http'}://{host}:{endpoint.get('port', 2480)}", context


def _basic(username: str, password: Secret | None) -> str:
    raw = f"{username}:{password.reveal() if password else ''}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _call(base, context, auth, method, path, body=None, query=None):
    """Ein HTTP-Aufruf; liefert (Status, JSON). Wirft AdapterError ohne Secret-Inhalte."""
    url = base + path + ("?" + urllib.parse.urlencode(query) if query else "")
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={
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
    except (TimeoutError, urllib.error.URLError, ConnectionError) as e:
        raise TransientError(f"{where}: {type(e).__name__}: {getattr(e, 'reason', e)}") from None
    except ValueError as e:
        raise PermanentError(f"{where}: invalid JSON response ({type(e).__name__})") from None


def _check(status, payload, where, ok=()):
    if 200 <= status < 300 or status in ok:
        return payload
    detail = payload.get("detail") or payload.get("error") if isinstance(payload, dict) else None
    message = f"{where}: HTTP {status}" + (f": {str(detail)[:200]}" if detail else "")
    if status in (401, 403):
        raise AuthorizationError(message)
    if status >= 500 or status == 429:
        raise TransientError(message)
    raise PermanentError(message)


def _groups(databases: dict) -> dict:
    return {db: sorted(set(groups)) for db, groups in sorted(databases.items())}


def _in_scope(scope, key, name):
    include = ((scope or {}).get(key) or {}).get("include")
    return include is None or any(fnmatch.fnmatchcase(name, g) for g in include)


class ArcadeDBAdapter(Adapter):
    id = "arcadedb"
    kinds = ("Database", "DatabaseUser")
    password_kinds = ("DatabaseUser",)

    def validate(self, doc):
        spec, kind = doc.get("spec") or {}, doc["kind"]
        if kind == "Target":
            return self._validate_target(spec)
        name = doc["metadata"]["name"]
        if kind == "Database":
            errors = [f"unknown field spec.{k}" for k in spec]
            if not DB_NAME.fullmatch(name):
                errors.append("metadata.name must match [A-Za-z0-9_][A-Za-z0-9_-]* (max 128)")
            return errors
        errors = [f"unknown field spec.{k}" for k in spec if k != "databases"]
        if name.startswith("apitoken:") or not name.isprintable():
            errors.append("metadata.name must be printable and must not start with 'apitoken:'")
        databases = spec.get("databases", {})
        if not isinstance(databases, dict) or not all(
                isinstance(db, str) and db and isinstance(g, list) and all(isinstance(x, str) and x for x in g)
                for db, g in databases.items()):
            errors.append("spec.databases must map database names to lists of group names")
        elif "*" in databases:  # gälte auch für jede künftige Datenbank, außerhalb jedes Scopes
            errors.append("spec.databases: '*' (all databases) is not supported, list the databases explicitly")
        return errors

    def validate_target(self, target, resources):
        return [f"DatabaseUser {r.id!r}: database {db!r} is outside spec.scope.databases"
                for r in resources if r.kind == "DatabaseUser"
                for db in r.attrs.get("databases", {}) if not _in_scope(target.get("scope"), "databases", db)]

    def check(self, session, resource, allow_privileged=False):
        if resource.kind != "DatabaseUser":
            return None
        if resource.id in (ROOT, session.username):  # auch wenn außerhalb des Scopes und daher nie entdeckt
            return f"user {resource.id!r} is protected (root or the Ordivus login)"
        privileged = sorted({g for groups in resource.attrs.get("databases", {}).values() for g in groups}
                            & PRIVILEGED_GROUPS)
        if privileged and not allow_privileged:
            return f"privileged group(s) {privileged} not permitted by operator policy allowPrivilegedGrants"
        return None

    @staticmethod
    def _validate_target(spec):
        errors = [f"unknown field spec.{k}" for k in spec if k not in ("endpoint", "username", "scope")]
        endpoint = spec.get("endpoint")
        if not isinstance(endpoint, dict):
            return [*errors, "spec.endpoint must be a mapping"]
        errors += [f"unknown field spec.endpoint.{k}" for k in endpoint if k not in ("host", "port", "tls")]
        host = endpoint.get("host")
        if not isinstance(host, str) or not host or HOST_FORBIDDEN & set(host) or any(c.isspace() for c in host):
            errors.append("spec.endpoint.host must be a host name or address (no '/', '@', '?', '#', whitespace)")
        if type(endpoint.get("port", 2480)) is not int or not 0 < endpoint.get("port", 2480) < 65536:
            errors.append("spec.endpoint.port must be an integer 1-65535")
        tls = endpoint.get("tls", {})
        if not isinstance(tls, dict):
            errors.append("spec.endpoint.tls must be a mapping")
        else:
            errors += [f"unknown field spec.endpoint.tls.{k}" for k in tls if k != "caFile"]
            if not isinstance(tls.get("caFile", ""), str):
                errors.append("spec.endpoint.tls.caFile must be a string")
        if not isinstance(spec.get("username", ROOT), str) or not spec.get("username", ROOT):
            errors.append("spec.username must be a non-empty string")
        scope = spec.get("scope", {})
        if not isinstance(scope, dict):
            return [*errors, "spec.scope must be a mapping"]
        for key, value in scope.items():
            if key not in ("databases", "users"):
                errors.append(f"unknown field spec.scope.{key}")
            elif not isinstance(value, dict) or set(value) - {"include"} or not isinstance(
                    value.get("include", []), list) or not all(isinstance(g, str) for g in value.get("include", [])):
                errors.append(f"spec.scope.{key} must be {{include: [glob, ...]}}")
        return errors

    def desired(self, doc):
        spec, name = doc.get("spec") or {}, doc["metadata"]["name"]
        attrs = {"databases": _groups(spec["databases"])} if "databases" in spec else {}
        return Resource(doc["kind"], name, attrs)

    def insecure_transport(self, target):
        return target["endpoint"].get("tls") is None  # ohne tls: http://

    @contextmanager
    def connect(self, target, secret, write):
        base, context = _base(target)
        username = target.get("username", ROOT)
        session = Session(base, context, username, _basic(username, secret), write)
        self._request(session, "GET", "/api/v1/server", query={"mode": "basic"})  # Login prüfen
        yield session

    def _request(self, session, method, path, body=None, query=None, ok=()):
        if method != "GET" and not session.write:  # Read-only-Session: niemals schreibende Requests
            raise PermanentError(f"{method} {path} refused on read-only session")
        status, payload = _call(session.base, session.context, session.auth, method, path, body, query)
        return _check(status, payload, f"{method} {path}", ok)

    def discover(self, session, kind, scope):
        if kind == "Database":
            names = self._request(session, "GET", "/api/v1/databases").get("result", [])
            resources = [Resource(kind, n, manageable=bool(DB_NAME.fullmatch(n)))
                         for n in names if _in_scope(scope, "databases", n)]
            if session.username != ROOT:  # Nicht-root sieht nur Datenbanken mit eigener Berechtigung
                return Discovery(PARTIAL, resources, "only root sees all databases")
            return Discovery(COMPLETE, resources)
        users = self._request(session, "GET", "/api/v1/server/users").get("result", [])
        return Discovery(COMPLETE, [
            Resource(kind, u["name"], {"databases": _groups(u.get("databases") or {})},
                     system=u["name"] in (ROOT, session.username))
            for u in users if _in_scope(scope, "users", u["name"])])

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        if op.kind == "Database":
            if not DB_NAME.fullmatch(op.id):  # Server-Kommando ist Freitext: nur sichere Namen
                raise PermanentError(f"database name {op.id!r} not safe for server commands")
            command = {CREATE: "create", DELETE: "drop"}.get(op.action)
            if command is None:
                raise PermanentError(f"{op.action} not supported for Database")
            # 409 (existiert schon) bzw. 400 (existiert nicht) erst nach Gegenprüfung als Erfolg werten
            try:
                self._request(session, "POST", "/api/v1/server", {"command": f"{command} database {op.id}"})
            except PermanentError:
                names = self._request(session, "GET", "/api/v1/databases").get("result", [])
                if (op.id in names) != (op.action == CREATE):
                    raise
            return
        if op.id in (ROOT, session.username):  # zweite Sperre neben check()
            raise PermanentError(f"user {op.id!r} is protected")
        users, name = "/api/v1/server/users", {"name": op.id}
        if op.action == CREATE:
            if op.password is None:
                raise PermanentError("ArcadeDB requires a password: declare spec.credentials")
            body = {"name": op.id, "password": op.password.reveal(), **op.desired.attrs}
            self._request(session, "POST", users, body)
        elif op.action == UPDATE:
            self._request(session, "PUT", users, {f: new for f, (_, new) in op.changes.items()}, name)
        elif op.action == SET_PASSWORD:
            self._request(session, "PUT", users, {"password": op.password.reveal()}, name)
        elif op.action == DELETE:
            self._request(session, "DELETE", users, query=name, ok=(404,))

    def verify_password(self, session, target, resource, password):
        if ":" in resource.id:  # Basic Auth trennt am ersten ':'; Login mit diesem Namen nicht prüfbar
            return None
        base, context = _base(target)
        auth = _basic(resource.id, password)
        status, _ = _call(base, context, auth, "GET", "/api/v1/server", query={"mode": "basic"})
        # 403 heißt: angemeldet, aber nicht berechtigt – kein Beweis für ein falsches Passwort
        return True if status == 200 else False if status == 401 else None
