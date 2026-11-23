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
import http.client
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass

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

DB_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,127}")
ROOT = "root"
PRIVILEGED_GROUPS = frozenset({"admin"})  # admin: Schema, Benutzerrechte und Konfiguration der Datenbank
TIMEOUT = 30
MIN_VERSION = (26, 3)  # erste Version mit /api/v1/server/users (26.2 antwortet 404)


@dataclass
class Session:
    base: str
    context: ssl.SSLContext | None
    username: str
    auth: str
    write: bool
    scope: dict | None = None
    version: str | None = None


def _base(target: dict) -> tuple[str, ssl.SSLContext | None]:
    endpoint = target["endpoint"]
    tls = endpoint.get("tls")
    context = None if tls is None else common.tls_context(tls)
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
    except (TimeoutError, urllib.error.URLError, ConnectionError, http.client.HTTPException) as e:
        raise TransientError(f"{where}: {type(e).__name__}: {getattr(e, 'reason', e)}") from None
    except ValueError as e:
        raise PermanentError(f"{where}: invalid JSON response ({type(e).__name__})") from None


def _check(status, payload, where, ok=()):
    if 200 <= status < 300 or status in ok:
        return payload
    detail = payload.get("detail") or payload.get("error") if isinstance(payload, dict) else None
    raise net.status_error(status, f"{where}: HTTP {status}" + (f": {str(detail)[:200]}" if detail else ""))


def _result(payload, where: str) -> list:
    """``result``-Liste einer Antwort; jede andere Form ist ein Fehler, nie eine leere Liste."""
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, list):
        raise PermanentError(f"{where}: unexpected response (no 'result' list)")
    return result


def _groups_ok(databases) -> bool:
    return isinstance(databases, dict) and all(
        isinstance(g, list) and all(isinstance(x, str) for x in g) for g in databases.values())


def _groups(databases: dict) -> dict:
    return {db: sorted(set(groups)) for db, groups in sorted(databases.items())}


def _managed_db(scope, db: str) -> bool:
    """Ob ein Eintrag der Zuordnung verwaltet wird; ``*`` und Datenbanken außerhalb des Scopes nie."""
    return db != "*" and common.in_scope(scope, "databases", db)


def _version(payload) -> tuple[str, tuple]:
    """``"26.12.1-SNAPSHOT (build ...)"`` → (``"26.12.1-SNAPSHOT"``, (26, 12, 1))."""
    raw = payload.get("version") if isinstance(payload, dict) else None
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?\S*", raw) if isinstance(raw, str) else None
    if not m:
        raise PermanentError("GET /api/v1/server: response without a readable 'version'")
    return m.group(0), tuple(int(x or 0) for x in m.groups())


class ArcadeDBAdapter(Adapter):
    id = "arcadedb"
    api_version = 1
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
                for db in r.attrs.get("databases", {}) if not common.in_scope(target.get("scope"), "databases", db)]

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
        errors += common.validate_endpoint(endpoint)
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
        session = Session(base, context, username, _basic(username, secret), write, target.get("scope"))
        version, numbers = _version(self._request(session, "GET", "/api/v1/server", query={"mode": "basic"}))
        if numbers < MIN_VERSION:
            raise PermanentError(f"ArcadeDB {version} is not supported (minimum 26.3)")
        session.version = f"ArcadeDB {version}"
        yield session

    def server_version(self, session):
        return session.version

    def _request(self, session, method, path, body=None, query=None, ok=()):
        if method != "GET" and not session.write:  # Read-only-Session: niemals schreibende Requests
            raise PermanentError(f"{method} {path} refused on read-only session")
        status, payload = _call(session.base, session.context, session.auth, method, path, body, query)
        return _check(status, payload, f"{method} {path}", ok)

    def discover(self, session, kind, scope):
        if kind == "Database":
            names = _result(self._request(session, "GET", "/api/v1/databases"), "list databases")
            if not all(isinstance(n, str) for n in names):
                raise PermanentError("list databases: unexpected response (non-string name)")
            resources = [Resource(kind, n, manageable=bool(DB_NAME.fullmatch(n)))
                         for n in names if common.in_scope(scope, "databases", n)]
            if session.username != ROOT:  # Nicht-root sieht nur Datenbanken mit eigener Berechtigung
                return Discovery(PARTIAL, resources, "only root sees all databases")
            return Discovery(COMPLETE, resources)
        users = _result(self._request(session, "GET", "/api/v1/server/users"), "list users")
        if not all(isinstance(u, dict) and isinstance(u.get("name"), str) and _groups_ok(u.get("databases") or {})
                   for u in users):
            raise PermanentError("list users: unexpected response (user without name or databases mapping)")
        return Discovery(COMPLETE, [
            Resource(kind, u["name"], {"databases": _groups(
                {db: g for db, g in (u.get("databases") or {}).items() if _managed_db(scope, db)})},
                     system=u["name"] in (ROOT, session.username))
            for u in users if common.in_scope(scope, "users", u["name"])])

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
                names = _result(self._request(session, "GET", "/api/v1/databases"), "list databases")
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
            body = {f: new for f, (_, new) in op.changes.items()}
            if "databases" in body:  # PUT ersetzt die ganze Zuordnung: nicht verwaltete Einträge übernehmen
                body["databases"] = {**self._unmanaged_dbs(session, op.id), **body["databases"]}
            self._request(session, "PUT", users, body, name)
        elif op.action == SET_PASSWORD:
            self._request(session, "PUT", users, {"password": op.password.reveal()}, name)
        elif op.action == DELETE:
            self._request(session, "DELETE", users, query=name, ok=(404,))

    def _unmanaged_dbs(self, session, name: str) -> dict:
        # shortcut: GET und PUT sind nicht atomar; eine parallele Änderung dazwischen geht verloren
        for u in _result(self._request(session, "GET", "/api/v1/server/users"), "list users"):
            if isinstance(u, dict) and u.get("name") == name:
                current = u.get("databases") or {}
                if not _groups_ok(current):
                    raise PermanentError("list users: unexpected response (databases mapping)")
                return {db: g for db, g in current.items() if not _managed_db(session.scope, db)}
        raise PermanentError(f"user {name!r} not found for update")

    def verify_password(self, session, target, resource, password):
        if ":" in resource.id:  # Basic Auth trennt am ersten ':'; Login mit diesem Namen nicht prüfbar
            return None
        base, context = _base(target)
        auth = _basic(resource.id, password)
        status, _ = _call(base, context, auth, "GET", "/api/v1/server", query={"mode": "basic"})
        # 403 heißt: angemeldet, aber nicht berechtigt – kein Beweis für ein falsches Passwort
        return True if status == 200 else False if status == 401 else None
