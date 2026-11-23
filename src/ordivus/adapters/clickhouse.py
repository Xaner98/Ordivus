"""ClickHouse-Adapter über das HTTP-Interface (nur Standardbibliothek).

Kinds: ``Database``, ``DatabaseRole``, ``DatabaseUser``, ``Grant`` (Doku: docs/adapters/clickhouse.md).
Anmeldung per Basic Auth im Header, SQL nur im POST-Body. Read-only-Sessions senden bei jeder
Anfrage ``readonly=2``; ``apply`` verweigert zusätzlich auf Read-only-Sessions.
"""

import base64
import fnmatch
import ipaddress
import json
import re
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass

from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
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

SYSTEM_DATABASES = frozenset({"system", "information_schema", "INFORMATION_SCHEMA", "default"})
SQL_STORAGES = frozenset({"local_directory", "replicated"})  # alles andere (users_xml …) ist nicht per SQL änderbar
AUTH_FAILED = 516
AUTH_CODES = frozenset({497, 516, 192})  # ACCESS_DENIED, AUTHENTICATION_FAILED, UNKNOWN_USER
TRANSIENT_CODES = frozenset({3, 159, 202, 209, 210, 241, 242, 425, 999})
PRIVILEGE = re.compile(r"[A-Z][A-Z0-9_]*( [A-Z][A-Z0-9_]*)*")
ENGINE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
FIELDS = {
    "Target": {"endpoint", "scope"},
    "Database": {"engine"},
    "DatabaseRole": set(),
    "DatabaseUser": {"roles", "defaultRoles", "hostIp", "hostNames"},
    "Grant": {"grantee", "privileges", "database", "table"},
}


def qi(name: str) -> str:
    """Identifier in Backticks; Backslash und Backtick werden escaped."""
    return "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"


def qs(value: str) -> str:
    """String-Literal in Hochkommas; Backslash und Hochkomma werden escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def privilege(name: str) -> str:
    return " ".join(name.split()).upper()


def grant_id(grantee: str, database: str | None, table: str | None) -> str:
    return f"{qi(grantee)} ON {qi(database) if database else '*'}.{qi(table) if table else '*'}"


@dataclass
class Session:
    url: str
    user: str
    password: Secret | None
    context: ssl.SSLContext | None
    timeout: float
    write: bool


def _error(status: int, code: str | None, text: str) -> Exception:
    num = int(code) if code and code.isdigit() else None
    msg = f"ClickHouse error {num if num is not None else f'HTTP {status}'}" + (f": {text}" if text else "")
    if num in AUTH_CODES or (num is None and status in (401, 403)):
        err = AuthorizationError(msg)
    elif num in TRANSIENT_CODES or (num is None and status >= 500):
        err = TransientError(msg)
    else:
        err = PermanentError(msg)
    err.code = num
    return err


def _post(s: Session, sql: str, secret: bool = False) -> list[dict]:
    """Führt ``sql`` aus; SELECTs müssen ``FORMAT JSON`` enden. ``secret``: Statement enthält ein
    Passwort, daher wird die Servermeldung (kann das Statement zitieren) nicht übernommen."""
    params = {"wait_end_of_query": "1", **({} if s.write else {"readonly": "2"})}
    auth = base64.b64encode(f"{s.user}:{s.password.reveal() if s.password else ''}".encode()).decode()
    req = urllib.request.Request(f"{s.url}/?{urllib.parse.urlencode(params)}", data=sql.encode(), method="POST",
                                 headers={"Authorization": f"Basic {auth}"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=s.timeout, context=s.context) as resp:
                body = resp.read()
            break
        except urllib.error.HTTPError as e:
            text = "" if secret else (e.read().decode(errors="replace").strip().splitlines() or [""])[0][:300]
            raise _error(e.code, e.headers.get("X-ClickHouse-Exception-Code"), text) from None
        except urllib.error.URLError as e:
            # URLError: Aufbau/Senden gescheitert, Anfrage kam nie vollständig an, Wiederholen ist sicher
            if isinstance(e.reason, ssl.SSLError):
                raise PermanentError(f"TLS error with {s.url}: {type(e.reason).__name__}") from None
            if attempt == 2:
                raise TransientError(f"cannot reach ClickHouse at {s.url}: {type(e.reason).__name__}") from None
        except (TimeoutError, OSError) as e:  # Lese-Timeout: Ausgang unbekannt, nicht wiederholen
            raise TransientError(f"cannot reach ClickHouse at {s.url}: {type(e).__name__}") from None
    if not (body.strip() and sql.rstrip().endswith("FORMAT JSON")):
        return []
    try:
        return json.loads(body)["data"]
    except (ValueError, KeyError, TypeError):
        raise PermanentError(f"unexpected response from {s.url} (not ClickHouse JSON)") from None


def _session(target: dict, user: str, password: Secret | None, write: bool) -> Session:
    endpoint = target["endpoint"]
    tls = endpoint.get("tls")
    context = None
    if tls is not None:
        try:
            context = ssl.create_default_context(cafile=tls.get("caFile"))
        except (OSError, ssl.SSLError) as e:
            raise PermanentError(f"cannot load TLS CA file: {type(e).__name__}") from None
    host = endpoint["host"]
    host = f"[{host}]" if ":" in host else host
    port = endpoint.get("port", 8443 if tls is not None else 8123)
    url = f"{'https' if tls is not None else 'http'}://{host}:{port}"
    return Session(url, user, password, context, float(endpoint.get("timeoutSeconds", 30)), write)


def _strings(value, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        return [f"{where} must be a list of non-empty strings"]
    return []


def _hosts(ips, names, regexps=(), likes=()) -> str:
    parts = [f"{k} {qs(v)}" for k, values in (("IP", ips), ("NAME", names), ("REGEXP", regexps), ("LIKE", likes))
             for v in values]
    return "HOST " + (", ".join(parts) if parts else "NONE")


def _roles(names) -> str:
    return ", ".join(qi(n) for n in names)


class ClickHouseAdapter(Adapter):
    id = "clickhouse"
    kinds = ("Database", "DatabaseRole", "DatabaseUser", "Grant")
    password_kinds = ("DatabaseUser",)

    def validate(self, doc):
        kind, spec = doc["kind"], doc.get("spec") or {}
        errors = [f"unknown field spec.{k}" for k in spec if k not in FIELDS[kind]]
        if kind == "Target":
            endpoint = spec.get("endpoint")
            if not isinstance(endpoint, dict):
                return [*errors, "spec.endpoint must be a mapping"]
            errors += [f"unknown field spec.endpoint.{k}" for k in endpoint
                       if k not in {"host", "port", "user", "tls", "timeoutSeconds"}]
            if not isinstance(endpoint.get("host"), str) or not endpoint.get("host"):
                errors.append("spec.endpoint.host must be a non-empty string")
            if "port" in endpoint and (type(endpoint["port"]) is not int or not 0 < endpoint["port"] < 65536):
                errors.append("spec.endpoint.port must be an integer 1..65535")
            user = endpoint.get("user", "default")
            if not isinstance(user, str) or not user or ":" in user:  # Basic Auth trennt am ersten ':'
                errors.append("spec.endpoint.user must be a non-empty string without ':'")
            timeout = endpoint.get("timeoutSeconds", 30)
            if type(timeout) not in (int, float) or timeout <= 0:
                errors.append("spec.endpoint.timeoutSeconds must be a positive number")
            tls = endpoint.get("tls", {})
            if not isinstance(tls, dict):
                errors.append("spec.endpoint.tls must be a mapping")
            else:
                errors += [f"unknown field spec.endpoint.tls.{k}" for k in tls if k != "caFile"]
                if not isinstance(tls.get("caFile", "x"), str):
                    errors.append("spec.endpoint.tls.caFile must be a string")
            scope = spec.get("scope", {})
            if not isinstance(scope, dict):
                return [*errors, "spec.scope must be a mapping"]
            errors += [f"unknown field spec.scope.{k}" for k in scope if k != "databases"]
            databases = scope.get("databases", {})
            if not isinstance(databases, dict) or set(databases) - {"include"}:
                errors.append("spec.scope.databases must be a mapping with 'include'")
            else:
                errors += _strings(databases.get("include", []), "spec.scope.databases.include")
            return errors
        if kind == "Database" and "engine" in spec and not (
                isinstance(spec["engine"], str) and ENGINE.fullmatch(spec["engine"])):
            errors.append("spec.engine must be a plain engine name like Atomic (no parameters)")
        for key in ("roles", "defaultRoles", "hostIp", "hostNames"):
            if key in spec:
                errors += _strings(spec[key], f"spec.{key}")
        if "hostIp" in spec and not _strings(spec["hostIp"], ""):
            for ip in spec["hostIp"]:
                try:
                    ipaddress.ip_network(ip, strict=False)
                except ValueError:
                    errors.append(f"spec.hostIp: invalid address or network {ip!r}")
        if kind == "Grant":
            if not isinstance(spec.get("grantee"), str) or not spec.get("grantee"):
                errors.append("spec.grantee must be a non-empty string")
            privileges = spec.get("privileges")
            if _strings(privileges, "spec.privileges") or not privileges:
                errors.append("spec.privileges must be a non-empty list of strings")
            else:
                for p in map(privilege, privileges):
                    if p in ("ALL", "ALL PRIVILEGES", "NONE"):
                        errors.append(f"spec.privileges: {p} expands server-side; list privileges explicitly")
                    elif not PRIVILEGE.fullmatch(p):
                        errors.append(f"spec.privileges: invalid privilege {p!r}")
            for key in ("database", "table"):
                if key in spec and (not isinstance(spec[key], str) or not spec[key]):
                    errors.append(f"spec.{key} must be a non-empty string")
            if "table" in spec and "database" not in spec:
                errors.append("spec.table requires spec.database")
        return errors

    def desired(self, doc):
        kind, name, spec = doc["kind"], doc["metadata"]["name"], doc.get("spec") or {}
        if kind == "Database":
            return Resource(kind, name, {k: spec[k] for k in ("engine",) if k in spec})
        if kind == "DatabaseRole":
            return Resource(kind, name)
        if kind == "DatabaseUser":
            attrs = {k: sorted(set(spec[k])) for k in FIELDS[kind] if k in spec}
            if "::/0" in attrs.get("hostIp", []):  # ClickHouse speichert ANY nur als ::/0
                attrs["hostIp"] = ["::/0"]
            return Resource(kind, name, attrs)
        grantee, db, table = spec["grantee"], spec.get("database"), spec.get("table")
        return Resource(kind, grant_id(grantee, db, table), {
            "grantee": grantee, "database": db, "table": table,
            "privileges": sorted({privilege(p) for p in spec["privileges"]})})

    def insecure_transport(self, target):
        return target["endpoint"].get("tls") is None  # ohne tls: http://

    @contextmanager
    def connect(self, target, secret, write):
        session = _session(target, target["endpoint"].get("user", "default"), secret, write)
        session.user = _post(session, "SELECT currentUser() AS u FORMAT JSON")[0]["u"]  # Selbstschutz: echter Name
        yield session

    def discover(self, session, kind, scope):
        include = ((scope or {}).get("databases") or {}).get("include")

        def in_scope(db):
            return db is None or include is None or any(fnmatch.fnmatchcase(db, g) for g in include)

        if kind == "Database":
            rows = _post(session, "SELECT name, engine FROM system.databases FORMAT JSON")
            return Discovery(COMPLETE, [Resource(kind, r["name"], {"engine": r["engine"]},
                                                 system=r["name"] in SYSTEM_DATABASES)
                                        for r in rows if in_scope(r["name"])])
        storage = {r["name"]: r["storage"] for r in _post(
            session, "SELECT name, storage FROM system.users UNION ALL SELECT name, storage FROM system.roles "
                     "FORMAT JSON")}
        if kind == "DatabaseRole":
            rows = _post(session, "SELECT name, storage FROM system.roles FORMAT JSON")
            return Discovery(COMPLETE, [Resource(kind, r["name"], manageable=r["storage"] in SQL_STORAGES)
                                        for r in rows])
        if kind == "DatabaseUser":
            grants = _post(session, "SELECT user_name, granted_role_name, granted_role_is_default "
                                    "FROM system.role_grants WHERE user_name IS NOT NULL FORMAT JSON")
            users = _post(session, "SELECT name, storage, host_ip, host_names, host_names_regexp, host_names_like "
                                   "FROM system.users FORMAT JSON")
            out = []
            for u in users:
                mine = [g for g in grants if g["user_name"] == u["name"]]
                manageable = u["storage"] in SQL_STORAGES
                out.append(Resource(kind, u["name"], {
                    "roles": sorted(g["granted_role_name"] for g in mine),
                    "defaultRoles": sorted(g["granted_role_name"] for g in mine if g["granted_role_is_default"]),
                    "hostIp": sorted(u["host_ip"]), "hostNames": sorted(u["host_names"]),
                    "hostNamesRegexp": sorted(u["host_names_regexp"]), "hostNamesLike": sorted(u["host_names_like"]),
                }, manageable=manageable, system=u["name"] == session.user))
            return Discovery(COMPLETE, out)
        rows = _post(session, "SELECT user_name, role_name, access_type, database, table, column, is_partial_revoke, "
                              "grant_option FROM system.grants FORMAT JSON")
        groups: dict[str, Resource] = {}
        for r in rows:
            if not in_scope(r["database"]):
                continue
            grantee = r["user_name"] if r["user_name"] is not None else r["role_name"]
            rid = grant_id(grantee, r["database"], r["table"])
            # Spalten-Grants, Teil-Revokes, GRANT OPTION modelliert der Adapter nicht: eigene, nicht änderbare Objekte
            special = [s for s, on in (("column " + str(r["column"]), r["column"] is not None),
                                       ("partial revoke", r["is_partial_revoke"]),
                                       ("with grant option", r["grant_option"])) if on]
            if special:
                rid += f" ({', '.join(special)})"
            have = groups.setdefault(rid, Resource(
                kind, rid, {"grantee": grantee, "database": r["database"], "table": r["table"], "privileges": []},
                manageable=not special and storage.get(grantee) in SQL_STORAGES, system=grantee == session.user))
            have.attrs["privileges"] = sorted({*have.attrs["privileges"], privilege(r["access_type"])})
        return Discovery(COMPLETE, list(groups.values()))

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        if op.observed is not None and (op.observed.system or not op.observed.manageable or op.id == session.user):
            raise PermanentError(f"{op.kind} {op.id!r} is protected or not manageable")
        noun = {"Database": "DATABASE", "DatabaseRole": "ROLE", "DatabaseUser": "USER"}.get(op.kind)
        if op.action == DELETE:
            if op.kind == "Grant":
                a = op.observed.attrs
                _post(session, f"REVOKE {', '.join(a['privileges'])} ON {self._on(a)} FROM {qi(a['grantee'])}")
            else:
                _post(session, f"DROP {noun} IF EXISTS {qi(op.id)}")
            return
        if op.action == SET_PASSWORD:
            _post(session, f"ALTER USER {qi(op.id)} IDENTIFIED WITH sha256_password BY {qs(op.password.reveal())}",
                  secret=True)
            return
        want = op.desired.attrs
        if op.kind == "Grant":
            old = set(op.changes["privileges"][0] or []) if op.action == UPDATE else set()
            if added := sorted(set(want["privileges"]) - old):
                _post(session, f"GRANT {', '.join(added)} ON {self._on(want)} TO {qi(want['grantee'])}")
            if removed := sorted(old - set(want["privileges"])):
                _post(session, f"REVOKE {', '.join(removed)} ON {self._on(want)} FROM {qi(want['grantee'])}")
            return
        if op.action == CREATE:
            if op.kind == "Database":
                engine = f" ENGINE = {want['engine']}" if "engine" in want else ""
                _post(session, f"CREATE DATABASE IF NOT EXISTS {qi(op.id)}{engine}")
            elif op.kind == "DatabaseRole":
                _post(session, f"CREATE ROLE IF NOT EXISTS {qi(op.id)}")
            else:
                # ohne verwaltetes Passwort: zufälliges, nirgends gespeichertes Passwort statt no_password
                password = op.password.reveal() if op.password else secrets.token_urlsafe(32)
                # Passwort-Statement ohne variable Klauseln: Parserfehler darin landen unmaskiert im Server-Log.
                # HOST NONE bis die Hosts gesetzt sind, damit der Benutzer nie kurz von überall erreichbar ist.
                _post(session, f"CREATE USER IF NOT EXISTS {qi(op.id)} IDENTIFIED WITH sha256_password BY "
                               f"{qs(password)} HOST NONE", secret=True)
                _post(session, f"ALTER USER {qi(op.id)} " + (_hosts(want.get("hostIp", []), want.get("hostNames", []))
                               if "hostIp" in want or "hostNames" in want else "HOST ANY"))
                if want.get("roles"):
                    _post(session, f"GRANT {_roles(want['roles'])} TO {qi(op.id)}")
                if "defaultRoles" in want:
                    self._default_roles(session, op.id, want["defaultRoles"])
            return
        # UPDATE
        changes = op.changes
        if op.kind == "Database" and "engine" in changes:
            raise PermanentError(f"Database {op.id!r}: engine is create-only")
        if op.kind != "DatabaseUser":
            return
        if "roles" in changes:
            old, new = set(changes["roles"][0] or []), set(changes["roles"][1])
            if new - old:
                _post(session, f"GRANT {_roles(sorted(new - old))} TO {qi(op.id)}")
            if old - new:
                _post(session, f"REVOKE {_roles(sorted(old - new))} FROM {qi(op.id)}")
        if "hostIp" in changes or "hostNames" in changes:
            a = {**op.observed.attrs, **{k: v for k, (_, v) in changes.items()}}  # nicht deklarierte Hosts bleiben
            _post(session, f"ALTER USER {qi(op.id)} " + _hosts(a["hostIp"], a["hostNames"],
                                                                 a["hostNamesRegexp"], a["hostNamesLike"]))
        if "defaultRoles" in changes:
            self._default_roles(session, op.id, changes["defaultRoles"][1])

    @staticmethod
    def _on(attrs) -> str:
        return f"{qi(attrs['database']) if attrs['database'] else '*'}.{qi(attrs['table']) if attrs['table'] else '*'}"

    @staticmethod
    def _default_roles(session, user, roles):
        _post(session, f"SET DEFAULT ROLE {_roles(roles) if roles else 'NONE'} TO {qi(user)}")

    def verify_password(self, session, target, resource, password):
        if ":" in resource.id:
            return None  # Basic Auth kann diesen Namen nicht übertragen
        try:
            _post(_session(target, resource.id, password, write=False), "SELECT 1 AS ok FORMAT JSON")
        except AuthorizationError as e:
            return False if e.code == AUTH_FAILED else None
        except (TransientError, PermanentError):
            return None
        return True
