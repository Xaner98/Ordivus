"""ClickHouse-Adapter über das HTTP-Interface (nur Standardbibliothek).

Kinds: ``Database``, ``DatabaseRole``, ``DatabaseUser``, ``Grant`` (Doku: docs/adapters/clickhouse.md).
Anmeldung per Basic Auth im Header, SQL nur im POST-Body. Read-only-Sessions senden bei jeder
Anfrage ``readonly=2``, außer der Server erzwingt für den Login schon ``readonly`` ≥ 1 (Profil);
``apply`` verweigert zusätzlich auf Read-only-Sessions.
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
from dataclasses import dataclass, field

from ordivus import net
from ordivus.adapters import common
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
GRANT_FORBIDDEN_DATABASES = SYSTEM_DATABASES - {"default"}  # Grants dort wären für scoped Discovery unsichtbar
# Expandieren serverseitig (CURRENT GRANTS = alle eigenen Rechte des Admins); immer abgelehnt
EXPANDING = frozenset({"ALL", "ALL PRIVILEGES", "NONE", "USAGE", "NO PRIVILEGES", "CURRENT GRANTS"})
# Privilegiert (allowPrivilegedGrants): diese Gruppen samt allen Unterrechten laut system.privileges.parent_group,
# außerdem jedes direkte Kind von ALL auf Ebene GLOBAL (Quellen FILE/URL/S3/…, KILL QUERY, CLUSTER …)
# und jedes Recht auf den Ebenen SOURCE/USER_NAME/NAMED_COLLECTION/DEFINER.
PRIVILEGED_GROUPS = frozenset({
    "ACCESS MANAGEMENT", "SYSTEM", "SOURCES", "READ", "WRITE", "INTROSPECTION", "DISPLAYSECRETSINSHOWANDSELECT",
    "KILL QUERY", "KILL TRANSACTION", "NAMED COLLECTION ADMIN", "SET DEFINER", "CLUSTER", "TABLE ENGINE",
    "MOVE PARTITION BETWEEN SHARDS", "CREATE FUNCTION", "DROP FUNCTION"})
PRIVILEGED_LEVELS = frozenset({"SOURCE", "USER_NAME", "NAMED_COLLECTION", "DEFINER"})
MIN_VERSION = (25, 8)  # älteste LTS-Linie, gegen die die Integrationstests laufen
# Nur diese Methoden ersetzt SET_PASSWORD ohne Verlust (ALTER USER … IDENTIFIED ersetzt ALLE Methoden)
PASSWORD_AUTH = frozenset({"no_password", "plaintext_password", "sha256_password", "double_sha1_password",
                           "bcrypt_password"})
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


def host_ip(value: str) -> str:
    """Form, in der ClickHouse eine Adresse/ein Netz speichert: Netzadresse, ohne /32 bzw. /128, Hex klein."""
    net_ = ipaddress.ip_network(value, strict=False)
    return str(net_.network_address) if net_.prefixlen == net_.max_prefixlen else str(net_)


def _loopback(value: str) -> bool:
    """ClickHouse speichert Loopback-Netze (auch ::ffff:127.x) als HOST LOCAL statt als IP."""
    net_ = ipaddress.ip_network(value, strict=False)
    return all((getattr(a, "ipv4_mapped", None) or a).is_loopback
               for a in (net_.network_address, net_.broadcast_address))


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
    guard: bool = True  # readonly=2 senden (nur ohne write); aus, wenn der Server readonly schon erzwingt
    version: str | None = None
    include: list[str] | None = None  # scope.databases.include
    cache: dict = field(default_factory=dict)  # Lookups je Lauf (system.privileges, Rollen des Admins)


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
    params = {"wait_end_of_query": "1", **({} if s.write or not s.guard else {"readonly": "2"})}
    auth = base64.b64encode(f"{s.user}:{s.password.reveal() if s.password else ''}".encode()).decode()
    req = urllib.request.Request(f"{s.url}/?{urllib.parse.urlencode(params)}", data=sql.encode(), method="POST",
                                 headers={"Authorization": f"Basic {auth}"})
    for attempt in range(3):
        try:
            with net.urlopen(req, s.timeout, s.context) as resp:
                body = net.read(resp)
            break
        except urllib.error.HTTPError as e:
            text = "" if secret else (net.read(e).decode(errors="replace").strip().splitlines() or [""])[0][:300]
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
    context = None if tls is None else common.tls_context(tls)
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
    api_version = 1
    kinds = ("Database", "DatabaseRole", "DatabaseUser", "Grant")
    password_kinds = ("DatabaseUser",)

    def validate(self, doc):
        kind, spec = doc["kind"], doc.get("spec") or {}
        errors = [f"unknown field spec.{k}" for k in spec if k not in FIELDS[kind]]
        if kind == "Target":
            endpoint = spec.get("endpoint")
            if not isinstance(endpoint, dict):
                return [*errors, "spec.endpoint must be a mapping"]
            errors += common.validate_endpoint(endpoint, extra=("user", "timeoutSeconds"))
            user = endpoint.get("user", "default")
            if not isinstance(user, str) or not user or ":" in user:  # Basic Auth trennt am ersten ':'
                errors.append("spec.endpoint.user must be a non-empty string without ':'")
            timeout = endpoint.get("timeoutSeconds", 30)
            if type(timeout) not in (int, float) or timeout <= 0:
                errors.append("spec.endpoint.timeoutSeconds must be a positive number")
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
                    if _loopback(ip):
                        errors.append(f"spec.hostIp: loopback {ip!r} is stored by ClickHouse as host name "
                                      "'localhost'; use hostNames: [localhost]")
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
                    if p in EXPANDING:
                        errors.append(f"spec.privileges: {p} expands server-side; list privileges explicitly")
                    elif not PRIVILEGE.fullmatch(p):
                        errors.append(f"spec.privileges: invalid privilege {p!r}")
            for key in ("database", "table"):
                if key in spec and (not isinstance(spec[key], str) or not spec[key]):
                    errors.append(f"spec.{key} must be a non-empty string")
            if "table" in spec and "database" not in spec:
                errors.append("spec.table requires spec.database")
            if spec.get("database") in GRANT_FORBIDDEN_DATABASES:
                errors.append(f"spec.database: grants on system database {spec['database']!r} are not supported")
        return errors

    def desired(self, doc):
        kind, name, spec = doc["kind"], doc["metadata"]["name"], doc.get("spec") or {}
        if kind == "Database":
            return Resource(kind, name, {k: spec[k] for k in ("engine",) if k in spec})
        if kind == "DatabaseRole":
            return Resource(kind, name)
        if kind == "DatabaseUser":
            attrs = {k: sorted(set(spec[k])) for k in FIELDS[kind] if k in spec}
            if "hostIp" in attrs:
                attrs["hostIp"] = sorted({host_ip(ip) for ip in attrs["hostIp"]})
            if {"::/0", "0.0.0.0/0"} & set(attrs.get("hostIp", [])):  # ClickHouse speichert ANY nur als ::/0
                attrs["hostIp"] = ["::/0"]
            return Resource(kind, name, attrs)
        grantee, db, table = spec["grantee"], spec.get("database"), spec.get("table")
        return Resource(kind, grant_id(grantee, db, table), {
            "grantee": grantee, "database": db, "table": table,
            "privileges": sorted({privilege(p) for p in spec["privileges"]})})

    def export(self, resource):
        # Grant ohne database/table hat dort None; leere REGEXP-/LIKE-Hosts entfallen (nicht deklarierbar:
        # gesetzte bleiben stehen und lassen die Validierung scheitern, der User wird dann nicht exportiert)
        return {k: v for k, v in resource.attrs.items()
                if v is not None and not (k in ("hostNamesRegexp", "hostNamesLike") and v == [])}

    def insecure_transport(self, target):
        return target["endpoint"].get("tls") is None  # ohne tls: http://

    @contextmanager
    def connect(self, target, secret, write):
        session = _session(target, target["endpoint"].get("user", "default"), secret, write)
        session.include = ((target.get("scope") or {}).get("databases") or {}).get("include")
        # Ohne readonly=2 gefragt: ein Login mit readonly-Profil lehnt jede Änderung von readonly ab (Code 164)
        session.guard = False
        row = _post(session, "SELECT currentUser() AS u, version() AS v, getSetting('readonly') AS ro FORMAT JSON")[0]
        session.user, session.version, session.guard = row["u"], row["v"], int(row["ro"]) == 0  # u: Selbstschutz
        found = re.match(r"(\d+)\.(\d+)", session.version)
        if not found or tuple(map(int, found.groups())) < MIN_VERSION:
            raise PermanentError(f"ClickHouse {session.version} is not supported "
                                 f"(minimum {'.'.join(map(str, MIN_VERSION))})")
        yield session

    def server_version(self, session):
        return f"ClickHouse {session.version}"

    # --- Rechte-Prüfung (INV-10) ---------------------------------------------------------------

    @staticmethod
    def _in_scope(session, db) -> bool:
        """Mit ``scope.databases`` gehören globale Grants (``db is None``) nicht zum Scope."""
        if session.include is None:
            return True
        return db is not None and any(fnmatch.fnmatchcase(db, g) for g in session.include)

    @staticmethod
    def _privileges(session) -> tuple[dict, dict, dict]:
        """(Name/Alias → kanonisch, kanonisch → Elterngruppe, kanonisch → Ebene) aus system.privileges."""
        if "privileges" not in session.cache:
            names, parent, level = {}, {}, {}
            rows = _post(session, "SELECT privilege, aliases, level, parent_group FROM system.privileges FORMAT JSON")
            for r in rows:
                canon = privilege(r["privilege"])
                for n in (r["privilege"], *r["aliases"]):
                    names[privilege(n)] = canon
                parent[canon] = privilege(r["parent_group"]) if r["parent_group"] else None
                level[canon] = r["level"]
            session.cache["privileges"] = names, parent, level
        return session.cache["privileges"]

    def _privileged(self, session, name: str) -> bool | None:
        """True/False; None = ClickHouse kennt das Recht nicht."""
        names, parent, level = self._privileges(session)
        canon = names.get(privilege(name))
        if canon is None:
            return None
        node, seen = canon, set()
        while node is not None and node not in seen:
            seen.add(node)
            if node in PRIVILEGED_GROUPS or level.get(node) in PRIVILEGED_LEVELS or (
                    parent.get(node) == "ALL" and level.get(node) == "GLOBAL"):
                return True
            node = parent.get(node)
        return False

    @staticmethod
    def _closure(edges: dict, start) -> set:
        out, todo = set(), list(start)
        while todo:
            role = todo.pop()
            if role not in out:
                out.add(role)
                todo += edges.get(role, [])
        return out

    def _roles(self, session) -> tuple[set, set]:
        """(Rollen des Admins transitiv, Rollen mit privilegierten Rechten transitiv)."""
        if "roles" not in session.cache:
            edges, admin = {}, []  # Rolle/Benutzer → direkt vergebene Rollen
            for g in _post(session, "SELECT user_name, role_name, granted_role_name FROM system.role_grants "
                                    "FORMAT JSON"):
                if g["user_name"] == session.user:
                    admin.append(g["granted_role_name"])
                elif g["role_name"] is not None:
                    edges.setdefault(g["role_name"], []).append(g["granted_role_name"])
            strong = {r["role_name"] for r in _post(
                session, "SELECT role_name, access_type, database, grant_option FROM system.grants "
                         "WHERE role_name IS NOT NULL FORMAT JSON")
                if r["database"] is None or r["database"] in GRANT_FORBIDDEN_DATABASES or r["grant_option"]
                or self._privileged(session, r["access_type"]) is not False}
            powerful = {role for role in edges.keys() | strong if self._closure(edges, [role]) & strong}
            session.cache["roles"] = self._closure(edges, admin), powerful
        return session.cache["roles"]

    def check(self, session, resource, allow_privileged=False):
        attrs = resource.attrs
        if resource.kind in ("Database", "Grant"):
            db = resource.id if resource.kind == "Database" else attrs["database"]
            if not self._in_scope(session, db):
                return "global grant (*.*) is outside spec.scope.databases" if db is None else \
                    f"database {db!r} is outside spec.scope.databases"
        admin_roles, powerful = self._roles(session)
        if resource.kind == "Grant":
            if attrs["grantee"] == session.user or attrs["grantee"] in admin_roles:
                return f"grantee {attrs['grantee']!r} is the Ordivus login or one of its roles (protected)"
            unknown = [p for p in attrs["privileges"] if self._privileged(session, p) is None]
            if unknown:
                return f"unknown privilege(s) {', '.join(unknown)}"
            if not allow_privileged:
                found = [p for p in attrs["privileges"] if self._privileged(session, p)]
                if attrs["database"] is None:
                    found.insert(0, "global grant on *.*")
                if found:
                    return f"privileged ({', '.join(found)}) requires operator policy allowPrivilegedGrants"
            return self._unstable(session, attrs)
        if resource.kind == "DatabaseUser":
            strong = (set(attrs.get("roles", [])) | set(attrs.get("defaultRoles", []))) & (powerful | admin_roles)
            if strong and not allow_privileged:
                return (f"role(s) {', '.join(sorted(strong))} carry privileged grants or belong to the Ordivus "
                        "login; requires operator policy allowPrivilegedGrants")
        return None

    def _unstable(self, session, attrs) -> str | None:
        """Grund, wenn ClickHouse die deklarierten Rechte anders speichert als deklariert (sonst ewige Drift)."""
        names, parent, _ = self._privileges(session)
        want = set(attrs["privileges"])
        if aliases := [f"{p} (= {names[p]})" for p in sorted(want) if names[p] != p]:
            return f"privilege alias(es) {', '.join(aliases)}; declare the canonical name"

        def ancestors(p):
            out = []
            while (p := parent.get(p)) is not None and p not in out:
                out.append(p)
            return out

        if inner := [f"{p} (in {a})" for p in sorted(want) for a in ancestors(p) if a in want]:
            return f"privilege(s) {', '.join(inner)} already contained in a declared group"
        for group in sorted(set(parent.values()) - {None, "ALL"}):
            children = {c for c, g in parent.items() if g == group}
            if children <= want:
                return f"all sub-privileges of {group} declared; declare {group} instead"
        # Ein breiterer Grant (db.* bzw. *.*) verschluckt den engeren: ClickHouse speichert ihn nicht separat
        if "grants" not in session.cache:
            session.cache["grants"] = _post(
                session, "SELECT user_name, role_name, access_type, database, table, column, is_partial_revoke "
                         "FROM system.grants FORMAT JSON")
        db, table = attrs["database"], attrs["table"]
        broader = {(None, None), (db, None)} - {(db, table)} if db else set()
        mine = [r for r in session.cache["grants"] if attrs["grantee"] in (r["user_name"], r["role_name"])]
        if any(r["is_partial_revoke"] and r["database"] in (None, db) for r in mine):
            return None  # Teil-Revokes: Abdeckung nicht sicher bestimmbar, engere Grants zeigt ClickHouse dann einzeln
        covered = sorted(p for p in want for r in mine if r["column"] is None and (r["database"], r["table"]) in broader
                         and privilege(r["access_type"]) in {p, *ancestors(p)})
        if covered:
            return (f"privilege(s) {', '.join(dict.fromkeys(covered))} already granted to {attrs['grantee']!r} on a "
                    "broader object (db.* or *.*); ClickHouse keeps no separate narrower grant, remove it here")
        return None

    def discover(self, session, kind, scope):
        include = ((scope or {}).get("databases") or {}).get("include")

        def in_scope(db):
            return include is None or (db is not None and any(fnmatch.fnmatchcase(db, g) for g in include))

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
            admin_roles = self._roles(session)[0]
            return Discovery(COMPLETE, [Resource(kind, r["name"], manageable=r["storage"] in SQL_STORAGES,
                                                 system=r["name"] in admin_roles) for r in rows])
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
        protected = {session.user, *self._roles(session)[0]}  # Selbstaussperrung: eigene Rollen nie ändern
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
                manageable=not special and storage.get(grantee) in SQL_STORAGES, system=grantee in protected))
            have.attrs["privileges"] = sorted({*have.attrs["privileges"], privilege(r["access_type"])})
        return Discovery(COMPLETE, list(groups.values()))

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        if op.observed is not None and (op.observed.system or not op.observed.manageable or op.id == session.user):
            raise PermanentError(f"{op.kind} {op.id!r} is protected or not manageable")
        if op.kind in ("Database", "Grant"):  # zweite Sperre neben check(): nie außerhalb des Scopes schreiben
            db = op.id if op.kind == "Database" else (op.desired or op.observed).attrs["database"]
            if not self._in_scope(session, db):
                raise PermanentError(f"{op.kind} {op.id!r} is outside spec.scope.databases")
        noun = {"Database": "DATABASE", "DatabaseRole": "ROLE", "DatabaseUser": "USER"}.get(op.kind)
        if op.action == DELETE:
            if op.kind == "Grant":
                a = op.observed.attrs
                _post(session, f"REVOKE {', '.join(a['privileges'])} ON {self._on(a)} FROM {qi(a['grantee'])}")
            else:
                _post(session, f"DROP {noun} IF EXISTS {qi(op.id)}")
            return
        if op.action == SET_PASSWORD:
            rows = _post(session, f"SELECT auth_type FROM system.users WHERE name = {qs(op.id)} FORMAT JSON")
            methods = rows[0]["auth_type"] if rows else []
            if len(methods) > 1 or set(methods) - PASSWORD_AUTH:
                raise PermanentError(f"DatabaseUser {op.id!r} has authentication methods {', '.join(methods)}; "
                                     "setting the password would replace all of them, refusing")
            _post(session, f"ALTER USER {qi(op.id)} IDENTIFIED WITH sha256_password BY {qs(op.password.reveal())}",
                  secret=True)
            return
        want = op.desired.attrs
        if op.kind == "Grant":
            old = set(op.changes["privileges"][0] or []) if op.action == UPDATE else set()
            # erst REVOKE: ein entzogenes Gruppenrecht nähme sonst gerade gewährte Unterrechte mit
            if removed := sorted(old - set(want["privileges"])):
                _post(session, f"REVOKE {', '.join(removed)} ON {self._on(want)} FROM {qi(want['grantee'])}")
            if added := sorted(set(want["privileges"]) - old):
                _post(session, f"GRANT {', '.join(added)} ON {self._on(want)} TO {qi(want['grantee'])}")
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
            probe = _session(target, resource.id, password, write=False)
            probe.guard = False  # fester SELECT; readonly=2 scheiterte an Benutzern mit readonly-Profil (Code 164)
            _post(probe, "SELECT 1 AS ok FORMAT JSON")
        except AuthorizationError as e:
            return False if e.code == AUTH_FAILED else None
        except (TransientError, PermanentError):
            return None
        return True
