"""PostgreSQL-Adapter (§7.2, §9.3, §32 Nr. 10–11). Nutzerdoku: ``docs/adapters/postgresql.md``.

Kinds: ``DatabaseRole`` (Rolle ohne LOGIN), ``DatabaseUser`` (Rolle mit LOGIN), ``Database``, ``Grant``.
Rollen sind instanzweit, Grants liegen je Datenbank: die Grant-Discovery öffnet eine Verbindung je
Datenbank im Scope (einmal je Session, danach wiederverwendet) und meldet ``partial``, sobald eine davon nicht
lesbar ist.
"""

import hashlib
import json
import logging
from collections import defaultdict
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

from ordivus.adapters import common
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    PARTIAL,
    SET_PASSWORD,
    UPDATE,
    Adapter,
    AdapterError,
    AuthorizationError,
    Discovery,
    Op,
    PermanentError,
    Resource,
    Secret,
    TransientError,
)

ROLE_KINDS = ("DatabaseRole", "DatabaseUser")
SYSTEM_DATABASES = frozenset({"postgres", "template0", "template1"})
BOOTSTRAP_OID = 10
TLS_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")
PRIVILEGES = {
    "database": ("CONNECT", "CREATE", "TEMPORARY"),
    "schema": ("CREATE", "USAGE"),
    "tables-in-schema": ("DELETE", "INSERT", "MAINTAIN", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"),
}
LOCK_KEY = int.from_bytes(hashlib.sha256(b"ordivus").digest()[:8], "big", signed=True)
USER_SCHEMA = "n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'"
ACL_QUERIES = {
    "database": "SELECT NULL, d.datdba, a.grantee, a.privilege_type FROM pg_database d, "
                "aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a WHERE d.datname = current_database()",
    "schema": "SELECT n.nspname, n.nspowner, a.grantee, a.privilege_type FROM pg_namespace n, "
              f"aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a WHERE {USER_SCHEMA}",
}
# Tabellen, Views, Materialized Views, Foreign und partitionierte Tabellen = Umfang von GRANT ... ALL TABLES
TABLES_QUERY = ("SELECT n.nspname, c.oid, c.relowner, a.grantee, a.privilege_type FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "LEFT JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a ON true "
                f"WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND {USER_SCHEMA}")


def _chain(start: str, where: str = "") -> str:
    """CTE ``up``: die Rolle ``start`` und alle Rollen, deren Mitglied sie (transitiv) ist; UNION bricht Zyklen."""
    return ("WITH RECURSIVE up(oid) AS (SELECT oid FROM pg_roles WHERE rolname = " + start +
            " UNION SELECT m.roleid FROM pg_auth_members m JOIN up ON m.member = up.oid" + where + ") ")


# Nur Mitgliedschaften, die Rechte bringen (INHERIT oder SET): PG 16+ macht eine CREATEROLE-Anmeldung zum reinen
# ADMIN-Mitglied jeder Rolle, die sie anlegt. Vor PG 16 fehlen die Spalten (NULL über to_jsonb) → jede zählt.
HOLDS_PRIVILEGES = (" WHERE coalesce((to_jsonb(m) ->> 'inherit_option')::bool OR "
                    "(to_jsonb(m) ->> 'set_option')::bool, true)")
# Rollen, deren Mitglied die Ordivus-Anmeldung ist: Entzug/Löschen hieße Selbstaussperrung (nie pg_has_role:
# für Superuser ist das für jede Rolle wahr)
ADMIN_CHAIN = _chain("current_user", HOLDS_PRIVILEGES) + "SELECT oid FROM up"
ROLES_QUERY = ("SELECT r.oid, r.rolname, r.rolcanlogin, r.rolsuper, r.rolconnlimit, r.rolcreatedb, r.rolcreaterole, "
               "array(SELECT DISTINCT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid "
               f"WHERE m.member = r.oid ORDER BY 1), r.rolname = current_user, r.oid IN ({ADMIN_CHAIN}) "
               "FROM pg_roles r")
# Rechte, die eine Mitgliedschaft in ``%s`` (transitiv) mitbringt
PRIVILEGED_QUERY = _chain("%s") + ("SELECT r.oid, r.rolname, r.rolsuper, r.rolcreaterole, r.rolreplication, "
                                   "r.rolbypassrls, r.rolcanlogin, r.rolname = current_user "
                                   "FROM pg_roles r JOIN up USING (oid)")
# Grants, mit denen der Empfänger Code unter fremder Identität ausführen lassen kann (allowPrivilegedGrants):
# TRIGGER: Trigger laufen als der Nutzer, der schreibt (z. B. ein Superuser) → Eskalation.
# MAINTAIN (PG 17): VACUUM/ANALYZE/REINDEX führen Index- und Funktionsausdrücke aus.
# CREATE auf Schema/Datenbank: Objekte im search_path fremder Rollen (bzw. ein Schema "$user") kapern deren Aufrufe.
PRIVILEGED_GRANTS = {"database": {"CREATE"}, "schema": {"CREATE"}, "tables-in-schema": {"TRIGGER", "MAINTAIN"}}
RESERVED_SCHEMAS = ("pg_catalog", "information_schema")
MAX_DATABASE_CONNECTIONS = 8  # je Session offen gehaltene Datenbankverbindungen (LRU); max_connections ist knapp
log = logging.getLogger("ordivus")
MIN_VERSION = 130000  # server_version_num; ältere Versionen sind ungetestet und ohne Herstellersupport


@dataclass
class Session:
    conn: Any
    target: dict
    secret: Secret | None
    write: bool
    version: int  # server_version_num, z. B. 170002
    databases: dict = field(default_factory=dict)  # dbname -> offene Verbindung, älteste zuerst (LRU)


# --- Validierung --------------------------------------------------------------------------------

def _unknown(spec: dict, allowed: set[str], prefix: str = "spec") -> list[str]:
    return [f"unknown field {prefix}.{k}" for k in spec if k not in allowed]


def _name(value, field: str) -> list[str]:
    if not isinstance(value, str) or not value or "\x00" in value:
        return [f"{field} must be a non-empty string"]
    if len(value.encode()) > 63:  # PostgreSQL kürzt längere Identifier stillschweigend
        return [f"{field} must be at most 63 bytes"]
    return []


def _mapping(spec: dict, key: str, allowed: set[str], prefix: str) -> tuple[dict, list[str]]:
    value = spec.get(key, {})
    if not isinstance(value, dict):
        return {}, [f"{prefix}.{key} must be a mapping"]
    return value, _unknown(value, allowed, f"{prefix}.{key}")


def _validate_target(spec: dict) -> list[str]:
    errors = _unknown(spec, {"endpoint", "scope"})
    if not isinstance(spec.get("endpoint"), dict):
        return [*errors, "spec.endpoint must be a mapping"]
    ep = spec["endpoint"]
    errors += common.validate_endpoint(ep, extra=("database", "user"), tls_fields=("mode", "caFile"))
    errors += _name(ep.get("user"), "spec.endpoint.user")
    errors += _name(ep.get("database", "postgres"), "spec.endpoint.database")
    tls = ep.get("tls", {})
    if isinstance(tls, dict) and tls.get("mode", "prefer") not in TLS_MODES:
        errors.append(f"spec.endpoint.tls.mode must be one of {list(TLS_MODES)}")
    scope, problems = _mapping(spec, "scope", {"databases", "roles"}, "spec")
    errors += problems
    for key in ("databases", "roles"):
        part, problems = _mapping(scope, key, {"include"}, "spec.scope")
        include = part.get("include", [])
        if not isinstance(include, list) or not all(isinstance(i, str) for i in include):
            problems.append(f"spec.scope.{key}.include must be a list of strings")
        errors += problems
    return errors


def _privilege(value) -> str:
    value = value.upper() if isinstance(value, str) else ""
    return "TEMPORARY" if value == "TEMP" else value


def _validate_resource(kind: str, spec: dict) -> list[str]:
    errors = _name(spec["name"], "spec.name") if "name" in spec else []
    if kind == "Database":
        errors += _unknown(spec, {"name", "owner", "encoding"})
        if "owner" in spec:
            errors += _name(spec["owner"], "spec.owner")
        if "encoding" in spec and (not isinstance(spec["encoding"], str) or not spec["encoding"]):
            errors.append("spec.encoding must be a non-empty string")
    elif kind in ROLE_KINDS:
        if "superuser" in spec:
            errors.append("spec.superuser is not manageable by Ordivus")
        errors += _unknown(spec, {"name", "memberOf", "connectionLimit", "createdb", "createrole", "superuser"})
        member_of = spec.get("memberOf", [])
        if not isinstance(member_of, list):
            errors.append("spec.memberOf must be a list of role names")
        else:
            errors += [e for i, r in enumerate(member_of) for e in _name(r, f"spec.memberOf[{i}]")]
        limit = spec.get("connectionLimit", -1)
        if type(limit) is not int or limit < -1:
            errors.append("spec.connectionLimit must be an integer >= -1")
        errors += [f"spec.{k} must be a boolean" for k in ("createdb", "createrole")
                   if not isinstance(spec.get(k, False), bool)]
    else:  # Grant
        errors = _unknown(spec, {"grantee", "database", "on", "schema", "privileges"})
        errors += _name(spec.get("grantee"), "spec.grantee") + _name(spec.get("database"), "spec.database")
        if isinstance(spec.get("grantee"), str) and spec["grantee"].lower() == "public":
            errors.append("grants to PUBLIC are not supported")
        on = spec.get("on")
        if on not in PRIVILEGES:
            return [*errors, f"spec.on must be one of {list(PRIVILEGES)}"]
        if on == "database" and "schema" in spec:
            errors.append("spec.schema is not allowed with on: database")
        elif on != "database":
            errors += _name(spec.get("schema"), "spec.schema")
            schema = spec.get("schema")
            if isinstance(schema, str) and (schema in RESERVED_SCHEMAS or schema.startswith("pg_")):
                errors.append(f"spec.schema {schema!r} is a system schema; grants on it are not supported")
        privileges = spec.get("privileges")
        if not isinstance(privileges, list) or not privileges:
            errors.append("spec.privileges must be a non-empty list")
        else:
            errors += [f"spec.privileges: {p!r} is not one of {list(PRIVILEGES[on])}"
                       for p in privileges if _privilege(p) not in PRIVILEGES[on]]
    return errors


def _grant_id(attrs: dict) -> str:
    # JSON statt Trennzeichen: Namen dürfen jedes Zeichen enthalten, der Schlüssel bleibt eindeutig
    key = [attrs["grantee"], attrs["database"], attrs["on"]] + ([attrs["schema"]] if "schema" in attrs else [])
    return json.dumps(key, ensure_ascii=False, separators=(",", ":"))


# --- Verbindung und Fehler ------------------------------------------------------------------------

def _params(target: dict, secret: Secret | None, dbname: str | None = None, user: str | None = None,
            read_only: bool = True) -> dict:
    ep = target["endpoint"]
    tls = ep.get("tls", {})
    params = {"host": ep["host"], "port": ep.get("port", 5432), "dbname": dbname or ep.get("database", "postgres"),
              "user": user or ep["user"], "connect_timeout": 10, "application_name": "ordivus", "autocommit": True}
    if secret is not None:
        params["password"] = secret.reveal()
    if "mode" in tls:
        params["sslmode"] = tls["mode"]
    if "caFile" in tls:
        params["sslrootcert"] = tls["caFile"]
    if read_only:
        params["options"] = "-c default_transaction_read_only=on"
    return params


def _error(e) -> AdapterError:
    import psycopg

    state = e.sqlstate or ""
    text = (e.diag.message_primary if state else None) or " ".join(str(e).split())
    message = f"{state}: {text}" if state else text
    if state == "42501" or state.startswith("28"):
        return AuthorizationError(message)
    if state[:2] in ("08", "40", "53", "57") or state == "55P03":
        return TransientError(message)
    if not state and isinstance(e, psycopg.OperationalError):  # Verbindungsfehler tragen keinen SQLSTATE
        return (AuthorizationError if "password authentication failed" in text else TransientError)(message)
    return PermanentError(message)


@contextmanager
def _mapped():
    import psycopg

    try:
        yield
    except psycopg.Error as e:
        raise _error(e) from None


def _connect(params: dict):
    import psycopg

    with _mapped():
        return psycopg.connect(**params)


@contextmanager
def _open(params: dict):
    conn = _connect(params)
    try:
        yield conn
    finally:
        conn.close()


# --- Adapter ------------------------------------------------------------------------------------

class PostgreSQLAdapter(Adapter):
    id = "postgresql"
    api_version = 1
    # Rollen vor Datenbanken: CREATE DATABASE ... OWNER braucht die Rolle; Löschen läuft umgekehrt
    kinds = ("DatabaseRole", "DatabaseUser", "Database", "Grant")
    password_kinds = ("DatabaseUser",)

    def validate(self, doc):
        spec = doc.get("spec") or {}
        return _validate_target(spec) if doc["kind"] == "Target" else _validate_resource(doc["kind"], spec)

    def desired(self, doc):
        kind, spec = doc["kind"], doc.get("spec") or {}
        name = spec.get("name", doc["metadata"]["name"])
        if kind == "Database":
            attrs = {k: spec[k] for k in ("owner",) if k in spec}
            if "encoding" in spec:
                attrs["encoding"] = spec["encoding"].upper()
            return Resource(kind, name, attrs)
        if kind in ROLE_KINDS:
            attrs = {k: spec[k] for k in ("connectionLimit", "createdb", "createrole") if k in spec}
            if "memberOf" in spec:
                attrs["memberOf"] = sorted(set(spec["memberOf"]))
            return Resource(kind, name, attrs)
        attrs = {k: spec[k] for k in ("grantee", "database", "on", "schema") if k in spec}
        attrs["privileges"] = sorted({_privilege(p) for p in spec["privileges"]})
        return Resource(kind, _grant_id(attrs), attrs)

    def validate_target(self, target, resources):
        roles = {r.id for r in resources if r.kind == "DatabaseRole"}  # beides ist dieselbe native Rolle
        return [f"role {r.id!r} is declared as both DatabaseRole and DatabaseUser"
                for r in resources if r.kind == "DatabaseUser" and r.id in roles]

    def dependencies(self, resource):
        # GRANT parent TO member braucht die Elternrolle; sie kann DatabaseRole oder DatabaseUser sein
        if resource.kind not in ROLE_KINDS:
            return []
        return [(kind, parent) for parent in resource.attrs.get("memberOf", []) for kind in ROLE_KINDS]

    def insecure_transport(self, target):
        # verify-ca prüft den Hostnamen nicht: jedes Zertifikat derselben CA wäre akzeptiert
        return target["endpoint"].get("tls", {}).get("mode", "prefer") != "verify-full"

    def export(self, resource):
        # superuser ist nur beobachtet (Regeln), nie verwaltbar; Superuser selbst sind manageable=False
        return {k: v for k, v in resource.attrs.items() if k != "superuser"}

    def check(self, session, resource, allow_privileged=False):
        policy = "requires operator policy allowPrivilegedGrants"
        if resource.kind == "Grant":
            if "MAINTAIN" in resource.attrs["privileges"] and session.version < 170000:
                return f"MAINTAIN requires PostgreSQL 17 or later (server is {self.server_version(session)})"
            found = sorted(PRIVILEGED_GRANTS[resource.attrs["on"]] & set(resource.attrs["privileges"]))
            if found and not allow_privileged:
                return f"{', '.join(found)} on {resource.attrs['on']} is privileged; {policy}"
            return None
        if resource.kind not in ROLE_KINDS:
            return None
        if resource.attrs.get("createrole") and not allow_privileged:
            return f"createrole is privileged; {policy}"
        for parent in resource.attrs.get("memberOf", []):
            if not common.in_scope(session.target.get("scope"), "roles", parent):  # auch mit Freigabe nie
                return f"memberOf {parent!r} is outside spec.scope.roles"
            if parent.startswith("pg_") and not allow_privileged:
                return f"memberOf {parent!r}: predefined pg_* roles are privileged; {policy}"
            with _mapped():
                rows = session.conn.execute(PRIVILEGED_QUERY, (parent,)).fetchall()
            for oid, name, superuser, createrole, replication, bypassrls, login, me in rows:
                if me or oid == BOOTSTRAP_OID:  # auch mit Freigabe nie: Ordivus-Anmeldung, Bootstrap-Superuser
                    return f"memberOf {parent!r} would grant the role {name!r} (Ordivus login or bootstrap superuser)"
                why = [w for w, on in (("SUPERUSER", superuser), ("CREATEROLE", createrole),
                                       ("REPLICATION", replication), ("BYPASSRLS", bypassrls),
                                       ("LOGIN role", login),
                                       ("predefined pg_* role", name.startswith("pg_"))) if on]
                if why and not allow_privileged:
                    return f"memberOf {parent!r} is privileged (via {name!r}: {', '.join(why)}); {policy}"
        return None

    @contextmanager
    def connect(self, target, secret, write):
        with _open(_params(target, secret, read_only=not write)) as conn:
            session = Session(conn, target, secret, write, conn.info.server_version)
            if session.version < MIN_VERSION:
                raise PermanentError(f"{self.server_version(session)} is not supported (minimum PostgreSQL 13)")
            try:
                yield session
            finally:
                _close_databases(session)

    def server_version(self, session):
        major, minor = divmod(session.version, 10000)  # ab PG 10: MMmmmm, davor MMmmpp (9.6.24 = 90624)
        return f"PostgreSQL {major}.{minor}" if major >= 10 else f"PostgreSQL {major}.{minor // 100}.{minor % 100}"

    def _database(self, session: Session, dbname: str):
        # Schreibsession: eine Verbindung je Datenbank für Lesen und Schreiben; plan/drift bleiben read-only
        conn = session.databases.pop(dbname, None)
        if conn is None or conn.closed:
            while len(session.databases) >= MAX_DATABASE_CONNECTIONS:
                _close_databases(session, next(iter(session.databases)))
            conn = _connect(_params(session.target, session.secret, dbname=dbname, read_only=not session.write))
        session.databases[dbname] = conn
        return conn

    def discover(self, session, kind, scope):
        with _mapped():
            if kind == "Database":
                rows = session.conn.execute(
                    "SELECT datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding) FROM pg_database")
                return Discovery(COMPLETE, [
                    Resource(kind, n, {"owner": owner, "encoding": enc}, system=n in SYSTEM_DATABASES)
                    for n, owner, enc in rows if common.in_scope(scope, "databases", n)])
            if kind in ROLE_KINDS:
                return Discovery(COMPLETE, [
                    Resource(kind, n, {"memberOf": list(member_of), "connectionLimit": limit, "createdb": createdb,
                                       "createrole": createrole, "superuser": superuser},
                             manageable=not (superuser or me),
                             system=oid == BOOTSTRAP_OID or n.startswith("pg_") or admin_chain)
                    for oid, n, login, superuser, limit, createdb, createrole, member_of, me, admin_chain
                    in session.conn.execute(ROLES_QUERY)
                    if login == (kind == "DatabaseUser") and common.in_scope(scope, "roles", n)])
            databases = [n for (n,) in session.conn.execute(
                "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1")
                if common.in_scope(scope, "databases", n)]
        resources, failed = [], []
        for db in databases:
            try:
                with _mapped():
                    resources += _grants(self._database(session, db), db, scope)
            except AdapterError as e:
                failed.append(f"database {db!r}: {type(e).__name__}: {e}")
                log.warning("grant discovery in database %r failed: %s: %s", db, type(e).__name__, e)
        return Discovery(PARTIAL if failed else COMPLETE, resources, "; ".join(failed))

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        from psycopg import sql

        with _mapped():
            if op.kind == "Grant":
                self._apply_grant(session, op, sql)
            elif op.kind == "Database":
                if op.action == DELETE:  # DROP DATABASE scheitert an offenen Verbindungen
                    _close_databases(session, op.id)
                _apply_database(session.conn, op, sql)
            else:
                with session.conn.transaction():
                    _apply_role(session.conn, op, sql)

    def _apply_grant(self, session: Session, op: Op, sql):
        attrs = (op.desired or op.observed).attrs
        db, on = attrs["database"], attrs["on"]
        if not common.in_scope(session.target.get("scope"), "databases", db):
            raise PermanentError(f"database {db!r} is outside the target scope")
        obj = sql.SQL({"database": "DATABASE {}", "schema": "SCHEMA {}", "tables-in-schema": "ALL TABLES IN SCHEMA {}"}
                      [on]).format(sql.Identifier(db if on == "database" else attrs["schema"]))
        grantee = sql.Identifier(attrs["grantee"])

        def privileges(names):  # nur Werte aus der Allowlist werden zu SQL
            if not set(names) <= set(PRIVILEGES[on]):
                raise PermanentError(f"invalid privileges for {on}")
            return sql.SQL(", ").join(sql.SQL(p) for p in names)

        conn = self._database(session, db)
        with _mapped(), conn.transaction():
            if op.action == DELETE:
                # nur die beobachteten Rechte: ALL PRIVILEGES träfe auch nicht verwaltete Einzeltabellen-Grants
                conn.execute(sql.SQL("REVOKE {} ON {} FROM {}").format(privileges(attrs["privileges"]), obj, grantee))
                return
            want = attrs["privileges"]
            known = [p for p in PRIVILEGES[on] if p != "MAINTAIN" or conn.info.server_version >= 170000]
            extra = [p for p in known if p not in want]
            conn.execute(sql.SQL("GRANT {} ON {} TO {}").format(privileges(want), obj, grantee))
            if extra:
                conn.execute(sql.SQL("REVOKE {} ON {} FROM {}").format(privileges(extra), obj, grantee))

    def verify_password(self, session, target, resource, password):
        try:
            with _open(_params(target, password, user=resource.id)):
                return True
        except AdapterError as e:
            # Verbindungsfehler tragen keinen SQLSTATE: 28P01 nur am Servertext erkennbar (lc_messages=English);
            # der Rollenname wird entfernt, damit er den Text nicht vortäuschen kann
            return False if "password authentication failed" in str(e).replace(resource.id, "") else None

    @contextmanager
    def lock(self, session):
        with _mapped():
            got = session.conn.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0]
        if not got:
            raise TransientError("another Ordivus apply holds the advisory lock on this target")
        try:
            yield
        finally:
            with suppress(Exception):  # bricht die Verbindung ab, gibt PostgreSQL die Sperre selbst frei
                session.conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))


def _close_databases(session: Session, dbname: str | None = None) -> None:
    for key in [k for k in session.databases if dbname in (None, k)]:
        with suppress(Exception):
            session.databases.pop(key).close()


def _grants(conn, db: str, scope: dict | None) -> list[Resource]:
    names = dict(conn.execute("SELECT oid, rolname FROM pg_roles"))
    admin = {oid for (oid,) in conn.execute(ADMIN_CHAIN)}  # Rechte der eigenen Anmeldung nie entziehen
    found, owners = defaultdict(set), {}
    for on, query in ACL_QUERIES.items():
        for schema, owner, grantee, privilege in conn.execute(query):
            if grantee:  # 0 = PUBLIC: nicht inventarisiert
                found[(on, schema, grantee)].add(privilege)
                owners[(on, schema)] = owner
    tables, held = defaultdict(dict), defaultdict(lambda: defaultdict(set))
    for schema, oid, owner, grantee, privilege in conn.execute(TABLES_QUERY):
        tables[schema][oid] = owner
        if grantee and grantee != owner:
            held[(schema, grantee)][privilege].add(oid)
    for (schema, grantee), by_privilege in held.items():
        owned = {oid for oid, owner in tables[schema].items() if owner == grantee}  # Eigentümer hat implizit alles
        complete = {p for p, oids in by_privilege.items() if len(oids | owned) == len(tables[schema])}
        if complete:  # nur Einzeltabellen-Rechte: kein tables-in-schema-Grant (sonst UNMANAGED/DELETE-Rauschen)
            found[("tables-in-schema", schema, grantee)] = complete
    resources = []
    for (on, schema, grantee), privileges in found.items():
        name = names.get(grantee)
        if name is None or not common.in_scope(scope, "roles", name):
            continue
        attrs = {"grantee": name, "database": db, "on": on, **({"schema": schema} if schema else {}),
                 "privileges": sorted(privileges)}
        system = grantee == BOOTSTRAP_OID or name.startswith("pg_") or grantee == owners.get((on, schema)) \
            or grantee in admin
        resources.append(Resource("Grant", _grant_id(attrs), attrs, system=system))
    return resources


def _apply_database(conn, op: Op, sql):
    name = sql.Identifier(op.id)
    if op.action == CREATE:
        attrs = op.desired.attrs
        query = sql.SQL("CREATE DATABASE {}").format(name)
        if "owner" in attrs:
            query += sql.SQL(" OWNER {}").format(sql.Identifier(attrs["owner"]))
        if "encoding" in attrs:
            query += sql.SQL(" ENCODING {} TEMPLATE template0").format(sql.Literal(attrs["encoding"]))
    elif op.action == UPDATE:
        if "encoding" in op.changes:
            raise PermanentError("the encoding of an existing database cannot be changed")
        query = sql.SQL("ALTER DATABASE {} OWNER TO {}").format(name, sql.Identifier(op.changes["owner"][1]))
    elif op.action == DELETE:
        query = sql.SQL("DROP DATABASE {}").format(name)
    else:
        raise PermanentError(f"unsupported action {op.action} for Database")
    conn.execute(query)


def _role_options(attrs: dict, sql) -> list:
    options = [sql.SQL(f"{'' if attrs[k] else 'NO'}{k.upper()}") for k in ("createdb", "createrole") if k in attrs]
    if "connectionLimit" in attrs:
        options.append(sql.SQL("CONNECTION LIMIT {}").format(sql.Literal(attrs["connectionLimit"])))
    return options


def _verifier(conn, op: Op, sql):
    # SCRAM-Verifier clientseitig: das Klartextpasswort erreicht weder Server noch Server-Log
    value = conn.pgconn.encrypt_password(op.password.reveal().encode(), op.id.encode(), b"scram-sha-256")
    return sql.SQL("PASSWORD {}").format(sql.Literal(value.decode()))


def _apply_role(conn, op: Op, sql):
    name = sql.Identifier(op.id)
    if op.action == CREATE:
        attrs = op.desired.attrs
        options = [sql.SQL("LOGIN" if op.kind == "DatabaseUser" else "NOLOGIN"), *_role_options(attrs, sql)]
        if op.password is not None:
            options.append(_verifier(conn, op, sql))
        conn.execute(sql.SQL("CREATE ROLE {} WITH {}").format(name, sql.SQL(" ").join(options)))
        for role in attrs.get("memberOf", []):
            conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(role), name))
    elif op.action == UPDATE:
        options = _role_options({k: new for k, (_, new) in op.changes.items()}, sql)
        if options:
            conn.execute(sql.SQL("ALTER ROLE {} WITH {}").format(name, sql.SQL(" ").join(options)))
        if "memberOf" in op.changes:
            old, new = (set(v or []) for v in op.changes["memberOf"])
            for role in sorted(new - old):
                conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(role), name))
            for role in sorted(old - new):
                conn.execute(sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(role), name))
    elif op.action == SET_PASSWORD:
        conn.execute(sql.SQL("ALTER ROLE {} WITH {}").format(name, _verifier(conn, op, sql)))
    elif op.action == DELETE:
        conn.execute(sql.SQL("DROP ROLE {}").format(name))
    else:
        raise PermanentError(f"unsupported action {op.action} for {op.kind}")
