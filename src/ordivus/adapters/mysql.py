"""MySQL-8-Adapter (PyMySQL): Database, DatabaseRole, DatabaseUser, Grant. Doku: docs/adapters/mysql.md.

Konten sind ``name@host``. Rolle = Konto mit ``account_locked='Y'``, ``password_expired='Y'`` und leerem
``authentication_string`` (Fingerabdruck von ``CREATE ROLE``); alles andere ist ein User.
Werte (Kontonamen, Passwörter) gehen über PyMySQLs ``escape()`` (dieselbe Escape-Funktion wie bei
Query-Parametern, beachtet ``NO_BACKSLASH_ESCAPES``); Identifier über ``quote_ident``. Statements werden
ohne Parameter ausgeführt, damit ``%`` in Identifiern nicht als Platzhalter gelesen wird.
"""

import fnmatch
import re
import ssl
from contextlib import contextmanager
from dataclasses import dataclass, field, replace

from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    PARTIAL,
    SET_PASSWORD,
    Adapter,
    AuthorizationError,
    Discovery,
    Op,
    PermanentError,
    Resource,
    Secret,
    TransientError,
)

SYSTEM_DATABASES = frozenset({"mysql", "sys", "information_schema", "performance_schema"})
SYSTEM_USERS = frozenset({"root", "mysql.sys", "mysql.session", "mysql.infoschema"})  # root auf jedem Host
TLS_MODES = ("disable", "require", "verify-ca", "verify-full")
LEVELS = ("global", "database", "table")
AUTH_CODES = {1044, 1045, 1142, 1143, 1227, 1370, 1410}
TRANSIENT_CODES = {1040, 1053, 1205, 1213, 2002, 2003, 2005, 2006, 2013, 2055}
PRIV_RE = re.compile(r"[A-Z_]+( [A-Z_]+)*")
CHARSET_RE = re.compile(r"[a-z0-9_]+")
COLUMN_PRIVS = {"Create_tmp_table": "CREATE TEMPORARY TABLES", "Repl_slave": "REPLICATION SLAVE",
                "Repl_client": "REPLICATION CLIENT", "Show_db": "SHOW DATABASES", "Grant": "GRANT OPTION"}
LOCK_TIMEOUT = 10
# INV-10: nur mit Operator-Policy allowPrivilegedGrants (zusätzlich: jedes on: global und alles auf *_ADMIN)
PRIVILEGED = frozenset({"SUPER", "CREATE USER", "SYSTEM_USER", "FILE", "PROXY", "SHUTDOWN", "PROCESS", "RELOAD",
                        "GRANT OPTION", "CREATE ROLE", "DROP ROLE", "REPLICATION SLAVE", "REPLICATION CLIENT",
                        "CREATE TABLESPACE", "SHOW DATABASES"})


def quote_ident(name: str) -> str:
    """Backtick-Quoting für Identifier; eingebettete Backticks werden verdoppelt."""
    return "`" + name.replace("`", "``") + "`"


def account(ref: str) -> tuple[str, str]:
    """``name@host`` → (name, host); ohne ``@`` ist der Host ``%``. Letztes ``@`` trennt (E-Mail-Namen)."""
    name, at, host = ref.rpartition("@")
    return (name, host.lower()) if at else (ref, "%")


def _id(name: str, host: str) -> str:
    return f"{name}@{host}"


def _norm_privs(privs) -> list[str]:
    return sorted({" ".join(p.split()).upper() for p in privs})


def _grant_object(attrs: dict, statement: bool = False) -> str:
    """``db.*``/``db.tbl``/``*.*``; ``statement``: Datenbankname für GRANT/REVOKE auf Datenbankebene escapen."""
    if attrs["on"] == "global":
        return "*.*"
    table = quote_ident(attrs["table"]) if attrs["on"] == "table" else "*"
    db = attrs["database"]
    if statement and attrs["on"] == "database":
        db = re.sub(r"([\\_%])", r"\\\1", db)  # _ und % sind dort Wildcards: app_db träfe sonst auch appXdb
    return f"{quote_ident(db)}.{table}"


def _db_pattern(raw: str) -> tuple[str, bool]:
    """``mysql.db.Db`` → (Name ohne Escapes, enthält unescapte Wildcards ``_``/``%``)."""
    tokens = re.findall(r"\\.|.", raw, re.S)
    return "".join(t[-1] for t in tokens), any(t in ("_", "%") for t in tokens)


def _grant_resource(grantee: str, level: str, privs, db=None, table=None, **flags) -> Resource:
    attrs = {"grantee": grantee, "on": level, **({"database": db} if db is not None else {}),
             **({"table": table} if table is not None else {}), "privileges": _norm_privs(privs)}
    return Resource("Grant", f"{grantee} ON {_grant_object(attrs)}", attrs, **flags)


def _error(e: Exception, what: str, secret: bool = False) -> Exception:
    """Treiberfehler → AdapterError. Bei Statements mit Passwort nur der Code (MySQL zitiert SQL-Text)."""
    code = e.args[0] if e.args and isinstance(e.args[0], int) else None
    text = "" if secret or len(e.args) < 2 else f": {e.args[1]}"
    if code == 1396:
        text += " (account exists or is missing; an account cannot be both DatabaseUser and DatabaseRole)"
    msg = f"{what} failed: MySQL error {code}{text}"
    if code in AUTH_CODES:
        return AuthorizationError(msg)
    if code in TRANSIENT_CODES or code is None:
        return TransientError(msg)
    return PermanentError(msg)


@dataclass
class MySQLSession:
    conn: object
    write: bool
    current: str  # eigenes Konto, wird nie verändert oder gelöscht
    scope: dict | None = None
    cache: dict = field(default_factory=dict)  # Lookups für check/discover, gilt nur für diese Session


def _privileged(attrs: dict) -> list[str]:
    privs = [p for p in attrs["privileges"] if p in PRIVILEGED or p.endswith("_ADMIN")]
    return ["on: global", *privs] if attrs["on"] == "global" else privs


def _connect_args(endpoint: dict) -> dict:
    tls = endpoint.get("tls") or {}
    mode = tls.get("mode", "verify-full")
    args = {"host": endpoint["host"], "port": endpoint.get("port", 3306), "connect_timeout": 10,
            "autocommit": True, "charset": "utf8mb4"}
    if mode == "disable":
        return {**args, "ssl_disabled": True}
    ctx = ssl.create_default_context(cafile=tls.get("caFile"))
    if mode in ("require", "verify-ca"):
        ctx.check_hostname = False
    if mode == "require":
        ctx.verify_mode = ssl.CERT_NONE
    return {**args, "ssl": ctx}


def _open(endpoint: dict, user: str, password: str):
    import pymysql  # lazy: fehlendes Extra blockiert andere Adapter nicht

    # PyMySQL kodiert str-Passwörter als latin1, der Server hasht UTF-8 → Bytes übergeben
    return pymysql.connect(user=user, password=password.encode(), **_connect_args(endpoint))


class MySQLAdapter(Adapter):
    id = "mysql"
    kinds = ("Database", "DatabaseRole", "DatabaseUser", "Grant")
    password_kinds = ("DatabaseUser",)

    # --- Validierung ----------------------------------------------------------------------------

    def validate(self, doc):
        spec, kind = doc.get("spec") or {}, doc["kind"]
        fields = {"Target": {"endpoint", "scope"}, "Database": {"name", "characterSet", "collation"},
                  "DatabaseRole": {"identity"}, "DatabaseUser": {"identity", "roles", "defaultRoles", "accountLocked"},
                  "Grant": {"grantee", "on", "database", "table", "privileges"}}[kind]
        errors = [f"unknown field spec.{k}" for k in spec if k not in fields]
        if kind == "Database":  # Datenbankname: spec.name, sonst metadata.name
            spec = {"name": doc["metadata"]["name"], **spec}
        check = getattr(self, f"_validate_{kind}")
        return errors + check(spec)

    @staticmethod
    def _name_errors(value, where, limit) -> list[str]:
        if not isinstance(value, str) or not value or len(value) > limit or "\0" in value:
            return [f"{where} must be a non-empty string of at most {limit} characters"]
        return []

    def _validate_Target(self, spec):
        ep = spec.get("endpoint")
        if not isinstance(ep, dict):
            return ["spec.endpoint must be a mapping"]
        errors = [f"unknown field spec.endpoint.{k}" for k in ep if k not in {"host", "port", "user", "tls"}]
        for key in ("host", "user"):
            errors += self._name_errors(ep.get(key), f"spec.endpoint.{key}", 255)
        if "port" in ep and (type(ep["port"]) is not int or not 0 < ep["port"] < 65536):
            errors.append("spec.endpoint.port must be an integer 1-65535")
        tls = ep.get("tls", {})
        if not isinstance(tls, dict):
            errors.append("spec.endpoint.tls must be a mapping")
        else:
            errors += [f"unknown field spec.endpoint.tls.{k}" for k in tls if k not in {"mode", "caFile"}]
            if tls.get("mode", "verify-full") not in TLS_MODES:
                errors.append(f"spec.endpoint.tls.mode must be one of {list(TLS_MODES)}")
            if "caFile" in tls and not isinstance(tls["caFile"], str):
                errors.append("spec.endpoint.tls.caFile must be a string")
        scope = spec.get("scope", {})
        if not isinstance(scope, dict):
            return [*errors, "spec.scope must be a mapping"]
        for key, value in scope.items():
            if key not in ("databases", "users", "roles"):
                errors.append(f"unknown field spec.scope.{key}")
            elif not isinstance(value, dict) or set(value) - {"include"} or not isinstance(
                    value.get("include"), list) or not all(isinstance(g, str) for g in value["include"]):
                errors.append(f"spec.scope.{key} must be {{include: [glob, ...]}}")
        return errors

    def _validate_Database(self, spec):
        name = spec["name"]
        errors = self._name_errors(name, "spec.name", 64)
        if isinstance(name, str) and name != name.rstrip():
            errors.append("spec.name must not end with a space")
        for key in ("characterSet", "collation"):
            if key in spec and not (isinstance(spec[key], str) and CHARSET_RE.fullmatch(spec[key].lower())):
                errors.append(f"spec.{key} must be a MySQL charset/collation name")
        return errors

    def _validate_identity(self, spec):
        ident = spec.get("identity")
        if not isinstance(ident, dict):
            return ["spec.identity must be a mapping with username and optional host"]
        errors = [f"unknown field spec.identity.{k}" for k in ident if k not in {"username", "host"}]
        errors += self._name_errors(ident.get("username"), "spec.identity.username", 32)
        if "host" in ident:
            errors += self._name_errors(ident["host"], "spec.identity.host", 255)
        return errors

    _validate_DatabaseRole = _validate_identity

    def _validate_DatabaseUser(self, spec):
        errors = self._validate_identity(spec)
        for key in ("roles", "defaultRoles"):
            if key in spec and not (isinstance(spec[key], list) and all(isinstance(r, str) and r for r in spec[key])):
                errors.append(f"spec.{key} must be a list of account names (name or name@host)")
        if not errors and "defaultRoles" in spec and "roles" in spec and not (
                {account(r) for r in spec["defaultRoles"]} <= {account(r) for r in spec["roles"]}):
            errors.append("spec.defaultRoles must be a subset of spec.roles")
        if "accountLocked" in spec and not isinstance(spec["accountLocked"], bool):
            errors.append("spec.accountLocked must be a boolean")
        return errors

    def _validate_Grant(self, spec):
        errors = [] if isinstance(spec.get("grantee"), str) and spec["grantee"] else [
            "spec.grantee must be an account name (name or name@host)"]
        level = spec.get("on")
        if level not in LEVELS:
            return [*errors, f"spec.on must be one of {list(LEVELS)}"]
        for key, needed in (("database", level != "global"), ("table", level == "table")):
            if needed:
                errors += self._name_errors(spec.get(key), f"spec.{key}", 64)
            elif key in spec:
                errors.append(f"spec.{key} is not allowed with on: {level}")
        if isinstance(spec.get("database"), str) and spec["database"].lower() in SYSTEM_DATABASES:
            errors.append(f"grants on system database {spec['database']!r} are not supported")  # mysql.* = root
        privs = spec.get("privileges")
        if not isinstance(privs, list) or not privs or not all(isinstance(p, str) for p in privs):
            return [*errors, "spec.privileges must be a non-empty list of strings"]
        for p in _norm_privs(privs):
            if p in ("ALL", "ALL PRIVILEGES", "USAGE"):
                errors.append(f"privilege {p} is not supported, list the privileges explicitly")
            elif not PRIV_RE.fullmatch(p):
                errors.append(f"invalid privilege name {p!r}")
        return errors

    def desired(self, doc):
        spec, kind = doc.get("spec") or {}, doc["kind"]
        if kind == "Database":
            attrs = {k: spec[k].lower() for k in ("characterSet", "collation") if k in spec}
            return Resource(kind, spec.get("name", doc["metadata"]["name"]), attrs)
        if kind == "Grant":
            return _grant_resource(_id(*account(spec["grantee"])), spec["on"], spec["privileges"],
                                   spec.get("database"), spec.get("table"))
        ident = spec["identity"]
        rid = _id(ident["username"], ident.get("host", "%").lower())
        attrs = {k: sorted({_id(*account(r)) for r in spec[k]}) for k in ("roles", "defaultRoles") if k in spec}
        if "accountLocked" in spec:
            attrs["accountLocked"] = spec["accountLocked"]
        return Resource(kind, rid, attrs)

    def validate_target(self, target, resources):
        roles = {r.id for r in resources if r.kind == "DatabaseRole"}  # Rolle und User sind dasselbe Konto
        return [f"account {r.id!r} is declared as both DatabaseRole and DatabaseUser"
                for r in resources if r.kind == "DatabaseUser" and r.id in roles]

    def dependencies(self, resource):
        # GRANT role TO user: als Rolle darf auch ein anderer DatabaseUser dienen
        if resource.kind != "DatabaseUser":
            return []
        return [(kind, role) for role in resource.attrs.get("roles", []) for kind in ("DatabaseRole", "DatabaseUser")]

    def insecure_transport(self, target):
        # verify-ca prüft den Hostnamen nicht: jedes Zertifikat der CA passt, daher nur verify-full sicher
        return (target["endpoint"].get("tls") or {}).get("mode", "verify-full") != "verify-full"

    # --- Planungsprüfung (INV-10) -----------------------------------------------------------------

    def check(self, session, resource, allow_privileged=False):
        if resource.kind in ("DatabaseUser", "DatabaseRole") and account(resource.id)[0] in SYSTEM_USERS:
            return f"account {resource.id!r} is a system account"
        if resource.kind == "DatabaseUser":
            roles = sorted({*resource.attrs.get("roles", []), *resource.attrs.get("defaultRoles", [])})
            for role in roles:
                if account(role)[0] in SYSTEM_USERS or role == session.current:
                    return f"role {role!r} is a system account or the admin login"
            if allow_privileged:
                return None
            accounts, powerful = self._lookup(session)
            for role in roles:
                # fehlt die Rolle, legt sie eine deklarierte DatabaseRole an (läuft vorher, siehe dependencies)
                if role in accounts and not accounts[role]:
                    return f"role {role!r} is a user account, not a role; granting it requires allowPrivilegedGrants"
                if self._closure(session, role) & powerful:
                    return (f"role {role!r} holds global or system-database privileges; granting it requires "
                            "allowPrivilegedGrants")
        if resource.kind == "Grant":
            a = resource.attrs
            if account(a["grantee"])[0] in SYSTEM_USERS or a["grantee"] == session.current:
                return f"grantee {a['grantee']!r} is a system account or the admin login"
            if "database" in a and not self._in(session.scope, "databases", a["database"]):
                return f"database {a['database']!r} is outside the target scope"
            if (privileged := _privileged(a)) and not allow_privileged:
                return f"privileged grant ({', '.join(privileged)}) requires operator policy allowPrivilegedGrants"
        return None

    def _lookup(self, session):
        """({konto: ist_rolle}, Konten mit globalen oder Systemdatenbank-Rechten), ungefiltert vom Scope."""
        if "lookup" not in session.cache:
            accounts = {_id(n, h): locked == "Y" and expired == "Y" and bool(empty) for n, h, locked, expired, empty
                        in self._run(session, "SELECT User, Host, account_locked, password_expired, "
                                              "authentication_string = '' FROM mysql.user")}
            powerful = {_id(r["User"], r["Host"]) for r in self._dicts(session, "SELECT * FROM mysql.user")
                        if any(c.endswith("_priv") and v == "Y" for c, v in r.items())}
            powerful |= {_id(u, h) for u, h in self._run(session, "SELECT USER, HOST FROM mysql.global_grants")}
            powerful |= {_id(u, h) for u, h, db in self._run(session, "SELECT User, Host, Db FROM mysql.db")
                         if _db_pattern(db)[0].lower() in SYSTEM_DATABASES}
            session.cache["lookup"] = accounts, powerful
        return session.cache["lookup"]

    def _closure(self, session, rid: str) -> set[str]:
        """``rid`` und alle Rollen, die es (transitiv über mysql.role_edges) hält."""
        if "edges" not in session.cache:
            edges: dict[str, set] = {}
            for fu, fh, tu, th in self._run(session, "SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST "
                                                      "FROM mysql.role_edges"):
                edges.setdefault(_id(tu, th), set()).add(_id(fu, fh))
            session.cache["edges"] = edges
        seen, todo = set(), [rid]
        while todo:
            if (r := todo.pop()) not in seen:
                seen.add(r)
                todo += session.cache["edges"].get(r, ())
        return seen

    def _admin_roles(self, session) -> set[str]:
        """Rollen des eigenen Logins: nie entziehen oder löschen (Selbstaussperrung)."""
        return self._closure(session, session.current) - {session.current}

    # --- Verbindung -----------------------------------------------------------------------------

    @contextmanager
    def connect(self, target, secret: Secret | None, write):
        import pymysql

        endpoint = target["endpoint"]
        try:
            conn = _open(endpoint, endpoint["user"], secret.reveal() if secret else "")
        except pymysql.MySQLError as e:
            raise _error(e, f"connect to {endpoint['host']}") from None
        except ssl.SSLError as e:
            raise PermanentError(f"TLS error connecting to {endpoint['host']}: {e.reason}") from None
        except OSError as e:
            raise TransientError(f"connect to {endpoint['host']} failed: {type(e).__name__}") from None
        try:
            session = MySQLSession(conn, write, "", target.get("scope"))
            if not write:  # zweite Schicht: MySQL 8.4 weist dann auch CREATE USER ab (1792)
                self._run(session, "SET SESSION TRANSACTION READ ONLY")
            session.current = self._run(session, "SELECT CURRENT_USER()")[0][0]
            yield session
        finally:
            conn.close()

    @contextmanager
    def lock(self, session):
        got = self._run(session, f"SELECT GET_LOCK('ordivus', {LOCK_TIMEOUT})")[0][0]
        if got != 1:
            raise TransientError("another Ordivus run holds the MySQL lock 'ordivus'")
        try:
            yield
        finally:
            self._run(session, "SELECT RELEASE_LOCK('ordivus')")

    def _run(self, session, sql, secret=False, what=None):
        import pymysql

        try:
            with session.conn.cursor() as cur:
                cur.execute(sql)
                return cur.fetchall()
        except pymysql.MySQLError as e:
            raise _error(e, what or sql.split(" ", 2)[0] + " statement", secret) from None

    # --- Discovery ------------------------------------------------------------------------------

    @staticmethod
    def _in(scope, key, name) -> bool:
        patterns = (scope or {}).get(key)
        return patterns is None or any(fnmatch.fnmatchcase(name, g) for g in patterns["include"])

    def _accounts(self, session, scope):
        """{id: (name, is_role, locked)} innerhalb des Scopes."""
        rows = self._run(session, "SELECT User, Host, account_locked, password_expired, "
                                   "authentication_string = '' FROM mysql.user")
        out = {}
        for name, host, locked, expired, empty in rows:
            is_role = locked == "Y" and expired == "Y" and bool(empty)
            if self._in(scope, "roles" if is_role else "users", name):
                out[_id(name, host)] = (name, is_role, locked == "Y")
        return out

    def discover(self, session, kind, scope):
        if kind == "Database":
            rows = self._run(session, "SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME "
                                       "FROM information_schema.SCHEMATA")
            found = [Resource(kind, n, {"characterSet": cs, "collation": co}, system=n in SYSTEM_DATABASES)
                     for n, cs, co in rows if self._in(scope, "databases", n)]
            # shortcut: checks only the account's own SHOW DATABASES privilege, not one inherited via roles.
            own = self._run(session, "SELECT Show_db_priv FROM mysql.user "
                                      "WHERE CONCAT(User, '@', Host) = CURRENT_USER()")
            if not own or own[0][0] != "Y":
                return Discovery(PARTIAL, found, "SHOW DATABASES privilege missing; database list may be incomplete")
            return Discovery(COMPLETE, found)
        accounts = self._accounts(session, scope)
        if kind == "Grant":
            return Discovery(COMPLETE, self._grants(session, scope, accounts))
        want_role = kind == "DatabaseRole"
        edges, defaults = {}, {}
        if not want_role:
            for fu, fh, tu, th in self._run(session, "SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST "
                                                      "FROM mysql.role_edges"):
                edges.setdefault(_id(tu, th), []).append(_id(fu, fh))
            for h, u, rh, ru in self._run(session, "SELECT HOST, USER, DEFAULT_ROLE_HOST, DEFAULT_ROLE_USER "
                                                    "FROM mysql.default_roles"):
                defaults.setdefault(_id(u, h), []).append(_id(ru, rh))
        found, admin_roles = [], self._admin_roles(session)
        for rid, (name, is_role, locked) in sorted(accounts.items()):
            if is_role != want_role:
                continue
            attrs = {} if want_role else {"roles": sorted(edges.get(rid, [])),
                                          "defaultRoles": sorted(defaults.get(rid, [])), "accountLocked": locked}
            found.append(Resource(kind, rid, attrs, system=name in SYSTEM_USERS or rid in admin_roles,
                                  manageable=rid != session.current))
        return Discovery(COMPLETE, found)

    def _grants(self, session, scope, accounts) -> list[Resource]:
        by_key: dict[tuple, set] = {}  # (grantee, level, db, table) -> privileges

        def add(user, host, level, privs, db=None, table=None, wildcard=False):
            gid = _id(user, host)
            if gid in accounts and (db is None or self._in(scope, "databases", db)) and privs:
                by_key.setdefault((gid, level, db, table, wildcard), set()).update(privs)

        def column_privs(row: dict):
            return [COLUMN_PRIVS.get(c[:-5], c[:-5].replace("_", " ").upper())
                    for c, v in row.items() if c.endswith("_priv") and v == "Y"]

        for row in self._dicts(session, "SELECT * FROM mysql.user"):
            add(row["User"], row["Host"], "global", column_privs(row))
        for user, host, priv in self._run(session, "SELECT USER, HOST, PRIV FROM mysql.global_grants"):
            add(user, host, "global", [priv])
        for row in self._dicts(session, "SELECT * FROM mysql.db"):
            db, wildcard = _db_pattern(row["Db"])
            add(row["User"], row["Host"], "database", column_privs(row), row["Db"] if wildcard else db,
                wildcard=wildcard)
        for user, host, db, table, privs in self._run(
                session, "SELECT User, Host, Db, Table_name, Table_priv FROM mysql.tables_priv"):
            privs = privs if isinstance(privs, str) else ",".join(privs)  # SET-Spalte
            names = ["GRANT OPTION" if p == "Grant" else p.upper() for p in privs.split(",") if p]
            add(user, host, "table", names, db, table)
        out, admin_roles = [], self._admin_roles(session)
        for (gid, level, db, table, wildcard), privs in sorted(by_key.items(), key=lambda kv: str(kv[0])):
            grant = _grant_resource(gid, level, privs, db, table,
                                    system=accounts[gid][0] in SYSTEM_USERS or gid in admin_roles,
                                    manageable=gid != session.current and not wildcard)
            # fremder Wildcard-Grant (z. B. app_db als Muster): eigenes, nicht änderbares Objekt, nie "gleich" app_db
            out.append(replace(grant, id=grant.id + " (wildcard pattern)") if wildcard else grant)
        return out

    def _dicts(self, session, sql):
        import pymysql

        try:
            with session.conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(sql)
                return cur.fetchall()
        except pymysql.MySQLError as e:
            raise _error(e, "SELECT statement") from None

    # --- Ausführung -----------------------------------------------------------------------------

    def apply(self, session, op: Op):
        if not session.write:  # erste Schicht: nie auf den Session-Modus des Servers allein verlassen
            raise PermanentError("refusing to modify target on a read-only session")
        lit = session.conn.escape

        def acct(rid):
            name, host = account(rid)
            return f"{lit(name)}@{lit(host)}"

        def run(sql, secret=False):
            self._run(session, sql, secret, f"{op.action} {op.kind} {op.id!r}")

        me = acct(op.id) if op.kind in ("DatabaseUser", "DatabaseRole") else None
        if op.kind == "Database":
            name = quote_ident(op.id)
            if op.action == DELETE:
                return run(f"DROP DATABASE {name}")
            attrs = op.desired.attrs if op.action == CREATE else {f: new for f, (_, new) in op.changes.items()}
            opts = "".join(f" {sql} {attrs[k]}" for k, sql in (("characterSet", "CHARACTER SET"),
                                                               ("collation", "COLLATE")) if k in attrs)
            if not all(CHARSET_RE.fullmatch(attrs[k]) for k in ("characterSet", "collation") if k in attrs):
                raise PermanentError("invalid character set or collation name")
            return run(f"CREATE DATABASE {name}{opts}" if op.action == CREATE else f"ALTER DATABASE {name}{opts}")
        if op.kind == "DatabaseRole":
            return run(f"CREATE ROLE {me}" if op.action == CREATE else f"DROP ROLE {me}")
        if op.kind == "Grant":
            attrs = (op.observed if op.action == DELETE else op.desired).attrs
            if op.action != DELETE and "database" in attrs and (attrs["database"].lower() in SYSTEM_DATABASES
                                                                or not self._in(session.scope, "databases",
                                                                                attrs["database"])):
                raise PermanentError(f"database {attrs['database']!r} is a system database or outside the scope")
            obj, grantee = _grant_object(attrs, statement=True), acct(attrs["grantee"])
            if op.action == CREATE:
                return run(f"GRANT {self._privs(attrs['privileges'])} ON {obj} TO {grantee}")
            if op.action == DELETE:
                return run(f"REVOKE {self._privs(attrs['privileges'])} ON {obj} FROM {grantee}")
            old, new = (set(v or []) for v in op.changes.get("privileges", ([], [])))
            if new - old:
                run(f"GRANT {self._privs(new - old)} ON {obj} TO {grantee}")
            if old - new:
                run(f"REVOKE {self._privs(old - new)} ON {obj} FROM {grantee}")
            return None
        # DatabaseUser
        if op.action == DELETE:
            return run(f"DROP USER {me}")
        if op.action == SET_PASSWORD:
            return run(f"ALTER USER {me} IDENTIFIED BY {lit(op.password.reveal())}", secret=True)
        if op.action == CREATE:
            attrs = op.desired.attrs
            locked = attrs.get("accountLocked", False)
            if op.password is None and not locked:
                raise PermanentError("DatabaseUser without spec.credentials must set accountLocked: true "
                                     "(MySQL would create it with an empty password)")
            auth = f" IDENTIFIED BY {lit(op.password.reveal())}" if op.password else ""
            run(f"CREATE USER {me}{auth}{' ACCOUNT LOCK' if locked else ''}", secret=bool(op.password))
            changes = {k: ([], v) for k, v in attrs.items() if k in ("roles", "defaultRoles")}
        else:
            changes = op.changes
            if "accountLocked" in changes:
                run(f"ALTER USER {me} ACCOUNT {'LOCK' if changes['accountLocked'][1] else 'UNLOCK'}")
        if any(account(r)[0] in SYSTEM_USERS or r == session.current
               for r in [*changes.get("roles", ([], []))[1], *changes.get("defaultRoles", ([], []))[1]]):
            raise PermanentError("refusing to grant a system account or the admin login as role")
        if "roles" in changes:
            old, new = (set(v or []) for v in changes["roles"])
            if new - old:
                run(f"GRANT {', '.join(acct(r) for r in sorted(new - old))} TO {me}")
            if old - new:
                run(f"REVOKE {', '.join(acct(r) for r in sorted(old - new))} FROM {me}")
        if "defaultRoles" in changes:
            roles = changes["defaultRoles"][1]
            run(f"SET DEFAULT ROLE {', '.join(acct(r) for r in roles) if roles else 'NONE'} TO {me}")
        return None

    @staticmethod
    def _privs(privs) -> str:
        privs = sorted(privs)
        if not all(PRIV_RE.fullmatch(p) for p in privs):  # Privilegnamen werden roh eingesetzt
            raise PermanentError("invalid privilege name")
        return ", ".join(privs)

    def verify_password(self, session, target, resource, password: Secret):
        """Echter Login-Versuch. Nie bei Konten mit Login-Sperre (FAILED_LOGIN_ATTEMPTS) oder aktivem
        connection_control: ein Fehlversuch würde das Konto sperren bzw. verzögern (plan bleibt read-only)."""
        import pymysql

        name, host = account(resource.id)
        lit = session.conn.escape
        try:
            locking = self._run(session, "SELECT JSON_EXTRACT(User_attributes, "
                                         "'$.Password_locking.failed_login_attempts') FROM mysql.user "
                                         f"WHERE User = {lit(name)} AND Host = {lit(host)}")
            control = self._run(session, "SELECT 1 FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE "
                                         "'CONNECTION_CONTROL%' AND PLUGIN_STATUS = 'ACTIVE' UNION ALL "
                                         "SELECT 1 FROM mysql.component "
                                         "WHERE component_urn LIKE '%connection_control%'")
            # andere Einträge mit diesem Namen oder anonyme Konten können beim Login greifen: 1045 beweist dann nichts
            shadows = self._run(session, f"SELECT COUNT(*) FROM mysql.user WHERE User IN ({lit(name)}, '')")[0][0]
        except (PermanentError, AuthorizationError, TransientError):
            return None
        if control or (locking and locking[0][0] not in (None, 0, "0")):
            return None
        try:
            conn = _open(target["endpoint"], name, password.reveal())
        except pymysql.MySQLError as e:
            wrong = e.args and e.args[0] == 1045 and host == "%" and shadows == 1
            return False if wrong else None
        except Exception:  # OSError, RuntimeError (cryptography fehlt für caching_sha2) …: nicht prüfbar
            return None
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT CURRENT_USER()")
                # anderer Host-Eintrag hat gegriffen: über dieses Konto sagt der Login nichts aus
                return True if cur.fetchone()[0] == resource.id else None
        except pymysql.MySQLError:
            return None
        finally:
            conn.close()
