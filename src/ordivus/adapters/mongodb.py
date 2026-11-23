"""MongoDB-Adapter (pymongo): eigene Rollen als ``DatabaseRole``, Benutzer als ``DatabaseUser``.
Nutzerdoku: ``docs/adapters/mongodb.md``.

Ressourcen-ID ist MongoDBs eigene ``_id``-Form ``<db>.<name>`` (Datenbanknamen enthalten nie einen Punkt,
die Trennung am ersten Punkt ist eindeutig). Benutzer liegen je Authentifizierungsdatenbank, Rollen je
Datenbank. Rollenreferenzen und Privilegien werden für Soll und Ist gleich normalisiert (sortiert,
Privilegien je Ressource zusammengeführt – so speichert sie auch der Server).
"""

import json
import re
from contextlib import contextmanager
from dataclasses import dataclass

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

MIN_VERSION = (6, 0)
# Unix-Verbotszeichen plus die unter Windows verbotenen, damit eine Konfiguration überall gleich gilt
DB_RE = re.compile(r'[^/\\. "$*<>:|?\x00]{1,63}')
ACTION_RE = re.compile(r"[A-Za-z]+")
SYSTEM_DATABASES = ("admin", "config", "local")
MECHANISMS = ["SCRAM-SHA-256"]
BUILTIN_ROLES = frozenset({
    "read", "readWrite", "dbAdmin", "dbOwner", "userAdmin", "clusterAdmin", "clusterManager", "clusterMonitor",
    "hostManager", "backup", "restore", "readAnyDatabase", "readWriteAnyDatabase", "userAdminAnyDatabase",
    "dbAdminAnyDatabase", "root", "__system", "__queryableBackup", "enableSharding", "directShardOperations",
    "searchCoordinator"})
# INV-10: nur mit allowPrivilegedGrants. backup/restore lesen bzw. schreiben system.users (Hashes, Konten).
PRIVILEGED_ROLES = frozenset({
    "root", "__queryableBackup", "userAdminAnyDatabase", "readWriteAnyDatabase", "dbAdminAnyDatabase",
    "readAnyDatabase", "clusterAdmin", "clusterManager", "hostManager", "backup", "restore", "directShardOperations"})
NEVER_GRANTED = frozenset({"__system"})  # auch mit Freigabe nie: interne Cluster-Identität
# Benutzer-/Rollenverwaltung und Identitätswechsel: Wer sie hat, kann sich jede Rolle der Datenbank geben
DANGEROUS_ACTIONS = frozenset({
    "anyAction", "internal", "impersonate", "createUser", "dropUser", "changePassword", "changeCustomData",
    "createRole", "dropRole", "grantRole", "revokeRole", "setAuthenticationRestriction", "useUUID", "forceUUID"})
AUTH_CODES = {13, 18}  # Unauthorized, AuthenticationFailed
TRANSIENT_CODES = {6, 7, 50, 89, 91, 112, 189, 262, 9001, 10107, 11600, 11602, 13435, 13436}


@dataclass
class Session:
    client: object
    target: dict
    write: bool
    version: str
    login: tuple | None  # (authDatabase, user) der eigenen Anmeldung
    own_roles: frozenset  # "db.role" aller (transitiv) gehaltenen Rollen der eigenen Anmeldung


# --- Normalisierung ------------------------------------------------------------------------------

def _roles(items, db: str) -> list[dict]:
    """``"name"`` (Rolle der eigenen Datenbank) oder ``{role, db}`` → sortierte Liste ``{db, role}``."""
    pairs = {(i.get("db", db), i["role"]) if isinstance(i, dict) else (db, i) for i in items}
    return [{"db": d, "role": r} for d, r in sorted(pairs)]


def _privileges(items) -> list[dict]:
    merged: dict[str, set] = {}
    for p in items:
        merged.setdefault(json.dumps(p["resource"], sort_keys=True), set()).update(p["actions"])
    return [{"resource": json.loads(k), "actions": sorted(a)} for k, a in sorted(merged.items())]


def _split(rid: str) -> tuple[str, str]:
    db, _, name = rid.partition(".")
    return db, name


# --- Privilegien (INV-10) ------------------------------------------------------------------------

def _builtin_privileged(db: str, role: str) -> bool:
    # Auf admin/config/local ist jede eingebaute Rolle außer read/clusterMonitor Eskalation (dbOwner@admin = root)
    return role in PRIVILEGED_ROLES or (role in BUILTIN_ROLES and db in SYSTEM_DATABASES
                                        and role not in ("read", "clusterMonitor"))


def _dangerous(privilege: dict) -> str | None:
    res, actions = privilege["resource"], set(privilege["actions"])
    if res.get("cluster") or res.get("anyResource"):
        return "privilege on the cluster resource"
    db, coll = res.get("db"), res.get("collection")
    if db == "" or db in SYSTEM_DATABASES:
        return f"privilege on database {db or '<any>'!r}"
    if not isinstance(coll, str):
        return "privilege on a non-standard resource"
    if coll.startswith("system."):
        return f"privilege on system collection {db}.{coll}"
    if hit := sorted(actions & DANGEROUS_ACTIONS):
        return f"actions {', '.join(hit)}"
    return None


# --- Validierung ---------------------------------------------------------------------------------

def _str(value) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _db(value) -> bool:
    return isinstance(value, str) and bool(DB_RE.fullmatch(value))


def _validate_target(spec: dict) -> list[str]:
    errors = [f"unknown field spec.{k}" for k in spec if k not in {"endpoint", "scope"}]
    ep = spec.get("endpoint")
    if not isinstance(ep, dict):
        return [*errors, "spec.endpoint must be a mapping"]
    errors += common.validate_endpoint(ep, extra=("user", "authDatabase", "replicaSet"))
    if isinstance(ep.get("host"), str) and re.search("[,:]", ep["host"]):  # pymongo läse sonst Seed-Listen/Ports
        errors.append("spec.endpoint.host must be a single host name or IPv4 address (no ',' or ':')")
    if not _str(ep.get("user")):
        errors.append("spec.endpoint.user must be a non-empty string")
    if not _db(ep.get("authDatabase", "admin")):
        errors.append("spec.endpoint.authDatabase must be a valid database name")
    if "replicaSet" in ep and not _str(ep["replicaSet"]):
        errors.append("spec.endpoint.replicaSet must be a non-empty string")
    scope = spec.get("scope", {})
    if not isinstance(scope, dict):
        return [*errors, "spec.scope must be a mapping"]
    for key, value in scope.items():
        if key != "databases":
            errors.append(f"unknown field spec.scope.{key}")
        elif not isinstance(value, dict) or set(value) - {"include"} or not isinstance(value.get("include"), list) \
                or not all(isinstance(g, str) for g in value["include"]):
            errors.append("spec.scope.databases must be {include: [glob, ...]}")
    return errors


def _validate_resource(doc: dict) -> list[str]:
    kind, spec = doc["kind"], doc.get("spec") or {}
    allowed = {"name", "database", "roles", *(("privileges",) if kind == "DatabaseRole" else ())}
    errors = [f"unknown field spec.{k}" for k in spec if k not in allowed]
    if not _str(spec.get("name", doc["metadata"]["name"])):
        errors.append("spec.name must be a non-empty string")
    if not _db(spec.get("database")):
        errors.append("spec.database is required and must be a valid database name")
    elif spec["database"] in ("config", "local"):
        errors.append(f"spec.database {spec['database']!r}: MongoDB does not allow users or roles there")
    roles = spec.get("roles", [])
    if not isinstance(roles, list):
        errors.append("spec.roles must be a list")
        roles = []
    for i, r in enumerate(roles):
        ok = _str(r) or (isinstance(r, dict) and not set(r) - {"role", "db"} and _str(r.get("role"))
                         and _db(r.get("db", "admin")))
        if not ok:
            errors.append(f"spec.roles[{i}] must be a role name or {{role, db}}")
        elif kind == "DatabaseRole" and isinstance(r, dict) and r.get("db", spec.get("database")) != \
                spec.get("database") and spec.get("database") != "admin":
            errors.append(f"spec.roles[{i}]: roles outside admin cannot inherit roles from other databases")
    privileges = spec.get("privileges", [])
    if not isinstance(privileges, list):
        return [*errors, "spec.privileges must be a list"]
    for i, p in enumerate(privileges):
        where = f"spec.privileges[{i}]"
        if not isinstance(p, dict) or set(p) != {"resource", "actions"}:
            errors.append(f"{where} must have exactly the fields resource and actions")
            continue
        res = p["resource"]
        if not isinstance(res, dict):
            res = {}
        coll = res.get("collection")
        if not (res == {"cluster": True} or (set(res) == {"db", "collection"} and (res["db"] == "" or _db(res["db"]))
                                              and isinstance(coll, str) and "\x00" not in coll)):
            errors.append(f"{where}.resource must be {{db, collection}} (\"\" = any) or {{cluster: true}}")
        elif kind == "DatabaseRole" and spec.get("database") != "admin" and res.get("db") != spec.get("database"):
            # MongoDB-Regel: nur Rollen in admin dürfen auf andere Datenbanken oder den Cluster zeigen
            errors.append(f"{where}.resource: roles outside admin can only target their own database")
        actions = p["actions"]
        if not isinstance(actions, list) or not actions or not all(
                isinstance(a, str) and ACTION_RE.fullmatch(a) for a in actions):
            errors.append(f"{where}.actions must be a non-empty list of action names")
    return errors


# --- Verbindung und Fehler -----------------------------------------------------------------------

def _error(e, secrets=()) -> Exception:
    import pymongo.errors as pe

    if isinstance(e, pe.OperationFailure):
        details = e.details or {}
        # Servermeldungen geben teils das ganze Kommando wieder ("not authorized ... to execute command {...}")
        text = str(details.get("errmsg", "")).split("{", 1)[0].strip()
        msg = f"{details.get('codeName', 'error')} ({e.code}): {text}"
        cls = AuthorizationError if e.code in AUTH_CODES else \
            TransientError if e.code in TRANSIENT_CODES else PermanentError
    else:
        msg = f"{type(e).__name__}: {e}"
        cls = TransientError if isinstance(e, pe.ConnectionFailure) else PermanentError
    for s in secrets:
        if s is not None and s.reveal():
            msg = msg.replace(s.reveal(), "***")
    return cls(msg[:300])


@contextmanager
def _mapped(*secrets):
    import pymongo.errors

    try:
        yield
    except pymongo.errors.PyMongoError as e:
        raise _error(e, secrets) from None


def _client(target: dict, user: str | None, password: Secret | None, auth_db: str, mechanism: str | None = None):
    import pymongo  # Extra ordivus[mongodb]

    ep = target["endpoint"]
    kw = {"host": ep["host"], "port": ep.get("port", 27017), "appname": "ordivus", "connectTimeoutMS": 10000,
          "serverSelectionTimeoutMS": 10000, "socketTimeoutMS": 30000}
    if "replicaSet" in ep:
        kw["replicaSet"] = ep["replicaSet"]
    else:
        kw["directConnection"] = True
    if "tls" in ep:
        kw["tls"] = True
        if "caFile" in ep["tls"]:
            kw["tlsCAFile"] = ep["tls"]["caFile"]
    if password is not None:
        kw.update(username=user, password=password.reveal(), authSource=auth_db)
        if mechanism:
            kw["authMechanism"] = mechanism
    with _mapped(password):
        return pymongo.MongoClient(**kw)


def _version(text) -> str:
    try:
        major, minor = (int(x) for x in str(text).split(".")[:2])
    except ValueError:
        raise PermanentError(f"cannot parse MongoDB version {text!r}") from None
    if (major, minor) < MIN_VERSION:
        raise PermanentError(f"MongoDB {text} is not supported (minimum {'.'.join(map(str, MIN_VERSION))})")
    return f"MongoDB {text}"


# --- Adapter -------------------------------------------------------------------------------------

class MongoDBAdapter(Adapter):
    id = "mongodb"
    api_version = 1
    kinds = ("DatabaseRole", "DatabaseUser")
    password_kinds = ("DatabaseUser",)

    def validate(self, doc):
        return _validate_target(doc.get("spec") or {}) if doc["kind"] == "Target" else _validate_resource(doc)

    def desired(self, doc):
        spec = doc.get("spec") or {}
        db = spec["database"]
        attrs = {}
        if "roles" in spec:
            attrs["roles"] = _roles(spec["roles"], db)
        if "privileges" in spec:
            attrs["privileges"] = _privileges(spec["privileges"])
        return Resource(doc["kind"], f"{db}.{spec.get('name', doc['metadata']['name'])}", attrs)

    def validate_target(self, target, resources):
        # SCRAM-Benutzer ohne Passwort lässt MongoDB nicht zu
        return [f"DatabaseUser {r.id!r} needs spec.credentials (MongoDB users require a password)"
                for r in resources if r.kind == "DatabaseUser" and r.password_ref is None]

    def dependencies(self, resource):
        return [("DatabaseRole", f"{r['db']}.{r['role']}") for r in resource.attrs.get("roles", [])
                if r["role"] not in BUILTIN_ROLES]

    def insecure_transport(self, target):
        return "tls" not in target["endpoint"]

    @contextmanager
    def connect(self, target, secret, write):
        ep = target["endpoint"]
        auth_db = ep.get("authDatabase", "admin")
        client = _client(target, ep["user"], secret, auth_db)
        try:
            with _mapped(secret):
                version = _version(client.admin.command("buildInfo").get("version"))
                auth = client.admin.command("connectionStatus")["authInfo"]  # braucht keine Rechte
            own = frozenset(f"{r['db']}.{r['role']}" for r in auth.get("authenticatedUserRoles", []))
            yield Session(client, target, write, version, (auth_db, ep["user"]) if secret else None, own)
        finally:
            client.close()

    def server_version(self, session):
        return session.version

    def _protected(self, session, kind: str, rid: str) -> str | None:
        """Gründe, die auch mit allowPrivilegedGrants gelten (Plan: BLOCKED, Apply: Abbruch)."""
        db, name = _split(rid)
        if not common.in_scope(session.target.get("scope"), "databases", db):
            return f"database {db!r} is outside spec.scope.databases"
        if kind == "DatabaseUser" and ((db, name) == session.login or name == "__system"):
            return f"user {rid!r} is protected (Ordivus login or __system)"
        if kind == "DatabaseRole" and name in BUILTIN_ROLES:
            return f"{name!r} is a built-in role and cannot be managed"
        return None

    def check(self, session, resource, allow_privileged=False):
        if reason := self._protected(session, resource.kind, resource.id):
            return reason
        policy = "requires operator policy allowPrivilegedGrants"
        for p in resource.attrs.get("privileges", []):
            if (why := _dangerous(p)) and not allow_privileged:
                return f"{why} is privileged; {policy}"
        for r in resource.attrs.get("roles", []):
            ref = f"{r['role']}@{r['db']}"
            if not common.in_scope(session.target.get("scope"), "databases", r["db"]):
                return f"role {ref} is outside spec.scope.databases"
            if r["role"] in NEVER_GRANTED:
                return f"role {ref} is never granted"
            if not allow_privileged and (why := self._role_privileged(session, r)):
                return f"role {ref} is privileged ({why}); {policy}"
        return None

    def _role_privileged(self, session, ref: dict) -> str | None:
        if _builtin_privileged(ref["db"], ref["role"]):
            return "built-in administrative role"
        if ref["role"] in BUILTIN_ROLES:
            return None
        import pymongo.errors

        db = session.client[ref["db"]]
        try:
            found = db.command("rolesInfo", ref)["roles"]
            if not found:  # entsteht aus einer deklarierten DatabaseRole, die selbst geprüft wird
                return None
            chain = found[0].get("inheritedRoles", [])
            for r in chain:
                if _builtin_privileged(r["db"], r["role"]):
                    return f"inherits {r['role']}@{r['db']}"
            # Eingebaute Rollen nur über den Namen prüfen: ihre Privilegien (z. B. read → system.js) sind bekannt
            custom = [ref, *({"role": r["role"], "db": r["db"]} for r in chain if r["role"] not in BUILTIN_ROLES)]
            for info in db.command("rolesInfo", custom, showPrivileges=True)["roles"]:
                for p in info.get("privileges", []):
                    if why := _dangerous(p):
                        return f"via {info['role']}@{info['db']}: {why}"
        except pymongo.errors.PyMongoError as e:
            return f"cannot resolve role to check for privileges ({type(_error(e)).__name__})"
        return None

    def discover(self, session, kind, scope):
        users = kind == "DatabaseUser"
        failed = []
        try:
            with _mapped():
                if users:
                    docs = session.client.admin.command("usersInfo", {"forAllDBs": True})["users"]
                else:  # rolesInfo kennt kein forAllDBs; Rollen leerer Datenbanken stehen nur hier
                    docs = list(session.client.admin["system.roles"].find(
                        {}, {"role": 1, "db": 1, "privileges": 1, "roles": 1}))
        except AuthorizationError:
            docs, failed = self._per_database(session, users, scope)
        resources = []
        for d in docs:
            db = d["db"]
            if not common.in_scope(scope, "databases", db):
                continue
            if users:
                rid = f"{db}.{d['user']}"
                attrs = {"roles": _roles(d.get("roles", []), db), "mechanisms": sorted(d.get("mechanisms", []))}
                system = (db, d["user"]) == session.login or d["user"] == "__system"
                # $external (x509/LDAP) hat kein Passwort; Ordivus legt dort nichts an
                resources.append(Resource(kind, rid, attrs, manageable=db != "$external", system=system))
            else:
                rid = f"{db}.{d['role']}"
                attrs = {"privileges": _privileges(d.get("privileges", [])), "roles": _roles(d.get("roles", []), db)}
                resources.append(Resource(kind, rid, attrs, system=rid in session.own_roles))
        return Discovery(PARTIAL if failed else COMPLETE, resources, "; ".join(failed))

    def _per_database(self, session, users: bool, scope) -> tuple[list, list[str]]:
        """Fallback ohne instanzweites Leserecht: je Datenbank aus ``scope.databases`` einzeln lesen.
        Globs lassen sich so nicht aufzählen (Benutzer leerer Datenbanks fehlen in listDatabases) → partial."""
        include = ((scope or {}).get("databases") or {}).get("include")
        what = "usersInfo forAllDBs" if users else "find on admin.system.roles"
        if not include:
            raise AuthorizationError(f"{what} not permitted and spec.scope.databases is not set")
        docs, failed = [], []
        for name in include:
            if any(c in name for c in "*?["):
                failed.append(f"glob {name!r} cannot be enumerated without {what}")
                continue
            try:
                with _mapped():
                    if users:
                        docs += session.client[name].command("usersInfo", 1)["users"]
                    else:
                        docs += session.client[name].command("rolesInfo", 1, showPrivileges=True)["roles"]
            except AdapterError as e:
                failed.append(f"database {name!r}: {type(e).__name__}: {e}")
        if len(failed) == len(include):
            raise AuthorizationError("; ".join(failed))
        return docs, failed

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session: refusing to modify MongoDB")
        if reason := self._protected(session, op.kind, op.id):
            raise PermanentError(f"refusing: {reason}")
        db, name = _split(op.id)
        user = op.kind == "DatabaseUser"
        if op.action == CREATE:
            attrs = op.desired.attrs
            if user:
                if op.password is None:
                    raise PermanentError("MongoDB users require a password (spec.credentials)")
                cmd = {"createUser": name, "pwd": op.password.reveal(), "roles": attrs.get("roles", []),
                       "mechanisms": MECHANISMS}
            else:
                cmd = {"createRole": name, "privileges": attrs.get("privileges", []), "roles": attrs.get("roles", [])}
        elif op.action == UPDATE:
            fields = {k: new for k, (_, new) in op.changes.items() if k in ("roles", "privileges")}
            cmd = {"updateUser" if user else "updateRole": name, **fields}
        elif op.action == SET_PASSWORD and user:
            cmd = {"updateUser": name, "pwd": op.password.reveal(), "mechanisms": MECHANISMS}
        elif op.action == DELETE:
            cmd = {"dropUser" if user else "dropRole": name}
        else:
            raise PermanentError(f"unsupported action {op.action} for {op.kind}")
        with _mapped(op.password):
            session.client[db].command(cmd)

    def verify_password(self, session, target, resource, password):
        # Eigener SCRAM-Anmeldeversuch; MongoDB kennt keine Kontosperre nach Fehlversuchen
        import pymongo.errors

        mechanisms = resource.attrs.get("mechanisms", [])
        mechanism = next((m for m in ("SCRAM-SHA-256", "SCRAM-SHA-1") if m in mechanisms), None)
        if mechanism is None:
            return None
        db, name = _split(resource.id)
        try:
            client = _client(target, name, password, db, mechanism)
        except (PermanentError, TransientError):
            return None
        try:
            client.admin.command("ping")
            return True
        except pymongo.errors.OperationFailure as e:
            return False if e.code == 18 else None
        except pymongo.errors.PyMongoError:
            return None
        finally:
            client.close()

