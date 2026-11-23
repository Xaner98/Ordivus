"""MariaDB-Adapter: Unterklasse des MySQL-Adapters, überschreibt nur die Unterschiede. Doku: docs/adapters/mariadb.md.

Unterschiede zu MySQL 8: Rollen sind Zeilen mit ``is_role`` und leerem Host (ID = Rollenname ohne ``@``),
Rollenvergaben in ``mysql.roles_mapping``, höchstens eine Default-Rolle (``mysql.user.default_role``),
globale Rechte als Bitmaske in ``mysql.global_priv`` (kein ``mysql.global_grants``), Login-Sperre über
``max_password_errors``. ``CREATE ROLE`` vergibt die Rolle automatisch an den Ersteller (mit Admin-Option);
geschützt werden deshalb nur die Default-Rolle des eigenen Logins und deren Unterrollen, die in seiner
Session tatsächlich aktiv sind.
"""

from ordivus.adapters.base import DELETE, PermanentError, Resource
from ordivus.adapters.mysql import MySQLAdapter, _product_version

MIN_VERSION = (10, 6, 0)  # Privileg-Bitlayout ab 10.5 (SET USER … SLAVE MONITOR); 10.6 = ältestes LTS damit
SYSTEM_USERS = frozenset({"root", "mariadb.sys", "mysql", "PUBLIC"})  # root auf jedem Host; PUBLIC = Pseudo-Rolle
NO_PASSWORD_LIMIT = 4294967295  # Default von max_password_errors: keine Sperre
# Bit n von global_priv.access → GRANT-Name, wie SHOW GRANTS ihn ausgibt (geprüft gegen USER_PRIVILEGES, 11.4)
ACCESS_BITS = ("SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "RELOAD", "SHUTDOWN", "PROCESS", "FILE",
               "GRANT OPTION", "REFERENCES", "INDEX", "ALTER", "SHOW DATABASES", "SUPER", "CREATE TEMPORARY TABLES",
               "LOCK TABLES", "EXECUTE", "REPLICATION SLAVE", "BINLOG MONITOR", "CREATE VIEW", "SHOW VIEW",
               "CREATE ROUTINE", "ALTER ROUTINE", "CREATE USER", "EVENT", "TRIGGER", "CREATE TABLESPACE",
               "DELETE HISTORY", "SET USER", "FEDERATED ADMIN", "CONNECTION ADMIN", "READ_ONLY ADMIN",
               "REPLICATION SLAVE ADMIN", "REPLICATION MASTER ADMIN", "BINLOG ADMIN", "BINLOG REPLAY",
               "SLAVE MONITOR", "SHOW CREATE ROUTINE")


def access_privs(access: int) -> list[str]:
    """Bitmaske → Privilegnamen. Unbekannte Bits bleiben sichtbar (ungültiger Name: nie per REVOKE angefasst)."""
    return [ACCESS_BITS[b] if b < len(ACCESS_BITS) else f"UNKNOWN PRIVILEGE BIT {b}"
            for b in range(access.bit_length()) if access >> b & 1]


class MariaDBAdapter(MySQLAdapter):
    id = "mariadb"
    api_version = 1
    product = "MariaDB"
    system_users = SYSTEM_USERS
    default_role_sql = "SET DEFAULT ROLE {roles} FOR {user}"

    @staticmethod
    def _ref(ref: str) -> tuple[str, str]:
        """``name@host`` = Konto, ``name`` (ohne ``@``) = Rolle (leerer Host)."""
        name, at, host = ref.rpartition("@")
        return (name, host.lower()) if at else (ref, "")

    @staticmethod
    def _rid(name: str, host: str) -> str:
        return f"{name}@{host}" if host else name

    def _is_system(self, name):
        name = name.rstrip(" ")  # PAD SPACE: 'root ' ist root
        return name in SYSTEM_USERS or name.upper() == "PUBLIC"  # 'public' meint ebenfalls PUBLIC

    def _check_version(self, raw):
        if "mariadb" not in raw.lower():
            raise PermanentError(f"server is not MariaDB ({raw}); use adapter 'mysql' instead of 'mariadb'")
        return _product_version("MariaDB", raw, MIN_VERSION)

    def _acct(self, session, rid):
        name, host = self._ref(rid)
        return session.conn.escape(name) if host == "" else super()._acct(session, rid)

    def apply(self, session, op):
        if op.kind == "Grant" and session.write:
            grantee = (op.observed if op.action == DELETE else op.desired).attrs["grantee"]
            name, host = self._ref(grantee)
            # ohne Rolle dieses Namens wendet MariaDB "TO 'name'" auf das Konto name@'%' an
            if host == "" and not self._run(session, f"SELECT 1 FROM mysql.global_priv WHERE User = "
                                                     f"{session.conn.escape(name)} AND Host = '' AND "
                                                     "JSON_VALUE(Priv, '$.is_role') IN ('1', 'true')"):
                raise PermanentError(f"role {name!r} does not exist; refusing grant (MariaDB would apply it to "
                                     f"the account {name}@%)")
        return super().apply(session, op)

    # --- Validierung ----------------------------------------------------------------------------

    def _validate_DatabaseRole(self, spec):
        errors = self._validate_identity(spec)
        ident = spec.get("identity")
        if isinstance(ident, dict) and "host" in ident:
            errors.append("spec.identity.host is not allowed: MariaDB roles have no host")
        if isinstance(ident, dict) and "@" in str(ident.get("username", "")):
            errors.append("spec.identity.username of a role must not contain '@'")
        return errors

    def _validate_DatabaseUser(self, spec):
        errors = super()._validate_DatabaseUser(spec)
        for key in ("roles", "defaultRoles"):
            if isinstance(spec.get(key), list):
                errors += [f"spec.{key}[{i}] must be a role name without '@' (MariaDB roles have no host)"
                           for i, r in enumerate(spec[key]) if isinstance(r, str) and "@" in r]
        if isinstance(spec.get("defaultRoles"), list) and len(spec["defaultRoles"]) > 1:
            errors.append("spec.defaultRoles: MariaDB supports at most one default role")
        return errors

    def desired(self, doc):
        if doc["kind"] == "DatabaseRole":
            return Resource("DatabaseRole", doc["spec"]["identity"]["username"])
        return super().desired(doc)

    # --- Systemtabellen -------------------------------------------------------------------------

    def _account_rows(self, session):
        # JSON true liefert JSON_VALUE als '1'
        return [(n, h, role in ("1", "true"), locked in ("1", "true")) for n, h, role, locked in self._run(
            session, "SELECT User, Host, JSON_VALUE(Priv, '$.is_role'), JSON_VALUE(Priv, '$.account_locked') "
                     "FROM mysql.global_priv")]

    def _edges(self, session):
        return [(role, self._rid(u, h)) for role, u, h in self._run(
            session, "SELECT Role, User, Host FROM mysql.roles_mapping")]

    def _default_roles(self, session):
        return [(self._rid(u, h), role) for u, h, role in self._run(
            session, "SELECT User, Host, default_role FROM mysql.user WHERE default_role <> ''")]

    def _global_privs(self, session):
        return [(u, h, access_privs(int(a or 0))) for u, h, a in self._run(
            session, "SELECT User, Host, JSON_VALUE(Priv, '$.access') FROM mysql.global_priv")]

    def _admin_roles(self, session):
        # nur aktive Rollen (Default-Rolle + Unterrollen) tragen Rechte des eigenen Logins; CREATE ROLE vergibt
        # jede neue Rolle an den Ersteller, die zählt nicht, sonst wäre jede angelegte Rolle unantastbar
        roles: set[str] = set()
        for holder, role in self._default_roles(session):
            if holder == session.current:
                roles |= self._closure(session, role)
        return roles

    def _login_risky(self, session, name):
        lit = session.conn.escape
        rows = self._run(session, f"SELECT 1 FROM mysql.user WHERE User IN ({lit(name)}, '')")
        limit = self._run(session, "SELECT @@max_password_errors")[0][0]
        return len(rows) != 1 or int(limit) < NO_PASSWORD_LIMIT
