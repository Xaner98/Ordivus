"""MariaDB-Adapter gegen einen echten Container (ordivus-it-mariadb, Port 13307); sonst sauber übersprungen."""

import json
import os
import secrets
from contextlib import closing

import pytest

from ordivus import adapters
from ordivus.adapters.base import CREATE, Op, PermanentError, Resource, Secret, TransientError
from ordivus.adapters.mariadb import ACCESS_BITS, MariaDBAdapter, access_privs
from ordivus.adapters.mysql import MySQLAdapter, quote_ident
from ordivus.cli import main
from ordivus.core import config, engine, report
from ordivus.core.policy import OperatorPolicy

HOST = os.environ.get("ORDIVUS_TEST_HOST", "localhost")
PORT = 13307
MYSQL_PORT = 13306
ROOT_PASSWORD = os.environ.get("ORDIVUS_TEST_MARIADB_PASSWORD", "ordivus-root")
ENDPOINT = {"host": HOST, "port": PORT, "user": "root", "tls": {"mode": "require"}}


def doc(kind, name, /, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


def connect(user="root", password=ROOT_PASSWORD):
    pymysql = pytest.importorskip("pymysql")
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return pymysql.connect(host=HOST, port=PORT, user=user, password=password.encode(), ssl=ctx,
                           connect_timeout=3, autocommit=True)


def escaped(db):
    """Datenbankname, wie ihn GRANT auf Datenbankebene ohne Wildcard-Wirkung braucht."""
    return db.replace("_", "\\_")


def sql(statement, *args):
    with closing(connect()) as c, c.cursor() as cur:
        cur.execute(statement, args or None)
        return cur.fetchall()


def can_login(user, password, host="%"):
    try:
        with closing(connect(user, password)) as c, c.cursor() as cur:
            cur.execute("SELECT CURRENT_USER()")
            return cur.fetchone()[0] == f"{user}@{host}"
    except Exception:
        return False


def actions(rep):
    return [(o["kind"], o["id"], o["action"]) for o in rep["operations"]]


def problems(rep):
    return [(o["id"], o.get("status"), o.get("reason"), o.get("error")) for o in rep["operations"]
            if o.get("status") not in (None, "succeeded")]


def mutating(rep):
    return [a for a in actions(rep) if a[2] in engine.MUTATING]


def blocked(rep):
    return {o["id"] for o in rep["operations"] if o["action"] == "BLOCKED"}


@pytest.fixture
def my(tmp_path):
    """Präfix, Config-Writer und Aufräumen aller Objekte mit diesem Präfix."""
    try:
        sql("SELECT 1")
    except Exception as e:
        pytest.skip(f"MariaDB at {HOST}:{PORT} not reachable: {type(e).__name__}")
    adapters._load()
    prefix = f"oi{secrets.token_hex(3)}_"
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "admin").write_text(ROOT_PASSWORD)

    def write(*extra, endpoint=ENDPOINT, **target):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        base = [doc("Target", "my", adapter="mariadb", endpoint=endpoint, authentication={"credentialRef": "admin"},
                    **target),
                doc("CredentialProvider", "files", type="file", directory=str(secret_dir)),
                doc("Credential", "admin", providerRef="files", path="admin")]
        for i, d in enumerate(base + list(extra)):
            (directory / f"{i:02}.json").write_text(json.dumps(d))
        return directory

    write.prefix, write.secrets = prefix, secret_dir
    yield write
    like = prefix.replace("_", "\\_") + "%"
    for (name,) in sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE %s", like):
        sql(f"DROP DATABASE {quote_ident(name)}")
    for user, host, role in sql("SELECT User, Host, is_role FROM mysql.user WHERE User LIKE %s", like):
        sql("DROP ROLE %s", user) if role == "Y" else sql("DROP USER %s@%s", user, host)


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def user_doc(name, cred=None, policy="verify", **spec):
    extra = {"credentials": {"credentialRef": cred, "passwordPolicy": policy}} if cred else {}
    return doc("DatabaseUser", name.replace("_", "-"), targetRef="my", identity={"username": name}, **extra, **spec)


def snapshot():
    return (sql("SELECT User, Host, Priv FROM mysql.global_priv ORDER BY 1, 2"),
            sql("SELECT * FROM mysql.db ORDER BY 1, 2, 3"), sql("SELECT * FROM mysql.roles_mapping ORDER BY 1, 2, 3"),
            sql("SELECT SCHEMA_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA ORDER BY 1"))


def full_config(my):
    p = my.prefix
    return my(doc("Database", "db", targetRef="my", name=f"{p}app", characterSet="utf8mb4", collation="utf8mb4_bin"),
              doc("DatabaseRole", "role", targetRef="my", identity={"username": f"{p}reader"}),
              doc("Credential", "app-pw", providerRef="files", path="app"),
              user_doc(f"{p}app", "app-pw", roles=[f"{p}reader"], defaultRoles=[f"{p}reader"], accountLocked=False),
              doc("Grant", "g1", targetRef="my", grantee=f"{p}reader", on="database", database=f"{p}app",
                  privileges=["select", "Insert", "SHOW  VIEW"]),
              doc("Grant", "g2", targetRef="my", grantee=f"{p}app@%", on="global", privileges=["PROCESS"]))


def test_plan_apply_converge_and_login(my):
    p, path = my.prefix, full_config(my)
    before = snapshot()
    rep = run(path, "plan", allowPrivilegedGrants=True)
    assert rep["targets"][0]["serverVersion"].startswith("MariaDB 1")
    assert set(mutating(rep)) == {("Credential", "app-pw", "CREATE_SECRET"), ("Database", f"{p}app", "CREATE"),
                                  ("DatabaseRole", f"{p}reader", "CREATE"), ("DatabaseUser", f"{p}app@%", "CREATE"),
                                  ("Grant", f"{p}reader ON `{p}app`.*", "CREATE"),
                                  ("Grant", f"{p}app@% ON *.*", "CREATE")}
    assert snapshot() == before and not (my.secrets / "app").exists()  # plan ändert nichts

    assert ("Grant", f"{p}app@% ON *.*", "BLOCKED") in actions(run(path, "plan"))  # ohne Policy: gesperrt
    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert report.exit_code(rep) == 0, problems(rep)
    assert can_login(f"{p}app", (my.secrets / "app").read_text())
    assert sql("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s",
               f"{p}app") == (("utf8mb4_bin",),)
    assert sql("SELECT default_role FROM mysql.user WHERE User=%s", f"{p}app") == ((f"{p}reader",),)

    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert mutating(rep) == [] and rep["targets"][0]["status"] == "in_sync", rep["operations"]

    # Drift: Privileg und Rolle entzogen → UPDATE stellt es wieder her
    sql(f"REVOKE INSERT ON {quote_ident(escaped(p + 'app'))}.* FROM %s", f"{p}reader")
    sql("SET DEFAULT ROLE NONE FOR %s@'%%'", f"{p}app")
    sql("REVOKE %s FROM %s@'%%'", f"{p}reader", f"{p}app")
    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert {a[2] for a in mutating(rep)} == {"UPDATE"} and report.exit_code(rep) == 0, problems(rep)
    assert mutating(run(path, "plan", allowPrivilegedGrants=True)) == []
    assert sql("SELECT default_role FROM mysql.user WHERE User=%s", f"{p}app") == ((f"{p}reader",),)


def test_created_role_is_not_protected_and_can_be_deleted(my):
    """CREATE ROLE vergibt die Rolle an den Ersteller; das macht sie nicht zur geschützten Admin-Rolle."""
    p = my.prefix
    path = my(doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}tmp"}))
    assert report.exit_code(run(path, "apply")) == 0
    assert sql("SELECT 1 FROM mysql.roles_mapping WHERE Role=%s", f"{p}tmp")  # an root vergeben
    path = my(doc("ReconciliationPolicy", "gov", targetRef="my", mode="authoritative",
                  scope={"resourceKinds": ["DatabaseRole"], "DatabaseRole": {"glob": [f"{p}*"]}}))
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    assert set(mutating(rep)) == {("DatabaseRole", f"{p}tmp", "DELETE")} and report.exit_code(rep) == 0, problems(rep)


def test_authoritative_deletes_only_in_scope(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'x-doomed-1'", f"{p}doomed")
    sql(f"GRANT SELECT ON {quote_ident(escaped(p + 'gone'))}.* TO %s@'%%'", f"{p}doomed")
    sql("CREATE ROLE %s", f"{p}doomedrole")
    sql(f"CREATE DATABASE {quote_ident(p + 'gone')}")
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'x-keep-1'", f"{p}keep")
    kinds = ["Database", "DatabaseRole", "DatabaseUser", "Grant"]
    policy = doc("ReconciliationPolicy", "gov", targetRef="my", mode="authoritative",
                 scope={"resourceKinds": kinds, "DatabaseUser": {"glob": [f"{p}doomed*"]},
                        "DatabaseRole": {"glob": [f"{p}*"]}, "Database": {"glob": [f"{p}*"]},
                        "Grant": {"glob": [f"{p}*"]}})
    path = my(policy, doc("Database", "db", targetRef="my", name=f"{p}stay"))
    rep = run(path, "apply", allowAuthoritative=True)
    assert ("DatabaseUser", f"{p}doomed@%", "UNDESIRABLE") in actions(rep)
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    assert set(mutating(rep)) == {("DatabaseUser", f"{p}doomed@%", "DELETE"),
                                  ("DatabaseRole", f"{p}doomedrole", "DELETE"),
                                  ("Database", f"{p}gone", "DELETE"),
                                  ("Grant", f"{p}doomed@% ON `{p}gone`.*", "DELETE")}, rep["operations"]
    assert report.exit_code(rep) == 0, problems(rep)
    users = {u for (u,) in sql("SELECT User FROM mysql.user")}
    assert f"{p}keep" in users and f"{p}doomed" not in users and f"{p}doomedrole" not in users
    assert {"root", "mariadb.sys"} <= users


def test_identifier_injection_is_inert(my):
    p = my.prefix
    sql(f"CREATE DATABASE {quote_ident(p + 'canary')}")
    evil_db = f"{p}x`; DROP DATABASE {p}canary; -- ' \" % ü"
    evil_user = f"{p}u'`;\" ü%"
    (my.secrets / "evil").write_text("pw'; DROP USER root; -- `\"\\ ü")
    path = my(doc("Database", "db", targetRef="my", name=evil_db),
              doc("Credential", "evil", providerRef="files", path="evil"),
              doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}r`'; x"}),
              user_doc(evil_user, "evil", roles=[f"{p}r`'; x"]),
              doc("Grant", "g", targetRef="my", grantee=f"{evil_user}@%", on="database", database=evil_db,
                  privileges=["SELECT"]))
    rep = run(path, "apply")
    assert report.exit_code(rep) == 0, problems(rep)
    names = {d for (d,) in sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")}
    assert evil_db in names and f"{p}canary" in names
    assert can_login(evil_user, (my.secrets / "evil").read_text())
    assert mutating(run(path, "apply")) == []


def test_wrong_password_verify_sets_password(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'wrong-password-1'", f"{p}pw")
    (my.secrets / "pw").write_text("right-password-1\n")
    path = my(doc("Credential", "pw", providerRef="files", path="pw"), user_doc(f"{p}pw", "pw"))
    assert ("DatabaseUser", f"{p}pw@%", "SET_PASSWORD") in actions(run(path, "drift"))
    assert can_login(f"{p}pw", "wrong-password-1")  # drift änderte nichts
    rep = run(path, "apply")
    assert report.exit_code(rep) == 0, problems(rep)
    assert can_login(f"{p}pw", "right-password-1") and not can_login(f"{p}pw", "wrong-password-1")
    assert mutating(run(path, "plan")) == []
    # enforce setzt auch ein passendes Passwort neu, ohne Login-Versuch
    path = my(doc("Credential", "pw", providerRef="files", path="pw"), user_doc(f"{p}pw", "pw", policy="enforce"))
    assert ("DatabaseUser", f"{p}pw@%", "SET_PASSWORD") in actions(run(path, "plan"))


def test_verify_skipped_with_max_password_errors(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'right-password-1'", f"{p}lock")
    (my.secrets / "stale").write_text("stale-password-1")
    path = my(doc("Credential", "stale", providerRef="files", path="stale"), user_doc(f"{p}lock", "stale"))
    (old,), = sql("SELECT @@GLOBAL.max_password_errors")
    sql("SET GLOBAL max_password_errors = 1")
    try:
        for _ in range(3):
            assert ("DatabaseUser", f"{p}lock@%", "UNKNOWN") in actions(run(path, "drift"))
        assert can_login(f"{p}lock", "right-password-1")  # kein Fehl-Login → nicht gesperrt
    finally:
        sql(f"SET GLOBAL max_password_errors = {int(old)}")


def test_read_only_session_refuses_writes(my):
    p = my.prefix
    adapter = MariaDBAdapter()
    with adapter.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=False) as session:
        assert adapter.server_version(session).startswith("MariaDB ")
        for op in (Op("my", "Database", f"{p}ro", CREATE, desired=Resource("Database", f"{p}ro")),
                   Op("my", "DatabaseRole", f"{p}ro", CREATE, desired=Resource("DatabaseRole", f"{p}ro"))):
            with pytest.raises(PermanentError, match="read-only"):
                adapter.apply(session, op)
        for stmt in (f"CREATE USER {session.conn.escape(p + 'ro')}", f"CREATE ROLE {session.conn.escape(p + 'ro')}"):
            with pytest.raises(PermanentError, match="1792"):  # zweite Schicht: READ-ONLY-Session des Servers
                adapter._run(session, stmt)
    assert not sql("SELECT 1 FROM mysql.user WHERE User=%s", f"{p}ro")
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'old-password-1'", f"{p}stale")
    (my.secrets / "stale").write_text("new-password-1")
    path = my(doc("Credential", "stale", providerRef="files", path="stale"), user_doc(f"{p}stale", "stale"),
              doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}newrole"}),
              doc("Database", "db", targetRef="my", name=f"{p}new"))
    before = snapshot()
    for mode in ("plan", "drift"):
        assert run(path, mode)["operations"]
    assert snapshot() == before


def test_lock_is_exclusive(my):
    adapter = MariaDBAdapter()
    with adapter.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=True) as s1, adapter.lock(s1), \
            adapter.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=True) as s2:
        import ordivus.adapters.mysql as m

        old, m.LOCK_TIMEOUT = m.LOCK_TIMEOUT, 0
        try:
            with pytest.raises(TransientError, match="MariaDB lock"), adapter.lock(s2):
                pass
        finally:
            m.LOCK_TIMEOUT = old


def test_wrong_product_is_rejected(my):
    with pytest.raises(PermanentError, match="use adapter 'mariadb'"):
        with MySQLAdapter().connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=False):
            pass
    mysql_ep = {**ENDPOINT, "port": MYSQL_PORT}
    try:
        with MariaDBAdapter().connect({"endpoint": mysql_ep}, Secret(ROOT_PASSWORD), write=False):
            pass
    except PermanentError as e:
        assert "use adapter 'mysql'" in str(e)
    except Exception:
        pytest.skip("MySQL container not reachable")
    else:
        pytest.fail("MariaDB adapter accepted a MySQL server")


def test_access_bits_match_server(my):
    """Bitmaske in global_priv deckt sich mit information_schema.USER_PRIVILEGES (root@% hat alle Rechte)."""
    (access,), = sql("SELECT JSON_VALUE(Priv, '$.access') FROM mysql.global_priv WHERE User='root' AND Host='%'")
    names = {p for (p,) in sql("SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES "
                               "WHERE GRANTEE = \"'root'@'%'\"")}
    assert set(access_privs(int(access))) == names | {"GRANT OPTION"}
    assert set(ACCESS_BITS) == names | {"GRANT OPTION"}


def test_secret_canary_never_in_output(my, capsys):
    p = my.prefix
    canary = "CANARY-mariadb-s3cr3t-" + secrets.token_hex(4)
    (my.secrets / "c").write_text(canary)
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'other-password-1'", f"{p}c")
    path = my(doc("Credential", "c", providerRef="files", path="c"), user_doc(f"{p}c", "c"),
              doc("Credential", "n", providerRef="files", path="c"), user_doc(f"{p}n", "n"))
    for args in (["plan"], ["apply"], ["apply", "--format", "json"]):
        main([*args, "-f", str(path)])
        out = capsys.readouterr()
        assert canary not in out.out + out.err
    assert can_login(f"{p}c", canary) and can_login(f"{p}n", canary)


# --- Sicherheitsgrenzen -------------------------------------------------------------------------

def test_privileged_roles_and_grants_need_policy(my):
    p = my.prefix
    sql("CREATE ROLE %s", f"{p}boss")
    sql("GRANT CONNECTION ADMIN ON *.* TO %s", f"{p}boss")
    sql("CREATE ROLE %s", f"{p}plain")
    sql("CREATE ROLE %s", f"{p}wrap")
    sql("GRANT %s TO %s", f"{p}boss", f"{p}wrap")  # transitiv privilegiert
    sql("CREATE ROLE %s", f"{p}tbl")
    sql("GRANT UPDATE ON mysql.global_priv TO %s", f"{p}tbl")
    (my.secrets / "u").write_text("user-pw-1234567")
    cases = {"root": ["root"], "pub": ["PUBLIC"], "boss": [f"{p}boss"], "wrap": [f"{p}wrap"], "tbl": [f"{p}tbl"],
             "ok": [f"{p}plain"]}
    path = my(doc("Credential", "u", providerRef="files", path="u"),
              *[user_doc(f"{p}{k}", "u", roles=r) for k, r in cases.items()],
              doc("Grant", "g1", targetRef="my", grantee=f"{p}plain", on="database", database=f"{p}x",
                  privileges=["SELECT", "BINLOG MONITOR"]),
              doc("Grant", "g2", targetRef="my", grantee=f"{p}plain", on="database", database=f"{p}y",
                  privileges=["SELECT", "SET USER"]),
              doc("Grant", "g3", targetRef="my", grantee=f"{p}plain", on="database", database=f"{p}z",
                  privileges=["SELECT"]),
              doc("Grant", "g4", targetRef="my", grantee="public", on="database", database=f"{p}z",
                  privileges=["SELECT"]),
              doc("Grant", "g5", targetRef="my", grantee="root@localhost", on="database", database=f"{p}z",
                  privileges=["SELECT"]))
    always = {f"{p}root@%", f"{p}pub@%", f"public ON `{p}z`.*", f"root@localhost ON `{p}z`.*"}
    assert blocked(run(path, "plan")) == always | {f"{p}{k}@%" for k in ("boss", "wrap", "tbl")} | {
        f"{p}plain ON `{p}x`.*", f"{p}plain ON `{p}y`.*"}
    assert blocked(run(path, "plan", allowPrivilegedGrants=True)) == always
    rep = run(path, "apply")
    assert report.exit_code(rep) == 11
    edges = set(sql("SELECT Role, User FROM mysql.roles_mapping WHERE User LIKE %s", p.replace("_", "\\_") + "%"))
    assert edges == {(f"{p}boss", f"{p}wrap"), (f"{p}plain", f"{p}ok")}
    assert not sql("SELECT 1 FROM mysql.db WHERE User IN ('PUBLIC', 'root') AND Db LIKE %s",
                   p.replace("_", "\\_") + "%")


def test_admin_default_role_is_never_dropped(my):
    p = my.prefix
    sql("CREATE ROLE %s", f"{p}inner")
    sql("GRANT ALL ON *.* TO %s WITH GRANT OPTION", f"{p}inner")
    sql("CREATE ROLE %s", f"{p}adminrole")
    sql("GRANT %s TO %s", f"{p}inner", f"{p}adminrole")
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'admin-pw-12345'", f"{p}adm")
    sql("GRANT %s TO %s@'%%'", f"{p}adminrole", f"{p}adm")
    sql("SET DEFAULT ROLE %s FOR %s@'%%'", f"{p}adminrole", f"{p}adm")
    sql("CREATE ROLE %s", f"{p}junk")
    (my.secrets / "admin").write_text("admin-pw-12345")
    kinds = ["Database", "DatabaseRole", "DatabaseUser", "Grant"]
    path = my(doc("ReconciliationPolicy", "gov", targetRef="my", mode="authoritative",
                  scope={"resourceKinds": kinds, "DatabaseRole": {"glob": [f"{p}*"]}, "Grant": {"glob": [f"{p}*"]},
                         "DatabaseUser": {"glob": [f"{p}*"]}, "Database": {"glob": [f"{p}*"]}}),
              endpoint={**ENDPOINT, "user": f"{p}adm"})
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True, allowPrivilegedGrants=True)
    assert ("DatabaseRole", f"{p}junk", "DELETE") in mutating(rep), rep["operations"]
    assert problems(rep) == []  # Database-Inventar ist partial: SHOW DATABASES kommt nur über die Rolle
    assert not any(a[1] in (f"{p}adminrole", f"{p}inner", f"{p}adm@%") for a in mutating(rep))
    roles = {u for (u,) in sql("SELECT User FROM mysql.user")}
    assert {f"{p}adminrole", f"{p}inner"} <= roles and f"{p}junk" not in roles


def test_check_resolves_accounts_like_mariadb(my):
    a = MariaDBAdapter()
    with a.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=False) as session:
        grant = Resource("Grant", "x", {"grantee": "root  @localhost", "on": "global", "privileges": ["SELECT"]})
        assert "system account" in a.check(session, grant, allow_privileged=True)
        assert "system account" in a.check(session, Resource("DatabaseRole", "root "), allow_privileged=True)
        assert "system account" in a.check(session, Resource("DatabaseRole", "Public"), allow_privileged=True)
        own = Resource("Grant", "y", {"grantee": session.current, "on": "global", "privileges": ["SELECT"]})
        assert "admin login" in a.check(session, own, allow_privileged=True)


def test_grant_outside_scope_is_blocked_and_refused(my):
    p = my.prefix
    sql("CREATE ROLE %s", f"{p}r")
    adapter = MariaDBAdapter()
    target = {"endpoint": ENDPOINT, "scope": {"databases": {"include": [f"{p}*"]}}}
    g = adapter.desired(doc("Grant", "g", grantee=f"{p}r", on="database", database="otherdb", privileges=["SELECT"]))
    with adapter.connect(target, Secret(ROOT_PASSWORD), write=True) as session:
        assert "outside the target scope" in adapter.check(session, g)
        with pytest.raises(PermanentError, match="outside the scope"):
            adapter.apply(session, Op("my", "Grant", g.id, CREATE, desired=g))
    assert not sql("SELECT 1 FROM mysql.db WHERE User=%s", f"{p}r")


def test_account_as_user_and_role_is_config_error(my):
    p = my.prefix
    path = my(doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}dup", "host": "%"}))
    assert main(["apply", "-f", str(path)]) == 12


# --- ohne Server ---------------------------------------------------------------------------------

def test_validation_and_ids():
    a = MariaDBAdapter()
    assert a.desired(doc("DatabaseRole", "r", identity={"username": "reader"})).id == "reader"
    u = a.desired(doc("DatabaseUser", "u", identity={"username": "app"}, roles=["reader"], defaultRoles=["reader"]))
    assert u.id == "app@%" and u.attrs["roles"] == ["reader"] and u.attrs["defaultRoles"] == ["reader"]
    assert a.desired(doc("Grant", "g", grantee="reader", on="database", database="d",
                         privileges=["select"])).id == "reader ON `d`.*"
    assert a.desired(doc("Grant", "g", grantee="app@%", on="global", privileges=["select"])).id == "app@% ON *.*"
    assert a.validate(doc("DatabaseRole", "r", identity={"username": "r", "host": "%"}))
    assert a.validate(doc("DatabaseRole", "r", identity={"username": "r@x"}))
    assert a.validate(doc("DatabaseUser", "u", identity={"username": "u"}, roles=["r@%"]))
    assert any("at most one" in e for e in a.validate(
        doc("DatabaseUser", "u", identity={"username": "u"}, roles=["a", "b"], defaultRoles=["a", "b"])))
    assert a.validate(doc("Grant", "g", grantee="x@", on="global", privileges=["SELECT"]))
    assert not a.validate(doc("Grant", "g", grantee="x", on="global", privileges=["SELECT"]))
    assert access_privs(1 | 1 << 10 | 1 << 32 | 1 << 45) == ["SELECT", "GRANT OPTION", "CONNECTION ADMIN",
                                                            "UNKNOWN PRIVILEGE BIT 45"]


def test_grant_to_missing_role_never_hits_user_account(my):
    """``GRANT … TO 'x'`` ohne Rolle x träfe das Konto x@'%'; apply verweigert das."""
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'same-name-pw-1'", f"{p}same")
    adapter = MariaDBAdapter()
    g = adapter.desired(doc("Grant", "g", grantee=f"{p}same", on="database", database=f"{p}d", privileges=["SELECT"]))
    with adapter.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=True) as session:
        with pytest.raises(PermanentError, match="does not exist"):
            adapter.apply(session, Op("my", "Grant", g.id, CREATE, desired=g))
    assert not sql("SELECT 1 FROM mysql.db WHERE User=%s", f"{p}same")
    with pytest.raises(PermanentError, match=r"MariaDB 10.5.9 is not supported \(minimum 10.6.0\)"):
        adapter._check_version("10.5.9-MariaDB")
