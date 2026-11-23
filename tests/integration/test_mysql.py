"""MySQL-Adapter gegen einen echten Container (ordivus-it-mysql, Port 13306); sonst sauber übersprungen."""

import json
import os
import secrets
from contextlib import closing

import pytest

from ordivus import adapters
from ordivus.adapters.base import CREATE, Op, PermanentError, Resource, Secret, TransientError
from ordivus.adapters.mysql import MySQLAdapter, account, quote_ident
from ordivus.cli import main
from ordivus.core import config, engine, report
from ordivus.core.policy import OperatorPolicy

HOST = os.environ.get("ORDIVUS_TEST_HOST", "localhost")
PORT = 13306
ROOT_PASSWORD = os.environ.get("ORDIVUS_TEST_MYSQL_PASSWORD", "ordivus-root")
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
    return [(o["id"], o["status"], o["reason"]) for o in rep["operations"]
            if o.get("status") not in (None, "succeeded")]


def mutating(rep):
    return [a for a in actions(rep) if a[2] in engine.MUTATING]


@pytest.fixture
def my(tmp_path):
    """Präfix, Config-Writer und Aufräumen aller Objekte mit diesem Präfix."""
    try:
        sql("SELECT 1")
    except Exception as e:
        pytest.skip(f"MySQL at {HOST}:{PORT} not reachable: {type(e).__name__}")
    adapters._load()
    prefix = f"oi{secrets.token_hex(3)}_"
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "admin").write_text(ROOT_PASSWORD)

    def write(*extra, endpoint=ENDPOINT):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        base = [doc("Target", "my", adapter="mysql", endpoint=endpoint, authentication={"credentialRef": "admin"}),
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
    for user, host in sql("SELECT User, Host FROM mysql.user WHERE User LIKE %s", like):
        sql("DROP USER %s@%s", user, host)


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def user_doc(name, cred=None, policy="verify", **spec):
    extra = {"credentials": {"credentialRef": cred, "passwordPolicy": policy}} if cred else {}
    return doc("DatabaseUser", name.replace("_", "-"), targetRef="my", identity={"username": name}, **extra, **spec)


def snapshot():
    return (sql("SELECT User, Host, account_locked, authentication_string FROM mysql.user ORDER BY 1, 2"),
            sql("SELECT * FROM mysql.db ORDER BY 1, 2, 3"), sql("SELECT * FROM mysql.role_edges ORDER BY 1, 2, 3, 4"),
            sql("SELECT SCHEMA_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA ORDER BY 1"))


def full_config(my):
    p = my.prefix
    return my(doc("Database", "db", targetRef="my", name=f"{p}app", characterSet="utf8mb4", collation="utf8mb4_bin"),
              doc("DatabaseRole", "role", targetRef="my", identity={"username": f"{p}reader"}),
              doc("Credential", "app-pw", providerRef="files", path="app"),
              user_doc(f"{p}app", "app-pw", roles=[f"{p}reader"], defaultRoles=[f"{p}reader"], accountLocked=False),
              doc("Grant", "g1", targetRef="my", grantee=f"{p}reader", on="database", database=f"{p}app",
                  privileges=["select", "Insert", "SHOW  VIEW"]),
              doc("Grant", "g2", targetRef="my", grantee=f"{p}app", on="global", privileges=["PROCESS"]))


def test_plan_apply_converge_and_login(my):
    p, path = my.prefix, full_config(my)
    before = snapshot()
    rep = run(path, "plan")
    assert set(mutating(rep)) == {("Credential", "app-pw", "CREATE_SECRET"), ("Database", f"{p}app", "CREATE"),
                                  ("DatabaseRole", f"{p}reader@%", "CREATE"), ("DatabaseUser", f"{p}app@%", "CREATE"),
                                  ("Grant", f"{p}reader@% ON `{p}app`.*", "CREATE"),
                                  ("Grant", f"{p}app@% ON *.*", "CREATE")}
    assert snapshot() == before and not (my.secrets / "app").exists()  # plan ändert nichts

    rep = run(path, "apply")
    assert report.exit_code(rep) == 0, problems(rep)
    assert all(o["status"] == "succeeded" for o in rep["operations"] if o["action"] in engine.MUTATING)
    assert can_login(f"{p}app", (my.secrets / "app").read_text())  # Secret fehlte → erzeugt, Login klappt
    assert sql("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s",
               f"{p}app") == (("utf8mb4_bin",),)
    assert sql("SELECT DEFAULT_ROLE_USER FROM mysql.default_roles WHERE USER=%s", f"{p}app") == ((f"{p}reader",),)

    rep = run(path, "apply")
    assert mutating(rep) == [] and rep["targets"][0]["status"] == "in_sync"

    # Drift: Privileg entzogen, Rolle entzogen → UPDATE stellt es wieder her
    sql(f"REVOKE INSERT ON {quote_ident(p + 'app')}.* FROM %s@'%%'", f"{p}reader")
    sql("REVOKE %s@'%%' FROM %s@'%%'", f"{p}reader", f"{p}app")
    rep = run(path, "apply")
    assert {a[2] for a in mutating(rep)} == {"UPDATE"} and report.exit_code(rep) == 0
    assert mutating(run(path, "plan")) == []


def test_undeclared_unmanaged_survives_additive(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'x-unmanaged-1'", f"{p}other")
    sql(f"CREATE DATABASE {quote_ident(p + 'otherdb')}")
    rep = run(my(doc("Database", "db", targetRef="my", name=f"{p}mine")), "apply", allowDelete=True)
    assert ("DatabaseUser", f"{p}other@%", "UNMANAGED") in actions(rep)
    assert ("Database", f"{p}otherdb", "UNMANAGED") in actions(rep)
    assert ("Database", "mysql", "UNMANAGED") not in actions(rep)  # Systemobjekte: IGNORE, nicht gelistet
    assert sql("SELECT 1 FROM mysql.user WHERE User=%s", f"{p}other")
    assert sql("SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s", f"{p}otherdb")


def test_authoritative_deletes_only_in_scope(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'x-doomed-1'", f"{p}doomed")
    sql(f"GRANT SELECT ON {quote_ident(p + 'gone')}.* TO %s@'%%'", f"{p}doomed")
    sql("CREATE ROLE %s", f"{p}doomedrole")
    sql(f"CREATE DATABASE {quote_ident(p + 'gone')}")
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'x-keep-1'", f"{p}keep")  # außerhalb des Policy-Scopes
    kinds = ["Database", "DatabaseRole", "DatabaseUser", "Grant"]
    policy = doc("ReconciliationPolicy", "gov", targetRef="my", mode="authoritative",
                 scope={"resourceKinds": kinds, "DatabaseUser": {"glob": [f"{p}doomed*"]},
                        "DatabaseRole": {"glob": [f"{p}*"]}, "Database": {"glob": [f"{p}*"]},
                        "Grant": {"glob": [f"{p}*"]}})
    path = my(policy, doc("Database", "db", targetRef="my", name=f"{p}stay"))
    rep = run(path, "apply", allowAuthoritative=True)  # ohne allowDelete: nur UNDESIRABLE
    assert ("DatabaseUser", f"{p}doomed@%", "UNDESIRABLE") in actions(rep)
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    assert set(mutating(rep)) == {("DatabaseUser", f"{p}doomed@%", "DELETE"),
                                  ("DatabaseRole", f"{p}doomedrole@%", "DELETE"),
                                  ("Database", f"{p}gone", "DELETE"),
                                  ("Grant", f"{p}doomed@% ON `{p}gone`.*", "DELETE")}, rep["operations"]
    assert report.exit_code(rep) == 0, problems(rep)
    assert ("DatabaseUser", f"{p}keep@%", "UNMANAGED") in actions(rep)
    users = {u for (u,) in sql("SELECT User FROM mysql.user")}
    assert f"{p}keep" in users and f"{p}doomed" not in users and f"{p}doomedrole" not in users
    assert {"root", "mysql.sys", "mysql.session", "mysql.infoschema"} <= users
    assert {"mysql", "sys"} <= {d for (d,) in sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")}


def test_identifier_injection_is_inert(my):
    p = my.prefix
    sql(f"CREATE DATABASE {quote_ident(p + 'canary')}")
    evil_db = f"{p}x`; DROP DATABASE {p}canary; -- ' \" % ü 数据"
    evil_user = f"{p}u'`;\" ü%"
    (my.secrets / "evil").write_text("pw'; DROP USER root; -- `\"\\ ü")
    path = my(doc("Database", "db", targetRef="my", name=evil_db),
              doc("Credential", "evil", providerRef="files", path="evil"),
              doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}r`'; x", "host": "%"}),
              user_doc(evil_user, "evil", roles=[f"{p}r`'; x"]),
              doc("Grant", "g", targetRef="my", grantee=evil_user, on="database", database=evil_db,
                  privileges=["SELECT"]))
    rep = run(path, "apply")
    assert report.exit_code(rep) == 0, problems(rep)
    names = {d for (d,) in sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")}
    assert evil_db in names and f"{p}canary" in names
    assert can_login(evil_user, (my.secrets / "evil").read_text())
    assert "root" in {u for (u,) in sql("SELECT User FROM mysql.user")}
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


def test_read_only_session_refuses_writes(my):
    p = my.prefix
    adapter = MySQLAdapter()
    with adapter.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=False) as session:
        for op in (Op("my", "Database", f"{p}ro", CREATE, desired=Resource("Database", f"{p}ro")),
                   Op("my", "DatabaseUser", f"{p}ro@%", CREATE, desired=Resource("DatabaseUser", f"{p}ro@%"),
                      password=Secret("x-ro-password-1"))):
            with pytest.raises(PermanentError, match="read-only"):
                adapter.apply(session, op)
        with pytest.raises(PermanentError, match="1792"):  # zweite Schicht: READ-ONLY-Session des Servers
            adapter._run(session, f"CREATE USER {session.conn.escape(p + 'ro')}")
    assert not sql("SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s", f"{p}ro")
    assert not sql("SELECT 1 FROM mysql.user WHERE User=%s", f"{p}ro")
    # plan/drift mit allen Operationsarten lassen den Server unverändert
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'old-password-1'", f"{p}stale")
    (my.secrets / "stale").write_text("new-password-1")
    path = my(doc("Credential", "stale", providerRef="files", path="stale"), user_doc(f"{p}stale", "stale"),
              doc("Database", "db", targetRef="my", name=f"{p}new"))
    before = snapshot()
    for mode in ("plan", "drift"):
        assert run(path, mode)["operations"]
    assert snapshot() == before


def test_lock_is_exclusive(my):
    adapter = MySQLAdapter()
    with adapter.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=True) as s1, adapter.lock(s1), \
            adapter.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=True) as s2:
        import ordivus.adapters.mysql as m

        old, m.LOCK_TIMEOUT = m.LOCK_TIMEOUT, 0
        try:
            with pytest.raises(TransientError), adapter.lock(s2):
                pass
        finally:
            m.LOCK_TIMEOUT = old


def test_account_as_user_and_role_fails_cleanly(my):
    p = my.prefix
    (my.secrets / "dup").write_text("dup-password-123")
    path = my(doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}dup"}),
              doc("Credential", "dup", providerRef="files", path="dup"), user_doc(f"{p}dup", "dup"))
    rep = run(path, "apply")
    op = next(o for o in rep["operations"] if o["kind"] == "DatabaseUser" and o["action"] == "CREATE")
    assert op["status"] == "failed" and "both DatabaseUser and DatabaseRole" in op["reason"]


def test_secret_canary_never_in_output(my, capsys):
    p = my.prefix
    canary = "CANARY-mysql-s3cr3t-" + secrets.token_hex(4)
    (my.secrets / "c").write_text(canary)
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'other-password-1'", f"{p}c")
    path = my(doc("Credential", "c", providerRef="files", path="c"), user_doc(f"{p}c", "c"),
              doc("Credential", "n", providerRef="files", path="c"), user_doc(f"{p}n", "n"))
    for args in (["plan"], ["apply"], ["apply", "--format", "json"]):
        main([*args, "-f", str(path)])
        out = capsys.readouterr()
        assert canary not in out.out + out.err
    assert can_login(f"{p}c", canary) and can_login(f"{p}n", canary)


# --- ohne Server ---------------------------------------------------------------------------------

def test_quoting_and_account_parsing():
    assert quote_ident("a`b") == "`a``b`"
    assert account("me@example.com@10.%") == ("me@example.com", "10.%")
    assert account("reader") == ("reader", "%") and account("r@LocalHost") == ("r", "localhost")


def test_validation():
    a = MySQLAdapter()
    errs = a.validate(doc("Grant", "g", grantee="x", on="database", privileges=["ALL PRIVILEGES", "SEL;ECT"]))
    assert any("database" in e for e in errs) and any("ALL PRIVILEGES" in e for e in errs)
    assert any("invalid privilege" in e for e in errs)
    assert a.validate(doc("DatabaseUser", "u", identity={"username": "u"}, roles=["a"], defaultRoles=["b"]))
    assert a.validate(doc("Target", "t", endpoint={"host": "h", "username": "u", "tls": {"mode": "off"}}, x=1))
    assert a.validate(doc("Database", "d", collation="utf8; DROP")) and not a.validate(doc("Database", "d"))
    g = a.desired(doc("Grant", "g", grantee="r", on="table", database="d.b", table="t", privileges=["select", "a b"]))
    assert g.id == "r@% ON `d.b`.`t`" and g.attrs["privileges"] == ["A B", "SELECT"]


def test_read_only_identity_sees_complete_inventory(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'ro-password-123'", f"{p}ro")
    sql("GRANT SELECT ON mysql.* TO %s@'%%'", f"{p}ro")
    sql("GRANT SHOW DATABASES ON *.* TO %s@'%%'", f"{p}ro")
    (my.secrets / "admin").write_text("ro-password-123")
    path = my(doc("Database", "db", targetRef="my", name=f"{p}new"), endpoint={**ENDPOINT, "user": f"{p}ro"})
    rep = run(path, "plan")
    assert {k: v["status"] for k, v in rep["targets"][0]["inventory"].items()} == dict.fromkeys(
        MySQLAdapter.kinds, "complete")
    assert ("Database", f"{p}new", "CREATE") in actions(rep)
    sql("REVOKE SHOW DATABASES ON *.* FROM %s@'%%'", f"{p}ro")
    rep = run(path, "plan")
    assert rep["targets"][0]["inventory"]["Database"]["status"] == "partial"
    assert ("Database", f"{p}new", "UNKNOWN") in actions(rep)  # nie CREATE auf Teilinventar
    assert rep["targets"][0]["inventory"]["DatabaseUser"]["status"] == "complete"


def test_table_grant_and_grant_option_converge(my):
    p = my.prefix
    sql(f"CREATE DATABASE {quote_ident(p + 'd')}")
    sql(f"CREATE TABLE {quote_ident(p + 'd')}.{quote_ident('or.ders')} (i int)")
    path = my(doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}w"}),
              doc("Grant", "t", targetRef="my", grantee=f"{p}w", on="table", database=f"{p}d", table="or.ders",
                  privileges=["insert", "update", "grant option"]))
    rep = run(path, "apply")
    assert ("Grant", f"{p}w@% ON `{p}d`.`or.ders`", "CREATE") in actions(rep) and report.exit_code(rep) == 0
    assert mutating(run(path, "apply")) == []
