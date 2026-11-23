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
TLS = ("disable", "require", "verify-ca", "verify-full")


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

    def write(*extra, endpoint=ENDPOINT, **target):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        base = [doc("Target", "my", adapter="mysql", endpoint=endpoint, authentication={"credentialRef": "admin"},
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
    rep = run(path, "plan", allowPrivilegedGrants=True)  # g2 ist global
    assert set(mutating(rep)) == {("Credential", "app-pw", "CREATE_SECRET"), ("Database", f"{p}app", "CREATE"),
                                  ("DatabaseRole", f"{p}reader@%", "CREATE"), ("DatabaseUser", f"{p}app@%", "CREATE"),
                                  ("Grant", f"{p}reader@% ON `{p}app`.*", "CREATE"),
                                  ("Grant", f"{p}app@% ON *.*", "CREATE")}
    assert snapshot() == before and not (my.secrets / "app").exists()  # plan ändert nichts

    assert ("Grant", f"{p}app@% ON *.*", "BLOCKED") in actions(run(path, "plan"))  # ohne Policy: gesperrt
    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert report.exit_code(rep) == 0, problems(rep)
    assert all(o["status"] == "succeeded" for o in rep["operations"] if o["action"] in engine.MUTATING)
    assert can_login(f"{p}app", (my.secrets / "app").read_text())  # Secret fehlte → erzeugt, Login klappt
    assert sql("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s",
               f"{p}app") == (("utf8mb4_bin",),)
    assert sql("SELECT DEFAULT_ROLE_USER FROM mysql.default_roles WHERE USER=%s", f"{p}app") == ((f"{p}reader",),)

    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert mutating(rep) == [] and rep["targets"][0]["status"] == "in_sync"

    # Drift: Privileg entzogen, Rolle entzogen → UPDATE stellt es wieder her
    sql(f"REVOKE INSERT ON {quote_ident(escaped(p + 'app'))}.* FROM %s@'%%'", f"{p}reader")
    sql("REVOKE %s@'%%' FROM %s@'%%'", f"{p}reader", f"{p}app")
    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert {a[2] for a in mutating(rep)} == {"UPDATE"} and report.exit_code(rep) == 0
    assert mutating(run(path, "plan", allowPrivilegedGrants=True)) == []


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
    sql(f"GRANT SELECT ON {quote_ident(escaped(p + 'gone'))}.* TO %s@'%%'", f"{p}doomed")
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


def test_account_as_user_and_role_is_config_error(my):
    p = my.prefix
    (my.secrets / "dup").write_text("dup-password-123")
    path = my(doc("DatabaseRole", "r", targetRef="my", identity={"username": f"{p}dup"}),
              doc("Credential", "dup", providerRef="files", path="dup"), user_doc(f"{p}dup", "dup"))
    with pytest.raises(config.ConfigError, match="both DatabaseRole and DatabaseUser"):
        run(path, "plan")
    assert main(["apply", "-f", str(path)]) == 12


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
    for db in ("mysql", "SYS", "performance_schema", "information_schema"):  # mysql.* schreiben = root
        assert any("system database" in e for e in a.validate(
            doc("Grant", "g", grantee="x", on="database", database=db, privileges=["SELECT"])))
    ep = {"host": "h", "user": "u"}
    assert [a.insecure_transport({"endpoint": {**ep, "tls": {"mode": m}}}) for m in TLS] == [True, True, True, False]
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
    rep = run(path, "apply", allowPrivilegedGrants=True)  # GRANT OPTION ist privilegiert
    assert ("Grant", f"{p}w@% ON `{p}d`.`or.ders`", "CREATE") in actions(rep) and report.exit_code(rep) == 0
    assert mutating(run(path, "apply", allowPrivilegedGrants=True)) == []


def test_database_grant_is_not_a_wildcard(my):
    p = my.prefix
    for db in (f"{p}app_db", f"{p}appXdb"):
        sql(f"CREATE DATABASE {quote_ident(db)}")
        sql(f"CREATE TABLE {quote_ident(db)}.t (i int)")
    (my.secrets / "w").write_text("wildcard-pw-123")
    path = my(doc("Credential", "w", providerRef="files", path="w"), user_doc(f"{p}w", "w"),
              doc("Grant", "g", targetRef="my", grantee=f"{p}w", on="database", database=f"{p}app_db",
                  privileges=["SELECT"]))
    assert report.exit_code(run(path, "apply")) == 0
    assert mutating(run(path, "plan")) == []  # Escapes beim Lesen entfernt: konvergiert
    with closing(connect(f"{p}w", "wildcard-pw-123")) as c, c.cursor() as cur:
        cur.execute(f"SELECT * FROM {quote_ident(p + 'app_db')}.t")
        with pytest.raises(Exception, match="1142|denied"):
            cur.execute(f"SELECT * FROM {quote_ident(p + 'appXdb')}.t")
    # fremder Wildcard-Grant auf dasselbe Muster: nicht änderbar und nie mit dem exakten Grant verwechselt
    sql(f"GRANT INSERT ON {quote_ident(p + 'app_db')}.* TO %s@'%%'", f"{p}w")
    rep = run(path, "plan")
    wild = next(o for o in rep["operations"] if o["id"].endswith("(wildcard pattern)"))
    assert wild["action"] == "UNMANAGED" and wild["manageable"] is False
    assert mutating(rep) == []


# --- Sicherheitsgrenzen (INV-10, Review C3/C4/C5/L4) ---------------------------------------------

def test_privileged_roles_and_grants_need_policy(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'other-user-pw-1'", f"{p}peer")
    sql("CREATE ROLE %s", f"{p}boss")
    sql("GRANT CREATE USER ON *.* TO %s", f"{p}boss")
    sql("CREATE ROLE %s, %s", f"{p}plain", f"{p}wrap")
    sql("GRANT %s TO %s", f"{p}boss", f"{p}wrap")  # transitiv privilegiert
    (my.secrets / "u").write_text("user-pw-1234567")
    cases = {"root": ["root@%"], "self": ["root@localhost"], "peer": [f"{p}peer"], "boss": [f"{p}boss"],
             "wrap": [f"{p}wrap"], "ok": [f"{p}plain"]}
    path = my(doc("Credential", "u", providerRef="files", path="u"),
              *[user_doc(f"{p}{k}", "u", roles=r) for k, r in cases.items()],
              doc("Grant", "g1", targetRef="my", grantee=f"{p}ok", on="global", privileges=["SELECT"]),
              doc("Grant", "g2", targetRef="my", grantee=f"{p}ok", on="database", database=f"{p}x",
                  privileges=["SELECT", "GRANT OPTION"]),
              doc("Grant", "g3", targetRef="my", grantee=f"{p}ok", on="database", database=f"{p}y",
                  privileges=["SELECT"]),
              doc("Grant", "g4", targetRef="my", grantee="root", on="database", database=f"{p}x",
                  privileges=["SELECT"]))

    def blocked(rep):
        return {o["id"] for o in rep["operations"] if o["action"] == "BLOCKED"}

    grants = {f"{p}ok@% ON *.*", f"{p}ok@% ON `{p}x`.*"}
    assert blocked(run(path, "plan")) == {f"{p}{k}@%" for k in ("root", "self", "peer", "boss", "wrap")} | grants | {
        f"root@% ON `{p}x`.*"}
    # mit Policy: nur Systemkonten bleiben gesperrt (root als Rolle oder Grantee)
    assert blocked(run(path, "plan", allowPrivilegedGrants=True)) == {f"{p}root@%", f"{p}self@%",
                                                                       f"root@% ON `{p}x`.*"}
    rep = run(path, "apply")
    assert report.exit_code(rep) == 11
    edges = set(sql("SELECT FROM_USER, TO_USER FROM mysql.role_edges WHERE TO_USER LIKE %s",
                    p.replace("_", "\\_") + "%"))
    assert edges == {(f"{p}boss", f"{p}wrap"), (f"{p}plain", f"{p}ok")}  # nur die unprivilegierte Rolle vergeben
    assert not sql("SELECT 1 FROM mysql.global_grants WHERE USER LIKE %s", p.replace("_", "\\_") + "%ok")


def test_grant_outside_scope_is_blocked_and_refused(my):
    p = my.prefix
    sql("CREATE ROLE %s", f"{p}r")
    path = my(doc("Grant", "g", targetRef="my", grantee=f"{p}r", on="database", database="otherdb",
                  privileges=["SELECT"]), scope={"databases": {"include": [f"{p}*"]}})
    op = next(o for o in run(path, "plan")["operations"] if o["kind"] == "Grant")
    assert op["action"] == "BLOCKED" and "outside the target scope" in op["reason"]
    adapter = MySQLAdapter()
    target = {"endpoint": ENDPOINT, "scope": {"databases": {"include": [f"{p}*"]}}}
    g = adapter.desired(doc("Grant", "g", grantee=f"{p}r", on="database", database="otherdb", privileges=["SELECT"]))
    with adapter.connect(target, Secret(ROOT_PASSWORD), write=True) as session:
        with pytest.raises(PermanentError, match="outside the scope"):  # zweite Schicht in apply
            adapter.apply(session, Op("my", "Grant", g.id, CREATE, desired=g))
    assert not sql("SELECT 1 FROM mysql.db WHERE User=%s", f"{p}r")


def test_verify_never_locks_accounts(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'right-password-1' FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1",
        f"{p}lock")
    sql("CREATE USER %s@'10.0.0.%%' IDENTIFIED BY 'right-password-2'", f"{p}far")
    (my.secrets / "stale").write_text("stale-password-1")
    path = my(doc("Credential", "stale", providerRef="files", path="stale"), user_doc(f"{p}lock", "stale"),
              doc("DatabaseUser", "far", targetRef="my", identity={"username": f"{p}far", "host": "10.0.0.%"},
                  credentials={"credentialRef": "stale"}))
    for _ in range(3):
        rep = run(path, "drift")
        assert {o["id"]: o["action"] for o in rep["operations"] if o["id"].startswith(p)} == {
            f"{p}lock@%": "UNKNOWN", f"{p}far@10.0.0.%": "UNKNOWN"}  # nie SET_PASSWORD ohne Beweis
    assert can_login(f"{p}lock", "right-password-1")  # kein Login-Versuch → keine Sperre
    assert report.exit_code(run(path, "apply")) == 13  # unprüfbar: incomplete, nichts geändert
    assert can_login(f"{p}lock", "right-password-1")


def test_admin_roles_are_never_dropped(my):
    p = my.prefix
    sql("CREATE ROLE %s, %s", f"{p}adminrole", f"{p}inner")
    sql("GRANT ALL ON *.* TO %s WITH GRANT OPTION", f"{p}inner")
    sql("GRANT %s TO %s", f"{p}inner", f"{p}adminrole")
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'admin-pw-12345' DEFAULT ROLE %s", f"{p}adm", f"{p}adminrole")
    sql("GRANT %s TO %s@'%%'", f"{p}adminrole", f"{p}adm")
    sql("SET DEFAULT ROLE ALL TO %s@'%%'", f"{p}adm")
    sql("GRANT CREATE USER, ROLE_ADMIN ON *.* TO %s@'%%'", f"{p}adm")
    sql("CREATE ROLE %s", f"{p}junk")
    (my.secrets / "admin").write_text("admin-pw-12345")
    kinds = ["Database", "DatabaseRole", "DatabaseUser", "Grant"]
    path = my(doc("ReconciliationPolicy", "gov", targetRef="my", mode="authoritative",
                  scope={"resourceKinds": kinds, "DatabaseRole": {"glob": [f"{p}*"]}, "Grant": {"glob": [f"{p}*"]},
                         "DatabaseUser": {"glob": [f"{p}*"]}, "Database": {"glob": [f"{p}*"]}}),
              endpoint={**ENDPOINT, "user": f"{p}adm"})
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    assert set(mutating(rep)) == {("DatabaseRole", f"{p}junk@%", "DELETE")}, rep["operations"]
    roles = {u for (u,) in sql("SELECT User FROM mysql.user")}
    assert {f"{p}adminrole", f"{p}inner"} <= roles and f"{p}junk" not in roles


# --- Review 2: PAD SPACE, Rollenstärke, Login-Sperre ----------------------------------------------

def test_whitespace_in_account_and_database_names_is_rejected():
    a = MySQLAdapter()
    cases = [doc("DatabaseUser", "u", identity={"username": "u"}, roles=["root "]),
             doc("DatabaseUser", "u", identity={"username": "u"}, roles=[" root@%"]),
             doc("DatabaseUser", "u", identity={"username": "u"}, roles=["x"], defaultRoles=["root @localhost"]),
             doc("DatabaseUser", "u", identity={"username": "root "}),
             doc("DatabaseRole", "r", identity={"username": "r", "host": "% "}),
             doc("Grant", "g", grantee="root ", on="global", privileges=["SELECT"]),
             doc("Grant", "g", grantee="x@ localhost", on="global", privileges=["SELECT"]),
             doc("Grant", "g", grantee="x", on="database", database="mysql ", privileges=["SELECT"]),
             doc("Grant", "g", grantee="x", on="table", database="d", table="t ", privileges=["SELECT"]),
             doc("Database", "d", name=" d")]
    for d in cases:
        assert any("whitespace" in e for e in a.validate(d)), d


def test_check_resolves_accounts_like_mysql(my):
    """Auch ohne Validierung: check() vergleicht mit der mysql.user-Zeile, die MySQL selbst wählt (PAD SPACE)."""
    a = MySQLAdapter()
    with a.connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=False) as session:
        user = Resource("DatabaseUser", f"{my.prefix}u@%", {"roles": ["root @%"]})
        assert "system account" in a.check(session, user, allow_privileged=True)
        grant = Resource("Grant", "x", {"grantee": "root  @localhost", "on": "global", "privileges": ["SELECT"]})
        assert "system account" in a.check(session, grant, allow_privileged=True)
        assert "system account" in a.check(session, Resource("DatabaseRole", "root   @%"), allow_privileged=True)


def test_roles_with_system_table_or_proxy_privileges_are_powerful(my):
    p = my.prefix
    sql("CREATE ROLE %s, %s, %s, %s", f"{p}tbl", f"{p}proxy", f"{p}wild", f"{p}plain")
    sql("GRANT UPDATE ON mysql.user TO %s", f"{p}tbl")
    sql("GRANT PROXY ON root@'%%' TO %s", f"{p}proxy")
    sql("GRANT SELECT ON `m%%`.* TO %s", f"{p}wild")  # Wildcard-Muster trifft mysql
    path = my(*[doc("DatabaseUser", k, targetRef="my", identity={"username": f"{p}u{k}"}, roles=[f"{p}{k}"],
                    accountLocked=True) for k in ("tbl", "proxy", "wild", "plain")])
    rep = run(path, "plan")
    assert {o["id"] for o in rep["operations"] if o["action"] == "BLOCKED"} == {
        f"{p}u{k}@%" for k in ("tbl", "proxy", "wild")}
    assert not any(o["action"] == "BLOCKED" for o in run(path, "plan", allowPrivilegedGrants=True)["operations"])


def test_verify_skips_when_another_host_row_has_login_locking(my):
    p = my.prefix
    sql("CREATE USER %s@'%%' IDENTIFIED BY 'right-password-3'", f"{p}two")
    sql("CREATE USER %s@'127.0.0.1' IDENTIFIED BY 'right-password-4' FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME 1",
        f"{p}two")
    a = MySQLAdapter()
    target = {"endpoint": ENDPOINT}
    with a.connect(target, Secret(ROOT_PASSWORD), write=False) as session:
        assert a.verify_password(session, target, Resource("DatabaseUser", f"{p}two@%"), Secret("stale-pw-1")) is None
    assert can_login(f"{p}two", "right-password-4", host="127.0.0.1") or can_login(f"{p}two", "right-password-3")


def test_server_version_and_minimum(my):
    from ordivus.adapters.mysql import _product_version

    with MySQLAdapter().connect({"endpoint": ENDPOINT}, Secret(ROOT_PASSWORD), write=False) as session:
        assert MySQLAdapter().server_version(session).startswith("MySQL 8.")
    assert _product_version("MySQL", "8.0.16-log", (8, 0, 16)) == "MySQL 8.0.16"
    with pytest.raises(PermanentError, match=r"MySQL 8.0.15 is not supported \(minimum 8.0.16\)"):
        _product_version("MySQL", "8.0.15", (8, 0, 16))
    with pytest.raises(PermanentError, match="use adapter 'mariadb'"):
        MySQLAdapter()._check_version("11.4.13-MariaDB-ubu2404")
