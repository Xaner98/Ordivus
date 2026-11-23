"""Integration tests for the PostgreSQL adapter against container `ordivus-it-postgresql` (port 15432)."""

import json
import os
import secrets
import uuid

import pytest

from ordivus import adapters
from ordivus.adapters.base import CREATE, Op, PermanentError, Resource, Secret, TransientError
from ordivus.adapters.postgresql import PostgreSQLAdapter
from ordivus.cli import main
from ordivus.core import config, engine, report
from ordivus.core.policy import OperatorPolicy

psycopg = pytest.importorskip("psycopg")
HOST, PORT, ADMIN_PW = os.environ.get("ORDIVUS_TEST_HOST", "localhost"), 15432, "ordivus-it"
MUTATING = set(engine.MUTATING)


def connect(user="postgres", password=ADMIN_PW, dbname="postgres"):
    return psycopg.connect(host=HOST, port=PORT, user=user, password=password, dbname=dbname,
                           autocommit=True, connect_timeout=3)


@pytest.fixture(scope="module")
def admin():
    try:
        conn = connect()
    except psycopg.OperationalError:
        pytest.skip(f"PostgreSQL not reachable at {HOST}:{PORT}")
    adapters.register(PostgreSQLAdapter)
    yield conn
    conn.close()


def doc(kind, doc_name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": doc_name}, "spec": spec}


class Env:
    def __init__(self, admin, tmp_path):
        self.admin, self.tmp = admin, tmp_path
        self.p = f"oit_{uuid.uuid4().hex[:6]}_"
        self.secrets = tmp_path / "secrets"
        self.secrets.mkdir()
        (self.secrets / "admin").write_text(ADMIN_PW)

    def target(self, scoped=True, user="postgres"):
        scope = {"roles": {"include": [self.p + "*"]}, "databases": {"include": [self.p + "*"]}} if scoped else {}
        return {"endpoint": {"host": HOST, "port": PORT, "user": user, "database": "postgres"}, "scope": scope}

    def cfg(self, *docs, scoped=True, user="postgres", cred="admin"):
        directory = self.tmp / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        base = [doc("Target", "pg", adapter="postgresql", authentication={"credentialRef": cred},
                    **self.target(scoped, user)),
                doc("CredentialProvider", "files", type="file", directory=str(self.secrets)),
                doc("Credential", "admin", providerRef="files", path="admin")]
        resources = [{**d, "spec": {"targetRef": "pg", **d["spec"]}} if d["kind"] not in config.ENGINE_KINDS else d
                     for d in docs]
        for i, d in enumerate(base + resources):
            (directory / f"{i:02}.json").write_text(json.dumps(d))
        return directory

    def objects(self):
        rows = self.admin.execute("SELECT rolname FROM pg_roles UNION ALL SELECT datname FROM pg_database")
        return sorted(n for (n,) in rows if n.startswith(self.p))

    def cleanup(self):
        for (name,) in self.admin.execute("SELECT datname FROM pg_database").fetchall():
            if name.startswith(self.p):
                self.admin.execute(psycopg.sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                    psycopg.sql.Identifier(name)))
        for (name,) in self.admin.execute("SELECT rolname FROM pg_roles").fetchall():
            if name.startswith(self.p):
                self.admin.execute(psycopg.sql.SQL("DROP ROLE {}").format(psycopg.sql.Identifier(name)))

    def sql(self, query, *names, dbname=None):
        q = psycopg.sql.SQL(query).format(*map(psycopg.sql.Identifier, names))
        if dbname is None:
            return self.admin.execute(q)
        with connect(dbname=dbname) as conn:
            conn.execute(q)


@pytest.fixture
def pg(admin, tmp_path):
    env = Env(admin, tmp_path)
    yield env
    env.cleanup()


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def actions(rep):
    return {(o["kind"], o["id"], o["action"]) for o in rep["operations"]}


def grant_id(grantee, database, on, schema=None):
    return json.dumps([grantee, database, on] + ([schema] if schema else []), ensure_ascii=False,
                      separators=(",", ":"))


def test_plan_apply_idempotent_and_password_from_file(pg):
    p = pg.p
    path = pg.cfg(
        doc("DatabaseRole", "readers", name=p + "readers"),
        doc("Credential", "app-pw", providerRef="files", path="app"),
        doc("DatabaseUser", "app", name=p + "app", memberOf=[p + "readers"], connectionLimit=5,
            credentials={"credentialRef": "app-pw"}),
        doc("Database", "db", name=p + "db", owner=p + "app", encoding="utf8"),
        doc("Grant", "g1", grantee=p + "readers", database=p + "db", on="database", privileges=["connect", "temp"]),
        doc("Grant", "g2", grantee=p + "readers", database=p + "db", on="schema", schema="public",
            privileges=["USAGE"]))
    plan = run(path, "plan")
    assert {("DatabaseRole", p + "readers", "CREATE"), ("DatabaseUser", p + "app", "CREATE"),
            ("Database", p + "db", "CREATE"), ("Credential", "app-pw", "CREATE_SECRET"),
            ("Grant", grant_id(p + "readers", p + "db", "database"), "CREATE"),
            ("Grant", grant_id(p + "readers", p + "db", "schema", "public"), "CREATE")} <= actions(plan)
    assert pg.objects() == [] and not (pg.secrets / "app").exists()

    first = run(path, "apply")
    assert report.exit_code(first) == 0, first["operations"]
    assert all(o["status"] == "succeeded" for o in first["operations"] if o["action"] in MUTATING)
    with connect(p + "app", (pg.secrets / "app").read_text(), p + "db") as conn:
        assert conn.execute("SELECT current_user").fetchone()[0] == p + "app"
    assert pg.admin.execute("SELECT rolconnlimit FROM pg_roles WHERE rolname = %s", (p + "app",)).fetchone() == (5,)

    second = run(path, "apply")
    assert [o for o in second["operations"] if o["action"] in MUTATING] == []
    assert report.exit_code(second) == 0


def test_unmanaged_survives_additive_and_authoritative_deletes_in_scope(pg):
    p = pg.p
    for name in ("extra", "del_a"):
        pg.sql("CREATE ROLE {} LOGIN", p + name)
    pg.sql("CREATE ROLE {} NOLOGIN", p + "del_b")
    pg.sql("CREATE DATABASE {}", p + "deldb")
    keep = doc("DatabaseRole", "keep", name=p + "keep")

    additive = run(pg.cfg(keep), "apply", allowDelete=True)
    assert ("DatabaseUser", p + "extra", "UNMANAGED") in actions(additive)
    assert ("Database", p + "deldb", "UNMANAGED") in actions(additive)

    policy = doc("ReconciliationPolicy", "gov", targetRef="pg", mode="authoritative",
                 scope={"resourceKinds": ["DatabaseUser", "DatabaseRole"],
                        "DatabaseUser": {"glob": [p + "del*"]}, "DatabaseRole": {"glob": [p + "del*"]}})
    rep = run(pg.cfg(keep, policy), "apply", allowAuthoritative=True, allowDelete=True)
    assert {("DatabaseUser", p + "del_a", "DELETE"), ("DatabaseRole", p + "del_b", "DELETE"),
            ("DatabaseUser", p + "extra", "UNMANAGED"), ("DatabaseRole", p + "keep", "NOOP"),
            ("Database", p + "deldb", "UNMANAGED")} <= actions(rep)
    assert report.exit_code(rep) == 0
    assert pg.objects() == sorted([p + "deldb", p + "extra", p + "keep"])

    # Ohne Target-Scope: Systemobjekte sind IGNORE, nie DELETE (nur plan, mutiert nichts)
    wide = doc("ReconciliationPolicy", "gov", targetRef="pg", mode="authoritative",
               scope={"resourceKinds": ["DatabaseUser", "DatabaseRole", "Database"]})
    rep = run(pg.cfg(wide, scoped=False), "plan", allowAuthoritative=True, allowDelete=True)
    deletes = {name for _, name, action in actions(rep) if action == "DELETE"}
    assert p + "extra" in deletes  # Scope greift, Systemobjekte werden trotzdem nie geplant
    assert not deletes & {"postgres", "template0", "template1"} and not any(n.startswith("pg_") for n in deletes)
    assert pg.objects() == sorted([p + "deldb", p + "extra", p + "keep"])


def test_identifier_injection_is_safe(pg):
    p = pg.p
    role, user, db = p + 'r"; DROP ROLE postgres; --', p + "u sp ä名'x", p + 'd"b;x'
    path = pg.cfg(
        doc("DatabaseRole", "r", name=role),
        doc("DatabaseUser", "u", name=user, memberOf=[role]),
        doc("Database", "d", name=db, owner=user),
        doc("Grant", "g", grantee=role, database=db, on="database", privileges=["CONNECT"]),
        doc("Grant", "s", grantee=user, database=db, on="schema", schema="public", privileges=["CREATE", "USAGE"]))
    first = run(path, "apply", allowPrivilegedGrants=True)  # CREATE auf Schema ist privilegiert
    assert report.exit_code(first) == 0, first["operations"]
    assert pg.objects() == sorted([db, role, user])
    assert pg.admin.execute("SELECT count(*) FROM pg_roles WHERE rolname = 'postgres'").fetchone() == (1,)
    second = run(path, "apply", allowPrivilegedGrants=True)
    assert [o for o in second["operations"] if o["action"] in MUTATING] == []


def test_wrong_password_is_reset_with_verify_and_canary_never_leaks(pg, capsys):
    p, canary = pg.p, "Canary" + secrets.token_hex(12)
    pg.sql("CREATE ROLE {} LOGIN PASSWORD 'old-wrong'", p + "u")
    (pg.secrets / "u").write_text(canary)
    path = pg.cfg(doc("Credential", "u-pw", providerRef="files", path="u"),
                  doc("DatabaseUser", "u", name=p + "u",
                      credentials={"credentialRef": "u-pw", "passwordPolicy": "verify"}))
    adapter = PostgreSQLAdapter()
    observed = Resource("DatabaseUser", p + "u")
    assert adapter.verify_password(None, pg.target(), observed, Secret(canary)) is False

    assert main(["plan", "-f", str(path), "--format", "json"]) in (0, 10)
    plan = run(path, "plan")
    assert ("DatabaseUser", p + "u", "SET_PASSWORD") in actions(plan)
    assert main(["apply", "-f", str(path), "--format", "json"]) == 0
    assert adapter.verify_password(None, pg.target(), observed, Secret(canary)) is True
    with connect(p + "u", canary):
        pass
    again = run(path, "apply")
    assert [o for o in again["operations"] if o["action"] in MUTATING] == []
    out = capsys.readouterr()
    assert canary not in out.out + out.err + json.dumps(plan) + json.dumps(again)

    pg.sql("CREATE ROLE {} NOLOGIN PASSWORD 'x'", p + "nl")  # Login aus anderem Grund unmöglich → None
    assert adapter.verify_password(None, pg.target(), Resource("DatabaseUser", p + "nl"), Secret("x")) is None


def test_read_only_session_cannot_mutate(pg):
    adapter = PostgreSQLAdapter()
    with adapter.connect(pg.target(), Secret(ADMIN_PW), write=False) as session:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            session.conn.execute(psycopg.sql.SQL("CREATE ROLE {}").format(psycopg.sql.Identifier(pg.p + "x")))
        with adapter._database(session, "postgres") as conn, pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("CREATE TABLE ordivus_should_not_exist (i int)")
        op = Op("pg", "DatabaseRole", pg.p + "x", CREATE, desired=Resource("DatabaseRole", pg.p + "x"))
        with pytest.raises(PermanentError):
            adapter.apply(session, op)
    assert pg.objects() == []


def test_tables_in_schema_grant(pg):
    p = pg.p
    pg.sql("CREATE ROLE {} NOLOGIN", p + "r")
    pg.sql("CREATE DATABASE {}", p + "tdb")
    pg.sql("CREATE SCHEMA app; CREATE TABLE app.t1 (i int); CREATE VIEW app.v1 AS SELECT 1 AS i", dbname=p + "tdb")

    def grant(*privileges):
        return pg.cfg(doc("Grant", "g", grantee=p + "r", database=p + "tdb", on="tables-in-schema", schema="app",
                          privileges=list(privileges)))

    def has(privilege, table):
        with connect(dbname=p + "tdb") as conn:
            return conn.execute("SELECT has_table_privilege(%s, %s, %s)", (p + "r", table, privilege)).fetchone()[0]

    first = run(grant("SELECT", "INSERT"), "apply")
    assert report.exit_code(first) == 0, first["operations"]
    assert has("SELECT", "app.t1") and has("INSERT", "app.v1")
    assert [o for o in run(grant("SELECT", "INSERT"), "apply")["operations"] if o["action"] in MUTATING] == []
    update = run(grant("SELECT"), "apply")
    assert ("Grant", grant_id(p + "r", p + "tdb", "tables-in-schema", "app"), "UPDATE") in actions(update)
    assert report.exit_code(update) == 0 and has("SELECT", "app.t1") and not has("INSERT", "app.t1")


def test_unreadable_database_makes_grant_discovery_partial(pg):
    p = pg.p
    (pg.secrets / "ro").write_text("ro-secret-1234")
    pg.sql("CREATE ROLE {} LOGIN PASSWORD 'ro-secret-1234'", p + "ro")
    pg.sql("CREATE DATABASE {}", p + "locked")
    pg.sql("REVOKE CONNECT ON DATABASE {} FROM PUBLIC", p + "locked")
    path = pg.cfg(doc("Credential", "ro", providerRef="files", path="ro"),
                  doc("Grant", "g", grantee=p + "ro", database=p + "locked", on="database", privileges=["CONNECT"]),
                  user=p + "ro", cred="ro")
    rep = run(path, "plan")
    inventory = rep["targets"][0]["inventory"]
    assert inventory["Grant"]["status"] == "partial" and inventory["Database"]["status"] == "complete"
    assert ("Grant", grant_id(p + "ro", p + "locked", "database"), "UNKNOWN") in actions(rep)


def test_advisory_lock_excludes_second_apply(pg):
    adapter = PostgreSQLAdapter()
    with adapter.connect(pg.target(), Secret(ADMIN_PW), True) as one, adapter.lock(one), \
            adapter.connect(pg.target(), Secret(ADMIN_PW), True) as two:
        with pytest.raises(TransientError), adapter.lock(two):
            pass


def test_validation_without_connection():
    adapter = PostgreSQLAdapter()

    def errors(kind, **spec):
        return adapter.validate({"kind": kind, "metadata": {"name": "x"}, "spec": spec})

    assert errors("Target", endpoint={"host": "h", "user": "u"}) == []
    assert errors("Target", endpoint={"host": "h"}) == ["spec.endpoint.user must be a non-empty string"]
    assert errors("DatabaseUser", superuser=True) == ["spec.superuser is not manageable by Ordivus"]
    assert errors("DatabaseRole", name="x" * 64) == ["spec.name must be at most 63 bytes"]
    assert errors("DatabaseRole", bogus=1) == ["unknown field spec.bogus"]
    assert errors("Grant", grantee="public", database="d", on="database", privileges=["CONNECT"]) \
        == ["grants to PUBLIC are not supported"]
    assert errors("Grant", grantee="g", database="d", on="schema", schema="s", privileges=["SELECT"]) \
        == ["spec.privileges: 'SELECT' is not one of ['CREATE', 'USAGE']"]
    assert errors("Grant", grantee="g", database="d", on="database", privileges=["temp"]) == []
    for schema in ("pg_catalog", "information_schema", "pg_toast"):  # unsichtbar für die Discovery
        assert errors("Grant", grantee="g", database="d", on="tables-in-schema", schema=schema,
                      privileges=["SELECT"]) == [f"spec.schema {schema!r} is a system schema; grants on it are "
                                                 "not supported"]
    tls = {mode: adapter.insecure_transport({"endpoint": {"tls": {"mode": mode}}}) for mode in ("verify-ca",
                                                                                              "verify-full")}
    assert tls == {"verify-ca": True, "verify-full": False}  # verify-ca prüft den Hostnamen nicht


def test_member_before_parent_converges_in_one_apply(pg):
    member, parent = pg.p + "a_member", pg.p + "z_parent"  # Namensordnung wäre falsch herum
    path = pg.cfg(doc("DatabaseRole", "m", name=member, memberOf=[parent]), doc("DatabaseRole", "p", name=parent))
    rep = run(path, "apply")
    assert report.exit_code(rep) == 0, rep["operations"]
    assert [o["id"] for o in rep["operations"] if o["action"] == "CREATE"] == [parent, member]
    assert not any(o["action"] in MUTATING for o in run(path, "plan")["operations"])


def test_role_and_user_with_same_name_is_config_error(pg):
    path = pg.cfg(doc("DatabaseRole", "r", name=pg.p + "dup"), doc("DatabaseUser", "u", name=pg.p + "dup"))
    with pytest.raises(config.ConfigError, match="both DatabaseRole and DatabaseUser"):
        run(path, "plan")
    assert main(["plan", "-f", str(path)]) == 12


def test_privileged_membership_is_blocked_unless_policy_allows(pg):
    p = pg.p
    pg.sql("CREATE ROLE {} NOLOGIN SUPERUSER", p + "su")
    pg.sql("CREATE ROLE {} NOLOGIN", p + "mid")
    pg.sql("GRANT {} TO {}", p + "su", p + "mid")  # transitiv: mid bringt Superuser mit
    pg.sql("CREATE ROLE {} NOLOGIN CREATEROLE", p + "cr")
    users = {"bootstrap": ["postgres"], "server_program": ["pg_execute_server_program"], "via_mid": [p + "mid"],
             "creator": [p + "cr"], "plain": []}
    docs = [doc("DatabaseUser", k, name=p + k, memberOf=v) for k, v in users.items()]
    docs.append(doc("DatabaseRole", "attr", name=p + "attr", createrole=True))

    def blocked(rep):
        return {o["id"] for o in rep["operations"] if o["action"] == "BLOCKED"}

    path = pg.cfg(*docs, scoped=False)  # mit roles-Scope wären pg_*/postgres schon außerhalb
    rep = run(path, "apply")
    assert blocked(rep) == {p + k for k in ("bootstrap", "server_program", "via_mid", "creator", "attr")}
    assert report.exit_code(rep) == 11
    assert pg.objects() == sorted(p + n for n in ("cr", "mid", "plain", "su"))  # nichts Privilegiertes angelegt

    allowed = run(path, "apply", allowPrivilegedGrants=True)
    assert blocked(allowed) == {p + "bootstrap"}  # Bootstrap-Superuser bleibt auch mit Freigabe gesperrt
    assert pg.admin.execute("SELECT count(*) FROM pg_roles WHERE rolname = %s", (p + "bootstrap",)).fetchone() == (0,)


def test_roles_of_the_admin_login_are_system(pg):
    p = pg.p
    (pg.secrets / "adm").write_text("adm-secret-1234")
    pg.sql("CREATE ROLE {} NOLOGIN", p + "grp")
    pg.sql("CREATE ROLE {} NOLOGIN", p + "outer")
    pg.sql("GRANT {} TO {}", p + "outer", p + "grp")
    pg.sql("CREATE ROLE {} LOGIN CREATEROLE PASSWORD 'adm-secret-1234'", p + "adm")
    pg.sql("GRANT {} TO {}", p + "grp", p + "adm")  # adm ist (transitiv) Mitglied von grp und outer
    pg.sql("CREATE ROLE {} NOLOGIN", p + "other")
    policy = doc("ReconciliationPolicy", "gov", targetRef="pg", mode="authoritative",
                 scope={"resourceKinds": ["DatabaseRole"]})
    path = pg.cfg(doc("Credential", "adm", providerRef="files", path="adm"), policy,
                  doc("DatabaseRole", "g", name=p + "grp", memberOf=[]), user=p + "adm", cred="adm")
    rep = run(path, "plan", allowAuthoritative=True, allowDelete=True)
    ops = {o["id"]: o["action"] for o in rep["operations"] if o["kind"] == "DatabaseRole"}
    assert ops == {p + "grp": "BLOCKED", p + "other": "DELETE"}  # outer: IGNORE (nicht im Report)
    assert report.exit_code(rep) == 0


def test_escalating_grants_need_policy(pg):
    """TRIGGER/MAINTAIN führen Code als fremde (z. B. Superuser-)Sitzung aus; CREATE kapert den search_path."""
    p = pg.p
    pg.sql("CREATE DATABASE {}", p + "db")
    grants = {"trigger": ("tables-in-schema", ["TRIGGER", "SELECT"]), "maintain": ("tables-in-schema", ["MAINTAIN"]),
              "schema": ("schema", ["CREATE"]), "database": ("database", ["CREATE"]),
              "plain": ("tables-in-schema", ["SELECT", "INSERT"])}
    for k in grants:
        pg.sql("CREATE ROLE {} NOLOGIN", p + k)
    path = pg.cfg(*[doc("Grant", k, grantee=p + k, database=p + "db", on=on, privileges=privs,
                        **({} if on == "database" else {"schema": "public"})) for k, (on, privs) in grants.items()])

    def blocked(rep):
        return {json.loads(o["id"])[0] for o in rep["operations"] if o["action"] == "BLOCKED"}

    assert blocked(run(path, "plan")) == {p + k for k in ("trigger", "maintain", "schema", "database")}
    assert blocked(run(path, "plan", allowPrivilegedGrants=True)) == set()


def test_membership_in_login_roles_or_outside_scope(pg):
    p = pg.p
    pg.sql("CREATE ROLE {} LOGIN", p + "other_login")
    pg.sql("CREATE ROLE {} NOLOGIN", p + "group")
    pg.sql("CREATE ROLE {} NOLOGIN", "oit_outside_" + p)
    try:
        path = pg.cfg(doc("DatabaseUser", "a", name=p + "a", memberOf=[p + "other_login"]),
                      doc("DatabaseUser", "b", name=p + "b", memberOf=["oit_outside_" + p]),
                      doc("DatabaseUser", "c", name=p + "c", memberOf=[p + "group"]))

        def reasons(rep):
            return {o["id"]: o.get("reason", "") for o in rep["operations"] if o["action"] == "BLOCKED"}

        assert set(reasons(run(path, "plan"))) == {p + "a", p + "b"}
        allowed = reasons(run(path, "plan", allowPrivilegedGrants=True))
        assert set(allowed) == {p + "b"} and "outside spec.scope.roles" in allowed[p + "b"]
    finally:
        pg.sql("DROP ROLE {}", "oit_outside_" + p)
