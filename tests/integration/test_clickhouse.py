"""Integration gegen einen echten ClickHouse-Container (ordivus-it-clickhouse, Port 18123).

Der Container läuft mit CLICKHOUSE_USER=admin aus der Konfigurationsdatei (users_xml). Die Tests legen
per SQL einen eigenen Admin `oit_admin` an und verbinden den Adapter als dieser Benutzer; so ist
`admin` ein fremder users.xml-Benutzer (manageable: false). Alle Testobjekte beginnen mit `oit`.
"""

import json
import logging
import os
import secrets

import pytest

from ordivus import adapters
from ordivus.adapters import clickhouse as ch_module
from ordivus.adapters.base import CREATE_SECRET, DELETE, Op, PermanentError, Resource, Secret, TransientError
from ordivus.adapters.clickhouse import ClickHouseAdapter, _post, _session, grant_id, qi, qs
from ordivus.core import config, engine
from ordivus.core.engine import MUTATING
from ordivus.core.policy import OperatorPolicy

HOST = os.environ.get("ORDIVUS_TEST_HOST", "localhost")
PORT = int(os.environ.get("ORDIVUS_TEST_CLICKHOUSE_PORT", "18123"))
ROOT = ("admin", os.environ.get("ORDIVUS_TEST_CLICKHOUSE_PASSWORD", "adminpw-it"))
ADMIN, ADMIN_PW = "oit_admin", "oit-admin-pw-7f3a"
ENDPOINT = {"host": HOST, "port": PORT, "user": ADMIN, "timeoutSeconds": 10}
CH = ClickHouseAdapter()


def root(sql, secret=False):
    target = {"endpoint": {"host": HOST, "port": PORT, "timeoutSeconds": 10}}
    return _post(_session(target, ROOT[0], Secret(ROOT[1]), True), sql, secret)


def names(table):
    return {r["name"] for r in root(f"SELECT name FROM system.{table} WHERE startsWith(name, 'oit') FORMAT JSON")}


def cleanup():
    for table, noun in (("users", "USER"), ("roles", "ROLE"), ("databases", "DATABASE")):
        for name in names(table):
            root(f"DROP {noun} IF EXISTS {qi(name)}")


def snapshot():
    return [root(f"SELECT * FROM system.{t} ORDER BY ALL FORMAT JSON")
            for t in ("users", "roles", "role_grants", "grants", "databases")]


def can_login(user, password):
    return CH.verify_password(None, {"endpoint": ENDPOINT}, Resource("DatabaseUser", user), Secret(password))


@pytest.fixture(autouse=True)
def clickhouse():
    try:
        root("SELECT 1 AS ok FORMAT JSON")
    except (TransientError, PermanentError) as e:
        pytest.skip(f"ClickHouse not reachable at {HOST}:{PORT}: {e}")
    adapters.register(ClickHouseAdapter)
    cleanup()
    root(f"CREATE USER {ADMIN} IDENTIFIED WITH sha256_password BY {qs(ADMIN_PW)}", secret=True)
    root(f"GRANT CURRENT GRANTS ON *.* TO {ADMIN} WITH GRANT OPTION")
    yield
    cleanup()


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


def res(kind, name, **spec):
    return doc(kind, name, targetRef="ch", **spec)


def cred(name):
    return doc("Credential", name, providerRef="files", path=name)


def user(name, password=None, policy="verify", **spec):
    creds = {"credentials": {"credentialRef": f"pw-{name}", "passwordPolicy": policy}} if password else {}
    return res("DatabaseUser", name, **spec, **creds)


@pytest.fixture
def cfg(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "admin").write_text(ADMIN_PW)

    def write(*extra, secrets=None, scope=None):
        for name, value in (secrets or {}).items():
            (secrets_dir / f"pw-{name}").write_text(value)
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        docs = [doc("Target", "ch", adapter="clickhouse", endpoint=ENDPOINT, authentication={"credentialRef": "admin"},
                    **({"scope": scope} if scope else {})),
                doc("CredentialProvider", "files", type="file", directory=str(secrets_dir)), cred("admin")]
        docs += [cred(d["spec"]["credentials"]["credentialRef"]) for d in extra if "credentials" in d["spec"]]
        for i, d in enumerate(docs + list(extra)):
            (directory / f"{i:02}.json").write_text(json.dumps(d))
        return directory

    write.secrets = secrets_dir
    return write


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def acts(rep):
    return {(o["kind"], o["id"]): o["action"] for o in rep["operations"]}


def mutating(rep):
    return [o for o in rep["operations"] if o["action"] in MUTATING]


def authoritative(**scope):
    return doc("ReconciliationPolicy", "gov", targetRef="ch", mode="authoritative", scope=scope)


BASIC = [res("Database", "oit_db"), res("DatabaseRole", "oit_role"),
         user("oit_user", roles=["oit_role"], defaultRoles=["oit_role"], hostIp=["10.0.0.0/8", "::/0"]),
         res("Grant", "g1", grantee="oit_role", database="oit_db", privileges=["select", "insert"])]


def test_plan_apply_converge(cfg):
    path = cfg(*BASIC)
    before = snapshot()
    plan = run(path, "plan")
    assert snapshot() == before
    grant = grant_id("oit_role", "oit_db", None)
    expected = {("Database", "oit_db"), ("DatabaseRole", "oit_role"), ("DatabaseUser", "oit_user"), ("Grant", grant)}
    assert {k for k, a in acts(plan).items() if a == "CREATE"} == expected
    first = run(path, "apply")
    assert [o for o in mutating(first) if o["status"] != "succeeded"] == []
    assert {(o["kind"], o["id"]) for o in mutating(first)} == expected
    assert root("SHOW GRANTS FOR oit_role FORMAT JSON")[0]["GRANTS FOR oit_role FORMAT JSON"] == \
        "GRANT SELECT, INSERT ON oit_db.* TO oit_role"
    second = run(path, "apply")
    assert mutating(second) == [] and second["targets"][0]["status"] == "in_sync"


def test_update_roles_hosts_and_privileges(cfg):
    run(cfg(*BASIC), "apply")
    root("CREATE ROLE oit_role2")
    path = cfg(res("DatabaseRole", "oit_role"), user("oit_user", roles=["oit_role2"], hostIp=["10.0.0.0/8"]),
               res("Grant", "g1", grantee="oit_role", database="oit_db", privileges=["SELECT", "SHOW TABLES"]))
    rep = run(path, "apply")
    assert {o["action"] for o in mutating(rep)} == {"UPDATE"} and all(o["status"] == "succeeded" for o in mutating(rep))
    assert mutating(run(path, "apply")) == []


def test_unmanaged_survives_additive(cfg):
    root("CREATE USER oit_extra")
    rep = run(cfg(res("Database", "oit_db")), "apply", allowDelete=True)
    assert acts(rep)[("DatabaseUser", "oit_extra")] == "UNMANAGED"
    assert "oit_extra" in names("users")


def test_authoritative_deletes_only_in_scope(cfg):
    for sql in ("CREATE USER oit_x1", "CREATE USER oit_keep", "CREATE ROLE oit_rx", "CREATE DATABASE oit_dbx",
                "GRANT SELECT ON oit_dbx.* TO oit_keep"):
        root(sql)
    policy = authoritative(resourceKinds=["DatabaseUser", "DatabaseRole"], DatabaseUser={"glob": ["oit_x*"]})
    rep = run(cfg(policy), "apply", allowAuthoritative=True, allowDelete=True)
    assert {(o["kind"], o["id"]) for o in mutating(rep)} == {("DatabaseUser", "oit_x1"), ("DatabaseRole", "oit_rx")}
    assert all(o["status"] == "succeeded" for o in mutating(rep))
    assert names("users") == {"oit_keep", ADMIN} and names("roles") == set() and names("databases") == {"oit_dbx"}
    # alles, was der Adapter schützt, bleibt: Systemdatenbanken, Verbindungsbenutzer, users.xml-Benutzer
    full = authoritative(resourceKinds=list(CH.kinds))
    rep = run(cfg(full), "apply", allowAuthoritative=True, allowDelete=True)
    deleted = {(o["kind"], o["id"]) for o in rep["operations"] if o["action"] == DELETE}
    assert ("DatabaseUser", "oit_keep") in deleted and ("Database", "oit_dbx") in deleted
    assert not any(i in ("admin", ADMIN, "system", "default", "information_schema") for _, i in deleted)
    assert names("users") == {ADMIN}
    assert "admin" in {r["name"] for r in root("SELECT name FROM system.users FORMAT JSON")}
    assert {r["name"] for r in root("SELECT name FROM system.databases FORMAT JSON")} >= {"system", "default"}


def test_config_file_user_is_not_manageable(cfg):
    with CH.connect({"endpoint": ENDPOINT}, Secret(ADMIN_PW), write=False) as s:
        found = {r.id: r for r in CH.discover(s, "DatabaseUser", None).resources}
    assert found["admin"].manageable is False and found["admin"].system is False
    assert found[ADMIN].system is True  # Selbstschutz
    assert acts(run(cfg(), "plan"))[("DatabaseUser", "admin")] == "UNMANAGED"
    rep = run(cfg(authoritative(resourceKinds=["DatabaseUser", "Grant"])), "apply",
              allowAuthoritative=True, allowDelete=True)
    assert acts(rep)[("DatabaseUser", "admin")] == "UNDESIRABLE" and mutating(rep) == []
    assert "admin" in {r["name"] for r in root("SELECT name FROM system.users FORMAT JSON")}
    op = next(o for o in run(cfg(user("admin")), "plan")["operations"] if o["id"] == "admin")
    assert op["action"] == "BLOCKED" and op["reason"] == "not manageable by adapter"
    assert op["manageable"] is False and "sqlManaged" not in op["changes"]  # Engine sperrt, kein Hilfsfeld


def test_identifier_injection_is_quoted(cfg):
    evil = ["oit_a`b", "oit_q'uote", "oit_x; DROP USER admin; --", "oit_sp ace", "oit_ünï€", "oit_back\\slash`'"]
    docs = [d for i, n in enumerate(evil) for d in (
        res("Database", n), res("DatabaseRole", n + "_r"), user(n, roles=[n + "_r"], hostNames=[n + ".example"]),
        res("Grant", f"g{i}", grantee=n + "_r", database=n, table=n, privileges=["SELECT"]))]
    path = cfg(*docs)
    first = run(path, "apply")
    assert len(mutating(first)) == 4 * len(evil) and all(o["status"] == "succeeded" for o in mutating(first)), \
        json.dumps([o for o in mutating(first) if o["status"] != "succeeded"])
    assert names("users") == {ADMIN, *evil} and names("databases") == set(evil)
    assert "admin" in {r["name"] for r in root("SELECT name FROM system.users FORMAT JSON")}
    assert mutating(run(path, "apply")) == []


def test_password_created_via_file_provider(cfg):
    path = cfg(user("oit_pw", password=True))
    rep = run(path, "apply")
    assert [(o["kind"], o["action"], o["status"]) for o in mutating(rep)] == [
        ("Credential", CREATE_SECRET, "succeeded"), ("DatabaseUser", "CREATE", "succeeded")]
    password = (cfg.secrets / "pw-oit_pw").read_text()
    assert len(password) == 32 and can_login("oit_pw", password) is True
    assert can_login("oit_pw", password + "x") is False
    assert mutating(run(path, "apply")) == []


def test_wrong_password_is_reset_with_verify(cfg):
    root("CREATE USER oit_pw IDENTIFIED WITH sha256_password BY 'old-password'", secret=True)
    path = cfg(user("oit_pw", password=True), secrets={"oit_pw": "new-password-0123456789"})
    plan = run(path, "plan")
    assert [o["action"] for o in mutating(plan)] == ["SET_PASSWORD"]
    rep = run(path, "apply")
    assert [(o["action"], o["status"]) for o in mutating(rep)] == [("SET_PASSWORD", "succeeded")]
    assert can_login("oit_pw", "new-password-0123456789") is True and can_login("oit_pw", "old-password") is False
    assert mutating(run(path, "apply")) == []


@pytest.mark.parametrize("mode", ["plan", "drift"])
def test_plan_and_drift_cannot_mutate(cfg, mode):
    root("CREATE USER oit_x1 IDENTIFIED WITH sha256_password BY 'old-password'", secret=True)
    root("CREATE DATABASE oit_dbx")
    root("CREATE USER oit_gone")
    path = cfg(*BASIC, user("oit_x1", password=True, roles=["oit_role"]), res("Database", "oit_dbx", engine="Memory"),
               user("oit_new", password=True), authoritative(resourceKinds=["DatabaseUser"]),
               secrets={"oit_x1": "new-password-0123456789"})
    before = snapshot()
    rep = run(path, mode, allowAuthoritative=True, allowDelete=True)
    assert {"CREATE_SECRET", "CREATE", "UPDATE", "SET_PASSWORD", "DELETE"} <= {o["action"] for o in rep["operations"]}
    assert snapshot() == before and not (cfg.secrets / "pw-oit_new").exists()
    # auch direkt: eine Read-only-Session kann nicht schreiben (readonly=2 und apply verweigert)
    with CH.connect({"endpoint": ENDPOINT}, Secret(ADMIN_PW), write=False) as s:
        with pytest.raises(PermanentError, match="read-only session"):
            CH.apply(s, Op("ch", "Database", "oit_ro", "CREATE", desired=Resource("Database", "oit_ro")))
        for sql in ("CREATE DATABASE oit_ro", "CREATE USER oit_ro", "GRANT SELECT ON *.* TO oit_x1",
                    "ALTER USER oit_x1 IDENTIFIED WITH sha256_password BY 'x'", "SET DEFAULT ROLE NONE TO oit_x1"):
            with pytest.raises(PermanentError) as e:
                _post(s, sql)
            assert e.value.code == 164  # READONLY
    assert snapshot() == before


def test_secret_canary_never_in_output(cfg, caplog, capsys):
    canary = "CANARY-" + secrets.token_hex(8)
    root("CREATE USER oit_pw IDENTIFIED WITH sha256_password BY 'old-password'", secret=True)
    path = cfg(user("oit_pw", password=True), user("oit_bad", password=True, roles=["oit_missing_role"]),
               secrets={"oit_pw": canary, "oit_bad": canary})
    caplog.set_level(logging.DEBUG)
    reports = [run(path, "plan"), run(path, "apply"), run(path, "drift")]
    assert acts(reports[1])[("DatabaseUser", "oit_bad")] == "CREATE"
    assert next(o for o in reports[1]["operations"] if o["id"] == "oit_bad")["status"] == "failed"
    out = capsys.readouterr()
    text = json.dumps(reports) + caplog.text + out.out + out.err
    assert canary not in text and ADMIN_PW not in text
    # ClickHouse maskiert Passwörter im query_log, außer ein Statement scheitert schon am Parser
    root("SYSTEM FLUSH LOGS")
    leaked = root(f"SELECT count() AS n FROM system.query_log WHERE position(query, {qs(canary)}) > 0 "
                  "AND query_kind != 'Select' FORMAT JSON")
    assert leaked[0]["n"] in (0, "0")


def test_validate_rejects_unsafe_values():
    v = CH.validate
    assert v({"kind": "DatabaseUser", "spec": {"hostIp": ["10.0.0.0/8", "2001:db8::1"]}}) == []
    assert v({"kind": "DatabaseUser", "spec": {"hostIp": ["not-an-ip"]}})
    assert v({"kind": "DatabaseUser", "spec": {"hostIp": ["127.0.0.1"]}})  # ClickHouse: HOST LOCAL
    assert v({"kind": "Database", "spec": {"engine": "Memory; DROP DATABASE x"}})
    for p in ("ALL", "SELECT; DROP USER admin", "SELECT(x)", "all privileges", "CURRENT GRANTS", "current  grants",
              "NONE", "USAGE", "no privileges"):
        assert v({"kind": "Grant", "spec": {"grantee": "r", "privileges": [p]}}), p
    for db in ("system", "information_schema", "INFORMATION_SCHEMA"):  # dort unsichtbar für scoped Discovery
        assert v({"kind": "Grant", "spec": {"grantee": "r", "database": db, "privileges": ["SELECT"]}}), db
    for host in ("evil.example/x", "user@evil.example", "h?x", "h#x", "h x"):
        assert v({"kind": "Target", "spec": {"endpoint": {"host": host}}}), host
    assert v({"kind": "Grant", "spec": {"grantee": "r", "table": "t", "privileges": ["SELECT"]}})
    assert v({"kind": "Target", "spec": {"endpoint": {"host": "h", "user": "a:b"}}})


def test_unreachable_and_bad_credentials_are_target_errors(cfg):
    (cfg.secrets / "admin").write_text("wrong")
    rep = run(cfg(), "plan")
    assert rep["targets"][0]["status"] == "error" and "AuthorizationError" in rep["targets"][0]["reason"]
    target = {"endpoint": {"host": HOST, "port": 1}}
    with pytest.raises(TransientError), CH.connect(target, None, write=False):
        pass


def blocked(rep):
    return {o["id"]: o["reason"] for o in rep["operations"] if o["action"] == "BLOCKED"}


def grants_of(name):
    return [next(iter(r.values())) for r in root(f"SHOW GRANTS FOR {qi(name)} FORMAT JSON")]


def test_privileged_grants_need_operator_policy(cfg):
    """C6: Admin-, System-, Quellen- und Geheimnisrechte (auch Aliase/Unterrechte) nur mit allowPrivilegedGrants."""
    privileged = [["ACCESS MANAGEMENT"], ["CREATE USER"], ["ROLE ADMIN"], ["SHUTDOWN"], ["SYSTEM FLUSH LOGS"],
                  ["FILE"], ["S3"], ["URL"], ["SOURCES"], ["INTROSPECTION FUNCTIONS"],
                  ["displaySecretsInShowAndSelect"],
                  ["KILL QUERY"], ["SHOW NAMED COLLECTIONS SECRETS"], ["SELECT"]]  # SELECT: global *.* ist privilegiert
    for i in range(len(privileged)):
        root(f"CREATE ROLE oit_r{i}")
    root("CREATE ROLE oit_ok")
    docs = [res("Grant", f"g{i}", grantee=f"oit_r{i}", privileges=p) for i, p in enumerate(privileged)]
    docs += [res("Database", "oit_db"), res("Grant", "ok", grantee="oit_ok", database="oit_db", privileges=["SELECT"]),
             res("Grant", "unknown", grantee="oit_ok", privileges=["NO SUCH PRIV"])]
    path = cfg(*docs)
    rep = run(path, "apply")
    reasons = blocked(rep)
    unknown = grant_id("oit_ok", None, None)
    assert set(reasons) == {grant_id(f"oit_r{i}", None, None) for i in range(len(privileged))} | {unknown}
    assert reasons[unknown].startswith("unknown privilege")
    assert all("allowPrivilegedGrants" in r for k, r in reasons.items() if k != unknown), reasons
    assert engine_exit(rep) == 11
    assert grants_of("oit_ok") == ["GRANT SELECT ON oit_db.* TO oit_ok"]
    assert all(grants_of(f"oit_r{i}") == [] for i in range(len(privileged)))
    allowed = cfg(res("Grant", "g11", grantee="oit_r11", privileges=["KILL QUERY"]),
                  res("Grant", "g10", grantee="oit_r10", privileges=["displaySecretsInShowAndSelect"]), docs[-1])
    rep = run(allowed, "apply", allowPrivilegedGrants=True)
    assert list(blocked(rep)) == [unknown]  # unbekannt bleibt gesperrt
    assert [o["status"] for o in mutating(rep)] == ["succeeded", "succeeded"]
    assert grants_of("oit_r10") == ["GRANT displaySecretsInShowAndSelect ON *.* TO oit_r10"]
    assert grants_of("oit_r11") == ["GRANT KILL QUERY ON *.* TO oit_r11"]


def engine_exit(rep):
    from ordivus.core import report
    return report.exit_code(rep)


def test_current_grants_config_is_rejected(cfg):
    with pytest.raises(config.ConfigError, match="CURRENT GRANTS"):
        run(cfg(res("Grant", "g", grantee="oit_r", privileges=["CURRENT GRANTS"])), "plan")


def test_roles_with_privileged_grants_need_operator_policy(cfg):
    root("CREATE ROLE oit_power")
    root("GRANT ACCESS MANAGEMENT ON *.* TO oit_power")
    root("CREATE ROLE oit_plain")
    root("GRANT oit_power TO oit_plain")  # transitiv
    path = cfg(user("oit_u", roles=["oit_plain"]))
    assert "allowPrivilegedGrants" in blocked(run(path, "apply"))["oit_u"]
    assert "oit_u" not in names("users")
    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert blocked(rep) == {} and "oit_u" in names("users")


def test_roles_with_system_database_grants_are_strong(cfg):
    root("CREATE ROLE oit_sys")
    root("GRANT SELECT ON system.* TO oit_sys")  # system.users, system.grants … lesbar
    root("CREATE ROLE oit_info")
    root("GRANT SELECT ON INFORMATION_SCHEMA.* TO oit_info")
    path = cfg(user("oit_u1", roles=["oit_sys"]), user("oit_u2", roles=["oit_info"]))
    assert set(blocked(run(path, "plan"))) == {"oit_u1", "oit_u2"}
    assert blocked(run(path, "plan", allowPrivilegedGrants=True)) == {}


def test_scope_limits_grants_and_databases(cfg):
    """C7: Grants/Datenbanken außerhalb scope.databases und globale Grants mit Scope werden gesperrt."""
    root("CREATE ROLE oit_r")
    path = cfg(res("Database", "other_db"), res("Grant", "out", grantee="oit_r", database="other_db",
                                                 privileges=["SELECT"]),
               res("Grant", "glob", grantee="oit_r", privileges=["SELECT"]),
               res("Grant", "in", grantee="oit_r", database="oit_db", privileges=["SELECT"]), res("Database", "oit_db"),
               scope={"databases": {"include": ["oit_*"]}})
    rep = run(path, "apply", allowPrivilegedGrants=True)
    assert set(blocked(rep)) == {"other_db", grant_id("oit_r", "other_db", None), grant_id("oit_r", None, None)}
    assert all("outside spec.scope.databases" in r for r in blocked(rep).values())
    assert grants_of("oit_r") == ["GRANT SELECT ON oit_db.* TO oit_r"]
    assert "other_db" not in {r["name"] for r in root("SELECT name FROM system.databases FORMAT JSON")}
    # zweite Sperre im Adapter: apply verweigert auch ohne Engine
    with CH.connect({"endpoint": ENDPOINT, "scope": {"databases": {"include": ["oit_*"]}}}, Secret(ADMIN_PW),
                    write=True) as s:
        g = CH.desired(doc("Grant", "x", grantee="oit_r", privileges=["SELECT"], database="other_db"))
        with pytest.raises(PermanentError, match="outside"):
            CH.apply(s, Op("ch", "Grant", g.id, "CREATE", desired=g))


def test_admin_roles_are_protected(cfg):
    """L4: Rollen des Verbindungsbenutzers (transitiv) werden nie entzogen, gelöscht oder geändert."""
    root("CREATE DATABASE oit_db")
    for sql in ("CREATE ROLE oit_adm1", "CREATE ROLE oit_adm2", "GRANT oit_adm2 TO oit_adm1",
                f"GRANT oit_adm1 TO {ADMIN}", "GRANT SELECT ON oit_db.* TO oit_adm2"):
        root(sql)
    rep = run(cfg(authoritative(resourceKinds=list(CH.kinds))), "apply", allowAuthoritative=True, allowDelete=True)
    assert not [o for o in rep["operations"] if o["action"] == DELETE and "oit_adm" in o["id"]]
    assert names("roles") >= {"oit_adm1", "oit_adm2"} and grants_of("oit_adm2") == [
        "GRANT SELECT ON oit_db.* TO oit_adm2"]
    rep = run(cfg(res("Grant", "g", grantee="oit_adm2", database="oit_db", privileges=["INSERT"])), "apply",
              allowPrivilegedGrants=True)
    assert "protected" in blocked(rep)[grant_id("oit_adm2", "oit_db", None)]


def test_server_version_and_minimum(cfg, monkeypatch):
    with CH.connect({"endpoint": ENDPOINT}, Secret(ADMIN_PW), write=False) as s:
        assert CH.server_version(s).startswith("ClickHouse 25.")
    assert run(cfg(), "plan")["targets"][0]["serverVersion"].startswith("ClickHouse ")
    monkeypatch.setattr(ch_module, "MIN_VERSION", (99, 0))
    with pytest.raises(PermanentError, match=r"is not supported \(minimum 99.0\)"), \
            CH.connect({"endpoint": ENDPOINT}, Secret(ADMIN_PW), write=False):
        pass


def test_privilege_aliases_and_groups_are_blocked(cfg):
    """ClickHouse speichert UPDATE als ALTER UPDATE und fasst Gruppen zusammen: sonst ewige Drift bzw. ein
    REVOKE ALTER UPDATE nach GRANT UPDATE, das das Recht entzieht."""
    root("CREATE DATABASE oit_db")
    for i in range(3):
        root(f"CREATE ROLE oit_r{i}")
    root("GRANT ALTER UPDATE ON oit_db.* TO oit_r0")
    index = [r["privilege"] for r in root("SELECT privilege FROM system.privileges "
                                          "WHERE parent_group = 'ALTER INDEX' FORMAT JSON")]
    path = cfg(res("Grant", "a", grantee="oit_r0", database="oit_db", privileges=["update", "select"]),
               res("Grant", "b", grantee="oit_r1", database="oit_db", privileges=["ALTER", "ALTER UPDATE"]),
               res("Grant", "c", grantee="oit_r2", database="oit_db", privileges=index))
    reasons = blocked(run(path, "apply"))
    assert "UPDATE (= ALTER UPDATE)" in reasons[grant_id("oit_r0", "oit_db", None)]
    assert "ALTER UPDATE (in ALTER)" in reasons[grant_id("oit_r1", "oit_db", None)]
    assert "declare ALTER INDEX instead" in reasons[grant_id("oit_r2", "oit_db", None)]
    assert grants_of("oit_r0") == ["GRANT ALTER UPDATE ON oit_db.* TO oit_r0"]
    # Gruppe → Unterrecht: erst REVOKE, dann GRANT, sonst nähme das REVOKE ALTER das neue Recht mit
    root("GRANT ALTER ON oit_db.* TO oit_r1")
    path = cfg(res("Grant", "b", grantee="oit_r1", database="oit_db", privileges=["ALTER UPDATE"]))
    assert [o["status"] for o in mutating(run(path, "apply"))] == ["succeeded"]
    assert grants_of("oit_r1") == ["GRANT ALTER UPDATE ON oit_db.* TO oit_r1"]
    assert mutating(run(path, "apply")) == []


def test_grant_covered_by_broader_grant_is_blocked(cfg):
    root("CREATE DATABASE oit_db")
    root("CREATE ROLE oit_r")
    root("GRANT SELECT ON oit_db.* TO oit_r")
    root("CREATE ROLE oit_p")
    root("GRANT SELECT ON *.* TO oit_p")
    root("REVOKE SELECT ON oit_db.* FROM oit_p")  # Teil-Revoke: der engere Grant ist wieder sichtbar
    path = cfg(res("Grant", "t", grantee="oit_r", database="oit_db", table="t", privileges=["SELECT", "INSERT"]),
               res("Grant", "p", grantee="oit_p", database="oit_db", table="t", privileges=["SELECT"]))
    rep = run(path, "apply")
    assert "SELECT already granted to 'oit_r' on a broader object" in blocked(rep)[grant_id("oit_r", "oit_db", "t")]
    assert [(o["id"], o["status"]) for o in mutating(rep)] == [(grant_id("oit_p", "oit_db", "t"), "succeeded")]
    assert grants_of("oit_r") == ["GRANT SELECT ON oit_db.* TO oit_r"]
    assert mutating(run(path, "apply")) == []


def test_readonly_profile_login_can_plan(cfg):
    """Ein Login mit readonly=1 im Profil lehnt jedes Setzen von readonly ab (Code 164)."""
    root("CREATE SETTINGS PROFILE OR REPLACE oit_prof SETTINGS readonly = 1")
    try:
        root("CREATE USER oit_ro IDENTIFIED WITH sha256_password BY 'oit-ro-pw-123' SETTINGS PROFILE 'oit_prof'",
             secret=True)
        root("GRANT SHOW USERS, SHOW ROLES ON *.* TO oit_ro")
        root("GRANT SELECT ON system.* TO oit_ro")
        with CH.connect({"endpoint": {**ENDPOINT, "user": "oit_ro"}}, Secret("oit-ro-pw-123"), write=False) as s:
            assert s.guard is False
            assert {CH.discover(s, k, None).status for k in CH.kinds} == {"complete"}
        assert can_login("oit_ro", "oit-ro-pw-123") is True
        with CH.connect({"endpoint": ENDPOINT}, Secret(ADMIN_PW), write=False) as s:
            assert s.guard is True  # normaler Login: readonly=2 wird weiter gesendet
    finally:
        root("DROP USER IF EXISTS oit_ro")
        root("DROP SETTINGS PROFILE IF EXISTS oit_prof")


def test_host_ip_is_normalized(cfg):
    path = cfg(user("oit_u", hostIp=["10.0.0.1/8", "10.9.0.2/32", "2001:DB8::1/64", "10.0.0.0/8"]))
    assert [o["status"] for o in mutating(run(path, "apply"))] == ["succeeded"]
    assert sorted(root("SELECT host_ip FROM system.users WHERE name = 'oit_u' FORMAT JSON")[0]["host_ip"]) == \
        ["10.0.0.0/8", "10.9.0.2", "2001:db8::/64"]
    assert mutating(run(path, "apply")) == []
    assert CH.validate({"kind": "DatabaseUser", "spec": {"hostIp": ["::ffff:127.0.0.1"]}})  # wird HOST LOCAL


def test_set_password_refuses_multiple_auth_methods(cfg):
    """ALTER USER … IDENTIFIED ersetzt alle Authentifizierungsmethoden; Ordivus verweigert das."""
    root("CREATE USER oit_pw IDENTIFIED WITH sha256_password BY 'old-a-123', plaintext_password BY 'old-b-123'",
         secret=True)
    path = cfg(user("oit_pw", password=True), secrets={"oit_pw": "new-password-0123456789"})
    op = mutating(run(path, "apply"))[0]
    assert (op["action"], op["status"]) == ("SET_PASSWORD", "failed")
    assert can_login("oit_pw", "old-a-123") is True and can_login("oit_pw", "old-b-123") is True


def test_export_roundtrip(cfg, tmp_path):
    from roundtrip import assert_export_roundtrip

    assert mutating(run(cfg(*BASIC), "apply"))
    root("CREATE USER oit_grown IDENTIFIED WITH no_password HOST NAME 'app.example.org', IP '192.168.1.1'")
    root("GRANT oit_role TO oit_grown")
    root("CREATE TABLE oit_db.t (id UInt8) ENGINE = Memory")
    root("GRANT SELECT ON oit_db.t TO oit_grown")
    assert_export_roundtrip(cfg(scope={"databases": {"include": ["oit_*"]}}), {
        ("Database", "oit_db"), ("DatabaseRole", "oit_role"), ("DatabaseUser", "oit_user"),
        ("DatabaseUser", "oit_grown"), ("Grant", grant_id("oit_role", "oit_db", None)),
        ("Grant", grant_id("oit_grown", "oit_db", "t"))}, tmp_path)
