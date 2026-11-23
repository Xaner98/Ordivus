"""Integration gegen einen echten ArcadeDB-Container (ordivus-it-arcadedb, Port 12480).

Start: docker run -d --name ordivus-it-arcadedb -p 12480:2480 \
  -e JAVA_OPTS="-Darcadedb.server.rootPassword=ordivus-root-pw" arcadedata/arcadedb:latest
"""

import json
import logging
import os
import secrets

import pytest

from ordivus.adapters import arcadedb
from ordivus.adapters.arcadedb import ArcadeDBAdapter
from ordivus.adapters.base import CREATE, Op, PermanentError, Resource, Secret
from ordivus.core import config, engine
from ordivus.core.config import ConfigError
from ordivus.core.policy import OperatorPolicy

HOST = os.environ.get("ORDIVUS_TEST_HOST", "localhost")
PORT = int(os.environ.get("ORDIVUS_ARCADEDB_PORT", "12480"))
ROOT_PW = os.environ.get("ORDIVUS_ARCADEDB_ROOT_PASSWORD", "ordivus-root-pw")
TARGET = {"endpoint": {"host": HOST, "port": PORT}, "username": "root"}
BASE = f"http://{HOST}:{PORT}"
MUTATING = set(engine.MUTATING)


def root(method, path, body=None, query=None):
    return arcadedb._call(BASE, None, arcadedb._basic("root", Secret(ROOT_PW)), method, path, body, query)


def users():
    return {u["name"]: u["databases"] for u in root("GET", "/api/v1/server/users")[1]["result"]}


def databases():
    return set(root("GET", "/api/v1/databases")[1]["result"])


def can_login(name, password):
    return ArcadeDBAdapter().verify_password(None, TARGET, Resource("DatabaseUser", name), Secret(password))


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


@pytest.fixture
def p():
    """Eindeutiges Präfix je Test; räumt danach alle Objekte mit diesem Präfix ab."""
    try:
        if root("GET", "/api/v1/server", query={"mode": "basic"})[0] != 200:
            pytest.skip("ArcadeDB root login failed")
    except Exception as e:
        pytest.skip(f"ArcadeDB not reachable at {BASE}: {type(e).__name__}")
    prefix = f"it{secrets.token_hex(3)}_"
    yield prefix
    for name in users():
        if name.startswith(prefix):
            root("DELETE", "/api/v1/server/users", query={"name": name})
    for db in databases():
        if db.startswith(prefix):
            root("POST", "/api/v1/server", {"command": f"drop database {db}"})


@pytest.fixture
def cfg(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "admin").write_text(ROOT_PW)

    def write(*extra, **target):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        docs = [doc("Target", "adb", adapter="arcadedb", **TARGET, **target, authentication={"credentialRef": "admin"}),
                doc("CredentialProvider", "files", type="file", directory=str(secrets_dir)),
                doc("Credential", "admin", providerRef="files", path="admin"), *extra]
        for i, d in enumerate(docs):
            (directory / f"{i:02}.json").write_text(json.dumps(d))
        return directory

    write.secrets = secrets_dir
    return write


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def actions(rep):
    return {(o["kind"], o["id"], o["action"]) for o in rep["operations"]}


def user(name, cred, **spec):
    return [doc("Credential", cred, providerRef="files", path=cred),
            doc("DatabaseUser", name, targetRef="adb", **spec, credentials={"credentialRef": cred})]


def test_plan_apply_converge(p, cfg, caplog):
    caplog.set_level(logging.DEBUG)
    db, name, canary = f"{p}graph", f"{p}writer", f"CANARY-{secrets.token_hex(8)}"
    path = cfg(doc("Database", db, targetRef="adb"), *user(name, "pw", databases={db: ["crud", "readonly", "crud"]}))
    (cfg.secrets / "pw").write_text(canary)

    plan = run(path, "plan")
    assert {("Database", db, "CREATE"), ("DatabaseUser", name, "CREATE")} <= actions(plan)
    assert db not in databases() and name not in users()

    first = run(path, "apply")
    assert all(o["status"] == "succeeded" for o in first["operations"] if o["action"] in MUTATING), first["operations"]
    assert db in databases() and users()[name] == {db: ["crud", "readonly"]}
    assert can_login(name, canary) is True and can_login(name, "wrong-password") is False

    second = run(path, "apply")
    assert not [o for o in second["operations"] if o["action"] in MUTATING]
    for rep in (plan, first, second):
        assert canary not in json.dumps(rep) and ROOT_PW not in json.dumps(rep)
    assert canary not in caplog.text and ROOT_PW not in caplog.text


def test_update_databases(p, cfg):
    name = f"{p}u"
    path = cfg(*user(name, "pw", databases={"a": ["readonly"]}))
    run(path, "apply")
    rep = run(cfg(*user(name, "pw", databases={"b": ["crud"]})), "apply")
    assert ("DatabaseUser", name, "UPDATE") in actions(rep) and users()[name] == {"b": ["crud"]}


def test_secret_absent_created_and_usable(p, cfg):
    name = f"{p}gen"
    rep = run(cfg(*user(name, "gen")), "apply")
    assert {("Credential", "gen", "CREATE_SECRET"), ("DatabaseUser", name, "CREATE")} <= actions(rep)
    assert can_login(name, (cfg.secrets / "gen").read_text()) is True


def test_wrong_password_verify_resets(p, cfg):
    name = f"{p}pw"
    path = cfg(*user(name, "pw"))
    (cfg.secrets / "pw").write_text("the-declared-password")
    run(path, "apply")
    root("PUT", "/api/v1/server/users", {"password": "changed-elsewhere"}, {"name": name})
    assert ("DatabaseUser", name, "SET_PASSWORD") in actions(run(path, "plan"))
    assert can_login(name, "the-declared-password") is False
    rep = run(path, "apply")
    assert ("DatabaseUser", name, "SET_PASSWORD") in actions(rep)
    assert can_login(name, "the-declared-password") is True
    assert not [o for o in run(path, "apply")["operations"] if o["action"] in MUTATING]


def test_unmanaged_survives_additive(p, cfg):
    other = f"{p}other"
    root("POST", "/api/v1/server/users", {"name": other, "password": "password-123"})
    rep = run(cfg(*user(f"{p}a", "pw")), "apply", allowDelete=True)
    assert ("DatabaseUser", other, "UNMANAGED") in actions(rep) and other in users()


def test_authoritative_deletes_only_in_scope(p, cfg):
    stray_user, stray_db, outside = f"{p}stray", f"{p}straydb", f"{p[:-1]}-outside"
    root("POST", "/api/v1/server/users", {"name": stray_user, "password": "password-123"})
    root("POST", "/api/v1/server/users", {"name": outside, "password": "password-123"})
    root("POST", "/api/v1/server", {"command": f"create database {stray_db}"})
    try:
        policy = doc("ReconciliationPolicy", "gov", targetRef="adb", mode="authoritative",
                     scope={"resourceKinds": ["Database", "DatabaseUser"],
                            "Database": {"glob": [f"{p}*"]}, "DatabaseUser": {"glob": [f"{p}*", "root"]}})
        rep = run(cfg(policy, *user(f"{p}keep", "pw")), "apply", allowAuthoritative=True, allowDelete=True)
        deletes = {(k, i) for k, i, a in actions(rep) if a == "DELETE"}
        assert deletes == {("DatabaseUser", stray_user), ("Database", stray_db)}
        assert stray_user not in users() and stray_db not in databases()
        assert {"root", outside, f"{p}keep"} <= set(users())
    finally:
        root("DELETE", "/api/v1/server/users", query={"name": outside})


def test_injection_prone_names(p, cfg):
    name = f'{p}a"b {{c}}: [d],\\ e\'f'
    weird_db = p + 'x"}, "*": ["crud"]'
    path = cfg(*user(name, "pw", databases={weird_db: ["crud"]}))
    rep = run(path, "apply")
    assert ("DatabaseUser", name, "CREATE") in actions(rep)
    assert users()[name] == {weird_db: ["crud"]} and "*" not in users()[name]
    assert can_login(name, (cfg.secrets / "pw").read_text()) is None  # ':' im Namen: per Basic Auth nicht prüfbar
    assert not [o for o in run(path, "apply")["operations"] if o["action"] in MUTATING]
    with pytest.raises(ConfigError):
        engine.prepare(config.load(cfg(doc("Database", f"{p}x; drop database y", targetRef="adb"))))


def test_read_only_session_cannot_mutate(p):
    adapter, name, db = ArcadeDBAdapter(), f"{p}ro", f"{p}rodb"
    with adapter.connect(TARGET, Secret(ROOT_PW), write=False) as session:
        for op in (Op("adb", "DatabaseUser", name, CREATE, desired=Resource("DatabaseUser", name),
                      password=Secret("password-123")),
                   Op("adb", "Database", db, CREATE, desired=Resource("Database", db))):
            with pytest.raises(PermanentError):
                adapter.apply(session, op)
        with pytest.raises(PermanentError):
            adapter._request(session, "POST", "/api/v1/server/users", {"name": name, "password": "password-123"})
    assert name not in users() and db not in databases()


def test_privileged_and_out_of_scope_databases(p, cfg, tmp_path):
    """C10: '*' immer abgelehnt; Gruppe admin nur mit allowPrivilegedGrants; root nie, auch außerhalb des Scopes."""
    name = f"{p}adm"
    with pytest.raises(ConfigError, match="all databases"):
        engine.prepare(config.load(cfg(*user(name, "pw", databases={"*": ["readonly"]}))))
    path = cfg(*user(name, "pw", databases={f"{p}db": ["admin"]}))
    rep = run(path, "apply")
    op = next(o for o in rep["operations"] if o["id"] == name)
    assert op["action"] == "BLOCKED" and "allowPrivilegedGrants" in op["reason"] and name not in users()
    run(path, "apply", allowPrivilegedGrants=True)
    assert users()[name] == {f"{p}db": ["admin"]}

    scoped = {"databases": {"include": [f"{p}*"]}, "users": {"include": [f"{p}*"]}}
    adapter = ArcadeDBAdapter()
    errors = adapter.validate_target({**TARGET, "scope": scoped},
                                     [Resource("DatabaseUser", name, {"databases": {"other": ["readonly"]}})])
    assert errors and "outside spec.scope.databases" in errors[0]
    before = users()["root"]
    with adapter.connect({**TARGET, "scope": scoped}, Secret(ROOT_PW), write=True) as session:
        assert "root" not in {r.id for r in adapter.discover(session, "DatabaseUser", scoped).resources}
        root_user = Resource("DatabaseUser", "root", {"databases": {f"{p}db": ["readonly"]}})
        assert "protected" in adapter.check(session, root_user, allow_privileged=True)
        with pytest.raises(PermanentError, match="protected"):
            adapter.apply(session, Op("adb", "DatabaseUser", "root", CREATE, desired=root_user,
                                      password=Secret(ROOT_PW)))
    assert users()["root"] == before
    assert adapter.validate({"kind": "Target", "metadata": {"name": "t"},
                             "spec": {"endpoint": {"host": "evil@host/x"}}})


def test_update_keeps_out_of_scope_and_wildcard_access(p, cfg):
    """Regression: PUT ersetzt die ganze Zuordnung; Einträge außerhalb des Scopes und '*' bleiben erhalten."""
    name, inside = f"{p}scoped", f"{p}in"
    granted = {inside: ["readonly"], "elsewhere": ["crud"], "*": ["readonly"]}
    root("POST", "/api/v1/server/users", {"name": name, "password": "password-123", "databases": granted})
    scoped = {"databases": {"include": [f"{p}*"]}, "users": {"include": [f"{p}*"]}}
    adapter = ArcadeDBAdapter()
    with adapter.connect({**TARGET, "scope": scoped}, Secret(ROOT_PW), write=False) as session:
        observed = {r.id: r for r in adapter.discover(session, "DatabaseUser", scoped).resources}
    assert observed[name].attrs == {"databases": {inside: ["readonly"]}}

    path = cfg(*user(name, "pw", databases={inside: ["crud"]}))
    target = json.loads((path / "00.json").read_text())
    target["spec"]["scope"] = scoped
    (path / "00.json").write_text(json.dumps(target))
    rep = run(path, "apply")
    assert ("DatabaseUser", name, "UPDATE") in actions(rep)
    assert users()[name] == {inside: ["crud"], "elsewhere": ["crud"], "*": ["readonly"]}
    assert not [o for o in run(path, "apply")["operations"] if o["action"] in MUTATING]


def test_server_version(p):
    adapter = ArcadeDBAdapter()
    with adapter.connect(TARGET, Secret(ROOT_PW), write=False) as session:
        assert adapter.server_version(session).startswith("ArcadeDB 26.")
    assert arcadedb._version({"version": "26.12.1-SNAPSHOT (build x)"}) == ("26.12.1-SNAPSHOT", (26, 12, 1))
    assert arcadedb._version({"version": "26.2.1 (build x)"})[1] < arcadedb.MIN_VERSION
    with pytest.raises(PermanentError, match="version"):
        arcadedb._version({"version": "unknown"})


def test_export_roundtrip(p, cfg, tmp_path):
    from roundtrip import assert_export_roundtrip

    db, name = f"{p}graph", f"{p}writer"
    run(cfg(doc("Database", db, targetRef="adb"), *user(name, "pw", databases={db: ["crud", "readonly"]})), "apply")
    root("POST", "/api/v1/server/users", {"name": f"{p}grown", "password": secrets.token_hex(8),
                                          "databases": {db: ["readonly"]}})
    scope = {"databases": {"include": [p + "*"]}, "users": {"include": [p + "*"]}}
    assert_export_roundtrip(cfg(scope=scope), {("Database", db), ("DatabaseUser", name), ("DatabaseUser", f"{p}grown")},
                            tmp_path)
