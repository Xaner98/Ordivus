"""Integration tests for the MongoDB adapter against container `ordivus-it-mongodb` (port 17017,
root/ordivus-root, see scripts/test-containers.sh)."""

import json
import os

import pytest

pymongo = pytest.importorskip("pymongo")

from ordivus import adapters  # noqa: E402
from ordivus.adapters.base import CREATE, Op, PermanentError, Resource, Secret  # noqa: E402
from ordivus.adapters.mongodb import MongoDBAdapter  # noqa: E402
from ordivus.core import config, engine, report  # noqa: E402
from ordivus.core.policy import OperatorPolicy  # noqa: E402

HOST, PORT, ADMIN_PW = os.environ.get("ORDIVUS_TEST_HOST", "localhost"), 17017, "ordivus-root"
APP, OTHER = "it_app", "it_other"
CANARY = "canary-Mq7vX2pL9tZw4sB1"
TARGET = {"endpoint": {"host": HOST, "port": PORT, "user": "root", "authDatabase": "admin"},
          "scope": {"databases": {"include": ["it_*"]}}}
MUTATING = set(engine.MUTATING)


def client(user="root", password=ADMIN_PW, db="admin"):
    return pymongo.MongoClient(HOST, PORT, username=user, password=password, authSource=db, directConnection=True,
                               serverSelectionTimeoutMS=3000)


def can_login(user, password, db=APP):
    c = client(user, password, db)
    try:
        c.admin.command("ping")
        return True
    except pymongo.errors.OperationFailure:
        return False
    finally:
        c.close()


@pytest.fixture(autouse=True)
def mongo():
    c = client()
    try:
        c.admin.command("ping")
    except pymongo.errors.PyMongoError:
        pytest.skip(f"MongoDB not reachable at {HOST}:{PORT}")
    adapters.register(MongoDBAdapter)

    def clean():
        for db in (APP, OTHER):
            c[db].command("dropAllUsersFromDatabase")
            c[db].command("dropAllRolesFromDatabase")
        for u in c.admin.command("usersInfo")["users"]:
            if u["user"].startswith("it_"):
                c.admin.command("dropUser", u["user"])
        for r in c.admin.command("rolesInfo", 1)["roles"]:
            if r["role"].startswith("it_"):
                c.admin.command("dropRole", r["role"])
    clean()
    yield c
    clean()
    c.close()


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


def user(name, db=APP, **spec):
    return doc("DatabaseUser", name, targetRef="m", database=db, **spec)


def role(name, db=APP, **spec):
    return doc("DatabaseRole", name, targetRef="m", database=db, **spec)


def creds(policy="verify", ref="pw"):
    return {"credentialRef": ref, "passwordPolicy": policy}


@pytest.fixture
def cfg(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "admin").write_text(ADMIN_PW)

    def write(*extra, **target):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        cred = target.pop("cred", "adm")
        docs = [doc("Target", "m", adapter="mongodb", **{**TARGET, **target}, authentication={"credentialRef": cred}),
                doc("CredentialProvider", "files", type="file", directory=str(secrets)),
                doc("Credential", "adm", providerRef="files", path="admin"),
                doc("Credential", "pw", providerRef="files", path="u_pw"), *extra]
        for i, d in enumerate(docs):
            (directory / f"{i:02}.json").write_text(json.dumps(d))
        return directory

    write.secrets = secrets
    return write


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def actions(rep):
    return {(o["kind"], o["id"], o["action"]) for o in rep["operations"]}


def mutating(rep):
    return [o for o in rep["operations"] if o["action"] in MUTATING]


def snapshot(c):
    return (c.admin.command("usersInfo", {"forAllDBs": True})["users"],
            list(c.admin["system.roles"].find({}, {"_id": 1, "privileges": 1, "roles": 1})))


READER = [{"resource": {"db": APP, "collection": "orders"}, "actions": ["find", "insert"]},
          {"resource": {"db": APP, "collection": ""}, "actions": ["listCollections"]}]


def test_plan_apply_converges(cfg, mongo):
    (cfg.secrets / "u_pw").write_text("app-pw-1")
    path = cfg(role("it_reader", privileges=READER, roles=["read"]),
               user("it_app_user", roles=["it_reader", {"role": "read", "db": OTHER}], credentials=creds()))
    before = snapshot(mongo)
    plan = run(path, "plan")
    assert {("DatabaseRole", "it_app.it_reader", "CREATE"), ("DatabaseUser", "it_app.it_app_user", "CREATE")} \
        <= actions(plan)
    assert snapshot(mongo) == before
    assert plan["targets"][0]["serverVersion"].startswith("MongoDB 8.0")
    first = run(path, "apply")
    assert report.exit_code(first) == 0, first
    info = mongo[APP].command("rolesInfo", "it_reader", showPrivileges=True)["roles"][0]
    assert sorted(info["privileges"][0]["actions"]) in (["find", "insert"], ["listCollections"])
    assert can_login("it_app_user", "app-pw-1")
    second = run(path, "apply")
    assert mutating(second) == [] and second["targets"][0]["status"] == "in_sync", second["operations"]
    assert ("DatabaseUser", "it_app.it_app_user", "NOOP") in actions(run(path, "drift"))


def test_update_only_declared_fields(cfg, mongo):
    mongo[APP].command("createRole", "it_r", privileges=READER, roles=["read"])
    mongo[APP].command("createUser", "it_u", pwd="x-pw", roles=["it_r"])
    (cfg.secrets / "u_pw").write_text("x-pw")
    path = cfg(role("it_r", roles=[]), user("it_u", roles=["read", "it_r"], credentials=creds()))
    rep = run(path, "apply")
    assert {("DatabaseRole", "it_app.it_r", "UPDATE"), ("DatabaseUser", "it_app.it_u", "UPDATE")} <= actions(rep)
    info = mongo[APP].command("rolesInfo", "it_r", showPrivileges=True)["roles"][0]
    assert info["roles"] == [] and info["privileges"]  # privileges not declared → untouched
    roles = mongo[APP].command("usersInfo", "it_u")["users"][0]["roles"]
    assert sorted(r["role"] for r in roles) == ["it_r", "read"]
    assert mutating(run(path, "apply")) == []


def test_undeclared_is_unmanaged_and_delete_needs_policy(cfg, mongo):
    mongo[APP].command("createUser", "it_stray", pwd="s", roles=[])
    path = cfg(user("it_keep", credentials=creds()))
    assert ("DatabaseUser", "it_app.it_stray", "UNMANAGED") in actions(run(path, "plan"))
    path = cfg(user("it_keep", credentials=creds()),
               doc("ReconciliationPolicy", "rp", targetRef="m", mode="authoritative",
                   scope={"resourceKinds": ["DatabaseUser"]}))
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    assert ("DatabaseUser", "it_app.it_stray", "DELETE") in actions(rep)
    assert not mongo[APP].command("usersInfo", "it_stray")["users"]
    # eigene Anmeldung (admin.root) liegt außerhalb des Scopes und taucht nicht auf
    assert not any(o["id"] == "admin.root" for o in rep["operations"])


def test_password_policies(cfg, mongo):
    mongo[APP].command("createUser", "it_v", pwd="old-pw", roles=[])
    mongo[APP].command("createUser", "it_e", pwd="new-pw", roles=[])
    mongo[APP].command("createUser", "it_s", pwd="old-pw", roles=[])
    (cfg.secrets / "u_pw").write_text("new-pw")
    path = cfg(user("it_v", credentials=creds("verify")), user("it_e", credentials=creds("enforce")),
               user("it_s", credentials=creds("set-on-create")))
    plan = run(path, "plan")
    assert ("DatabaseUser", "it_app.it_v", "SET_PASSWORD") in actions(plan)
    assert ("DatabaseUser", "it_app.it_s", "SET_PASSWORD") not in actions(plan)
    assert can_login("it_v", "old-pw")  # plan ändert nichts
    rep = run(path, "apply")
    assert {("DatabaseUser", "it_app.it_v", "SET_PASSWORD"), ("DatabaseUser", "it_app.it_e", "SET_PASSWORD")} \
        <= actions(rep)
    assert can_login("it_v", "new-pw") and can_login("it_e", "new-pw") and can_login("it_s", "old-pw")
    assert ("DatabaseUser", "it_app.it_v", "SET_PASSWORD") not in actions(run(path, "plan"))
    users = {u["user"]: u for u in mongo[APP].command("usersInfo", 1)["users"]}
    assert users["it_v"]["mechanisms"] == ["SCRAM-SHA-256"]


def test_verify_sha1_only_user_and_secret_creation(cfg, mongo):
    mongo[APP].command("createUser", "it_sha1", pwd="new-pw", roles=[], mechanisms=["SCRAM-SHA-1"])
    (cfg.secrets / "u_pw").write_text("new-pw")
    rep = run(cfg(user("it_sha1", credentials=creds())), "plan")
    assert ("DatabaseUser", "it_app.it_sha1", "NOOP") in actions(rep)  # verify fällt auf SCRAM-SHA-1 zurück
    (cfg.secrets / "u_pw").unlink()
    path = cfg(doc("Credential", "gen", providerRef="files", path="gen_pw",
                   lifecycle={"generator": {"length": 32}}),
               user("it_gen", credentials=creds("verify", "gen")))
    assert ("Credential", "gen", "CREATE_SECRET") in {(o["kind"], o["id"], o["action"])
                                                     for o in run(path, "plan")["operations"]}
    assert not (cfg.secrets / "gen_pw").exists()
    run(path, "apply")
    assert can_login("it_gen", (cfg.secrets / "gen_pw").read_text())


def test_secrets_never_in_report(cfg, mongo):
    (cfg.secrets / "u_pw").write_text(CANARY)
    mongo[APP].command("createUser", "it_pw", pwd="other-password", roles=[])
    path = cfg(user("it_pw", credentials=creds("verify")), user("it_new", credentials=creds("enforce")))
    reports = [run(path, m) for m in ("plan", "apply", "drift")]
    text = json.dumps(reports) + repr(reports)
    assert CANARY not in text and ADMIN_PW not in text and "other-password" not in text


def test_wrong_admin_password(cfg):
    (cfg.secrets / "admin").write_text("not-the-admin-password")
    rep = run(cfg(user("it_a", credentials=creds())), "plan")
    assert rep["targets"][0]["status"] == "error"
    assert rep["targets"][0]["reason"].startswith("AuthorizationError")
    assert "not-the-admin-password" not in json.dumps(rep)


PRIV = {"scope": {"databases": {"include": ["it_*", "admin"]}}}


@pytest.mark.parametrize("resource, privileged", [
    (user("it_p", roles=[{"role": "root", "db": "admin"}]), True),
    (user("it_p", roles=[{"role": "dbOwner", "db": "admin"}]), True),
    (user("it_p", roles=[{"role": "readWriteAnyDatabase", "db": "admin"}]), True),
    (user("it_p", roles=[{"role": "clusterAdmin", "db": "admin"}]), True),
    (user("it_p", roles=["userAdmin"]), False),  # userAdmin nur auf it_app: kein INV-10-Fall laut Regel
    (user("it_p", roles=["readWrite", {"role": "clusterMonitor", "db": "admin"}]), False),
    (role("it_p", "admin", privileges=[{"resource": {"cluster": True}, "actions": ["shutdown"]}]), True),
    (role("it_p", privileges=[{"resource": {"db": APP, "collection": ""}, "actions": ["createUser"]}]), True),
    (role("it_p", "admin", privileges=[{"resource": {"db": "admin", "collection": "system.users"},
                                        "actions": ["find"]}]), True),
    (role("it_p", privileges=READER), False),
])
def test_privileged_blocked_without_policy(cfg, mongo, resource, privileged):
    if resource["kind"] == "DatabaseUser":
        resource["spec"]["credentials"] = creds()
    before = snapshot(mongo)
    rep = run(cfg(resource, **PRIV), "apply")
    rid = f"{resource['spec']['database']}.it_p"
    op = next(o for o in rep["operations"] if o["id"] == rid)
    if privileged:
        assert op["action"] == "BLOCKED" and "allowPrivilegedGrants" in op["reason"], op
        assert report.exit_code(rep) == 11
        assert snapshot(mongo) == before
        allowed = run(cfg(resource, **PRIV), "apply", allowPrivilegedGrants=True)
        assert next(o for o in allowed["operations"] if o["id"] == rid)["action"] == "CREATE"
    else:
        assert op["action"] == "CREATE" and op["status"] == "succeeded", op


def test_privileges_via_existing_custom_role_chain(cfg, mongo):
    mongo.admin.command("createRole", "it_admin", privileges=[], roles=[{"role": "dbOwner", "db": "admin"}])
    mongo.admin.command("createRole", "it_mid", privileges=[], roles=["it_admin"])
    mongo.admin.command("createRole", "it_ops", privileges=[{"resource": {"cluster": True}, "actions": ["fsync"]}],
                       roles=[])
    for name, needle in (("it_mid", "inherits dbOwner@admin"), ("it_ops", "cluster")):
        ref = {"role": name, "db": "admin"}
        rep = run(cfg(user("it_x", roles=[ref], credentials=creds()), **PRIV), "plan")
        op = next(o for o in rep["operations"] if o["id"] == "it_app.it_x")
        assert op["action"] == "BLOCKED" and needle in op["reason"], op


def test_protected_objects(cfg, mongo):
    mongo.admin.command("createRole", "it_own", privileges=[], roles=[])
    mongo.admin.command("grantRolesToUser", "root", roles=["it_own"])
    try:
        path = cfg(user("root", db="admin", credentials=creds()), role("read", roles=[]),
                   role("it_own", db="admin", roles=["read"]), **PRIV)
        rep = run(path, "apply", allowPrivilegedGrants=True)
        ops = {o["id"]: o for o in rep["operations"]}
        assert ops["admin.root"]["action"] == "BLOCKED" and ops["it_app.read"]["action"] == "BLOCKED"
        assert ops["admin.it_own"]["action"] == "BLOCKED"  # Rolle der eigenen Anmeldung: system
        assert mongo.admin.command("rolesInfo", "it_own", showPrivileges=True)["roles"][0]["roles"] == []
    finally:
        mongo.admin.command("revokeRolesFromUser", "root", roles=["it_own"])


def test_read_only_session_refuses_writes(mongo):
    adapter = MongoDBAdapter()
    op = Op("m", "DatabaseRole", "it_app.it_ro", CREATE, desired=Resource("DatabaseRole", "it_app.it_ro"))
    with adapter.connect(TARGET, Secret(ADMIN_PW), write=False) as session:
        with pytest.raises(PermanentError, match="read-only"):
            adapter.apply(session, op)
    assert not mongo[APP].command("rolesInfo", "it_ro")["roles"]


def test_limited_identity_plan_and_partial_scope(cfg, mongo):
    # Lesekennung nur mit viewUser/viewRole auf it_app: forAllDBs verboten → Fallback je Datenbank
    mongo.admin.command("createRole", "it_viewer", roles=[], privileges=[
        {"resource": {"db": APP, "collection": ""}, "actions": ["viewUser", "viewRole"]}])
    mongo.admin.command("createUser", "it_ro", pwd="ro-pw", roles=["it_viewer"])
    mongo[APP].command("createUser", "it_seen", pwd="pw", roles=[])
    (cfg.secrets / "ro").write_text("ro-pw")
    extra = [doc("Credential", "ro", providerRef="files", path="ro")]
    ro_target = {"endpoint": {**TARGET["endpoint"], "user": "it_ro"}}
    path = cfg(*extra, role("it_new", roles=[]), cred="ro", **ro_target,
               scope={"databases": {"include": [APP]}})
    rep = run(path, "plan")
    inventory = rep["targets"][0]["inventory"]
    assert inventory["DatabaseUser"]["status"] == "complete", inventory
    assert ("DatabaseUser", "it_app.it_seen", "UNMANAGED") in actions(rep)
    assert ("DatabaseRole", "it_app.it_new", "CREATE") in actions(rep)
    path = cfg(*extra, user("it_other_u", db=OTHER, credentials=creds()), cred="ro", **ro_target,
               scope={"databases": {"include": [APP, OTHER]}})
    rep = run(path, "plan")
    inventory = rep["targets"][0]["inventory"]
    assert inventory["DatabaseUser"]["status"] == "partial" and "it_other" in inventory["DatabaseUser"]["reason"]
    assert ("DatabaseUser", "it_other.it_other_u", "UNKNOWN") in actions(rep)
    rep = run(cfg(*extra, cred="ro", **ro_target, scope={}), "plan")
    assert rep["targets"][0]["inventory"]["DatabaseUser"]["status"] == "forbidden"
    # Apply mit der Lesekennung scheitert am Server, nicht am Adapter – und ändert nichts
    rep = run(cfg(*extra, role("it_new", roles=[]), cred="ro", **ro_target,
                  scope={"databases": {"include": [APP]}}), "apply")
    assert not mongo[APP].command("rolesInfo", "it_new")["roles"]


def test_documented_read_only_identity_is_complete(cfg, mongo):
    # Rechte aus docs/adapters/mongodb.md ("plan/drift"): vollständiges Inventar ohne Schreibrechte
    mongo.admin.command("createRole", "it_inventory", roles=[], privileges=[
        {"resource": {"cluster": True}, "actions": ["viewUser"]},
        {"resource": {"db": "", "collection": ""}, "actions": ["viewRole"]},
        {"resource": {"db": "admin", "collection": "system.roles"}, "actions": ["find"]}])
    mongo[OTHER].command("createRole", "it_base", privileges=[], roles=[])
    mongo.admin.command("createUser", "it_ro", pwd="ro-pw", roles=["it_inventory"])
    mongo[OTHER].command("createRole", "it_r", privileges=[], roles=[])
    (cfg.secrets / "ro").write_text("ro-pw")
    rep = run(cfg(doc("Credential", "ro", providerRef="files", path="ro"),
                  user("it_x", roles=[{"role": "it_base", "db": OTHER}], credentials=creds()), cred="ro",
                  endpoint={**TARGET["endpoint"], "user": "it_ro"}), "plan")
    assert ("DatabaseUser", "it_app.it_x", "CREATE") in actions(rep)  # Rollenprüfung per rolesInfo möglich
    inventory = rep["targets"][0]["inventory"]
    assert inventory["DatabaseUser"]["status"] == inventory["DatabaseRole"]["status"] == "complete", inventory
    assert ("DatabaseRole", "it_other.it_r", "UNMANAGED") in actions(rep)
