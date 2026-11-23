"""Integration gegen einen echten Redis (Container ordivus-it-redis, Port 16379).

Start: docker run -d --name ordivus-it-redis -p 16379:6379 redis:8-alpine redis-server \
  --user admin on '>adminpw-it' '~*' '&*' '+@all' --requirepass defaultpw-it
"""

import json
import os

import pytest

redis = pytest.importorskip("redis")

from ordivus import adapters  # noqa: E402
from ordivus.adapters.base import CREATE, Op, PermanentError, Secret  # noqa: E402
from ordivus.adapters.redis import RedisAdapter  # noqa: E402
from ordivus.core import config, engine  # noqa: E402
from ordivus.core.config import ConfigError  # noqa: E402
from ordivus.core.policy import OperatorPolicy  # noqa: E402

HOST, PORT, ADMIN_PW = os.environ.get("ORDIVUS_TEST_HOST", "localhost"), 16379, "adminpw-it"
CANARY = "canary-Zq8vX1mP4tLw9sB2"
TARGET = {"endpoint": {"host": HOST, "port": PORT}, "username": "admin"}


def admin(username="admin", password=ADMIN_PW):
    return redis.Redis(host=HOST, port=PORT, username=username, password=password, decode_responses=True,
                       socket_connect_timeout=3)


def can_auth(user, password):
    try:
        admin(user, password).ping()
        return True
    except redis.exceptions.AuthenticationError:
        return False


@pytest.fixture(autouse=True)
def client():
    try:
        c = admin()
        c.ping()
    except redis.exceptions.RedisError:
        pytest.skip(f"redis not reachable at {HOST}:{PORT}")
    adapters.register(RedisAdapter)

    def clean():
        for u in c.acl_users():
            if u not in ("admin", "default"):
                c.acl_deluser(u)
    clean()
    yield c
    clean()
    c.close()


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


def user(name, **spec):
    return doc("DatabaseUser", name, targetRef="r", **spec)


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
        docs = [doc("Target", "r", adapter="redis", **{**TARGET, **target}, authentication={"credentialRef": "adm"}),
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
    return {(o["id"], o["action"]) for o in rep["operations"]}


ROUND_TRIPS = [
    {"keys": ["a", "~b", "%R~c", "%W~d", "%RW~e", "%R~a"], "channels": ["x", "&y", "x"]},
    {"keys": ["*", "a"], "channels": ["*", "z"], "commands": ["allcommands", "-FLUSHALL", "-@dangerous"]},
    {"keys": ["%R~*", "w:*"], "commands": ["+@read", "-get", "+get", "+@read", "-keys"]},
    {"commands": ["+config|get", "+config", "+client|list", "-@all", "+@read", "+@write", "-@read"]},
    {"commands": ["+get", "+get", "nocommands", "+set", "+config", "+config|get"], "enabled": False},
    {"keys": ["schlüssel:ä*", "日本:*"], "channels": ["kanal:ö"], "commands": []},
]


@pytest.mark.parametrize("spec", ROUND_TRIPS)
def test_rules_round_trip(cfg, spec):
    path = cfg(user("it_rt", **spec))
    first = run(path, "apply")
    assert ("it_rt", "CREATE") in actions(first), first["operations"]
    assert all(o["status"] == "succeeded" for o in first["operations"] if o["action"] == "CREATE")
    assert actions(run(path, "plan")) >= {("it_rt", "NOOP")}  # normalized desired == observed


def test_plan_create_then_apply_converges(cfg, client):
    path = cfg(user("it_a", keys=["app:*"], commands=["+@read"]), user("it_b", enabled=False))
    plan = run(path, "plan")
    assert {("it_a", "CREATE"), ("it_b", "CREATE")} <= actions(plan)
    assert set(client.acl_users()) == {"admin", "default"}
    first = run(path, "apply")
    assert all(o["status"] == "succeeded" for o in first["operations"] if o["action"] == "CREATE")
    info = client.execute_command("ACL", "GETUSER", "it_a")
    assert info["keys"] == "~app:*" and info["commands"] == "-@all +@read" and "on" in info["flags"]
    second = run(path, "apply")
    assert not [o for o in second["operations"] if o["action"] in engine.MUTATING]
    assert second["targets"][0]["status"] == "in_sync"


def test_update_only_declared_fields(cfg, client):
    client.execute_command("ACL", "SETUSER", "it_u", "on", "~keep:*", "&chan", "+get")
    rep = run(cfg(user("it_u", commands=["+@read", "-keys"])), "apply")
    op = next(o for o in rep["operations"] if o["id"] == "it_u")
    assert op["action"] == "UPDATE" and set(op["changes"]) == {"commands"} and op["status"] == "succeeded"
    info = client.execute_command("ACL", "GETUSER", "it_u")
    assert (info["keys"], info["channels"], info["commands"]) == ("~keep:*", "&chan", "-@all +@read -keys")


def test_unmanaged_survives_additive(cfg, client):
    client.execute_command("ACL", "SETUSER", "it_other", "on", ">x")
    rep = run(cfg(user("it_a")), "apply", allowDelete=True)
    assert ("it_other", "UNMANAGED") in actions(rep)
    assert rep["summary"]["actions"]["IGNORE"] == 2  # admin + default: system, only counted
    assert "it_other" in client.acl_users()


def test_authoritative_deletes_only_in_scope(cfg, client):
    for u in ("it_x", "keep_y"):
        client.execute_command("ACL", "SETUSER", u, "on", ">x")
    policy = doc("ReconciliationPolicy", "gov", targetRef="r", mode="authoritative",
                 scope={"resourceKinds": ["DatabaseUser"], "DatabaseUser": {"glob": ["it_*", "admin", "default"]}})
    rep = run(cfg(user("it_a"), policy), "apply", allowAuthoritative=True, allowDelete=True)
    assert {("it_x", "DELETE"), ("keep_y", "UNMANAGED")} <= actions(rep)
    assert rep["summary"]["actions"]["IGNORE"] == 2 and rep["summary"]["actions"]["DELETE"] == 1
    assert set(client.acl_users()) == {"admin", "default", "it_a", "keep_y"}


@pytest.mark.parametrize("bad", [
    {"name": "it bad"}, {"name": "it\nbad"}, {"name": ">pw"}, {"name": "#hash"}, {"name": "ümlaut"},
    {"commands": ["+get >pw"]}, {"commands": [">secret"]}, {"commands": ["nopass"]}, {"commands": ["on"]},
    {"commands": ["reset"]}, {"commands": ["+@read\n+@all"]}, {"keys": ["a b"]}, {"keys": ["a\nb"]},
    {"channels": ["x y"]}, {"keys": [""]}, {"keys": "a"}, {"selectors": ["(~x +get)"]}, {"enabled": "yes"},
    {"password": "x"},
])
def test_injection_and_invalid_input_rejected(cfg, client, bad):
    name = bad.pop("name", "it_ok")
    with pytest.raises(ConfigError):
        run(cfg(user(name, **bad)), "plan")
    assert set(client.acl_users()) == {"admin", "default"}


def test_prefix_characters_in_patterns_are_literal(cfg, client):
    run(cfg(user("it_p", keys=[">pw", "<h", "#x"], channels=[">c"])), "apply")
    info = client.execute_command("ACL", "GETUSER", "it_p")
    assert info["passwords"] == [] and sorted(info["keys"].split()) == ["~#x", "~<h", "~>pw"]
    assert info["channels"] == "&>c"


def test_password_created_via_file_provider(cfg, client):
    path = cfg(user("it_pw", commands=["+ping"], credentials={"credentialRef": "pw"}))
    rep = run(path, "apply")
    assert {("pw", "CREATE_SECRET"), ("it_pw", "CREATE")} <= actions(rep)
    assert all(o["status"] == "succeeded" for o in rep["operations"] if o["action"] in engine.MUTATING)
    assert can_auth("it_pw", (cfg.secrets / "u_pw").read_text())
    assert not [o for o in run(path, "apply")["operations"] if o["action"] in engine.MUTATING]


def test_wrong_password_is_reset_on_verify(cfg, client):
    (cfg.secrets / "u_pw").write_text(CANARY)
    client.execute_command("ACL", "SETUSER", "it_pw", "on", ">wrong-old-password", "+ping")
    path = cfg(user("it_pw", commands=["+ping"], credentials={"credentialRef": "pw", "passwordPolicy": "verify"}))
    plan = run(path, "plan")
    assert ("it_pw", "SET_PASSWORD") in actions(plan)
    rep = run(path, "apply")
    op = next(o for o in rep["operations"] if o["action"] == "SET_PASSWORD")
    assert op["status"] == "succeeded"
    assert can_auth("it_pw", CANARY) and not can_auth("it_pw", "wrong-old-password")
    assert ("it_pw", "NOOP") in actions(run(path, "plan"))


@pytest.mark.parametrize("mode", ["plan", "drift"])
def test_plan_and_drift_never_mutate(cfg, client, mode):
    client.execute_command("ACL", "SETUSER", "it_old", "on", ">x", "+get")
    client.execute_command("ACL", "SETUSER", "it_x", "on")
    before = client.acl_list()
    policy = doc("ReconciliationPolicy", "gov", targetRef="r", mode="authoritative",
                 scope={"resourceKinds": ["DatabaseUser"]})
    path = cfg(user("it_new"), user("it_old", commands=["+@read"], credentials={"credentialRef": "pw"}), policy)
    rep = run(path, mode, allowAuthoritative=True, allowDelete=True)
    assert {("it_new", "CREATE"), ("it_old", "UPDATE"), ("it_x", "DELETE"), ("pw", "CREATE_SECRET")} <= actions(rep)
    assert client.acl_list() == before and not (cfg.secrets / "u_pw").exists()


def test_read_only_session_refuses_writes(client):
    adapter = RedisAdapter()
    op = Op("r", "DatabaseUser", "it_ro", CREATE, desired=adapter.desired(user("it_ro")))
    with adapter.connect(TARGET, Secret(ADMIN_PW), write=False) as session:
        with pytest.raises(PermanentError, match="read-only"):
            adapter.apply(session, op)
    assert "it_ro" not in client.acl_users()


def test_secrets_and_hashes_never_in_report(cfg, client):
    (cfg.secrets / "u_pw").write_text(CANARY)
    client.execute_command("ACL", "SETUSER", "it_pw", "on", ">other-password")
    path = cfg(user("it_pw", credentials={"credentialRef": "pw", "passwordPolicy": "enforce"}))
    reports = [run(path, m) for m in ("plan", "apply", "drift")]
    text = json.dumps(reports) + repr(reports)
    hashes = {h.lstrip("#") for line in client.acl_list() for h in line.split() if h.startswith("#")}
    assert hashes and CANARY not in text and ADMIN_PW not in text
    assert not any(h in text for h in hashes)


def test_wrong_admin_password_is_authorization_error(cfg):
    (cfg.secrets / "admin").write_text("not-the-admin-password")
    rep = run(cfg(user("it_a")), "plan")
    assert rep["targets"][0]["status"] == "error"
    assert rep["targets"][0]["reason"].startswith("AuthorizationError")
    assert "not-the-admin-password" not in json.dumps(rep)


def test_persist_without_config_file_fails_before_changes(cfg, client):
    path = cfg(user("it_a"), persist="configRewrite")
    assert ("it_a", "CREATE") in actions(run(path, "plan"))  # read-only: no persistence check
    rep = run(path, "apply")
    assert rep["targets"][0]["status"] == "error" and "config file" in rep["targets"][0]["reason"]
    assert "it_a" not in client.acl_users()
