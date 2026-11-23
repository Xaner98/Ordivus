"""Integration gegen einen echten RabbitMQ-Container (scripts/test-containers.sh, Management-API Port 15673).

Start: docker run -d --name ordivus-it-rabbitmq -p 127.0.0.1:15673:15672 \
  -e RABBITMQ_DEFAULT_USER=admin -e RABBITMQ_DEFAULT_PASS=adminpw-it rabbitmq:4.1-management
"""

import json
import logging
import os
import secrets

import pytest

from ordivus.adapters import rabbitmq
from ordivus.adapters.base import CREATE, AuthorizationError, Op, PermanentError, Resource, Secret
from ordivus.adapters.rabbitmq import USER, VHOST, RabbitMQAdapter, _path
from ordivus.core import config, engine
from ordivus.core.policy import OperatorPolicy

HOST = os.environ.get("ORDIVUS_TEST_HOST", "localhost")
PORT = int(os.environ.get("ORDIVUS_RABBITMQ_PORT", "15673"))
ADMIN_PW = os.environ.get("ORDIVUS_RABBITMQ_ADMIN_PASSWORD", "adminpw-it")
TARGET = {"endpoint": {"host": HOST, "port": PORT}, "username": "admin"}
BASE = f"http://{HOST}:{PORT}"
MUTATING = set(engine.MUTATING)
PERM = {"configure": "^$", "write": "^app\\.", "read": ".*"}


def admin(method, path, body=None):
    return rabbitmq._call(BASE, None, rabbitmq._basic("admin", Secret(ADMIN_PW)), method, path, body)


def users():
    return {u["name"]: u for u in admin("GET", "/api/users")[1]}


def vhosts():
    return {v["name"] for v in admin("GET", "/api/vhosts")[1]}


def perms(user):
    return {p["vhost"]: {f: p[f] for f in ("configure", "write", "read")}
            for p in admin("GET", _path("users", user, "permissions"))[1]}


def can_login(name, password):
    return RabbitMQAdapter().verify_password(None, TARGET, Resource(USER, name), Secret(password))


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


@pytest.fixture
def p():
    """Eindeutiges Präfix je Test; räumt danach alle Benutzer und vhosts mit diesem Präfix ab."""
    try:
        if admin("GET", "/api/whoami")[0] != 200:
            pytest.skip("RabbitMQ admin login failed")
    except Exception as e:
        pytest.skip(f"RabbitMQ not reachable at {BASE}: {type(e).__name__}")
    prefix = f"it{secrets.token_hex(3)}-"
    yield prefix
    for name in users():
        if name.startswith(prefix):
            admin("DELETE", _path("users", name))
    for name in vhosts():
        if name.startswith(prefix):
            admin("DELETE", _path("vhosts", name))


@pytest.fixture
def cfg(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "admin").write_text(ADMIN_PW)

    def write(*extra, scope=None):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        target = {**TARGET, **({"scope": scope} if scope else {})}
        docs = [doc("Target", "mq", adapter="rabbitmq", **target, authentication={"credentialRef": "admin"}),
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
            doc(USER, name, targetRef="mq", **spec, credentials={"credentialRef": cred, "passwordPolicy": "verify"})]


def test_plan_apply_drift_converge(p, cfg, caplog):
    caplog.set_level(logging.DEBUG)
    vhost, name, canary = f"{p}team/a", f"{p}app", f"CANARY-{secrets.token_hex(8)}"
    path = cfg(doc(VHOST, vhost, targetRef="mq"), *user(name, "pw", tags=[], permissions={vhost: PERM, "/": PERM}))
    (cfg.secrets / "pw").write_text(canary)

    plan = run(path, "plan")
    assert {(VHOST, vhost, "CREATE"), (USER, name, "CREATE")} <= actions(plan)
    assert plan["targets"][0]["serverVersion"].startswith("RabbitMQ ")
    assert vhost not in vhosts() and name not in users()

    first = run(path, "apply")
    assert all(o["status"] == "succeeded" for o in first["operations"] if o["action"] in MUTATING), first["operations"]
    assert vhost in vhosts() and perms(name) == {vhost: PERM, "/": PERM}
    # ohne management-Tag: whoami meldet "Not management user", das Passwort stimmt trotzdem
    assert can_login(name, canary) is True and can_login(name, "wrong-password") is False

    for mode in ("apply", "drift"):
        rep = run(path, mode)
        assert not [o for o in rep["operations"] if o["action"] in MUTATING], rep["operations"]
    dump = json.dumps([plan, first, rep])
    assert canary not in dump and ADMIN_PW not in dump and "password_hash" not in dump
    assert canary not in caplog.text and ADMIN_PW not in caplog.text


def test_update_tags_and_permissions_keep_password(p, cfg):
    name, v1, v2 = f"{p}u", f"{p}v1", f"{p}v2"
    vh = [doc(VHOST, v1, targetRef="mq"), doc(VHOST, v2, targetRef="mq")]
    run(cfg(*vh, *user(name, "pw", tags=["management"], permissions={v1: PERM})), "apply")
    password = (cfg.secrets / "pw").read_text()
    rep = run(cfg(*vh, *user(name, "pw", tags=["custom"], permissions={v2: PERM})), "apply")
    assert (USER, name, "UPDATE") in actions(rep) and (USER, name, "SET_PASSWORD") not in actions(rep)
    assert users()[name]["tags"] == ["custom"] and perms(name) == {v2: PERM}
    assert can_login(name, password) is True  # PUT ohne password_hash hätte das Passwort gelöscht


def test_wrong_password_verify_resets(p, cfg):
    name = f"{p}pw"
    path = cfg(*user(name, "pw"))  # Tags nicht deklariert = nicht verwaltet
    (cfg.secrets / "pw").write_text("the-declared-password")
    run(path, "apply")
    admin("PUT", _path("users", name), {"password": "changed-elsewhere", "tags": ["management", "keep"]})
    assert (USER, name, "SET_PASSWORD") in actions(run(path, "plan"))
    assert can_login(name, "the-declared-password") is False
    run(path, "apply")
    assert can_login(name, "the-declared-password") is True
    assert users()[name]["tags"] == ["management", "keep"]  # SET_PASSWORD lässt Tags unverändert


def test_secret_absent_created_and_usable(p, cfg):
    name = f"{p}gen"
    rep = run(cfg(*user(name, "gen")), "apply")
    assert {("Credential", "gen", "CREATE_SECRET"), (USER, name, "CREATE")} <= actions(rep)
    assert can_login(name, (cfg.secrets / "gen").read_text()) is True


def test_privileged_tags_blocked(p, cfg):
    name = f"{p}adm"
    path = cfg(*user(name, "pw", tags=["administrator"]))
    op = next(o for o in run(path, "apply")["operations"] if o["id"] == name)
    assert op["action"] == "BLOCKED" and "allowPrivilegedGrants" in op["reason"] and name not in users()
    run(path, "apply", allowPrivilegedGrants=True)
    assert users()[name]["tags"] == ["administrator"]
    # eigener Login und Default-vhost bleiben auch mit Freigabe gesperrt
    rep = run(cfg(doc(USER, "admin", targetRef="mq", tags=[]), doc(VHOST, "/", targetRef="mq")), "apply",
              allowPrivilegedGrants=True)
    assert {(USER, "admin", "BLOCKED"), (VHOST, "/", "BLOCKED")} <= actions(rep)
    assert users()["admin"]["tags"] == ["administrator"]


@pytest.mark.parametrize("mode", ["plan", "drift"])
def test_plan_and_drift_never_mutate(p, cfg, mode):
    name, vhost = f"{p}ro", f"{p}rov"
    run(cfg(*user(name, "pw", tags=["management"])), "apply")
    before = users()[name]
    rep = run(cfg(doc(VHOST, vhost, targetRef="mq"), *user(name, "pw", tags=["x"], permissions={"/": PERM})), mode)
    assert {(VHOST, vhost, "CREATE"), (USER, name, "UPDATE")} <= actions(rep)
    assert users()[name] == before and vhost not in vhosts() and perms(name) == {}


def test_read_only_session_cannot_mutate(p):
    adapter, name, vhost = RabbitMQAdapter(), f"{p}ro", f"{p}rov"
    with adapter.connect(TARGET, Secret(ADMIN_PW), write=False) as session:
        for op in (Op("mq", USER, name, CREATE, desired=Resource(USER, name), password=Secret("pw-123")),
                   Op("mq", VHOST, vhost, CREATE, desired=Resource(VHOST, vhost))):
            with pytest.raises(PermanentError):
                adapter.apply(session, op)
        with pytest.raises(PermanentError):
            adapter._request(session, "PUT", _path("vhosts", vhost), {})
    assert name not in users() and vhost not in vhosts()


def test_authoritative_deletes_only_in_scope(p, cfg):
    stray_user, stray_vhost, outside = f"{p}stray", f"{p}strayv", f"x{p}outside"
    admin("PUT", _path("users", stray_user), {"password": "pw-123", "tags": []})
    admin("PUT", _path("users", outside), {"password": "pw-123", "tags": []})
    admin("PUT", _path("vhosts", stray_vhost), {})
    try:
        scope = {"vhosts": {"include": [f"{p}*", "/"]}, "users": {"include": [f"{p}*", "admin"]}}
        policy = doc("ReconciliationPolicy", "gov", targetRef="mq", mode="authoritative",
                     scope={"resourceKinds": [VHOST, USER], VHOST: {"glob": ["*"]}, USER: {"glob": ["*"]}})
        rep = run(cfg(policy, *user(f"{p}keep", "pw"), scope=scope), "apply",
                  allowAuthoritative=True, allowDelete=True)
        deletes = {(k, i) for k, i, a in actions(rep) if a == "DELETE"}
        assert deletes == {(USER, stray_user), (VHOST, stray_vhost)}
        assert stray_user not in users() and stray_vhost not in vhosts()
        assert {"admin", outside, f"{p}keep"} <= set(users()) and "/" in vhosts()
    finally:
        admin("DELETE", _path("users", outside))


def test_scope_hides_and_rejects(p, cfg):
    scope = {"vhosts": {"include": [f"{p}*"]}, "users": {"include": [f"{p}*"]}}
    adapter = RabbitMQAdapter()
    assert adapter.validate_target({"scope": scope}, [Resource(USER, "u", {"permissions": {"/": PERM}})])
    admin("PUT", _path("users", f"{p}s"), {"password": "pw-123", "tags": []})
    admin("PUT", _path("permissions", "/", f"{p}s"), PERM)
    with adapter.connect({**TARGET, "scope": scope}, Secret(ADMIN_PW), write=False) as session:
        assert "/" not in {r.id for r in adapter.discover(session, VHOST, scope).resources}
        found = {r.id: r for r in adapter.discover(session, USER, scope).resources}
    assert "admin" not in found and found[f"{p}s"].attrs["permissions"] == {}


def test_non_admin_login_is_partial_or_forbidden(p):
    name = f"{p}mgmt"
    admin("PUT", _path("users", name), {"password": "pw-12345", "tags": ["management"]})
    admin("PUT", _path("permissions", "/", name), PERM)
    adapter, target = RabbitMQAdapter(), {**TARGET, "username": name}
    with adapter.connect(target, Secret("pw-12345"), write=False) as session:
        assert adapter.discover(session, VHOST, None).status == "partial"
        with pytest.raises(AuthorizationError):  # Engine meldet das Kind als forbidden
            adapter.discover(session, USER, None)
