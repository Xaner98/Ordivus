"""Integration gegen einen echten Kafka-Broker (Container ordivus-it-kafka, Port 19092).

Start: scripts/test-containers.sh up (KRaft, SASL_PLAINTEXT/SCRAM, StandardAuthorizer, super user admin).
"""

import json
import logging
import os
import time

import pytest

pytest.importorskip("kafka")

from kafka import KafkaAdminClient  # noqa: E402
from kafka.admin import (  # noqa: E402
    ACL,
    ACLFilter,
    ACLOperation,
    ACLPermissionType,
    ACLResourcePatternType,
    ResourcePattern,
    ResourcePatternFilter,
    ResourceType,
    UserScramCredentialDeletion,
    UserScramCredentialUpsertion,
)

from ordivus import adapters  # noqa: E402
from ordivus.adapters.base import CREATE, Op, PermanentError, Secret, TransientError  # noqa: E402
from ordivus.adapters.kafka import KafkaAdapter, _sasl_login  # noqa: E402
from ordivus.core import config, engine  # noqa: E402
from ordivus.core.policy import OperatorPolicy  # noqa: E402

HOST, PORT, ADMIN_PW = os.environ.get("ORDIVUS_TEST_HOST", "127.0.0.1"), 19092, "adminpw-it"
CANARY = "canary-Kf7wQ2nR8xLp3vZ9"
TARGET = {"bootstrapServers": [f"{HOST}:{PORT}"], "securityProtocol": "SASL_PLAINTEXT", "username": "admin",
          "superUsers": ["User:admin"]}
ANY = ACLFilter(None, None, ACLOperation.ANY, ACLPermissionType.ANY,
                ResourcePatternFilter(ResourceType.ANY, None, ACLResourcePatternType.ANY))
logging.getLogger("kafka").setLevel(logging.CRITICAL)


def admin_client(user="admin", password=ADMIN_PW, mechanism="SCRAM-SHA-512"):
    return KafkaAdminClient(bootstrap_servers=f"{HOST}:{PORT}", security_protocol="SASL_PLAINTEXT",
                            sasl_mechanism=mechanism, sasl_plain_username=user, sasl_plain_password=password,
                            request_timeout_ms=5000, bootstrap_timeout_ms=5000)


def can_login(user, password, mechanism="SCRAM-SHA-512"):
    return _sasl_login(TARGET, user, Secret(password), mechanism) is True


def acls(client):
    return sorted(repr(a) for a in client.describe_acls(ANY)[0])


def users(client):
    return {u: sorted((ci["mechanism"].name, ci["iterations"]) for ci in info["credential_infos"])
            for u, info in client.describe_user_scram_credentials().items()}


def add_user(client, name, password="x-old-password", mechanism="SCRAM-SHA-512", iterations=4096):
    assert client.alter_user_scram_credentials(
        [UserScramCredentialUpsertion(name, mechanism, password, iterations=iterations)]) == {name: None}


def add_acl(client, principal, rtype, name, op, pattern="LITERAL", permission="ALLOW"):
    res = client.create_acls([ACL(principal, "*", ACLOperation[op], ACLPermissionType[permission],
                                  ResourcePattern(ResourceType[rtype], name, ACLResourcePatternType[pattern]))])
    assert not res["failed"], res


@pytest.fixture(autouse=True)
def client():
    try:
        c = admin_client()
    except Exception:
        pytest.skip(f"kafka not reachable at {HOST}:{PORT}")
    adapters.register(KafkaAdapter)

    def clean():
        c.delete_acls([ANY])
        for u, creds in users(c).items():
            if u != "admin":
                for mech, _ in creds:
                    c.alter_user_scram_credentials([UserScramCredentialDeletion(u, mech)])
    clean()
    yield c
    clean()
    c.close()


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


def user(name, **spec):
    return doc("KafkaUser", name, targetRef="k", **spec)


def acl(name, principal, resourceType, resourceName, operations, **spec):
    return doc("KafkaAcl", name, targetRef="k", principal=principal, resourceType=resourceType,
               resourceName=resourceName, operations=operations, **spec)


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
        docs = [doc("Target", "k", adapter="kafka", **{**TARGET, **target}, authentication={"credentialRef": "adm"}),
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


def acl_id(principal, rtype, name, pattern="LITERAL", permission="ALLOW", host="*"):
    return json.dumps([principal, rtype, pattern, name, permission, host], separators=(",", ":"))


def test_plan_apply_converges(cfg, client):
    path = cfg(user("it-app", credentials={"credentialRef": "pw"}),
               acl("a1", "User:it-app", "TOPIC", "orders.", ["WRITE", "describe"], patternType="prefixed"),
               acl("a2", "User:it-app", "group", "it-app", ["READ"]))
    plan = run(path, "plan")
    assert plan["targets"][0]["serverVersion"] == "Kafka 4.1"
    assert plan["targets"][0]["insecureTransport"] is True
    want = {("KafkaUser", "it-app", "CREATE"),
            ("KafkaAcl", acl_id("User:it-app", "TOPIC", "orders.", "PREFIXED"), "CREATE"),
            ("KafkaAcl", acl_id("User:it-app", "GROUP", "it-app"), "CREATE")}
    assert want <= actions(plan)
    assert users(client) == {"admin": [("SCRAM_SHA_512", 4096)]} and acls(client) == []
    first = run(path, "apply")
    assert all(o["status"] == "succeeded" for o in first["operations"] if o["action"] in engine.MUTATING), first
    assert can_login("it-app", (cfg.secrets / "u_pw").read_text())
    assert len(acls(client)) == 3
    second = run(path, "apply")
    assert not [o for o in second["operations"] if o["action"] in engine.MUTATING]
    assert second["targets"][0]["status"] == "in_sync"


def test_acl_update_adds_and_removes_operations(cfg, client):
    add_acl(client, "User:it-u", "TOPIC", "t1", "READ")
    add_acl(client, "User:it-u", "TOPIC", "t1", "DESCRIBE")
    rep = run(cfg(acl("a", "User:it-u", "TOPIC", "t1", ["DESCRIBE", "WRITE"])), "apply")
    op = next(o for o in rep["operations"] if o["kind"] == "KafkaAcl")
    assert op["action"] == "UPDATE" and op["status"] == "succeeded", op
    assert [a for a in acls(client)] == sorted(repr(a) for a in [
        ACL("User:it-u", "*", ACLOperation[o], ACLPermissionType.ALLOW, ResourcePattern(ResourceType.TOPIC, "t1"))
        for o in ("DESCRIBE", "WRITE")])


def test_additive_keeps_unmanaged_and_authoritative_deletes_in_scope(cfg, client):
    add_user(client, "it-other")
    add_acl(client, "User:it-other", "TOPIC", "x", "READ")
    add_acl(client, "User:admin", "TOPIC", "x", "READ")  # eigene Anmeldung: system
    rep = run(cfg(acl("a", "User:it-a", "TOPIC", "x", ["READ"])), "apply", allowDelete=True)
    assert {("KafkaUser", "it-other", "UNMANAGED"),
            ("KafkaAcl", acl_id("User:it-other", "TOPIC", "x"), "UNMANAGED")} <= actions(rep)
    assert rep["summary"]["actions"]["IGNORE"] == 2  # admin-Benutzer und seine ACL: system, nur gezählt
    policy = doc("ReconciliationPolicy", "gov", targetRef="k", mode="authoritative",
                 scope={"resourceKinds": ["KafkaAcl", "KafkaUser"]})
    rep = run(cfg(acl("a", "User:it-a", "TOPIC", "x", ["READ"]), policy), "apply",
              allowAuthoritative=True, allowDelete=True)
    assert {("KafkaUser", "it-other", "DELETE"), ("KafkaAcl", acl_id("User:it-other", "TOPIC", "x"), "DELETE")} \
        <= actions(rep) and rep["summary"]["actions"]["IGNORE"] == 2
    assert all(o["status"] == "succeeded" for o in rep["operations"] if o["action"] in engine.MUTATING), rep
    assert set(users(client)) == {"admin"} and len(acls(client)) == 2  # admin + it-a


def test_target_scope_limits_discovery_and_blocks_outside(cfg, client):
    add_acl(client, "User:other", "TOPIC", "x", "READ")
    add_user(client, "other")
    path = cfg(acl("a", "User:app-1", "TOPIC", "x", ["READ"]), acl("b", "User:outside", "TOPIC", "x", ["READ"]),
               scope={"principals": {"include": ["User:app-*"]}})
    rep = run(path, "plan")
    ids = {o["id"] for o in rep["operations"]}
    assert "other" not in ids and acl_id("User:other", "TOPIC", "x") not in ids
    blocked = next(o for o in rep["operations"] if o["id"] == acl_id("User:outside", "TOPIC", "x"))
    assert blocked["action"] == "BLOCKED" and "outside spec.scope" in blocked["reason"]


def test_wrong_password_is_reset_on_verify(cfg, client):
    (cfg.secrets / "u_pw").write_text(CANARY)
    add_user(client, "it-pw")
    path = cfg(user("it-pw", credentials={"credentialRef": "pw", "passwordPolicy": "verify"}))
    assert ("KafkaUser", "it-pw", "SET_PASSWORD") in actions(run(path, "plan"))
    rep = run(path, "apply")
    assert next(o for o in rep["operations"] if o["action"] == "SET_PASSWORD")["status"] == "succeeded"
    assert can_login("it-pw", CANARY) and not can_login("it-pw", "x-old-password")
    assert ("KafkaUser", "it-pw", "NOOP") in actions(run(path, "plan"))


def test_mechanism_and_iterations_mismatch_is_reset(cfg, client):
    (cfg.secrets / "u_pw").write_text(CANARY)
    add_user(client, "it-m", CANARY, "SCRAM-SHA-256")
    add_user(client, "it-m", CANARY, "SCRAM-SHA-512", 4096)
    path = cfg(user("it-m", credentials={"credentialRef": "pw"}),
               scram={"mechanism": "SCRAM-SHA-512", "iterations": 8192})
    rep = run(path, "apply")
    assert ("KafkaUser", "it-m", "SET_PASSWORD") in actions(rep)
    assert users(client)["it-m"] == [("SCRAM_SHA_512", 8192)]
    assert ("KafkaUser", "it-m", "NOOP") in actions(run(path, "plan"))


def test_enforce_and_set_on_create(cfg, client):
    (cfg.secrets / "u_pw").write_text(CANARY)
    add_user(client, "it-e", CANARY)
    enforce = run(cfg(user("it-e", credentials={"credentialRef": "pw", "passwordPolicy": "enforce"})), "plan")
    assert ("KafkaUser", "it-e", "SET_PASSWORD") in actions(enforce)
    once = run(cfg(user("it-e", credentials={"credentialRef": "pw", "passwordPolicy": "set-on-create"})), "plan")
    assert ("KafkaUser", "it-e", "NOOP") in actions(once)


def test_new_user_without_credentials_is_blocked(cfg, client):
    add_user(client, "it-exists")
    rep = run(cfg(user("it-new"), user("it-exists")), "plan")
    assert ("KafkaUser", "it-exists", "NOOP") in actions(rep)
    op = next(o for o in rep["operations"] if o["id"] == "it-new")
    assert op["action"] == "BLOCKED" and "spec.credentials" in op["reason"]


@pytest.mark.parametrize("mode", ["plan", "drift"])
def test_plan_and_drift_never_mutate(cfg, client, mode):
    add_user(client, "it-old")
    add_acl(client, "User:it-x", "TOPIC", "x", "READ")
    before = (users(client), acls(client))
    policy = doc("ReconciliationPolicy", "gov", targetRef="k", mode="authoritative",
                 scope={"resourceKinds": ["KafkaAcl", "KafkaUser"]})
    path = cfg(user("it-new", credentials={"credentialRef": "pw"}),
               user("it-old", credentials={"credentialRef": "pw", "passwordPolicy": "enforce"}),
               acl("a", "User:it-new", "TOPIC", "y", ["READ"]), policy)
    rep = run(path, mode, allowAuthoritative=True, allowDelete=True)
    assert {("KafkaUser", "it-new", "CREATE"), ("KafkaAcl", acl_id("User:it-x", "TOPIC", "x"), "DELETE"),
            ("Credential", "pw", "CREATE_SECRET")} <= actions(rep)
    assert (users(client), acls(client)) == before and not (cfg.secrets / "u_pw").exists()


def test_read_only_session_refuses_writes(client):
    adapter = KafkaAdapter()
    op = Op("k", "KafkaUser", "it-ro", CREATE, desired=adapter.desired(user("it-ro")), password=Secret("x-pw"))
    with adapter.connect(TARGET, Secret(ADMIN_PW), write=False) as session:
        with pytest.raises(PermanentError, match="read-only"):
            adapter.apply(session, op)
    assert "it-ro" not in users(client)


@pytest.mark.parametrize("spec, privileged", [
    ({"resourceType": "CLUSTER", "resourceName": "kafka-cluster", "operations": ["DESCRIBE"]}, True),
    ({"resourceType": "TOPIC", "resourceName": "t", "operations": ["ALL"]}, True),
    ({"resourceType": "TOPIC", "resourceName": "t", "operations": ["ALTER_CONFIGS"]}, True),
    ({"resourceType": "GROUP", "resourceName": "g", "operations": ["ALTER"]}, True),
    ({"resourceType": "TOPIC", "resourceName": "*", "operations": ["WRITE"]}, True),
    ({"resourceType": "USER", "resourceName": "someone", "operations": ["CREATE_TOKENS"]}, True),
    ({"resourceType": "TOPIC", "resourceName": "t", "operations": ["READ"], "principal": "User:*",
      "permission": "DENY"}, True),
    ({"resourceType": "TOPIC", "resourceName": "*", "operations": ["READ", "DESCRIBE"]}, False),
    ({"resourceType": "TOPIC", "resourceName": "t", "operations": ["WRITE", "CREATE"]}, False),
    ({"resourceType": "TOPIC", "resourceName": "t", "operations": ["ALL"], "permission": "DENY"}, False),
])
def test_privileged_acls_blocked_without_policy(cfg, client, spec, privileged):
    spec = {"principal": "User:it-p", **spec}
    path = cfg(doc("KafkaAcl", "p", targetRef="k", **spec))
    rep = run(path, "apply")
    op = next(o for o in rep["operations"] if o["kind"] == "KafkaAcl")
    if privileged:
        assert op["action"] == "BLOCKED" and "allowPrivilegedGrants" in op["reason"], op
        assert acls(client) == []
        allowed = run(path, "apply", allowPrivilegedGrants=True)
        assert next(o for o in allowed["operations"] if o["kind"] == "KafkaAcl")["status"] == "succeeded"
    else:
        assert op["action"] == "CREATE" and op["status"] == "succeeded", op


def test_super_users_and_own_login_protected(cfg, client):
    path = cfg(acl("s", "User:root", "TOPIC", "t", ["READ"]), user("root", credentials={"credentialRef": "pw"}),
               acl("own", "User:admin", "TOPIC", "t", ["READ"]), user("admin", credentials={"credentialRef": "pw"}),
               superUsers=["User:admin", "User:root"])
    for policy in ({}, {"allowPrivilegedGrants": True}):
        rep = run(path, "plan", **policy)
        by_id = {(o["kind"], o["id"]): o for o in rep["operations"]}
        assert by_id[("KafkaAcl", acl_id("User:admin", "TOPIC", "t"))]["action"] == "BLOCKED"
        assert by_id[("KafkaUser", "admin")]["action"] == "BLOCKED"
        root = {by_id[("KafkaUser", "root")]["action"],
                by_id[("KafkaAcl", acl_id("User:root", "TOPIC", "t"))]["action"]}
        assert root == ({"CREATE"} if policy else {"BLOCKED"})


def test_discovery_forbidden_for_unprivileged_login(cfg, client):
    add_user(client, "it-weak", "weak-pw-it")
    (cfg.secrets / "admin").write_text("weak-pw-it")
    rep = run(cfg(acl("a", "User:it-a", "TOPIC", "x", ["READ"]), username="it-weak"), "plan")
    inventory = rep["targets"][0]["inventory"]
    assert inventory["KafkaAcl"]["status"] == inventory["KafkaUser"]["status"] == "forbidden", inventory
    assert next(o for o in rep["operations"] if o["kind"] == "KafkaAcl")["action"] == "UNKNOWN"


def test_wrong_admin_password_is_authorization_error(cfg):
    (cfg.secrets / "admin").write_text("not-the-admin-password")
    rep = run(cfg(user("it-a")), "plan")
    assert rep["targets"][0]["status"] == "error"
    assert rep["targets"][0]["reason"].startswith("AuthorizationError"), rep["targets"][0]
    assert "not-the-admin-password" not in json.dumps(rep)


def test_unreachable_broker_is_transient_and_fast():
    adapter = KafkaAdapter()
    start = time.monotonic()
    with pytest.raises(TransientError):
        with adapter.connect({**TARGET, "bootstrapServers": [f"{HOST}:1"]}, Secret(ADMIN_PW), write=False):
            pass
    assert time.monotonic() - start < 15


def test_secrets_never_in_report(cfg, client):
    (cfg.secrets / "u_pw").write_text(CANARY)
    add_user(client, "it-pw")
    path = cfg(user("it-pw", credentials={"credentialRef": "pw", "passwordPolicy": "verify"}))
    text = json.dumps([run(path, m) for m in ("plan", "apply", "drift")])
    assert CANARY not in text and ADMIN_PW not in text
