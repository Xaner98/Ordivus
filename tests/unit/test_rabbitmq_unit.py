"""RabbitMQ ohne Server: Validierung, Sperren, Pfad-Kodierung, Versionsprüfung, Passwort-Erhalt bei UPDATE."""

import pytest

from ordivus.adapters import rabbitmq
from ordivus.adapters.base import CREATE, SET_PASSWORD, UPDATE, Op, PermanentError, Resource, Secret
from ordivus.adapters.rabbitmq import USER, VHOST, RabbitMQAdapter, Session

A = RabbitMQAdapter()


def doc(kind, name, **spec):
    return {"kind": kind, "metadata": {"name": name}, "spec": spec}


def session(write=True, tags=("administrator",)):
    return Session("http://h:15672", None, "ordivus", "Basic x", write, "RabbitMQ 4.1.8", list(tags))


@pytest.fixture
def calls(monkeypatch):
    class Calls(list):
        responses = {}
    log = Calls()
    responses = log.responses = {}

    def fake(base, context, auth, method, path, body=None):
        log.append((method, path, body))
        return responses.get((method, path), (204, None))
    monkeypatch.setattr(rabbitmq, "_call", fake)
    return log


def test_validate():
    assert A.validate(doc("Target", "t", endpoint={"host": "mq"}, username="ordivus",
                          scope={"vhosts": {"include": ["team-*"]}})) == []
    assert "spec.username is required" in A.validate(doc("Target", "t", endpoint={"host": "mq"}))[0]
    assert A.validate(doc("Target", "t", endpoint={"host": "mq"}, username="u", scope={"queues": {}})) == [
        "unknown field spec.scope.queues"]
    assert A.validate(doc(VHOST, "team/a")) == []
    assert A.validate(doc(VHOST, "x", description="d")) == ["unknown field spec.description"]
    assert A.validate(doc(USER, "app", tags=["management"],
                          permissions={"/": {"configure": "^$", "write": ".*", "read": ".*"}})) == []
    assert len(A.validate(doc(USER, "app", tags=["a,b"], permissions={"/": {"read": ".*"}}))) == 2


def test_desired_normalizes():
    r = A.desired(doc(USER, "app", tags=["b", "a", "b"],
                      permissions={"z": {"read": "r", "write": "w", "configure": "c"}, "a": {
                          "configure": "", "write": "", "read": ""}}))
    assert r.attrs == {"tags": ["a", "b"], "permissions": {"a": {"configure": "", "write": "", "read": ""},
                                                           "z": {"configure": "c", "write": "w", "read": "r"}}}
    assert A.desired(doc(USER, "app")).attrs == {}  # nicht deklariert = nicht verwaltet


def test_check_protects_and_blocks_privileged():
    s = session()
    assert "protected" in A.check(s, Resource(VHOST, "/"), allow_privileged=True)
    assert A.check(s, Resource(VHOST, "team")) is None
    assert "Ordivus login" in A.check(s, Resource(USER, "ordivus"), allow_privileged=True)
    for tag in ("administrator", "policymaker", "monitoring", "impersonator"):
        assert "allowPrivilegedGrants" in A.check(s, Resource(USER, "u", {"tags": [tag]}))
        assert A.check(s, Resource(USER, "u", {"tags": [tag]}), allow_privileged=True) is None
    assert A.check(s, Resource(USER, "u", {"tags": ["management", "custom"]})) is None


def test_validate_target_scope():
    target = {"scope": {"vhosts": {"include": ["team-*"]}}}
    r = Resource(USER, "u", {"permissions": {"team-a": {}, "other": {}}})
    assert A.validate_target(target, [r]) == ["MessagingUser 'u': vhost 'other' is outside spec.scope.vhosts"]


def test_path_encoding():
    assert rabbitmq._path("permissions", "/", "a b/c") == "/api/permissions/%2F/a%20b%2Fc"
    assert rabbitmq._path("vhosts", "../x?y#") == "/api/vhosts/..%2Fx%3Fy%23"


def test_version_check():
    assert rabbitmq.version_check("4.1.8") == "RabbitMQ 4.1.8"
    assert rabbitmq.version_check("3.13.0") == "RabbitMQ 3.13.0"
    with pytest.raises(PermanentError, match=r"RabbitMQ 3.12.14 is not supported \(minimum 3.13\)"):
        rabbitmq.version_check("3.12.14")
    assert rabbitmq.version_check(None) is None


def test_read_only_refuses_writes(calls):
    s = session(write=False)
    with pytest.raises(PermanentError):
        A.apply(s, Op("t", VHOST, "v", CREATE, desired=Resource(VHOST, "v")))
    with pytest.raises(PermanentError, match="read-only"):
        A._request(s, "PUT", "/api/vhosts/v", {})
    assert calls == []


def test_update_tags_keeps_password_hash(calls):
    calls.responses[("GET", "/api/users/u")] = (200, {"name": "u", "password_hash": "H", "tags": ["old"],
                                                      "hashing_algorithm": "rabbit_password_hashing_sha256"})
    perm = {"configure": "", "write": "", "read": ".*"}
    A.apply(session(), Op("t", USER, "u", UPDATE, changes={
        "tags": (["old"], ["new"]), "permissions": ({"gone": perm, "same": perm}, {"same": perm, "/": perm})}))
    assert ("PUT", "/api/users/u", {"password_hash": "H", "hashing_algorithm": "rabbit_password_hashing_sha256",
                                    "tags": ["new"]}) in calls
    assert ("PUT", "/api/permissions/%2F/u", perm) in calls and ("DELETE", "/api/permissions/gone/u", None) in calls
    assert not [c for c in calls if c[1] == "/api/permissions/same/u"]
    calls.clear()
    A.apply(session(), Op("t", USER, "u", SET_PASSWORD, password=Secret("pw")))
    assert calls[-1] == ("PUT", "/api/users/u", {"password": "pw", "tags": ["old"]})


def test_protected_apply(calls):
    with pytest.raises(PermanentError, match="protected"):
        A.apply(session(), Op("t", VHOST, "/", CREATE, desired=Resource(VHOST, "/")))
    with pytest.raises(PermanentError, match="protected"):
        A.apply(session(), Op("t", USER, "ordivus", SET_PASSWORD, password=Secret("x")))
    assert calls == []


@pytest.mark.parametrize("status,payload,expected", [
    (200, {"name": "u"}, True), (401, {"reason": "Not management user"}, True),
    (401, {"reason": "Not_Authorized"}, False), (401, {"reason": "User can only log in via localhost"}, None),
    (503, None, None)])
def test_verify_password(calls, status, payload, expected):
    calls.responses[("GET", "/api/whoami")] = (status, payload)
    target = {"endpoint": {"host": "h"}, "username": "ordivus"}
    assert A.verify_password(None, target, Resource(USER, "u"), Secret("p")) is expected
    assert A.verify_password(None, target, Resource(USER, "a:b"), Secret("p")) is None


@pytest.mark.parametrize("kind,responses", [
    (VHOST, {"/api/vhosts": None}), (VHOST, {"/api/vhosts": [{}]}),
    (USER, {"/api/users": [{"name": "u"}], "/api/permissions": []}),
    (USER, {"/api/users": [], "/api/permissions": [{"user": "u", "vhost": "/"}]})])
def test_discover_rejects_bad_shapes(calls, kind, responses):
    calls.responses.update({("GET", p): (200, r) for p, r in responses.items()})
    with pytest.raises(PermanentError, match="unexpected response"):
        A.discover(session(), kind, None)


def test_discover_scope_and_partial(calls):
    perm = {"configure": ".*", "write": ".*", "read": ".*"}
    calls.responses.update({
        ("GET", "/api/vhosts"): (200, [{"name": "/"}, {"name": "team-a"}, {"name": "x"},
                                      {"name": "team-p", "protected_from_deletion": True}]),
        ("GET", "/api/users"): (200, [{"name": "ordivus", "tags": ["administrator"], "password_hash": "SECRET"},
                                     {"name": "app", "tags": [], "password_hash": "SECRET"}]),
        ("GET", "/api/permissions"): (200, [{"user": "app", "vhost": "team-a", **perm},
                                           {"user": "app", "vhost": "x", **perm}])})
    scope = {"vhosts": {"include": ["team-*", "/"]}}
    d = A.discover(session(), VHOST, scope)
    assert d.status == "complete" and {(r.id, r.system) for r in d.resources} == {
        ("/", True), ("team-a", False), ("team-p", True)}
    assert A.discover(session(tags=["management"]), VHOST, scope).status == "partial"
    users = {r.id: r for r in A.discover(session(), USER, scope).resources}
    assert users["app"].attrs == {"tags": [], "permissions": {"team-a": perm}} and users["ordivus"].system
    assert "SECRET" not in repr(users)
