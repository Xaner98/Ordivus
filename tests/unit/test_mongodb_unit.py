"""MongoDB-Adapter ohne Server: Validierung, Normalisierung, Privilegien-Regeln, Fehlerbereinigung."""

import pytest

from ordivus.adapters.base import AuthorizationError, PermanentError, Resource, Secret, TransientError
from ordivus.adapters.mongodb import MongoDBAdapter, _builtin_privileged, _dangerous, _error, _version

A = MongoDBAdapter()
TARGET = {"endpoint": {"host": "mongo", "user": "ordivus"}}


def doc(kind, meta="x", **spec):
    return {"kind": kind, "metadata": {"name": meta}, "spec": spec}


def test_target_validation():
    assert A.validate(doc("Target", **TARGET)) == []
    full = {"endpoint": {"host": "m", "port": 27018, "user": "u", "authDatabase": "ops", "replicaSet": "rs0",
                         "tls": {"caFile": "/ca.pem"}}, "scope": {"databases": {"include": ["app*"]}}}
    assert A.validate(doc("Target", **full)) == []
    errors = A.validate(doc("Target", endpoint={"host": "a,b", "user": "", "authDatabase": "a.b", "x": 1},
                            scope={"roles": {}}))
    assert any("unknown field spec.endpoint.x" in e for e in errors)
    assert any("',' or ':'" in e for e in errors) and any("endpoint.user" in e for e in errors)
    assert any("authDatabase" in e for e in errors) and any("spec.scope.roles" in e for e in errors)
    assert any("host" in e for e in A.validate(doc("Target", endpoint={"host": "mongodb://u:p@h", "user": "u"})))


def test_resource_validation():
    assert A.validate(doc("DatabaseUser", database="app", roles=["r", {"role": "read", "db": "other"}])) == []
    good = [{"resource": {"db": "app", "collection": ""}, "actions": ["find"]},
            {"resource": {"cluster": True}, "actions": ["serverStatus"]}]
    assert A.validate(doc("DatabaseRole", database="admin", privileges=good)) == []
    assert len(A.validate(doc("DatabaseRole", database="app", privileges=good))) == 1  # cluster nur in admin
    assert any("required" in e for e in A.validate(doc("DatabaseUser")))
    assert A.validate(doc("DatabaseRole", database="admin", roles=[{"role": "read", "db": "app"}])) == []
    assert any("other databases" in e for e in A.validate(
        doc("DatabaseRole", database="app", roles=[{"role": "read", "db": "admin"}])))
    assert any("does not allow" in e for e in A.validate(doc("DatabaseUser", database="local")))
    assert any("unknown field spec.privileges" in e for e in A.validate(doc("DatabaseUser", database="a",
                                                                            privileges=[])))
    bad = [{"resource": {"anyResource": True}, "actions": ["find"]},
           {"resource": {"db": "a", "collection": "c"}, "actions": []},
           {"resource": {"db": "a.b", "collection": "c"}, "actions": ["find; drop"]}, {"resource": 5, "actions": ["x"]}]
    errors = A.validate(doc("DatabaseRole", database="admin", privileges=bad, roles=[{"role": "r", "x": 1}, 3]))
    assert len([e for e in errors if "resource" in e]) == 3 and len([e for e in errors if "actions" in e]) == 2
    assert len([e for e in errors if "spec.roles" in e]) == 2


def test_desired_normalization():
    r = A.desired(doc("DatabaseRole", "rr", database="app", roles=["b", "a", {"role": "a", "db": "app"}],
                      privileges=[{"resource": {"db": "app", "collection": "c"}, "actions": ["insert"]},
                                  {"resource": {"collection": "c", "db": "app"}, "actions": ["find", "insert"]}]))
    assert r.id == "app.rr"
    assert r.attrs == {"roles": [{"db": "app", "role": "a"}, {"db": "app", "role": "b"}],
                       "privileges": [{"resource": {"collection": "c", "db": "app"}, "actions": ["find", "insert"]}]}
    u = A.desired(doc("DatabaseUser", "meta", name="u.with.dots", database="admin"))
    assert u.id == "admin.u.with.dots" and u.attrs == {}
    assert A.dependencies(A.desired(doc("DatabaseUser", database="app", roles=["read", "custom"]))) == [
        ("DatabaseRole", "app.custom")]


def test_validate_target_requires_credentials():
    errors = A.validate_target({}, [Resource("DatabaseUser", "app.a"), Resource("DatabaseUser", "app.b",
                                                                              password_ref="pw")])
    assert errors == ["DatabaseUser 'app.a' needs spec.credentials (MongoDB users require a password)"]


@pytest.mark.parametrize("db, role, privileged", [
    ("app", "read", False), ("app", "readWrite", False), ("app", "dbOwner", False), ("admin", "read", False),
    ("admin", "clusterMonitor", False), ("app", "custom", False),
    ("admin", "root", True), ("admin", "dbOwner", True), ("admin", "userAdmin", True), ("config", "readWrite", True),
    ("admin", "readWriteAnyDatabase", True), ("admin", "clusterAdmin", True), ("admin", "backup", True),
    ("admin", "restore", True), ("admin", "readAnyDatabase", True),
])
def test_builtin_privileged(db, role, privileged):
    assert _builtin_privileged(db, role) is privileged


@pytest.mark.parametrize("resource, actions, privileged", [
    ({"db": "app", "collection": ""}, ["find", "insert", "update"], False),
    ({"db": "app", "collection": "c"}, ["dropCollection"], False),
    ({"cluster": True}, ["serverStatus"], True),
    ({"anyResource": True}, ["find"], True),
    ({"db": "", "collection": ""}, ["find"], True),
    ({"db": "admin", "collection": "x"}, ["find"], True),
    ({"db": "local", "collection": "oplog.rs"}, ["find"], True),
    ({"db": "app", "collection": "system.js"}, ["find"], True),
    ({"db": "app", "collection": ""}, ["createUser"], True),
    ({"db": "app", "collection": ""}, ["grantRole"], True),
    ({"db": "app", "system_buckets": "x"}, ["find"], True),
])
def test_dangerous_privileges(resource, actions, privileged):
    assert (_dangerous({"resource": resource, "actions": actions}) is not None) is privileged


def test_version():
    assert _version("8.0.4") == "MongoDB 8.0.4"
    assert _version("6.0.0") == "MongoDB 6.0.0"
    with pytest.raises(PermanentError, match=r"MongoDB 5.0.9 is not supported \(minimum 6.0\)"):
        _version("5.0.9")
    with pytest.raises(PermanentError, match="cannot parse"):
        _version(None)


def test_errors_never_echo_commands_or_secrets():
    pymongo = pytest.importorskip("pymongo")
    from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

    secret = Secret("s3cr3t-pw")
    echo = OperationFailure("x", 13, {"errmsg": 'not authorized on app to execute command { createUser: "u", '
                                                 'pwd: "s3cr3t-pw" }', "code": 13, "codeName": "Unauthorized"})
    e = _error(echo, [secret])
    assert isinstance(e, AuthorizationError) and "s3cr3t" not in str(e) and "{" not in str(e)
    assert str(e) == "Unauthorized (13): not authorized on app to execute command"
    e = _error(OperationFailure("x", 2, {"errmsg": "bad s3cr3t-pw", "codeName": "BadValue"}), [secret])
    assert isinstance(e, PermanentError) and str(e) == "BadValue (2): bad ***"
    assert isinstance(_error(OperationFailure("x", 10107, {"errmsg": "not primary"})), TransientError)
    assert isinstance(_error(ServerSelectionTimeoutError("timeout")), TransientError)
    assert pymongo


def test_read_only_session_refuses_apply():
    from ordivus.adapters.base import CREATE, Op
    from ordivus.adapters.mongodb import Session

    session = Session(None, TARGET, False, "MongoDB 8.0.0", ("admin", "ordivus"), frozenset())
    with pytest.raises(PermanentError, match="read-only"):
        A.apply(session, Op("t", "DatabaseRole", "app.r", CREATE, desired=Resource("DatabaseRole", "app.r")))


def test_protected_names_blocked_even_with_policy():
    from ordivus.adapters.mongodb import Session

    session = Session(None, {**TARGET, "scope": {"databases": {"include": ["app", "admin"]}}}, False, "", (
        "admin", "ordivus"), frozenset())
    check = lambda kind, rid, **attrs: A.check(session, Resource(kind, rid, attrs), allow_privileged=True)  # noqa: E731
    assert "protected" in check("DatabaseUser", "admin.ordivus")
    assert "protected" in check("DatabaseUser", "app.__system")
    assert "built-in" in check("DatabaseRole", "app.read")
    assert "outside spec.scope" in check("DatabaseUser", "other.u")
    assert "outside spec.scope" in check("DatabaseUser", "app.u", roles=[{"db": "other", "role": "read"}])
    assert "never granted" in check("DatabaseUser", "app.u", roles=[{"db": "admin", "role": "__system"}])
    assert check("DatabaseUser", "app.u", roles=[{"db": "admin", "role": "root"}]) is None
    assert "allowPrivilegedGrants" in A.check(session, Resource("DatabaseUser", "app.u", {
        "roles": [{"db": "admin", "role": "root"}]}))
