"""Keycloak ohne Server: Validierung, Login/Re-Login, Versionsprüfung, Rechte-Klassifikation, Read-only."""

import pytest

from ordivus.adapters import keycloak
from ordivus.adapters.base import CREATE, AuthorizationError, Op, PermanentError, Resource, Secret
from ordivus.adapters.keycloak import KeycloakAdapter, Session

A = KeycloakAdapter()
TARGET = {"endpoint": {"host": "kc", "port": 8080}, "login": {"username": "admin"}}
PW = "s3cr3t-admin-pw"


def doc(kind, metadata_name, **spec):
    return {"kind": kind, "metadata": {"name": metadata_name}, "spec": spec}


def fake_http(routes, calls):
    """routes: (method, path) -> (status, payload) oder Liste davon (nacheinander)."""
    def http(base, context, method, path, headers, data=None, query=None):
        calls.append((method, path, headers, data))
        result = routes[(method, path)]
        return result.pop(0) if isinstance(result, list) else result
    return http


TOKEN = ("POST", "/realms/master/protocol/openid-connect/token")
ADMIN_ROUTES = {
    TOKEN: (200, {"access_token": "tok", "expires_in": 60}),
    ("GET", "/admin/serverinfo"): (200, {"systemInfo": {"version": "26.4.7"}}),
    ("GET", "/admin/realms/master/users"): (200, [{"id": "u1", "username": "admin"}]),
    ("GET", "/admin/realms/master/users/u1/role-mappings/realm/composite"): (200, [{"name": "admin"}]),
}


def test_validate():
    assert A.validate(doc("Target", "t", **TARGET)) == []
    assert A.validate(doc("Target", "t", endpoint={"host": "kc", "path": "/auth"},
                          login={"realm": "ops", "clientId": "ordivus"})) == []
    errors = A.validate(doc("Target", "t", endpoint={"host": "kc", "path": "auth/../x"},
                            login={"username": "a", "clientId": "b"}, scope={"users": {}}))
    assert len(errors) == 3
    assert A.validate(doc("KeycloakRealm", "bad/realm", enabled="yes", sslRequired="never", x=1)) == [
        "unknown field spec.x", "spec.enabled must be a bool",
        "metadata.name (realm) must match [A-Za-z0-9][A-Za-z0-9_.-]* (max 100)",
        "spec.sslRequired must be one of none, external, all"]
    assert A.validate(doc("KeycloakGroup", "g", realm="r", name="a/b"))
    assert A.validate(doc("KeycloakClient", "c", realm="r", protocol="saml"))
    assert A.validate(doc("KeycloakRealmRole", "r", name="x"))  # realm fehlt
    assert A.validate(doc("KeycloakRealmRole", "r", realm="r", composites=["a", 1]))


def test_desired_ids_and_lists():
    assert A.desired(doc("KeycloakRealmRole", "x", realm="r", name="viewer", composites=["b", "a", "a"])) == \
        Resource("KeycloakRealmRole", "r/viewer", {"composites": ["a", "b"]})
    assert A.desired(doc("KeycloakClient", "app", realm="r", enabled=True)).id == "r/app"
    assert A.desired(doc("KeycloakRealm", "r", enabled=True)) == Resource("KeycloakRealm", "r", {"enabled": True})


def test_validate_target():
    sa = {**TARGET, "login": {"realm": "ops", "clientId": "o"}, "scope": {"realms": {"include": ["ops", "x"]}}}
    resources = [Resource("KeycloakGroup", "x/g"), Resource("KeycloakRealm", "y"),
                 Resource("KeycloakClient", "ops/c", {"publicClient": True}, password_ref="cred")]
    errors = A.validate_target(sa, resources)
    assert len(errors) == 4 and "outside spec.scope.realms" in errors[1] and "confidential" in errors[3]


def test_connect_login_version_and_secret_handling(monkeypatch):
    calls = []
    monkeypatch.setattr(keycloak, "_http", fake_http(dict(ADMIN_ROUTES), calls))
    with A.connect(TARGET, Secret(PW), write=False) as s:
        assert A.server_version(s) == "Keycloak 26.4.7" and s.master_admin
    assert PW.encode() in calls[0][3]  # nur im Formular-Body des Token-Requests
    assert all(PW not in str(c[:3]) and (c[3] is None or PW.encode() not in c[3]) for c in calls[1:])
    assert all(c[2]["Authorization"] == "Bearer tok" for c in calls[1:])


def test_old_version_rejected(monkeypatch):
    routes = {**ADMIN_ROUTES, ("GET", "/admin/serverinfo"): (200, {"systemInfo": {"version": "22.0.5"}})}
    monkeypatch.setattr(keycloak, "_http", fake_http(routes, []))
    with pytest.raises(PermanentError, match=r"Keycloak 22.0.5 is not supported \(minimum 24\)"):
        with A.connect(TARGET, Secret(PW), write=False):
            pass


def test_login_failure_is_authorization_error_without_secret(monkeypatch):
    routes = {TOKEN: (401, {"error": "invalid_grant", "error_description": "Invalid user credentials"})}
    monkeypatch.setattr(keycloak, "_http", fake_http(routes, []))
    with pytest.raises(AuthorizationError) as e, A.connect(TARGET, Secret(PW), write=False):
        pass
    assert "invalid_grant" in str(e.value) and PW not in str(e.value)


def test_relogin_on_401_and_expiry(monkeypatch):
    calls = []
    routes = {TOKEN: (200, {"access_token": "new", "expires_in": 60}),
              ("GET", "/admin/realms"): [(401, None), (200, [{"realm": "master"}])]}
    monkeypatch.setattr(keycloak, "_http", fake_http(routes, calls))
    s = Session("http://kc", None, False, {"username": "admin"}, Secret(PW), token="old", expires=1e12)
    assert A._get(s, "/admin/realms") == [{"realm": "master"}]
    assert [c[1] for c in calls] == ["/admin/realms", TOKEN[1], "/admin/realms"] and s.token == "new"
    s.expires = 0  # abgelaufen: vor dem Request neu anmelden
    routes[("GET", "/admin/realms")] = (200, [])
    A._get(s, "/admin/realms")
    assert calls[-2][1] == TOKEN[1]


def test_read_only_refuses_writes_before_network(monkeypatch):
    monkeypatch.setattr(keycloak, "_http", lambda *a, **k: pytest.fail("network call"))
    s = Session("http://kc", None, False, {"username": "admin"}, Secret(PW), token="t", expires=1e12)
    with pytest.raises(PermanentError, match="read-only"):
        A._request(s, "DELETE", "/admin/realms/x")
    with pytest.raises(PermanentError, match="read-only"):
        A.apply(s, Op("t", "KeycloakRealm", "x", CREATE, desired=Resource("KeycloakRealm", "x")))


def session(**kw):
    s = Session("http://kc", None, False, {"username": "admin"}, Secret(PW), own_roles=frozenset({"admin"}), **kw)
    s.realms = [{"realm": "master"}, {"realm": "app"}]
    return s


def test_privilege_classification():
    s = session()
    s.roles_done.add("app")
    s.roles.update({("app", "ops"): {"composites": set(), "admin": True},          # realm-management-Rollen
                    ("app", "lead"): {"composites": {"ops"}, "admin": False},      # transitiv privilegiert
                    ("app", "odd"): {"composites": set(), "admin": None},          # Client-Rollen unklar
                    ("app", "viewer"): {"composites": set(), "admin": False}})

    def check(kind, id, allow=False, **attrs):
        return A.check(s, Resource(kind, id, attrs), allow)

    assert check("KeycloakGroup", "app/g", realmRoles=["viewer"]) is None
    assert "allowPrivilegedGrants" in check("KeycloakGroup", "app/g", realmRoles=["lead"])
    assert "allowPrivilegedGrants" in check("KeycloakRealmRole", "app/r", composites=["odd"])
    assert check("KeycloakGroup", "app/g", allow=True, realmRoles=["lead"]) is None
    assert "master realm" in check("KeycloakGroup", "master/g", realmRoles=["offline_access"])
    assert check("KeycloakGroup", "new/g", realmRoles=["x"]) is None  # Realm entsteht erst in diesem Lauf
    assert "protected" in check("KeycloakRealm", "master", allow=True)
    assert "protected" in check("KeycloakRealmRole", "app/default-roles-app", allow=True)
    assert "protected" in check("KeycloakClient", "app/realm-management", allow=True)
    assert "protected" in check("KeycloakClient", "master/app-realm", allow=True)
    s.roles_done.clear()  # Rollen nicht lesbar → unbekannt = privilegiert
    assert "could not be read" in check("KeycloakGroup", "app/g", realmRoles=["unknown"])


def test_partial_without_admin_permissions(monkeypatch):
    s = session(own_id="u1")
    s.own_roles = frozenset()
    s.login = {"realm": "app", "clientId": "ordivus"}
    s.realms = [{"realm": "app"}]
    routes = {("GET", "/admin/realms/app/clients"): (200, [{"id": "rm", "clientId": "realm-management",
                                                             "attributes": {"realm_client": "true"}}]),
              ("GET", "/admin/realms/app/users/u1/role-mappings/clients/rm/composite"): (200, [{"name": "view-users"}]),
              ("GET", "/admin/realms/app/groups"): (200, [{"name": "g", "realmRoles": ["b", "a"]}])}
    monkeypatch.setattr(keycloak, "_http", fake_http(routes, []))
    s.token, s.expires = "t", 1e12
    found = A.discover(s, "KeycloakGroup", None)
    assert found.status == "complete" and found.resources[0].attrs == {"realmRoles": ["a", "b"]}
    clients = A.discover(s, "KeycloakClient", None)  # view-clients fehlt → gefilterte Liste möglich
    assert clients.status == "partial" and "view-clients" in clients.reason
    assert A.discover(s, "KeycloakRealm", None).status == "partial"


@pytest.mark.parametrize("payload", [None, {"x": 1}, [{"no": "name"}], [1]])
def test_discover_rejects_bad_shapes(monkeypatch, payload):
    s = session()
    s.token, s.expires = "t", 1e12
    monkeypatch.setattr(keycloak, "_http", fake_http({("GET", "/admin/realms/app/groups"): (200, payload)}, []))
    with pytest.raises(PermanentError, match="unexpected response"):
        A.discover(s, "KeycloakGroup", {"realms": {"include": ["app"]}})
