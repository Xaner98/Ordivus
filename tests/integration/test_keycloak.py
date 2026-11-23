"""Integration gegen einen echten Keycloak-Container (ordivus-it-keycloak, Port 18080).

Start: docker run -d --name ordivus-it-keycloak -p 127.0.0.1:18080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=adminpw-it \
  quay.io/keycloak/keycloak:26.4 start-dev
"""

import json
import logging
import os
import secrets

import pytest

from ordivus.adapters.base import CREATE, AuthorizationError, Op, PermanentError, Resource, Secret
from ordivus.adapters.keycloak import KeycloakAdapter
from ordivus.core import config, engine
from ordivus.core.config import ConfigError
from ordivus.core.policy import OperatorPolicy

HOST = os.environ.get("ORDIVUS_TEST_HOST", "localhost")
PORT = int(os.environ.get("ORDIVUS_KEYCLOAK_PORT", "18080"))
ADMIN_PW = os.environ.get("ORDIVUS_KEYCLOAK_ADMIN_PASSWORD", "adminpw-it")
ENDPOINT = {"host": HOST, "port": PORT}
TARGET = {"endpoint": ENDPOINT, "login": {"username": "admin"}}
MUTATING = set(engine.MUTATING)


@pytest.fixture(scope="module")
def admin():
    """Write-Session als Bootstrap-Admin für Vorbereitung und Prüfungen (direkt über den Adapter-Transport)."""
    adapter = KeycloakAdapter()
    try:
        with adapter.connect(TARGET, Secret(ADMIN_PW), write=True) as session:
            yield lambda method, path, body=None, query=None, ok=(): adapter._request(
                session, method, path, body, query, ok)
    except Exception as e:
        pytest.skip(f"Keycloak not reachable at {HOST}:{PORT}: {type(e).__name__}: {e}")


@pytest.fixture
def realm(admin):
    """Eindeutiger Realm je Test; wird danach gelöscht (samt allem darin)."""
    name = f"it{secrets.token_hex(3)}"
    yield name
    admin("DELETE", f"/admin/realms/{name}", ok=(404,))


def doc(kind, metadata_name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": metadata_name}, "spec": spec}


@pytest.fixture
def cfg(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "admin").write_text(ADMIN_PW)

    def write(*extra, target=None):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        auth = {"credentialRef": "admin"}
        docs = [doc("Target", "kc", adapter="keycloak", **(target or TARGET), authentication=auth),
                doc("CredentialProvider", "files", type="file", directory=str(secrets_dir)),
                doc("Credential", "admin", providerRef="files", path="admin"), *extra]
        for d in docs:
            if d["kind"].startswith("Keycloak"):
                d["spec"].setdefault("targetRef", "kc")
        for i, d in enumerate(docs):
            (directory / f"{i:02}.json").write_text(json.dumps(d))
        return directory

    write.secrets = secrets_dir
    return write


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def actions(rep):
    return {(o["kind"], o["id"], o["action"]) for o in rep["operations"]}


def mutations(rep):
    return [o for o in rep["operations"] if o["action"] in MUTATING]


def client(admin, realm, client_id):
    found = [c for c in admin("GET", f"/admin/realms/{realm}/clients", query={"clientId": client_id})
             if c["clientId"] == client_id]
    return found[0] if found else None


def client_secret(admin, realm, client_id):
    return admin("GET", f"/admin/realms/{realm}/clients/{client(admin, realm, client_id)['id']}/client-secret")["value"]


def app(realm, cred="app-secret", policy="verify", **spec):
    return [doc("Credential", cred, providerRef="files", path=cred),
            doc("KeycloakClient", f"{realm}-app", realm=realm, clientId="app", publicClient=False,
                credentials={"credentialRef": cred, "passwordPolicy": policy}, **spec)]


def test_plan_apply_converge(realm, admin, cfg, caplog):
    caplog.set_level(logging.DEBUG)
    canary = f"CANARY-{secrets.token_hex(8)}"
    path = cfg(doc("KeycloakRealm", realm, enabled=True, displayName="IT Realm"),
               doc("KeycloakRealmRole", f"{realm}-viewer", realm=realm, name="viewer", description="read"),
               doc("KeycloakRealmRole", f"{realm}-editor", realm=realm, name="editor", composites=["viewer"]),
               doc("KeycloakGroup", f"{realm}-editors", realm=realm, name="editors", realmRoles=["editor", "viewer"]),
               *app(realm, redirectUris=["https://app.example/*", "https://app.example/*"],
                    webOrigins=["https://app.example"], standardFlowEnabled=True, directAccessGrantsEnabled=False))
    (cfg.secrets / "app-secret").write_text(canary)

    plan = run(path, "plan")
    assert {("KeycloakRealm", realm, "CREATE"), ("KeycloakRealmRole", f"{realm}/editor", "CREATE"),
            ("KeycloakGroup", f"{realm}/editors", "CREATE"), ("KeycloakClient", f"{realm}/app", "CREATE")} \
        <= actions(plan)
    assert realm not in {r["realm"] for r in admin("GET", "/admin/realms")}

    first = run(path, "apply")
    assert all(o["status"] == "succeeded" for o in mutations(first)), first["operations"]
    assert admin("GET", f"/admin/realms/{realm}")["displayName"] == "IT Realm"
    assert [r["name"] for r in admin("GET", f"/admin/realms/{realm}/roles/editor/composites")] == ["viewer"]
    group = admin("GET", f"/admin/realms/{realm}/groups", query={"briefRepresentation": "false"})[0]
    assert sorted(group["realmRoles"]) == ["editor", "viewer"]
    assert client(admin, realm, "app")["redirectUris"] == ["https://app.example/*"]
    assert client_secret(admin, realm, "app") == canary

    second = run(path, "apply")
    assert not mutations(second), second["operations"]
    assert run(path, "drift")["targets"][0]["status"] == "in_sync"
    for rep in (plan, first, second):
        assert canary not in json.dumps(rep) and ADMIN_PW not in json.dumps(rep)
    assert canary not in caplog.text and ADMIN_PW not in caplog.text


def test_update_keeps_undeclared_fields(realm, admin, cfg):
    admin("POST", "/admin/realms", {"realm": realm, "enabled": True, "webAuthnPolicyRpEntityName": "custom-rp",
                                    "displayName": "old"})
    admin("POST", f"/admin/realms/{realm}/clients", {"clientId": "web", "description": "keep me",
                                                     "redirectUris": ["https://old/*"], "publicClient": True})
    admin("POST", f"/admin/realms/{realm}/roles", {"name": "r", "description": "keep", "attributes": {"a": ["1"]}})
    admin("POST", f"/admin/realms/{realm}/roles", {"name": "other"})
    path = cfg(doc("KeycloakRealm", realm, displayName="new"),
               doc("KeycloakClient", "web", realm=realm, clientId="web", redirectUris=["https://new/*"]),
               doc("KeycloakRealmRole", "r", realm=realm, name="r", composites=["other"]))
    rep = run(path, "apply")
    assert {("KeycloakRealm", realm, "UPDATE"), ("KeycloakClient", f"{realm}/web", "UPDATE"),
            ("KeycloakRealmRole", f"{realm}/r", "UPDATE")} <= actions(rep)
    realm_rep = admin("GET", f"/admin/realms/{realm}")
    assert realm_rep["displayName"] == "new" and realm_rep["webAuthnPolicyRpEntityName"] == "custom-rp"
    web = client(admin, realm, "web")
    assert web["redirectUris"] == ["https://new/*"] and web["description"] == "keep me" and web["publicClient"]
    role = admin("GET", f"/admin/realms/{realm}/roles/r")
    assert role["description"] == "keep" and role["attributes"] == {"a": ["1"]}
    assert not mutations(run(path, "apply"))


@pytest.mark.parametrize("policy", ["verify", "enforce", "set-on-create"])
def test_client_secret_policies(realm, admin, cfg, policy):
    admin("POST", "/admin/realms", {"realm": realm, "enabled": True})
    path = cfg(*app(realm, policy=policy))
    (cfg.secrets / "app-secret").write_text("declared-secret-1")
    run(path, "apply")
    assert client_secret(admin, realm, "app") == "declared-secret-1"
    uuid = client(admin, realm, "app")["id"]
    admin("POST", f"/admin/realms/{realm}/clients/{uuid}/client-secret")  # außerhalb rotiert
    plan = actions(run(path, "plan"))
    expected = policy != "set-on-create"
    assert (("KeycloakClient", f"{realm}/app", "SET_PASSWORD") in plan) == expected
    run(path, "apply")
    assert (client_secret(admin, realm, "app") == "declared-secret-1") == expected
    if policy == "verify":
        assert not mutations(run(path, "apply"))


def test_secret_absent_generated(realm, admin, cfg):
    admin("POST", "/admin/realms", {"realm": realm, "enabled": True})
    rep = run(cfg(*app(realm, cred="gen")), "apply")
    assert {("Credential", "gen", "CREATE_SECRET"), ("KeycloakClient", f"{realm}/app", "CREATE")} <= actions(rep)
    assert client_secret(admin, realm, "app") == (cfg.secrets / "gen").read_text()


def test_privileged_blocked(realm, admin, cfg):
    admin("POST", "/admin/realms", {"realm": realm, "enabled": True})
    rm = client(admin, realm, "realm-management")["id"]
    realm_admin = admin("GET", f"/admin/realms/{realm}/clients/{rm}/roles/realm-admin")
    admin("POST", f"/admin/realms/{realm}/roles", {"name": "ops"})
    admin("POST", f"/admin/realms/{realm}/roles/ops/composites", [realm_admin])
    admin("POST", f"/admin/realms/{realm}/clients", {"clientId": "bot", "publicClient": False,
                                                     "serviceAccountsEnabled": True})
    bot = admin("GET", f"/admin/realms/{realm}/clients/{client(admin, realm, 'bot')['id']}/service-account-user")
    admin("POST", f"/admin/realms/{realm}/users/{bot['id']}/role-mappings/clients/{rm}", [realm_admin])
    path = cfg(doc("KeycloakGroup", "g", realm=realm, name="admins", realmRoles=["ops"]),
               doc("KeycloakRealmRole", "super", realm=realm, name="super", composites=["ops"]),
               doc("KeycloakClient", "bot", realm=realm, clientId="bot", redirectUris=["https://bot/*"]),
               doc("KeycloakGroup", "m", realm="master", name=f"{realm}-m", realmRoles=["offline_access"]),
               doc("KeycloakRealm", "master", displayName="x"),
               doc("KeycloakClient", "acct", realm=realm, clientId="account", enabled=False),
               doc("KeycloakRealmRole", "dr", realm=realm, name=f"default-roles-{realm}", description="x"))
    try:
        rep = run(path, "apply")
        blocked = {o["id"]: o["reason"] for o in rep["operations"] if o["action"] == "BLOCKED"}
        for id in (f"{realm}/admins", f"{realm}/super", f"{realm}/bot", f"master/{realm}-m"):
            assert "allowPrivilegedGrants" in blocked[id], blocked
        for id in ("master", f"{realm}/account", f"{realm}/default-roles-{realm}"):
            assert "protected" in blocked[id], blocked
        assert not admin("GET", f"/admin/realms/{realm}/groups")
        assert admin("GET", "/admin/realms/master")["displayName"] != "x"

        rep = run(path, "apply", allowPrivilegedGrants=True)
        blocked = {o["id"] for o in rep["operations"] if o["action"] == "BLOCKED"}
        assert blocked == {"master", f"{realm}/account", f"{realm}/default-roles-{realm}"}
        assert [g["name"] for g in admin("GET", f"/admin/realms/{realm}/groups")] == ["admins"]
    finally:
        for g in admin("GET", "/admin/realms/master/groups", query={"search": f"{realm}-m"}):
            admin("DELETE", f"/admin/realms/master/groups/{g['id']}", ok=(404,))


def test_read_only_session_cannot_mutate(realm, admin):
    adapter = KeycloakAdapter()
    with adapter.connect(TARGET, Secret(ADMIN_PW), write=False) as session:
        with pytest.raises(PermanentError):
            adapter.apply(session, Op("kc", "KeycloakRealm", realm, CREATE,
                                      desired=Resource("KeycloakRealm", realm, {"enabled": True})))
        with pytest.raises(PermanentError, match="read-only"):
            adapter._request(session, "POST", "/admin/realms", {"realm": realm})
        session.expires = 0  # Re-Login ist auch read-only erlaubt
        assert adapter.discover(session, "KeycloakRealm", None).status == "complete"
    assert realm not in {r["realm"] for r in admin("GET", "/admin/realms")}


def test_relogin_on_expired_or_rejected_token(admin):
    adapter = KeycloakAdapter()
    with adapter.connect(TARGET, Secret(ADMIN_PW), write=False) as session:
        session.token = "invalid"  # 401 → einmal neu anmelden, dann erfolgreich
        assert adapter.discover(session, "KeycloakRealm", None).resources


def test_scope_and_authoritative_delete(realm, admin, cfg):
    admin("POST", "/admin/realms", {"realm": realm, "enabled": True})
    for name in ("keep", "stray", "app_x"):
        admin("POST", f"/admin/realms/{realm}/roles", {"name": name})
    scope = {"realms": {"include": [realm]}, "roles": {"include": ["keep", "stray"]}}
    target = {**TARGET, "scope": scope}
    adapter = KeycloakAdapter()
    with adapter.connect(target, Secret(ADMIN_PW), write=False) as session:
        assert {r.id for r in adapter.discover(session, "KeycloakRealm", scope).resources} == {realm}
        assert {r.id for r in adapter.discover(session, "KeycloakRealmRole", scope).resources} == {
            f"{realm}/keep", f"{realm}/stray"}
    with pytest.raises(ConfigError, match="outside spec.scope.realms"):
        engine.prepare(config.load(cfg(doc("KeycloakRealmRole", "x", realm="master", name="x"), target=target)))
    gov = doc("ReconciliationPolicy", "gov", targetRef="kc", mode="authoritative",
              scope={"resourceKinds": ["KeycloakRealmRole"], "KeycloakRealmRole": {"glob": [f"{realm}/*"]}})
    path = cfg(gov, doc("KeycloakRealmRole", "keep", realm=realm, name="keep"), target=target)
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    assert {i for k, i, a in actions(rep) if a == "DELETE"} == {f"{realm}/stray"}
    names = {r["name"] for r in admin("GET", f"/admin/realms/{realm}/roles")}
    assert "stray" not in names and {"keep", "app_x"} <= names


def test_service_account_login(realm, admin, cfg):
    """Client Credentials in einem Nicht-master-Realm: vollständige Discovery, eigener Client geschützt."""
    admin("POST", "/admin/realms", {"realm": realm, "enabled": True})
    admin("POST", f"/admin/realms/{realm}/clients", {"clientId": "ordivus", "publicClient": False,
                                                     "serviceAccountsEnabled": True, "secret": "sa-secret-123"})
    rm = client(admin, realm, "realm-management")["id"]
    sa = admin("GET", f"/admin/realms/{realm}/clients/{client(admin, realm, 'ordivus')['id']}/service-account-user")
    roles = [admin("GET", f"/admin/realms/{realm}/clients/{rm}/roles/{r}")
             for r in ("manage-realm", "manage-users", "manage-clients", "view-users")]
    admin("POST", f"/admin/realms/{realm}/users/{sa['id']}/role-mappings/clients/{rm}", roles)
    target = {"endpoint": ENDPOINT, "login": {"realm": realm, "clientId": "ordivus"}}
    adapter = KeycloakAdapter()
    with adapter.connect(target, Secret("sa-secret-123"), write=False) as session:
        assert adapter.discover(session, "KeycloakRealm", None).status == "partial"
        for kind in ("KeycloakRealmRole", "KeycloakGroup", "KeycloakClient"):
            assert adapter.discover(session, kind, None).status == "complete", kind
        own = Resource("KeycloakClient", f"{realm}/ordivus", {"enabled": False})
        assert "protected" in adapter.check(session, own, allow_privileged=True)
    (cfg.secrets / "admin").write_text("sa-secret-123")
    path = cfg(doc("KeycloakGroup", "g", realm=realm, name="team"), target=target)
    assert ("KeycloakGroup", f"{realm}/team", "CREATE") in actions(run(path, "apply"))
    with pytest.raises(ConfigError, match="can only manage that realm"):
        engine.prepare(config.load(cfg(doc("KeycloakGroup", "g", realm="other", name="team"), target=target)))
    with pytest.raises(AuthorizationError, match="login"), adapter.connect(target, Secret("wrong"), write=False):
        pass


def test_export_roundtrip(realm, admin, cfg, tmp_path):
    from roundtrip import assert_export_roundtrip

    run(cfg(doc("KeycloakRealm", realm, enabled=True, displayName="IT Realm"),
            doc("KeycloakRealmRole", f"{realm}-reader", realm=realm, name="reader", description="reads"),
            doc("KeycloakGroup", f"{realm}-staff", realm=realm, name="staff", realmRoles=["reader"]),
            *app(realm, redirectUris=["https://app.example.org/*"])), "apply")
    admin("POST", f"/admin/realms/{realm}/roles", {"name": "grown", "composite": False})
    admin("POST", f"/admin/realms/{realm}/clients", {"clientId": "spa", "publicClient": True,
                                                       "webOrigins": ["+"], "redirectUris": ["/x"]})
    target = {**TARGET, "scope": {"realms": {"include": [realm]}}}
    assert_export_roundtrip(cfg(target=target), {
        ("KeycloakRealm", realm), ("KeycloakRealmRole", f"{realm}/reader"), ("KeycloakRealmRole", f"{realm}/grown"),
        ("KeycloakGroup", f"{realm}/staff"), ("KeycloakClient", f"{realm}/app"), ("KeycloakClient", f"{realm}/spa")},
        tmp_path)
