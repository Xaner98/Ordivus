"""Grafana ohne Server: Validierung, Normalisierung, Sperren, Versionsprüfung, Discovery-Abbildung."""

import pytest

from ordivus.adapters import grafana
from ordivus.adapters.base import (
    COMPLETE,
    PARTIAL,
    AuthorizationError,
    Op,
    PermanentError,
    Resource,
    Secret,
)
from ordivus.adapters.grafana import FOLDER, SA, TEAM, GrafanaAdapter

TOKEN = "glsa_s3cr3t-token"
TARGET = {"endpoint": {"host": "grafana.example", "port": 3000, "tls": {}}}
ALL = {"teams:read": ["teams:*"], "folders:read": ["folders:*"], "serviceaccounts:read": ["serviceaccounts:*"]}


def fake(monkeypatch, routes, calls=None):
    """Ersetzt den HTTP-Aufruf; ``routes``: (Methode, Pfad) → (Status, JSON)."""
    def call(session, method, path, body=None, query=None):
        assert session.auth.reveal() == f"Bearer {TOKEN}"
        if calls is not None:
            calls.append((method, path, body, query))
        return routes[(method, path)]
    monkeypatch.setattr(grafana, "_call", call)


def connect_routes(version="12.2.0", user=None, perms=ALL, org=1):
    return {("GET", "/api/frontend/settings"): (200, {"buildInfo": {"version": version}}),
            ("GET", "/api/org"): (200, {"id": org}),
            ("GET", "/api/user"): (200, user or {"uid": "service-account:7", "name": "ordivus"}),
            ("GET", "/api/access-control/user/permissions"): (200, perms)}


def session(write=False, **kw):
    return grafana.Session("https://g", None, Secret(f"Bearer {TOKEN}"), 1, write, **kw)


def doc(kind, name, **spec):
    return {"kind": kind, "metadata": {"name": name}, "spec": spec}


@pytest.mark.parametrize("d, error", [
    (doc("Target", "t", endpoint={"host": "evil@h"}), "spec.endpoint.host"),
    (doc("Target", "t", endpoint={"host": "h"}, orgId=0), "orgId"),
    (doc("Target", "t", endpoint={"host": "h"}, username="a:b"), "username"),
    (doc("Target", "t", endpoint={"host": "h"}, scope={"users": {}}), "spec.scope.users"),
    (doc(FOLDER, "../x", title="t"), "folder uid"),
    (doc(FOLDER, "f"), "spec.title"),
    (doc(FOLDER, "f", title="t", permissions=[{"role": "Admin", "permission": "View"}]), "role must be"),
    (doc(FOLDER, "f", title="t", permissions=[{"team": "a", "permission": "Owner"}]), "permission must be"),
    (doc(FOLDER, "f", title="t", permissions=[{"team": "a", "role": "Viewer", "permission": "View"}]), "exactly"),
    (doc(FOLDER, "f", title="t",
         permissions=[{"team": "a", "permission": "View"}, {"team": "a", "permission": "Edit"}]), "duplicate"),
    (doc(TEAM, "t", members="alice"), "spec.members"),
    (doc(TEAM, "t", admins=["x"]), "unknown field spec.admins"),
    (doc(SA, "s", role="GrafanaAdmin"), "spec.role"),
    (doc(SA, "s", isDisabled="no"), "isDisabled"),
    (doc(SA, "s", tokens=[]), "unknown field spec.tokens"),
])
def test_validate_rejects(d, error):
    assert any(error in e for e in GrafanaAdapter().validate(d)), GrafanaAdapter().validate(d)


def test_validate_accepts_and_normalizes():
    a = GrafanaAdapter()
    assert a.validate(doc("Target", "t", endpoint={"host": "h", "port": 3000}, orgId=2, username="admin",
                          scope={"folders": {"include": ["team-*"]}})) == []
    folder = doc(FOLDER, "ops", title="Ops", permissions=[{"team": "ops", "permission": "Edit"},
                                                          {"role": "Viewer", "permission": "View"}])
    assert a.validate(folder) == []
    assert a.desired(folder).attrs["permissions"] == [{"role": "Viewer", "permission": "View"},
                                                      {"team": "ops", "permission": "Edit"}]
    assert a.desired(doc(TEAM, "t", members=["b", "a", "b"])).attrs == {"members": ["a", "b"]}
    assert a.desired(doc(SA, "s", role="Viewer")).attrs == {"role": "Viewer"}  # isDisabled nicht deklariert
    errors = a.validate_target({"scope": {"teams": {"include": ["ops-*"]}}}, [Resource(TEAM, "dev")])
    assert errors == ["GrafanaTeam 'dev' is outside spec.scope.teams"]


def test_check_privileged_protected_and_members(monkeypatch):
    a, s = GrafanaAdapter(), session(own_sa="ordivus")
    admin_folder = Resource(FOLDER, "f", {"permissions": [{"team": "ops", "permission": "Admin"}]})
    assert "allowPrivilegedGrants" in a.check(s, admin_folder)
    assert a.check(s, admin_folder, allow_privileged=True) is None
    assert "protected" in a.check(s, Resource(FOLDER, "General", {}), allow_privileged=True)
    assert "allowPrivilegedGrants" in a.check(s, Resource(SA, "x", {"role": "Admin"}))
    assert "protected" in a.check(s, Resource(SA, "ordivus", {"role": "Viewer"}), allow_privileged=True)

    fake(monkeypatch, {("GET", "/api/org/users/search"): (200, {"orgUsers": [{"login": "alice", "userId": 2}]})})
    assert a.check(s, Resource(TEAM, "t", {"members": ["alice"]})) is None
    assert "do not exist" in a.check(s, Resource(TEAM, "t", {"members": ["alice", "mallory"]}))
    fake(monkeypatch, {("GET", "/api/org/users/search"): (403, {"message": "denied"})})
    assert "org.users:read" in a.check(session(), Resource(TEAM, "t", {"members": ["alice"]}))


@pytest.mark.parametrize("routes, error", [
    (connect_routes(version="9.5.3"), r"Grafana 9\.5\.3 is not supported \(minimum 10\.0\)"),
    (connect_routes(version=""), "cannot read Grafana version"),
    (connect_routes(org=2), "expected orgId 1"),
])
def test_connect_rejects(monkeypatch, routes, error):
    fake(monkeypatch, routes)
    with pytest.raises(PermanentError, match=error):
        with GrafanaAdapter().connect(TARGET, Secret(TOKEN), write=False):
            pass


def test_connect_reads_identity_and_never_leaks_token(monkeypatch):
    fake(monkeypatch, connect_routes(version="12.2.0-security-01"))
    with GrafanaAdapter().connect(TARGET, Secret(TOKEN), write=False) as s:
        assert GrafanaAdapter().server_version(s) == "Grafana 12.2.0-security-01" and s.own_sa == "ordivus"
        assert TOKEN not in repr(s)
    fake(monkeypatch, {("GET", "/api/frontend/settings"): (401, {"message": "invalid API key"})})
    with pytest.raises(AuthorizationError) as e:
        with GrafanaAdapter().connect(TARGET, Secret(TOKEN), write=False):
            pass
    assert TOKEN not in str(e.value)


def test_read_only_session_never_sends_writes(monkeypatch):
    calls = []
    fake(monkeypatch, {}, calls)
    a, s = GrafanaAdapter(), session()
    with pytest.raises(PermanentError, match="read-only"):
        a.apply(s, Op("t", SA, "x", "CREATE", desired=Resource(SA, "x", {"role": "Viewer"})))
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(PermanentError, match="read-only"):
            grafana._request(s, method, "/api/teams", {})
    assert calls == []


def test_discover_maps_and_reports_partial(monkeypatch):
    acl = [{"isManaged": True, "teamId": 3, "team": "ops", "permission": "Edit"},
           {"isManaged": True, "builtInRole": "Viewer", "permission": "View"},
           {"isManaged": True, "userId": 1, "userLogin": "admin", "permission": "Admin"},  # Benutzer: nicht verwaltet
           {"isManaged": True, "isInherited": True, "builtInRole": "Editor", "permission": "Edit"},
           {"isManaged": False, "builtInRole": "Admin", "permission": "Admin"}]
    fake(monkeypatch, {
        ("GET", "/api/search"): (200, [{"uid": "ops"}, {"uid": "git"}, {"uid": "other"}]),
        ("GET", "/api/folders/ops"): (200, {"title": "Ops"}),
        ("GET", "/api/folders/git"): (200, {"title": "Git", "managedBy": "repo"}),
        ("GET", "/api/access-control/folders/ops"): (200, acl),
        ("GET", "/api/access-control/folders/git"): (200, []),
        ("GET", "/api/serviceaccounts/search"): (200, {"serviceAccounts": [
            {"name": "ordivus", "role": "Admin"}, {"name": "extsvc-x", "role": "Editor", "isExternal": True},
            {"name": "ci", "role": "Viewer", "isDisabled": True}]}),
        ("GET", "/api/teams/search"): (200, {"teams": [{"id": 3, "name": "ops", "email": "", "isProvisioned": True}]}),
        ("GET", "/api/teams/3/members"): (200, [{"login": "bob", "userId": 5}, {"login": "alice", "userId": 4}]),
    })
    a, scope = GrafanaAdapter(), {"folders": {"include": ["ops", "git"]}}
    folders = a.discover(session(permissions=ALL), FOLDER, scope)
    assert folders.status == COMPLETE
    ops, git = folders.resources
    assert ops.attrs == {"title": "Ops", "permissions": [{"role": "Viewer", "permission": "View"},
                                                         {"team": "ops", "permission": "Edit"}]}
    assert ops.manageable and not git.manageable
    sas = {r.id: r for r in a.discover(session(permissions=ALL, own_sa="ordivus"), SA, None).resources}
    assert sas["ordivus"].system and sas["extsvc-x"].system and not sas["ci"].system
    assert sas["ci"].attrs == {"role": "Viewer", "isDisabled": True}
    team = a.discover(session(permissions=ALL), TEAM, None).resources[0]
    assert team.attrs["members"] == ["alice", "bob"] and not team.manageable

    partial = a.discover(session(permissions={"folders:read": ["folders:uid:ops"]}), FOLDER, scope)
    assert partial.status == PARTIAL and "folders:read" in partial.reason


def test_paging_reads_all_pages(monkeypatch):
    monkeypatch.setattr(grafana, "PAGE", 2)
    pages = {1: [{"name": "a"}, {"name": "b"}], 2: [{"name": "c"}]}
    monkeypatch.setattr(grafana, "_call", lambda s, m, p, b=None, q=None: (200, {"serviceAccounts": pages[q["page"]]}))
    assert [x["name"] for x in grafana._paged(session(), "/x", "serviceAccounts")] == ["a", "b", "c"]
    monkeypatch.setattr(grafana, "_call", lambda *a: (200, {"other": []}))
    with pytest.raises(PermanentError, match="unexpected response"):
        grafana._paged(session(), "/x", "serviceAccounts")


def test_set_permissions_only_touches_team_and_role_entries(monkeypatch):
    calls = []
    fake(monkeypatch, {
        ("GET", "/api/access-control/folders/f"): (200, [
            {"isManaged": True, "teamId": 3, "team": "old", "permission": "Edit"},
            {"isManaged": True, "builtInRole": "Editor", "permission": "Edit"},
            {"isManaged": True, "userId": 1, "permission": "Admin"}]),
        ("GET", "/api/teams/search"): (200, {"teams": [{"id": 9, "name": "new"}]}),
        ("POST", "/api/access-control/folders/f/teams/3"): (200, {}),
        ("POST", "/api/access-control/folders/f/teams/9"): (200, {}),
        ("POST", "/api/access-control/folders/f/builtInRoles/Editor"): (200, {}),
    }, calls)
    GrafanaAdapter()._set_permissions(session(write=True), "f", [{"team": "new", "permission": "View"},
                                                                 {"role": "Editor", "permission": "Edit"}])
    writes = [(p, b) for m, p, b, _ in calls if m == "POST"]
    assert writes == [("/api/access-control/folders/f/teams/9", {"permission": "View"}),
                      ("/api/access-control/folders/f/teams/3", {"permission": ""})]
