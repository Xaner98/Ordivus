"""Integration gegen einen echten Grafana-Container (ordivus-it-grafana, Port 13000).

Start: docker run -d --name ordivus-it-grafana -p 127.0.0.1:13000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=adminpw-it grafana/grafana:12.2.0
"""

import base64
import json
import logging
import os
import secrets

import pytest

from ordivus.adapters import grafana
from ordivus.adapters.base import CREATE, PARTIAL, Op, PermanentError, Resource, Secret
from ordivus.adapters.grafana import GrafanaAdapter
from ordivus.core import config, engine
from ordivus.core.config import ConfigError
from ordivus.core.policy import OperatorPolicy

HOST = os.environ.get("ORDIVUS_TEST_HOST", "localhost")
PORT = int(os.environ.get("ORDIVUS_GRAFANA_PORT", "13000"))
ADMIN_PW = os.environ.get("ORDIVUS_GRAFANA_ADMIN_PASSWORD", "adminpw-it")
TARGET = {"endpoint": {"host": HOST, "port": PORT}, "username": "admin"}
MUTATING = set(engine.MUTATING)
ADMIN = grafana.Session(f"http://{HOST}:{PORT}", None,
                        Secret("Basic " + base64.b64encode(f"admin:{ADMIN_PW}".encode()).decode()), 1, True)


def api(method, path, body=None, query=None):
    return grafana._call(ADMIN, method, path, body, query)[1]


def teams():
    return {t["name"]: t for t in api("GET", "/api/teams/search", query={"perpage": 1000})["teams"]}


def members(name):
    return sorted(m["login"] for m in api("GET", f"/api/teams/{teams()[name]['id']}/members"))


def folders():
    return {f["uid"]: f for f in api("GET", "/api/search", query={"type": "dash-folder", "limit": 1000})}


def folder_perms(uid):
    return grafana._perms(api("GET", f"/api/access-control/folders/{uid}"))


def accounts():
    return {s["name"]: s for s in api("GET", "/api/serviceaccounts/search", query={"perpage": 1000})["serviceAccounts"]}


def token(name, role):
    sa = api("POST", "/api/serviceaccounts", {"name": name, "role": role})
    return api("POST", f"/api/serviceaccounts/{sa['id']}/tokens", {"name": "t"})["key"]


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


@pytest.fixture
def p():
    """Eindeutiges Präfix je Test; räumt danach alle Objekte und Benutzer mit diesem Präfix ab."""
    try:
        if not isinstance(api("GET", "/api/org"), dict) or api("GET", "/api/org").get("id") != 1:
            pytest.skip("Grafana admin login failed")
    except Exception as e:
        pytest.skip(f"Grafana not reachable at {ADMIN.base}: {type(e).__name__}")
    prefix = f"it{secrets.token_hex(3)}-"
    yield prefix
    for name, t in teams().items():
        if name.startswith(prefix):
            api("DELETE", f"/api/teams/{t['id']}")
    for uid in folders():
        if uid.startswith(prefix):
            api("DELETE", f"/api/folders/{uid}")
    for name, s in accounts().items():
        if name.startswith(prefix):
            api("DELETE", f"/api/serviceaccounts/{s['id']}")
    for u in api("GET", "/api/users/search", query={"query": prefix})["users"]:
        api("DELETE", f"/api/admin/users/{u['id']}")


def user(login):
    api("POST", "/api/admin/users", {"login": login, "email": f"{login}@example.invalid", "password": "pw-" + login})
    return login


@pytest.fixture
def cfg(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "admin").write_text(ADMIN_PW)

    def write(*extra, target=TARGET):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        docs = [doc("Target", "gf", adapter="grafana", **target, authentication={"credentialRef": "admin"}),
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


def mutations(rep):
    return [o for o in rep["operations"] if o["action"] in MUTATING]


def test_plan_apply_converge_drift(p, cfg, caplog):
    caplog.set_level(logging.DEBUG)
    alice, bob = user(f"{p}alice"), user(f"{p}bob")
    team, uid, sa = f"{p}ops", f"{p}fold", f"{p}deployer"
    path = cfg(doc("GrafanaTeam", team, targetRef="gf", email="ops@example.invalid", members=[alice, bob]),
               doc("GrafanaFolder", uid, targetRef="gf", title=f"{p} Ops",
                   permissions=[{"team": team, "permission": "Edit"}, {"role": "Viewer", "permission": "View"}]),
               doc("GrafanaServiceAccount", sa, targetRef="gf", role="Editor"))

    plan = run(path, "plan")
    assert {("GrafanaTeam", team, "CREATE"), ("GrafanaFolder", uid, "CREATE"),
            ("GrafanaServiceAccount", sa, "CREATE")} <= actions(plan)
    assert plan["targets"][0]["serverVersion"].startswith("Grafana ")
    assert team not in teams() and uid not in folders() and sa not in accounts()

    first = run(path, "apply")
    assert all(o["status"] == "succeeded" for o in mutations(first)), first["operations"]
    assert members(team) == [alice, bob]  # der anlegende admin wurde wieder entfernt
    # Grafana setzt beim Anlegen Editor:Edit; nicht deklariert → entfernt
    assert folder_perms(uid) == [{"role": "Viewer", "permission": "View"}, {"team": team, "permission": "Edit"}]
    assert accounts()[sa]["role"] == "Editor" and accounts()[sa]["isDisabled"] is False

    assert not mutations(run(path, "apply"))
    # Drift von Hand: Mitglied entfernt, Titel geändert, Service Account deaktiviert
    api("DELETE", f"/api/teams/{teams()[team]['id']}/members/"
                  f"{api('GET', '/api/users/lookup', query={'loginOrEmail': bob})['id']}")
    api("PUT", f"/api/folders/{uid}", {"title": "renamed by hand", "overwrite": True})
    api("PATCH", f"/api/serviceaccounts/{accounts()[sa]['id']}", {"isDisabled": True})
    drift = run(path, "drift")
    assert {("GrafanaTeam", team, "UPDATE"), ("GrafanaFolder", uid, "UPDATE")} <= actions(drift)
    assert ("GrafanaServiceAccount", sa, "NOOP") in actions(drift)  # isDisabled nicht deklariert: nicht verwaltet
    run(path, "apply")
    assert members(team) == [alice, bob] and folders()[uid]["title"] == f"{p} Ops"
    assert accounts()[sa]["isDisabled"] is True
    for rep in (plan, first, drift):
        assert ADMIN_PW not in json.dumps(rep)
    assert ADMIN_PW not in caplog.text


def test_unknown_member_blocked(p, cfg):
    team = f"{p}t"
    rep = run(cfg(doc("GrafanaTeam", team, targetRef="gf", members=[f"{p}nobody"])), "apply")
    op = next(o for o in rep["operations"] if o["id"] == team)
    assert op["action"] == "BLOCKED" and "does not create users" in op["reason"] and team not in teams()


def test_privileged_blocked_and_allowed(p, cfg):
    uid, sa = f"{p}adm", f"{p}admin-sa"
    path = cfg(doc("GrafanaFolder", uid, targetRef="gf", title="adm",
                   permissions=[{"role": "Editor", "permission": "Admin"}]),
               doc("GrafanaServiceAccount", sa, targetRef="gf", role="Admin"))
    rep = run(path, "apply")
    blocked = {o["id"]: o["reason"] for o in rep["operations"] if o["action"] == "BLOCKED"}
    assert set(blocked) == {uid, sa} and all("allowPrivilegedGrants" in r for r in blocked.values())
    assert uid not in folders() and sa not in accounts()
    run(path, "apply", allowPrivilegedGrants=True)
    assert folder_perms(uid) == [{"role": "Editor", "permission": "Admin"}] and accounts()[sa]["role"] == "Admin"


def test_protected_general_folder_and_own_service_account(p, cfg):
    path = cfg(doc("GrafanaFolder", "general", targetRef="gf", title="x"))
    op = run(path, "apply", allowPrivilegedGrants=True)["operations"][0]
    assert op["action"] == "BLOCKED" and "protected" in op["reason"]

    me = f"{p}ordivus"
    tok = token(me, "Admin")
    adapter = GrafanaAdapter()
    target = {"endpoint": TARGET["endpoint"]}
    with adapter.connect(target, Secret(tok), write=True) as session:
        found = adapter.discover(session, "GrafanaServiceAccount", None)
        assert next(r for r in found.resources if r.id == me).system
        mine = Resource("GrafanaServiceAccount", me, {"role": "Viewer"})
        assert "protected" in adapter.check(session, mine, allow_privileged=True)
        with pytest.raises(PermanentError, match="protected"):
            adapter.apply(session, Op("gf", "GrafanaServiceAccount", me, "UPDATE", desired=mine,
                                      changes={"role": ("Admin", "Viewer")}))
    assert accounts()[me]["role"] == "Admin"


def test_read_only_session_cannot_mutate(p):
    adapter, uid = GrafanaAdapter(), f"{p}ro"
    with adapter.connect(TARGET, Secret(ADMIN_PW), write=False) as session:
        with pytest.raises(PermanentError):
            adapter.apply(session, Op("gf", "GrafanaFolder", uid, CREATE,
                                      desired=Resource("GrafanaFolder", uid, {"title": "x"})))
        with pytest.raises(PermanentError, match="read-only"):
            grafana._request(session, "POST", "/api/folders", {"uid": uid, "title": "x"})
    assert uid not in folders()


def test_scope_partial_and_authoritative_delete(p, cfg):
    keep, stray, outside = f"{p}keep", f"{p}stray", f"{p[:-1]}_outside"
    for uid in (stray, outside):
        api("POST", "/api/folders", {"uid": uid, "title": uid})
    target = {**TARGET, "scope": {"folders": {"include": [f"{p}*"]}}}
    policy = doc("ReconciliationPolicy", "gov", targetRef="gf", mode="authoritative",
                 scope={"resourceKinds": ["GrafanaFolder"]})
    rep = run(cfg(policy, doc("GrafanaFolder", keep, targetRef="gf", title=keep), target=target),
              "apply", allowAuthoritative=True, allowDelete=True)
    assert {(i, a) for k, i, a in actions(rep) if k == "GrafanaFolder"} == {(keep, "CREATE"), (stray, "DELETE")}
    assert keep in folders() and stray not in folders() and outside in folders()
    api("DELETE", f"/api/folders/{outside}")
    with pytest.raises(ConfigError, match="outside spec.scope.folders"):
        engine.prepare(config.load(cfg(doc("GrafanaFolder", "elsewhere", targetRef="gf", title="x"), target=target)))

    # Identität ohne Leserecht auf alle Objekte: Inventar partial, nie "leer und vollständig"
    tok, adapter = token(f"{p}nobody", "None"), GrafanaAdapter()
    with adapter.connect({"endpoint": TARGET["endpoint"]}, Secret(tok), write=False) as session:
        assert adapter.discover(session, "GrafanaFolder", None).status == PARTIAL


def test_export_roundtrip(p, cfg, tmp_path):
    from roundtrip import assert_export_roundtrip

    alice = user(f"{p}alice")
    team, uid, sa = f"{p}ops", f"{p}fold", f"{p}deployer"
    run(cfg(doc("GrafanaTeam", team, targetRef="gf", email="ops@example.invalid", members=[alice]),
            doc("GrafanaFolder", uid, targetRef="gf", title=f"{p} Ops",
                permissions=[{"team": team, "permission": "Edit"}, {"role": "Viewer", "permission": "View"}]),
            doc("GrafanaServiceAccount", sa, targetRef="gf", role="Editor")), "apply")
    api("POST", "/api/folders", {"uid": f"{p}grown", "title": "no"})  # Grafana-Standardrechte bleiben stehen
    scope = {k: {"include": [p + "*"]} for k in ("teams", "folders", "serviceAccounts")}
    assert_export_roundtrip(cfg(target={**TARGET, "scope": scope}), {
        ("GrafanaTeam", team), ("GrafanaFolder", uid), ("GrafanaFolder", f"{p}grown"),
        ("GrafanaServiceAccount", sa)}, tmp_path, allowPrivilegedGrants=True)
